use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::SystemTime,
};

use crate::model::{
    packet::DecryptionState,
    session::TlsDecryptionConfig,
};

use super::conversation::TlsConversationData;

#[derive(Debug, Default)]
pub struct DecryptionService {
    keylog: Option<LoadedKeylog>,
}

#[derive(Debug, Clone)]
struct LoadedKeylog {
    path: PathBuf,
    modified_at: Option<SystemTime>,
    secrets: HashMap<String, HashMap<String, String>>,
}

impl DecryptionService {
    pub fn inspect_tls(
        &mut self,
        config: &TlsDecryptionConfig,
        conversation: &TlsConversationData,
        content_type: &str,
    ) -> Option<DecryptionState> {
        if !config.enabled {
            return Some(DecryptionState {
                attempted: false,
                secrets_loaded: false,
                status: "disabled".to_string(),
                protocol_hint: conversation.decrypted_protocol_hint.clone(),
                note: Some("TLS 解密未启用".to_string()),
                keylog_path: config.keylog_path.clone(),
            });
        }

        let Some(path) = config.keylog_path.as_ref() else {
            return Some(DecryptionState {
                attempted: false,
                secrets_loaded: false,
                status: "missing_keylog_path".to_string(),
                protocol_hint: conversation.decrypted_protocol_hint.clone(),
                note: Some("未配置 SSLKEYLOGFILE 路径".to_string()),
                keylog_path: None,
            });
        };

        let loaded = match self.load_keylog(path, config.reload_on_change) {
            Ok(loaded) => loaded,
            Err(err) => {
                return Some(DecryptionState {
                    attempted: true,
                    secrets_loaded: false,
                    status: "keylog_error".to_string(),
                    protocol_hint: conversation.decrypted_protocol_hint.clone(),
                    note: Some(err),
                    keylog_path: Some(path.clone()),
                });
            }
        };

        let Some(client_random) = conversation.client_random.as_ref() else {
            return Some(DecryptionState {
                attempted: true,
                secrets_loaded: false,
                status: "awaiting_client_random".to_string(),
                protocol_hint: conversation.decrypted_protocol_hint.clone(),
                note: Some("当前会话尚未提取到 Client Random".to_string()),
                keylog_path: Some(path.clone()),
            });
        };

        let matched = lookup_any_secret(&loaded.secrets, client_random);
        let strict_match_missing = config.strict_secret_match && matched.is_none();

        Some(DecryptionState {
            attempted: true,
            secrets_loaded: matched.is_some(),
            status: if matched.is_some() {
                "ready".to_string()
            } else if strict_match_missing {
                "missing_session_secret".to_string()
            } else {
                "best_effort".to_string()
            },
            protocol_hint: conversation.decrypted_protocol_hint.clone(),
            note: matched.map(|label| {
                format!(
                    "已在 keylog 中匹配到 {label}，当前版本仅完成 secrets 匹配与状态接线，未启用 TLS 负载解密"
                )
            }).or_else(|| {
                Some(format!(
                    "未在 keylog 中找到与 Client Random 匹配的 secret，当前记录类型为 {content_type}"
                ))
            }),
            keylog_path: Some(path.clone()),
        })
    }

    fn load_keylog(&mut self, path: &str, reload_on_change: bool) -> Result<&LoadedKeylog, String> {
        let path_buf = PathBuf::from(path);
        let modified_at = fs::metadata(&path_buf)
            .and_then(|meta| meta.modified())
            .ok();

        let reuse = self
            .keylog
            .as_ref()
            .is_some_and(|loaded| loaded.path == path_buf && (!reload_on_change || loaded.modified_at == modified_at));
        if !reuse {
            let contents = fs::read_to_string(&path_buf)
                .map_err(|err| format!("无法读取 keylog 文件: {err}"))?;
            let secrets = parse_keylog(&contents);
            self.keylog = Some(LoadedKeylog {
                path: path_buf,
                modified_at,
                secrets,
            });
        }

        self.keylog
            .as_ref()
            .ok_or_else(|| "keylog 未加载".to_string())
    }
}

fn parse_keylog(contents: &str) -> HashMap<String, HashMap<String, String>> {
    let mut parsed = HashMap::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(label) = parts.next() else {
            continue;
        };
        let Some(client_random) = parts.next() else {
            continue;
        };
        let Some(secret) = parts.next() else {
            continue;
        };

        parsed
            .entry(label.to_string())
            .or_insert_with(HashMap::new)
            .insert(client_random.to_ascii_lowercase(), secret.to_string());
    }

    parsed
}

fn lookup_any_secret<'a>(
    secrets: &'a HashMap<String, HashMap<String, String>>,
    client_random: &str,
) -> Option<&'a str> {
    let client_random = client_random.to_ascii_lowercase();

    [
        "CLIENT_TRAFFIC_SECRET_0",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_RANDOM",
    ]
    .into_iter()
    .find(|label| {
        secrets
            .get(*label)
            .is_some_and(|entries| entries.contains_key(&client_random))
    })
}

#[cfg(test)]
mod tests {
    use super::parse_keylog;

    #[test]
    fn parses_sslkeylog_lines() {
        let parsed = parse_keylog(
            "# comment\nCLIENT_RANDOM 001122 aabbcc\nCLIENT_HANDSHAKE_TRAFFIC_SECRET 334455 ddeeff\n",
        );

        assert_eq!(
            parsed
                .get("CLIENT_RANDOM")
                .and_then(|entries| entries.get("001122"))
                .map(String::as_str),
            Some("aabbcc")
        );
        assert_eq!(
            parsed
                .get("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
                .and_then(|entries| entries.get("334455"))
                .map(String::as_str),
            Some("ddeeff")
        );
    }
}
