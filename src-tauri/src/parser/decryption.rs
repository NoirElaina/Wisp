use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::SystemTime,
};

use ring::{aead, hkdf};

use crate::model::{
    packet::DecryptionState,
    session::TlsDecryptionConfig,
};

use super::conversation::{tls_role_for_packet, TlsConversationData, TlsPeerRole};

#[derive(Debug, Default)]
pub struct DecryptionService {
    keylog: Option<LoadedKeylog>,
}

#[derive(Debug, Clone)]
struct LoadedKeylog {
    path: PathBuf,
    modified_at: Option<SystemTime>,
    secrets: HashMap<String, HashMap<String, Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub struct DecryptedTlsRecord {
    pub payload: Vec<u8>,
    pub inner_content_type: u8,
    pub secret_label: String,
}

#[derive(Debug, Clone)]
pub struct DecryptionOutcome {
    pub state: DecryptionState,
    pub record: Option<DecryptedTlsRecord>,
}

#[derive(Debug, Clone, Copy)]
enum CipherSpec {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

#[derive(Debug, Clone, Copy)]
enum SecretPhase {
    Handshake,
    Application,
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl DecryptionService {
    pub fn inspect_tls(&mut self, config: &TlsDecryptionConfig, conversation: &TlsConversationData) -> DecryptionState {
        if !config.enabled {
            return state(
                false,
                false,
                "disabled",
                conversation,
                Some("TLS 解密未启用".to_string()),
                config.keylog_path.clone(),
            );
        }

        let Some(path) = config.keylog_path.as_ref() else {
            return state(
                false,
                false,
                "missing_keylog_path",
                conversation,
                Some("未配置 SSLKEYLOGFILE 路径".to_string()),
                None,
            );
        };

        let loaded = match self.load_keylog(path, config.reload_on_change) {
            Ok(loaded) => loaded,
            Err(err) => {
                return state(
                    true,
                    false,
                    "decrypt_failed",
                    conversation,
                    Some(err),
                    Some(path.clone()),
                );
            }
        };

        let Some(client_random) = conversation.client_random.as_ref() else {
            return state(
                true,
                false,
                "awaiting_client_random",
                conversation,
                Some("当前会话尚未提取到 Client Random，无法匹配 TLS 1.3 secrets".to_string()),
                Some(path.clone()),
            );
        };

        let Some(cipher_spec) = conversation
            .cipher_suite
            .as_deref()
            .and_then(cipher_spec_from_suite)
        else {
            return state(
                true,
                false,
                "unsupported_cipher",
                conversation,
                Some(
                    conversation
                        .cipher_suite
                        .as_ref()
                        .map(|suite| format!("当前 cipher 暂不支持 TLS 1.3 解密: {suite}"))
                        .unwrap_or_else(|| "当前会话尚未提取到 TLS 1.3 cipher suite".to_string()),
                ),
                Some(path.clone()),
            );
        };

        let available_labels = labels_for_any_role(client_random, &loaded.secrets, cipher_spec);
        let secrets_loaded = !available_labels.is_empty();
        if config.strict_secret_match && !secrets_loaded {
            return state(
                true,
                false,
                "missing_session_secret",
                conversation,
                Some("未在 keylog 中找到当前会话可用的 TLS 1.3 traffic secret".to_string()),
                Some(path.clone()),
            );
        }

        state(
            true,
            secrets_loaded,
            if secrets_loaded { "ready" } else { "missing_session_secret" },
            conversation,
            Some(if secrets_loaded {
                format!("已匹配到 keylog secret: {}", available_labels.join(", "))
            } else {
                "当前会话尚未匹配到可用 secret".to_string()
            }),
            Some(path.clone()),
        )
    }

    pub fn decrypt_tls13_record(
        &mut self,
        config: &TlsDecryptionConfig,
        conversation: &mut TlsConversationData,
        src_ip: &str,
        src_port: u16,
        record_bytes: &[u8],
    ) -> DecryptionOutcome {
        let readiness = self.inspect_tls(config, conversation);
        if readiness.status != "ready" {
            return DecryptionOutcome {
                state: readiness,
                record: None,
            };
        }

        let Some(path) = config.keylog_path.as_ref() else {
            return DecryptionOutcome {
                state: readiness,
                record: None,
            };
        };

        let loaded = match self.load_keylog(path, config.reload_on_change) {
            Ok(loaded) => loaded,
            Err(err) => {
                return DecryptionOutcome {
                    state: state(
                        true,
                        false,
                        "decrypt_failed",
                        conversation,
                        Some(err),
                        Some(path.clone()),
                    ),
                    record: None,
                };
            }
        };

        let Some(client_random) = conversation.client_random.as_ref() else {
            return DecryptionOutcome {
                state: state(
                    true,
                    false,
                    "awaiting_client_random",
                    conversation,
                    Some("当前会话尚未提取到 Client Random".to_string()),
                    Some(path.clone()),
                ),
                record: None,
            };
        };

        let Some(cipher_spec) = conversation
            .cipher_suite
            .as_deref()
            .and_then(cipher_spec_from_suite)
        else {
            return DecryptionOutcome {
                state: state(
                    true,
                    false,
                    "unsupported_cipher",
                    conversation,
                    Some("当前 cipher 暂不支持 TLS 1.3 解密".to_string()),
                    Some(path.clone()),
                ),
                record: None,
            };
        };

        if record_bytes.len() < 6 {
            return DecryptionOutcome {
                state: state(
                    true,
                    false,
                    "record_incomplete",
                    conversation,
                    Some("TLS record 头部不完整".to_string()),
                    Some(path.clone()),
                ),
                record: None,
            };
        }

        if record_bytes[0] != 23 {
            return DecryptionOutcome {
                state: state(
                    false,
                    true,
                    "ready",
                    conversation,
                    Some("当前记录仍是明文 TLS 记录，无需 TLS 1.3 payload 解密".to_string()),
                    Some(path.clone()),
                ),
                record: None,
            };
        }

        let Some(role) = tls_role_for_packet(conversation, src_ip, src_port) else {
            return DecryptionOutcome {
                state: state(
                    true,
                    false,
                    "decrypt_failed",
                    conversation,
                    Some("当前会话未能确定客户端/服务端方向，通常意味着抓包从中途开始".to_string()),
                    Some(path.clone()),
                ),
                record: None,
            };
        };

        let mut last_error = None;
        for candidate in candidate_labels_for_role(role) {
            let Some(secret) = loaded
                .secrets
                .get(candidate.label)
                .and_then(|entries| entries.get(&client_random.to_ascii_lowercase()))
            else {
                continue;
            };

            let seq = current_sequence(conversation, role, candidate.phase);
            match decrypt_record_bytes(record_bytes, cipher_spec, secret, seq) {
                Ok(record) => {
                    increment_sequence(conversation, role, candidate.phase);
                    return DecryptionOutcome {
                        state: state(
                            true,
                            true,
                            "decrypted",
                            conversation,
                            Some(format!(
                                "已使用 {} 解密 TLS 1.3 记录",
                                candidate.label
                            )),
                            Some(path.clone()),
                        ),
                        record: Some(DecryptedTlsRecord {
                            payload: record.payload,
                            inner_content_type: record.inner_content_type,
                            secret_label: candidate.label.to_string(),
                        }),
                    };
                }
                Err(err) => last_error = Some(err),
            }
        }

        DecryptionOutcome {
            state: state(
                true,
                true,
                "decrypt_failed",
                conversation,
                Some(last_error.unwrap_or_else(|| "未找到可用的 TLS 1.3 secret 或解密校验失败".to_string())),
                Some(path.clone()),
            ),
            record: None,
        }
    }

    fn load_keylog(&mut self, path: &str, reload_on_change: bool) -> Result<&LoadedKeylog, String> {
        let path_buf = PathBuf::from(path);
        let modified_at = fs::metadata(&path_buf)
            .and_then(|meta| meta.modified())
            .ok();

        let reuse = self.keylog.as_ref().is_some_and(|loaded| {
            loaded.path == path_buf && (!reload_on_change || loaded.modified_at == modified_at)
        });

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

#[derive(Debug, Clone)]
struct SecretCandidate {
    label: &'static str,
    phase: SecretPhase,
}

#[derive(Debug, Clone)]
struct PlaintextRecord {
    payload: Vec<u8>,
    inner_content_type: u8,
}

fn parse_keylog(contents: &str) -> HashMap<String, HashMap<String, Vec<u8>>> {
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
        let Some(secret_bytes) = decode_hex(secret) else {
            continue;
        };

        parsed
            .entry(label.to_string())
            .or_insert_with(HashMap::new)
            .insert(client_random.to_ascii_lowercase(), secret_bytes);
    }

    parsed
}

fn labels_for_any_role(
    client_random: &str,
    secrets: &HashMap<String, HashMap<String, Vec<u8>>>,
    _cipher_spec: CipherSpec,
) -> Vec<&'static str> {
    [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    ]
    .into_iter()
    .filter(|label| {
        secrets
            .get(*label)
            .is_some_and(|entries| entries.contains_key(&client_random.to_ascii_lowercase()))
    })
    .collect()
}

fn candidate_labels_for_role(role: TlsPeerRole) -> [SecretCandidate; 2] {
    match role {
        TlsPeerRole::Client => [
            SecretCandidate {
                label: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                phase: SecretPhase::Handshake,
            },
            SecretCandidate {
                label: "CLIENT_TRAFFIC_SECRET_0",
                phase: SecretPhase::Application,
            },
        ],
        TlsPeerRole::Server => [
            SecretCandidate {
                label: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                phase: SecretPhase::Handshake,
            },
            SecretCandidate {
                label: "SERVER_TRAFFIC_SECRET_0",
                phase: SecretPhase::Application,
            },
        ],
    }
}

fn current_sequence(
    conversation: &TlsConversationData,
    role: TlsPeerRole,
    phase: SecretPhase,
) -> u64 {
    match (role, phase) {
        (TlsPeerRole::Client, SecretPhase::Handshake) => conversation.client_handshake_seq,
        (TlsPeerRole::Server, SecretPhase::Handshake) => conversation.server_handshake_seq,
        (TlsPeerRole::Client, SecretPhase::Application) => conversation.client_application_seq,
        (TlsPeerRole::Server, SecretPhase::Application) => conversation.server_application_seq,
    }
}

fn increment_sequence(
    conversation: &mut TlsConversationData,
    role: TlsPeerRole,
    phase: SecretPhase,
) {
    match (role, phase) {
        (TlsPeerRole::Client, SecretPhase::Handshake) => {
            conversation.client_handshake_seq = conversation.client_handshake_seq.saturating_add(1);
        }
        (TlsPeerRole::Server, SecretPhase::Handshake) => {
            conversation.server_handshake_seq = conversation.server_handshake_seq.saturating_add(1);
        }
        (TlsPeerRole::Client, SecretPhase::Application) => {
            conversation.client_application_seq = conversation.client_application_seq.saturating_add(1);
        }
        (TlsPeerRole::Server, SecretPhase::Application) => {
            conversation.server_application_seq = conversation.server_application_seq.saturating_add(1);
        }
    }
}

fn decrypt_record_bytes(
    record_bytes: &[u8],
    cipher_spec: CipherSpec,
    secret: &[u8],
    sequence_number: u64,
) -> Result<PlaintextRecord, String> {
    let total_length = ((record_bytes[3] as usize) << 8) | record_bytes[4] as usize;
    if record_bytes.len() < 5 + total_length {
        return Err("TLS record 数据不完整".to_string());
    }

    let header = &record_bytes[..5];
    let ciphertext = &record_bytes[5..5 + total_length];
    let key_bytes = hkdf_expand_label(cipher_spec, secret, "key", cipher_spec.key_len())?;
    let iv_bytes = hkdf_expand_label(cipher_spec, secret, "iv", 12)?;

    let unbound =
        aead::UnboundKey::new(cipher_spec.algorithm(), &key_bytes).map_err(|_| "无法创建 AEAD key".to_string())?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = build_nonce(&iv_bytes, sequence_number)?;
    let mut buffer = ciphertext.to_vec();
    let opened = key
        .open_in_place(nonce, aead::Aad::from(header), &mut buffer)
        .map_err(|_| "TLS AEAD 校验失败，通常是 sequence 或 secret 不匹配".to_string())?;

    let (payload, inner_content_type) = split_tls13_plaintext(opened)?;
    Ok(PlaintextRecord {
        payload,
        inner_content_type,
    })
}

fn split_tls13_plaintext(plaintext: &[u8]) -> Result<(Vec<u8>, u8), String> {
    let Some(content_type_index) = plaintext.iter().rposition(|byte| *byte != 0) else {
        return Err("TLSInnerPlaintext 中缺少 content type".to_string());
    };

    let inner_content_type = plaintext[content_type_index];
    Ok((plaintext[..content_type_index].to_vec(), inner_content_type))
}

fn hkdf_expand_label(
    cipher_spec: CipherSpec,
    secret: &[u8],
    label: &str,
    len: usize,
) -> Result<Vec<u8>, String> {
    let prk = hkdf::Prk::new_less_safe(cipher_spec.hkdf_algorithm(), secret);
    let full_label = format!("tls13 {label}");

    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);

    let binding = [info.as_slice()];
    let okm = prk
        .expand(&binding, HkdfLen(len))
        .map_err(|_| "HKDF expand 失败".to_string())?;
    let mut output = vec![0u8; len];
    okm.fill(&mut output)
        .map_err(|_| "HKDF 输出填充失败".to_string())?;
    Ok(output)
}

fn build_nonce(iv: &[u8], sequence_number: u64) -> Result<aead::Nonce, String> {
    if iv.len() != 12 {
        return Err("TLS 1.3 IV 长度异常".to_string());
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    let sequence_bytes = sequence_number.to_be_bytes();
    for (index, byte) in sequence_bytes.iter().enumerate() {
        nonce[nonce.len() - sequence_bytes.len() + index] ^= *byte;
    }

    Ok(aead::Nonce::assume_unique_for_key(nonce))
}

fn cipher_spec_from_suite(cipher_suite: &str) -> Option<CipherSpec> {
    match cipher_suite {
        "TLS_AES_128_GCM_SHA256" => Some(CipherSpec::Aes128GcmSha256),
        "TLS_AES_256_GCM_SHA384" => Some(CipherSpec::Aes256GcmSha384),
        "TLS_CHACHA20_POLY1305_SHA256" => Some(CipherSpec::Chacha20Poly1305Sha256),
        _ => None,
    }
}

fn state(
    attempted: bool,
    secrets_loaded: bool,
    status: &str,
    conversation: &TlsConversationData,
    note: Option<String>,
    keylog_path: Option<String>,
) -> DecryptionState {
    DecryptionState {
        attempted,
        secrets_loaded,
        status: status.to_string(),
        protocol_hint: conversation.decrypted_protocol_hint.clone(),
        note,
        keylog_path,
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = from_hex_digit(chunk[0])?;
        let lo = from_hex_digit(chunk[1])?;
        output.push((hi << 4) | lo);
    }

    Some(output)
}

fn from_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

impl CipherSpec {
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    fn hkdf_algorithm(self) -> hkdf::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => hkdf::HKDF_SHA256,
            Self::Aes256GcmSha384 => hkdf::HKDF_SHA384,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 => 32,
            Self::Chacha20Poly1305Sha256 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::aead;

    use super::{
        build_nonce, cipher_spec_from_suite, decode_hex, decrypt_record_bytes, hkdf_expand_label,
        parse_keylog, CipherSpec,
    };

    #[test]
    fn parses_sslkeylog_lines() {
        let parsed = parse_keylog(
            "# comment\nCLIENT_RANDOM 001122 aabbcc\nCLIENT_HANDSHAKE_TRAFFIC_SECRET 334455 ddeeff\n",
        );

        assert_eq!(
            parsed
                .get("CLIENT_RANDOM")
                .and_then(|entries| entries.get("001122"))
                .map(Vec::as_slice),
            Some(&[0xaa, 0xbb, 0xcc][..])
        );
        assert_eq!(
            parsed
                .get("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
                .and_then(|entries| entries.get("334455"))
                .map(Vec::as_slice),
            Some(&[0xdd, 0xee, 0xff][..])
        );
    }

    #[test]
    fn decrypts_tls13_aes128_record() {
        let secret = decode_hex("4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566676869")
            .expect("secret");
        let payload = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let record = encrypt_record(CipherSpec::Aes128GcmSha256, &secret, 0, payload, 23);

        let decrypted =
            decrypt_record_bytes(&record, CipherSpec::Aes128GcmSha256, &secret, 0).expect("decrypt");
        assert_eq!(decrypted.payload, payload);
        assert_eq!(decrypted.inner_content_type, 23);
    }

    #[test]
    fn decrypts_tls13_chacha_record() {
        let secret = decode_hex("7a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293949596979899")
            .expect("secret");
        let payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let record = encrypt_record(CipherSpec::Chacha20Poly1305Sha256, &secret, 2, payload, 23);

        let decrypted =
            decrypt_record_bytes(&record, CipherSpec::Chacha20Poly1305Sha256, &secret, 2)
                .expect("decrypt");
        assert_eq!(decrypted.payload, payload);
    }

    #[test]
    fn resolves_tls13_cipher_suite() {
        assert!(matches!(
            cipher_spec_from_suite("TLS_AES_256_GCM_SHA384"),
            Some(CipherSpec::Aes256GcmSha384)
        ));
    }

    fn encrypt_record(
        cipher_spec: CipherSpec,
        secret: &[u8],
        sequence_number: u64,
        payload: &[u8],
        inner_content_type: u8,
    ) -> Vec<u8> {
        let key_bytes = hkdf_expand_label(cipher_spec, secret, "key", cipher_spec.key_len())
            .expect("key");
        let iv_bytes = hkdf_expand_label(cipher_spec, secret, "iv", 12).expect("iv");
        let nonce = build_nonce(&iv_bytes, sequence_number).expect("nonce");
        let unbound =
            aead::UnboundKey::new(cipher_spec.algorithm(), &key_bytes).expect("unbound key");
        let key = aead::LessSafeKey::new(unbound);

        let mut sealed = payload.to_vec();
        sealed.push(inner_content_type);

        let record_len = (sealed.len() + cipher_spec.algorithm().tag_len()) as u16;
        let aad = [23, 3, 3, (record_len >> 8) as u8, record_len as u8];
        let ciphertext = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut sealed)
            .expect("seal");
        sealed.extend_from_slice(ciphertext.as_ref());

        let mut final_record = vec![23, 3, 3];
        final_record.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        final_record.extend_from_slice(&sealed);
        final_record
    }
}
