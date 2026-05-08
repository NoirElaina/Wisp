<script setup lang="ts">
import { reactive, watch } from "vue";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";

import type { DecryptionState } from "../../types/packet";
import type { TlsDecryptionConfig } from "../../types/session";

const props = defineProps<{
  config: TlsDecryptionConfig
  currentState: DecryptionState | null
  saving: boolean
}>();

const emit = defineEmits<{
  (event: "save", config: TlsDecryptionConfig): void
}>();

const form = reactive<TlsDecryptionConfig>({
  enabled: false,
  keylog_path: null,
  reload_on_change: false,
  strict_secret_match: true,
});

watch(
  () => props.config,
  (config) => {
    form.enabled = config.enabled;
    form.keylog_path = config.keylog_path;
    form.reload_on_change = config.reload_on_change;
    form.strict_secret_match = config.strict_secret_match;
  },
  { immediate: true, deep: true },
);

function submit() {
  emit("save", {
    enabled: form.enabled,
    keylog_path: normalizePath(form.keylog_path),
    reload_on_change: form.reload_on_change,
    strict_secret_match: form.strict_secret_match,
  });
}

function normalizePath(value: string | null) {
  const next = value?.trim();
  return next ? next : null;
}

function statusTitle() {
  const state = props.currentState;
  if (!form.enabled) {
    return "当前已关闭 TLS 解密。";
  }
  if (!form.keylog_path?.trim()) {
    return "已启用，但还没有配置 SSLKEYLOGFILE 路径。";
  }
  if (!state) {
    return "配置已就绪，等待抓到可分析的 TLS 会话。";
  }

  switch (state.status) {
    case "decrypted":
      return "当前会话已经成功解密。";
    case "awaiting_client_random":
      return "当前会话还没拿到 ClientHello，需要更多握手包。";
    case "missing_session_secret":
      return "已读取 keylog，但还没匹配到当前会话的 secret。";
    case "unsupported_cipher":
      return "当前 cipher 暂不在这一阶段的解密支持范围内。";
    case "record_incomplete":
      return "TLS record 还没完整重组完成。";
    case "decrypt_failed":
      return "尝试过解密，但 secret、sequence 或 record 还没对上。";
    case "ready":
      return "会话条件已满足，正在等待可解密的 TLS 1.3 ApplicationData。";
    default:
      return "当前会话的解密状态已同步到这里。";
  }
}
</script>

<template>
  <div class="grid gap-4">
    <section class="rounded-2xl border border-slate-200/80 bg-white/80 p-4">
      <p class="m-0 text-sm font-semibold text-slate-900">TLS 1.3 + SSLKEYLOGFILE</p>
      <p class="mt-1 text-sm leading-6 text-slate-500">
        这一阶段只打通 TLS 1.3 的 keylog 解密链，重点是让研发更快看到 HTTP/1.1、HTTP/2 和解密失败原因。
      </p>
    </section>

    <section class="rounded-2xl border border-slate-200/80 bg-white/80 p-4">
      <div class="grid gap-3">
        <label class="toggle-row">
          <Checkbox :checked="form.enabled" @update:checked="form.enabled = $event === true" />
          <span>启用 TLS 解密</span>
        </label>

        <div class="grid gap-2">
          <span class="label">SSLKEYLOGFILE 路径</span>
          <Input
            :model-value="form.keylog_path ?? ''"
            placeholder="例如 C:\\Users\\you\\sslkeys.log"
            @update:model-value="form.keylog_path = String($event)"
          />
        </div>

        <label class="toggle-row">
          <Checkbox
            :checked="form.reload_on_change"
            @update:checked="form.reload_on_change = $event === true"
          />
          <span>每次读取时检查文件变化</span>
        </label>

        <label class="toggle-row">
          <Checkbox
            :checked="form.strict_secret_match"
            @update:checked="form.strict_secret_match = $event === true"
          />
          <span>必须命中当前会话 secret 才算就绪</span>
        </label>
      </div>
    </section>

    <section class="rounded-2xl border border-blue-200/80 bg-blue-50/70 p-4">
      <p class="m-0 text-sm font-semibold text-blue-950">当前解释</p>
      <p class="mt-1 text-sm leading-6 text-blue-900">{{ statusTitle() }}</p>
      <dl v-if="currentState" class="mt-3 grid gap-2">
        <div>
          <dt>状态</dt>
          <dd>{{ currentState.status }}</dd>
        </div>
        <div>
          <dt>协议提示</dt>
          <dd>{{ currentState.protocol_hint ?? "—" }}</dd>
        </div>
        <div>
          <dt>备注</dt>
          <dd>{{ currentState.note ?? "—" }}</dd>
        </div>
      </dl>
    </section>

    <div class="flex justify-end">
      <Button :disabled="saving" @click="submit">
        {{ saving ? "保存中..." : "保存配置" }}
      </Button>
    </div>
  </div>
</template>

<style scoped>
.toggle-row {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  color: rgb(15 23 42);
  font-size: 14px;
}

.label {
  color: rgb(100 116 139);
  font-size: 12px;
}

dl {
  margin: 0;
}

dt {
  color: rgb(59 130 246);
  font-size: 12px;
}

dd {
  margin: 0;
  color: rgb(15 23 42);
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}
</style>
