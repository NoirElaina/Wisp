<script setup lang="ts">
import type { CaptureSessionMeta } from "../../types/session";
import type { CaptureStats } from "../../types/stats";
import { formatBytes, formatDateTime } from "../../utils/format";

defineProps<{
  stats: CaptureStats | null
  activeSession: CaptureSessionMeta | null
}>();

function formatInterfaceName(value: string | null | undefined): string {
  if (!value) {
    return "未选择";
  }

  if (value.startsWith("\\Device\\NPF_Loopback")) {
    return "本地回环";
  }

  const match = value.match(/^\\Device\\NPF_(\{.+\})$/i);
  if (match) {
    return `Npcap 网卡 ${match[1]}`;
  }

  return value;
}

</script>

<template>
  <section class="panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">会话</p>
        <h3>捕获概览</h3>
      </div>
      <span class="status" :class="{ live: activeSession?.running }">
        {{ activeSession?.running ? "实时" : "回放" }}
      </span>
    </div>

    <div class="metrics">
      <article>
        <span>总包数</span>
        <strong>{{ stats?.packets_total ?? activeSession?.packet_count ?? 0 }}</strong>
      </article>
      <article>
        <span>捕获字节</span>
        <strong>{{ formatBytes(stats?.bytes_total ?? activeSession?.bytes_captured ?? 0) }}</strong>
      </article>
      <article>
        <span>网卡</span>
        <strong>{{ formatInterfaceName(activeSession?.interface_name) }}</strong>
      </article>
      <article>
        <span>开始时间</span>
        <strong>{{ activeSession ? formatDateTime(activeSession.started_at_ms) : "—" }}</strong>
      </article>
    </div>

  </section>
</template>

<style scoped>
.panel {
  display: grid;
  grid-template-rows: auto auto;
  gap: 12px;
  height: 100%;
  min-height: 0;
}

.panel-head,
.sessions-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

h3 {
  margin: 0;
  font-size: 16px;
}

.status {
  padding: 6px 10px;
  border-radius: 999px;
  background: rgba(102, 112, 133, 0.08);
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
}

.status.live {
  background: rgba(2, 122, 72, 0.12);
  color: var(--success);
}

.metrics {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.metrics article {
  display: grid;
  gap: 6px;
  align-content: start;
  min-height: 72px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.7);
}

.metrics span,
.session-item span,
.sessions-head span {
  color: var(--muted);
  font-size: 12px;
}

.metrics strong,
.metrics strong {
  font-size: 13px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
</style>
