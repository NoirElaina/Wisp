<script setup lang="ts">
import type { CaptureSessionMeta } from "../../types/session";
import type { CaptureStats } from "../../types/stats";
import { formatBytes, formatDateTime } from "../../utils/format";

defineProps<{
  stats: CaptureStats | null
  activeSession: CaptureSessionMeta | null
  sessions: CaptureSessionMeta[]
}>();

defineEmits<{
  (event: "load-session", sessionId: string): void
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

function formatSessionTitle(session: CaptureSessionMeta): string {
  const suffix = session.id.match(/(\d+)$/)?.[1];
  if (suffix) {
    return `${formatInterfaceName(session.interface_name)} · 捕获 ${suffix}`;
  }

  return `${formatInterfaceName(session.interface_name)} · 捕获会话`;
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

    <div class="sessions">
      <div class="sessions-head">
        <p class="eyebrow">历史</p>
        <span>{{ sessions.length }} 个会话</span>
      </div>

      <button
        v-for="session in sessions"
        :key="session.id"
        class="session-item"
        :class="{ active: session.id === activeSession?.id }"
        @click="$emit('load-session', session.id)"
      >
        <div>
          <strong>{{ formatSessionTitle(session) }}</strong>
          <span>{{ formatInterfaceName(session.interface_name) }}</span>
        </div>
        <small>{{ session.packet_count }} 个包</small>
      </button>
    </div>
  </section>
</template>

<style scoped>
.panel {
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr);
  gap: 16px;
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
  gap: 10px;
}

.metrics article {
  display: grid;
  gap: 6px;
  align-content: start;
  min-height: 86px;
  padding: 12px;
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
.session-item strong {
  font-size: 13px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.sessions {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 10px;
  min-height: 0;
  overflow: auto;
  padding-right: 2px;
}

.session-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.72);
  color: var(--text);
  text-align: left;
}

.session-item.active {
  border-color: rgba(21, 94, 239, 0.24);
  background: rgba(21, 94, 239, 0.08);
}

.session-item div {
  display: grid;
  gap: 2px;
  min-width: 0;
  flex: 1;
}

small {
  color: var(--subtle);
}
</style>
