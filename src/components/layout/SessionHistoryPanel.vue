<script setup lang="ts">
import type { CaptureSessionMeta } from "../../types/session";
import { formatDateTime } from "../../utils/format";

defineProps<{
  sessions: CaptureSessionMeta[]
  activeSession: CaptureSessionMeta | null
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
        <p class="eyebrow">历史</p>
        <h3>捕获会话</h3>
      </div>
      <span>{{ sessions.length }} 个会话</span>
    </div>

    <div class="session-list">
      <button
        v-for="session in sessions"
        :key="session.id"
        class="session-item"
        :class="{ active: session.id === activeSession?.id }"
        @click="$emit('load-session', session.id)"
      >
        <div class="main">
          <strong>{{ formatSessionTitle(session) }}</strong>
          <span>{{ formatDateTime(session.started_at_ms) }}</span>
        </div>
        <div class="meta">
          <small>{{ session.packet_count }} 个包</small>
          <small>{{ session.running ? "实时" : "已结束" }}</small>
        </div>
      </button>
    </div>
  </section>
</template>

<style scoped>
.panel {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 12px;
  min-height: 0;
  height: 100%;
}

.panel-head {
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

.panel-head span,
.main span,
.meta small {
  color: var(--muted);
  font-size: 12px;
}

.session-list {
  display: grid;
  gap: 10px;
  min-height: 0;
  overflow: auto;
  padding-right: 2px;
}

.session-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 14px;
  width: 100%;
  padding: 12px 14px;
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

.main {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.main strong {
  font-size: 13px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}

.meta {
  display: grid;
  gap: 4px;
  justify-items: end;
}
</style>
