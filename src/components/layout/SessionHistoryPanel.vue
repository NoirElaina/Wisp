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
  <div class="history-panel">
    <div class="history-meta">
      <span>历史</span>
      <span>{{ sessions.length }} 个会话</span>
    </div>

    <div v-if="sessions.length > 0" class="session-list">
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

    <div v-else class="empty-state">
      <strong>还没有捕获历史</strong>
      <span>开始一次抓包后，会话会出现在这里。</span>
    </div>
  </div>
</template>

<style scoped>
.history-panel {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 12px;
  min-height: 0;
  height: 100%;
}

.history-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.history-meta span,
.main span,
.meta small {
  color: var(--muted);
  font-size: 12px;
}

.session-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-height: 0;
  overflow: auto;
  padding-right: 2px;
  align-items: stretch;
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
  flex: 0 0 auto;
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

.empty-state {
  display: grid;
  place-items: center;
  gap: 6px;
  min-height: 180px;
  border: 1px dashed var(--line);
  border-radius: 18px;
  color: var(--muted);
  text-align: center;
}

.empty-state strong {
  color: var(--text);
  font-size: 14px;
}

.empty-state span {
  font-size: 12px;
}
</style>
