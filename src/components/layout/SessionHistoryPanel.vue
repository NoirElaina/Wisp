<script setup lang="ts">
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";

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
  <div class="grid h-full min-h-0 grid-rows-[auto_auto_minmax(0,1fr)] gap-3">
    <div class="flex items-center justify-between gap-3">
      <span class="text-xs text-slate-500">历史</span>
      <span class="text-xs text-slate-500">{{ sessions.length }} 个会话</span>
    </div>

    <Separator />

    <ScrollArea v-if="sessions.length > 0" class="session-list">
      <div class="flex flex-col gap-2.5 pr-2">
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
    </ScrollArea>

    <div v-else class="grid min-h-[180px] place-items-center gap-1.5 rounded-2xl border border-dashed border-slate-200 text-center text-slate-500">
      <strong class="text-sm font-semibold text-slate-900">还没有捕获历史</strong>
      <span class="text-xs">开始一次抓包后，会话会出现在这里。</span>
    </div>
  </div>
</template>

<style scoped>
.session-list {
  min-height: 0;
}

.session-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 14px;
  width: 100%;
  padding: 12px 14px;
  border: 1px solid rgb(226 232 240 / 0.9);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.82);
  color: rgb(15 23 42);
  text-align: left;
  flex: 0 0 auto;
  transition: background-color 160ms ease, border-color 160ms ease, transform 160ms ease;
}

.session-item.active {
  border-color: rgba(21, 94, 239, 0.22);
  background: rgba(239, 246, 255, 0.92);
}

.session-item:hover {
  transform: translateY(-1px);
  background: rgba(248, 250, 252, 0.96);
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

.main span,
.meta small {
  color: rgb(100 116 139);
  font-size: 12px;
}

.meta {
  display: grid;
  gap: 4px;
  justify-items: end;
}
</style>
