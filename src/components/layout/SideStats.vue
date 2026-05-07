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
  <section class="grid h-full min-h-0 grid-rows-[auto_auto] gap-3">
    <div class="flex items-center justify-between gap-3">
      <div>
        <p class="mb-1 text-xs uppercase tracking-[0.08em] text-slate-500">会话</p>
        <h3 class="m-0 text-base font-semibold text-slate-950">捕获概览</h3>
      </div>
      <span
        class="rounded-full px-2.5 py-1 text-xs font-semibold"
        :class="
          activeSession?.running
            ? 'bg-emerald-100 text-emerald-700'
            : 'bg-slate-100 text-slate-500'
        "
      >
        {{ activeSession?.running ? "实时" : "回放" }}
      </span>
    </div>

    <div class="grid grid-cols-2 gap-x-4 gap-y-0">
      <article class="grid min-h-[76px] content-start gap-1.5 border-b border-slate-200/80 py-3">
        <span class="text-xs text-slate-500">总包数</span>
        <strong class="text-sm font-semibold leading-6 text-slate-950">{{ stats?.packets_total ?? activeSession?.packet_count ?? 0 }}</strong>
      </article>
      <article class="grid min-h-[76px] content-start gap-1.5 border-b border-slate-200/80 py-3">
        <span class="text-xs text-slate-500">捕获字节</span>
        <strong class="text-sm font-semibold leading-6 text-slate-950">{{ formatBytes(stats?.bytes_total ?? activeSession?.bytes_captured ?? 0) }}</strong>
      </article>
      <article class="grid min-h-[76px] content-start gap-1.5 border-b border-slate-200/80 py-3">
        <span class="text-xs text-slate-500">网卡</span>
        <strong class="overflow-wrap-anywhere text-sm font-semibold leading-6 text-slate-950">{{ formatInterfaceName(activeSession?.interface_name) }}</strong>
      </article>
      <article class="grid min-h-[76px] content-start gap-1.5 border-b border-slate-200/80 py-3">
        <span class="text-xs text-slate-500">开始时间</span>
        <strong class="text-sm font-semibold leading-6 text-slate-950">{{ activeSession ? formatDateTime(activeSession.started_at_ms) : "—" }}</strong>
      </article>
    </div>
  </section>
</template>
