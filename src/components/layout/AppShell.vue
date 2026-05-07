<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { toast } from "vue-sonner";

import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

import { useCaptureStore } from "../../stores/capture";
import CaptureControls from "../capture/CaptureControls.vue";
import FilterBar from "../capture/FilterBar.vue";
import InterfaceSelector from "../capture/InterfaceSelector.vue";
import PacketDetailPanel from "../capture/PacketDetailPanel.vue";
import PacketTable from "../capture/PacketTable.vue";
import ProtocolDonut from "../capture/ProtocolDonut.vue";
import SearchBox from "../capture/SearchBox.vue";
import TimelineChart from "../capture/TimelineChart.vue";
import SideStats from "./SideStats.vue";
import SessionHistoryPanel from "./SessionHistoryPanel.vue";
import TopBar from "./TopBar.vue";

const store = useCaptureStore();
const historyOpen = ref(false);

const portFilterValue = computed(() =>
  store.state.filter.port ? String(store.state.filter.port) : "",
);

const searchValue = computed(() => store.state.filter.query ?? "");
const ipFilterValue = computed(() => store.state.filter.ip ?? "");

onMounted(() => {
  void store.init();
});

watch(
  () => store.state.errorMessage,
  (message, previous) => {
    if (!message || message === previous) {
      return;
    }

    toast.error(message, {
      id: "capture-error",
      duration: 4200,
    });
  },
);

function openHistory() {
  historyOpen.value = true;
}

function closeHistory() {
  historyOpen.value = false;
}
</script>

<template>
  <div class="grid h-screen grid-rows-[auto_auto_minmax(0,1fr)_auto] gap-[18px] overflow-hidden bg-[radial-gradient(circle_at_top_left,rgba(21,94,239,0.06),transparent_24%),linear-gradient(180deg,#fbfcfd_0%,#eef2f6_100%)] p-[22px]">
    <header class="grid grid-cols-[minmax(0,1fr)_minmax(360px,520px)] items-center gap-6">
      <div class="flex items-center gap-4">
        <span class="grid h-[52px] w-[52px] place-items-center rounded-2xl border border-blue-200/70 bg-[linear-gradient(135deg,rgba(21,94,239,0.16),rgba(21,94,239,0.02)),#fff] text-[20px] font-bold text-blue-700 shadow-sm">W</span>
        <div>
          <p class="m-0 text-sm text-slate-500">Windows 网络抓包工作台</p>
          <h1 class="mt-0.5 text-[32px] font-bold leading-none text-slate-950">Wisp</h1>
        </div>
      </div>
      <p class="m-0 max-w-[520px] justify-self-end text-left leading-7 text-slate-500">
        聚焦高密度数据包检查、回放分析与实时流量可视化。
      </p>
    </header>

    <TopBar>
      <div class="flex min-w-0 items-end gap-3">
        <InterfaceSelector
          :interfaces="store.state.interfaces"
          :model-value="store.state.selectedInterface"
          @update:model-value="store.setSelectedInterface"
        />
        <CaptureControls
          :running="store.state.running"
          :can-start="Boolean(store.state.selectedInterface)"
          :busy="store.state.busy"
          @start="store.startCapture"
          @stop="store.stopCapture"
          @history="openHistory"
        />
      </div>

      <div class="flex min-w-0 flex-wrap items-end justify-start gap-3">
        <FilterBar
          :selected-protocols="store.state.filter.protocols"
          :ip="ipFilterValue"
          :port="portFilterValue"
          :only-malformed="store.state.filter.only_malformed"
          @toggle-protocol="store.toggleProtocol"
          @update:ip="store.setIpFilter"
          @update:port="store.setPortFilter"
          @update:only-malformed="store.setOnlyMalformed"
        />
        <SearchBox :model-value="searchValue" @update:model-value="store.setSearch" />
      </div>
    </TopBar>

    <main class="grid min-h-0 grid-cols-[minmax(740px,1.8fr)_minmax(380px,1fr)] gap-[18px]">
      <section class="min-h-0 overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 shadow-[0_18px_48px_rgba(15,23,42,0.08)] backdrop-blur-xl">
        <PacketTable
          :packets="store.filteredPackets.value"
          :selected-id="store.state.selectedPacketId"
          :total-count="store.state.stats?.packets_total ?? store.state.activeSession?.packet_count ?? store.filteredPackets.value.length"
          @select="store.selectPacket"
        />
      </section>

      <aside class="min-h-0 overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 shadow-[0_18px_48px_rgba(15,23,42,0.08)] backdrop-blur-xl">
        <PacketDetailPanel :packet="store.state.selectedDetail" />
      </aside>
    </main>

    <section class="grid min-h-[260px] max-h-[320px] grid-cols-[minmax(480px,1.6fr)_minmax(300px,1fr)_minmax(320px,1fr)] gap-[18px]">
      <article class="min-h-[250px] overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.08)] backdrop-blur-xl">
        <TimelineChart :stats="store.state.stats" />
      </article>

      <article class="min-h-[250px] overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.08)] backdrop-blur-xl">
        <ProtocolDonut :stats="store.state.stats" />
      </article>

      <article class="min-h-[250px] overflow-hidden rounded-3xl border border-slate-200/80 bg-white/90 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.08)] backdrop-blur-xl">
        <SideStats
          :stats="store.state.stats"
          :active-session="store.state.activeSession"
        />
      </article>
    </section>

    <Sheet :open="historyOpen" @update:open="historyOpen = $event">
      <SheetContent side="right" class="w-[520px] max-w-[100vw] bg-slate-50/95 px-5 py-6 backdrop-blur-xl">
        <SheetHeader class="space-y-1 pb-4">
          <p class="drawer-eyebrow">历史</p>
          <SheetTitle>捕获会话</SheetTitle>
        </SheetHeader>
        <Separator class="mb-4" />
        <SessionHistoryPanel
          :sessions="store.state.sessions"
          :active-session="store.state.activeSession"
          @load-session="
            (sessionId) => {
              closeHistory();
              void store.loadSession(sessionId);
            }
          "
        />
      </SheetContent>
    </Sheet>
  </div>
</template>

<style scoped>
.drawer-eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
</style>
