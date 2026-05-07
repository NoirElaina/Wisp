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
  <div class="shell">
    <header class="hero">
      <div class="brand">
        <span class="brand-mark">W</span>
        <div>
          <p>Windows 网络抓包工作台</p>
          <h1>Wisp</h1>
        </div>
      </div>
      <p class="tagline">
        基于 Tauri 的桌面抓包控制台，聚焦高密度数据包检查、回放分析与实时流量可视化。
      </p>
    </header>

    <TopBar>
      <div class="toolbar-left">
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

      <div class="toolbar-right">
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

    <main class="content">
      <section class="panel table-panel">
        <PacketTable
          :packets="store.filteredPackets.value"
          :selected-id="store.state.selectedPacketId"
          :total-count="store.state.stats?.packets_total ?? store.state.activeSession?.packet_count ?? store.filteredPackets.value.length"
          @select="store.selectPacket"
        />
      </section>

      <aside class="panel detail-panel">
        <PacketDetailPanel :packet="store.state.selectedDetail" />
      </aside>
    </main>

    <section class="dashboard">
      <article class="panel chart-panel">
        <TimelineChart :stats="store.state.stats" />
      </article>

      <article class="panel donut-panel">
        <ProtocolDonut :stats="store.state.stats" />
      </article>

      <article class="panel sidebar-panel">
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
.shell {
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto;
  gap: 18px;
  padding: 22px;
  height: 100vh;
  overflow: hidden;
}

.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(360px, 520px);
  align-items: center;
  gap: 24px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 16px;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 52px;
  height: 52px;
  border-radius: 16px;
  background:
    linear-gradient(135deg, rgba(21, 94, 239, 0.16), rgba(21, 94, 239, 0.02)),
    #fff;
  border: 1px solid rgba(21, 94, 239, 0.14);
  color: var(--accent);
  font-size: 20px;
  font-weight: 700;
}

.brand p,
.tagline {
  margin: 0;
  color: var(--muted);
}

.brand h1 {
  margin: 2px 0 0;
  font-size: 32px;
  line-height: 1;
}

.tagline {
  max-width: 520px;
  justify-self: end;
  line-height: 1.6;
  text-align: left;
}

.toolbar-left,
.toolbar-right {
  display: flex;
  align-items: end;
  gap: 12px;
  min-width: 0;
}

.toolbar-right {
  justify-content: flex-start;
  flex-wrap: wrap;
}

.content {
  display: grid;
  grid-template-columns: minmax(740px, 1.8fr) minmax(380px, 1fr);
  gap: 18px;
  min-height: 0;
}

.dashboard {
  display: grid;
  grid-template-columns: minmax(480px, 1.6fr) minmax(300px, 1fr) minmax(320px, 1fr);
  gap: 18px;
  max-height: 320px;
  min-height: 260px;
}

.panel {
  border: 1px solid var(--line);
  border-radius: 20px;
  background: var(--panel);
  box-shadow: var(--shadow);
  backdrop-filter: blur(12px);
}

.table-panel,
.detail-panel,
.chart-panel,
.donut-panel,
.sidebar-panel {
  overflow: hidden;
}

.table-panel,
.detail-panel {
  min-height: 0;
}

.chart-panel,
.donut-panel,
.sidebar-panel {
  min-height: 250px;
  padding: 16px;
}

.drawer-eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
</style>
