<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

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

    <transition name="toast">
      <aside v-if="store.state.errorMessage" class="toast-panel">
        <div class="toast-head">
          <strong>操作提示</strong>
          <button class="toast-close" @click="store.clearError">关闭</button>
        </div>
        <p>{{ store.state.errorMessage }}</p>
      </aside>
    </transition>

    <transition name="drawer-fade">
      <div v-if="historyOpen" class="drawer-mask" @click.self="closeHistory">
        <aside class="history-drawer">
          <div class="drawer-head">
            <div>
              <p class="drawer-eyebrow">历史</p>
              <h3>捕获会话</h3>
            </div>
            <button class="drawer-close" @click="closeHistory">关闭</button>
          </div>

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
        </aside>
      </div>
    </transition>
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

.toast-panel {
  position: fixed;
  top: 28px;
  right: 28px;
  z-index: 40;
  display: grid;
  gap: 10px;
  width: min(360px, calc(100vw - 56px));
  padding: 14px 16px;
  border: 1px solid rgba(180, 35, 24, 0.18);
  border-radius: 18px;
  background: rgba(255, 248, 247, 0.96);
  box-shadow: 0 18px 40px rgba(180, 35, 24, 0.12);
  backdrop-filter: blur(18px);
  color: var(--danger);
}

.toast-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.toast-head strong {
  font-size: 13px;
}

.toast-close {
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--muted);
  font-size: 12px;
}

.toast-panel p {
  margin: 0;
  line-height: 1.6;
  font-size: 13px;
  font-weight: 600;
}

.toast-enter-active,
.toast-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translate3d(0, -10px, 0);
}

.drawer-mask {
  position: fixed;
  inset: 0;
  z-index: 35;
  display: flex;
  justify-content: flex-end;
  background: rgba(15, 23, 42, 0.18);
  backdrop-filter: blur(6px);
}

.history-drawer {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  width: min(520px, 100vw);
  height: 100vh;
  padding: 22px 20px;
  background: rgba(248, 250, 252, 0.98);
  border-left: 1px solid var(--line);
  box-shadow: -18px 0 40px rgba(15, 23, 42, 0.12);
}

.drawer-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 14px;
}

.drawer-eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.drawer-head h3 {
  margin: 0;
  font-size: 18px;
}

.drawer-close {
  height: 36px;
  padding: 0 14px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.86);
  color: var(--text);
}

.drawer-fade-enter-active,
.drawer-fade-leave-active {
  transition: opacity 0.22s ease;
}

.drawer-fade-enter-active .history-drawer,
.drawer-fade-leave-active .history-drawer {
  transition: transform 0.22s ease;
}

.drawer-fade-enter-from,
.drawer-fade-leave-to {
  opacity: 0;
}

.drawer-fade-enter-from .history-drawer,
.drawer-fade-leave-to .history-drawer {
  transform: translate3d(28px, 0, 0);
}
</style>
