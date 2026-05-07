<script setup lang="ts">
import { computed, toRef } from "vue";
import { useVirtualList } from "@vueuse/core";

import type { PacketSummary } from "../../types/packet";
import { protocolColor } from "../../utils/color";
import { formatProtocol, formatTimestamp } from "../../utils/format";

const ROW_HEIGHT = 46;
const COLUMN_TEMPLATE = "140px minmax(220px,1.05fr) minmax(220px,1.05fr) 90px 84px minmax(320px,2fr)";

const props = defineProps<{
  packets: PacketSummary[]
  selectedId: number | null
  totalCount: number
  livePacketWindow?: number
}>();

defineEmits<{
  (event: "select", packetId: number): void
}>();

const packetsRef = toRef(props, "packets");
const { list, containerProps, wrapperProps } = useVirtualList(packetsRef, {
  itemHeight: ROW_HEIGHT,
  overscan: 12,
});

const visibleLabel = computed(() =>
  props.livePacketWindow && props.totalCount > props.livePacketWindow
    ? `当前显示最近 ${props.packets.length} / 累计 ${props.totalCount} 条`
    : `${props.packets.length} 条可见记录`,
);
</script>

<template>
  <div class="table-shell">
    <div class="table-head">
      <div>
        <p class="eyebrow">实时流</p>
        <h2>数据包列表</h2>
      </div>
      <span>{{ visibleLabel }}</span>
    </div>

    <div class="table-scroll" v-bind="containerProps">
      <div class="table-header-row">
        <span>时间</span>
        <span>源地址</span>
        <span>目标地址</span>
        <span>协议</span>
        <span>长度</span>
        <span>信息</span>
      </div>

      <div class="table-inner" v-bind="wrapperProps">
        <div
          v-for="row in list"
          :key="row.data.id"
          class="table-row"
          :class="{ selected: row.data.id === selectedId }"
          @click="$emit('select', row.data.id)"
        >
          <span>{{ formatTimestamp(row.data.ts_unix_ms) }}</span>
          <span class="mono">{{ row.data.src }}</span>
          <span class="mono">{{ row.data.dst }}</span>
          <span class="protocol" :style="{ color: protocolColor(row.data.protocol) }">
            {{ formatProtocol(row.data.protocol) }}
          </span>
          <span class="mono">{{ row.data.length }}</span>
          <span class="info">{{ row.data.info }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.table-shell {
  display: grid;
  grid-template-rows: auto 1fr;
  height: 100%;
  min-height: 0;
}

.table-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 18px;
  border-bottom: 1px solid var(--line);
}

.eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

h2 {
  margin: 0;
  font-size: 16px;
}

.table-head span {
  color: var(--muted);
  font-size: 12px;
}

.table-scroll {
  overflow: auto;
  min-height: 0;
}

.table-inner {
  position: relative;
  min-width: 0;
}

.table-header-row,
.table-row {
  display: grid;
  grid-template-columns: v-bind(COLUMN_TEMPLATE);
  align-items: center;
}

.table-header-row {
  position: sticky;
  top: 0;
  z-index: 2;
  min-height: 42px;
  padding: 0 12px;
  background: rgba(248, 250, 252, 0.96);
  border-bottom: 1px solid var(--line);
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
}

.table-row {
  min-height: 46px;
  padding: 0 12px;
  border-top: 1px solid rgba(12, 18, 28, 0.05);
  cursor: pointer;
}

.table-row:hover {
  background: rgba(12, 18, 28, 0.025);
}

.table-row.selected {
  background: rgba(21, 94, 239, 0.065);
}

.table-row span {
  min-width: 0;
  white-space: nowrap;
}

.protocol {
  font-weight: 700;
  letter-spacing: 0.03em;
}

.mono {
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
}

.info {
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
