<script setup lang="ts">
import { computed } from "vue";

import type { CaptureStats } from "../../types/stats";
import { formatBytes, formatProtocol } from "../../utils/format";
import { protocolColor } from "../../utils/color";

const props = defineProps<{
  stats: CaptureStats | null
}>();

const total = computed(() =>
  (props.stats?.protocols ?? []).reduce((sum, item) => sum + item.packets, 0),
);

const slices = computed(() => {
  const protocols = props.stats?.protocols ?? [];
  if (protocols.length === 0 || total.value === 0) {
    return [];
  }

  let start = 0;
  return protocols.map((item) => {
    const portion = item.packets / total.value;
    const end = start + portion;
    const slice = { ...item, start, end };
    start = end;
    return slice;
  });
});

function polar(cx: number, cy: number, radius: number, fraction: number) {
  const angle = fraction * Math.PI * 2 - Math.PI / 2;
  return {
    x: cx + Math.cos(angle) * radius,
    y: cy + Math.sin(angle) * radius,
  };
}

function path(start: number, end: number) {
  const startPoint = polar(86, 86, 60, start);
  const endPoint = polar(86, 86, 60, end);
  const largeArc = end - start > 0.5 ? 1 : 0;

  return [
    `M ${startPoint.x} ${startPoint.y}`,
    `A 60 60 0 ${largeArc} 1 ${endPoint.x} ${endPoint.y}`,
  ].join(" ");
}
</script>

<template>
  <div class="donut">
    <div class="donut-head">
      <div>
        <p class="eyebrow">分布</p>
        <h3>协议占比</h3>
      </div>
      <span>{{ total }} 个包</span>
    </div>

    <div class="donut-body">
      <svg viewBox="0 0 172 172" class="chart">
        <circle cx="86" cy="86" r="60" fill="none" stroke="rgba(15, 23, 42, 0.08)" stroke-width="20" />
        <path
          v-for="slice in slices"
          :key="slice.protocol"
          :d="path(slice.start, slice.end)"
          fill="none"
          :stroke="protocolColor(slice.protocol)"
          stroke-width="20"
          stroke-linecap="round"
        />
      </svg>

      <div class="legend">
        <div v-if="slices.length === 0" class="empty">暂无数据包</div>
        <div v-for="slice in slices" :key="slice.protocol" class="legend-row">
          <span class="swatch" :style="{ background: protocolColor(slice.protocol) }" />
          <strong>{{ formatProtocol(slice.protocol) }}</strong>
          <small>{{ slice.packets }} · {{ formatBytes(slice.bytes) }}</small>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.donut {
  display: grid;
  gap: 12px;
  height: 100%;
}

.donut-head {
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

span,
small {
  color: var(--muted);
}

.donut-body {
  display: grid;
  grid-template-columns: 172px 1fr;
  gap: 14px;
  align-items: center;
}

.chart {
  width: 172px;
  height: 172px;
}

.legend {
  display: grid;
  gap: 10px;
}

.legend-row {
  display: grid;
  grid-template-columns: 12px 1fr auto;
  align-items: center;
  gap: 10px;
}

.swatch {
  width: 12px;
  height: 12px;
  border-radius: 999px;
}

.legend-row strong {
  font-size: 12px;
}

.empty {
  color: var(--muted);
}
</style>
