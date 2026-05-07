<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

import type { CaptureStats } from "../../types/stats";
import { formatBytes } from "../../utils/format";

const props = defineProps<{
  stats: CaptureStats | null
}>();

const canvas = ref<HTMLCanvasElement | null>(null);

function draw() {
  const el = canvas.value;
  if (!el) {
    return;
  }

  const rect = el.getBoundingClientRect();
  const width = Math.max(rect.width, 320);
  const height = 210;
  const dpr = window.devicePixelRatio || 1;
  el.width = width * dpr;
  el.height = height * dpr;

  const ctx = el.getContext("2d");
  if (!ctx) {
    return;
  }

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(15, 23, 42, 0.08)";
  ctx.lineWidth = 1;
  for (let index = 0; index < 4; index += 1) {
    const y = 26 + index * 44;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  const points = props.stats?.bandwidth ?? [];
  if (points.length === 0) {
    ctx.fillStyle = "#98a2b3";
    ctx.font = "13px Segoe UI";
    ctx.fillText("等待数据包流入…", 14, 38);
    return;
  }

  const maxBytes = Math.max(...points.map((point) => point.bytes_per_sec), 1);
  const chartHeight = 148;
  const chartTop = 24;
  const chartBottom = chartTop + chartHeight;
  const step = points.length > 1 ? width / (points.length - 1) : width;

  ctx.beginPath();
  points.forEach((point, index) => {
    const x = index * step;
    const y = chartBottom - (point.bytes_per_sec / maxBytes) * chartHeight;
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  const gradient = ctx.createLinearGradient(0, chartTop, 0, chartBottom);
  gradient.addColorStop(0, "rgba(21, 94, 239, 0.32)");
  gradient.addColorStop(1, "rgba(21, 94, 239, 0.02)");
  ctx.strokeStyle = "#155eef";
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.lineTo(width, chartBottom);
  ctx.lineTo(0, chartBottom);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.fillStyle = "#667085";
  ctx.font = "12px Segoe UI";
  ctx.fillText(formatBytes(maxBytes), 12, 16);
  ctx.fillText("0 B", 12, chartBottom + 18);
}

function redraw() {
  requestAnimationFrame(draw);
}

onMounted(() => {
  redraw();
  window.addEventListener("resize", redraw);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", redraw);
});

watch(
  () => props.stats,
  () => redraw(),
  { deep: true },
);
</script>

<template>
  <div class="chart">
    <div class="chart-head">
      <div>
        <p class="eyebrow">流量</p>
        <h3>带宽时间线</h3>
      </div>
      <span>{{ stats?.bandwidth.length ?? 0 }} 个点</span>
    </div>
    <canvas ref="canvas" />
  </div>
</template>

<style scoped>
.chart {
  display: grid;
  grid-template-rows: auto 1fr;
  height: 100%;
}

.chart-head {
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

span {
  color: var(--muted);
  font-size: 12px;
}

canvas {
  width: 100%;
  height: 210px;
}
</style>
