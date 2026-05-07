<script setup lang="ts">
import type { PacketSummary } from "../../types/packet";
import { protocolColor } from "../../utils/color";
import { formatProtocol, formatTimestamp } from "../../utils/format";

defineProps<{
  packet: PacketSummary
  selected: boolean
}>();

defineEmits<{
  (event: "select", packetId: number): void
}>();
</script>

<template>
  <tr :class="{ selected }" @click="$emit('select', packet.id)">
    <td>{{ formatTimestamp(packet.ts_unix_ms) }}</td>
    <td class="mono">{{ packet.src }}</td>
    <td class="mono">{{ packet.dst }}</td>
    <td>
      <span class="protocol" :style="{ color: protocolColor(packet.protocol) }">
        {{ formatProtocol(packet.protocol) }}
      </span>
    </td>
    <td class="mono">{{ packet.length }}</td>
    <td class="info">{{ packet.info }}</td>
  </tr>
</template>

<style scoped>
tr {
  cursor: pointer;
}

td {
  padding: 10px 12px;
  border-top: 1px solid rgba(12, 18, 28, 0.05);
  white-space: nowrap;
  color: var(--text);
}

tr:hover td {
  background: rgba(12, 18, 28, 0.025);
}

tr.selected td {
  background: rgba(21, 94, 239, 0.065);
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
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
