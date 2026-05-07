<script setup lang="ts">
import type { PacketSummary } from "../../types/packet";
import PacketRow from "./PacketRow.vue";

defineProps<{
  packets: PacketSummary[]
  selectedId: number | null
}>();

defineEmits<{
  (event: "select", packetId: number): void
}>();
</script>

<template>
  <div class="table-shell">
    <div class="table-head">
      <div>
        <p class="eyebrow">实时流</p>
        <h2>数据包列表</h2>
      </div>
      <span>{{ packets.length }} 条可见记录</span>
    </div>

    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>源地址</th>
            <th>目标地址</th>
            <th>协议</th>
            <th>长度</th>
            <th>信息</th>
          </tr>
        </thead>
        <tbody>
          <PacketRow
            v-for="packet in packets"
            :key="packet.id"
            :packet="packet"
            :selected="packet.id === selectedId"
            @select="$emit('select', $event)"
          />
        </tbody>
      </table>
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

table {
  width: 100%;
  border-collapse: collapse;
}

thead th {
  position: sticky;
  top: 0;
  z-index: 1;
  padding: 10px 12px;
  background: rgba(248, 250, 252, 0.96);
  border-bottom: 1px solid var(--line);
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  text-align: left;
}
</style>
