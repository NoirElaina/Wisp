<script setup lang="ts">
import type { PacketDetail } from "../../types/packet";

const props = defineProps<{
  packet: PacketDetail
}>();

function transportLabel() {
  if (!props.packet.transport) {
    return "传输层";
  }

  if ("tcp" in props.packet.transport) {
    const tcp = props.packet.transport.tcp;
    return `TCP ${tcp.src_port} → ${tcp.dst_port}`;
  }

  const udp = props.packet.transport.udp;
  return `UDP ${udp.src_port} → ${udp.dst_port}`;
}

function applicationLabel() {
  if (!props.packet.application) {
    return "应用层";
  }

  if ("http" in props.packet.application) {
    return props.packet.application.http.is_request ? "HTTP 请求" : "HTTP 响应";
  }

  return "应用层载荷";
}
</script>

<template>
  <ul class="tree">
    <li v-if="packet.ethernet">
      <strong>Ethernet II</strong>
      <span>{{ packet.ethernet.src_mac }} → {{ packet.ethernet.dst_mac }}</span>
    </li>
    <li v-if="packet.ipv4">
      <strong>IPv4</strong>
      <span>{{ packet.ipv4.src_ip }} → {{ packet.ipv4.dst_ip }}</span>
    </li>
    <li v-if="packet.arp">
      <strong>ARP</strong>
      <span>{{ packet.arp.src_ip }} 正在查询 {{ packet.arp.dst_ip }}</span>
    </li>
    <li v-if="packet.transport">
      <strong>{{ transportLabel() }}</strong>
      <span>序列号、长度等字段均为手动解析</span>
    </li>
    <li v-if="packet.application">
      <strong>{{ applicationLabel() }}</strong>
      <span>可查看原始内容预览</span>
    </li>
  </ul>
</template>

<style scoped>
.tree {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  padding: 0;
  margin: 0;
  list-style: none;
}

.tree li {
  display: grid;
  gap: 4px;
  align-content: start;
  min-height: 74px;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.74);
}

.tree strong {
  font-size: 13px;
}

.tree span {
  color: var(--muted);
  font-size: 12px;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  overflow-wrap: anywhere;
}
</style>
