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

  if ("tls" in props.packet.application) {
    return props.packet.application.tls.handshake_type
      ? `${props.packet.summary.protocol === "https" ? "HTTPS" : "TLS"} ${props.packet.application.tls.handshake_type}`
      : "TLS 记录";
  }

  if ("dns" in props.packet.application) {
    return props.packet.application.dns.is_response ? "DNS 响应" : "DNS 查询";
  }

  if ("quic" in props.packet.application) {
    return `QUIC ${props.packet.application.quic.packet_type}`;
  }

  return "应用层载荷";
}

function applicationHint() {
  if (!props.packet.application) {
    return "等待上层协议识别";
  }

  if ("http" in props.packet.application) {
    return props.packet.application.http.start_line;
  }

  if ("tls" in props.packet.application) {
    const tls = props.packet.application.tls;
    const name = tls.server_name ? ` · ${tls.server_name}` : "";
    const alpn = tls.alpn_protocols.length > 0 ? ` [${tls.alpn_protocols.join(", ")}]` : "";
    return `${tls.version} · ${tls.content_type}${name}${alpn}`;
  }

  if ("dns" in props.packet.application) {
    const dns = props.packet.application.dns;
    const subject = dns.questions[0] ? `${dns.questions[0].qtype} ${dns.questions[0].name}` : "Message";
    return dns.is_response ? `响应 ${subject}` : `查询 ${subject}`;
  }

  if ("quic" in props.packet.application) {
    const quic = props.packet.application.quic;
    return `${quic.version} · DCID ${quic.dcid || "—"}`;
  }

  return "可查看原始内容预览";
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
    <li v-if="packet.ipv6">
      <strong>IPv6</strong>
      <span>{{ packet.ipv6.src_ip }} → {{ packet.ipv6.dst_ip }}</span>
    </li>
    <li v-if="packet.arp">
      <strong>ARP</strong>
      <span>{{ packet.arp.src_ip }} 正在查询 {{ packet.arp.dst_ip }}</span>
    </li>
    <li v-if="packet.icmp">
      <strong>ICMP</strong>
      <span>{{ packet.icmp.description }}</span>
    </li>
    <li v-if="packet.icmpv6">
      <strong>ICMPv6</strong>
      <span>{{ packet.icmpv6.target_address ?? packet.icmpv6.description }}</span>
    </li>
    <li v-if="packet.transport">
      <strong>{{ transportLabel() }}</strong>
      <span>序列号、长度等字段均为手动解析</span>
    </li>
    <li v-if="packet.application">
      <strong>{{ applicationLabel() }}</strong>
      <span>{{ applicationHint() }}</span>
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
