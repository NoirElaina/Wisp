<script setup lang="ts">
import type { PacketDetail } from "../../types/packet";
import { formatProtocol, formatTimestamp } from "../../utils/format";
import HexViewer from "./HexViewer.vue";
import ProtocolTree from "./ProtocolTree.vue";

defineProps<{
  packet: PacketDetail | null
}>();
</script>

<template>
  <div v-if="packet" class="detail-shell">
    <header class="detail-head">
      <div>
        <p class="eyebrow">详情</p>
        <h2>#{{ packet.summary.frame_no }} · {{ formatProtocol(packet.summary.protocol) }}</h2>
      </div>
      <span>{{ formatTimestamp(packet.summary.ts_unix_ms) }}</span>
    </header>

    <div class="detail-body">
      <ProtocolTree :packet="packet" />

      <section class="grid">
        <article class="kv">
          <h3>摘要</h3>
          <dl>
            <div>
              <dt>源地址</dt>
              <dd>{{ packet.summary.src }}</dd>
            </div>
            <div>
              <dt>目标地址</dt>
              <dd>{{ packet.summary.dst }}</dd>
            </div>
            <div>
              <dt>长度</dt>
              <dd>{{ packet.summary.length }} 字节</dd>
            </div>
            <div>
              <dt>信息</dt>
              <dd>{{ packet.summary.info }}</dd>
            </div>
          </dl>
        </article>

        <article v-if="packet.ipv4" class="kv">
          <h3>IPv4</h3>
          <dl>
            <div>
              <dt>版本</dt>
              <dd>{{ packet.ipv4.version }}</dd>
            </div>
            <div>
              <dt>TTL</dt>
              <dd>{{ packet.ipv4.ttl }}</dd>
            </div>
            <div>
              <dt>校验和</dt>
              <dd>0x{{ packet.ipv4.checksum.toString(16) }}</dd>
            </div>
            <div>
              <dt>总长度</dt>
              <dd>{{ packet.ipv4.total_length }}</dd>
            </div>
          </dl>
        </article>

        <article v-if="packet.transport && 'tcp' in packet.transport" class="kv">
          <h3>TCP</h3>
          <dl>
            <div>
              <dt>端口</dt>
              <dd>{{ packet.transport.tcp.src_port }} → {{ packet.transport.tcp.dst_port }}</dd>
            </div>
            <div>
              <dt>序列号</dt>
              <dd>{{ packet.transport.tcp.seq }}</dd>
            </div>
            <div>
              <dt>标志位</dt>
              <dd>
                {{ Object.entries(packet.transport.tcp.flags).filter(([, value]) => value).map(([key]) => key.toUpperCase()).join(", ") || "—" }}
              </dd>
            </div>
            <div>
              <dt>窗口大小</dt>
              <dd>{{ packet.transport.tcp.window_size }}</dd>
            </div>
          </dl>
        </article>

        <article v-if="packet.transport && 'udp' in packet.transport" class="kv">
          <h3>UDP</h3>
          <dl>
            <div>
              <dt>端口</dt>
              <dd>{{ packet.transport.udp.src_port }} → {{ packet.transport.udp.dst_port }}</dd>
            </div>
            <div>
              <dt>长度</dt>
              <dd>{{ packet.transport.udp.length }}</dd>
            </div>
            <div>
              <dt>校验和</dt>
              <dd>0x{{ packet.transport.udp.checksum.toString(16) }}</dd>
            </div>
          </dl>
        </article>
      </section>

      <section v-if="packet.application && 'http' in packet.application" class="http-block">
        <header>HTTP 原始内容</header>
        <pre>{{ packet.application.http.raw_text }}</pre>
      </section>

      <section v-if="packet.parse_notes.length > 0" class="notes">
        <header>解析备注</header>
        <ul>
          <li v-for="note in packet.parse_notes" :key="note">{{ note }}</li>
        </ul>
      </section>

      <HexViewer :bytes-hex="packet.raw.bytes_hex" :ascii-preview="packet.raw.ascii_preview" />
    </div>
  </div>

  <div v-else class="empty">
    <p>从左侧表格中选择一个数据包，即可查看逐层解析结果。</p>
  </div>
</template>

<style scoped>
.detail-shell {
  display: grid;
  grid-template-rows: auto 1fr;
  height: 100%;
}

.detail-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
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

.detail-head span {
  color: var(--muted);
  font-size: 12px;
}

.detail-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px;
  overflow: auto;
}

.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.kv,
.http-block,
.notes {
  border: 1px solid var(--line);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.72);
}

.kv h3,
.http-block header,
.notes header {
  margin: 0;
  padding: 12px 14px;
  border-bottom: 1px solid var(--line);
  font-size: 13px;
}

dl {
  display: grid;
  gap: 10px;
  margin: 0;
  padding: 14px;
}

dl div {
  display: grid;
  gap: 4px;
}

dt {
  color: var(--muted);
  font-size: 12px;
}

dd {
  margin: 0;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}

pre {
  margin: 0;
  padding: 14px;
  overflow: auto;
  white-space: pre-wrap;
  font-size: 12px;
  line-height: 1.55;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
}

ul {
  margin: 0;
  padding: 10px 18px 14px;
}

.empty {
  display: grid;
  place-items: center;
  height: 100%;
  color: var(--muted);
  padding: 24px;
  text-align: center;
}
</style>
