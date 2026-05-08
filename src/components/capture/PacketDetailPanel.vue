<script setup lang="ts">
import type { PacketDetail } from "../../types/packet";
import { formatProtocol, formatTimestamp } from "../../utils/format";
import HexViewer from "./HexViewer.vue";
import ProtocolTree from "./ProtocolTree.vue";

defineProps<{
  packet: PacketDetail | null
}>();

function dnsFlagsLabel(rcode: number) {
  return rcode === 0 ? "NoError" : `RCODE=${rcode}`;
}
</script>

<template>
  <div v-if="packet" class="grid h-full min-h-0 grid-rows-[auto_1fr]">
    <header class="flex items-center justify-between gap-3 border-b border-slate-200/80 px-[18px] py-4">
      <div>
        <p class="mb-1 text-xs uppercase tracking-[0.08em] text-slate-500">详情</p>
        <h2 class="m-0 text-base font-semibold text-slate-950">#{{ packet.summary.frame_no }} · {{ formatProtocol(packet.summary.protocol) }}</h2>
      </div>
      <span class="text-xs text-slate-500">{{ formatTimestamp(packet.summary.ts_unix_ms) }}</span>
    </header>

    <div class="flex min-h-0 flex-col gap-3.5 overflow-auto p-4">
      <ProtocolTree :packet="packet" />

      <section class="grid grid-cols-2 gap-3">
        <article class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">摘要</h3>
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

        <article v-if="packet.ipv4" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">IPv4</h3>
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

        <article v-if="packet.ipv6" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">IPv6</h3>
          <dl>
            <div>
              <dt>版本</dt>
              <dd>{{ packet.ipv6.version }}</dd>
            </div>
            <div>
              <dt>Hop Limit</dt>
              <dd>{{ packet.ipv6.hop_limit }}</dd>
            </div>
            <div>
              <dt>Next Header</dt>
              <dd>{{ packet.ipv6.next_header }}</dd>
            </div>
            <div>
              <dt>负载长度</dt>
              <dd>{{ packet.ipv6.payload_length }}</dd>
            </div>
          </dl>
        </article>

        <article v-if="packet.transport && 'tcp' in packet.transport" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">TCP</h3>
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

        <article v-if="packet.transport && 'udp' in packet.transport" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">UDP</h3>
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

        <article v-if="packet.icmp" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">ICMP</h3>
          <dl>
            <div>
              <dt>类型 / 代码</dt>
              <dd>{{ packet.icmp.icmp_type }} / {{ packet.icmp.code }}</dd>
            </div>
            <div>
              <dt>语义</dt>
              <dd>{{ packet.icmp.description }}</dd>
            </div>
            <div>
              <dt>标识符</dt>
              <dd>{{ packet.icmp.identifier ?? "—" }}</dd>
            </div>
            <div>
              <dt>序号</dt>
              <dd>{{ packet.icmp.sequence ?? "—" }}</dd>
            </div>
          </dl>
        </article>

        <article v-if="packet.icmpv6" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
          <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">ICMPv6</h3>
          <dl>
            <div>
              <dt>类型 / 代码</dt>
              <dd>{{ packet.icmpv6.icmp_type }} / {{ packet.icmpv6.code }}</dd>
            </div>
            <div>
              <dt>语义</dt>
              <dd>{{ packet.icmpv6.description }}</dd>
            </div>
            <div>
              <dt>目标地址</dt>
              <dd>{{ packet.icmpv6.target_address ?? "—" }}</dd>
            </div>
            <div>
              <dt>标识符 / 序号</dt>
              <dd>{{ packet.icmpv6.identifier ?? "—" }} / {{ packet.icmpv6.sequence ?? "—" }}</dd>
            </div>
          </dl>
        </article>
      </section>

      <section v-if="packet.application && 'http' in packet.application" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <header class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">HTTP 原始内容</header>
        <pre class="m-0 overflow-auto whitespace-pre-wrap px-4 py-4 font-mono text-xs leading-[1.55]">{{ packet.application.http.raw_text }}</pre>
      </section>

      <section v-if="packet.application && 'http2' in packet.application" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <header class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">HTTP/2</header>
        <div class="grid gap-3 p-4">
          <p class="m-0 text-xs text-slate-500">
            {{ packet.application.http2.has_preface ? "已识别客户端 Preface。" : "已识别 HTTP/2 帧。" }}
          </p>
          <ul class="m-0 grid gap-2 p-0 list-none">
            <li
              v-for="(frame, index) in packet.application.http2.frames"
              :key="`${frame.frame_type}:${frame.stream_id}:${index}`"
              class="rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-xs text-slate-700"
            >
              {{ frame.frame_type }} · stream {{ frame.stream_id }} · len {{ frame.length }} · flags 0x{{ frame.flags.toString(16).padStart(2, "0") }}
            </li>
          </ul>
        </div>
      </section>

      <section v-if="packet.decrypted_application && 'http' in packet.decrypted_application" class="overflow-hidden rounded-2xl border border-emerald-200/80 bg-emerald-50/60 shadow-sm">
        <header class="m-0 border-b border-emerald-200/80 px-4 py-3 text-[13px] font-semibold text-emerald-950">解密后的 HTTP/1.x</header>
        <pre class="m-0 overflow-auto whitespace-pre-wrap px-4 py-4 font-mono text-xs leading-[1.55]">{{ packet.decrypted_application.http.raw_text }}</pre>
      </section>

      <section v-if="packet.decrypted_application && 'http2' in packet.decrypted_application" class="overflow-hidden rounded-2xl border border-emerald-200/80 bg-emerald-50/60 shadow-sm">
        <header class="m-0 border-b border-emerald-200/80 px-4 py-3 text-[13px] font-semibold text-emerald-950">解密后的 HTTP/2</header>
        <div class="grid gap-3 p-4">
          <p class="m-0 text-xs text-emerald-800">
            {{ packet.decrypted_application.http2.has_preface ? "已识别客户端 Preface。" : "已识别 HTTP/2 帧。" }}
          </p>
          <ul class="m-0 grid gap-2 p-0 list-none">
            <li
              v-for="(frame, index) in packet.decrypted_application.http2.frames"
              :key="`${frame.frame_type}:${frame.stream_id}:${index}`"
              class="rounded-xl border border-emerald-200/80 bg-white/80 px-3 py-2 text-xs text-emerald-900"
            >
              {{ frame.frame_type }} · stream {{ frame.stream_id }} · len {{ frame.length }} · flags 0x{{ frame.flags.toString(16).padStart(2, "0") }}
            </li>
          </ul>
        </div>
      </section>

      <section v-if="packet.application && 'dns' in packet.application" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <header class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">DNS</header>
        <div class="grid gap-4 p-4 md:grid-cols-2">
          <div>
            <p class="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">报文概览</p>
            <dl class="!p-0">
              <div>
                <dt>事务 ID</dt>
                <dd>0x{{ packet.application.dns.transaction_id.toString(16) }}</dd>
              </div>
              <div>
                <dt>方向</dt>
                <dd>{{ packet.application.dns.is_response ? "响应" : "查询" }}</dd>
              </div>
              <div>
                <dt>状态</dt>
                <dd>{{ dnsFlagsLabel(packet.application.dns.rcode) }}</dd>
              </div>
            </dl>
          </div>
          <div>
            <p class="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">问题区</p>
            <ul class="m-0 grid gap-2 p-0 list-none">
              <li v-for="question in packet.application.dns.questions" :key="`${question.qtype}:${question.name}`" class="rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-xs text-slate-700">
                {{ question.qtype }} {{ question.name }}
              </li>
              <li v-if="packet.application.dns.questions.length === 0" class="rounded-xl border border-dashed border-slate-200 px-3 py-2 text-xs text-slate-400">
                无问题记录
              </li>
            </ul>
          </div>
        </div>
        <div class="border-t border-slate-200/80 px-4 py-4">
          <p class="mb-2 text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">应答区</p>
          <ul class="m-0 grid gap-2 p-0 list-none">
            <li v-for="answer in packet.application.dns.answers" :key="`${answer.rtype}:${answer.name}:${answer.data}`" class="rounded-xl border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-xs text-slate-700">
              {{ answer.rtype }} {{ answer.name }} → {{ answer.data }} · TTL {{ answer.ttl }}
            </li>
            <li v-if="packet.application.dns.answers.length === 0" class="rounded-xl border border-dashed border-slate-200 px-3 py-2 text-xs text-slate-400">
              无应答记录
            </li>
          </ul>
        </div>
      </section>

      <section v-if="packet.application && 'tls' in packet.application" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">TLS</h3>
        <dl>
          <div>
            <dt>记录类型</dt>
            <dd>{{ packet.application.tls.content_type }}</dd>
          </div>
          <div>
            <dt>版本</dt>
            <dd>{{ packet.application.tls.version }}</dd>
          </div>
          <div>
            <dt>握手类型</dt>
            <dd>{{ packet.application.tls.handshake_type ?? "—" }}</dd>
          </div>
          <div>
            <dt>SNI</dt>
            <dd>{{ packet.application.tls.server_name ?? "—" }}</dd>
          </div>
          <div>
            <dt>ALPN</dt>
            <dd>{{ packet.application.tls.alpn_protocols.join(", ") || "—" }}</dd>
          </div>
          <div>
            <dt>Cipher Suite</dt>
            <dd>{{ packet.application.tls.cipher_suite ?? "—" }}</dd>
          </div>
          <div>
            <dt>Client Random</dt>
            <dd>{{ packet.application.tls.client_random ?? "—" }}</dd>
          </div>
          <div>
            <dt>Server Random</dt>
            <dd>{{ packet.application.tls.server_random ?? "—" }}</dd>
          </div>
          <div>
            <dt>记录长度</dt>
            <dd>{{ packet.application.tls.record_length }}</dd>
          </div>
        </dl>
      </section>

      <section v-if="packet.reassembly_state" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">重组状态</h3>
        <dl>
          <div>
            <dt>状态</dt>
            <dd>{{ packet.reassembly_state.status }}</dd>
          </div>
          <div>
            <dt>流标识</dt>
            <dd>{{ packet.reassembly_state.stream_key }}</dd>
          </div>
          <div>
            <dt>缓冲字节</dt>
            <dd>{{ packet.reassembly_state.buffered_bytes }}</dd>
          </div>
          <div>
            <dt>缺失区间</dt>
            <dd>{{ packet.reassembly_state.missing_ranges }}</dd>
          </div>
          <div>
            <dt>备注</dt>
            <dd>{{ packet.reassembly_state.note ?? "—" }}</dd>
          </div>
        </dl>
      </section>

      <section v-if="packet.decryption_state" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">解密状态</h3>
        <dl>
          <div>
            <dt>状态</dt>
            <dd>{{ packet.decryption_state.status }}</dd>
          </div>
          <div>
            <dt>Secrets 已加载</dt>
            <dd>{{ packet.decryption_state.secrets_loaded ? "是" : "否" }}</dd>
          </div>
          <div>
            <dt>协议提示</dt>
            <dd>{{ packet.decryption_state.protocol_hint ?? "—" }}</dd>
          </div>
          <div>
            <dt>Keylog 路径</dt>
            <dd>{{ packet.decryption_state.keylog_path ?? "—" }}</dd>
          </div>
          <div>
            <dt>备注</dt>
            <dd>{{ packet.decryption_state.note ?? "—" }}</dd>
          </div>
        </dl>
      </section>

      <section v-if="packet.application && 'quic' in packet.application" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <h3 class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">QUIC</h3>
        <dl>
          <div>
            <dt>包类型</dt>
            <dd>{{ packet.application.quic.packet_type }}</dd>
          </div>
          <div>
            <dt>版本</dt>
            <dd>{{ packet.application.quic.version }}</dd>
          </div>
          <div>
            <dt>DCID</dt>
            <dd>{{ packet.application.quic.dcid || "—" }}</dd>
          </div>
          <div>
            <dt>SCID</dt>
            <dd>{{ packet.application.quic.scid || "—" }}</dd>
          </div>
        </dl>
      </section>

      <section v-if="packet.artifacts.length > 0" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <header class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">分析产物</header>
        <div class="grid gap-3 p-4">
          <article
            v-for="artifact in packet.artifacts"
            :key="`${artifact.name}:${artifact.content_type}`"
            class="rounded-xl border border-slate-200/80 bg-slate-50/80"
          >
            <header class="border-b border-slate-200/80 px-3 py-2 text-xs font-semibold text-slate-700">
              {{ artifact.name }}
            </header>
            <pre class="m-0 overflow-auto whitespace-pre-wrap px-3 py-3 font-mono text-xs leading-[1.55]">{{ artifact.value }}</pre>
          </article>
        </div>
      </section>

      <section v-if="packet.parse_notes.length > 0" class="overflow-hidden rounded-2xl border border-slate-200/80 bg-white/80 shadow-sm">
        <header class="m-0 border-b border-slate-200/80 px-4 py-3 text-[13px] font-semibold text-slate-950">解析备注</header>
        <ul class="m-0 px-[18px] pb-[14px] pt-[10px]">
          <li v-for="note in packet.parse_notes" :key="note">{{ note }}</li>
        </ul>
      </section>

      <HexViewer :bytes-hex="packet.raw.bytes_hex" :ascii-preview="packet.raw.ascii_preview" />
    </div>
  </div>

  <div v-else class="grid h-full place-items-center p-6 text-center text-slate-500">
    <p>从左侧表格中选择一个数据包，即可查看逐层解析结果。</p>
  </div>
</template>

<style scoped>
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
  color: rgb(100 116 139);
  font-size: 12px;
}

dd {
  margin: 0;
  font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
  color: rgb(15 23 42);
}
</style>
