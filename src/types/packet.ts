export type PacketProtocol =
  | "ethernet"
  | "arp"
  | "ipv4"
  | "ipv6"
  | "dns"
  | "http2"
  | "icmp"
  | "icmpv6"
  | "https"
  | "quic"
  | "tcp"
  | "udp"
  | "http"
  | "tls"
  | "unknown"

export interface PacketSummary {
  id: number
  session_id: string
  ts_unix_ms: number
  frame_no: number
  src: string
  dst: string
  protocol: PacketProtocol
  length: number
  info: string
  matched: boolean
  is_malformed: boolean
}

export interface PacketPage {
  items: PacketSummary[]
  total: number
}

export interface EthernetFrame {
  src_mac: string
  dst_mac: string
  ether_type: number
}

export interface Ipv4Packet {
  version: number
  header_length: number
  total_length: number
  ttl: number
  protocol: number
  checksum: number
  src_ip: string
  dst_ip: string
}

export interface Ipv6Packet {
  version: number
  payload_length: number
  next_header: number
  hop_limit: number
  src_ip: string
  dst_ip: string
}

export interface ArpPacket {
  opcode: number
  src_mac: string
  src_ip: string
  dst_mac: string
  dst_ip: string
}

export interface IcmpPacket {
  icmp_type: number
  code: number
  identifier: number | null
  sequence: number | null
  description: string
}

export interface Icmpv6Packet {
  icmp_type: number
  code: number
  identifier: number | null
  sequence: number | null
  target_address: string | null
  description: string
}

export interface TcpFlags {
  fin: boolean
  syn: boolean
  rst: boolean
  psh: boolean
  ack: boolean
  urg: boolean
}

export interface TcpSegment {
  src_port: number
  dst_port: number
  seq: number
  ack: number
  header_length: number
  checksum: number
  window_size: number
  flags: TcpFlags
}

export interface UdpDatagram {
  src_port: number
  dst_port: number
  length: number
  checksum: number
}

export type TransportPacket = { tcp: TcpSegment } | { udp: UdpDatagram }

export interface HeaderField {
  name: string
  value: string
}

export interface HttpMessage {
  is_request: boolean
  start_line: string
  headers: HeaderField[]
  body_preview: string
  content_length: number | null
  transfer_encoding_chunked: boolean
  consumed_bytes: number
  raw_text: string
}

export interface Http2Frame {
  frame_type: string
  length: number
  flags: number
  stream_id: number
}

export interface Http2Message {
  has_preface: boolean
  frames: Http2Frame[]
}

export interface TlsMessage {
  content_type: string
  version: string
  record_length: number
  handshake_type: string | null
  server_name: string | null
  alpn_protocols: string[]
  cipher_suite: string | null
  client_random: string | null
  server_random: string | null
}

export interface DnsQuestion {
  name: string
  qtype: string
}

export interface DnsAnswer {
  name: string
  rtype: string
  data: string
  ttl: number
}

export interface DnsMessage {
  transaction_id: number
  is_response: boolean
  opcode: number
  rcode: number
  questions: DnsQuestion[]
  answers: DnsAnswer[]
}

export interface QuicMessage {
  packet_type: string
  version: string
  dcid: string
  scid: string
}

export interface UnknownPayload {
  preview: string
}

export type ApplicationPacket =
  | { http: HttpMessage }
  | { http2: Http2Message }
  | { tls: TlsMessage }
  | { dns: DnsMessage }
  | { quic: QuicMessage }
  | { unknown: UnknownPayload }

export interface FieldNode {
  name: string
  filter_key: string
  value: string
  children: FieldNode[]
}

export interface ProtocolLayerNode {
  name: string
  filter_key: string
  summary: string
  fields: FieldNode[]
}

export interface PacketArtifact {
  name: string
  content_type: string
  value: string
}

export interface ReassemblyState {
  status: string
  stream_key: string
  buffered_bytes: number
  missing_ranges: number
  note: string | null
}

export interface DecryptionState {
  attempted: boolean
  secrets_loaded: boolean
  status: string
  protocol_hint: string | null
  note: string | null
  keylog_path: string | null
}

export interface RawPacketData {
  captured_len: number
  original_len: number
  bytes_hex: string
  ascii_preview: string
}

export interface PacketDetail {
  id: number
  summary: PacketSummary
  ethernet: EthernetFrame | null
  ipv4: Ipv4Packet | null
  ipv6: Ipv6Packet | null
  arp: ArpPacket | null
  icmp: IcmpPacket | null
  icmpv6: Icmpv6Packet | null
  transport: TransportPacket | null
  application: ApplicationPacket | null
  layers: ProtocolLayerNode[]
  fields: FieldNode[]
  artifacts: PacketArtifact[]
  reassembly_state: ReassemblyState | null
  decryption_state: DecryptionState | null
  raw: RawPacketData
  parse_notes: string[]
  is_malformed: boolean
}
