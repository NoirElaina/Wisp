export type PacketProtocol =
  | "ethernet"
  | "arp"
  | "ipv4"
  | "tcp"
  | "udp"
  | "http"
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

export interface ArpPacket {
  opcode: number
  src_mac: string
  src_ip: string
  dst_mac: string
  dst_ip: string
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
  raw_text: string
}

export interface UnknownPayload {
  preview: string
}

export type ApplicationPacket = { http: HttpMessage } | { unknown: UnknownPayload }

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
  arp: ArpPacket | null
  transport: TransportPacket | null
  application: ApplicationPacket | null
  raw: RawPacketData
  parse_notes: string[]
  is_malformed: boolean
}
