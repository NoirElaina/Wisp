export interface BandwidthPoint {
  ts_unix_ms: number
  bytes_per_sec: number
  packets_per_sec: number
}

export interface ProtocolStat {
  protocol: string
  packets: number
  bytes: number
}

export interface CaptureStats {
  session_id: string
  packets_total: number
  bytes_total: number
  bandwidth: BandwidthPoint[]
  protocols: ProtocolStat[]
}
