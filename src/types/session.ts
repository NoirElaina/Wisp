import type { FilterState } from "./filter";

export interface NetworkInterface {
  name: string
  description: string
  addresses: string[]
  is_loopback: boolean
}

export interface CaptureSessionMeta {
  id: string
  name: string
  interface_name: string
  started_at_ms: number
  ended_at_ms: number | null
  packet_count: number
  bytes_captured: number
  running: boolean
}

export interface CaptureRuntimeState {
  active_session_id: string | null
}

export interface TlsDecryptionConfig {
  enabled: boolean
  keylog_path: string | null
  reload_on_change: boolean
  strict_secret_match: boolean
}

export interface StartCaptureRequest {
  interface_name: string
  filter: FilterState | null
}
