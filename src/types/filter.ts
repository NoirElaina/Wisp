export interface FilterState {
  protocols: string[]
  ip: string | null
  port: number | null
  query: string | null
  only_malformed: boolean
}

export interface PacketQuery {
  session_id: string
  filter: FilterState | null
  offset: number
  limit: number
}
