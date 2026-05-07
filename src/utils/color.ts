export const PROTOCOL_COLORS: Record<string, string> = {
  http: "#f79009",
  https: "#06b6d4",
  tls: "#0ba5ec",
  dns: "#f97316",
  icmp: "#e11d48",
  icmpv6: "#be123c",
  quic: "#7c3aed",
  tcp: "#155eef",
  udp: "#039855",
  arp: "#7a5af8",
  ipv4: "#0f766e",
  ipv6: "#9333ea",
  unknown: "#98a2b3",
  ethernet: "#344054",
};

export function protocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol] ?? PROTOCOL_COLORS.unknown;
}
