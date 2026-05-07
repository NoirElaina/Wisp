export const PROTOCOL_COLORS: Record<string, string> = {
  http: "#f79009",
  tcp: "#155eef",
  udp: "#039855",
  arp: "#7a5af8",
  ipv4: "#0f766e",
  unknown: "#98a2b3",
  ethernet: "#344054",
};

export function protocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol] ?? PROTOCOL_COLORS.unknown;
}
