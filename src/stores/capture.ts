import { computed, reactive } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type { FilterState, PacketQuery } from "../types/filter";
import type { PacketDetail, PacketPage, PacketSummary } from "../types/packet";
import type {
  CaptureRuntimeState,
  CaptureSessionMeta,
  NetworkInterface,
  StartCaptureRequest,
} from "../types/session";
import type { CaptureStats } from "../types/stats";

const FILTER_REFRESH_DELAY_MS = 140;

const state = reactive({
  initialized: false,
  busy: false,
  running: false,
  selectedInterface: "",
  interfaces: [] as NetworkInterface[],
  sessions: [] as CaptureSessionMeta[],
  packets: [] as PacketSummary[],
  selectedPacketId: null as number | null,
  selectedDetail: null as PacketDetail | null,
  activeSession: null as CaptureSessionMeta | null,
  filter: {
    protocols: [],
    ip: null,
    port: null,
    query: null,
    only_malformed: false,
  } as FilterState,
  stats: null as CaptureStats | null,
  errorMessage: "",
});

let listenersReady = false;
let unlisteners: UnlistenFn[] = [];
let errorTimer: number | null = null;
let filterRefreshTimer: number | null = null;
let packetViewRequestId = 0;
let detailRequestId = 0;
const packetIds = new Set<number>();

const filteredPackets = computed(() => state.packets);

const selectedSummary = computed(
  () => state.packets.find((packet) => packet.id === state.selectedPacketId) ?? null,
);

export function useCaptureStore() {
  async function init() {
    if (!listenersReady) {
      await attachListeners();
    }

    await refreshInterfaces();
    await refreshSessions();
    await restoreRuntimeState();

    if (state.activeSession) {
      await loadSession(state.activeSession.id);
    }

    state.initialized = true;
  }

  async function refreshInterfaces() {
    state.interfaces = await invoke<NetworkInterface[]>("list_interfaces");
  }

  async function refreshSessions() {
    state.sessions = await invoke<CaptureSessionMeta[]>("list_sessions");
  }

  async function startCapture() {
    if (!state.selectedInterface || state.busy) {
      return;
    }

    state.busy = true;
    clearError();

    try {
      state.packets = [];
      packetIds.clear();
      state.selectedPacketId = null;
      state.selectedDetail = null;
      state.stats = emptyStats();

      const req: StartCaptureRequest = {
        interface_name: state.selectedInterface,
        filter: snapshotFilter(),
      };

      const session = await invoke<CaptureSessionMeta>("start_capture", { req });
      state.activeSession = session;
      state.running = true;
      await refreshSessions();
    } catch (error) {
      setErrorMessage(normalizeError(error));
      await refreshSessions();
    } finally {
      state.busy = false;
    }
  }

  async function stopCapture() {
    if (state.busy) {
      return;
    }

    state.busy = true;
    clearError();
    state.running = false;

    try {
      const session = await invoke<CaptureSessionMeta>("stop_capture");
      state.activeSession = session;
      state.selectedInterface = session.interface_name;
      await refreshSessions();
      await loadSession(session.id);
    } catch (error) {
      setErrorMessage(normalizeError(error));
      await refreshSessions();
    } finally {
      state.busy = false;
    }
  }

  async function loadSession(sessionId: string) {
    const session = state.sessions.find((item) => item.id === sessionId) ?? null;
    state.activeSession = session;
    state.running = session?.running ?? false;
    if (session) {
      state.selectedInterface = session.interface_name;
    }

    await refreshPacketView({
      sessionId,
      preserveSelection: false,
      refreshStats: true,
    });
  }

  async function selectPacket(packetId: number) {
    await loadSelectedDetail(packetId);
  }

  function setSelectedInterface(name: string) {
    state.selectedInterface = name;
  }

  function toggleProtocol(protocol: string) {
    const protocols = new Set(state.filter.protocols);
    if (protocols.has(protocol)) {
      protocols.delete(protocol);
    } else {
      protocols.add(protocol);
    }
    state.filter.protocols = Array.from(protocols);
    schedulePacketRefresh();
  }

  function setIpFilter(value: string) {
    state.filter.ip = value.trim() ? value : null;
    schedulePacketRefresh();
  }

  function setPortFilter(value: string) {
    const port = value.trim();
    if (!port) {
      state.filter.port = null;
      schedulePacketRefresh();
      return;
    }

    const parsed = Number.parseInt(port, 10);
    state.filter.port = Number.isNaN(parsed) ? null : parsed;
    schedulePacketRefresh();
  }

  function setSearch(value: string) {
    state.filter.query = value.trim() ? value : null;
    schedulePacketRefresh();
  }

  function setOnlyMalformed(value: boolean) {
    state.filter.only_malformed = value;
    schedulePacketRefresh();
  }

  return {
    state,
    filteredPackets,
    selectedSummary,
    init,
    loadSession,
    refreshSessions,
    selectPacket,
    setSelectedInterface,
    startCapture,
    stopCapture,
    toggleProtocol,
    setIpFilter,
    setPortFilter,
    setSearch,
    setOnlyMalformed,
    clearError,
  };
}

async function attachListeners() {
  const packetUnlisten = await listen<PacketSummary>("capture:packet", async (event) => {
    const packet = event.payload;
    const activeSessionId = state.activeSession?.id;
    if (!state.running || !activeSessionId || packet.session_id !== activeSessionId) {
      return;
    }

    if (await shouldIncludeLivePacket(packet)) {
      if (!state.running || state.activeSession?.id !== activeSessionId) {
        return;
      }

      prependPacket(packet);

      if (!state.selectedPacketId) {
        await selectFirstPacket(packet.id);
      }
    }
  });

  const statsUnlisten = await listen<CaptureStats>("capture:stats", (event) => {
    if (!state.running) {
      return;
    }

    if (!event.payload.session_id) {
      return;
    }

    if (state.activeSession && event.payload.session_id !== state.activeSession.id) {
      return;
    }

    state.stats = event.payload;
  });

  const stateUnlisten = await listen<CaptureSessionMeta>("capture:state", (event) => {
    state.activeSession = event.payload;
    state.running = event.payload.running;
    state.selectedInterface = event.payload.interface_name;
  });

  const errorUnlisten = await listen<string>("capture:error", (event) => {
    setErrorMessage(event.payload);
    void refreshSessionsSnapshot();
  });

  unlisteners = [packetUnlisten, statsUnlisten, stateUnlisten, errorUnlisten];
  listenersReady = true;
}

async function shouldIncludeLivePacket(packet: PacketSummary): Promise<boolean> {
  const filter = snapshotFilter();
  if (!hasActiveFilter(filter)) {
    return true;
  }

  const sessionId = state.activeSession?.id;
  if (!sessionId) {
    return false;
  }

  const detail = await invoke<PacketDetail>("get_packet_detail", {
    sessionId,
    packetId: packet.id,
  });
  return matchesDetail(detail, filter);
}

async function refreshPacketView(options?: {
  sessionId?: string
  preserveSelection?: boolean
  refreshStats?: boolean
}) {
  const sessionId = options?.sessionId ?? state.activeSession?.id;
  if (!sessionId) {
    replacePackets([]);
    state.selectedPacketId = null;
    state.selectedDetail = null;
    state.stats = emptyStats();
    return;
  }

  const session = state.sessions.find((item) => item.id === sessionId) ?? state.activeSession;
  if (session) {
    state.activeSession = session;
    state.running = session.running;
    state.selectedInterface = session.interface_name;
  }

  const preserveSelection = options?.preserveSelection ?? true;
  const refreshStats = options?.refreshStats ?? !state.running;
  const previousSelectedId = preserveSelection ? state.selectedPacketId : null;
  const requestId = ++packetViewRequestId;

  const visibleReq: PacketQuery = {
    session_id: sessionId,
    filter: snapshotFilter(),
    offset: 0,
    limit: 0,
  };

  const statsReq: PacketQuery = {
    session_id: sessionId,
    filter: null,
    offset: 0,
    limit: 0,
  };

  const [visiblePage, statsPage] = await Promise.all([
    invoke<PacketPage>("query_packets", { req: visibleReq }),
    refreshStats ? invoke<PacketPage>("query_packets", { req: statsReq }) : Promise.resolve(null),
  ]);

  if (requestId !== packetViewRequestId) {
    return;
  }

  replacePackets(visiblePage.items);

  if (refreshStats) {
    state.stats = buildStatsFromPackets(sessionId, statsPage?.items ?? []);
  }

  await syncSelection(visiblePage.items, previousSelectedId);
}

async function syncSelection(items: PacketSummary[], preferredPacketId: number | null) {
  if (items.length === 0) {
    state.selectedPacketId = null;
    state.selectedDetail = null;
    return;
  }

  const nextPacketId =
    preferredPacketId && items.some((packet) => packet.id === preferredPacketId)
      ? preferredPacketId
      : items[0].id;

  if (state.selectedPacketId === nextPacketId && state.selectedDetail?.id === nextPacketId) {
    return;
  }

  await selectFirstPacket(nextPacketId);
}

function schedulePacketRefresh() {
  if (!state.activeSession) {
    return;
  }

  if (filterRefreshTimer !== null) {
    window.clearTimeout(filterRefreshTimer);
  }

  filterRefreshTimer = window.setTimeout(() => {
    filterRefreshTimer = null;
    void refreshPacketView({
      preserveSelection: true,
      refreshStats: !state.running,
    });
  }, FILTER_REFRESH_DELAY_MS);
}

async function selectFirstPacket(packetId: number) {
  await loadSelectedDetail(packetId);
}

function hasActiveFilter(filter: FilterState): boolean {
  return (
    filter.protocols.length > 0 ||
    Boolean(filter.ip) ||
    filter.port !== null ||
    Boolean(filter.query) ||
    filter.only_malformed
  );
}

function matchesDetail(detail: PacketDetail, filter: FilterState): boolean {
  if (filter.protocols.length > 0 && !filter.protocols.includes(detail.summary.protocol)) {
    return false;
  }

  if (filter.ip) {
    const ip = filter.ip.trim().toLowerCase();
    if (
      ip &&
      !detail.summary.src.toLowerCase().includes(ip) &&
      !detail.summary.dst.toLowerCase().includes(ip)
    ) {
      return false;
    }
  }

  if (filter.port !== null) {
    const matched =
      detail.transport && "tcp" in detail.transport
        ? detail.transport.tcp.src_port === filter.port || detail.transport.tcp.dst_port === filter.port
        : detail.transport && "udp" in detail.transport
          ? detail.transport.udp.src_port === filter.port || detail.transport.udp.dst_port === filter.port
          : false;

    if (!matched) {
      return false;
    }
  }

  if (filter.only_malformed && !detail.is_malformed) {
    return false;
  }

  if (filter.query) {
    const needle = filter.query.trim().toLowerCase();
    if (needle) {
      const corpus = buildQueryCorpus(detail);
      if (!corpus.some((value) => value.includes(needle))) {
        return false;
      }
    }
  }

  return true;
}

function buildQueryCorpus(detail: PacketDetail): string[] {
  const corpus = [
    detail.summary.info.toLowerCase(),
    detail.raw.ascii_preview.toLowerCase(),
  ];

  if (detail.application) {
    if ("http" in detail.application) {
      corpus.push(detail.application.http.start_line.toLowerCase());
      corpus.push(detail.application.http.raw_text.toLowerCase());
    } else if ("tls" in detail.application) {
      corpus.push(detail.application.tls.content_type.toLowerCase());
      corpus.push(detail.application.tls.version.toLowerCase());
      if (detail.application.tls.handshake_type) {
        corpus.push(detail.application.tls.handshake_type.toLowerCase());
      }
      if (detail.application.tls.server_name) {
        corpus.push(detail.application.tls.server_name.toLowerCase());
      }
      if (detail.application.tls.cipher_suite) {
        corpus.push(detail.application.tls.cipher_suite.toLowerCase());
      }
      corpus.push(...detail.application.tls.alpn_protocols.map((item) => item.toLowerCase()));
    } else if ("dns" in detail.application) {
      corpus.push(
        ...detail.application.dns.questions.flatMap((question) => [
          question.name.toLowerCase(),
          question.qtype.toLowerCase(),
        ]),
      );
      corpus.push(
        ...detail.application.dns.answers.flatMap((answer) => [
          answer.name.toLowerCase(),
          answer.rtype.toLowerCase(),
          answer.data.toLowerCase(),
        ]),
      );
    } else if ("quic" in detail.application) {
      corpus.push(detail.application.quic.packet_type.toLowerCase());
      corpus.push(detail.application.quic.version.toLowerCase());
      corpus.push(detail.application.quic.dcid.toLowerCase());
      corpus.push(detail.application.quic.scid.toLowerCase());
    } else if ("unknown" in detail.application) {
      corpus.push(detail.application.unknown.preview.toLowerCase());
    }
  }

  if (detail.icmp) {
    corpus.push(detail.icmp.description.toLowerCase());
  }

  if (detail.icmpv6) {
    corpus.push(detail.icmpv6.description.toLowerCase());
    if (detail.icmpv6.target_address) {
      corpus.push(detail.icmpv6.target_address.toLowerCase());
    }
  }

  return corpus;
}

function emptyStats(): CaptureStats {
  return {
    session_id: "",
    packets_total: 0,
    bytes_total: 0,
    bandwidth: [],
    protocols: [],
  };
}

async function refreshSessionsSnapshot() {
  state.sessions = await invoke<CaptureSessionMeta[]>("list_sessions");
}

function replacePackets(items: PacketSummary[]) {
  packetIds.clear();
  for (const packet of items) {
    packetIds.add(packet.id);
  }
  state.packets = items;
}

function prependPacket(packet: PacketSummary) {
  if (packetIds.has(packet.id)) {
    return;
  }

  packetIds.add(packet.id);
  state.packets = [packet, ...state.packets];
}

async function loadSelectedDetail(packetId: number) {
  if (!state.activeSession) {
    return;
  }

  const sessionId = state.activeSession.id;
  const requestId = ++detailRequestId;
  state.selectedPacketId = packetId;

  const detail = await invoke<PacketDetail>("get_packet_detail", {
    sessionId,
    packetId,
  });

  if (
    requestId !== detailRequestId ||
    !state.activeSession ||
    state.activeSession.id !== sessionId ||
    state.selectedPacketId !== packetId
  ) {
    return;
  }

  state.selectedDetail = detail;
}

async function restoreRuntimeState() {
  const runtime = await invoke<CaptureRuntimeState>("get_runtime_state");
  const activeSessionId = runtime.active_session_id;

  if (!activeSessionId) {
    state.activeSession = null;
    state.running = false;
    state.stats = emptyStats();
    return;
  }

  const session = state.sessions.find((item) => item.id === activeSessionId) ?? null;
  if (!session) {
    state.activeSession = null;
    state.running = false;
    state.stats = emptyStats();
    return;
  }

  state.activeSession = session;
  state.running = true;
  state.selectedInterface = session.interface_name;
}

function normalizeError(error: unknown): string {
  if (typeof error === "string") {
    return error;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "操作失败";
}

function setErrorMessage(message: string) {
  clearErrorTimer();
  state.errorMessage = translateErrorMessage(message);
  errorTimer = window.setTimeout(() => {
    state.errorMessage = "";
    errorTimer = null;
  }, 4200);
}

function clearError() {
  clearErrorTimer();
  state.errorMessage = "";
}

function clearErrorTimer() {
  if (errorTimer !== null) {
    window.clearTimeout(errorTimer);
    errorTimer = null;
  }
}

function translateErrorMessage(message: string): string {
  switch (message) {
    case "capture is not running":
      return "当前没有正在运行的捕获任务。";
    case "capture is already running":
      return "已有一个捕获任务正在运行，请先停止后再重新开始。";
    default:
      return message;
  }
}

function snapshotFilter(): FilterState {
  return {
    protocols: [...state.filter.protocols],
    ip: state.filter.ip,
    port: state.filter.port,
    query: state.filter.query,
    only_malformed: state.filter.only_malformed,
  };
}

function buildStatsFromPackets(sessionId: string, packets: PacketSummary[]): CaptureStats {
  const protocolMap = new Map<string, { packets: number; bytes: number }>();
  const bandwidthMap = new Map<number, { bytes: number; packets: number }>();

  let bytesTotal = 0;

  for (const packet of packets) {
    bytesTotal += packet.length;

    const protocolKey = packet.protocol;
    const protocol = protocolMap.get(protocolKey) ?? { packets: 0, bytes: 0 };
    protocol.packets += 1;
    protocol.bytes += packet.length;
    protocolMap.set(protocolKey, protocol);

    const bucket = Math.floor(packet.ts_unix_ms / 1000) * 1000;
    const bandwidth = bandwidthMap.get(bucket) ?? { bytes: 0, packets: 0 };
    bandwidth.bytes += packet.length;
    bandwidth.packets += 1;
    bandwidthMap.set(bucket, bandwidth);
  }

  const protocols = Array.from(protocolMap.entries())
    .map(([protocol, values]) => ({
      protocol,
      packets: values.packets,
      bytes: values.bytes,
    }))
    .sort((left, right) => right.packets - left.packets);

  const bandwidth = Array.from(bandwidthMap.entries())
    .sort(([left], [right]) => left - right)
    .map(([ts_unix_ms, values]) => ({
      ts_unix_ms,
      bytes_per_sec: values.bytes,
      packets_per_sec: values.packets,
    }));

  return {
    session_id: sessionId,
    packets_total: packets.length,
    bytes_total: bytesTotal,
    bandwidth,
    protocols,
  };
}

void unlisteners;
