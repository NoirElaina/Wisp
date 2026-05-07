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

const filteredPackets = computed(() =>
  state.packets.filter((packet) => matchSummary(packet, state.filter)),
);

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

    try {
      const session = await invoke<CaptureSessionMeta>("stop_capture");
      state.activeSession = session;
      state.running = false;
      await refreshSessions();
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
    state.selectedPacketId = null;
    state.selectedDetail = null;

    const req: PacketQuery = {
      session_id: sessionId,
      filter: snapshotFilter(),
      offset: 0,
      limit: 0,
    };

    const page = await invoke<PacketPage>("query_packets", { req });
    state.packets = page.items;

    if (page.items.length > 0) {
      await selectPacket(page.items[0].id);
    }
  }

  async function selectPacket(packetId: number) {
    if (!state.activeSession) {
      return;
    }

    state.selectedPacketId = packetId;
    state.selectedDetail = await invoke<PacketDetail>("get_packet_detail", {
      sessionId: state.activeSession.id,
      packetId,
    });
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
  }

  function setIpFilter(value: string) {
    state.filter.ip = value.trim() ? value : null;
  }

  function setPortFilter(value: string) {
    const port = value.trim();
    if (!port) {
      state.filter.port = null;
      return;
    }

    const parsed = Number.parseInt(port, 10);
    state.filter.port = Number.isNaN(parsed) ? null : parsed;
  }

  function setSearch(value: string) {
    state.filter.query = value.trim() ? value : null;
  }

  function setOnlyMalformed(value: boolean) {
    state.filter.only_malformed = value;
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
    if (!state.activeSession || packet.session_id !== state.activeSession.id) {
      return;
    }

    state.packets = [packet, ...state.packets];

    if (!state.selectedPacketId) {
      await selectFirstPacket(packet.id);
    }
  });

  const statsUnlisten = await listen<CaptureStats>("capture:stats", (event) => {
    state.stats = event.payload.session_id ? event.payload : emptyStats();
  });

  const stateUnlisten = await listen<CaptureSessionMeta>("capture:state", (event) => {
    state.activeSession = event.payload;
    state.running = event.payload.running;
  });

  const errorUnlisten = await listen<string>("capture:error", (event) => {
    setErrorMessage(event.payload);
    void refreshSessionsSnapshot();
  });

  unlisteners = [packetUnlisten, statsUnlisten, stateUnlisten, errorUnlisten];
  listenersReady = true;
}

async function selectFirstPacket(packetId: number) {
  if (!state.activeSession) {
    return;
  }

  state.selectedPacketId = packetId;
  state.selectedDetail = await invoke<PacketDetail>("get_packet_detail", {
    sessionId: state.activeSession.id,
    packetId,
  });
}

function matchSummary(packet: PacketSummary, filter: FilterState): boolean {
  if (filter.protocols.length > 0 && !filter.protocols.includes(packet.protocol)) {
    return false;
  }

  if (filter.ip) {
    const ip = filter.ip.toLowerCase();
    if (!packet.src.toLowerCase().includes(ip) && !packet.dst.toLowerCase().includes(ip)) {
      return false;
    }
  }

  if (filter.port && !packet.info.includes(filter.port.toString())) {
    return false;
  }

  if (filter.query) {
    const query = filter.query.toLowerCase();
    const corpus = `${packet.info} ${packet.src} ${packet.dst} ${packet.protocol}`.toLowerCase();
    if (!corpus.includes(query)) {
      return false;
    }
  }

  if (filter.only_malformed && !packet.is_malformed) {
    return false;
  }

  return true;
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

void unlisteners;
