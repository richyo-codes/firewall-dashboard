<script lang="ts">
  import { onMount, onDestroy } from "svelte";

type PacketLogEntry = {
  timestamp: string;
  interface: string;
  source: string;
  dest: string;
  protocol: string;
  action: string;
  reason: string;
  error?: string;
  direction?: string;
  ruleId?: number;
};

  type RuleCounter = {
    ruleId: number;
    ruleLabel: string;
    evaluations: number;
    packets: number;
    bytes: number;
  };

  type Page = "traffic" | "combined" | "rules";

  type SortDirection = "asc" | "desc";
  type PacketColumn = "timestamp" | "action" | "interface" | "source" | "dest" | "protocol" | "reason" | "direction" | "ruleId";
  type RuleColumn = "ruleLabel" | "ruleId" | "evaluations" | "packets" | "bytes";
  type SortState<C extends string> = { column: C; direction: SortDirection };

  const pageMeta: Record<
    Page,
    {
      title: string;
      description: string;
    }
  > = {
    traffic: {
      title: "Firewall Dashboard",
      description: "Real-time insight into PF blocked/passed activity.",
    },
    combined: {
      title: "PF Unified Traffic",
      description: "All packet activity with pass/block state in a single view.",
    },
    rules: {
      title: "PF Rule Counters",
      description: "Rule evaluation statistics for auditing PF behaviour.",
    },
  };

  const HASH_TO_PAGE: Record<string, Page> = {
    "#traffic": "traffic",
    "#combined": "combined",
    "#rules": "rules",
  };

  let activePage: Page = "traffic";
  let backend = "pf";
  let unifiedViewEnabled = true;
  let blockedViewEnabled = true;
  let streamViewEnabled = true;
  let rulesViewEnabled = true;
  let autoRefreshTraffic = true;
  let paused = false;
  let trafficIntervalMs = 2000;
  let trafficTimer: ReturnType<typeof setInterval> | null = null;

  const MAX_TRAFFIC_ENTRIES = 1000;

  let blocked: PacketLogEntry[] = [];
  let passed: PacketLogEntry[] = [];
let combined: PacketLogEntry[] = [];
let rules: RuleCounter[] = [];

let combinedStreamController: AbortController | null = null;
let combinedStreaming = false;

  let blockedSort: SortState<PacketColumn> = { column: "timestamp", direction: "desc" };
  let passedSort: SortState<PacketColumn> = { column: "timestamp", direction: "desc" };
  let combinedSort: SortState<PacketColumn> = { column: "timestamp", direction: "desc" };
  let rulesSort: SortState<RuleColumn> = { column: "evaluations", direction: "desc" };
  let showCombinedPass = true;
  let showCombinedBlock = true;

  let trafficLoading = false;
  let trafficError: string | null = null;
  let trafficLastUpdated: Date | null = null;

let combinedLoading = false;
let combinedError: string | null = null;
let combinedLastUpdated: Date | null = null;
let combinedLoaded = false;
let combinedStreamTask: Promise<void> | null = null;

  let rulesLoading = false;
  let rulesError: string | null = null;
  let rulesLastUpdated: Date | null = null;
  let rulesLoaded = false;

  $: currentLoading =
    activePage === "traffic"
      ? trafficLoading
      : activePage === "combined"
        ? combinedLoading
        : rulesLoading;
  $: currentError =
    activePage === "traffic"
      ? trafficError
      : activePage === "combined"
        ? combinedError
        : rulesError;
  $: currentLastUpdated =
    activePage === "traffic"
      ? trafficLastUpdated
      : activePage === "combined"
        ? combinedLastUpdated
        : rulesLastUpdated;

  onMount(() => {
    if (typeof window !== "undefined") {
      const initial = HASH_TO_PAGE[window.location.hash.toLowerCase()];
      if (initial) {
        activePage = initial;
      }
    }

    loadRefreshConfig().finally(() => {
      if (!unifiedViewEnabled && activePage === "combined") {
        activePage = "traffic";
        if (typeof window !== "undefined") {
          window.location.hash = "#traffic";
        }
      }
      if (activePage === "rules") {
        loadRules();
      } else if (activePage === "combined") {
        startCombinedStream();
      } else {
        loadTraffic();
      }
      scheduleTrafficRefresh();
    });
  });

  onDestroy(() => {
    if (trafficTimer) {
      clearInterval(trafficTimer);
      trafficTimer = null;
    }
    stopCombinedStream();
  });

  function toString(value: unknown): string {
    if (typeof value === "string") return value;
    if (value == null) return "";
    return String(value);
  }

  function toNumber(value: unknown): number {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string") {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    return 0;
  }

  function normalizePackets(data: unknown): PacketLogEntry[] {
    if (!Array.isArray(data)) return [];
    const normalized = data
      .map((item) => (item && typeof item === "object" ? (item as Record<string, unknown>) : null))
      .filter((item): item is Record<string, unknown> => item !== null)
      .map((item) => ({
        timestamp: toString(item.timestamp ?? item.Timestamp),
        interface: toString(item.interface ?? item.Interface),
        source: toString(item.source ?? item.Source),
        dest: toString(item.dest ?? item.Dest ?? item.destination),
        protocol: toString(item.protocol ?? item.Protocol),
        action: toString(item.action ?? item.Action),
        reason: toString(item.reason ?? item.Reason),
        error: toString(item.error ?? item.Error),
        direction: toString(item.direction ?? item.Direction),
        ruleId: Math.trunc(toNumber(item.ruleId ?? item.RuleID)),
      }))
      .filter((entry) => Object.values(entry).some((value) => value !== ""));

    normalized.sort((a, b) => {
      const aTime = Date.parse(a.timestamp);
      const bTime = Date.parse(b.timestamp);
      if (Number.isNaN(aTime) && Number.isNaN(bTime)) return 0;
      if (Number.isNaN(aTime)) return 1;
      if (Number.isNaN(bTime)) return -1;
      return bTime - aTime;
    });

    return normalized;
  }

function packetKey(entry: PacketLogEntry): string {
  return [
    entry.timestamp ?? "",
    entry.interface ?? "",
    entry.source ?? "",
    entry.dest ?? "",
    entry.protocol ?? "",
    entry.action ?? "",
    entry.reason ?? "",
    entry.direction ?? "",
    entry.ruleId ?? "",
  ].join("|");
}

  function mergePackets(current: PacketLogEntry[], incoming: PacketLogEntry[]): PacketLogEntry[] {
    if (incoming.length === 0 && current.length <= MAX_TRAFFIC_ENTRIES) {
      return current;
    }

    const merged = [...incoming, ...current];
    const seen = new Set<string>();
    const deduped: PacketLogEntry[] = [];
    for (const entry of merged) {
      const key = packetKey(entry);
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(entry);
      if (deduped.length >= MAX_TRAFFIC_ENTRIES) {
        break;
      }
    }

    deduped.sort((a, b) => {
      const aTime = Date.parse(a.timestamp ?? "");
      const bTime = Date.parse(b.timestamp ?? "");
      if (Number.isNaN(aTime) && Number.isNaN(bTime)) return 0;
      if (Number.isNaN(aTime)) return 1;
      if (Number.isNaN(bTime)) return -1;
      return bTime - aTime;
    });

    return deduped;
  }

  function compareStrings(a: string, b: string, direction: SortDirection): number {
    return direction === "asc" ? a.localeCompare(b) : b.localeCompare(a);
  }

  function compareNumbers(a: number, b: number, direction: SortDirection): number {
    return direction === "asc" ? a - b : b - a;
  }

  function sortPacketsView(entries: PacketLogEntry[], sort: SortState<PacketColumn>): PacketLogEntry[] {
    const sorted = [...entries];
    sorted.sort((a, b) => {
      switch (sort.column) {
        case "timestamp": {
          const aTime = Date.parse(a.timestamp ?? "");
          const bTime = Date.parse(b.timestamp ?? "");
          if (Number.isNaN(aTime) && Number.isNaN(bTime)) return 0;
          if (Number.isNaN(aTime)) return sort.direction === "asc" ? -1 : 1;
          if (Number.isNaN(bTime)) return sort.direction === "asc" ? 1 : -1;
          return compareNumbers(aTime, bTime, sort.direction);
        }
        case "action":
          return compareStrings((a.action ?? "").toLowerCase(), (b.action ?? "").toLowerCase(), sort.direction);
        case "direction":
          return compareStrings((a.direction ?? "").toLowerCase(), (b.direction ?? "").toLowerCase(), sort.direction);
        case "interface":
          return compareStrings((a.interface ?? "").toLowerCase(), (b.interface ?? "").toLowerCase(), sort.direction);
        case "source":
          return compareStrings((a.source ?? "").toLowerCase(), (b.source ?? "").toLowerCase(), sort.direction);
        case "dest":
          return compareStrings((a.dest ?? "").toLowerCase(), (b.dest ?? "").toLowerCase(), sort.direction);
        case "protocol":
          return compareStrings((a.protocol ?? "").toLowerCase(), (b.protocol ?? "").toLowerCase(), sort.direction);
        case "reason":
          return compareStrings((a.reason ?? "").toLowerCase(), (b.reason ?? "").toLowerCase(), sort.direction);
        case "ruleId":
          return compareNumbers(a.ruleId ?? 0, b.ruleId ?? 0, sort.direction);
        default:
          return 0;
      }
    });
    return sorted;
  }

  function sortRulesView(entries: RuleCounter[], sort: SortState<RuleColumn>): RuleCounter[] {
    const sorted = [...entries];
    sorted.sort((a, b) => {
      switch (sort.column) {
        case "ruleLabel":
          return compareStrings(a.ruleLabel ?? "", b.ruleLabel ?? "", sort.direction);
        case "ruleId":
          return compareNumbers(a.ruleId ?? 0, b.ruleId ?? 0, sort.direction);
        case "evaluations":
          return compareNumbers(a.evaluations ?? 0, b.evaluations ?? 0, sort.direction);
        case "packets":
          return compareNumbers(a.packets ?? 0, b.packets ?? 0, sort.direction);
        case "bytes":
          return compareNumbers(a.bytes ?? 0, b.bytes ?? 0, sort.direction);
        default:
          return 0;
      }
    });
    return sorted;
  }

  async function loadRefreshConfig() {
    try {
      const response = await fetch("/api/config/refresh");
      if (!response.ok) {
        throw new Error(`refresh config request failed: ${response.statusText}`);
      }
      const data = (await response.json()) as {
        trafficIntervalMs?: number;
        backend?: string;
        unifiedViewEnabled?: boolean;
        supportsUnifiedView?: boolean;
        supportsBlockedPacketDetails?: boolean;
        supportsTrafficStream?: boolean;
        supportsRuleCounters?: boolean;
      };
      if (data?.trafficIntervalMs && data.trafficIntervalMs > 0) {
        trafficIntervalMs = data.trafficIntervalMs;
      }
      if (typeof data?.backend === "string" && data.backend.trim() !== "") {
        backend = data.backend.toLowerCase();
      }
      unifiedViewEnabled =
        data?.supportsUnifiedView === true || data?.unifiedViewEnabled === true || backend === "pf";
      blockedViewEnabled = data?.supportsBlockedPacketDetails === true || backend === "pf";
      streamViewEnabled = data?.supportsTrafficStream === true || backend === "pf";
      rulesViewEnabled = data?.supportsRuleCounters !== false;
    } catch (err) {
      console.warn("failed to load refresh config", err);
    }
  }

  $: blockedView = sortPacketsView(blocked, blockedSort);
  $: passedView = sortPacketsView(passed, passedSort);
  $: combinedView = sortPacketsView(combined, combinedSort);
  $: combinedFilteredView = combinedView.filter((entry) => {
    const action = (entry?.action ?? "").toLowerCase();
    if (action === "pass") return showCombinedPass;
    if (action === "block") return showCombinedBlock;
    return true;
  });
  $: rulesView = sortRulesView(rules, rulesSort);

  function updateSort<C extends string>(state: SortState<C>, column: C): SortState<C> {
    if (state.column === column) {
      return { column, direction: state.direction === "asc" ? "desc" : "asc" };
    }
    return { column, direction: "desc" };
  }

  function toggleBlockedSort(column: PacketColumn) {
    blockedSort = updateSort(blockedSort, column);
  }

  function togglePassedSort(column: PacketColumn) {
    passedSort = updateSort(passedSort, column);
  }

  function toggleCombinedSort(column: PacketColumn) {
    combinedSort = updateSort(combinedSort, column);
  }

  function toggleRulesSort(column: RuleColumn) {
    rulesSort = updateSort(rulesSort, column);
  }

  function sortIndicator<C extends string>(state: SortState<C>, column: C): string {
    if (state.column !== column) return "";
    return state.direction === "asc" ? "▲" : "▼";
  }

  const streamRegex = /^(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+rule\s+(?<rule>\d+\/\d+)\(match\):\s+(?<action>[A-Za-z]+)\s+(?<direction>in|out)\s+on\s+(?<iface>[^:]+):\s+(?<payload>.*)$/;

  function parseStreamLine(line: string): PacketLogEntry | null {
    const match = streamRegex.exec(line);
    if (!match || !match.groups) {
      return null;
    }

    const { date, time, rule, action, direction, iface, payload } = match.groups;
    const timestamp = new Date(`${date}T${time}`).toISOString();
    const ruleId = parseRuleId(rule);
    const [traffic, meta] = splitStreamPayload(payload ?? "");
    const [source, dest] = parseStreamEndpoints(traffic);
    const protocol = detectProtocol(meta ?? "");

    return {
      timestamp,
      interface: iface?.trim() ?? "",
      source,
      dest,
      protocol,
      action: (action ?? "").toLowerCase() || "unknown",
      reason: meta?.trim() ?? "pflog",
      direction: (direction ?? "").toLowerCase() || "unknown",
      ruleId,
    };
  }

  function splitStreamPayload(payload: string): [string, string] {
    const idx = payload.indexOf(": ");
    if (idx === -1) {
      return [payload, ""];
    }
    return [payload.slice(0, idx), payload.slice(idx + 2)];
  }

  function parseStreamEndpoints(traffic: string): [string, string] {
    const parts = traffic.split(" > ");
    if (parts.length !== 2) {
      const trimmed = traffic.trim();
      return [trimmed, ""];
    }
    return [parts[0].trim(), parts[1].trim()];
  }

  function parseRuleId(rule: string | undefined): number {
    if (!rule) return 0;
    const slash = rule.indexOf("/");
    const idStr = slash === -1 ? rule : rule.slice(0, slash);
    const parsed = Number.parseInt(idStr, 10);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function detectProtocol(meta: string): string {
    const lower = meta.toLowerCase();
    if (lower.includes("proto tcp") || lower.includes("flags [")) return "tcp";
    if (lower.includes("proto udp")) return "udp";
    if (lower.includes("proto icmp")) return "icmp";
    if (lower.includes("proto gre")) return "gre";
    return "unknown";
  }

  function normalizeRules(data: unknown): RuleCounter[] {
    if (!Array.isArray(data)) return [];
    return data
      .map((item) => (item && typeof item === "object" ? (item as Record<string, unknown>) : null))
      .filter((item): item is Record<string, unknown> => item !== null)
      .map((item) => ({
        ruleId: Math.trunc(toNumber(item.ruleId ?? item.RuleID)),
        ruleLabel: toString(item.ruleLabel ?? item.RuleLabel ?? item.label),
        evaluations: toNumber(item.evaluations ?? item.Evaluations),
        packets: toNumber(item.packets ?? item.Packets),
        bytes: toNumber(item.bytes ?? item.Bytes),
      }));
  }

  async function fetchJSON(path: string): Promise<unknown> {
    const response = await fetch(path);
    if (!response.ok) {
      throw new Error(`failed to load ${path}: ${response.statusText}`);
    }
    return response.json() as Promise<unknown>;
  }

  async function loadTraffic() {
    if (paused) return;
    if (trafficLoading) return;
    trafficLoading = true;
    trafficError = null;
    try {
      const [blockedResp, passedResp] = await Promise.all([fetchJSON("/api/blocked"), fetchJSON("/api/passed")]);
      blocked = mergePackets(blocked, normalizePackets(blockedResp));
      passed = mergePackets(passed, normalizePackets(passedResp));
      trafficLastUpdated = new Date();
    } catch (err) {
      if (err instanceof Error) {
        trafficError = err.message;
      } else {
        trafficError = "unknown error";
      }
    } finally {
      trafficLoading = false;
    }
  }

  async function loadCombined(force = false) {
    if (paused) return;
    if (combinedLoading) return;
    if (combinedLoaded && !force) return;
    combinedLoading = true;
    combinedError = null;
    try {
      const trafficResp = await fetchJSON("/api/traffic");
      combined = mergePackets(combined, normalizePackets(trafficResp));
      combinedLastUpdated = new Date();
      combinedLoaded = true;
    } catch (err) {
      if (err instanceof Error) {
        combinedError = err.message;
      } else {
        combinedError = "unknown error";
      }
      combinedLoaded = false;
    } finally {
      combinedLoading = false;
    }
  }

  async function startCombinedStream(force = false) {
    if (paused) return;
    if (combinedStreaming && !force) return;
    stopCombinedStream();
    if (!force && combined.length === 0) {
      await loadCombined(true);
    }

    combinedLoading = true;
    combinedError = null;
    const controller = new AbortController();
    combinedStreamController = controller;
    try {
      const response = await fetch("/api/stream/traffic", {
        signal: controller.signal,
      });
      if (!response.ok) {
        if (response.status === 501) {
          combinedError = "Streaming not supported on this backend";
          combinedStreaming = false;
          combinedLoading = false;
          stopCombinedStream();
          loadCombined(true);
          return;
        }
        throw new Error(`stream request failed: ${response.statusText}`);
      }
      const body = response.body;
      if (!body) {
        throw new Error("stream response missing body");
      }
      const reader = body.getReader();
      const decoder = new TextDecoder();
      combinedLoaded = true;
      combinedLoading = false;
      combinedStreaming = true;
      let buffer = "";
      combinedStreamTask = (async () => {
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            buffer = processStreamBuffer(buffer);
          }
        } finally {
          combinedStreaming = false;
        }
      })();
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) {
        if (err instanceof Error) {
          combinedError = err.message;
        } else {
          combinedError = "stream error";
        }
        combinedStreaming = false;
        combinedLoading = false;
      }
    }
  }

  function stopCombinedStream() {
    if (combinedStreamController) {
      combinedStreamController.abort();
      combinedStreamController = null;
    }
    combinedStreaming = false;
    combinedStreamTask = null;
  }

  function processStreamBuffer(buffer: string) {
    const lines = buffer.split(/\r?\n/);
    let remainder = lines.pop() ?? "";
    for (const line of lines) {
      if (paused) {
        break;
      }
      const entry = parseStreamLine(line);
      if (!entry) continue;
      combined = mergePackets(combined, [entry]);
      if (entry.timestamp) {
        combinedLastUpdated = new Date();
      }
    }
    return remainder;
  }

  async function loadRules(force = false) {
    if (paused) return;
    if (rulesLoading) return;
    if (rulesLoaded && !force) return;
    rulesLoading = true;
    rulesError = null;
    try {
      const rulesResp = await fetchJSON("/api/rules");
      rules = normalizeRules(rulesResp);
      rulesLastUpdated = new Date();
      rulesLoaded = true;
    } catch (err) {
      if (err instanceof Error) {
        rulesError = err.message;
      } else {
        rulesError = "unknown error";
      }
      rulesLoaded = false;
    } finally {
      rulesLoading = false;
    }
  }

  function refreshActive() {
    if (paused) return;
    if (activePage === "traffic") {
      loadTraffic();
    } else if (activePage === "combined" && unifiedViewEnabled && streamViewEnabled) {
      startCombinedStream(true);
    } else {
      loadRules(true);
    }
  }

  function scheduleTrafficRefresh() {
    if (trafficTimer) {
      clearInterval(trafficTimer);
      trafficTimer = null;
    }
    if (paused) {
      return;
    }
    if (autoRefreshTraffic && activePage === "traffic") {
      trafficTimer = setInterval(() => {
        if (activePage === "traffic" && !paused) {
          loadTraffic();
        }
      }, trafficIntervalMs);
    }
  }

  $: scheduleTrafficRefresh();

  function setActivePage(page: Page) {
    if (page === "combined" && !unifiedViewEnabled) {
      page = "traffic";
    }
    if (page === "rules" && !rulesViewEnabled) {
      page = "traffic";
    }
    if (activePage === page) return;
    if (activePage === "combined") {
      stopCombinedStream();
    }

    activePage = page;
    if (typeof window !== "undefined") {
      window.location.hash = `#${page}`;
    }
    if (page === "traffic" && !blocked.length && !passed.length && !paused) {
      loadTraffic();
    }
    if (!paused) {
      if (page === "combined" && !combinedLoaded) {
        startCombinedStream();
      } else if (page === "combined") {
        startCombinedStream(true);
      }
      if (page === "rules" && !rulesLoaded) {
        loadRules();
      }
    }
    scheduleTrafficRefresh();
  }

  function togglePause() {
    paused = !paused;
    if (paused) {
      if (trafficTimer) {
        clearInterval(trafficTimer);
        trafficTimer = null;
      }
      stopCombinedStream();
    } else {
      if (activePage === "traffic") {
        loadTraffic();
      } else if (activePage === "combined" && unifiedViewEnabled && streamViewEnabled) {
        startCombinedStream(true);
      } else if (activePage === "rules") {
        loadRules(true);
      }
      scheduleTrafficRefresh();
    }
  }

  function formatDate(value: string) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
  }

  function formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let idx = -1;
    let value = bytes;
    do {
      value /= 1024;
      idx += 1;
    } while (value >= 1024 && idx < units.length - 1);
    return `${value.toFixed(1)} ${units[idx]}`;
  }
</script>

<main class="mx-auto flex min-h-screen max-w-6xl flex-col gap-8 px-6 py-10">
  <header class="flex flex-col gap-4">
    <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
      <div>
        <h1 class="text-3xl font-semibold tracking-tight text-slate-50">
          {pageMeta[activePage].title}
        </h1>
        <p class="text-sm text-slate-400">
          {pageMeta[activePage].description}
        </p>
      </div>
      <div class="flex flex-wrap items-center justify-end gap-4">
        {#if activePage === "traffic"}
          <label class="flex items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              class="h-3 w-3 rounded border border-slate-700 bg-slate-900 accent-blue-500"
              disabled={paused}
              bind:checked={autoRefreshTraffic}
            />
            Auto refresh
          </label>
        {/if}
        {#if activePage === "combined"}
          <label class="flex items-center gap-1 text-xs text-emerald-200">
            <input
              type="checkbox"
              class="h-3 w-3 rounded border border-slate-700 bg-slate-900 accent-emerald-500"
              bind:checked={showCombinedPass}
            />
            Show Pass
          </label>
          <label class="flex items-center gap-1 text-xs text-rose-200">
            <input
              type="checkbox"
              class="h-3 w-3 rounded border border-slate-700 bg-slate-900 accent-rose-500"
              bind:checked={showCombinedBlock}
            />
            Show Block
          </label>
        {/if}
        {#if currentLastUpdated}
          <span class="text-xs text-slate-400">
            Updated {currentLastUpdated.toLocaleTimeString()}
          </span>
        {/if}
        {#if paused}
          <span class="rounded-full bg-amber-500/10 px-3 py-1 text-xs text-amber-200">
            Paused
          </span>
        {/if}
        <button
          class={`rounded px-4 py-2 text-sm font-medium transition ${
            paused ? "bg-emerald-500 text-white hover:bg-emerald-400" : "bg-slate-700 text-slate-200 hover:bg-slate-600"
          } disabled:cursor-not-allowed disabled:bg-slate-600`}
          on:click={togglePause}
          type="button"
        >
          {paused ? "Resume" : "Pause"}
        </button>
        <button
          class="rounded bg-blue-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-400 disabled:cursor-not-allowed disabled:bg-slate-600"
          on:click={refreshActive}
          disabled={currentLoading || paused}
          type="button"
        >
          {#if currentLoading}
            Loading…
          {:else}
            Refresh
          {/if}
        </button>
      </div>
    </div>

    <nav class="flex gap-2 border-b border-slate-800 pb-2">
      <button
        class={`rounded px-3 py-1 text-sm font-medium transition ${
          activePage === "traffic"
            ? "bg-slate-800 text-slate-100"
            : "text-slate-400 hover:text-slate-200"
        }`}
        on:click={() => setActivePage("traffic")}
        type="button"
      >
        Traffic
      </button>
      {#if unifiedViewEnabled}
        <button
          class={`rounded px-3 py-1 text-sm font-medium transition ${
            activePage === "combined"
              ? "bg-slate-800 text-slate-100"
              : "text-slate-400 hover:text-slate-200"
          }`}
          on:click={() => setActivePage("combined")}
          type="button"
        >
          Unified
        </button>
      {/if}
      {#if rulesViewEnabled}
        <button
          class={`rounded px-3 py-1 text-sm font-medium transition ${
            activePage === "rules"
              ? "bg-slate-800 text-slate-100"
              : "text-slate-400 hover:text-slate-200"
          }`}
          on:click={() => setActivePage("rules")}
          type="button"
        >
          Rule Counters
        </button>
      {/if}
    </nav>
  </header>

  {#if currentError}
    <div class="rounded border border-rose-700 bg-rose-950/40 p-4 text-sm text-rose-200">
      {currentError}
    </div>
  {/if}

  {#if activePage === "traffic"}
    <section class={`traffic-split grid gap-6 ${blockedViewEnabled ? "has-blocked" : ""}`}>
      {#if blockedViewEnabled}
      <div class="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold text-slate-100">Blocked Traffic</h2>
          <span class="rounded-full bg-rose-500/10 px-3 py-1 text-xs text-rose-300">
            {blocked.length} entries
          </span>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("timestamp")}>
                    Time <span>{sortIndicator(blockedSort, "timestamp")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("interface")}>
                    Interface <span>{sortIndicator(blockedSort, "interface")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("source")}>
                    Source <span>{sortIndicator(blockedSort, "source")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("dest")}>
                    Destination <span>{sortIndicator(blockedSort, "dest")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("protocol")}>
                    Protocol <span>{sortIndicator(blockedSort, "protocol")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => toggleBlockedSort("reason")}>
                    Reason <span>{sortIndicator(blockedSort, "reason")}</span>
                  </button>
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-900/60 text-slate-200">
              {#if blockedView.length === 0}
                <tr>
                  <td colspan="6" class="py-6 text-center text-sm text-slate-500">
                    No blocked packets reported.
                  </td>
                </tr>
              {:else}
                {#each blockedView as entry}
                  <tr class="hover:bg-slate-800/40">
                    <td class="py-2 pr-4 text-xs text-slate-400">
                      {formatDate(entry?.timestamp ?? "")}
                    </td>
                    <td class="py-2 pr-4">{(entry?.interface ?? "").toUpperCase()}</td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.source ?? ""}
                    </td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.dest ?? ""}
                    </td>
                    <td class="py-2 pr-4 uppercase text-slate-300">
                      {(entry?.protocol ?? "").toUpperCase()}
                    </td>
                    <td class="py-2 pr-4 text-slate-300">{entry?.reason ?? ""}</td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>
      {/if}

      <div class="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold text-slate-100">Passed Traffic</h2>
          <span class="rounded-full bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
            {passed.length} entries
          </span>
        </div>
        {#if !blockedViewEnabled}
          <div class="rounded border border-amber-700 bg-amber-950/30 p-3 text-xs text-amber-200">
            Blocked packet details are not yet supported on the <code>{backend}</code> backend.
          </div>
        {/if}
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("timestamp")}>
                    Time <span>{sortIndicator(passedSort, "timestamp")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("interface")}>
                    Interface <span>{sortIndicator(passedSort, "interface")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("source")}>
                    Source <span>{sortIndicator(passedSort, "source")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("dest")}>
                    Destination <span>{sortIndicator(passedSort, "dest")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("protocol")}>
                    Protocol <span>{sortIndicator(passedSort, "protocol")}</span>
                  </button>
                </th>
                <th class="py-2 pr-4">
                  <button type="button" class="flex items-center gap-1" on:click={() => togglePassedSort("action")}>
                    Action <span>{sortIndicator(passedSort, "action")}</span>
                  </button>
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-900/60 text-slate-200">
              {#if passedView.length === 0}
                <tr>
                  <td colspan="6" class="py-6 text-center text-sm text-slate-500">
                    No passed packets reported.
                  </td>
                </tr>
              {:else}
                {#each passedView as entry}
                  <tr class="hover:bg-slate-800/40">
                    <td class="py-2 pr-4 text-xs text-slate-400">
                      {formatDate(entry?.timestamp ?? "")}
                    </td>
                    <td class="py-2 pr-4">{(entry?.interface ?? "").toUpperCase()}</td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.source ?? ""}
                    </td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.dest ?? ""}
                    </td>
                    <td class="py-2 pr-4 uppercase text-slate-300">
                      {(entry?.protocol ?? "").toUpperCase()}
                    </td>
                    <td class="py-2 pr-4 text-emerald-300">{(entry?.action ?? "").toUpperCase()}</td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  {:else if activePage === "combined"}
    <section class="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div class="flex items-center justify-between pb-4">
        <h2 class="text-lg font-semibold text-slate-100">Unified Traffic</h2>
        <span class="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">
          {combinedFilteredView.length} entries
        </span>
      </div>
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-800 text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("timestamp")}>
                  Time <span>{sortIndicator(combinedSort, "timestamp")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("action")}>
                  Action <span>{sortIndicator(combinedSort, "action")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("direction")}>
                  Direction <span>{sortIndicator(combinedSort, "direction")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("ruleId")}>
                  Rule <span>{sortIndicator(combinedSort, "ruleId")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("interface")}>
                  Interface <span>{sortIndicator(combinedSort, "interface")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("source")}>
                  Source <span>{sortIndicator(combinedSort, "source")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("dest")}>
                  Destination <span>{sortIndicator(combinedSort, "dest")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("protocol")}>
                  Protocol <span>{sortIndicator(combinedSort, "protocol")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleCombinedSort("reason")}>
                  Reason <span>{sortIndicator(combinedSort, "reason")}</span>
                </button>
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-900/60 text-slate-200">
            {#if combinedFilteredView.length === 0}
              <tr>
                <td colspan="7" class="py-6 text-center text-sm text-slate-500">
                  {#if combinedLoading}
                    Loading traffic…
                  {:else}
                    No traffic entries available.
                  {/if}
                </td>
              </tr>
            {:else}
              {#each combinedFilteredView as entry}
                {#if entry}
                  <tr class="hover:bg-slate-800/40">
                    <td class="py-2 pr-4 text-xs text-slate-400">
                      {formatDate(entry?.timestamp ?? "")}
                    </td>
                    <td class="py-2 pr-4 text-xs">
                      <span
                        class={`rounded-full px-2 py-1 font-medium ${
                          (entry?.action ?? "").toLowerCase() === "pass"
                            ? "bg-emerald-500/10 text-emerald-300"
                            : "bg-rose-500/10 text-rose-300"
                        }`}
                      >
                        {(entry?.action ?? "").toUpperCase() || "?"}
                      </span>
                    </td>
                    <td class="py-2 pr-4 text-xs text-slate-300">
                      {(entry?.direction ?? "").toUpperCase() || "—"}
                    </td>
                    <td class="py-2 pr-4 text-xs text-slate-300">
                      {entry?.ruleId ?? "—"}
                    </td>
                    <td class="py-2 pr-4 text-sm text-slate-200">
                      {(entry?.interface ?? "").toUpperCase()}
                    </td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.source ?? ""}
                    </td>
                    <td class="py-2 pr-4 font-mono text-xs text-slate-300">
                      {entry?.dest ?? ""}
                    </td>
                    <td class="py-2 pr-4 uppercase text-slate-300">
                      {(entry?.protocol ?? "").toUpperCase()}
                    </td>
                    <td class="py-2 pr-4 text-slate-300">
                      {entry?.reason ?? ""}
                    </td>
                  </tr>
                {/if}
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </section>
  {:else}
    <section class="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <div class="flex items-center justify-between pb-4">
        <h2 class="text-lg font-semibold text-slate-100">Rule Counters</h2>
        <span class="text-xs text-slate-400">
          {rules.length} rules
        </span>
      </div>
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-800 text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleRulesSort("ruleLabel")}>
                  Rule <span>{sortIndicator(rulesSort, "ruleLabel")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleRulesSort("evaluations")}>
                  Evaluations <span>{sortIndicator(rulesSort, "evaluations")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleRulesSort("packets")}>
                  Packets <span>{sortIndicator(rulesSort, "packets")}</span>
                </button>
              </th>
              <th class="py-2 pr-4">
                <button type="button" class="flex items-center gap-1" on:click={() => toggleRulesSort("bytes")}>
                  Bytes <span>{sortIndicator(rulesSort, "bytes")}</span>
                </button>
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-900/60 text-slate-200">
            {#if rulesView.length === 0}
              <tr>
                <td colspan="4" class="py-6 text-center text-sm text-slate-500">
                  {#if rulesLoading}
                    Loading rule counters…
                  {:else}
                    Rule counters unavailable.
                  {/if}
                </td>
              </tr>
            {:else}
            {#each rulesView as rule}
                <tr class="hover:bg-slate-800/40">
                  <td class="py-3 pr-4">
                    <div class="font-medium text-slate-100">{rule?.ruleLabel ?? "Unnamed rule"}</div>
                    <div class="text-xs text-slate-500">ID #{rule?.ruleId ?? "—"}</div>
                  </td>
                  <td class="py-3 pr-4 font-mono text-xs text-slate-300">
                    {(rule?.evaluations ?? 0).toLocaleString()}
                  </td>
                  <td class="py-3 pr-4 font-mono text-xs text-slate-300">
                    {(rule?.packets ?? 0).toLocaleString()}
                  </td>
                  <td class="py-3 pr-4 font-mono text-xs text-slate-300">
                    {formatBytes(rule?.bytes ?? 0)}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <footer class="pb-6 text-center text-xs text-slate-500">

  </footer>
</main>
