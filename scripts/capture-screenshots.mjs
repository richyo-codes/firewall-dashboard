import { spawn } from "node:child_process";
import { mkdir, readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const uiRoot = join(root, "ui", "dist");
const outputRoot = join(root, "docs", "screenshots");

const packet = (timestamp, interfaceName, source, dest, protocol, action, reason, direction, ruleId) => ({
  timestamp,
  interface: interfaceName,
  source,
  dest,
  protocol,
  action,
  reason,
  direction,
  ruleId,
});

const fixtures = {
  "/api/config/refresh": {
    trafficIntervalMs: 60000,
    backend: "pf",
    supportsUnifiedView: true,
    supportsBlockedPacketDetails: true,
    supportsTrafficStream: true,
    supportsRuleCounters: true,
    supportsBandwidth: true,
    supportsQoS: true,
  },
  "/api/blocked": [
    packet("2026-07-28T19:42:18Z", "wan0", "203.0.113.84.54122", "198.51.100.10.22", "tcp", "block", "match", "in", 32),
    packet("2026-07-28T19:42:11Z", "wan0", "192.0.2.187.48191", "198.51.100.10.443", "tcp", "block", "match", "in", 48),
    packet("2026-07-28T19:41:55Z", "lan0.40", "10.40.0.27.5353", "224.0.0.251.5353", "udp", "block", "match", "in", 71),
    packet("2026-07-28T19:41:37Z", "guest0", "10.90.0.14.49820", "10.10.0.5.445", "tcp", "block", "match", "in", 86),
  ],
  "/api/passed": [
    packet("2026-07-28T19:42:20Z", "wan0", "10.10.0.25.51244", "1.1.1.1.443", "tcp", "pass", "state", "out", 12),
    packet("2026-07-28T19:42:16Z", "lan0", "10.10.0.42.62001", "9.9.9.9.53", "udp", "pass", "state", "out", 18),
    packet("2026-07-28T19:42:02Z", "lan0.20", "10.20.0.18.49732", "198.51.100.35.443", "tcp", "pass", "state", "out", 24),
  ],
  "/api/rules": [
    { ruleId: 32, ruleLabel: "WAN inbound policy", evaluations: 1842230, packets: 12842, bytes: 921450 },
    { ruleId: 12, ruleLabel: "Trusted LAN to internet", evaluations: 1294200, packets: 842301, bytes: 925482112 },
    { ruleId: 48, ruleLabel: "Public HTTPS service", evaluations: 774115, packets: 284903, bytes: 428134991 },
    { ruleId: 71, ruleLabel: "Block cross-VLAN discovery", evaluations: 422018, packets: 8942, bytes: 1839540 },
    { ruleId: 86, ruleLabel: "Guest isolation", evaluations: 318902, packets: 4012, bytes: 612840 },
  ],
  "/api/bandwidth": {
    interfaces: [
      bandwidthInterface("wan0", "Fiber WAN", 928_441_302_188, 142_118_992_410, 187_500_000, 42_300_000, 0),
      bandwidthInterface("lan0", "Trusted LAN", 681_882_119_440, 719_102_388_221, 91_200_000, 124_800_000, 11),
      bandwidthInterface("lan0.20", "IoT VLAN", 84_119_882_144, 101_443_998_201, 18_400_000, 11_900_000, 22),
      bandwidthInterface("lan0.40", "Guest VLAN", 128_330_481_002, 173_005_220_118, 31_700_000, 21_500_000, 33),
    ],
  },
  "/api/qos": {
    backend: "pf-altq",
    queues: [
      { name: "root_wan", interface: "wan0", bandwidth: "1Gb", scheduler: "hfsc", packets: 9451032, bytes: 1294401892, droppedPackets: 0, droppedBytes: 0, queueLength: 3, queueLimit: 100 },
      { name: "voice_realtime", interface: "wan0", parent: "root_wan", bandwidth: "50Mb", scheduler: "hfsc", packets: 228401, bytes: 91844220, droppedPackets: 0, droppedBytes: 0, queueLength: 1, queueLimit: 50 },
      { name: "interactive", interface: "wan0", parent: "root_wan", bandwidth: "250Mb", scheduler: "hfsc", packets: 2901184, bytes: 482194481, droppedPackets: 14, droppedBytes: 20160, queueLength: 12, queueLimit: 100 },
      { name: "bulk_default", interface: "wan0", parent: "root_wan", bandwidth: "700Mb", scheduler: "hfsc", packets: 6321447, bytes: 720363191, droppedPackets: 184, droppedBytes: 265120, queueLength: 38, queueLimit: 100 },
    ],
  },
};

function bandwidthInterface(name, alias, totalRx, totalTx, currentRx, currentTx, phase) {
  const history = Array.from({ length: 24 }, (_, index) => ({
    at: new Date(Date.UTC(2026, 6, 28, 17, index * 5)).toISOString(),
    rx: Math.round(currentRx * (0.55 + ((index + phase) % 7) * 0.075)),
    tx: Math.round(currentTx * (0.62 + ((index + phase * 2) % 5) * 0.09)),
  }));
  return { name, alias, total: { rx: totalRx, tx: totalTx }, fiveMinute: history.at(-1), history };
}

const captures = [
  { name: "traffic-overview.png", hash: "#traffic", marker: "203.0.113.84.54122" },
  { name: "wan-bandwidth.png", hash: "#bandwidth?interface=wan0", marker: "Fiber WAN" },
  { name: "qos-queues.png", hash: "#qos", marker: "voice_realtime" },
  { name: "rule-counters.png", hash: "#rules", marker: "WAN inbound policy" },
];

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

await stat(join(uiRoot, "index.html")).catch(() => {
  throw new Error("ui/dist is missing; run npm --prefix ui run build first");
});
await mkdir(outputRoot, { recursive: true });

const server = createServer(async (request, response) => {
  const requestURL = new URL(request.url ?? "/", "http://127.0.0.1");
  if (requestURL.pathname in fixtures) {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(fixtures[requestURL.pathname]));
    return;
  }

  const relative = normalize(decodeURIComponent(requestURL.pathname)).replace(/^(\.\.(\/|\\|$))+/, "").replace(/^[/\\]+/, "");
  let filePath = join(uiRoot, relative || "index.html");
  try {
    if ((await stat(filePath)).isDirectory()) filePath = join(filePath, "index.html");
    const body = await readFile(filePath);
    response.writeHead(200, { "content-type": contentTypes[extname(filePath)] ?? "application/octet-stream" });
    response.end(body);
  } catch {
    const body = await readFile(join(uiRoot, "index.html"));
    response.writeHead(200, { "content-type": contentTypes[".html"] });
    response.end(body);
  }
});

await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const address = server.address();
const port = typeof address === "object" && address ? address.port : 0;
const chrome = await findChrome();

try {
  for (const capture of captures) {
    const url = `http://127.0.0.1:${port}/${capture.hash}`;
    const commonArgs = [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--hide-scrollbars",
      "--force-device-scale-factor=1",
      "--window-size=1440,1000",
      "--virtual-time-budget=2500",
      url,
    ];
    const dom = await run(chrome, ["--dump-dom", ...commonArgs]);
    if (!dom.stdout.includes(capture.marker)) {
      throw new Error(`${capture.name}: rendered page did not contain fixture marker ${JSON.stringify(capture.marker)}`);
    }
    const output = join(outputRoot, capture.name);
    await run(chrome, [`--screenshot=${output}`, ...commonArgs]);
    const image = await stat(output);
    if (image.size < 10_000) throw new Error(`${capture.name}: screenshot is unexpectedly small (${image.size} bytes)`);
    console.log(`captured ${output}`);
  }
} finally {
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function findChrome() {
  const candidates = [process.env.CHROME_BIN, "chromium-browser", "chromium", "google-chrome", "google-chrome-stable"].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await run("sh", ["-c", `command -v "$1"`, "sh", candidate]);
      return candidate;
    } catch {
      // Try the next common executable name.
    }
  }
  throw new Error("Chrome/Chromium was not found; set CHROME_BIN to its executable");
}

function run(command, args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, { env: { ...process.env, TZ: "UTC" } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", rejectRun);
    child.on("close", (code) => {
      if (code === 0) resolveRun({ stdout, stderr });
      else rejectRun(new Error(`${command} exited with ${code}: ${stderr.trim()}`));
    });
  });
}
