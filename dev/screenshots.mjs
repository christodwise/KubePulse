// Takes the README screenshots with headless Chrome.
//
//   python3 dev/fake_cluster.py &
//   K8S_API=http://127.0.0.1:8911 DATA_DIR=/tmp KUBEPULSE_USERS=admin:demo CLUSTER_NAME=demo-cluster \
//     OPENAI_API_KEY=x OPENAI_BASE_URL=http://127.0.0.1:8912/v1 MATTERMOST_WEBHOOK_URL=http://127.0.0.1:8913/hook python3 app.py &
//   node dev/screenshots.mjs [out-dir] [base-url]      # wait ~2 minutes first, so the trend lines have data
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const OUT = process.argv[2] || "docs/screenshots";
const URL = process.argv[3] || "http://localhost:8080";
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
mkdirSync(OUT, { recursive: true });

const chrome = spawn(CHROME, ["--headless=new", "--hide-scrollbars", "--remote-debugging-port=9341",
  `--user-data-dir=${mkdtempSync(join(tmpdir(), "kp-shots-"))}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let targets;
for (let i = 0; i < 120 && !targets; i++) { try { targets = await (await fetch("http://127.0.0.1:9341/json")).json(); } catch { await sleep(250); } }
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((r) => ws.onopen = r);
let id = 0; const pending = new Map(), errors = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (pending.has(d.id)) { pending.get(d.id)(d.result); pending.delete(d.id); }
  if (d.method === "Runtime.exceptionThrown") errors.push(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text);
};
const send = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
const js = (expression) => send("Runtime.evaluate", { expression, awaitPromise: true });
const size = (width, height) => send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
const theme = (t) => send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: t }, { name: "prefers-reduced-motion", value: "reduce" }] });
const shot = async (name, full) => {
  const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: !!full });
  writeFileSync(join(OUT, name + ".png"), Buffer.from(r.data, "base64"));
  console.log("saved", name);
};

await send("Runtime.enable");
// The sign-in screen with its animations running (heartbeat and network), then everything else still
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] }); await size(1440, 900);
await send("Page.navigate", { url: URL + "/" }); await sleep(3400);
await shot("login");
await theme("light"); await size(1440, 1000);
await js(`$("lu").value = "admin"; $("lp").value = "${process.env.KP_PASSWORD || "demo"}"; $("loginForm").requestSubmit()`); await sleep(2500);
await shot("overview", true);
await js(`setView("insights")`); await sleep(800); await shot("insights", true);
await js(`setView("pods")`); await sleep(500);
await js(`openPod("prod", "payments-api-7d9f8c6b5-x2k4p", "ai")`); await sleep(4500); await shot("ai-investigation");
await js(`setTab("logs")`); await sleep(1200); await shot("pod-logs");
await js(`closeDrawer()`); await theme("dark"); await js(`setView("overview")`); await sleep(900); await shot("overview-dark", true);
await size(1920, 1080); await send("Page.navigate", { url: URL + "/wall" }); await sleep(2500); await shot("wallboard");
console.log("page errors:", errors.length ? errors : "none");
ws.close(); chrome.kill();
