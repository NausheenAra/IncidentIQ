// Browser-level smoke test of the dashboard (jsdom). Run it with tests/dashboard_smoke/run.sh
const { JSDOM, VirtualConsole } = require("jsdom");
const BASE = process.env.SMOKE_BASE_URL || "http://127.0.0.1:8765";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(name, cond, extra) { console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : "  -> " + extra)); if (!cond) failures++; }

async function load(path, confirmAnswer) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
  vc.on("error", (e) => errors.push(String(e)));
  const dom = await JSDOM.fromURL(BASE + path, { runScripts: "dangerously", resources: "usable", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) { w.confirm = () => confirmAnswer !== false; w.fetch = (u, i) => { const init = Object.assign({}, i); delete init.signal; return fetch(new URL(u, BASE), init); }; } });
  dom.errors = errors;
  return dom;
}

(async () => {
  // ---- index
  let dom = await load("/");
  await sleep(1500);
  let d = dom.window.document;
  check("index: no script errors", dom.errors.length === 0, dom.errors.join("|"));
  check("index: total metric = 2", d.getElementById("metric-total").textContent === "2", d.getElementById("metric-total").textContent);
  check("index: resolved metric = 1", d.getElementById("metric-resolved").textContent === "1", d.getElementById("metric-resolved").textContent);
  check("index: avg MTTR present as measured text (not fabricated 0)", /s$/.test(d.getElementById("metric-mttr").textContent) || d.getElementById("metric-mttr").textContent === "\u2013", d.getElementById("metric-mttr").textContent);
  const rows = d.querySelectorAll("#incident-rows tr");
  check("index: two incident rows", rows.length === 2, rows.length);
  check("index: row links to /incidents/1", !!d.querySelector('a[href="/incidents/1"]'), "missing link");
  check("index: awaiting approval badge", d.querySelector(".status-awaiting_approval") !== null, "no badge");
  check("index: status strip shows approval required", /Approval required/.test(d.getElementById("status-strip").textContent), d.getElementById("status-strip").textContent);
  check("index: no error banner while API is up", d.getElementById("error-banner").hidden === true, "banner visible");
  dom.window.close();

  // ---- incident detail (awaiting approval)
  dom = await load("/incidents/1");
  await sleep(1500);
  d = dom.window.document;
  check("detail: no script errors", dom.errors.length === 0, dom.errors.join("|"));
  check("detail: title", /Incident #1/.test(d.getElementById("detail-title").textContent), d.getElementById("detail-title").textContent);
  check("detail: approval panel visible", d.getElementById("approval-panel").hidden === false, "hidden");
  check("detail: probable cause shown as TEXT (no markup injected)", d.getElementById("rca-cause").textContent.includes("<b>bold</b>") && d.getElementById("rca-cause").querySelector("b") === null, d.getElementById("rca-cause").innerHTML);
  check("detail: confidence 87%", d.getElementById("rca-confidence-text").textContent === "87%", d.getElementById("rca-confidence-text").textContent);
  check("detail: source badge says Gemini", /Gemini/.test(d.getElementById("rca-source").textContent), d.getElementById("rca-source").textContent);
  check("detail: timeline has 3 entries", d.querySelectorAll("#timeline li").length === 3, d.querySelectorAll("#timeline li").length);
  const logHtml = d.getElementById("ev-logs").innerHTML;
  check("detail: hostile log line rendered inert", d.querySelector("#ev-logs img") === null && dom.window.__pwned === undefined, logHtml);
  check("detail: hostile text still visible as text", d.getElementById("ev-logs").textContent.includes("<img src=x"), "text missing");
  check("detail: pods table lists CrashLoopBackOff", /CrashLoopBackOff/.test(d.getElementById("ev-pods").textContent), d.getElementById("ev-pods").textContent);
  check("detail: events table shows BackOff", /BackOff/.test(d.getElementById("ev-events").textContent), "");
  check("detail: rollout table shows revision 2", /shop-api:v2/.test(d.getElementById("ev-rollout").textContent), "");

  // approve without key
  d.getElementById("approve-btn").click();
  await sleep(300);
  check("approve: empty key is refused client-side", /Enter the API key/.test(d.getElementById("approval-msg").textContent), d.getElementById("approval-msg").textContent);
  // approve with wrong key -> 401
  d.getElementById("api-key-input").value = "wrong";
  d.getElementById("approve-btn").click();
  await sleep(800);
  check("approve: wrong key shows rejected message", /rejected/.test(d.getElementById("approval-msg").textContent), d.getElementById("approval-msg").textContent);
  check("approve: wrong key is not kept in sessionStorage", dom.window.sessionStorage.getItem("incidentiq.apiKey") === null, "stored!");
  // approve with correct key -> 202 (remediation then fails safely without a cluster)
  d.getElementById("api-key-input").value = "smoke-key-123";
  d.getElementById("approve-btn").click();
  await sleep(800);
  check("approve: correct key accepted", /Approved/.test(d.getElementById("approval-msg").textContent), d.getElementById("approval-msg").textContent);
  check("approve: key kept for this tab only", dom.window.sessionStorage.getItem("incidentiq.apiKey") === "smoke-key-123", "");
  await sleep(4500); // let a poll cycle pick up the new status
  const st = d.getElementById("detail-status").textContent;
  check("approve: status moved off AWAITING APPROVAL after refresh", st !== "AWAITING APPROVAL", st);
  check("approve: approval panel hidden after approval", d.getElementById("approval-panel").hidden === true, "still visible");
  dom.window.close();

  // ---- closed incident + missing incident
  dom = await load("/incidents/2");
  await sleep(1200);
  d = dom.window.document;
  check("closed: no approval panel", d.getElementById("approval-panel").hidden === true, "visible");
  check("closed: no diagnosis message", /No diagnosis/.test(d.getElementById("diagnosis-state").textContent), d.getElementById("diagnosis-state").textContent);
  check("closed: no evidence message", /No evidence/.test(d.getElementById("evidence-state").textContent), d.getElementById("evidence-state").textContent);
  dom.window.close();

  dom = await load("/incidents/999");
  await sleep(1200);
  d = dom.window.document;
  check("missing: friendly 404 state", /does not exist/.test(d.getElementById("detail-state").textContent), d.getElementById("detail-state").textContent);
  dom.window.close();

  console.log(failures ? `\n${failures} FAILED` : "\nALL PASSED");
  process.exit(failures ? 1 : 0);
})();
