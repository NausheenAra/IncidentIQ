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

  // ---- multi-cluster live dashboard
  check("clusters: healthy row shows only the cluster without an incident", d.querySelectorAll("#cluster-grid .cluster-card").length === 1 && /staging/.test(d.getElementById("cluster-grid").textContent), d.getElementById("cluster-grid").textContent);
  check("clusters: cluster with the incident sits in the incident box", d.querySelectorAll("#active-grid .cluster-card-incident").length === 1 && d.getElementById("active-count").textContent === "1", d.getElementById("active-grid").textContent);
  check("clusters: incident card links to the incident", !!d.querySelector('#active-grid a[href="/incidents/1"]'), "no link");
  check("clusters: awaiting approval shows a review button", /Review and approve/.test(d.getElementById("active-grid").textContent), "");
  const delButtons = (grid) => Array.from(d.querySelectorAll(grid + " button")).filter((b) => b.textContent === "Delete");
  check("delete: disabled while the incident is open", delButtons("#active-grid").every((b) => b.disabled && b.title.length > 0), "enabled");
  check("kpi: clusters = 2", d.getElementById("kpi-clusters").textContent === "2", d.getElementById("kpi-clusters").textContent);
  check("charts: pods chart drew lines", d.querySelectorAll("#chart-pods svg path.line").length >= 1, "no line");
  check("charts: log chart has one line per cluster", d.querySelectorAll("#chart-logs svg path.line").length === 2, d.querySelectorAll("#chart-logs svg path.line").length);
  check("charts: delta arrow rendered for errors", /[\u25b2\u25bc\u25ac]/.test(d.getElementById("delta-errors").textContent), d.getElementById("delta-errors").textContent);
  check("charts: status donut and reasons drawn", d.querySelectorAll("#chart-status svg").length === 1 && d.querySelectorAll("#chart-reasons rect.hbar").length >= 1, "");
  check("workloads: hostile workload name is inert", d.querySelector("#workload-rows img") === null && dom.window.__pwned === undefined && /<img src=x/.test(d.getElementById("workload-rows").textContent), "");
  check("activity: feed lists timeline entries", d.querySelectorAll("#activity-list li").length >= 3, d.querySelectorAll("#activity-list li").length);
  check("live: indicator says live", /Live/.test(d.getElementById("live-text").textContent), d.getElementById("live-text").textContent);

  // analytics cluster selector
  const sel = d.getElementById("analytics-cluster");
  sel.value = String(2);
  sel.dispatchEvent(new dom.window.Event("change"));
  check("charts: selecting one cluster shows one line", d.querySelectorAll("#chart-logs svg path.line").length === 1, d.querySelectorAll("#chart-logs svg path.line").length);

  // connect dialog (the smoke backend has no kubeconfig, so it must say so clearly)
  d.getElementById("connect-btn").click();
  d.getElementById("connect-key").value = "smoke-key-123";
  d.getElementById("connect-load").click();
  await sleep(800);
  check("connect: reports that no kubeconfig contexts exist", /no kubeconfig/i.test(d.getElementById("connect-msg").textContent), d.getElementById("connect-msg").textContent);
  d.getElementById("connect-key").value = "wrong";
  d.getElementById("connect-load").click();
  await sleep(600);
  check("connect: wrong key is rejected", /rejected/.test(d.getElementById("connect-msg").textContent), d.getElementById("connect-msg").textContent);
  d.getElementById("connect-cancel").click();

  // delete the healthy cluster
  delButtons("#cluster-grid")[0].click();
  d.getElementById("delete-key").value = "wrong";
  d.getElementById("delete-confirm").click();
  await sleep(600);
  check("delete: wrong key is rejected", /rejected/.test(d.getElementById("delete-msg").textContent) && d.querySelectorAll("#cluster-grid .cluster-card").length === 1, d.getElementById("delete-msg").textContent);
  d.getElementById("delete-key").value = "smoke-key-123";
  d.getElementById("delete-confirm").click();
  await sleep(4500);
  check("delete: cluster disappears after a correct delete", d.querySelectorAll("#cluster-grid .cluster-card").length === 0 && !/staging/.test(d.getElementById("cluster-grid").textContent), d.getElementById("cluster-grid").textContent);
  check("delete: kpi drops to 1 cluster", d.getElementById("kpi-clusters").textContent === "1", d.getElementById("kpi-clusters").textContent);
  check("index: still no script errors after interaction", dom.errors.length === 0, dom.errors.join("|"));
  dom.window.close();

  // ---- incident detail (awaiting approval)
  dom = await load("/incidents/1");
  await sleep(1500);
  d = dom.window.document;
  check("detail: no script errors", dom.errors.length === 0, dom.errors.join("|"));
  check("detail: shows the cluster name", /primary/.test(d.getElementById("summary").textContent), d.getElementById("summary").textContent);
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
