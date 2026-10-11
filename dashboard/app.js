/*
 * IncidentIQ dashboard (vanilla JS, no build step).
 *
 * Security notes
 *  - The page CSP forbids inline scripts/styles, so this is the only script.
 *  - Logs, events and AI text are untrusted. Every value is written with
 *    textContent, never as markup, so a hostile log line cannot inject HTML.
 *  - The API key is only needed for the approve action. It is typed by the user,
 *    sent in the X-API-Key header, and kept in sessionStorage (this tab only)
 *    after a successful approval. It is never put in a URL.
 */
(function () {
  "use strict";

  var POLL_MS = 3000;          // refresh interval required by the spec
  var POLL_CLOSED_MS = 15000;  // closed incidents no longer change
  var REQUEST_TIMEOUT_MS = 8000;
  var KEY_STORAGE = "incidentiq.apiKey";
  var DASH = "\u2013";

  // ------------------------------------------------------------------ helpers

  function $(id) { return document.getElementById(id); }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function show(node, visible) { node.hidden = !visible; }

  function isNum(value) { return typeof value === "number" && isFinite(value); }

  function fmtSeconds(value) {
    if (!isNum(value)) { return DASH; }
    if (value < 60) { return value.toFixed(1) + " s"; }
    var minutes = Math.floor(value / 60);
    var seconds = Math.round(value - minutes * 60);
    if (seconds === 60) { minutes += 1; seconds = 0; }
    return minutes + " m " + seconds + " s";
  }

  function fmtTime(iso) {
    if (!iso) { return DASH; }
    var date = new Date(iso);
    if (isNaN(date.getTime())) { return String(iso); }
    return date.toLocaleString(undefined, { hour12: false });
  }

  function fmtTimeShort(iso) {
    if (!iso) { return DASH; }
    var date = new Date(iso);
    if (isNaN(date.getTime())) { return String(iso); }
    return date.toLocaleTimeString(undefined, { hour12: false });
  }

  function statusClass(status) {
    return "status-" + String(status || "").toLowerCase();
  }

  function statusBadge(status) {
    return el("span", "badge " + statusClass(status), String(status || DASH).replace(/_/g, " "));
  }

  function signature(value) {
    try { return JSON.stringify(value); } catch (err) { return String(Math.random()); }
  }

  function storage() {
    try { return window.sessionStorage; } catch (err) { return null; }
  }

  // ---------------------------------------------------------------------- API

  function ApiError(status, message) {
    this.name = "ApiError";
    this.status = status;
    this.message = message;
  }
  ApiError.prototype = Object.create(Error.prototype);

  function errorDetail(body, fallback) {
    if (body && typeof body.detail === "string") { return body.detail; }
    if (body && Array.isArray(body.detail) && body.detail.length) {
      return body.detail.map(function (item) { return item && item.msg ? item.msg : "invalid request"; }).join("; ");
    }
    return fallback;
  }

  function api(path, options) {
    options = options || {};
    var controller = typeof AbortController === "function" ? new AbortController() : null;
    var timer = controller ? setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT_MS) : null;
    var init = { method: options.method || "GET", headers: options.headers || {}, cache: "no-store" };
    if (controller) { init.signal = controller.signal; }
    return fetch(path, init).then(function (response) {
      return response.text().then(function (text) {
        var body = null;
        if (text) { try { body = JSON.parse(text); } catch (err) { body = null; } }
        if (!response.ok) {
          throw new ApiError(response.status, errorDetail(body, "HTTP " + response.status));
        }
        return body;
      });
    }).catch(function (err) {
      if (err instanceof ApiError) { throw err; }
      throw new ApiError(0, err && err.name === "AbortError" ? "request timed out" : "network error");
    }).then(function (value) {
      if (timer) { clearTimeout(timer); }
      return value;
    }, function (err) {
      if (timer) { clearTimeout(timer); }
      throw err;
    });
  }

  // ------------------------------------------------------------------ polling

  /** Calls task() now and then again after each run finishes (never overlapping). */
  function startPolling(task, intervalFn) {
    var timer = null;
    var stopped = false;
    var running = false;

    function schedule() {
      if (stopped) { return; }
      clearTimeout(timer);
      timer = setTimeout(run, intervalFn());
    }

    function run() {
      if (stopped || running) { return; }
      if (document.hidden) { schedule(); return; }
      running = true;
      Promise.resolve().then(task).catch(function () { /* task reports its own errors */ }).then(function () {
        running = false;
        schedule();
      });
    }

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) { clearTimeout(timer); run(); }
    });
    run();
    return {
      now: function () { clearTimeout(timer); run(); },
      stop: function () { stopped = true; clearTimeout(timer); }
    };
  }

  // -------------------------------------------------------------- shared bits

  function setBanner(message) {
    var banner = $("error-banner");
    if (!banner) { return; }
    if (message) { banner.textContent = message; }
    show(banner, !!message);
  }

  function chip(text, tone) {
    return el("span", "chip chip-" + tone, text);
  }

  var lastStatusSig = null;
  function renderStatus(status) {
    var strip = $("status-strip");
    if (!strip) { return; }
    var sig = signature(status && {
      a: status.auto_remediate, r: status.rollback_mode, g: status.gemini_enabled,
      d: status.detector && status.detector.running, n: status.detector && status.detector.in_flight,
      k: status.kubernetes && status.kubernetes.state, e: status.environment
    });
    if (sig === lastStatusSig) { return; }
    lastStatusSig = sig;
    clear(strip);
    if (!status) { strip.appendChild(chip("Status unavailable", "muted")); return; }

    var k8s = status.kubernetes && status.kubernetes.state;
    var k8sTone = k8s === "connected" ? "ok" : (k8s === "forbidden" || k8s === "error" ? "warn" : "bad");
    strip.appendChild(chip("Cluster: " + (k8s || "unknown").replace(/_/g, " "), k8sTone));

    var detector = status.detector || {};
    var inFlight = (detector.in_flight || []).length;
    strip.appendChild(chip(detector.running ? "Detector running" + (inFlight ? " (" + inFlight + " active)" : "") : "Detector stopped",
      detector.running ? "ok" : "bad"));

    strip.appendChild(chip(status.auto_remediate ? "Auto-remediate ON" : "Approval required", status.auto_remediate ? "warn" : "ok"));
    strip.appendChild(chip(status.gemini_enabled ? "Gemini RCA" : "Fallback RCA (no Gemini key)", status.gemini_enabled ? "info" : "muted"));
    strip.appendChild(chip("Rollback: " + (status.rollback_mode || DASH), "muted"));
    if (status.environment && status.environment !== "development") {
      strip.appendChild(chip(status.environment, "muted"));
    }
  }

  function loadStatus() {
    return api("/api/status").then(renderStatus, function () {
      lastStatusSig = null;
      renderStatus(null);
      return Promise.reject();
    });
  }

  // --------------------------------------------------------------- index page

  var lastIncidentsSig = null;

  function renderMetrics(metrics) {
    $("metric-total").textContent = isNum(metrics.total) ? metrics.total : DASH;
    $("metric-resolved").textContent = isNum(metrics.resolved) ? metrics.resolved : DASH;
    $("metric-mttd").textContent = fmtSeconds(metrics.avg_mttd_seconds);
    $("metric-mttr").textContent = fmtSeconds(metrics.avg_mttr_seconds);
  }

  function renderIncidentList(list) {
    var sig = signature(list);
    if (sig === lastIncidentsSig) { return; }
    lastIncidentsSig = sig;

    var state = $("incident-state");
    var wrap = $("incident-table-wrap");
    var rows = $("incident-rows");
    clear(rows);

    if (!list.length) {
      state.className = "state";
      state.textContent = "No incidents yet. Run scripts/deploy_bad.sh v2 to inject a failure.";
      show(state, true);
      show(wrap, false);
      return;
    }
    show(state, false);
    show(wrap, true);

    list.forEach(function (item) {
      var tr = el("tr");
      var idCell = el("td", "nowrap");
      var link = el("a", "mono", "#" + item.id);
      link.href = "/incidents/" + encodeURIComponent(item.id);
      idCell.appendChild(link);
      tr.appendChild(idCell);

      tr.appendChild(el("td", null, item.service));
      tr.appendChild(el("td", "mono", item.namespace));
      var statusCell = el("td");
      statusCell.appendChild(statusBadge(item.status));
      tr.appendChild(statusCell);
      tr.appendChild(el("td", null, item.reason));
      tr.appendChild(el("td", "nowrap", fmtTime(item.detected_at)));
      tr.appendChild(el("td", "num", fmtSeconds(item.mttd_seconds)));
      tr.appendChild(el("td", "num", fmtSeconds(item.mttr_seconds)));
      rows.appendChild(tr);
    });
  }

  function refreshIndex() {
    return Promise.all([
      api("/api/metrics").then(function (m) { renderMetrics(m); return true; }, function () { return false; }),
      api("/api/incidents").then(function (l) { renderIncidentList(l); return true; }, function () { return false; }),
      loadStatus().then(function () { return true; }, function () { return false; })
    ]).then(function (results) {
      var incidentsOk = results[1];
      var anyFailed = results.some(function (ok) { return !ok; });
      setBanner(anyFailed ? "Cannot reach the IncidentIQ API. Showing the last data received; retrying every few seconds." : "");
      if (!incidentsOk && lastIncidentsSig === null) {
        var state = $("incident-state");
        state.className = "state state-error";
        state.textContent = "Could not load incidents.";
        show(state, true);
        show($("incident-table-wrap"), false);
      }
    });
  }

  // ------------------------------------------------------------ incident page

  var detailId = null;
  var detailPoller = null;
  var lastDetailSig = null;
  var currentIncident = null;

  function incidentIdFromPath() {
    var match = /^\/incidents\/(\d+)\/?$/.exec(window.location.pathname);
    return match ? match[1] : null;
  }

  function fact(label, value) {
    var wrapper = el("div");
    wrapper.appendChild(el("dt", null, label));
    var dd = el("dd");
    if (value instanceof Node) { dd.appendChild(value); } else { dd.textContent = value === null || value === undefined || value === "" ? DASH : String(value); }
    wrapper.appendChild(dd);
    return wrapper;
  }

  function renderSummary(inc) {
    var rca = inc.rca || null;
    var summary = $("summary");
    clear(summary);
    summary.appendChild(fact("Service", inc.service));
    summary.appendChild(fact("Namespace", inc.namespace));
    summary.appendChild(fact("Detector reason", inc.reason));
    summary.appendChild(fact("Detected", fmtTime(inc.detected_at)));
    summary.appendChild(fact("Failure injected", inc.injected_at ? fmtTime(inc.injected_at) : "not recorded"));
    summary.appendChild(fact("Resolved", fmtTime(inc.resolved_at)));
    summary.appendChild(fact("MTTD", fmtSeconds(inc.mttd_seconds)));
    summary.appendChild(fact("MTTR", fmtSeconds(inc.mttr_seconds)));
    summary.appendChild(fact("Recommended action", rca && rca.recommended_action ? rca.recommended_action : DASH));
    summary.appendChild(fact("Action executed", inc.action ? inc.action : "none yet"));
    summary.appendChild(fact("Remediation attempts", isNum(inc.remediation_attempts) ? inc.remediation_attempts : DASH));
  }

  function renderApproval(inc) {
    var panel = $("approval-panel");
    var needs = inc.status === "AWAITING_APPROVAL";
    show(panel, needs);
    if (!needs) { return; }
    var rca = inc.rca || {};
    $("approval-text").textContent = rca.recommended_action
      ? "Recommended action: " + rca.recommended_action + " on " + inc.namespace + "/" + inc.service + ". Nothing has been changed in the cluster yet."
      : "Waiting for approval, but no valid recommendation is stored.";
    $("approve-btn").disabled = !rca.recommended_action || approving;
    var saved = storage() && storage().getItem(KEY_STORAGE);
    var input = $("api-key-input");
    if (saved && !input.value) { input.value = saved; }
  }

  function renderDiagnosis(inc) {
    var rca = inc.rca;
    var state = $("diagnosis-state");
    var body = $("diagnosis");
    if (!rca) {
      var pending = inc.status === "DETECTED" || inc.status === "ANALYZING";
      state.className = "state";
      state.textContent = pending ? "Analysis in progress\u2026" : "No diagnosis was recorded for this incident.";
      show(state, true);
      show(body, false);
      return;
    }
    show(state, false);
    show(body, true);

    var source = $("rca-source");
    source.textContent = rca.source === "llm" ? "AI diagnosis (Gemini)" : "Fallback heuristic";
    source.className = "badge source-" + (rca.source === "llm" ? "llm" : "fallback");
    $("rca-action").textContent = "Recommends: " + (rca.recommended_action || DASH);

    var confidence = isNum(rca.confidence) ? Math.min(1, Math.max(0, rca.confidence)) : null;
    $("rca-confidence").value = confidence === null ? 0 : confidence;
    $("rca-confidence-text").textContent = confidence === null ? DASH : Math.round(confidence * 100) + "%";
    $("rca-cause").textContent = rca.probable_cause || DASH;

    var quotes = $("rca-evidence");
    clear(quotes);
    var lines = Array.isArray(rca.evidence) ? rca.evidence : [];
    if (!lines.length) {
      quotes.appendChild(el("li", null, "No quoted evidence."));
    }
    lines.forEach(function (line) { quotes.appendChild(el("li", null, line)); });
  }

  function renderTimeline(inc) {
    var list = $("timeline");
    clear(list);
    var entries = Array.isArray(inc.timeline) ? inc.timeline : [];
    if (!entries.length) { list.appendChild(el("li", null, "No timeline entries yet.")); return; }
    entries.forEach(function (entry) {
      var li = el("li", "t-" + String(entry.step || "").toLowerCase());
      var head = el("div");
      head.appendChild(el("span", "t-step", String(entry.step || "").replace(/_/g, " ")));
      var time = el("span", "t-time", fmtTimeShort(entry.timestamp));
      time.title = fmtTime(entry.timestamp);
      head.appendChild(time);
      li.appendChild(head);
      li.appendChild(el("p", "t-msg", entry.message));
      list.appendChild(li);
    });
  }

  function simpleTable(headers, rows) {
    var table = el("table");
    var thead = el("thead");
    var headRow = el("tr");
    headers.forEach(function (h) { headRow.appendChild(el("th", null, h)); });
    thead.appendChild(headRow);
    table.appendChild(thead);
    var tbody = el("tbody");
    rows.forEach(function (cells) {
      var tr = el("tr");
      cells.forEach(function (cell) { tr.appendChild(el("td", null, cell === null || cell === undefined || cell === "" ? DASH : cell)); });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function renderEvidence(inc) {
    var evidence = inc.evidence;
    var state = $("evidence-state");
    var container = $("evidence");
    if (!evidence || typeof evidence !== "object") {
      state.className = "state";
      state.textContent = inc.status === "DETECTED" || inc.status === "ANALYZING"
        ? "Collecting evidence\u2026" : "No evidence was stored for this incident.";
      show(state, true);
      show(container, false);
      return;
    }
    show(state, false);
    show(container, true);

    // Pods
    var pods = Array.isArray(evidence.pods) ? evidence.pods : [];
    $("ev-pods-count").textContent = "(" + pods.length + ")";
    var podBox = $("ev-pods");
    clear(podBox);
    if (!pods.length) { podBox.appendChild(el("p", "muted", "No pod data.")); }
    else {
      var podRows = [];
      pods.forEach(function (pod) {
        (pod.containers || [{}]).forEach(function (c) {
          var last = c.last_termination_reason ? c.last_termination_reason + (c.last_exit_code !== null && c.last_exit_code !== undefined ? " (exit " + c.last_exit_code + ")" : "") : "";
          podRows.push([pod.name, pod.phase, pod.ready ? "yes" : "no", c.name, c.waiting_reason || c.terminated_reason || c.state, c.restart_count, last]);
        });
      });
      podBox.appendChild(simpleTable(["Pod", "Phase", "Ready", "Container", "State", "Restarts", "Last termination"], podRows));
    }
    if (evidence.last_deploy_time) {
      podBox.appendChild(el("p", "muted small", "Deployment last changed: " + fmtTime(evidence.last_deploy_time)));
    }

    // Logs
    var logs = Array.isArray(evidence.logs) ? evidence.logs : [];
    $("ev-logs-count").textContent = "(" + logs.length + ")";
    var logBox = $("ev-logs");
    clear(logBox);
    if (!logs.length) { logBox.appendChild(el("p", "muted", "No logs collected.")); }
    logs.forEach(function (entry) {
      logBox.appendChild(el("h4", null, entry.pod + " / " + entry.container + "  [" + (entry.source || "none") + " logs]"));
      if (entry.error) { logBox.appendChild(el("p", "note-warn", "Could not read logs: " + entry.error)); }
      var lines = Array.isArray(entry.lines) ? entry.lines : [];
      if (lines.length) { logBox.appendChild(el("pre", "log", lines.join("\n"))); }
      else if (!entry.error) { logBox.appendChild(el("p", "muted small", "No log lines.")); }
    });

    // Events
    var events = Array.isArray(evidence.events) ? evidence.events : [];
    $("ev-events-count").textContent = "(" + events.length + ")";
    var eventBox = $("ev-events");
    clear(eventBox);
    if (!events.length) { eventBox.appendChild(el("p", "muted", "No events collected.")); }
    else {
      eventBox.appendChild(simpleTable(["Time", "Type", "Reason", "Object", "Count", "Message"],
        events.map(function (ev) { return [fmtTimeShort(ev.timestamp), ev.type, ev.reason, ev.involved_object, ev.count, ev.message]; })));
    }

    // Rollout history
    var history = Array.isArray(evidence.rollout_history) ? evidence.rollout_history : [];
    $("ev-rollout-count").textContent = "(" + history.length + ")";
    var rolloutBox = $("ev-rollout");
    clear(rolloutBox);
    if (!history.length) { rolloutBox.appendChild(el("p", "muted", "No rollout history.")); }
    else {
      rolloutBox.appendChild(simpleTable(["Revision", "Current", "Images", "Ready / desired", "Created", "ReplicaSet"],
        history.map(function (rs) {
          return [rs.revision, rs.is_current ? "yes" : "", (rs.images || []).join(", "),
            (rs.ready_replicas || 0) + " / " + (rs.desired_replicas === undefined ? DASH : rs.desired_replicas), fmtTime(rs.created), rs.name];
        })));
    }
  }

  function renderIncident(inc) {
    currentIncident = inc;
    var sig = signature(inc);
    if (sig === lastDetailSig) { return; }
    lastDetailSig = sig;

    $("detail-title").textContent = "Incident #" + inc.id + " \u2013 " + inc.namespace + "/" + inc.service;
    document.title = "IncidentIQ - Incident #" + inc.id;
    var badge = $("detail-status");
    badge.textContent = String(inc.status).replace(/_/g, " ");
    badge.className = "badge " + statusClass(inc.status);

    renderSummary(inc);
    renderApproval(inc);
    renderDiagnosis(inc);
    renderTimeline(inc);
    renderEvidence(inc);

    show($("detail-state"), false);
    show($("detail"), true);
  }

  function isClosed(inc) { return inc && (inc.status === "RESOLVED" || inc.status === "FAILED"); }

  function refreshIncident() {
    return Promise.all([
      api("/api/incidents/" + detailId).then(function (inc) { renderIncident(inc); return true; }, function (err) {
        if (err.status === 404) {
          var state = $("detail-state");
          state.className = "state state-error";
          state.textContent = "Incident #" + detailId + " does not exist.";
          show(state, true);
          show($("detail"), false);
          setBanner("");
          if (detailPoller) { detailPoller.stop(); }
          return "gone";
        }
        if (!currentIncident) {
          var st = $("detail-state");
          st.className = "state state-error";
          st.textContent = "Could not load this incident.";
          show(st, true);
        }
        return false;
      }),
      loadStatus().then(function () { return true; }, function () { return false; })
    ]).then(function (results) {
      if (results[0] === "gone") { return; }
      setBanner(results.some(function (ok) { return ok !== true; })
        ? "Cannot reach the IncidentIQ API. Showing the last data received; retrying every few seconds." : "");
    });
  }

  // ----------------------------------------------------------------- approval

  var approving = false;

  function setApprovalMessage(text, kind) {
    var msg = $("approval-msg");
    msg.textContent = text;
    msg.className = "small " + (kind === "ok" ? "msg-ok" : (kind === "error" ? "msg-error" : "muted"));
  }

  function approve() {
    if (approving || !currentIncident) { return; }
    var input = $("api-key-input");
    var key = input.value.trim();
    if (!key) { setApprovalMessage("Enter the API key to approve.", "error"); input.focus(); return; }
    var rca = currentIncident.rca || {};
    var question = "Approve '" + rca.recommended_action + "' on " + currentIncident.namespace + "/" + currentIncident.service + "?";
    if (!window.confirm(question)) { return; }

    approving = true;
    $("approve-btn").disabled = true;
    setApprovalMessage("Approving\u2026", "info");
    api("/api/incidents/" + detailId + "/approve", { method: "POST", headers: { "X-API-Key": key } }).then(function (result) {
      var store = storage();
      if (store) { try { store.setItem(KEY_STORAGE, key); } catch (err) { /* ignore */ } }
      setApprovalMessage("Approved. Running " + (result && result.action ? result.action : "remediation") + "\u2026", "ok");
    }, function (err) {
      var store = storage();
      if (err.status === 401) {
        if (store) { try { store.removeItem(KEY_STORAGE); } catch (e) { /* ignore */ } }
        setApprovalMessage("The API key was rejected.", "error");
      } else if (err.status === 409) {
        setApprovalMessage("This incident is no longer waiting for approval (already approved or closed).", "error");
      } else if (err.status === 422) {
        setApprovalMessage("Cannot approve: " + err.message, "error");
      } else if (err.status === 0) {
        setApprovalMessage("Could not reach the API: " + err.message + ".", "error");
      } else {
        setApprovalMessage("Approval failed: " + err.message, "error");
      }
    }).then(function () {
      approving = false;
      lastDetailSig = null;
      if (detailPoller) { detailPoller.now(); }
    });
  }

  // --------------------------------------------------------------------- boot

  function boot() {
    var page = document.body && document.body.getAttribute("data-page");
    if (page === "index") {
      startPolling(refreshIndex, function () { return POLL_MS; });
    } else if (page === "incident") {
      detailId = incidentIdFromPath();
      if (!detailId) {
        var state = $("detail-state");
        state.className = "state state-error";
        state.textContent = "Invalid incident address.";
        return;
      }
      $("approve-btn").addEventListener("click", approve);
      $("api-key-input").addEventListener("keydown", function (event) {
        if (event.key === "Enter") { event.preventDefault(); approve(); }
      });
      detailPoller = startPolling(refreshIncident, function () { return isClosed(currentIncident) ? POLL_CLOSED_MS : POLL_MS; });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
