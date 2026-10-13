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
    if (options.body !== undefined) {
      init.body = JSON.stringify(options.body);
      init.headers = Object.assign({ "Content-Type": "application/json" }, init.headers);
    }
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

  // ------------------------------------------------------------ SVG charts
  // Everything is built with createElementNS + attributes (no markup strings, no
  // style attributes), so it is safe under the strict CSP and with hostile text.

  var SVG_NS = "http://www.w3.org/2000/svg";
  var PALETTE_SIZE = 8;

  function svgEl(tag, attrs, text) {
    var node = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (name) {
        if (name !== "style") { node.setAttribute(name, String(attrs[name])); }
      });
    }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function niceMax(value) {
    if (!isNum(value) || value <= 0) { return 1; }
    var power = Math.pow(10, Math.floor(Math.log(value) / Math.LN10));
    var fraction = value / power;
    var nice = fraction <= 1 ? 1 : (fraction <= 2 ? 2 : (fraction <= 5 ? 5 : 10));
    return nice * power;
  }

  function fmtNum(value) {
    if (!isNum(value)) { return DASH; }
    if (Math.abs(value) >= 10000) { return (value / 1000).toFixed(0) + "k"; }
    if (Math.abs(value) >= 1000) { return (value / 1000).toFixed(1) + "k"; }
    if (Math.abs(value) < 10 && Math.round(value) !== value) { return value.toFixed(1); }
    return String(Math.round(value));
  }

  function seriesPoints(timestamps, values) {
    var points = [];
    var count = Math.min((timestamps || []).length, (values || []).length);
    for (var i = 0; i < count; i += 1) {
      var t = Date.parse(timestamps[i]);
      if (isFinite(t) && isNum(values[i])) { points.push({ t: t, v: values[i] }); }
    }
    return points;
  }

  /** Sum several series aligned from the newest sample backwards (clusters are sampled together). */
  function sumAligned(list) {
    var longest = 0;
    list.forEach(function (s) { longest = Math.max(longest, s.length); });
    var out = [];
    for (var i = 0; i < longest; i += 1) {
      var total = 0;
      var t = 0;
      list.forEach(function (s) {
        var idx = s.length - longest + i;
        if (idx >= 0) { total += s[idx].v; t = Math.max(t, s[idx].t); }
      });
      out.push({ t: t, v: total });
    }
    return out;
  }

  function lineChart(container, opts) {
    var W = 420, H = 150, L = 34, R = 10, T = 10, B = 20;
    clear(container);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, "class": "chart-svg", role: "img", "aria-label": opts.label || "chart" });
    container.appendChild(svg);

    var all = [];
    opts.series.forEach(function (s) { s.points.forEach(function (p) { all.push(p); }); });
    if (!all.length) {
      svg.appendChild(svgEl("text", { x: W / 2, y: H / 2, "class": "chart-empty", "text-anchor": "middle" }, "Waiting for samples\u2026"));
      return;
    }
    var tMin = Infinity, tMax = -Infinity, vMax = 0;
    all.forEach(function (p) { tMin = Math.min(tMin, p.t); tMax = Math.max(tMax, p.t); vMax = Math.max(vMax, p.v); });
    if (tMax === tMin) { tMax = tMin + 1000; }
    var top = opts.fixedMax ? opts.fixedMax : niceMax(vMax * 1.1);
    function x(t) { return L + (t - tMin) / (tMax - tMin) * (W - L - R); }
    function y(v) { return T + (1 - Math.min(v / top, 1)) * (H - T - B); }

    for (var g = 0; g <= 4; g += 1) {
      var gv = top * g / 4;
      var gy = y(gv);
      svg.appendChild(svgEl("line", { x1: L, x2: W - R, y1: gy, y2: gy, "class": "grid" }));
      svg.appendChild(svgEl("text", { x: L - 5, y: gy + 3, "class": "axis", "text-anchor": "end" }, fmtNum(gv)));
    }
    svg.appendChild(svgEl("text", { x: L, y: H - 5, "class": "axis", "text-anchor": "start" }, fmtTimeShort(new Date(tMin).toISOString())));
    svg.appendChild(svgEl("text", { x: W - R, y: H - 5, "class": "axis", "text-anchor": "end" }, fmtTimeShort(new Date(tMax).toISOString())));

    opts.series.forEach(function (s) {
      if (!s.points.length) { return; }
      var line = "";
      s.points.forEach(function (p, i) { line += (i ? "L" : "M") + x(p.t).toFixed(1) + " " + y(p.v).toFixed(1); });
      if (s.area) {
        var last = s.points[s.points.length - 1];
        var first = s.points[0];
        svg.appendChild(svgEl("path", { d: line + "L" + x(last.t).toFixed(1) + " " + y(0).toFixed(1) + "L" + x(first.t).toFixed(1) + " " + y(0).toFixed(1) + "Z", "class": "area " + s.cls }));
      }
      svg.appendChild(svgEl("path", { d: line, "class": "line " + s.cls + (s.dashed ? " dashed" : "") }));
      var end = s.points[s.points.length - 1];
      svg.appendChild(svgEl("circle", { cx: x(end.t), cy: y(end.v), r: 3, "class": "dot " + s.cls }));
    });

    // hover: crosshair + tooltip, all via attributes and textContent
    var cross = svgEl("line", { y1: T, y2: H - B, x1: 0, x2: 0, "class": "crosshair", visibility: "hidden" });
    var tipBg = svgEl("rect", { rx: 4, ry: 4, "class": "tip-bg", visibility: "hidden", width: 10, height: 10 });
    var tipLines = [];
    svg.appendChild(cross);
    svg.appendChild(tipBg);
    var overlay = svgEl("rect", { x: L, y: T, width: W - L - R, height: H - T - B, "class": "hover-area" });
    svg.appendChild(overlay);

    function nearest(points, t) {
      var best = points[0];
      points.forEach(function (p) { if (Math.abs(p.t - t) < Math.abs(best.t - t)) { best = p; } });
      return best;
    }
    function hide() {
      cross.setAttribute("visibility", "hidden");
      tipBg.setAttribute("visibility", "hidden");
      tipLines.forEach(function (n) { n.setAttribute("visibility", "hidden"); });
    }
    overlay.addEventListener("mouseleave", hide);
    overlay.addEventListener("mousemove", function (event) {
      var rect = svg.getBoundingClientRect();
      if (!rect.width) { return; }
      var px = (event.clientX - rect.left) / rect.width * W;
      var t = tMin + Math.min(Math.max((px - L) / (W - L - R), 0), 1) * (tMax - tMin);
      var rows = [];
      var anchor = null;
      opts.series.forEach(function (s) {
        if (!s.points.length) { return; }
        var p = nearest(s.points, t);
        anchor = anchor || p;
        rows.push((s.name ? s.name + ": " : "") + fmtNum(p.v) + (opts.unit || ""));
      });
      if (!anchor) { return; }
      rows.unshift(fmtTimeShort(new Date(anchor.t).toISOString()));
      var cx = x(anchor.t);
      cross.setAttribute("x1", cx);
      cross.setAttribute("x2", cx);
      cross.setAttribute("visibility", "visible");
      var boxW = 118, boxH = 8 + rows.length * 13;
      var bx = cx + 8 + boxW > W ? cx - 8 - boxW : cx + 8;
      tipBg.setAttribute("x", bx);
      tipBg.setAttribute("y", T + 2);
      tipBg.setAttribute("width", boxW);
      tipBg.setAttribute("height", boxH);
      tipBg.setAttribute("visibility", "visible");
      while (tipLines.length < rows.length) { var node = svgEl("text", { "class": "tip-text" }); svg.insertBefore(node, overlay); tipLines.push(node); }
      tipLines.forEach(function (node, i) {
        if (i < rows.length) {
          node.setAttribute("x", bx + 6);
          node.setAttribute("y", T + 14 + i * 13);
          node.textContent = rows[i];
          node.setAttribute("visibility", "visible");
        } else { node.setAttribute("visibility", "hidden"); }
      });
    });
  }

  function sparkline(container, values, cls) {
    clear(container);
    var W = 120, H = 30;
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, "class": "spark-svg", role: "img", "aria-label": "trend" });
    container.appendChild(svg);
    if (!values || values.length < 2) { svg.appendChild(svgEl("line", { x1: 0, x2: W, y1: H - 3, y2: H - 3, "class": "grid" })); return; }
    var max = niceMax(Math.max.apply(null, values));
    var d = "";
    values.forEach(function (v, i) {
      d += (i ? "L" : "M") + (i / (values.length - 1) * (W - 4) + 2).toFixed(1) + " " + (H - 3 - (Math.min(v / max, 1)) * (H - 6)).toFixed(1);
    });
    svg.appendChild(svgEl("path", { d: d, "class": "line " + cls }));
  }

  function donutChart(container, slices, centerText) {
    clear(container);
    var size = 150, cx = 75, cy = 75, radius = 56, width = 18;
    var wrap = el("div", "donut-wrap");
    var svg = svgEl("svg", { viewBox: "0 0 " + size + " " + size, "class": "donut-svg", role: "img", "aria-label": "status mix" });
    wrap.appendChild(svg);
    var total = 0;
    slices.forEach(function (s) { total += s.value; });
    svg.appendChild(svgEl("circle", { cx: cx, cy: cy, r: radius, "class": "donut-track", "stroke-width": width, fill: "none" }));
    if (total > 0) {
      var angle = -Math.PI / 2;
      slices.forEach(function (s) {
        if (!s.value) { return; }
        var sweep = s.value / total * Math.PI * 2;
        if (s.value === total) {
          svg.appendChild(svgEl("circle", { cx: cx, cy: cy, r: radius, "class": "donut-arc " + s.cls, "stroke-width": width, fill: "none" }));
        } else {
          var x1 = cx + radius * Math.cos(angle), y1 = cy + radius * Math.sin(angle);
          var x2 = cx + radius * Math.cos(angle + sweep), y2 = cy + radius * Math.sin(angle + sweep);
          svg.appendChild(svgEl("path", {
            d: "M" + x1.toFixed(2) + " " + y1.toFixed(2) + "A" + radius + " " + radius + " 0 " + (sweep > Math.PI ? 1 : 0) + " 1 " + x2.toFixed(2) + " " + y2.toFixed(2),
            "class": "donut-arc " + s.cls, "stroke-width": width, fill: "none"
          }));
        }
        angle += sweep;
      });
    }
    svg.appendChild(svgEl("text", { x: cx, y: cy + 6, "class": "donut-center", "text-anchor": "middle" }, centerText));
    var legend = el("ul", "legend-list");
    slices.forEach(function (s) {
      var li = el("li");
      li.appendChild(el("span", "swatch " + s.cls));
      li.appendChild(el("span", null, String(s.label).replace(/_/g, " ") + " (" + s.value + ")"));
      legend.appendChild(li);
    });
    wrap.appendChild(legend);
    container.appendChild(wrap);
  }

  function barChart(container, groups, labelA, labelB) {
    clear(container);
    var W = 420, H = 150, L = 34, R = 10, T = 10, B = 24;
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, "class": "chart-svg", role: "img", "aria-label": "MTTD and MTTR by incident" });
    container.appendChild(svg);
    if (!groups.length) {
      svg.appendChild(svgEl("text", { x: W / 2, y: H / 2, "class": "chart-empty", "text-anchor": "middle" }, "No measured incidents yet"));
      return;
    }
    var max = 0;
    groups.forEach(function (g) { g.values.forEach(function (v) { if (isNum(v)) { max = Math.max(max, v); } }); });
    var top = niceMax(max * 1.1);
    for (var i = 0; i <= 4; i += 1) {
      var gy = T + (1 - i / 4) * (H - T - B);
      svg.appendChild(svgEl("line", { x1: L, x2: W - R, y1: gy, y2: gy, "class": "grid" }));
      svg.appendChild(svgEl("text", { x: L - 5, y: gy + 3, "class": "axis", "text-anchor": "end" }, fmtNum(top * i / 4) + "s"));
    }
    var slot = (W - L - R) / groups.length;
    var barW = Math.min(18, slot / 2.6);
    groups.forEach(function (g, gi) {
      var base = L + gi * slot + slot / 2;
      g.values.forEach(function (v, vi) {
        if (!isNum(v)) { return; }
        var h = Math.max(1.5, v / top * (H - T - B));
        var rect = svgEl("rect", { x: base + (vi === 0 ? -barW - 1 : 1), y: H - B - h, width: barW, height: h, rx: 2, "class": vi === 0 ? "bar-a" : "bar-b" });
        rect.appendChild(svgEl("title", null, (vi === 0 ? labelA : labelB) + " " + fmtSeconds(v) + " (" + g.label + ")"));
        svg.appendChild(rect);
      });
      svg.appendChild(svgEl("text", { x: base, y: H - 8, "class": "axis", "text-anchor": "middle" }, g.label));
    });
    var key = el("p", "bar-key small muted");
    key.appendChild(el("span", "swatch bar-a"));
    key.appendChild(document.createTextNode(" " + labelA + "   "));
    key.appendChild(el("span", "swatch bar-b"));
    key.appendChild(document.createTextNode(" " + labelB));
    container.appendChild(key);
  }

  function hbarChart(container, rows) {
    clear(container);
    var W = 420, rowH = 24, L = 120, R = 40;
    var H = Math.max(40, rows.length * rowH + 8);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, "class": "chart-svg", role: "img", "aria-label": "detector reasons" });
    container.appendChild(svg);
    if (!rows.length) {
      svg.appendChild(svgEl("text", { x: W / 2, y: 24, "class": "chart-empty", "text-anchor": "middle" }, "No incidents yet"));
      return;
    }
    var max = 0;
    rows.forEach(function (r) { max = Math.max(max, r.value); });
    rows.forEach(function (r, i) {
      var yy = 4 + i * rowH;
      svg.appendChild(svgEl("text", { x: L - 8, y: yy + 14, "class": "axis axis-label", "text-anchor": "end" }, r.label));
      svg.appendChild(svgEl("rect", { x: L, y: yy + 3, width: Math.max(3, r.value / max * (W - L - R)), height: 14, rx: 3, "class": "hbar" }));
      svg.appendChild(svgEl("text", { x: L + Math.max(3, r.value / max * (W - L - R)) + 6, y: yy + 14, "class": "axis" }, r.value));
    });
  }

  /** Compare the newest samples with the ones before them. */
  function trend(values) {
    var n = Math.min(6, Math.floor(values.length / 2));
    if (n < 1) { return null; }
    function mean(slice) { return slice.reduce(function (a, b) { return a + b; }, 0) / slice.length; }
    var recent = mean(values.slice(values.length - n));
    var prior = mean(values.slice(values.length - 2 * n, values.length - n));
    var delta = recent - prior;
    if (Math.abs(delta) < 0.05) { return { dir: "flat", pct: 0 }; }
    return { dir: delta > 0 ? "up" : "down", pct: prior > 0 ? Math.abs(delta) / prior * 100 : null };
  }

  /** goodWhen: "up" (more is better), "down" (less is better) or null (neutral). */
  function renderDelta(node, values, goodWhen) {
    var info = trend(values);
    node.className = "delta";
    if (!info) { node.textContent = "\u00a0"; return; }
    if (info.dir === "flat") { node.textContent = "\u25ac steady"; node.className = "delta delta-flat"; return; }
    var arrow = info.dir === "up" ? "\u25b2 " : "\u25bc ";
    node.textContent = arrow + (info.pct === null ? "new" : Math.round(info.pct) + "%");
    var good = goodWhen === null ? null : (info.dir === goodWhen);
    node.className = "delta " + (good === null ? "delta-flat" : (good ? "delta-good" : "delta-bad"));
  }

  // --------------------------------------------------------------- index page

  var OPEN_STATUSES = ["DETECTED", "ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING"];
  var ui = { clusters: [], incidents: [], activity: [], selected: "all", filter: "all", metrics: null, status: null, poller: null };
  var sigs = {};

  function isOpen(incident) { return OPEN_STATUSES.indexOf(incident.status) !== -1; }

  function clusterIndex(clusterId) {
    for (var i = 0; i < ui.clusters.length; i += 1) { if (ui.clusters[i].id === clusterId) { return i; } }
    return -1;
  }

  function clusterName(clusterId) {
    var i = clusterIndex(clusterId);
    return i === -1 ? "cluster #" + clusterId + " (removed)" : ui.clusters[i].name;
  }

  function colorClass(clusterId) {
    var i = clusterIndex(clusterId);
    return "c" + ((i === -1 ? 0 : i) % PALETTE_SIZE);
  }

  function changed(name, value) {
    var sig = signature(value);
    if (sigs[name] === sig) { return false; }
    sigs[name] = sig;
    return true;
  }

  function showToast(message, kind) {
    var toast = $("toast");
    if (!toast) { return; }
    toast.textContent = message;
    toast.className = "toast " + (kind === "error" ? "toast-error" : "toast-ok");
    show(toast, true);
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(function () { show(toast, false); }, 6000);
  }

  function renderMetrics(metrics) {
    $("metric-total").textContent = isNum(metrics.total) ? metrics.total : DASH;
    $("metric-resolved").textContent = isNum(metrics.resolved) ? metrics.resolved : DASH;
    $("metric-mttd").textContent = fmtSeconds(metrics.avg_mttd_seconds);
    $("metric-mttr").textContent = fmtSeconds(metrics.avg_mttr_seconds);
  }

  // ---- cluster cards

  function openIncidentsOf(clusterId) {
    return ui.incidents.filter(function (i) { return i.cluster_id === clusterId && isOpen(i); });
  }

  // Workloads that are failing right now (same rule alerts.js uses for the navbar error).
  function sickWorkloadsOf(cluster) {
    return (cluster.workloads || []).filter(function (w) { return w.status !== "Healthy" && w.status !== "ScaledToZero"; });
  }

  // A cluster belongs in the "active incident" area while it has an open incident
  // OR a failing workload, and returns to "Monitored clusters" once both are gone.
  function inError(cluster) {
    return openIncidentsOf(cluster.id).length > 0 || sickWorkloadsOf(cluster).length > 0;
  }

  function lastIncidentOf(clusterId) {
    var list = ui.incidents.filter(function (i) { return i.cluster_id === clusterId; });
    return list.length ? list[0] : null; // the API returns newest first
  }

  function sampleAgeText(iso) {
    if (!iso) { return "no sample yet"; }
    var seconds = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
    if (!isFinite(seconds)) { return DASH; }
    return seconds < 60 ? Math.round(seconds) + " s ago" : Math.floor(seconds / 60) + " min ago";
  }

  function stat(label, value, tone) {
    var box = el("div", "stat" + (tone ? " stat-" + tone : ""));
    box.appendChild(el("span", "stat-value", value));
    box.appendChild(el("span", "stat-label", label));
    return box;
  }

  function clusterCard(cluster, withIncident) {
    var latest = cluster.latest || {};
    var card = el("article", "cluster-card " + colorClass(cluster.id) + (withIncident ? " cluster-card-incident" : ""));

    var head = el("header", "cluster-head");
    var title = el("div", "cluster-title");
    title.appendChild(el("span", "cluster-dot " + colorClass(cluster.id)));
    title.appendChild(el("h3", null, cluster.name));
    head.appendChild(title);
    var live = cluster.state === "connected";
    var stateBadge = el("span", "badge " + (live ? (withIncident ? "status-failed" : "status-resolved") : "status-detected"),
      live ? (withIncident ? (openIncidentsOf(cluster.id).length ? "Incident" : "Error") : "Analysing") : String(cluster.state).replace(/_/g, " "));
    head.appendChild(stateBadge);
    card.appendChild(head);

    card.appendChild(el("p", "muted small mono cluster-context",
      cluster.is_default ? "built-in cluster" + (cluster.context ? " \u00b7 " + cluster.context : "") : (cluster.context || DASH)));

    var stats = el("div", "stats");
    stats.appendChild(stat("pods ready", isNum(latest.pods_total) ? latest.pods_ready + "/" + latest.pods_total : DASH,
      isNum(latest.pods_total) && latest.pods_ready < latest.pods_total ? "bad" : null));
    stats.appendChild(stat("restarts", isNum(latest.restarts_total) ? latest.restarts_total : DASH, latest.restarts_total > 0 ? "warn" : null));
    stats.appendChild(stat("logs / min", isNum(latest.log_rate) ? fmtNum(latest.log_rate) : DASH));
    stats.appendChild(stat("errors / min", isNum(latest.error_rate) ? fmtNum(latest.error_rate) : DASH, latest.error_rate > 0 ? "bad" : null));
    card.appendChild(stats);

    var spark = el("div", "spark");
    card.appendChild(spark);
    var series = cluster.series || {};
    sparkline(spark, withIncident ? series.unhealthy : series.log_rate, colorClass(cluster.id));

    var workloads = cluster.workloads || [];
    var sick = workloads.filter(function (w) { return w.status !== "Healthy" && w.status !== "ScaledToZero"; });
    card.appendChild(el("p", "small cluster-workloads" + (sick.length ? " text-bad" : " muted"),
      workloads.length ? workloads.length + " workload" + (workloads.length === 1 ? "" : "s") + (sick.length ? " \u00b7 " + sick.length + " not healthy: " + sick.map(function (w) { return w.name; }).join(", ") : " \u00b7 all healthy") : "no workloads sampled yet"));

    if (withIncident) {
      var openList = openIncidentsOf(cluster.id);
      if (!openList.length) {
        sick.forEach(function (w) {
          var wrow = el("div", "incident-line");
          wrow.appendChild(el("span", "mono", w.namespace + "/" + w.name));
          wrow.appendChild(el("span", "badge status-failed", w.status));
          if (w.problem) { wrow.appendChild(el("span", "muted small", w.problem)); }
          card.appendChild(wrow);
        });
        var prev = lastIncidentOf(cluster.id);
        if (prev) {
          var prevRow = el("div", "incident-line");
          prevRow.appendChild(el("span", "muted small", "Last incident"));
          var prevLink = el("a", "mono", "#" + prev.id);
          prevLink.href = "/incidents/" + encodeURIComponent(prev.id);
          prevRow.appendChild(prevLink);
          prevRow.appendChild(statusBadge(prev.status));
          card.appendChild(prevRow);
        }
      }
      openList.forEach(function (inc) {
        var row = el("div", "incident-line");
        var link = el("a", "mono", "#" + inc.id);
        link.href = "/incidents/" + encodeURIComponent(inc.id);
        row.appendChild(link);
        row.appendChild(el("span", null, inc.namespace + "/" + inc.service));
        row.appendChild(statusBadge(inc.status));
        row.appendChild(el("span", "muted small", inc.reason));
        card.appendChild(row);
        if (inc.status === "AWAITING_APPROVAL") {
          var go = el("a", "btn btn-warn btn-small", "Review and approve");
          go.href = "/incidents/" + encodeURIComponent(inc.id);
          card.appendChild(go);
        }
      });
    } else {
      var last = lastIncidentOf(cluster.id);
      if (last) {
        var lastRow = el("div", "incident-line");
        lastRow.appendChild(el("span", "muted small", "Last incident"));
        var lastLink = el("a", "mono", "#" + last.id);
        lastLink.href = "/incidents/" + encodeURIComponent(last.id);
        lastRow.appendChild(lastLink);
        lastRow.appendChild(statusBadge(last.status));
        card.appendChild(lastRow);
      }
    }

    var footer = el("footer", "cluster-foot");
    var age = el("span", "muted small sample-age", live ? "sampled " + sampleAgeText(cluster.last_sample_at) : (cluster.state_detail || cluster.state));
    if (live) { age.setAttribute("data-ts", cluster.last_sample_at || ""); }
    footer.appendChild(age);
    var actions = el("div", "cluster-actions");
    var view = el("button", "btn btn-small", "Analytics");
    view.type = "button";
    view.addEventListener("click", function () {
      ui.selected = String(cluster.id);
      $("analytics-cluster").value = ui.selected;
      sigs.charts = null;
      renderAnalytics();
      var target = $("analytics-heading");
      if (target && typeof target.scrollIntoView === "function") { target.scrollIntoView({ behavior: "smooth", block: "start" }); }
    });
    actions.appendChild(view);
    var del = el("button", "btn btn-small btn-danger", "Delete");
    del.type = "button";
    del.disabled = !cluster.can_delete;
    if (!cluster.can_delete) { del.title = cluster.delete_blocked_reason || "Cannot delete this cluster"; }
    del.addEventListener("click", function () { openDeleteDialog(cluster); });
    actions.appendChild(del);
    footer.appendChild(actions);
    card.appendChild(footer);
    return card;
  }

  function renderClusters() {
    var healthy = ui.clusters.filter(function (c) { return !inError(c); });
    var sick = ui.clusters.filter(function (c) { return inError(c); });
    var data = { c: ui.clusters, i: ui.incidents.map(function (i) { return [i.id, i.status, i.cluster_id]; }) };
    if (changed("clusters", data)) {
      var grid = $("cluster-grid");
      var state = $("cluster-state");
      clear(grid);
      if (!healthy.length) {
        state.className = "state" + (ui.clusters.length ? " state-error" : "");
        state.textContent = ui.clusters.length
          ? "Every connected cluster currently has an active incident (see below)."
          : "No clusters connected. Use \u201cConnect cluster\u201d to start analysing one.";
        show(state, true);
        show(grid, false);
      } else {
        show(state, false);
        show(grid, true);
        healthy.forEach(function (c) { grid.appendChild(clusterCard(c, false)); });
      }
      $("clusters-sub").textContent = ui.clusters.length + " cluster" + (ui.clusters.length === 1 ? "" : "s") + " connected \u00b7 " + healthy.length + " healthy";

      var activeGrid = $("active-grid");
      var activeState = $("active-state");
      clear(activeGrid);
      $("active-count").textContent = String(sick.length);
      $("active-count").className = "badge " + (sick.length ? "status-failed" : "status-resolved");
      $("incident-box").className = "panel panel-incident" + (sick.length ? " panel-incident-live" : "");
      show(activeState, !sick.length);
      show(activeGrid, sick.length > 0);
      sick.forEach(function (c) { activeGrid.appendChild(clusterCard(c, true)); });
    }
  }

  function renderKpis() {
    var clusters = ui.clusters;
    var healthy = clusters.filter(function (c) { return !inError(c); }).length;
    $("kpi-clusters").textContent = String(clusters.length);
    $("kpi-clusters-note").textContent = healthy + " healthy \u00b7 " + (clusters.length - healthy) + " with errors";
    var ready = 0, total = 0;
    clusters.forEach(function (c) { if (c.latest) { ready += c.latest.pods_ready; total += c.latest.pods_total; } });
    $("kpi-pods").textContent = total ? ready + " / " + total : DASH;
    $("kpi-pods-note").textContent = total ? Math.round(ready / total * 100) + "% ready across all clusters" : "no samples yet";
  }

  // ---- live analytics

  function selectedClusters() {
    if (ui.selected === "all") { return ui.clusters; }
    return ui.clusters.filter(function (c) { return String(c.id) === ui.selected; });
  }

  function syncClusterSelect() {
    var select = $("analytics-cluster");
    var sig = signature(ui.clusters.map(function (c) { return [c.id, c.name]; }));
    if (select.getAttribute("data-sig") === sig) { return; }
    select.setAttribute("data-sig", sig);
    clear(select);
    var all = el("option", null, "All clusters");
    all.value = "all";
    select.appendChild(all);
    ui.clusters.forEach(function (c) {
      var option = el("option", null, c.name);
      option.value = String(c.id);
      select.appendChild(option);
    });
    if (ui.selected !== "all" && clusterIndex(parseInt(ui.selected, 10)) === -1) { ui.selected = "all"; }
    select.value = ui.selected;

    var legend = $("chart-legend");
    clear(legend);
    ui.clusters.forEach(function (c) {
      var item = el("span", "legend-item");
      item.appendChild(el("span", "swatch " + colorClass(c.id)));
      item.appendChild(document.createTextNode(c.name));
      legend.appendChild(item);
    });
  }

  function perClusterSeries(key, area) {
    return selectedClusters().map(function (c) {
      var s = c.series || {};
      return { name: c.name, cls: "s-" + colorClass(c.id), points: seriesPoints(s.ts, s[key]), area: !!area && selectedClusters().length === 1 };
    });
  }

  function lastValues(seriesList) {
    return sumAligned(seriesList.map(function (s) { return s.points; })).map(function (p) { return p.v; });
  }

  function renderOneChart(id, valId, deltaId, key, goodWhen, opts) {
    var list = perClusterSeries(key, true);
    lineChart($(id), { series: list, label: opts.label, unit: opts.unit });
    var totals = lastValues(list);
    $(valId).textContent = totals.length ? fmtNum(totals[totals.length - 1]) : DASH;
    renderDelta($(deltaId), totals, goodWhen);
  }

  function renderAnalytics() {
    syncClusterSelect();
    var scoped = selectedClusters();
    if (!changed("charts", { sel: ui.selected, s: scoped.map(function (c) { return [c.id, (c.series || {}).ts]; }) })) { return; }

    // pods: ready (solid) vs total (dashed), summed over the selection
    var readyList = perClusterSeries("pods_ready");
    var totalList = perClusterSeries("pods_total");
    var ready = sumAligned(readyList.map(function (s) { return s.points; }));
    var total = sumAligned(totalList.map(function (s) { return s.points; }));
    lineChart($("chart-pods"), {
      label: "Pods ready",
      series: [
        { name: "total", cls: "s-muted", points: total, dashed: true },
        { name: "ready", cls: "s-good", points: ready, area: true }
      ]
    });
    $("val-pods").textContent = ready.length ? ready[ready.length - 1].v + " / " + total[total.length - 1].v : DASH;
    renderDelta($("delta-pods"), ready.map(function (p) { return p.v; }), "up");

    renderOneChart("chart-logs", "val-logs", "delta-logs", "log_rate", null, { label: "Log lines per minute" });
    renderOneChart("chart-errors", "val-errors", "delta-errors", "error_rate", "down", { label: "Error lines per minute" });
    renderOneChart("chart-restarts", "val-restarts", "delta-restarts", "restarts", "down", { label: "Container restarts" });
    renderOneChart("chart-unhealthy", "val-unhealthy", "delta-unhealthy", "unhealthy", "down", { label: "Unhealthy pods" });
    renderOneChart("chart-warnings", "val-warnings", "delta-warnings", "warnings", "down", { label: "Warning events" });
  }

  function renderIncidentAnalytics() {
    if (!changed("incident-analytics", ui.incidents.map(function (i) { return [i.id, i.status, i.mttd_seconds, i.mttr_seconds, i.reason]; }))) { return; }
    var counts = {};
    var reasons = {};
    ui.incidents.forEach(function (i) {
      counts[i.status] = (counts[i.status] || 0) + 1;
      reasons[i.reason] = (reasons[i.reason] || 0) + 1;
    });
    var order = ["DETECTED", "ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING", "RESOLVED", "FAILED"];
    donutChart($("chart-status"), order.filter(function (s) { return counts[s]; }).map(function (s) {
      return { label: s, value: counts[s], cls: "arc-" + s.toLowerCase() };
    }), String(ui.incidents.length));

    var measured = ui.incidents.filter(function (i) { return isNum(i.mttd_seconds) || isNum(i.mttr_seconds); }).slice(0, 8).reverse();
    barChart($("chart-mttr"), measured.map(function (i) { return { label: "#" + i.id, values: [i.mttd_seconds, i.mttr_seconds] }; }), "MTTD", "MTTR");

    hbarChart($("chart-reasons"), Object.keys(reasons).map(function (r) { return { label: r, value: reasons[r] }; })
      .sort(function (a, b) { return b.value - a.value; }).slice(0, 6));
  }

  // ---- workloads, activity, incident table

  function renderWorkloads() {
    var rows = [];
    selectedClusters().forEach(function (c) {
      (c.workloads || []).forEach(function (w) { rows.push([c, w]); });
    });
    if (!changed("workloads", { s: ui.selected, r: rows.map(function (r) { return [r[0].id, r[1]]; }) })) { return; }
    var state = $("workload-state");
    var wrap = $("workload-wrap");
    var body = $("workload-rows");
    clear(body);
    if (!rows.length) { show(state, true); show(wrap, false); return; }
    show(state, false);
    show(wrap, true);
    rows.forEach(function (pair) {
      var c = pair[0], w = pair[1];
      var tr = el("tr");
      var cell = el("td", "nowrap");
      cell.appendChild(el("span", "cluster-dot " + colorClass(c.id)));
      cell.appendChild(document.createTextNode(c.name));
      tr.appendChild(cell);
      tr.appendChild(el("td", null, w.namespace + "/" + w.name));
      tr.appendChild(el("td", "mono small", w.image));
      tr.appendChild(el("td", "num", w.ready + " / " + w.desired));
      tr.appendChild(el("td", "num", w.restarts));
      var status = el("td");
      var tone = w.status === "Healthy" ? "status-resolved" : (w.status === "ScaledToZero" ? "" : "status-failed");
      status.appendChild(el("span", "badge " + tone, w.problem ? w.status + " \u00b7 " + w.problem : w.status));
      tr.appendChild(status);
      body.appendChild(tr);
    });
  }

  function renderActivity() {
    if (!changed("activity", ui.activity.map(function (a) { return a.id; }))) { return; }
    var list = $("activity-list");
    var state = $("activity-state");
    clear(list);
    if (!ui.activity.length) { show(state, true); show(list, false); return; }
    show(state, false);
    show(list, true);
    ui.activity.slice(0, 25).forEach(function (a) {
      var li = el("li", "t-" + String(a.step || "").toLowerCase());
      var head = el("div", "activity-head");
      head.appendChild(el("span", "activity-time mono", fmtTimeShort(a.timestamp)));
      head.appendChild(el("span", "tag " + colorClass(a.cluster_id), clusterName(a.cluster_id)));
      var link = el("a", "mono", "#" + a.incident_id);
      link.href = "/incidents/" + encodeURIComponent(a.incident_id);
      head.appendChild(link);
      head.appendChild(el("span", "t-step", String(a.step || "").replace(/_/g, " ")));
      li.appendChild(head);
      li.appendChild(el("p", "t-msg small", a.message));
      list.appendChild(li);
    });
  }

  function renderIncidentList() {
    var all = ui.incidents;
    var list = all.filter(function (i) {
      return ui.filter === "all" || (ui.filter === "open" ? isOpen(i) : !isOpen(i));
    });
    if (!changed("incident-table", { f: ui.filter, l: list, n: ui.clusters.map(function (c) { return c.name; }) })) { return; }

    var state = $("incident-state");
    var wrap = $("incident-table-wrap");
    var rows = $("incident-rows");
    clear(rows);

    if (!list.length) {
      state.className = "state";
      state.textContent = all.length ? "No incidents match this filter."
        : "No incidents yet. Run scripts/deploy_bad.sh v2 to inject a failure.";
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

      var clusterCell = el("td", "nowrap");
      clusterCell.appendChild(el("span", "cluster-dot " + colorClass(item.cluster_id)));
      clusterCell.appendChild(document.createTextNode(clusterName(item.cluster_id)));
      tr.appendChild(clusterCell);
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

  function renderIndex() {
    renderClusters();
    renderKpis();
    renderAnalytics();
    renderIncidentAnalytics();
    renderWorkloads();
    renderActivity();
    renderIncidentList();
  }

  function setLive(ok) {
    var box = $("live-indicator");
    if (!box) { return; }
    box.className = "live " + (ok ? "live-on" : "live-stale");
    $("live-text").textContent = ok ? "Live \u00b7 updated " + new Date().toLocaleTimeString(undefined, { hour12: false }) : "Connection lost \u00b7 retrying";
  }

  function tickSampleAges() {
    var nodes = document.querySelectorAll(".sample-age[data-ts]");
    Array.prototype.forEach.call(nodes, function (node) {
      node.textContent = "sampled " + sampleAgeText(node.getAttribute("data-ts"));
    });
  }

  function refreshIndex() {
    function attempt(path, assign) {
      return api(path).then(function (value) { assign(value); return true; }, function () { return false; });
    }
    return Promise.all([
      attempt("/api/metrics", function (m) { ui.metrics = m; renderMetrics(m); }),
      attempt("/api/incidents", function (l) { ui.incidents = Array.isArray(l) ? l : []; ui.incidentsLoaded = true; }),
      attempt("/api/clusters", function (c) { ui.clusters = Array.isArray(c) ? c : []; ui.clustersLoaded = true; }),
      attempt("/api/activity?limit=25", function (a) { ui.activity = Array.isArray(a) ? a : []; }),
      loadStatus().then(function () { return true; }, function () { return false; })
    ]).then(function (results) {
      var incidentsOk = results[1];
      var anyFailed = results.some(function (ok) { return !ok; });
      setBanner(anyFailed ? "Cannot reach the IncidentIQ API. Showing the last data received; retrying every few seconds." : "");
      setLive(!anyFailed);
      if (!incidentsOk && !ui.incidentsLoaded) {
        var state = $("incident-state");
        state.className = "state state-error";
        state.textContent = "Could not load incidents.";
        show(state, true);
        show($("incident-table-wrap"), false);
      } else {
        renderIndex();
      }
      if (!results[2] && !ui.clustersLoaded) {
        var cs = $("cluster-state");
        cs.className = "state state-error";
        cs.textContent = "Could not load clusters.";
        show(cs, true);
      }
    });
  }

  // ----------------------------------------------------- connect / delete dialogs

  function openDialog(dialog) {
    if (typeof dialog.showModal === "function") { if (!dialog.open) { dialog.showModal(); } }
    else { dialog.setAttribute("open", ""); }
  }

  function closeDialog(dialog) {
    if (typeof dialog.close === "function") { dialog.close(); } else { dialog.removeAttribute("open"); }
  }

  function savedKey() {
    var store = storage();
    return (store && store.getItem(KEY_STORAGE)) || "";
  }

  function rememberKey(key) {
    var store = storage();
    if (store) { try { store.setItem(KEY_STORAGE, key); } catch (err) { /* ignore */ } }
  }

  function forgetKey() {
    var store = storage();
    if (store) { try { store.removeItem(KEY_STORAGE); } catch (err) { /* ignore */ } }
  }

  function setMsg(id, text, kind) {
    var node = $(id);
    node.textContent = text;
    node.className = "small " + (kind === "ok" ? "msg-ok" : (kind === "error" ? "msg-error" : "muted"));
  }

  function sanitizeName(text) {
    return String(text).replace(/[^A-Za-z0-9._ -]/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 63);
  }

  function loadContexts() {
    var key = $("connect-key").value.trim();
    if (!key) { setMsg("connect-msg", "Enter the API key first.", "error"); $("connect-key").focus(); return Promise.resolve(); }
    setMsg("connect-msg", "Reading kubeconfig contexts\u2026", "info");
    return api("/api/kube/contexts", { headers: { "X-API-Key": key } }).then(function (list) {
      rememberKey(key);
      var select = $("connect-context");
      clear(select);
      if (!list.length) {
        var none = el("option", null, "No contexts found");
        none.value = "";
        select.appendChild(none);
        setMsg("connect-msg", "The backend has no kubeconfig contexts. Run it on a machine with a kubeconfig (see the README).", "error");
        return;
      }
      list.forEach(function (c) {
        var option = el("option", null, c.name + (c.active ? " (current)" : "") + (c.connected ? " \u2013 already connected" : ""));
        option.value = c.name;
        option.disabled = !!c.connected;
        select.appendChild(option);
      });
      var firstFree = list.filter(function (c) { return !c.connected; })[0];
      if (firstFree) { select.value = firstFree.name; if (!$("connect-name").value) { $("connect-name").value = sanitizeName(firstFree.name); } }
      setMsg("connect-msg", list.length + " context" + (list.length === 1 ? "" : "s") + " found.", "ok");
    }, function (err) {
      if (err.status === 401) { forgetKey(); setMsg("connect-msg", "The API key was rejected.", "error"); }
      else { setMsg("connect-msg", "Could not read contexts: " + err.message, "error"); }
    });
  }

  var connecting = false;

  function submitConnect() {
    if (connecting) { return; }
    var key = $("connect-key").value.trim();
    var context = $("connect-context").value;
    var name = $("connect-name").value.trim();
    if (!key) { setMsg("connect-msg", "Enter the API key.", "error"); return; }
    if (!context) { setMsg("connect-msg", "Load and choose a kubeconfig context.", "error"); return; }
    if (!name) { setMsg("connect-msg", "Give the cluster a display name.", "error"); return; }
    connecting = true;
    $("connect-submit").disabled = true;
    setMsg("connect-msg", "Testing the connection\u2026", "info");
    api("/api/clusters", { method: "POST", headers: { "X-API-Key": key }, body: { name: name, context: context } }).then(function (cluster) {
      rememberKey(key);
      closeDialog($("connect-dialog"));
      showToast("Connected " + cluster.name + ". Analysis has started.", "ok");
      if (ui.poller) { ui.poller.now(); }
    }, function (err) {
      if (err.status === 401) { forgetKey(); setMsg("connect-msg", "The API key was rejected.", "error"); }
      else { setMsg("connect-msg", err.message, "error"); }
    }).then(function () {
      connecting = false;
      $("connect-submit").disabled = false;
    });
  }

  var deleteTarget = null;
  var deleting = false;

  function openDeleteDialog(cluster) {
    deleteTarget = cluster;
    $("delete-title").textContent = "Delete cluster \u201c" + cluster.name + "\u201d";
    $("delete-text").textContent = "IncidentIQ will stop analysing " + cluster.name + " and remove its live metrics. Incident history is kept. The cluster itself is not touched.";
    $("delete-key").value = savedKey();
    setMsg("delete-msg", "", "info");
    openDialog($("delete-dialog"));
  }

  function confirmDelete() {
    if (deleting || !deleteTarget) { return; }
    var key = $("delete-key").value.trim();
    if (!key) { setMsg("delete-msg", "Enter the API key.", "error"); return; }
    deleting = true;
    $("delete-confirm").disabled = true;
    setMsg("delete-msg", "Deleting\u2026", "info");
    var target = deleteTarget;
    api("/api/clusters/" + encodeURIComponent(target.id), { method: "DELETE", headers: { "X-API-Key": key } }).then(function () {
      rememberKey(key);
      closeDialog($("delete-dialog"));
      showToast("Deleted " + target.name + ".", "ok");
      sigs = {};
      if (ui.poller) { ui.poller.now(); }
    }, function (err) {
      if (err.status === 401) { forgetKey(); setMsg("delete-msg", "The API key was rejected.", "error"); }
      else { setMsg("delete-msg", err.message, "error"); }
    }).then(function () {
      deleting = false;
      $("delete-confirm").disabled = false;
    });
  }

  function bootIndex() {
    $("connect-btn").addEventListener("click", function () {
      $("connect-key").value = savedKey();
      setMsg("connect-msg", "", "info");
      openDialog($("connect-dialog"));
      if ($("connect-key").value) { loadContexts(); }
    });
    $("connect-cancel").addEventListener("click", function () { closeDialog($("connect-dialog")); });
    $("connect-load").addEventListener("click", loadContexts);
    $("connect-submit").addEventListener("click", submitConnect);
    $("delete-cancel").addEventListener("click", function () { closeDialog($("delete-dialog")); });
    $("delete-confirm").addEventListener("click", confirmDelete);
    $("analytics-cluster").addEventListener("change", function (event) {
      ui.selected = event.target.value;
      sigs.charts = null;
      sigs.workloads = null;
      renderAnalytics();
      renderWorkloads();
    });
    $("incident-filter").addEventListener("change", function (event) {
      ui.filter = event.target.value;
      renderIncidentList();
    });
    setInterval(tickSampleAges, 1000);
    ui.poller = startPolling(refreshIndex, function () { return POLL_MS; });
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

  var clusterNames = {};

  function clusterLabel(clusterId) {
    return clusterNames[clusterId] || "cluster #" + clusterId;
  }

  function loadClusterNames() {
    return api("/api/clusters").then(function (list) {
      var names = {};
      (Array.isArray(list) ? list : []).forEach(function (c) { names[c.id] = c.name; });
      if (signature(names) !== signature(clusterNames)) {
        clusterNames = names;
        lastDetailSig = null;
        if (currentIncident) { renderIncident(currentIncident); }  // show the name now, not on the next poll
      }
      return true;   // report success: refreshIncident() treats anything but true as "API unreachable"
    }, function () { return true; /* names are cosmetic, so a failure here must not raise the banner */ });
  }

  function renderSummary(inc) {
    var rca = inc.rca || null;
    var summary = $("summary");
    clear(summary);
    summary.appendChild(fact("Cluster", clusterLabel(inc.cluster_id)));
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
      loadStatus().then(function () { return true; }, function () { return false; }),
      loadClusterNames()
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
      bootIndex();
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