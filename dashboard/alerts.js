/*
 * IncidentIQ: error alerts (standalone add-on, does NOT touch app.js).
 * Adds a navbar error pill with a "View cluster" button, a popup when a cluster
 * enters an error, and scroll-to-cluster. Runs on the dashboard page only.
 * CSP-safe: no innerHTML, no inline styles, no inline handlers. Needs the CSS block
 * (.nav-alert, .alert-menu, .dialog-alert, .cluster-card-flash ...) from style.css.
 */
(function () {
  "use strict";

  var POLL_MS = 3000;
  var SEEN_KEY = "incidentiq.alertSeen.v2";
  var REMIND_MS = 5 * 60 * 1000;   // re-show the popup only if the error is still unresolved after this long
  var GRACE_MS = 60 * 1000;        // an error must be gone this long before it counts as a brand-new one next time
  var OPEN = ["DETECTED", "ANALYZING", "AWAITING_APPROVAL", "REMEDIATING", "VERIFYING"];
  var state = { clusters: [], incidents: [], alerts: [], seen: null, target: null, sig: "", loaded: false };
  var baseTitle = document.title;
  var nav, navText, navGo, navToggle, menu, menuList, dialog, dTitle, dSub, dList;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = String(text); }
    return n;
  }
  function clear(n) { while (n.firstChild) { n.removeChild(n.firstChild); } }
  function store() { try { return window.localStorage; } catch (e) { try { return window.sessionStorage; } catch (e2) { return null; } } }
  function pretty(s) { return String(s || "").replace(/_/g, " "); }

  function getJson(path) {
    return fetch(path, { cache: "no-store", headers: {} }).then(function (r) {
      if (!r.ok) { throw new Error("HTTP " + r.status); }
      return r.json();
    });
  }

  // ---------------------------------------------------------------- build UI
  function build() {
    var bar = document.querySelector(".topbar");
    if (!bar) { return false; }

    nav = el("div", "nav-alert");
    nav.setAttribute("role", "alert");
    nav.hidden = true;
    navToggle = el("button", "nav-alert-pill");
    navToggle.type = "button";
    navToggle.setAttribute("aria-haspopup", "true");
    navToggle.setAttribute("aria-expanded", "false");
    navToggle.appendChild(el("span", "nav-alert-icon", "!"));
    navText = el("span", null, "Error");
    navToggle.appendChild(navText);
    navGo = el("button", "btn btn-small btn-alert", "View cluster");
    navGo.type = "button";
    menu = el("div", "alert-menu");
    menu.hidden = true;
    menu.appendChild(el("p", "alert-menu-title", "Clusters needing attention"));
    menuList = el("ul", "alert-menu-list");
    menu.appendChild(menuList);
    nav.appendChild(navToggle);
    nav.appendChild(navGo);
    nav.appendChild(menu);
    var actions = bar.querySelector(".top-actions");
    if (actions) { bar.insertBefore(nav, actions); } else { bar.appendChild(nav); }

    dialog = el("dialog", "dialog dialog-alert");
    var head = el("div", "alert-dialog-head");
    head.appendChild(el("span", "alert-dialog-icon", "!"));
    var hb = el("div");
    dTitle = el("h2", null, "Cluster error detected");
    dSub = el("p", "muted small");
    hb.appendChild(dTitle);
    hb.appendChild(dSub);
    head.appendChild(hb);
    dList = el("ul", "alert-dialog-list");
    var actionsRow = el("div", "dialog-actions");
    var dismiss = el("button", "btn", "Dismiss");
    dismiss.type = "button";
    var go = el("button", "btn btn-alert", "Go to cluster");
    go.type = "button";
    actionsRow.appendChild(dismiss);
    actionsRow.appendChild(go);
    dialog.appendChild(head);
    dialog.appendChild(dList);
    dialog.appendChild(actionsRow);
    document.body.appendChild(dialog);

    navToggle.addEventListener("click", function (e) { e.stopPropagation(); toggleMenu(); });
    navGo.addEventListener("click", function () { if (state.alerts.length) { goToCluster(state.alerts[0].cluster); } });
    dismiss.addEventListener("click", function () { closeDialog(); });
    go.addEventListener("click", function () { closeDialog(); if (state.target) { goToCluster(state.target); } });
    document.addEventListener("click", function (e) { if (!nav.contains(e.target)) { toggleMenu(false); } });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") { toggleMenu(false); } });
    window.addEventListener("pageshow", function (e) { if (e.persisted) { closeDialog(); } });
    return true;
  }

  function toggleMenu(open) {
    var willOpen = open === undefined ? menu.hidden : open;
    menu.hidden = !willOpen;
    navToggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
  }
  function openDialog() {
    if (typeof dialog.showModal === "function") { if (!dialog.open) { dialog.showModal(); } }
    else { dialog.setAttribute("open", ""); }
  }
  function closeDialog() {
    if (typeof dialog.close === "function") { dialog.close(); } else { dialog.removeAttribute("open"); }
  }

  // --------------------------------------------------------------- navigation
  // Prefer the exact link the Incidents table already uses for this incident.
  function incidentUrl(id) {
    var links = document.querySelectorAll("#incident-rows a");
    for (var i = 0; i < links.length; i += 1) {
      if (links[i].textContent.replace(/^#/, "") === String(id) && links[i].getAttribute("href")) {
        return links[i].getAttribute("href");
      }
    }
    return "/incidents/" + encodeURIComponent(id);
  }

  function findCard(cluster) {
    var cards = document.querySelectorAll(".cluster-card");
    var best = null;
    for (var i = 0; i < cards.length; i += 1) {
      var h = cards[i].querySelector("h3");
      if (h && h.textContent === cluster.name) {
        if (cards[i].closest("#active-grid")) { return cards[i]; }
        best = best || cards[i];
      }
    }
    return best;
  }

  function goToCluster(cluster) {
    var card = findCard(cluster);
    var target = card || document.getElementById("incident-box");
    if (!target) { return; }
    if (target.scrollIntoView) { target.scrollIntoView({ behavior: "smooth", block: "center" }); }
    if (card) {
      card.classList.remove("cluster-card-flash");
      void card.offsetWidth;
      card.classList.add("cluster-card-flash");
      setTimeout(function () { card.classList.remove("cluster-card-flash"); }, 3000);
    }
  }

  // ------------------------------------------------------------------ alerts
  function compute() {
    var list = [];
    state.clusters.forEach(function (c) {
      var incs = state.incidents.filter(function (i) { return i.cluster_id === c.id && OPEN.indexOf(i.status) !== -1; });
      var sick = (c.workloads || []).filter(function (w) { return w.status !== "Healthy" && w.status !== "ScaledToZero"; });
      var offline = c.state && c.state !== "connected";
      if (!incs.length && !sick.length && !offline) { return; }
      var lines = [], title, items = [];
      incs.forEach(function (i) {
        items.push("i" + i.id);
        lines.push("Incident #" + i.id + " \u00b7 " + i.namespace + "/" + i.service + " \u00b7 " + pretty(i.status));
        if (!title) { title = i.reason || "Incident open"; }
      });
      sick.forEach(function (w) {
        items.push("w" + w.namespace + "/" + w.name);
        lines.push(w.namespace + "/" + w.name + " \u00b7 " + (w.problem ? w.status + " \u00b7 " + w.problem : w.status));
        if (!title) { title = w.problem || w.status; }
      });
      if (offline) {
        items.push("s" + c.state);
        lines.push("Cluster " + pretty(c.state) + (c.state_detail ? " \u00b7 " + c.state_detail : ""));
        if (!title) { title = pretty(c.state); }
      }
      list.push({
        cluster: c, title: title, lines: lines, items: items, incident: incs[0] || null,
        approval: incs.some(function (i) { return i.status === "AWAITING_APPROVAL"; }),
        severity: (incs.length || sick.length) ? "critical" : "warn",
        key: [c.state, incs.map(function (i) { return i.id; }).join(","), sick.map(function (w) { return w.name; }).join(",")].join("|")
      });
    });
    list.sort(function (a, b) { return a.severity === b.severity ? 0 : (a.severity === "critical" ? -1 : 1); });
    state.alerts = list;
  }

  function renderNav() {
    var n = state.alerts.length;
    document.title = n ? "(" + n + ") \u26a0 " + baseTitle : baseTitle;
    var sig = JSON.stringify(state.alerts.map(function (a) { return [a.cluster.id, a.key]; }));
    if (sig === state.sig) { return; }
    state.sig = sig;
    nav.hidden = n === 0;
    if (!n) { toggleMenu(false); return; }
    var first = state.alerts[0];
    nav.className = "nav-alert nav-alert-" + first.severity;
    navText.textContent = n === 1 ? "Error \u00b7 " + first.cluster.name + " \u00b7 " + first.title : n + " clusters in error";
    navGo.textContent = n === 1 ? "View cluster" : "View " + first.cluster.name;
    clear(menuList);
    state.alerts.forEach(function (a) {
      var li = el("li", "alert-menu-item alert-" + a.severity);
      var info = el("div", "alert-menu-info");
      info.appendChild(el("strong", null, a.cluster.name));
      info.appendChild(el("span", "small muted", a.title));
      li.appendChild(info);
      var b = el("button", "btn btn-small", "Go to cluster");
      b.type = "button";
      b.addEventListener("click", function () { toggleMenu(false); goToCluster(a.cluster); });
      li.appendChild(b);
      menuList.appendChild(li);
    });
  }

  function saveSeen() { var s = store(); if (s) { try { s.setItem(SEEN_KEY, JSON.stringify(state.seen)); } catch (e) { /* ignore */ } } }

  // Show the popup once per error. After it has been shown (dismissed, closed or "Go to cluster"),
  // it is NOT shown again unless (a) a genuinely new problem appears on that cluster, or
  // (b) the cluster is still in error REMIND_MS after the last time it was shown.
  function maybePopup() {
    if (state.seen === null) {
      try { state.seen = JSON.parse((store() && store().getItem(SEEN_KEY)) || "{}") || {}; } catch (e) { state.seen = {}; }
    }
    var now = Date.now();
    var open = {};
    state.alerts.forEach(function (a) { open[a.cluster.id] = true; });
    Object.keys(state.seen).forEach(function (id) {
      var rec = state.seen[id];
      if (open[id]) { rec.gone = null; return; }
      // Tolerate short flickers (a pod briefly Ready): only forget after GRACE_MS without any error.
      if (!rec.gone) { rec.gone = now; } else if (now - rec.gone > GRACE_MS) { delete state.seen[id]; }
    });
    var fresh = state.alerts.filter(function (a) {
      var rec = state.seen[a.cluster.id];
      if (!rec) { return true; }
      var known = rec.items || [];
      var isNew = a.items.some(function (it) { return known.indexOf(it) === -1; });
      a.reminder = !isNew;
      return isNew || now - rec.at >= REMIND_MS;
    });
    var otherOpen = Array.prototype.some.call(document.querySelectorAll("dialog"), function (d) { return d !== dialog && d.open; });
    if (!fresh.length || dialog.open || otherOpen) { saveSeen(); return; }
    fresh.forEach(function (a) {
      var old = state.seen[a.cluster.id];
      var items = (old && old.items ? old.items : []).slice();
      a.items.forEach(function (it) { if (items.indexOf(it) === -1) { items.push(it); } });
      state.seen[a.cluster.id] = { items: items, at: now, gone: null };
    });
    saveSeen();

    dTitle.textContent = fresh.length === 1 ? "Error in cluster " + fresh[0].cluster.name : fresh.length + " clusters have errors";
    dSub.textContent = (fresh.every(function (a) { return a.reminder; }) ? "Still unresolved at " : "Detected ") + new Date().toLocaleTimeString(undefined, { hour12: false }) + ". Review it now or jump to the cluster.";
    clear(dList);
    fresh.forEach(function (a) {
      var li = el("li", "alert-dialog-item alert-" + a.severity);
      var head = el("div", "alert-dialog-item-head");
      head.appendChild(el("strong", null, a.cluster.name));
      head.appendChild(el("span", "badge " + (a.severity === "critical" ? "status-failed" : "status-detected"), a.title));
      li.appendChild(head);
      a.lines.forEach(function (l) { li.appendChild(el("p", "small mono alert-line", l)); });
      var row = el("div", "alert-dialog-item-actions");
      var go = el("button", "btn btn-small", "Go to cluster");
      go.type = "button";
      go.addEventListener("click", function () { closeDialog(); goToCluster(a.cluster); });
      row.appendChild(go);
      if (a.incident) {
        var id = a.incident.id;
        // Plain link, exactly like the "Review and approve" button on the cluster card:
        // the browser navigates by itself, no script involved.
        var review = el("a", "btn btn-small" + (a.approval ? " btn-warn" : ""), a.approval ? "Review and approve" : "Open incident #" + id);
        review.href = incidentUrl(id);
        row.appendChild(review);
      }
      li.appendChild(row);
      dList.appendChild(li);
    });
    state.target = fresh[0].cluster;
    openDialog();
  }

  function tick() {
    Promise.all([getJson("/api/clusters"), getJson("/api/incidents")]).then(function (res) {
      state.clusters = Array.isArray(res[0]) ? res[0] : [];
      state.incidents = Array.isArray(res[1]) ? res[1] : [];
      compute();
      renderNav();
      maybePopup();
    }, function () { /* API unreachable: keep the last state, app.js shows the banner */ });
  }

  function boot() {
    if (!document.getElementById("cluster-grid")) { return; }   // dashboard page only
    if (!build()) { return; }
    tick();
    setInterval(tick, POLL_MS);
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", boot); } else { boot(); }
}());