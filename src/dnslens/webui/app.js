/* dnslens web UI. Plain DOM, no dependencies. User/DNS-controlled text is only ever set via textContent. */
(function () {
  "use strict";
  var state = { user: null, status: null, win: "24h", timer: null, statusTimer: null };
  var root = document.getElementById("app");

  /* ---------- helpers ---------- */
  function h(tag, attrs) {
    var e = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") e.className = v;
      else if (k.indexOf("on") === 0) e.addEventListener(k.slice(2), v);
      else if (k === "value") e.value = v;
      else if (k === "checked") e.checked = !!v;
      else e.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) add(e, arguments[i]);
    return e;
  }
  function add(parent, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) c.forEach(function (x) { add(parent, x); });
    else parent.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
  }
  function clear(e) { e.textContent = ""; return e; }
  var ICONS = {
    dashboard: "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z",
    log: "M4 5h16M4 12h16M4 19h10",
    filter: "M3 4h18l-7 8v7l-4 2v-9z",
    rewrite: "M4 12h13M13 6l6 6-6 6",
    settings: "M4 7h9M17 7h3M4 17h3M11 17h9M15 5a2 2 0 100 4 2 2 0 000-4zM9 15a2 2 0 100 4 2 2 0 000-4z",
    tools: "M14 6l4 4-8 8H6v-4z",
    user: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0",
    moon: "M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"
  };
  function icon(name) {
    var s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "ico");
    var p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", ICONS[name]); s.appendChild(p);
    return s;
  }
  function n(v) { return Number(v || 0).toLocaleString(); }
  function ago(ts) {
    if (!ts) return "never";
    var s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 90) return Math.round(s) + " s ago";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 129600) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function dur(s) {
    s = Math.round(s);
    var d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + (hh || d ? hh + "h " : "") + m + "m";
  }
  var toastTimer;
  function toast(msg, err) {
    var old = document.querySelector(".toast"); if (old) old.remove();
    var t = h("div", { class: "toast" + (err ? " err" : "") }, msg);
    document.body.appendChild(t);
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { t.remove(); }, err ? 6000 : 2800);
  }
  function api(method, path, body) {
    var opt = { method: method, headers: { "X-Requested-With": "dnslens" }, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    return fetch(path, opt).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (data) {
        if (r.status === 401 && path !== "/api/login") { state.user = null; renderLogin(); throw new Error("Session expired"); }
        if (!r.ok) throw new Error((data && data.error) || r.statusText || "request failed");
        return data;
      });
    });
  }
  function fail(e) { toast(e.message || String(e), true); }
  function field(label, input, hint) {
    return h("label", { class: "f" }, h("span", {}, label), input, hint ? h("div", { class: "hint" }, hint) : null);
  }
  function toggle(checked, onchange) {
    var i = h("input", { type: "checkbox", checked: checked, onchange: function () { onchange(i.checked); } });
    return h("label", { class: "sw" }, i, h("span"));
  }
  function setTheme(t) { document.documentElement.setAttribute("data-theme", t); try { localStorage.setItem("theme", t); } catch (e) { /* ignore */ } }
  (function initTheme() {
    var t = null; try { t = localStorage.getItem("theme"); } catch (e) { /* ignore */ }
    if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    setTheme(t);
  })();
  function stopTimers() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    if (state.live) { state.live.close(); state.live = null; }
  }

  /* ---------- login ---------- */
  function renderLogin() {
    stopTimers(); clearInterval(state.statusTimer);
    var err = h("div", { class: "err-text" });
    var u = h("input", { type: "text", autocomplete: "username", value: "admin" });
    var p = h("input", { type: "password", autocomplete: "current-password" });
    var go = function () {
      err.textContent = "";
      api("POST", "/api/login", { username: u.value, password: p.value })
        .then(function () { boot(); }).catch(function (e) { err.textContent = e.message; });
    };
    p.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    clear(root).appendChild(h("div", { class: "login" }, h("div", { class: "card" },
      h("h1", {}, h("img", { src: "/favicon.svg", width: 28, height: 28, alt: "" }), "dnslens"),
      field("Username", u), field("Password", p), err,
      h("button", { class: "primary", style: "width:100%", onclick: go }, "Sign in"))));
    p.focus();
  }

  /* ---------- shell ---------- */
  var PAGES = [
    ["dashboard", "Dashboard", "dashboard"], ["log", "Query log", "log"], ["filters", "Filters", "filter"],
    ["rewrites", "DNS rewrites", "rewrite"], ["settings", "Settings", "settings"], ["tools", "Tools", "tools"], ["account", "Account", "user"]
  ];
  function renderShell() {
    var nav = h("nav", { class: "nav" });
    PAGES.forEach(function (p) { nav.appendChild(h("a", { href: "#/" + p[0], "data-page": p[0] }, icon(p[2]), p[1])); });
    var prot = h("select", { id: "prot", "aria-label": "Protection", onchange: function () { setProtection(prot.value); } });
    [["on", "Protection enabled"], ["600", "Disable for 10 minutes"], ["3600", "Disable for 1 hour"], ["86400", "Disable for 24 hours"], ["0", "Disable until re-enabled"]]
      .forEach(function (o) { prot.appendChild(h("option", { value: o[0] }, o[1])); });
    clear(root).appendChild(h("div", { class: "layout" },
      h("aside", { class: "side" }, h("div", { class: "brand" }, h("img", { src: "/favicon.svg", alt: "" }), "dnslens"), nav,
        h("div", { class: "foot", id: "foot" }, "")),
      h("div", { class: "main" },
        h("header", { class: "top" }, h("h1", { id: "title" }, ""),
          h("div", { class: "right" }, h("span", { class: "pill", id: "protdot" }), prot,
            h("button", { title: "Toggle dark mode", onclick: function () { setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"); } }, icon("moon")),
            h("button", { onclick: function () { api("POST", "/api/logout", {}).then(function () { state.user = null; renderLogin(); }); } }, "Sign out"))),
        h("main", { class: "content", id: "content" }))));
    refreshStatus();
    state.statusTimer = setInterval(refreshStatus, 15000);
  }
  function refreshStatus() {
    return api("GET", "/api/status").then(function (s) {
      state.status = s;
      var sel = document.getElementById("prot"); if (!sel) return;
      var on = s.protection.enabled;
      sel.value = on ? "on" : (sel.value === "on" ? "0" : sel.value);
      var dot = document.getElementById("protdot");
      clear(dot).appendChild(h("span", { class: "dot" + (on ? "" : " off") }));
      if (!on && s.protection.until) dot.appendChild(h("span", { class: "muted" }, "back in " + dur(s.protection.until - Date.now() / 1000)));
      var f = document.getElementById("foot");
      if (f) f.textContent = "v" + s.version + " - up " + dur(s.uptime) + " - " + s.dns;
    }).catch(function () { /* handled by api() */ });
  }
  function setProtection(v) {
    var body = v === "on" ? { enabled: true } : { enabled: false, duration: Number(v) };
    api("POST", "/api/protection", body).then(function () { toast(v === "on" ? "Protection enabled" : "Protection disabled"); refreshStatus(); }).catch(fail);
  }

  /* ---------- router ---------- */
  function route() {
    if (!state.user) return;
    stopTimers();
    var page = (location.hash.replace(/^#\//, "") || "dashboard").split("?")[0];
    if (!PAGES.some(function (p) { return p[0] === page; })) page = "dashboard";
    document.querySelectorAll(".nav a").forEach(function (a) { a.classList.toggle("on", a.getAttribute("data-page") === page); });
    var meta = PAGES.filter(function (p) { return p[0] === page; })[0];
    document.getElementById("title").textContent = meta[1];
    var c = clear(document.getElementById("content"));
    try { VIEWS[page](c); } catch (e) { c.appendChild(h("div", { class: "card" }, "Error: " + e.message)); }
  }
  window.addEventListener("hashchange", route);

  /* ---------- live connection (Server-Sent Events, polling fallback) ---------- */
  function openLive(h) {
    var closed = false, es = null, poller = null, fallback = null, seq = 0, got = false, lastCheck = 0;
    function poll() {
      api("GET", "/api/live/poll?since=" + seq).then(function (r) {
        if (closed) return;
        seq = r.seq;
        if (r.hello) h.hello(r); else r.ticks.forEach(h.tick);
        h.status("polling");
      }).catch(function () { if (!closed) h.status("offline"); });
    }
    function startPolling() { if (poller || closed) return; poll(); poller = setInterval(poll, 1000); }
    function recheckSession() {
      if (Date.now() - lastCheck < 5000) return;
      lastCheck = Date.now();
      api("GET", "/api/session").then(function (s) { if (!s.authenticated) { close(); state.user = null; renderLogin(); } }).catch(function () { });
    }
    function close() { closed = true; if (es) es.close(); if (poller) clearInterval(poller); clearTimeout(fallback); }
    if (window.EventSource) {
      es = new window.EventSource("/api/live");
      fallback = setTimeout(function () { if (!got && !closed) { es.close(); es = null; startPolling(); } }, 5000); // buffering proxy?
      es.addEventListener("hello", function (e) { got = true; var d = JSON.parse(e.data); seq = d.seq; h.hello(d); h.status("live"); });
      es.addEventListener("tick", function (e) { got = true; var t = JSON.parse(e.data); seq = t.seq; h.tick(t); h.status("live"); });
      es.addEventListener("bye", function () { close(); recheckSession(); });
      es.onerror = function () { h.status("reconnecting"); recheckSession(); };
    } else startPolling();
    return { close: close };
  }

  /* ---------- dashboard ---------- */
  function stat(cls, label, value, sub) {
    var v = h("div", { class: "v" }, value), s2 = h("div", { class: "s" }, sub || "\u00a0");
    var el = h("div", { class: "card stat " + cls }, h("div", { class: "l" }, label), v, s2);
    el.setV = function (a, b) { v.textContent = a; if (b !== undefined) s2.textContent = b; };
    return el;
  }
  function ruleAction(action, domain) {
    return api("POST", "/api/rules/action", { action: action, domain: domain })
      .then(function () { toast((action === "block" ? "Blocked " : "Allowed ") + domain); }).catch(fail);
  }
  var LIVE_N = 120;
  function viewDashboard(c) {
    var cardsBox = h("div"), liveBox = h("div"), rest = h("div");
    var seg = h("div", { class: "seg" });
    ["1h", "6h", "24h", "7d", "30d"].forEach(function (w) {
      seg.appendChild(h("button", { class: state.win === w ? "on" : "", onclick: function () { state.win = w; stopTimers(); clear(c); viewDashboard(c); } }, w));
    });
    c.appendChild(h("div", { class: "row", style: "margin-bottom:12px" }, h("div", { class: "grow muted" }, "Statistics for the last"), seg));
    c.appendChild(cardsBox); c.appendChild(liveBox); c.appendChild(rest);

    /* ----- live section (built once; survives the 10 s statistics refresh) ----- */
    var base = null, delta = { total: 0, blocked: 0, cache: 0 }, cards = null;
    var ticks = [], hover = false, conn = null;
    var liveOn = true; try { liveOn = localStorage.getItem("liveDash") !== "off"; } catch (e) { /* ignore */ }
    var dot = h("span", { class: "dot off" }), stateLbl = h("span", { class: "muted" }, ""), qps = h("span", { class: "qps", id: "live-qps" }, "0"), peak = h("span", { class: "muted" }, "");
    var toggleBtn = h("button", { class: "small", id: "live-toggle", onclick: function () { liveOn = !liveOn; try { localStorage.setItem("liveDash", liveOn ? "on" : "off"); } catch (e) { /* ignore */ } applyLiveState(); } });
    var chartHost = h("div", { class: "chart", id: "live-chart" });
    chartHost.addEventListener("mouseenter", function () { hover = true; });
    chartHost.addEventListener("mouseleave", function () { hover = false; drawLive(); });
    var feedBody = h("tbody", { id: "live-feed" });
    var feedNote = h("div", { class: "hint" }, "");
    liveBox.appendChild(h("div", { class: "grid g2" },
      h("div", { class: "card" },
        h("div", { class: "row", style: "justify-content:space-between;margin-bottom:8px" },
          h("h2", { style: "margin:0" }, "Live traffic (last 2 minutes)"),
          h("div", { class: "row" }, h("span", { class: "pill" }, dot, stateLbl), toggleBtn)),
        h("div", { class: "row", style: "margin-bottom:6px;align-items:baseline" }, qps, h("span", { class: "muted" }, "queries/s"), peak),
        chartHost),
      h("div", { class: "card" }, h("h2", {}, "Live queries"),
        h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Time"), h("th", {}, "Domain"), h("th", {}, "Status"), h("th", {}, "Client"))), feedBody)), feedNote)));

    function drawLive() {
      if (hover) return;
      var cur = ticks.slice(-LIVE_N), pad = LIVE_N - cur.length, z = function () { return 0; };
      var series = { bucket_seconds: 1, start: (cur.length ? cur[0].ts : Math.floor(Date.now() / 1000)) - pad,
        total: new Array(pad).fill(0).concat(cur.map(function (t) { return t.total; })), blocked: new Array(pad).fill(0).concat(cur.map(function (t) { return t.blocked; })),
        resolved: new Array(pad).fill(0).concat(cur.map(function (t) { return t.resolved; })), failed: new Array(pad).fill(0).concat(cur.map(function (t) { return t.failed; })) };
      void z; Charts.timeline(chartHost, series);
      var last = cur.length ? cur[cur.length - 1] : { total: 0 }, mx = 0;
      cur.forEach(function (t) { if (t.total > mx) mx = t.total; });
      qps.textContent = n(last.total); peak.textContent = "peak " + n(mx) + "/s";
    }
    function addEvents(evts, quiet) {
      evts.forEach(function (e) {
        var tr = h("tr", { class: quiet ? "" : "flash" },
          h("td", { class: "muted" }, new Date(e.ts * 1000).toLocaleTimeString()),
          h("td", { class: "mono" }, e.name, h("span", { class: "muted" }, " " + e.type)),
          h("td", {}, h("span", { class: "badge " + e.source }, SRC[e.source] || e.source)),
          h("td", { class: "mono" }, e.client));
        feedBody.insertBefore(tr, feedBody.firstChild);
      });
      while (feedBody.children.length > 25) feedBody.removeChild(feedBody.lastChild);
    }
    function renderCards() {
      if (!base || !cards) return;
      var tot = base.queries + delta.total, bl = base.blocked + delta.blocked, ca = base.cache + delta.cache;
      cards.q.setV(n(tot), "avg " + base.avg_ms + " ms");
      cards.b.setV(n(bl), (tot ? Math.round(1000 * bl / tot) / 10 : 0) + "% of queries");
      cards.c.setV(n(ca), (tot ? Math.round(1000 * ca / tot) / 10 : 0) + "% of queries");
    }
    function setStatus(st) {
      dot.className = "dot" + (st === "live" || st === "polling" ? " pulse" : " off");
      stateLbl.textContent = !liveOn ? "paused" : st === "live" ? "live" : st === "polling" ? "live (polling)" : st === "reconnecting" ? "reconnecting..." : "offline";
    }
    function applyLiveState() {
      toggleBtn.textContent = liveOn ? "Pause" : "Resume";
      if (conn) { conn.close(); conn = null; }
      if (!liveOn) { setStatus("paused"); return; }
      setStatus("connecting");
      conn = openLive({
        status: setStatus,
        hello: function (d) { ticks = d.ticks.slice(); clear(feedBody); addEvents(d.events.slice(-25), true); drawLive(); },
        tick: function (t) {
          ticks.push(t); if (ticks.length > 300) ticks.shift();
          delta.total += t.total; delta.blocked += t.blocked; delta.cache += t.cache;
          if (t.events && t.events.length) addEvents(t.events, false);
          feedNote.textContent = t.total > t.events.length ? "Busy: showing a sample of " + t.events.length + " of " + t.total + " queries from the last second." : "";
          renderCards(); drawLive();
        }
      });
      state.live = conn;
    }

    /* ----- statistics (refreshed every 10 s) ----- */
    function load() {
      Promise.all([api("GET", "/api/stats?window=" + state.win + "&top=10"), refreshStatus()]).then(function (res) {
        var s = res[0], t = s.totals, st = state.status || { zone: {}, filters: {}, rewrites: 0 };
        base = t; delta = { total: 0, blocked: 0, cache: 0 };
        cards = { q: stat("acc", "DNS queries", n(t.queries), "avg " + t.avg_ms + " ms"), b: stat("bad", "Blocked", n(t.blocked), t.blocked_pct + "% of queries"),
          c: stat("ok", "Served from cache", n(t.cache), t.cache_pct + "% of queries"),
          r: stat("info", "Blocking rules", n(st.zone.blocked), (st.filters.enabled || 0) + " lists, " + (st.rewrites || 0) + " rewrites") };
        clear(cardsBox).appendChild(h("div", { class: "grid g4" }, cards.q, cards.b, cards.c, cards.r));
        clear(rest);
        if (st.filters && !st.filters.total && !t.blocked) {
          rest.appendChild(h("div", { class: "card" }, "No blocklists yet. ", h("a", { href: "#/filters" }, "Add one on the Filters page"), " to start blocking ads and trackers."));
        }
        var tl = h("div", { class: "chart" });
        rest.appendChild(h("div", { class: "card" }, h("h2", {}, "Queries over time"), tl));
        Charts.timeline(tl, s.series);
        var act = function (a) { return { label: a, fn: function (it) { ruleAction(a.toLowerCase(), it.name).then(function () { load(); }); } }; };
        var b1 = h("div"), b2 = h("div"), b3 = h("div"), b4 = h("div"), d1 = h("div"), d2 = h("div");
        rest.appendChild(h("div", { class: "grid g2" },
          h("div", { class: "card" }, h("h2", {}, "Top queried domains"), b1),
          h("div", { class: "card" }, h("h2", {}, "Top blocked domains"), b2),
          h("div", { class: "card" }, h("h2", {}, "Top clients"), b3),
          h("div", { class: "card" }, h("h2", {}, "Upstream servers"), b4),
          h("div", { class: "card" }, h("h2", {}, "Query types"), d1),
          h("div", { class: "card" }, h("h2", {}, "Response codes"), d2)));
        Charts.bars(b1, s.top_domains, { action: act("Block") });
        Charts.bars(b2, s.top_blocked, { red: true, action: act("Allow") });
        Charts.bars(b3, s.top_clients, { extra: function (i) { return i.blocked ? "(" + n(i.blocked) + " blocked)" : ""; } });
        Charts.bars(b4, s.top_upstreams, { extra: function (i) { return "- " + i.avg_ms + " ms"; } });
        Charts.donut(d1, s.query_types);
        Charts.donut(d2, s.rcodes);
      }).catch(function (e) { if (e.message !== "Session expired") fail(e); });
    }
    drawLive();
    applyLiveState();
    load();
    state.timer = setInterval(load, 10000);
  }

  /* ---------- query log ---------- */
  var SRC = { blocked: "Blocked", cache: "Cached", local: "Local", upstream: "Resolved", servfail: "Failed", error: "Failed", refused: "Refused" };
  function viewLog(c) {
    var lists = {}, q = { search: "", status: "all" }, live = false, nextId = null, tbody = h("tbody"), more = h("button", { class: "hidden", style: "display:none", onclick: function () { load(true); } }, "Load more");
    var search = h("input", { type: "search", placeholder: "Search domain, client or answer", class: "grow" });
    var t; search.addEventListener("input", function () { clearTimeout(t); t = setTimeout(function () { q.search = search.value; load(false); }, 300); });
    var status = h("select", { onchange: function () { q.status = status.value; load(false); } });
    [["all", "All"], ["blocked", "Blocked"], ["allowed", "Allowed"], ["cached", "Cached"], ["local", "Local rewrites"], ["upstream", "Resolved upstream"], ["failed", "Failed"]]
      .forEach(function (o) { status.appendChild(h("option", { value: o[0] }, o[1])); });
    var liveBox = toggle(false, function (v) { live = v; });
    var empty = h("div", { class: "empty", style: "display:none" }, "No queries match.");
    c.appendChild(h("div", { class: "card" },
      h("div", { class: "row", style: "margin-bottom:12px" }, search, h("div", { style: "width:200px" }, status),
        h("span", { class: "pill" }, liveBox, "Live"),
        h("button", { class: "danger", onclick: function () { if (confirm("Delete the whole query log and statistics?")) api("POST", "/api/querylog/clear", {}).then(function () { toast("Query log cleared"); load(false); }).catch(fail); } }, "Clear log")),
      h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Time"), h("th", {}, "Domain"), h("th", {}, "Status"), h("th", {}, "Response"), h("th", {}, "Client"), h("th", {}, "Server"), h("th", {}, ""))), tbody)),
      empty, h("div", { style: "margin-top:12px" }, more)));
    api("GET", "/api/filters").then(function (r) { r.filters.forEach(function (f) { lists[f.id] = f.name; }); }).catch(function () { });
    function listName(id) { return id === -1 ? "custom rules" : id === 0 ? "static config" : (lists[id] || "list " + id); }
    function rowFor(e) {
      var det = h("tr", { style: "display:none" }, h("td", { colspan: 7 }, h("div", { class: "mono" },
        "rcode " + e.rcode + " - " + e.transport + " - " + e.elapsed_ms + " ms" + (e.upstream ? " - upstream " + e.upstream : ""),
        e.rule ? h("div", {}, "Blocked by rule " + e.rule + " (" + listName(e.list_id) + ")") : null,
        e.answers.map(function (a) { return h("div", {}, a); }))));
      var blocked = e.source === "blocked";
      var tr = h("tr", { class: "click", onclick: function () { det.style.display = det.style.display === "none" ? "" : "none"; } },
        h("td", { title: new Date(e.ts * 1000).toLocaleString() }, new Date(e.ts * 1000).toLocaleTimeString()),
        h("td", {}, h("div", { class: "mono" }, e.name), h("div", { class: "muted" }, e.type)),
        h("td", {}, h("span", { class: "badge " + e.source }, SRC[e.source] || e.source)),
        h("td", { class: "mono" }, e.answers.length ? e.answers[0] + (e.answers.length > 1 ? " (+" + (e.answers.length - 1) + ")" : "") : e.rcode),
        h("td", { class: "mono" }, e.client),
        h("td", { class: "muted" }, e.upstream ? e.upstream + " - " + e.elapsed_ms + " ms" : e.elapsed_ms + " ms"),
        h("td", {}, h("button", { class: "small", onclick: function (ev) { ev.stopPropagation(); ruleAction(blocked ? "allow" : "block", e.name); } }, blocked ? "Unblock" : "Block")));
      return [tr, det];
    }
    function load(append) {
      var url = "/api/querylog?limit=100&status=" + q.status + "&search=" + encodeURIComponent(q.search) + (append && nextId ? "&before=" + nextId : "");
      return api("GET", url).then(function (r) {
        if (!append) clear(tbody);
        r.items.forEach(function (e) { rowFor(e).forEach(function (x) { tbody.appendChild(x); }); });
        nextId = r.next; more.style.display = r.next ? "" : "none";
        empty.style.display = tbody.children.length ? "none" : "";
      }).catch(function (e) { if (e.message !== "Session expired") fail(e); });
    }
    load(false);
    state.timer = setInterval(function () { if (live && !q.search) load(false); }, 2000);
  }

  /* ---------- filters ---------- */
  function viewFilters(c) {
    var listCard = h("div", { class: "card" }), rulesCard = h("div", { class: "card" }), checkCard = h("div", { class: "card" });
    c.appendChild(listCard); c.appendChild(rulesCard); c.appendChild(checkCard);
    function loadLists() {
      api("GET", "/api/filters").then(function (r) {
        clear(listCard).appendChild(h("h2", {}, "Blocklists"));
        var tb = h("tbody");
        r.filters.forEach(function (f) {
          tb.appendChild(h("tr", {},
            h("td", {}, toggle(f.enabled, function (v) { api("PUT", "/api/filters/" + f.id, { enabled: v }).then(function () { refreshStatus(); toast(v ? "List enabled" : "List disabled"); }).catch(fail); })),
            h("td", {}, h("div", {}, f.name), h("div", { class: "muted mono" }, f.url), f.error ? h("div", { style: "color:var(--bad)" }, f.error) : null),
            h("td", { class: "num" }, n(f.rules)), h("td", { class: "muted" }, ago(f.last_updated)),
            h("td", { class: "num" }, h("button", { class: "small", onclick: function () { api("POST", "/api/filters/refresh", { id: f.id }).then(function () { toast("List updated"); loadLists(); refreshStatus(); }).catch(fail); } }, "Update"), " ",
              h("button", { class: "small danger", onclick: function () { if (confirm("Remove " + f.name + "?")) api("DELETE", "/api/filters/" + f.id).then(function () { loadLists(); refreshStatus(); }).catch(fail); } }, "Remove"))));
        });
        listCard.appendChild(r.filters.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "On"), h("th", {}, "List"), h("th", { class: "num" }, "Rules"), h("th", {}, "Updated"), h("th", {}, ""))), tb)) : h("div", { class: "empty" }, "No lists yet."));
        var name = h("input", { type: "text", placeholder: "Name" }), url = h("input", { type: "text", placeholder: "https://.../list.txt" });
        var preset = h("select", { onchange: function () { var p = r.presets[Number(preset.value)]; if (p) { name.value = p.name; url.value = p.url; } } }, h("option", { value: "" }, "Choose a preset..."));
        r.presets.forEach(function (p, i) { preset.appendChild(h("option", { value: i }, p.name)); });
        var addBtn = h("button", { class: "primary", onclick: function () {
          addBtn.disabled = true; addBtn.textContent = "Downloading...";
          api("POST", "/api/filters", { name: name.value, url: url.value }).then(function () { toast("List added"); loadLists(); refreshStatus(); })
            .catch(fail).then(function () { addBtn.disabled = false; addBtn.textContent = "Add list"; });
        } }, "Add list");
        listCard.appendChild(h("h3", {}, "Add a list"));
        listCard.appendChild(h("div", { class: "row" }, h("div", { style: "width:220px" }, preset), h("div", { class: "grow" }, name), h("div", { class: "grow", style: "flex:2" }, url), addBtn,
          r.filters.length ? h("button", { onclick: function () { api("POST", "/api/filters/refresh", {}).then(function () { toast("All lists updated"); loadLists(); }).catch(fail); } }, "Update all") : null));
        listCard.appendChild(h("div", { class: "hint" }, "Supported formats: AdGuard (||domain^), hosts files and plain domain lists. Lists are refreshed automatically (see Settings)."));
      }).catch(fail);
    }
    loadLists();
    api("GET", "/api/rules").then(function (r) {
      var ta = h("textarea", { spellcheck: "false", placeholder: "||ads.example.com^\n@@||allowed.example.com^\n# comment" }); ta.value = r.text;
      rulesCard.appendChild(h("h2", {}, "Custom filtering rules"));
      rulesCard.appendChild(ta);
      rulesCard.appendChild(h("div", { class: "row", style: "margin-top:8px" }, h("button", { class: "primary", onclick: function () { api("PUT", "/api/rules", { text: ta.value }).then(function (x) { toast("Saved (" + x.rules + " rules)"); refreshStatus(); }).catch(fail); } }, "Save rules"),
        h("span", { class: "hint" }, "||domain^ blocks the domain and its subdomains. @@||domain^ allows it and overrides every list.")));
    }).catch(fail);
    var host = h("input", { type: "text", placeholder: "example.com", class: "grow" }), res = h("div", { style: "margin-top:10px" });
    var doCheck = function () { api("POST", "/api/check", { name: host.value }).then(function (r) {
      var txt = r.result === "blocked" ? "Blocked by rule " + r.rule + " in " + r.list : r.result === "allowed" ? "Allowed by rule " + r.rule + " in " + r.list : r.result === "rewritten" ? "Answered locally (DNS rewrite)" : "Not filtered, forwarded normally";
      clear(res).appendChild(h("span", { class: "badge " + (r.result === "blocked" ? "blocked" : r.result === "processed" ? "" : "OK") }, txt));
      if (!r.protection) res.appendChild(h("div", { class: "hint" }, "Protection is currently disabled, so nothing is blocked."));
    }).catch(fail); };
    host.addEventListener("keydown", function (e) { if (e.key === "Enter") doCheck(); });
    checkCard.appendChild(h("h2", {}, "Check a host"));
    checkCard.appendChild(h("div", { class: "row" }, host, h("button", { onclick: doCheck }, "Check")));
    checkCard.appendChild(res);
  }

  /* ---------- rewrites ---------- */
  function viewRewrites(c) {
    var editing = null, card = h("div", { class: "card" }), form = h("div", { class: "card" });
    c.appendChild(card); c.appendChild(form);
    var name = h("input", { type: "text", placeholder: "app.internal or *.dev.internal" }), data = h("input", { type: "text", placeholder: "10.0.0.5, fd00::5 or target.example.com" }),
      type = h("select"), ttl = h("input", { type: "number", value: 300, min: 0 }), save = h("button", { class: "primary" }, "Add rewrite"), cancel = h("button", { style: "display:none" }, "Cancel");
    ["AUTO", "A", "AAAA", "CNAME", "TXT", "MX", "PTR", "NS", "SRV", "CAA"].forEach(function (t) { type.appendChild(h("option", { value: t }, t === "AUTO" ? "Auto (A/AAAA/CNAME)" : t)); });
    function reset() { editing = null; name.value = ""; data.value = ""; type.value = "AUTO"; ttl.value = 300; save.textContent = "Add rewrite"; cancel.style.display = "none"; }
    cancel.addEventListener("click", reset);
    save.addEventListener("click", function () {
      var body = { name: name.value, data: data.value, type: type.value, ttl: Number(ttl.value) };
      (editing ? api("PUT", "/api/rewrites/" + editing, body) : api("POST", "/api/rewrites", body))
        .then(function () { toast("Saved"); reset(); load(); refreshStatus(); }).catch(fail);
    });
    form.appendChild(h("h2", {}, "Add / edit rewrite"));
    form.appendChild(h("div", { class: "grid g2" }, field("Domain", name, "Wildcards like *.dev.internal match any depth."), field("Answer", data)));
    form.appendChild(h("div", { class: "grid g2" }, field("Type", type), field("TTL (seconds)", ttl)));
    form.appendChild(h("div", { class: "row" }, save, cancel));
    function load() {
      api("GET", "/api/rewrites").then(function (rows) {
        clear(card).appendChild(h("h2", {}, "DNS rewrites"));
        if (!rows.length) { card.appendChild(h("div", { class: "empty" }, "No rewrites. Point a name at any address, for dev, staging or a home lab.")); return; }
        var tb = h("tbody");
        rows.forEach(function (r) {
          tb.appendChild(h("tr", {}, h("td", {}, toggle(r.enabled, function (v) { api("PUT", "/api/rewrites/" + r.id, { enabled: v }).then(function () { toast("Updated"); }).catch(fail); })),
            h("td", { class: "mono" }, r.name), h("td", {}, h("span", { class: "badge" }, r.type)), h("td", { class: "mono" }, r.data), h("td", { class: "num" }, r.ttl),
            h("td", { class: "num" }, h("button", { class: "small", onclick: function () { editing = r.id; name.value = r.name; data.value = r.data; type.value = r.type; ttl.value = r.ttl; save.textContent = "Save changes"; cancel.style.display = ""; window.scrollTo(0, document.body.scrollHeight); } }, "Edit"), " ",
              h("button", { class: "small danger", onclick: function () { api("DELETE", "/api/rewrites/" + r.id).then(function () { load(); refreshStatus(); }).catch(fail); } }, "Delete"))));
        });
        card.appendChild(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "On"), h("th", {}, "Domain"), h("th", {}, "Type"), h("th", {}, "Answer"), h("th", { class: "num" }, "TTL"), h("th", {}, ""))), tb)));
      }).catch(fail);
    }
    load();
  }

  /* ---------- settings ---------- */
  function viewSettings(c) {
    api("GET", "/api/settings").then(function (s) {
      var ups = h("textarea", { style: "min-height:90px", spellcheck: "false" }); ups.value = s.dns.upstreams.join("\n");
      var to = h("input", { type: "number", step: "0.5", min: 0.5, max: 10, value: s.dns.upstream_timeout });
      var cache = h("input", { type: "number", min: 0, value: s.dns.cache_size }), maxttl = h("input", { type: "number", min: 60, value: s.dns.max_ttl });
      var bm = h("select", {}, h("option", { value: "nxdomain" }, "NXDOMAIN (name does not exist)"), h("option", { value: "null" }, "0.0.0.0 / :: (null address)")); bm.value = s.dns.block_mode;
      var fwd = toggle(s.dns.forward, function () { });
      var logOn = toggle(s.log.enabled, function () { }), anon = toggle(s.log.anonymize, function () { });
      var ret = h("select"); s.retention_options.forEach(function (hrs) { ret.appendChild(h("option", { value: hrs }, hrs < 24 ? hrs + " hours" : hrs / 24 + " days")); }); ret.value = s.log.retention_hours;
      var upd = h("select"); [[0, "Never"], [1, "Every hour"], [12, "Every 12 hours"], [24, "Daily"], [72, "Every 3 days"], [168, "Weekly"]].forEach(function (o) { upd.appendChild(h("option", { value: o[0] }, o[1])); }); upd.value = s.filters_update_hours;
      var testOut = h("div", { style: "margin-top:8px" });
      var save = h("button", { class: "primary", onclick: function () {
        var upstreams = ups.value.split(/\s+/).filter(Boolean);
        api("PUT", "/api/settings", { dns: { upstreams: upstreams, upstream_timeout: Number(to.value), cache_size: Number(cache.value), max_ttl: Number(maxttl.value), block_mode: bm.value, forward: fwd.querySelector("input").checked },
          log: { enabled: logOn.querySelector("input").checked, anonymize: anon.querySelector("input").checked, retention_hours: Number(ret.value) }, filters_update_hours: Number(upd.value) })
          .then(function () { toast("Settings saved"); refreshStatus(); }).catch(fail);
      } }, "Save settings");
      c.appendChild(h("div", { class: "card" }, h("h2", {}, "Upstream DNS servers"),
        field("One per line (IP, IP#port or hostname)", ups, "Servers are tried in order until one answers."),
        h("div", { class: "row" }, h("button", { onclick: function () {
          clear(testOut).appendChild(document.createTextNode("Testing..."));
          api("POST", "/api/upstreams/test", {}).then(function (rows) {
            clear(testOut);
            rows.forEach(function (r) { testOut.appendChild(h("div", {}, h("span", { class: "badge " + (r.ok ? "OK" : "FAIL") }, r.ok ? "OK" : "FAIL"), " ", h("span", { class: "mono" }, r.upstream), " ", r.ok ? r.ms + " ms" : r.error)); });
          }).catch(fail);
        } }, "Test saved upstreams")), testOut,
        h("div", { class: "grid g3", style: "margin-top:12px" }, field("Upstream timeout (s)", to), field("Cache size (entries, 0 = off)", cache), field("Max cache TTL (s)", maxttl)),
        h("label", { class: "row", style: "margin-bottom:12px" }, fwd, "Forward queries that are not local or blocked"),
        h("div", {}, h("button", { onclick: function () { api("POST", "/api/cache/clear", {}).then(function () { toast("Cache cleared"); }).catch(fail); } }, "Clear DNS cache"))));
      c.appendChild(h("div", { class: "card" }, h("h2", {}, "Blocking"), field("Response for blocked domains", bm), field("Update blocklists", upd)));
      c.appendChild(h("div", { class: "card" }, h("h2", {}, "Query log and statistics"),
        h("label", { class: "row", style: "margin-bottom:12px" }, logOn, "Record queries (turning this off stops statistics too)"),
        h("label", { class: "row", style: "margin-bottom:12px" }, anon, "Anonymize client IP addresses (last IPv4 octet / IPv6 suffix)"), field("Keep for", ret)));
      c.appendChild(h("div", { class: "card" }, h("h2", {}, "Storage (read only)"),
        h("div", {}, h("span", { class: "badge" }, s.storage.mode === "database" ? "Database" : "Files")),
        h("p", {}, "Settings, blocklists, rewrites and the account: ", h("span", { class: "mono" }, s.storage.config)),
        h("p", {}, "Query log and statistics: ", h("span", { class: "mono" }, s.storage.log)),
        h("div", { class: "hint" }, "Chosen at startup with --data-dir or --db. Use `dnslens db migrate` to move file data into a database.")));
      c.appendChild(save);
    }).catch(fail);
  }

  /* ---------- tools ---------- */
  function viewTools(c) {
    var tool = h("select"), name = h("input", { type: "text", placeholder: "example.com", class: "grow" }), type = h("input", { type: "text", value: "A", style: "width:90px" });
    var res = h("select"), extra = h("input", { type: "text", placeholder: "", class: "grow", style: "display:none" }), out = h("div", { style: "margin-top:14px" });
    var TOOLS = { query: ["Lookup", "name"], propagate: ["Propagation", "name"], trace: ["Trace", "name"], audit: ["Domain audit", "domain"], dnssec: ["DNSSEC check", "domain"], bench: ["Benchmark resolvers", ""], reverse: ["Reverse lookup", "ip"] };
    Object.keys(TOOLS).forEach(function (k) { tool.appendChild(h("option", { value: k }, TOOLS[k][0])); });
    [["", "Default resolver"], ["this-server", "This dnslens server"], ["system", "System resolver"], ["public", "Public resolvers"], ["cloudflare", "Cloudflare"], ["google", "Google"], ["quad9", "Quad9"]].forEach(function (o) { res.appendChild(h("option", { value: o[0] }, o[1])); });
    function adapt() {
      var t = tool.value;
      name.placeholder = t === "reverse" ? "8.8.8.8" : t === "bench" ? "(optional) domain" : "example.com";
      type.style.display = (t === "query" || t === "propagate" || t === "trace") ? "" : "none";
      extra.style.display = (t === "propagate" || t === "audit") ? "" : "none";
      extra.placeholder = t === "propagate" ? "Expected value (optional)" : "DKIM selector (optional)";
    }
    tool.addEventListener("change", adapt); adapt();
    function run() {
      var t = tool.value, key = TOOLS[t][1], qs = [];
      if (key) qs.push(key + "=" + encodeURIComponent(name.value.trim())); else if (name.value.trim()) qs.push("domain=" + encodeURIComponent(name.value.trim()));
      if (type.style.display !== "none" && type.value) qs.push("type=" + encodeURIComponent(type.value));
      if (res.value) qs.push("resolver=" + encodeURIComponent(res.value));
      if (extra.value && t === "propagate") qs.push("expect=" + encodeURIComponent(extra.value));
      if (extra.value && t === "audit") qs.push("dkim_selector=" + encodeURIComponent(extra.value));
      clear(out).appendChild(document.createTextNode("Running..."));
      api("GET", "/api/tools/" + t + "?" + qs.join("&")).then(function (r) { clear(out); render(t, r, out); }).catch(function (e) { clear(out).appendChild(h("div", { style: "color:var(--bad)" }, e.message)); });
    }
    name.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
    c.appendChild(h("div", { class: "card" }, h("h2", {}, "Diagnostics"), h("div", { class: "row" }, h("div", { style: "width:200px" }, tool), name, type, h("div", { style: "width:190px" }, res), extra, h("button", { class: "primary", onclick: run }, "Run")), out));
    function recs(rows) {
      return h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", { class: "num" }, "TTL"), h("th", {}, "Type"), h("th", {}, "Data"))),
        h("tbody", {}, rows.map(function (r) { return h("tr", {}, h("td", { class: "mono" }, r.name), h("td", { class: "num" }, r.ttl), h("td", {}, r.type), h("td", { class: "mono" }, r.data)); })));
    }
    function findings(list) { return h("div", {}, list.map(function (f) { return h("div", { style: "padding:3px 0" }, h("span", { class: "badge " + f.level }, f.level), " ", h("span", { class: "muted" }, f.check + " "), f.message); })); }
    function render(t, r, box) {
      if (t === "query" || t === "reverse") {
        r.forEach(function (a) {
          box.appendChild(h("h3", {}, a.qname + " " + a.type + " @ " + a.server + (a.resolver ? " (" + a.resolver + ")" : "")));
          box.appendChild(h("div", { class: "muted" }, a.error ? a.error : a.rcode + " [" + a.flags + "] " + a.elapsed_ms + " ms " + a.transport));
          if (a.records.length) box.appendChild(h("div", { class: "scroll" }, recs(a.records)));
        });
      } else if (t === "propagate") {
        box.appendChild(h("div", {}, h("span", { class: "badge " + (r.ok ? "OK" : "FAIL") }, r.ok ? "OK" : "NOT OK"), " ", r.consistent ? "All responding resolvers agree." : r.groups.length + " different answers."));
        box.appendChild(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Resolver"), h("th", {}, "Answer"), h("th", { class: "num" }, "Time"))),
          h("tbody", {}, r.results.map(function (x) { return h("tr", {}, h("td", {}, x.resolver), h("td", { class: "mono" }, x.error ? x.error : x.records.filter(function (y) { return y.type === r.type; }).map(function (y) { return y.data; }).join(", ") || "(" + x.rcode + ")"), h("td", { class: "num" }, x.elapsed_ms + " ms")); })))));
      } else if (t === "trace") {
        box.appendChild(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Zone"), h("th", {}, "Server"), h("th", { class: "num" }, "RTT"), h("th", {}, "Result"))),
          h("tbody", {}, r.hops.map(function (x) { return h("tr", {}, h("td", { class: "mono" }, x.zone), h("td", { class: "mono" }, x.server), h("td", { class: "num" }, x.rtt_ms + " ms"), h("td", {}, x.outcome + " " + x.detail)); })))));
        if (r.error) box.appendChild(h("div", { style: "color:var(--bad)" }, r.error));
        if (r.final && r.final.records.length) box.appendChild(h("div", { class: "scroll" }, recs(r.final.records)));
      } else if (t === "audit" || t === "dnssec") {
        box.appendChild(findings(r.findings));
      } else if (t === "bench") {
        box.appendChild(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Resolver", "OK", "Loss %", "Min", "Avg", "Median", "P95", "Max"].map(function (x) { return h("th", { class: x === "Resolver" ? "" : "num" }, x); }))),
          h("tbody", {}, r.map(function (x) { return h("tr", {}, h("td", {}, x.resolver), h("td", { class: "num" }, x.answered + "/" + x.sent), h("td", { class: "num" }, x.loss_pct), h("td", { class: "num" }, x.min), h("td", { class: "num" }, x.avg), h("td", { class: "num" }, x.median), h("td", { class: "num" }, x.p95), h("td", { class: "num" }, x.max)); })))));
        box.appendChild(h("div", { class: "hint" }, "Times in milliseconds."));
      }
    }
  }

  /* ---------- account ---------- */
  function viewAccount(c) {
    var user = h("input", { type: "text", value: state.user, autocomplete: "username" }), cur = h("input", { type: "password", autocomplete: "current-password" }), np = h("input", { type: "password", autocomplete: "new-password" }), np2 = h("input", { type: "password", autocomplete: "new-password" });
    c.appendChild(h("div", { class: "card", style: "max-width:460px" }, h("h2", {}, "Account"), field("Username", user), field("Current password", cur), field("New password (leave empty to keep)", np, "At least 8 characters."), field("Repeat new password", np2),
      h("button", { class: "primary", onclick: function () {
        if (np.value !== np2.value) return toast("The new passwords do not match", true);
        api("PUT", "/api/account", { current_password: cur.value, username: user.value, new_password: np.value }).then(function (r) { state.user = r.username; cur.value = np.value = np2.value = ""; toast("Account updated"); }).catch(fail);
      } }, "Save")));
  }

  var VIEWS = { dashboard: viewDashboard, log: viewLog, filters: viewFilters, rewrites: viewRewrites, settings: viewSettings, tools: viewTools, account: viewAccount };

  /* ---------- boot ---------- */
  function boot() {
    api("GET", "/api/session").then(function (s) {
      if (!s.authenticated) return renderLogin();
      state.user = s.username; renderShell(); route();
    }).catch(function () { renderLogin(); });
  }
  boot();
})();
