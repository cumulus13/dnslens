/* Minimal dependency-free SVG/HTML charts. All text goes through textContent. */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var PALETTE = ["--c1", "--c2", "--c3", "--c4", "--c5", "--c6", "--c7", "--c8"];

  function svg(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function niceMax(v) {
    if (v <= 4) return 4;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var n = v / p;
    var m = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
    return m * p;
  }
  function fmtTime(ts, bucket) {
    var d = new Date(ts * 1000);
    if (bucket >= 43200) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
    if (bucket >= 3600 * 3) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function color(i) { return "var(" + PALETTE[i % PALETTE.length] + ")"; }

  /* stacked bar timeline: series = {bucket_seconds,start,resolved[],blocked[],failed[]} */
  function timeline(host, s) {
    host.textContent = "";
    var n = s.total.length, W = 800, H = 230, L = 44, R = 8, T = 10, B = 26;
    var max = niceMax(Math.max.apply(null, s.total.concat([1])));
    var plotW = W - L - R, plotH = H - T - B, bw = plotW / n;
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Queries over time" });
    for (var g = 0; g <= 4; g++) {
      var y = T + plotH - (plotH * g) / 4;
      root.appendChild(svg("line", { x1: L, x2: W - R, y1: y, y2: y, "class": "gl" }));
      var t = svg("text", { x: L - 6, y: y + 3, "text-anchor": "end", "class": "ax" });
      t.textContent = Math.round((max * g) / 4).toLocaleString();
      root.appendChild(t);
    }
    var tip = el("div", "tip");
    var cats = [["resolved", "b-resolved", "Resolved"], ["blocked", "b-blocked", "Blocked"], ["failed", "b-failed", "Failed"]];
    for (var i = 0; i < n; i++) {
      var base = T + plotH, x = L + i * bw;
      cats.forEach(function (c) {
        var v = s[c[0]][i];
        if (!v) return;
        var h = (plotH * v) / max;
        base -= h;
        root.appendChild(svg("rect", { x: x + bw * 0.12, y: base, width: Math.max(1, bw * 0.76), height: h, "class": c[1] }));
      });
      var hov = svg("rect", { x: x, y: T, width: bw, height: plotH, "class": "hov" });
      (function (idx, rect, xx) {
        rect.addEventListener("mouseenter", function () {
          tip.textContent = "";
          tip.appendChild(el("div", "", fmtTime(s.start + idx * s.bucket_seconds, s.bucket_seconds)));
          cats.forEach(function (c) { tip.appendChild(el("div", "", c[2] + ": " + (s[c[0]][idx] || 0).toLocaleString())); });
          tip.style.display = "block";
          var frac = (xx + bw / 2) / W;
          tip.style.left = Math.min(Math.max(frac * host.clientWidth - 50, 0), host.clientWidth - 130) + "px";
          tip.style.top = "0px";
        });
        rect.addEventListener("mouseleave", function () { tip.style.display = "none"; });
      })(i, hov, x);
      root.appendChild(hov);
    }
    var ticks = Math.min(6, n);
    for (var k = 0; k < ticks; k++) {
      var idx = Math.round((k * (n - 1)) / Math.max(1, ticks - 1));
      var tx = svg("text", { x: L + idx * bw + bw / 2, y: H - 8, "text-anchor": k === 0 ? "start" : k === ticks - 1 ? "end" : "middle", "class": "ax" });
      tx.textContent = fmtTime(s.start + idx * s.bucket_seconds, s.bucket_seconds);
      root.appendChild(tx);
    }
    host.appendChild(root);
    host.appendChild(tip);
    var lg = el("div", "legend");
    [["Resolved", "var(--c1)"], ["Blocked", "var(--bad)"], ["Failed", "var(--warn)"]].forEach(function (c) {
      var d = el("span"); var i2 = el("i"); i2.style.background = c[1]; d.appendChild(i2); d.appendChild(document.createTextNode(c[0])); lg.appendChild(d);
    });
    host.appendChild(lg);
  }

  /* donut: items = [{name,count}] */
  function donut(host, items) {
    host.textContent = "";
    var total = items.reduce(function (a, b) { return a + b.count; }, 0);
    if (!total) { host.appendChild(el("div", "empty", "No data yet")); return; }
    var wrap = el("div", "donut");
    var root = svg("svg", { viewBox: "0 0 42 42", role: "img" });
    root.appendChild(svg("circle", { cx: 21, cy: 21, r: 15.9155, fill: "none", stroke: "var(--line)", "stroke-width": 6 }));
    var off = 25, ul = el("ul");
    items.forEach(function (it, i) {
      var pct = (100 * it.count) / total;
      root.appendChild(svg("circle", { cx: 21, cy: 21, r: 15.9155, fill: "none", stroke: color(i), "stroke-width": 6,
        "stroke-dasharray": pct + " " + (100 - pct), "stroke-dashoffset": off }));
      off -= pct;
      var li = el("li"), l = el("span"), sw = el("i");
      sw.style.background = color(i);
      l.appendChild(sw); l.appendChild(document.createTextNode(it.name));
      li.appendChild(l);
      li.appendChild(el("span", "muted", it.count.toLocaleString() + " (" + pct.toFixed(1) + "%)"));
      ul.appendChild(li);
    });
    wrap.appendChild(root); wrap.appendChild(ul); host.appendChild(wrap);
  }

  /* ranked list: items=[{name,count,...}], opts={red,action:{label,fn},extra:fn(item)->string} */
  function bars(host, items, opts) {
    opts = opts || {};
    host.textContent = "";
    if (!items.length) { host.appendChild(el("div", "empty", "No data yet")); return; }
    var max = Math.max.apply(null, items.map(function (i) { return i.count; }));
    var box = el("div", "bars" + (opts.red ? " red" : ""));
    items.forEach(function (it) {
      var r = el("div", "r"), bg = el("div", "bg");
      bg.style.width = (100 * it.count / max) + "%";
      r.appendChild(bg);
      r.appendChild(el("div", "n", it.name || "(unknown)")).title = it.name;
      r.appendChild(el("div", "c", it.count.toLocaleString() + (opts.extra ? " " + opts.extra(it) : "")));
      if (opts.action) {
        var b = el("button", "small", opts.action.label);
        b.addEventListener("click", function () { opts.action.fn(it); });
        r.appendChild(b);
      } else { r.style.gridTemplateColumns = "minmax(0,1fr) auto"; }
      box.appendChild(r);
    });
    host.appendChild(box);
  }

  window.Charts = { timeline: timeline, donut: donut, bars: bars };
})();
