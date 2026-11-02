import { JSDOM } from "jsdom";
const base = `http://127.0.0.1:${process.env.UI_PORT || 18080}`;
const PASSWORD = process.env.UI_PASSWORD || "uitest-pass1";
const errors = [];
let cookie = "";
const html = await (await fetch(base + "/")).text();
const dom = new JSDOM(html, {
  url: base + "/", runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
  beforeParse(w) {
    w.matchMedia = () => ({ matches: false });
    w.confirm = () => true;
    w.scrollTo = () => {};
    w.addEventListener("error", (e) => errors.push("window error: " + (e.error?.stack || e.message)));
    w.fetch = async (url, opt = {}) => {
      const headers = { ...(opt.headers || {}) };
      if (cookie) headers.Cookie = cookie;
      const r = await fetch(new URL(url, base), { ...opt, headers });
      const sc = r.headers.get("set-cookie");
      if (sc) cookie = sc.split(";")[0].endsWith("=") ? "" : sc.split(";")[0];
      return r;
    };
  },
});
const w = dom.window, d = w.document;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, what, ms = 8000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { try { const v = fn(); if (v) return v; } catch (e) {} await sleep(50); }
  throw new Error("timeout waiting for " + what + "\n" + d.body.textContent.slice(0, 300));
}
const text = () => d.body.textContent;
const check = (cond, msg) => { if (!cond) { errors.push("CHECK FAILED: " + msg); } else console.log("ok  -", msg); };
const go = async (page) => { w.location.hash = "#/" + page; await sleep(80); };

// login with wrong password, then right
await waitFor(() => d.querySelector(".login"), "login form");
const [u, p] = d.querySelectorAll(".login input");
p.value = "wrong"; d.querySelector(".login button").click();
await waitFor(() => d.querySelector(".err-text").textContent.includes("wrong"), "login error shown");
check(true, "wrong password shows an error");
p.value = PASSWORD; d.querySelector(".login button").click();
await waitFor(() => d.querySelector(".layout"), "app shell");
check(d.querySelectorAll(".nav a").length === 7, "sidebar has 7 pages");

// dashboard
await waitFor(() => d.querySelector(".chart svg"), "timeline chart");
await waitFor(() => d.querySelectorAll(".card.stat").length === 4, "stat cards");
const stats = [...d.querySelectorAll(".card.stat .v")].map((e) => e.textContent);
console.log("stat values:", stats.join(" | "));
check(Number(stats[0].replace(/,/g, "")) >= 250, "dashboard shows total queries (>=250)");
check(Number(stats[1].replace(/,/g, "")) > 0, "dashboard shows blocked queries");
check(Number(stats[3].replace(/,/g, "")) >= 3, "blocking rules card shows list size (" + stats[3] + ")");
check(d.querySelectorAll(".chart svg rect.b-resolved").length > 0 && d.querySelectorAll(".chart svg rect.b-blocked").length > 0, "timeline has resolved and blocked bars");
await waitFor(() => d.querySelectorAll(".donut svg").length === 2, "two donut charts");
check(text().includes("ads.bad.test"), "top blocked lists ads.bad.test");
check(text().includes("Upstream servers") && text().includes("ms"), "upstream section rendered");
// hover tooltip
const hov = d.querySelector(".chart rect.hov"); hov.dispatchEvent(new w.Event("mouseenter"));
check(d.querySelector(".chart .tip").style.display === "block" && d.querySelector(".chart .tip").textContent.includes("Resolved"), "chart tooltip works");
// window switch
[...d.querySelectorAll(".seg button")].find((b) => b.textContent === "1h").click();
await waitFor(() => d.querySelector(".seg button.on").textContent === "1h", "window switch");
check(true, "time window switch");

// query log
await go("log");
await waitFor(() => d.querySelectorAll("tbody tr.click").length > 50, "query log rows");
check(d.querySelector(".badge.blocked") && d.querySelector(".badge.cache"), "log shows blocked and cached badges");
const first = d.querySelector("tbody tr.click"); first.click();
check(first.nextSibling.style.display === "", "row details expand");
const sel = d.querySelector(".content select"); sel.value = "blocked"; sel.dispatchEvent(new w.Event("change"));
await waitFor(() => { const rows = d.querySelectorAll("tbody tr.click"); return rows.length > 0 && [...rows].every((r) => r.textContent.includes("Blocked")); }, "blocked filter");
check(true, "status filter only shows blocked rows");
const s = d.querySelector("input[type=search]"); s.value = "tracker"; s.dispatchEvent(new w.Event("input"));
await waitFor(() => { const rows = d.querySelectorAll("tbody tr.click"); return rows.length > 0 && [...rows].every((r) => r.textContent.includes("tracker")); }, "search");
check(true, "search narrows the log");

// XSS: a hostile name sent by a DNS client must render as text
await go("account"); await go("log"); await waitFor(() => d.querySelectorAll("tbody tr.click").length > 5, "log again");
check(text().includes("xss.test"), "hostile domain is visible as literal text");
check(d.querySelectorAll("img[src='x']").length === 0 && !d.querySelector("[onerror]"), "no element was injected from a DNS name");

// filters
await go("filters");
await waitFor(() => text().includes("Test list"), "filters list");
check(text().includes("Blocklists") && text().includes("Custom filtering rules") && text().includes("Check a host"), "filters page sections");
const host = d.querySelector("input[placeholder='example.com']"); host.value = "x.tracker.bad.test";
[...d.querySelectorAll("button")].find((b) => b.textContent === "Check").click();
await waitFor(() => text().includes("Blocked by rule tracker.bad.test"), "host check result");
check(true, "check host reports the matching rule");
const ta = d.querySelector("textarea"); ta.value = "||custom.test^\n";
[...d.querySelectorAll("button")].find((b) => b.textContent === "Save rules").click();
await waitFor(() => text().includes("Saved (1 rules)"), "rules saved toast");
check(true, "custom rules save");
const presets = d.querySelector(".content select option[value='0']"); check(presets && presets.textContent.length > 3, "preset lists offered");

// rewrites
await go("rewrites");
await waitFor(() => text().includes("nas.home"), "rewrites table");
const [nm, dt] = d.querySelectorAll(".card input[type=text]");
nm.value = "printer.home"; dt.value = "10.0.0.50";
[...d.querySelectorAll("button")].find((b) => b.textContent === "Add rewrite").click();
await waitFor(() => text().includes("printer.home"), "new rewrite listed");
check(true, "rewrite added and listed");
[...d.querySelectorAll("button")].filter((b) => b.textContent === "Delete").pop().click();
await waitFor(() => !text().includes("printer.home"), "rewrite deleted");
check(true, "rewrite deleted");

// settings
await go("settings");
await waitFor(() => d.querySelector("textarea") && d.querySelector("textarea").value.includes("127.0.0.1"), "settings loaded");
[...d.querySelectorAll("button")].find((b) => b.textContent === "Test saved upstreams").click();
await waitFor(() => text().includes("OK"), "upstream test result");
check(true, "upstream test runs");
[...d.querySelectorAll("button")].find((b) => b.textContent === "Save settings").click();
await waitFor(() => text().includes("Settings saved"), "settings saved");
check(true, "settings save");

// tools
await go("tools");
await waitFor(() => d.querySelector(".content select"), "tools form");
const tn = d.querySelector(".card input[type=text]"); tn.value = "example.test";
const rs = d.querySelectorAll(".content select")[1]; rs.value = "this-server";
[...d.querySelectorAll("button")].find((b) => b.textContent === "Run").click();
await waitFor(() => text().includes("192.0.2.1"), "tool output");
check(true, "lookup tool returns data via this server");

// account + protection + logout
await go("account"); await waitFor(() => text().includes("Current password"), "account page");
const prot = d.getElementById("prot"); prot.value = "600"; prot.dispatchEvent(new w.Event("change"));
await waitFor(() => text().includes("Protection disabled"), "protection toast");
check(true, "protection can be paused");
prot.value = "on"; prot.dispatchEvent(new w.Event("change"));
await waitFor(() => text().includes("Protection enabled") && !text().includes("back in"), "re-enabled");
[...d.querySelectorAll("button")].find((b) => b.textContent === "Sign out").click();
await waitFor(() => d.querySelector(".login"), "back to login");
check(true, "sign out returns to login");

// XSS: make sure hostile names never become markup
console.log(errors.length ? "\nPROBLEMS:\n" + errors.join("\n") : "\nALL UI CHECKS PASSED");
w.close();
process.exit(errors.length ? 1 : 0);
