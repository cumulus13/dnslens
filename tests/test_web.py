# File: dnslens/tests/test_web.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

import json
import ssl
import time

import dns.message
import dns.query
import dns.rcode
from helpers import LIST, PW, Client, ListServer  # noqa: F401

from dnslens.filters import parse_rules
from dnslens.manage import Manager, hash_password, verify_password
from dnslens.querylog import QueryLog, anonymize
from dnslens.server import DNSHandler, QueryEvent, ZoneData
from dnslens.web import WebServer

# ---------------------------------------------------------------- units ---

def test_parse_rules_formats():
    p = parse_rules(LIST + "bad line with spaces\n||x.test^$important\n||y.test^$dnsrewrite=1.2.3.4\n")
    assert p.blocks == {"ads.bad.test", "tracker.bad.test", "plain.bad.test", "x.test"}
    assert p.allows == {"ok.bad.test"}
    assert p.skipped == 3  # regex, spaced line, unsupported modifier


def test_password_hash():
    h = hash_password("secret123")
    assert verify_password("secret123", h) and not verify_password("nope", h) and not verify_password("x", "garbage")


def test_anonymize_and_querylog(tmp_path):
    assert anonymize("192.168.1.77") == "192.168.1.0" and anonymize("2001:db8:1:2::5").startswith("2001:db8:1::")
    ql = QueryLog(str(tmp_path / "q.db"), retention_hours=1, anonymize_clients=True).start()
    now = time.time()
    ql.record(QueryEvent(now, "10.0.0.9", "a.test", "A", "NOERROR", "upstream", 5.0, upstream="1.1.1.1", answers=["A 1.2.3.4"]))
    ql.record(QueryEvent(now, "10.0.0.9", "b.test", "AAAA", "NXDOMAIN", "blocked", 0.1, rule="b.test", list_id=3))
    ql.record(QueryEvent(now - 7200, "10.0.0.9", "old.test", "A", "NOERROR", "cache", 0.1))
    ql.flush()
    assert ql.count() == 3
    s = ql.summary("24h")
    assert s["totals"]["queries"] == 3 and s["totals"]["blocked"] == 1 and s["top_clients"][0]["name"] == "10.0.0.0"
    assert ql.search(status="blocked")["items"][0]["rule"] == "b.test"
    assert [i["name"] for i in ql.search(search="a.te")["items"]] == ["a.test"]
    assert ql.search(search="%")["items"] == []  # LIKE wildcards are escaped
    assert ql.purge() == 1 and ql.count() == 2
    ql.clear()
    assert ql.count() == 0
    ql.stop()


# ------------------------------------------------------------- web/auth ---

def test_assets_and_headers(stack):
    c = Client(stack.client.base)
    code, body, h = c.call("GET", "/")
    assert code == 200 and b"<script src=\"/app.js\">" in body and "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert c.call("GET", "/app.js")[0] == 200 and c.call("GET", "/charts.js")[0] == 200 and c.call("GET", "/style.css")[0] == 200
    assert c.call("GET", "/nope.php")[0] == 404
    assert c.call("GET", "/some/spa/route")[0] == 200  # client-side routes fall back to index.html


def test_auth_flow(stack):
    c = Client(stack.client.base)
    assert c.call("GET", "/api/status")[0] == 401
    assert c.call("GET", "/api/session")[1]["authenticated"] is False
    code, body, _ = c.login("wrong")
    assert code == 401
    code, body, h = c.login()
    assert code == 200
    cookie = [v for k, v in h.items() if k.lower() == "set-cookie"][0]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert c.call("GET", "/api/session")[1]["username"] == "admin"
    assert c.call("GET", "/api/status")[0] == 200
    c.call("POST", "/api/logout", {})
    assert c.call("GET", "/api/status")[0] == 401


def test_csrf_protection(stack):
    c = stack.client
    assert c.call("POST", "/api/cache/clear", {}, csrf=False)[0] == 403
    code, body, _ = c.call("POST", "/api/cache/clear", {}, headers={"Origin": "http://evil.example"})
    assert code == 403
    assert c.call("POST", "/api/cache/clear", {})[0] == 200
    assert c.call("PUT", "/api/status", {})[0] == 405


def test_login_bruteforce_lockout(stack):
    c = Client(stack.client.base)
    for _ in range(5):
        assert c.login("bad")[0] == 401
    code, body, h = c.login(PW)
    assert code == 429 and "Retry-After" in h


# -------------------------------------------------------- core features ---

def test_filter_list_blocks_and_stats(stack):
    c = stack.client
    code, f, _ = c.call("POST", "/api/filters", {"name": "Test list", "url": stack.lists.url})
    assert code == 201 and f["rules"] == 4  # 3 blocks + 1 allow... see parse: ads, tracker, plain + ok
    assert stack.ask("ads.bad.test").rcode() == dns.rcode.NXDOMAIN
    assert stack.ask("sub.tracker.bad.test").rcode() == dns.rcode.NXDOMAIN  # subdomains too
    assert stack.ask("plain.bad.test").rcode() == dns.rcode.NXDOMAIN
    assert stack.ask("example.test").answer[0][0].address == "192.0.2.1"
    stack.mgr.qlog.flush()
    s = c.call("GET", "/api/stats?window=1h")[1]
    t = s["totals"]
    assert t["queries"] == 4 and t["blocked"] == 3 and t["blocked_pct"] == 75.0
    assert {b["name"] for b in s["top_blocked"]} >= {"ads.bad.test", "plain.bad.test"}
    assert sum(s["series"]["blocked"]) == 3 and len(s["series"]["total"]) == len(s["series"]["resolved"])
    assert s["top_upstreams"][0]["name"].startswith("127.0.0.1")
    log = c.call("GET", "/api/querylog?status=blocked")[1]["items"]
    assert len(log) == 3 and log[0]["list_id"] == f["id"] and log[0]["rule"]
    # toggling the list off lets the name resolve again
    assert c.call("PUT", f"/api/filters/{f['id']}", {"enabled": False})[0] == 200
    assert stack.ask("ads.bad.test").answer[0][0].address == "203.0.113.66"
    c.call("PUT", f"/api/filters/{f['id']}", {"enabled": True})
    assert stack.ask("ads.bad.test").rcode() == dns.rcode.NXDOMAIN
    assert c.call("DELETE", f"/api/filters/{f['id']}")[0] == 200
    assert stack.ask("ads.bad.test").rcode() == 0


def test_filter_errors(stack):
    c = stack.client
    assert c.call("POST", "/api/filters", {"name": "x", "url": "ftp://x"})[0] == 400
    assert c.call("POST", "/api/filters", {"name": "x", "url": "http://127.0.0.1:9/none.txt"})[0] == 400
    stack.lists.text = "! nothing usable\n"
    assert c.call("POST", "/api/filters", {"name": "empty", "url": stack.lists.url})[0] == 400


def test_custom_rules_allow_wins(stack):
    c = stack.client
    c.call("POST", "/api/filters", {"name": "L", "url": stack.lists.url})
    assert c.call("POST", "/api/rules/action", {"action": "allow", "domain": "ads.bad.test"})[0] == 200
    assert stack.ask("ads.bad.test").rcode() == 0
    c.call("POST", "/api/rules/action", {"action": "block", "domain": "example.test"})
    assert stack.ask("example.test").rcode() == dns.rcode.NXDOMAIN
    rules = c.call("GET", "/api/rules")[1]["text"]
    assert "@@||ads.bad.test^" in rules and "||example.test^" in rules
    c.call("POST", "/api/rules/action", {"action": "allow", "domain": "example.test"})
    assert "||example.test^" not in c.call("GET", "/api/rules")[1]["text"].replace("@@||example.test^", "")
    assert stack.ask("example.test").rcode() == 0
    assert c.call("PUT", "/api/rules", {"text": "||ads2.test^\n"})[1]["rules"] == 1
    assert c.call("POST", "/api/rules/action", {"action": "block", "domain": "bad domain!"})[0] == 400


def test_check_host(stack):
    c = stack.client
    c.call("POST", "/api/filters", {"name": "L", "url": stack.lists.url})
    r = c.call("POST", "/api/check", {"name": "x.tracker.bad.test"})[1]
    assert r["result"] == "blocked" and r["list"] == "L" and r["rule"] == "tracker.bad.test"
    assert c.call("POST", "/api/check", {"name": "ok.bad.test"})[1]["result"] == "allowed"
    assert c.call("POST", "/api/check", {"name": "example.test"})[1]["result"] == "processed"


def test_rewrites_crud(stack):
    c = stack.client
    code, rw, _ = c.call("POST", "/api/rewrites", {"name": "App.Internal", "data": "10.0.0.5", "type": "AUTO", "ttl": 60})
    assert code == 201 and rw["type"] == "A" and rw["name"] == "app.internal"
    r = stack.ask("app.internal")
    assert r.answer[0][0].address == "10.0.0.5" and r.answer[0].ttl == 60
    assert c.call("PUT", f"/api/rewrites/{rw['id']}", {"data": "10.0.0.6"})[0] == 200
    assert stack.ask("app.internal").answer[0][0].address == "10.0.0.6"
    c.call("POST", "/api/rewrites", {"name": "*.dev.internal", "data": "app.internal", "type": "AUTO"})  # -> CNAME
    assert stack.ask("x.dev.internal").answer[0].rdtype == dns.rdatatype.CNAME
    assert c.call("PUT", f"/api/rewrites/{rw['id']}", {"enabled": False})[0] == 200
    assert stack.ask("app.internal").rcode() in (0, dns.rcode.NXDOMAIN)
    assert c.call("POST", "/api/rewrites", {"name": "bad.test", "data": "not-an-ip", "type": "A"})[0] == 400
    assert c.call("POST", "/api/rewrites", {"name": "", "data": "1.1.1.1"})[0] == 400
    assert c.call("DELETE", f"/api/rewrites/{rw['id']}")[0] == 200
    assert c.call("DELETE", f"/api/rewrites/{rw['id']}")[0] == 404
    assert len(c.call("GET", "/api/rewrites")[1]) == 1


def test_protection_toggle(stack):
    c = stack.client
    c.call("POST", "/api/rules/action", {"action": "block", "domain": "example.test"})
    assert stack.ask("example.test").rcode() == dns.rcode.NXDOMAIN
    p = c.call("POST", "/api/protection", {"enabled": False, "duration": 600})[1]
    assert p["enabled"] is False and p["until"] > time.time()
    assert stack.ask("example.test").rcode() == 0
    stack.handler.protection_until = time.time() - 1  # timer expiry re-enables automatically
    assert stack.ask("example.test").rcode() == dns.rcode.NXDOMAIN
    assert c.call("GET", "/api/status")[1]["protection"]["enabled"] is True
    assert c.call("POST", "/api/protection", {"enabled": False, "duration": -5})[0] == 400


def test_settings_apply_and_persist(stack, tmp_path):
    c = stack.client
    code, s, _ = c.call("PUT", "/api/settings", {"dns": {"upstreams": ["9.9.9.9#5353"], "cache_size": 5, "max_ttl": 600,
                        "upstream_timeout": 1.5, "block_mode": "null"}, "log": {"retention_hours": 24, "anonymize": True}})
    assert code == 200 and s["dns"]["upstreams"] == ["9.9.9.9#5353"]
    assert stack.handler.opts.upstreams == ["9.9.9.9#5353"] and stack.handler.cache.size == 5 and stack.handler.opts.max_ttl == 600
    assert stack.mgr.qlog.retention_hours == 24 and stack.mgr.qlog.anonymize_clients is True
    assert stack.handler.zone.block_mode == "null"
    for bad in ({"dns": {"upstreams": []}}, {"dns": {"upstreams": ["bad address"]}}, {"dns": {"cache_size": -1}},
                {"dns": {"block_mode": "x"}}, {"log": {"retention_hours": 5}}, {"dns": {"upstream_timeout": 99}}):
        assert c.call("PUT", "/api/settings", bad)[0] == 400, bad
    saved = json.load(open(stack.mgr.path))
    assert saved["dns"]["upstreams"] == ["9.9.9.9#5353"] and saved["auth"]["password_hash"].startswith("pbkdf2_sha256$")
    # a new manager on the same directory loads the persisted state
    h2 = DNSHandler(ZoneData())
    m2 = Manager(stack.mgr.data_dir, h2, ZoneData())
    assert m2.cfg["dns"]["upstreams"] == ["9.9.9.9#5353"]
    m2.qlog.stop() if m2.qlog._thread.is_alive() else None


def test_upstream_test_and_tools(stack):
    c = stack.client
    r = c.call("POST", "/api/upstreams/test", {})[1]
    assert r[0]["ok"] is True
    code, body, _ = c.call("GET", "/api/tools/query?name=example.test&resolver=this-server&retries=0")
    assert code == 200 and body[0]["records"][0]["data"] == "192.0.2.1"
    assert c.call("GET", "/api/tools/probe?kind=query&name=example.test")[0] == 404
    assert c.call("GET", "/api/tools/nonsense")[0] == 404
    assert c.call("GET", "/api/tools/query?name=bad%20name")[0] == 400


def test_querylog_filters_and_clear(stack):
    c = stack.client
    for n in ("example.test", "ok.bad.test"):
        stack.ask(n)
    stack.ask("example.test")  # cached
    stack.mgr.qlog.flush()
    assert len(c.call("GET", "/api/querylog?search=ok.bad")[1]["items"]) == 1
    assert len(c.call("GET", "/api/querylog?status=cached")[1]["items"]) == 1
    page = c.call("GET", "/api/querylog?limit=2")[1]
    assert len(page["items"]) == 2 and page["next"]
    rest = c.call("GET", f"/api/querylog?limit=2&before={page['next']}")[1]
    assert len(rest["items"]) == 1
    assert c.call("GET", "/api/querylog?status=bogus")[0] == 400
    assert c.call("GET", "/api/stats?window=99y")[0] == 400
    assert c.call("POST", "/api/querylog/clear", {})[0] == 200
    assert c.call("GET", "/api/querylog")[1]["items"] == []
    cl = c.call("GET", "/api/clients")[1]
    assert cl == []


def test_account_change(stack):
    c, other = stack.client, Client(stack.client.base)
    other.login()
    assert c.call("PUT", "/api/account", {"current_password": "wrong", "new_password": "newpassword1"})[0] == 400
    assert c.call("PUT", "/api/account", {"current_password": PW, "new_password": "short"})[0] == 400
    assert c.call("PUT", "/api/account", {"current_password": PW, "username": "boss", "new_password": "newpassword1"})[0] == 200
    assert c.call("GET", "/api/status")[0] == 200  # current session survives
    assert other.call("GET", "/api/status")[0] == 401  # other sessions are dropped
    fresh = Client(c.base)
    assert fresh.login(PW, "boss")[0] == 401 and fresh.login("newpassword1", "boss")[0] == 200


def test_initial_password_generated(tmp_path):
    h = DNSHandler(ZoneData())
    m = Manager(str(tmp_path / "d"), h, ZoneData())
    m.start()
    assert m.initial_password and len(m.initial_password) >= 10 and m.verify_login("admin", m.initial_password)
    m.stop()
    h2 = DNSHandler(ZoneData())
    m2 = Manager(str(tmp_path / "d"), h2, ZoneData())
    m2.start()
    assert m2.initial_password is None  # not regenerated on the next start
    m2.stop()


def test_https(tmp_path, stack):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cp, kp = tmp_path / "c.pem", tmp_path / "k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    web = WebServer(stack.mgr, "127.0.0.1", 0, str(cp), str(kp)).start()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        c = Client(f"https://127.0.0.1:{web.port}", ctx)
        code, _, h = c.login()
        assert code == 200
        assert "Secure" in [v for k, v in h.items() if k.lower() == "set-cookie"][0]
        assert "Strict-Transport-Security" in h
        assert c.call("GET", "/api/status")[0] == 200
    finally:
        web.stop()


def test_rewrite_beats_blocklist(stack):
    c = stack.client
    c.call("POST", "/api/rules/action", {"action": "block", "domain": "nas.home"})
    assert stack.ask("nas.home").rcode() == dns.rcode.NXDOMAIN
    c.call("POST", "/api/rewrites", {"name": "nas.home", "data": "10.0.0.7"})
    assert stack.ask("nas.home").answer[0][0].address == "10.0.0.7"
    assert c.call("POST", "/api/check", {"name": "nas.home"})[1]["result"] == "rewritten"
