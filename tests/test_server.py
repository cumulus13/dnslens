# File: dnslens/tests/test_server.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

import json
import socket
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import pytest
from conftest import zone_handler

from dnslens.cli import main
from dnslens.core import QueryOpts, query
from dnslens.server import (
    ConfigError,
    DNSHandler,
    DNSServer,
    Reloader,
    ServerOptions,
    build_zone,
    default_allow,
    load_config_file,
    parse_blocklist,
)

CFG = {
    "ttl": 120,
    "authoritative": ["dev.test."],
    "block": ["ads.example.net"],
    "records": {
        "app.dev.test.": {"A": ["10.0.0.5", "10.0.0.6"], "TXT": "hello world", "AAAA": {"ttl": 30, "data": ["fd00::5"]}},
        "*.wild.dev.test.": {"A": ["10.9.9.9"]},
        "www.dev.test.": {"CNAME": "app.dev.test."},
        "ext.dev.test.": {"CNAME": "target.real.test."},
        "big.dev.test.": {"TXT": [("x" * 200 + str(i)) for i in range(8)]},
    },
}


@pytest.fixture
def up(serve):
    """fake upstream that counts queries"""
    calls = {"n": 0}
    h = zone_handler({("real.test.", "A"): ["203.0.113.7"], ("target.real.test.", "A"): ["203.0.113.9"]}, ttl=60, aa=False)

    def handler(q):
        calls["n"] += 1
        return h(q)

    s = serve(handler)
    s.calls = calls
    return s


def make(up, cfg=CFG, **kw):
    zone = build_zone(cfg)
    opts = ServerOptions(upstreams=[f"127.0.0.1#{up.port}"], upstream_timeout=1.0, **kw)
    h = DNSHandler(zone, opts)
    return DNSServer(h, "127.0.0.1", 0).start(), h


def ask(srv, name, rtype="A", tcp=False, **kw):
    q = dns.message.make_query(name, rtype, **kw)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, "127.0.0.1", timeout=2, port=srv.port)


def test_local_records(up):
    srv, h = make(up)
    with srv:
        r = ask(srv, "app.dev.test", "A")
        assert r.rcode() == 0 and r.flags & dns.flags.AA
        assert {x.address for x in r.answer[0]} == {"10.0.0.5", "10.0.0.6"} and r.answer[0].ttl == 120
        assert ask(srv, "app.dev.test", "AAAA").answer[0].ttl == 30
        assert ask(srv, "app.dev.test", "TXT").answer[0][0].strings == (b"hello world",)
        assert ask(srv, "deep.sub.wild.dev.test", "A").answer[0][0].address == "10.9.9.9"
        assert ask(srv, "APP.Dev.Test", "A").rcode() == 0  # case-insensitive
        nodata = ask(srv, "app.dev.test", "MX")
        assert nodata.rcode() == 0 and not nodata.answer
        assert up.calls["n"] == 0


def test_authoritative_nxdomain_and_ent(up):
    srv, h = make(up)
    with srv:
        assert ask(srv, "missing.dev.test").rcode() == dns.rcode.NXDOMAIN
        assert ask(srv, "wild.dev.test").rcode() == 0  # empty non-terminal -> NODATA
        assert up.calls["n"] == 0


def test_cname_local_and_chase_upstream(up):
    srv, h = make(up)
    with srv:
        r = ask(srv, "www.dev.test", "A")
        assert [dns.rdatatype.to_text(x.rdtype) for x in r.answer] == ["CNAME", "A"]
        r = ask(srv, "ext.dev.test", "A")
        types = [dns.rdatatype.to_text(x.rdtype) for x in r.answer]
        assert types[0] == "CNAME" and "A" in types
        assert r.answer[-1][0].address == "203.0.113.9"


def test_forward_and_cache(up):
    srv, h = make(up)
    with srv:
        a = ask(srv, "real.test")
        assert a.answer[0][0].address == "203.0.113.7" and a.flags & dns.flags.RA
        b = ask(srv, "real.test")
        assert b.answer[0][0].address == "203.0.113.7"
        assert up.calls["n"] == 1
        assert h.stats.snapshot()["cache_hit"] == 1
        nx = ask(srv, "nope.real.test")
        assert nx.rcode() == dns.rcode.NXDOMAIN
        ask(srv, "nope.real.test")
        assert up.calls["n"] == 2  # negative answers are cached too (30s default)


def test_cache_ttl_decrements(up):
    srv, h = make(up)
    with srv:
        ask(srv, "real.test")
        time.sleep(1.2)
        assert ask(srv, "real.test").answer[0].ttl < 60


def test_no_cache_option(up):
    srv, h = make(up, cache_size=0)
    with srv:
        ask(srv, "real.test")
        ask(srv, "real.test")
        assert up.calls["n"] == 2


def test_block_modes(up):
    srv, h = make(up)
    with srv:
        assert ask(srv, "x.ads.example.net").rcode() == dns.rcode.NXDOMAIN
    z = build_zone({"block": ["ads.example.net"], "block_mode": "null"})
    h2 = DNSHandler(z, ServerOptions(upstreams=[f"127.0.0.1#{up.port}"]))
    with DNSServer(h2, "127.0.0.1", 0).start() as s2:
        r = ask(s2, "ads.example.net")
        assert r.answer[0][0].address == "0.0.0.0"


def test_tcp_and_truncation(up):
    srv, h = make(up)
    with srv:
        r = ask(srv, "big.dev.test", "TXT")  # > 512 bytes over UDP w/o EDNS
        assert r.flags & dns.flags.TC and not r.answer
        full = ask(srv, "big.dev.test", "TXT", tcp=True)
        assert len(full.answer[0]) == 8
        # EDNS payload 1232 still too small for ~1.7KB
        e = ask(srv, "big.dev.test", "TXT", use_edns=0, payload=1232)
        assert e.flags & dns.flags.TC
        # dnspython's udp_with_fallback goes through TCP transparently
        resp, used_tcp = dns.query.udp_with_fallback(dns.message.make_query("big.dev.test", "TXT"), "127.0.0.1", timeout=2, port=srv.port)
        assert used_tcp and len(resp.answer[0]) == 8


def test_acl_refused(up):
    zone = build_zone(CFG)
    opts = ServerOptions(upstreams=[f"127.0.0.1#{up.port}"], allow=default_allow("0.0.0.0")[1:2])  # only 10/8
    with DNSServer(DNSHandler(zone, opts), "127.0.0.1", 0).start() as s:
        assert ask(s, "app.dev.test").rcode() == dns.rcode.REFUSED
    assert default_allow("127.0.0.1") is None and default_allow("0.0.0.0")


def test_no_forward_refuses(up):
    srv, h = make(up, forward=False)
    with srv:
        assert ask(srv, "real.test").rcode() == dns.rcode.REFUSED
        assert ask(srv, "app.dev.test").rcode() == 0
        assert not ask(srv, "app.dev.test").flags & dns.flags.RA


def test_upstream_down_servfail():
    zone = build_zone(CFG)
    opts = ServerOptions(upstreams=["127.0.0.1#9"], upstream_timeout=0.3)
    with DNSServer(DNSHandler(zone, opts), "127.0.0.1", 0).start() as s:
        assert ask(s, "real.test").rcode() == dns.rcode.SERVFAIL


def test_garbage_and_formerr(up):
    srv, h = make(up)
    with srv:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"\x12\x34" + b"\xff" * 20, ("127.0.0.1", srv.port))
        data, _ = s.recvfrom(512)
        assert data[:2] == b"\x12\x34" and data[3] & 0x0F == 1  # FORMERR
        s.sendto(b"abc", ("127.0.0.1", srv.port))  # too short: dropped
        s.settimeout(0.3)
        with pytest.raises(socket.timeout):
            s.recvfrom(512)
        s.close()


def test_axfr_refused(up):
    srv, h = make(up)
    with srv:
        q = dns.message.make_query("dev.test", "AXFR")
        r = dns.query.tcp(q, "127.0.0.1", timeout=2, port=srv.port)
        assert r.rcode() == dns.rcode.REFUSED


def test_client_and_cli_against_server(up, capsys):
    srv, h = make(up)
    with srv:
        a = query("app.dev.test", "A", f"127.0.0.1#{srv.port}", QueryOpts(timeout=1, retries=0))
        assert a.ok and "10.0.0.5" in a.values()
        rc = main(["query", "app.dev.test", "--short", "-r", f"127.0.0.1#{srv.port}"])
        assert rc == 0 and "10.0.0.5" in capsys.readouterr().out


def test_config_validation(tmp_path):
    with pytest.raises(ConfigError):
        build_zone({"records": {"a.test.": {"A": ["not-an-ip"]}}})
    with pytest.raises(ConfigError):
        build_zone({"records": {"a.test.": {"CNAME": "b.test.", "A": "1.1.1.1"}}})
    with pytest.raises(ConfigError):
        build_zone(block_mode="weird")
    with pytest.raises(ConfigError):
        build_zone(records=["only two"])
    p = tmp_path / "c.json"
    p.write_text('{"recordz": {}}')
    with pytest.raises(ConfigError):
        load_config_file(str(p))
    p.write_text("{bad json")
    with pytest.raises(ConfigError):
        load_config_file(str(p))


def test_cli_records_and_blocklist(tmp_path):
    bl = tmp_path / "hosts.txt"
    bl.write_text("# c\n127.0.0.1 localhost\n0.0.0.0 tracker.test ads2.test\nplain.test\n")
    assert list(parse_blocklist(bl.read_text())) == ["localhost", "tracker.test", "ads2.test", "plain.test"]
    z = build_zone(records=["svc.test A 1.2.3.4", "svc.test TXT v=1 ok"], blocklist_files=[str(bl)])
    assert z.counts() == {"records": 2, "blocked": 3, "allowed": 0}  # localhost ignored


def test_hot_reload(tmp_path, up):
    p = tmp_path / "z.json"
    p.write_text(json.dumps({"records": {"a.test.": {"A": "1.1.1.1"}}}))
    loader = lambda: build_zone(load_config_file(str(p)))
    h = DNSHandler(loader(), ServerOptions(upstreams=[f"127.0.0.1#{up.port}"]))
    rl = Reloader([str(p)], loader, h.set_zone)
    with DNSServer(h, "127.0.0.1", 0).start() as s:
        assert ask(s, "a.test").answer[0][0].address == "1.1.1.1"
        time.sleep(0.05)
        p.write_text(json.dumps({"records": {"a.test.": {"A": "2.2.2.2"}}}))
        assert rl.check()
        assert ask(s, "a.test").answer[0][0].address == "2.2.2.2"
        p.write_text("{broken")
        assert not rl.check()  # keeps previous config
        assert ask(s, "a.test").answer[0][0].address == "2.2.2.2"


def test_relative_names_in_rdata_are_absolute(up):
    z = build_zone(records=["a.test CNAME b.test", "a2.test MX 10 mail.test", "b.test A 10.1.1.1"])
    h = DNSHandler(z, ServerOptions(forward=False))
    with DNSServer(h, "127.0.0.1", 0).start() as s:
        r = ask(s, "a.test", "A")
        assert [dns.rdatatype.to_text(x.rdtype) for x in r.answer] == ["CNAME", "A"]
        assert ask(s, "a2.test", "MX").answer[0][0].exchange.to_text() == "mail.test."
