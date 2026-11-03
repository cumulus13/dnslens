# File: dnslens/tests/test_tools.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

import dns.flags
import dns.message
import dns.rrset
from conftest import zone_handler

from dnslens.core import QueryOpts, Target
from dnslens.tools import bench, propagate, run_many, satisfied, wait
from dnslens.trace import trace

A = {("example.test.", "A"): ["192.0.2.1"]}
B = {("example.test.", "A"): ["192.0.2.9"]}


def opts(port):
    return QueryOpts(timeout=1.0, retries=0, port=port)


def two(serve, za, zb):
    s1, s2 = serve(zone_handler(za)), serve(zone_handler(zb))
    assert s1.port != s2.port
    return s1, s2


def test_propagate_consistent(serve):
    s = serve(zone_handler(A))
    t = [Target("a", "127.0.0.1"), Target("b", "127.0.0.1")]
    rep = propagate(t, "example.test", "A", opts(s.port), expected=["192.0.2.1"])
    assert rep.ok and rep.consistent and rep.matches_expected


def test_propagate_expected_mismatch(serve):
    s = serve(zone_handler(A))
    rep = propagate([Target("a", "127.0.0.1")], "example.test", "A", opts(s.port), expected=["192.0.2.2"])
    assert not rep.ok and rep.consistent and rep.matches_expected is False


def test_propagate_inconsistent_and_unreachable(serve):
    # per-target ports are not supported, so emulate via two servers and per-target opts
    s1, s2 = two(serve, A, B)
    r1 = run_many([Target("a", "127.0.0.1")], "example.test", "A", opts(s1.port))
    r2 = run_many([Target("b", "127.0.0.1")], "example.test", "A", opts(s2.port))
    from dnslens.tools import PropagationReport
    rep = PropagationReport("example.test", "A", r1 + r2)
    assert not rep.consistent and not rep.ok and len(rep.groups) == 2
    dead = run_many([Target("dead", "127.0.0.1")], "example.test", "A", QueryOpts(timeout=0.3, retries=0, port=9))
    rep2 = PropagationReport("example.test", "A", r1 + dead)
    assert rep2.ok and rep2.failed == ["dead"]
    rep3 = PropagationReport("example.test", "A", r1 + dead, strict=True)
    assert not rep3.ok


def test_bench(serve):
    s = serve(zone_handler({("example.test.", "A"): ["192.0.2.1"]}))
    res = bench([Target("x", "127.0.0.1")], ["example.test"], 5, opts(s.port))
    assert res[0].answered == 5 and res[0].loss_pct == 0 and res[0].stats["median"] is not None
    res = bench([Target("x", "127.0.0.1")], ["example.test"], 3, opts(s.port), uncached=True)
    assert res[0].answered == 3  # NXDOMAIN counts as answered


def test_wait_succeeds_after_change(serve):
    state = {"n": 0}
    base = zone_handler(A)
    new = zone_handler(B)

    def handler(q):
        state["n"] += 1
        return (base if state["n"] < 3 else new)(q)

    s = serve(handler)
    ok, _ = wait([Target("x", "127.0.0.1")], "example.test", "A", opts(s.port),
                 expected=["192.0.2.9"], interval=0.01, max_wait=5, sleep=lambda _: None)
    assert ok and state["n"] >= 3


def test_wait_timeout_and_absent(serve):
    s = serve(zone_handler(A))
    ok, _ = wait([Target("x", "127.0.0.1")], "example.test", "A", opts(s.port),
                 expected=["192.0.2.9"], interval=1, max_wait=2, sleep=lambda _: None)
    assert not ok
    ok, res = wait([Target("x", "127.0.0.1")], "gone.test", "A", opts(s.port),
                   absent=True, interval=1, max_wait=2, sleep=lambda _: None)
    assert ok


def test_trace_follows_referral(serve):
    calls = {"n": 0}
    ans = zone_handler(A)

    def handler(q):
        calls["n"] += 1
        if calls["n"] == 1:  # root: referral with glue
            r = dns.message.make_response(q)
            r.authority.append(dns.rrset.from_text("example.test.", 300, "IN", "NS", "ns1.example.test."))
            r.additional.append(dns.rrset.from_text("ns1.example.test.", 300, "IN", "A", "127.0.0.1"))
            return r
        return ans(q)

    s = serve(handler)
    res = trace("example.test", "A", opts(s.port), roots=[("fake-root", "127.0.0.1")])
    assert res.ok, res.error
    assert [h.outcome for h in res.hops] == ["referral", "answer"]
    assert res.final.values() == {"192.0.2.1"}


def test_trace_follows_cname(serve):
    calls = {"n": 0}

    def handler(q):
        calls["n"] += 1
        r = dns.message.make_response(q)
        qn = q.question[0].name.to_text()
        if qn == "www.example.test.":
            r.answer.append(dns.rrset.from_text(qn, 60, "IN", "CNAME", "host.example.test."))
        else:
            r.answer.append(dns.rrset.from_text(qn, 60, "IN", "A", "192.0.2.5"))
        return r

    s = serve(handler)
    res = trace("www.example.test", "A", opts(s.port), roots=[("fake", "127.0.0.1")])
    assert res.ok and [h.outcome for h in res.hops] == ["cname", "answer"]


def test_trace_lame(serve):
    s = serve(lambda q: None)  # never answers
    res = trace("example.test", "A", QueryOpts(timeout=0.2, retries=0, port=s.port),
                roots=[("dead", "127.0.0.1")])
    assert not res.ok and res.error


def test_satisfied_helper():
    assert satisfied([], None, False, False) == (0, 0)
