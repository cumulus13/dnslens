# File: dnslens/tests/test_live.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

import http.client
import json
import threading
import time

from helpers import Client

from dnslens.live import LiveHub
from dnslens.server import QueryEvent


def ev(source="upstream", name="a.test", ms=2.0):
    return QueryEvent(time.time(), "10.0.0.1", name, "A", "NOERROR", source, ms, answers=["A 1.2.3.4"])


def test_hub_aggregates_per_tick():
    hub = LiveHub(sample=3)
    for _ in range(4):
        hub.record(ev("upstream", ms=10))
    hub.record(ev("blocked", "ads.test", ms=0))
    hub.record(ev("cache"))
    hub.record(ev("servfail"))
    hub.record(ev("local"))
    t = hub.tick()
    assert (t["total"], t["blocked"], t["resolved"], t["failed"], t["cache"], t["local"]) == (8, 1, 6, 1, 1, 1)
    assert t["avg_ms"] > 0 and len(t["events"]) == 3 and t["events"][-1]["source"] == "local"  # only a sample is kept
    assert hub.tick()["total"] == 0  # counters reset every tick
    snap = hub.snapshot()
    assert snap["seq"] == 2 and all("events" not in x for x in snap["ticks"]) and len(snap["events"]) == 3
    assert [x["seq"] for x in hub.since(1)] == [2] and hub.since(2) == []


def test_hub_thread_ticks_and_wakes_waiters():
    hub = LiveHub().start()
    try:
        got = []
        threading.Thread(target=lambda: got.extend(hub.wait(0, 3.0))).start()
        hub.record(ev())
        deadline = time.time() + 4
        while not got and time.time() < deadline:
            time.sleep(0.05)
        assert got and got[0]["seq"] >= 1
    finally:
        hub.stop()


def session_cookie(client):
    return next(c.value for c in client.jar if c.name == "dnslens_session")


def read_events(resp, want, timeout=8.0):
    """Collect SSE frames until ``want(events)`` is true."""
    events, event, deadline = [], None, time.time() + timeout
    while time.time() < deadline:
        line = resp.readline().decode().rstrip("\n")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            events.append((event, json.loads(line[5:])))
            if want(events):
                return events
    raise AssertionError(f"did not get the expected events: {events[-3:]}")


def open_stream(stack, cookie):
    conn = http.client.HTTPConnection("127.0.0.1", stack.web.port, timeout=10)
    conn.request("GET", "/api/live", headers={"Cookie": f"dnslens_session={cookie}"})
    return conn, conn.getresponse()


def test_sse_stream_delivers_hello_and_ticks(stack):
    conn, resp = open_stream(stack, session_cookie(stack.client))
    try:
        assert resp.status == 200 and resp.getheader("Content-Type").startswith("text/event-stream")
        assert resp.getheader("X-Accel-Buffering") == "no" and resp.getheader("Cache-Control") == "no-cache"
        hello = read_events(resp, lambda e: e[-1][0] == "hello")[-1][1]
        assert "seq" in hello and isinstance(hello["ticks"], list)
        for i in range(12):  # traffic while the stream is open
            stack.ask("example.test")
            stack.ask(f"nope{i}.test")
        events = read_events(resp, lambda e: sum(d["total"] for k, d in e if k == "tick") >= 24, timeout=10)
        ticks = [d for k, d in events if k == "tick"]
        assert sum(t["total"] for t in ticks) >= 24 and all(t["seq"] > hello["seq"] for t in ticks)
        sample = [e for t in ticks for e in t["events"]]
        assert {"name", "type", "source", "client", "ms"} <= set(sample[0]) and any(e["name"] == "example.test" for e in sample)
        assert stack.web._live_clients == 1
    finally:
        resp.close()  # with 'Connection: close' the response owns the socket
        conn.close()
    deadline = time.time() + 5
    while stack.web._live_clients and time.time() < deadline:  # server notices the disconnect
        time.sleep(0.1)
    assert stack.web._live_clients == 0


def test_sse_requires_auth_and_is_limited(stack):
    anon = Client(stack.client.base)
    assert anon.call("GET", "/api/live")[0] == 401 and anon.call("GET", "/api/live/poll")[0] == 401
    stack.web._live_clients = 20
    assert stack.client.call("GET", "/api/live")[0] == 503
    stack.web._live_clients = 0


def test_sse_ends_when_session_is_dropped(stack):
    other = Client(stack.client.base)
    other.login()
    conn, resp = open_stream(stack, session_cookie(other))
    try:
        read_events(resp, lambda e: e[-1][0] == "hello")
        stack.web.drop_session(session_cookie(other))
        events = read_events(resp, lambda e: e[-1][0] == "bye", timeout=6)
        assert events[-1][1]["reason"] == "session expired"
    finally:
        resp.close()
        conn.close()


def test_poll_endpoint_for_proxies_that_buffer(stack):
    c = stack.client
    while stack.mgr.live.seq < 1:  # wait for the first one-second tick
        time.sleep(0.1)
    first = c.call("GET", "/api/live/poll")[1]
    assert first["hello"] is True and "ticks" in first and "events" in first
    stack.ask("example.test")
    time.sleep(2.2)
    r = c.call("GET", f"/api/live/poll?since={first['seq']}")[1]
    assert r["hello"] is False and r["seq"] > first["seq"] and sum(t["total"] for t in r["ticks"]) >= 1
    assert all(t["seq"] > first["seq"] for t in r["ticks"])
    assert c.call("GET", "/api/live/poll?since=99999999")[1]["hello"] is True  # server restarted: resync
    assert c.call("GET", "/api/live/poll?since=abc")[0] == 400
