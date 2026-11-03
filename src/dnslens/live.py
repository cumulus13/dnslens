# File: dnslens/src/dnslens/live.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Real-time feed for the dashboard: per-second aggregates plus a small sample of recent queries.

The DNS path only increments a few counters (cheap, constant cost); a ticker thread turns them into one
message per second, so load on the browser and the network is independent of the query rate."""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List

from .querylog import FAILED_SOURCES
from .server import QueryEvent

HISTORY = 300  # seconds of per-second history kept in memory
SAMPLE = 15  # max individual queries shown per second


def _event_dict(e: QueryEvent) -> Dict[str, Any]:
    return {"ts": round(e.ts, 2), "name": e.qname, "type": e.qtype, "rcode": e.rcode, "source": e.source,
            "client": e.client, "ms": round(e.elapsed_ms, 2), "answer": e.answers[0] if e.answers else "",
            "upstream": e.upstream, "rule": e.rule}


def _fresh() -> Dict[str, float]:
    return {"total": 0, "blocked": 0, "resolved": 0, "failed": 0, "cache": 0, "local": 0, "ms": 0.0}


class LiveHub:
    def __init__(self, sample: int = SAMPLE) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition()
        self._counts = _fresh()
        self._events: Deque[Dict[str, Any]] = deque(maxlen=sample)
        self.ticks: Deque[Dict[str, Any]] = deque(maxlen=HISTORY)
        self.recent: Deque[Dict[str, Any]] = deque(maxlen=60)
        self.seq = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="dnslens-live", daemon=True)

    # ---- producer side ----
    def record(self, ev: QueryEvent) -> None:
        cat = "blocked" if ev.source == "blocked" else "failed" if ev.source in FAILED_SOURCES else "resolved"
        with self._lock:
            c = self._counts
            c["total"] += 1
            c[cat] += 1
            c["ms"] += ev.elapsed_ms
            if ev.source == "cache":
                c["cache"] += 1
            elif ev.source == "local":
                c["local"] += 1
            self._events.append(_event_dict(ev))

    def tick(self) -> Dict[str, Any]:
        with self._lock:
            c, ev = self._counts, list(self._events)
            self._counts = _fresh()
            self._events.clear()
        total = int(c["total"])
        t: Dict[str, Any] = {"ts": int(time.time()), "total": total, "blocked": int(c["blocked"]),
                             "resolved": int(c["resolved"]), "failed": int(c["failed"]), "cache": int(c["cache"]),
                             "local": int(c["local"]), "avg_ms": round(c["ms"] / total, 2) if total else 0.0,
                             "events": ev}
        with self._cond:
            self.seq += 1
            t["seq"] = self.seq
            self.ticks.append(t)
            self.recent.extend(ev)
            self._cond.notify_all()
        return t

    def _run(self) -> None:
        nxt = time.monotonic() + 1.0
        while not self._stop.wait(max(0.0, nxt - time.monotonic())):
            self.tick()
            nxt += 1.0
            if nxt < time.monotonic():  # fell behind (suspend, heavy load): do not burst
                nxt = time.monotonic() + 1.0

    def start(self) -> LiveHub:
        if not self._thread.is_alive():
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
        if self._thread.is_alive():
            self._thread.join(2)

    # ---- consumer side ----
    def snapshot(self, n: int = 120) -> Dict[str, Any]:
        """History for a new viewer: ticks without their event lists, plus the latest individual queries."""
        with self._cond:
            ticks = [{k: v for k, v in t.items() if k != "events"} for t in list(self.ticks)[-n:]]
            return {"seq": self.seq, "ticks": ticks, "events": list(self.recent)[-30:]}

    def since(self, seq: int, limit: int = 120) -> List[Dict[str, Any]]:
        with self._cond:
            return [t for t in list(self.ticks)[-limit:] if t["seq"] > seq]

    def wait(self, seq: int, timeout: float) -> List[Dict[str, Any]]:
        with self._cond:
            if self.seq <= seq:
                self._cond.wait(timeout)
            return [t for t in self.ticks if t["seq"] > seq]
