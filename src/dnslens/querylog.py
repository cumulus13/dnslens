# File: dnslens/src/dnslens/querylog.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Query log and statistics. ``QueryLog`` uses SQLite from the standard library (default);
``sqlstore.SqlQueryLog`` offers the same API on any SQLAlchemy database."""
from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from .server import QueryEvent

log = logging.getLogger("dnslens.querylog")

WINDOWS = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
RETENTION_HOURS = (1, 6, 24, 168, 720, 2160)
STATUSES = ("all", "blocked", "allowed", "local", "cached", "upstream", "failed")
FAILED_SOURCES = ("servfail", "error", "refused")

# column order of one stored row
ROW_COLUMNS = ("ts", "ts_min", "client", "qname", "qtype", "rcode", "source", "elapsed", "upstream",
               "rule", "list_id", "answer", "transport")

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, ts_min INTEGER, client TEXT, qname TEXT, qtype TEXT, rcode TEXT, source TEXT,
  elapsed REAL, upstream TEXT, rule TEXT, list_id INTEGER, answer TEXT, transport TEXT);
CREATE INDEX IF NOT EXISTS idx_q_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_q_name ON queries(qname);
CREATE INDEX IF NOT EXISTS idx_q_client ON queries(client);
"""


def anonymize(ip: str) -> str:
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::"
    p = ip.split(".")
    return ".".join(p[:3] + ["0"]) if len(p) == 4 else ip


def like_pattern(text: str) -> str:
    """Lower-cased LIKE pattern with ``\\`` as the escape character."""
    return "%" + text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class BaseQueryLog:
    """Batching writer + result shaping. Subclasses implement the database access."""

    kind = "base"

    def __init__(self, retention_hours: int = 168, enabled: bool = True, anonymize_clients: bool = False) -> None:
        self.retention_hours = retention_hours
        self.enabled = enabled
        self.anonymize_clients = anonymize_clients
        self.dropped = 0
        self._q: queue.Queue[Any] = queue.Queue(maxsize=50000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="dnslens-querylog", daemon=True)

    # ---- to implement ----
    def _insert_rows(self, rows: List[tuple]) -> None:  # type: ignore[type-arg]
        raise NotImplementedError

    def _purge(self, cutoff: float) -> int:
        raise NotImplementedError

    def _clear(self) -> None:
        raise NotImplementedError

    def _count(self) -> int:
        raise NotImplementedError

    def _raw_summary(self, since: float, ntop: int) -> Dict[str, Any]:
        raise NotImplementedError

    def _raw_search(self, limit: int, before: int, search: str, status: str, client: str) -> List[tuple]:  # type: ignore[type-arg]
        raise NotImplementedError

    def describe(self) -> str:
        return self.kind

    def close(self) -> None:
        pass

    # ---- writing ----
    def start(self) -> BaseQueryLog:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        if self._thread.is_alive():
            self._thread.join(5)
        self.close()

    def flush(self, timeout: float = 5.0) -> None:
        ev = threading.Event()
        self._q.put(ev)
        ev.wait(timeout)

    def record(self, ev: QueryEvent) -> None:
        """Observer callback: never blocks the DNS path."""
        if not self.enabled:
            return
        try:
            self._q.put_nowait(ev)
        except queue.Full:
            self.dropped += 1

    def _to_row(self, e: QueryEvent) -> tuple:  # type: ignore[type-arg]
        return (e.ts, int(e.ts // 60), anonymize(e.client) if self.anonymize_clients else e.client, e.qname, e.qtype,
                e.rcode, e.source, e.elapsed_ms, e.upstream, e.rule, e.list_id,
                json.dumps(e.answers) if e.answers else "", e.transport)

    def _write(self, batch: List[QueryEvent]) -> None:
        try:
            self._insert_rows([self._to_row(e) for e in batch])
        except Exception:
            log.exception("could not write query log")

    def _run(self) -> None:
        batch: List[QueryEvent] = []
        last_flush = last_purge = time.monotonic()
        while True:
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                item = "tick"
            done = False
            if item is None:
                done = True
            elif isinstance(item, QueryEvent):
                batch.append(item)
            elif isinstance(item, threading.Event):
                if batch:
                    self._write(batch)
                    batch = []
                item.set()
            now = time.monotonic()
            if batch and (len(batch) >= 500 or now - last_flush >= 1.0 or done):
                self._write(batch)
                batch, last_flush = [], now
            if now - last_purge > 600:
                try:
                    self.purge()
                except Exception:
                    log.exception("purge failed")
                last_purge = now
            if done:
                break

    def purge(self) -> int:
        return self._purge(time.time() - self.retention_hours * 3600)

    def clear(self) -> None:
        self._clear()

    def count(self) -> int:
        return self._count()

    # ---- reading ----
    def summary(self, window: str = "24h", top: int = 10) -> Dict[str, Any]:
        seconds = WINDOWS.get(window, WINDOWS["24h"])
        now = time.time()
        since = now - seconds
        raw = self._raw_summary(since, max(1, min(top, 50)))
        tot = raw["totals"]
        total = int(tot[0] or 0)
        blocked, local, cache, upstream, failed = (int(x or 0) for x in tot[1:6])
        avg = float(tot[6]) if tot[6] is not None else 0.0
        bucket = max(60, seconds // 48)
        nb = int(seconds // bucket) + 1
        series: Dict[str, List[int]] = {k: [0] * nb for k in ("total", "blocked", "resolved", "failed")}
        for ts_min, src, n in raw["buckets"]:
            b = max(0, int((int(ts_min) * 60 - since) // bucket))
            if b >= nb:
                continue
            series["total"][b] += int(n)
            key = "blocked" if src == "blocked" else "failed" if src in FAILED_SOURCES else "resolved"
            series[key][b] += int(n)
        return {
            "window": window if window in WINDOWS else "24h", "since": since, "until": now,
            "totals": {"queries": total, "blocked": blocked, "local": local, "cache": cache, "upstream": upstream,
                       "failed": failed, "avg_ms": round(avg, 2),
                       "blocked_pct": round(100 * blocked / total, 1) if total else 0.0,
                       "cache_pct": round(100 * cache / total, 1) if total else 0.0},
            "series": {"bucket_seconds": bucket, "start": since, **series},
            "top_domains": [{"name": n, "count": int(c)} for n, c in raw["top_domains"]],
            "top_blocked": [{"name": n, "count": int(c)} for n, c in raw["top_blocked"]],
            "top_clients": [{"name": n, "count": int(c), "blocked": int(b or 0)} for n, c, b in raw["top_clients"]],
            "top_upstreams": [{"name": n, "count": int(c), "avg_ms": round(float(a or 0), 1)} for n, c, a in raw["top_upstreams"]],
            "query_types": [{"name": n, "count": int(c)} for n, c in raw["qtypes"]],
            "rcodes": [{"name": n, "count": int(c)} for n, c in raw["rcodes"]],
            "dropped": self.dropped,
        }

    def search(self, limit: int = 100, before: int = 0, search: str = "", status: str = "all",
               client: str = "") -> Dict[str, Any]:
        limit = max(1, min(limit, 500))
        rows = self._raw_search(limit + 1, before, search, status if status in STATUSES else "all", client)
        more = len(rows) > limit
        rows = rows[:limit]
        items = [{"id": r[0], "ts": r[1], "client": r[2], "name": r[3], "type": r[4], "rcode": r[5], "source": r[6],
                  "elapsed_ms": round(r[7] or 0, 2), "upstream": r[8], "rule": r[9], "list_id": r[10],
                  "answers": json.loads(r[11]) if r[11] else [], "transport": r[12]} for r in rows]
        return {"items": items, "next": items[-1]["id"] if more and items else None}

    def iter_rows(self, batch: int = 5000):  # type: ignore[no-untyped-def]
        """Oldest-first batches of raw rows (ROW_COLUMNS order) for migrations."""
        raise NotImplementedError


_STATUS_SQL = {
    "all": "", "blocked": " AND source='blocked'", "allowed": " AND source!='blocked'", "local": " AND source='local'",
    "cached": " AND source='cache'", "upstream": " AND source='upstream'",
    "failed": " AND source IN ('servfail','error','refused')",
}


class QueryLog(BaseQueryLog):
    """SQLite file (standard library only)."""

    kind = "sqlite3"

    def __init__(self, path: str, retention_hours: int = 168, enabled: bool = True, anonymize_clients: bool = False) -> None:
        super().__init__(retention_hours, enabled, anonymize_clients)
        self.path = path
        con = self._connect()
        con.executescript(SCHEMA)
        cols = {r[1] for r in con.execute("PRAGMA table_info(queries)")}
        if "ts_min" not in cols:  # database created by dnslens 1.2.x
            con.execute("ALTER TABLE queries ADD COLUMN ts_min INTEGER")
            con.execute("UPDATE queries SET ts_min = CAST(ts/60 AS INTEGER) WHERE ts_min IS NULL")
        con.execute("CREATE INDEX IF NOT EXISTS idx_q_tsmin ON queries(ts_min)")
        con.commit()
        con.close()
        self._wcon: Optional[sqlite3.Connection] = None

    def describe(self) -> str:
        return f"SQLite file {self.path}"

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def _insert_rows(self, rows: List[tuple]) -> None:  # type: ignore[type-arg]
        if self._wcon is None:
            self._wcon = self._connect()
        self._wcon.executemany(
            "INSERT INTO queries(ts,ts_min,client,qname,qtype,rcode,source,elapsed,upstream,rule,list_id,answer,transport)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self._wcon.commit()

    def close(self) -> None:
        if self._wcon is not None:
            self._wcon.close()
            self._wcon = None

    def _read(self, sql: str, args: tuple = ()) -> List[tuple]:  # type: ignore[type-arg]
        con = self._connect()
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def _purge(self, cutoff: float) -> int:
        con = self._connect()
        try:
            cur = con.execute("DELETE FROM queries WHERE ts < ?", (cutoff,))
            con.commit()
            return cur.rowcount
        finally:
            con.close()

    def _clear(self) -> None:
        con = self._connect()
        try:
            con.execute("DELETE FROM queries")
            con.commit()
            con.execute("VACUUM")
        finally:
            con.close()

    def _count(self) -> int:
        return int(self._read("SELECT COUNT(*) FROM queries")[0][0])

    def _raw_summary(self, since: float, ntop: int) -> Dict[str, Any]:
        con = self._connect()
        try:
            q = lambda sql, *a: con.execute(sql, a).fetchall()  # noqa: E731
            return {
                "totals": q("SELECT COUNT(*), COALESCE(SUM(source='blocked'),0), COALESCE(SUM(source='local'),0),"
                            " COALESCE(SUM(source='cache'),0), COALESCE(SUM(source='upstream'),0),"
                            " COALESCE(SUM(source IN ('servfail','error','refused')),0), AVG(elapsed)"
                            " FROM queries WHERE ts>=?", since)[0],
                "buckets": q("SELECT ts_min, source, COUNT(*) FROM queries WHERE ts>=? GROUP BY ts_min, source", since),
                "top_domains": q("SELECT qname, COUNT(*) c FROM queries WHERE ts>=? AND source!='blocked'"
                                 " GROUP BY qname ORDER BY c DESC LIMIT ?", since, ntop),
                "top_blocked": q("SELECT qname, COUNT(*) c FROM queries WHERE ts>=? AND source='blocked'"
                                 " GROUP BY qname ORDER BY c DESC LIMIT ?", since, ntop),
                "top_clients": q("SELECT client, COUNT(*) c, COALESCE(SUM(source='blocked'),0) FROM queries WHERE ts>=?"
                                 " GROUP BY client ORDER BY c DESC LIMIT ?", since, ntop),
                "top_upstreams": q("SELECT upstream, COUNT(*) c, AVG(elapsed) FROM queries WHERE ts>=? AND source='upstream'"
                                   " AND upstream!='' GROUP BY upstream ORDER BY c DESC LIMIT ?", since, ntop),
                "qtypes": q("SELECT qtype, COUNT(*) c FROM queries WHERE ts>=? GROUP BY qtype ORDER BY c DESC LIMIT 8", since),
                "rcodes": q("SELECT rcode, COUNT(*) c FROM queries WHERE ts>=? GROUP BY rcode ORDER BY c DESC", since),
            }
        finally:
            con.close()

    def _raw_search(self, limit: int, before: int, search: str, status: str, client: str) -> List[tuple]:  # type: ignore[type-arg]
        where = "WHERE 1=1"
        args: List[Any] = []
        if before:
            where += " AND id<?"
            args.append(before)
        where += _STATUS_SQL[status]
        if search:
            like = like_pattern(search)
            where += (" AND (LOWER(qname) LIKE ? ESCAPE '\\' OR LOWER(client) LIKE ? ESCAPE '\\'"
                      " OR LOWER(answer) LIKE ? ESCAPE '\\')")
            args += [like, like, like]
        if client:
            where += " AND client=?"
            args.append(client)
        return self._read("SELECT id,ts,client,qname,qtype,rcode,source,elapsed,upstream,rule,list_id,answer,transport"
                          f" FROM queries {where} ORDER BY id DESC LIMIT ?", (*args, limit))

    def iter_rows(self, batch: int = 5000):  # type: ignore[no-untyped-def]
        last = 0
        while True:
            rows = self._read("SELECT id,ts,ts_min,client,qname,qtype,rcode,source,elapsed,upstream,rule,list_id,answer,transport"
                              " FROM queries WHERE id>? ORDER BY id LIMIT ?", (last, batch))
            if not rows:
                return
            last = rows[-1][0]
            yield [r[1:] for r in rows]
