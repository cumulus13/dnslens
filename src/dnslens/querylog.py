"""Query log and statistics, stored in SQLite (standard library, works on every platform)."""
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

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, client TEXT, qname TEXT, qtype TEXT, rcode TEXT, source TEXT,
  elapsed REAL, upstream TEXT, rule TEXT, list_id INTEGER, answer TEXT, transport TEXT);
CREATE INDEX IF NOT EXISTS idx_q_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_q_name ON queries(qname);
CREATE INDEX IF NOT EXISTS idx_q_client ON queries(client);
"""

_STATUS_SQL = {
    "all": "",
    "blocked": " AND source='blocked'",
    "allowed": " AND source!='blocked'",
    "local": " AND source='local'",
    "cached": " AND source='cache'",
    "upstream": " AND source='upstream'",
    "failed": " AND source IN ('servfail','error','refused')",
}


def anonymize(ip: str) -> str:
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::"
    p = ip.split(".")
    return ".".join(p[:3] + ["0"]) if len(p) == 4 else ip


class QueryLog:
    def __init__(self, path: str, retention_hours: int = 168, enabled: bool = True, anonymize_clients: bool = False) -> None:
        self.path = path
        self.retention_hours = retention_hours
        self.enabled = enabled
        self.anonymize_clients = anonymize_clients
        self.dropped = 0
        self._q: queue.Queue[Any] = queue.Queue(maxsize=50000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="dnslens-querylog", daemon=True)
        con = self._connect()
        con.executescript(SCHEMA)
        con.close()

    # ---- plumbing ----
    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def start(self) -> QueryLog:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        self._thread.join(5)

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

    def _insert(self, con: sqlite3.Connection, batch: List[QueryEvent]) -> None:
        rows = [
            (e.ts, anonymize(e.client) if self.anonymize_clients else e.client, e.qname, e.qtype, e.rcode, e.source,
             e.elapsed_ms, e.upstream, e.rule, e.list_id, json.dumps(e.answers) if e.answers else "", e.transport)
            for e in batch
        ]
        con.executemany(
            "INSERT INTO queries(ts,client,qname,qtype,rcode,source,elapsed,upstream,rule,list_id,answer,transport)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()

    def _run(self) -> None:
        con = self._connect()
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
                    self._write(con, batch)
                    batch = []
                item.set()
            now = time.monotonic()
            if batch and (len(batch) >= 500 or now - last_flush >= 1.0 or done):
                self._write(con, batch)
                batch, last_flush = [], now
            if now - last_purge > 600:
                self.purge(con)
                last_purge = now
            if done:
                break
        con.close()

    def _write(self, con: sqlite3.Connection, batch: List[QueryEvent]) -> None:
        try:
            self._insert(con, batch)
        except sqlite3.Error:
            log.exception("could not write query log")

    def purge(self, con: Optional[sqlite3.Connection] = None) -> int:
        own = con is None
        con = con or self._connect()
        try:
            cur = con.execute("DELETE FROM queries WHERE ts < ?", (time.time() - self.retention_hours * 3600,))
            con.commit()
            return cur.rowcount
        finally:
            if own:
                con.close()

    def clear(self) -> None:
        con = self._connect()
        try:
            con.execute("DELETE FROM queries")
            con.commit()
            con.execute("VACUUM")
        finally:
            con.close()

    # ---- reading ----
    def _read(self, sql: str, args: tuple = ()) -> List[tuple]:  # type: ignore[type-arg]
        con = self._connect()
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def summary(self, window: str = "24h", top: int = 10) -> Dict[str, Any]:
        seconds = WINDOWS.get(window, WINDOWS["24h"])
        now = time.time()
        since = now - seconds
        con = self._connect()
        try:
            q = lambda sql, *a: con.execute(sql, a).fetchall()  # noqa: E731
            tot = q("SELECT COUNT(*), COALESCE(SUM(source='blocked'),0), COALESCE(SUM(source='local'),0),"
                    " COALESCE(SUM(source='cache'),0), COALESCE(SUM(source='upstream'),0),"
                    " COALESCE(SUM(source IN ('servfail','error','refused')),0), AVG(elapsed)"
                    " FROM queries WHERE ts>=?", since)[0]
            bucket = max(60, seconds // 48)
            nb = int(seconds // bucket) + 1
            series: Dict[str, List[int]] = {k: [0] * nb for k in ("total", "blocked", "resolved", "failed")}
            for b, src, n in q("SELECT CAST((ts-?)/? AS INTEGER), source, COUNT(*) FROM queries WHERE ts>=?"
                               " GROUP BY 1,2", since, bucket, since):
                if 0 <= b < nb:
                    series["total"][b] += n
                    key = "blocked" if src == "blocked" else "failed" if src in ("servfail", "error", "refused") else "resolved"
                    series[key][b] += n
            ntop = max(1, min(top, 50))
            top_domains = q("SELECT qname, COUNT(*) c FROM queries WHERE ts>=? AND source!='blocked'"
                            " GROUP BY qname ORDER BY c DESC LIMIT ?", since, ntop)
            top_blocked = q("SELECT qname, COUNT(*) c FROM queries WHERE ts>=? AND source='blocked'"
                            " GROUP BY qname ORDER BY c DESC LIMIT ?", since, ntop)
            top_clients = q("SELECT client, COUNT(*) c, COALESCE(SUM(source='blocked'),0) FROM queries WHERE ts>=?"
                            " GROUP BY client ORDER BY c DESC LIMIT ?", since, ntop)
            top_upstreams = q("SELECT upstream, COUNT(*) c, AVG(elapsed) FROM queries WHERE ts>=? AND source='upstream'"
                              " AND upstream!='' GROUP BY upstream ORDER BY c DESC LIMIT ?", since, ntop)
            qtypes = q("SELECT qtype, COUNT(*) c FROM queries WHERE ts>=? GROUP BY qtype ORDER BY c DESC LIMIT 8", since)
            rcodes = q("SELECT rcode, COUNT(*) c FROM queries WHERE ts>=? GROUP BY rcode ORDER BY c DESC", since)
        finally:
            con.close()
        total = tot[0]
        return {
            "window": window if window in WINDOWS else "24h",
            "since": since, "until": now,
            "totals": {"queries": total, "blocked": tot[1], "local": tot[2], "cache": tot[3], "upstream": tot[4],
                       "failed": tot[5], "avg_ms": round(tot[6], 2) if tot[6] is not None else 0.0,
                       "blocked_pct": round(100 * tot[1] / total, 1) if total else 0.0,
                       "cache_pct": round(100 * tot[3] / total, 1) if total else 0.0},
            "series": {"bucket_seconds": bucket, "start": since, **series},
            "top_domains": [{"name": n, "count": c} for n, c in top_domains],
            "top_blocked": [{"name": n, "count": c} for n, c in top_blocked],
            "top_clients": [{"name": n, "count": c, "blocked": b} for n, c, b in top_clients],
            "top_upstreams": [{"name": n, "count": c, "avg_ms": round(a or 0, 1)} for n, c, a in top_upstreams],
            "query_types": [{"name": n, "count": c} for n, c in qtypes],
            "rcodes": [{"name": n, "count": c} for n, c in rcodes],
            "dropped": self.dropped,
        }

    def search(self, limit: int = 100, before: int = 0, search: str = "", status: str = "all",
               client: str = "") -> Dict[str, Any]:
        limit = max(1, min(limit, 500))
        where = "WHERE 1=1"
        args: List[Any] = []
        if before:
            where += " AND id<?"
            args.append(before)
        where += _STATUS_SQL.get(status, "")
        if search:
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where += " AND (qname LIKE ? ESCAPE '\\' OR client LIKE ? ESCAPE '\\' OR answer LIKE ? ESCAPE '\\')"
            args += [like, like, like]
        if client:
            where += " AND client=?"
            args.append(client)
        rows = self._read(
            "SELECT id,ts,client,qname,qtype,rcode,source,elapsed,upstream,rule,list_id,answer,transport"
            f" FROM queries {where} ORDER BY id DESC LIMIT ?", (*args, limit + 1))
        more = len(rows) > limit
        rows = rows[:limit]
        items = [{"id": r[0], "ts": r[1], "client": r[2], "name": r[3], "type": r[4], "rcode": r[5], "source": r[6],
                  "elapsed_ms": round(r[7] or 0, 2), "upstream": r[8], "rule": r[9], "list_id": r[10],
                  "answers": json.loads(r[11]) if r[11] else [], "transport": r[12]} for r in rows]
        return {"items": items, "next": items[-1]["id"] if more and items else None}

    def count(self) -> int:
        return int(self._read("SELECT COUNT(*) FROM queries")[0][0])
