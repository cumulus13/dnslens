# File: dnslens/src/dnslens/sqlstore.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""SQLAlchemy (Core, 2.x) backend: config, blocklists and the query log in SQLite / PostgreSQL / MySQL / MariaDB."""
from __future__ import annotations

import json
import logging
import time
import zlib
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    BigInteger,
    Column,
    Float,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    case,
    create_engine,
    delete,
    desc,
    event,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError

from .querylog import FAILED_SOURCES, ROW_COLUMNS, BaseQueryLog, like_pattern
from .server import ConfigError

log = logging.getLogger("dnslens.sql")

SCHEMA_VERSION = 1
_BigPK = BigInteger().with_variant(Integer(), "sqlite")
_LongText = Text().with_variant(mysql.LONGTEXT(), "mysql").with_variant(mysql.LONGTEXT(), "mariadb")
_LongBlob = LargeBinary().with_variant(mysql.LONGBLOB(), "mysql").with_variant(mysql.LONGBLOB(), "mariadb")


def normalize_url(url: str) -> str:
    """Pick an installed driver when the URL names none (``postgresql://`` -> psycopg 3 / psycopg2)."""
    u = make_url(url)
    name = u.drivername
    if "+" in name:
        return url
    try:
        if name in ("postgres", "postgresql"):
            try:
                import psycopg2  # noqa: F401
                return url
            except ImportError:
                import psycopg  # noqa: F401
                return u.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)
        if name in ("mysql", "mariadb"):
            try:
                import MySQLdb  # noqa: F401
                return url
            except ImportError:
                import pymysql  # noqa: F401
                return u.set(drivername=f"{name}+pymysql").render_as_string(hide_password=False)
    except ImportError:
        raise ConfigError(f"no database driver installed for {name}: pip install 'dnslens[postgres]' or 'dnslens[mysql]'") from None
    return url


def mask_url(url: str) -> str:
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<database>"


class SqlBackend:
    """One engine plus the table definitions, shared by the config store and the query log."""

    def __init__(self, url: str) -> None:
        try:
            url = normalize_url(url)
            u = make_url(url)
            kw: Dict[str, Any] = {"pool_pre_ping": True}
            if u.get_backend_name() == "sqlite":
                kw["connect_args"] = {"check_same_thread": False, "timeout": 15}
            else:
                kw.update(pool_recycle=1800, pool_size=5, max_overflow=5)
            self.engine: Engine = create_engine(u, **kw)
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(f"invalid database URL: {e}") from e
        self.url = mask_url(url)
        self.dialect = self.engine.dialect.name
        if self.dialect == "sqlite":
            @event.listens_for(self.engine, "connect")
            def _pragmas(dbapi_con: Any, _rec: Any) -> None:
                cur = dbapi_con.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.close()
        self.meta = MetaData()
        self.queries = Table(
            "dnslens_queries", self.meta,
            Column("id", _BigPK, primary_key=True, autoincrement=True),
            Column("ts", Float, nullable=False), Column("ts_min", Integer, nullable=False),
            Column("client", String(64)), Column("qname", String(255)), Column("qtype", String(16)),
            Column("rcode", String(16)), Column("source", String(16)), Column("elapsed", Float),
            Column("upstream", String(255)), Column("rule", String(255)), Column("list_id", Integer),
            Column("answer", Text), Column("transport", String(8)),
            Index("ix_dnslens_q_ts", "ts"), Index("ix_dnslens_q_tsmin", "ts_min"),
            Index("ix_dnslens_q_name", "qname", mysql_length=191), Index("ix_dnslens_q_client", "client"),
        )
        self.config = Table("dnslens_config", self.meta, Column("name", String(64), primary_key=True),
                            Column("value", _LongText, nullable=False), Column("rev", BigInteger, nullable=False))
        self.lists = Table("dnslens_lists", self.meta, Column("id", Integer, primary_key=True, autoincrement=False),
                           Column("data", _LongBlob, nullable=False), Column("updated", Float))
        try:
            self.meta.create_all(self.engine)
        except SQLAlchemyError as e:
            raise ConfigError(f"cannot use database {self.url}: {getattr(e, 'orig', e)}") from e

    def close(self) -> None:
        self.engine.dispose()


class SqlStore:
    kind = "database"

    def __init__(self, backend: SqlBackend) -> None:
        self.b = backend

    def describe(self) -> str:
        return f"{self.b.dialect} database {self.b.url}"

    def load(self) -> Optional[Dict[str, Any]]:
        with self.b.engine.connect() as c:
            row = c.execute(select(self.b.config.c.value).where(self.b.config.c.name == "main")).first()
        if row is None:
            return None
        data = json.loads(row[0])
        if not isinstance(data, dict):
            raise ConfigError("stored configuration is not an object")
        return data

    def save(self, cfg: Dict[str, Any]) -> None:
        t, text = self.b.config, json.dumps(cfg)
        with self.b.engine.begin() as c:
            res = c.execute(update(t).where(t.c.name == "main").values(value=text, rev=t.c.rev + 1))
            if res.rowcount == 0:
                c.execute(insert(t).values(name="main", value=text, rev=1))

    def revision(self) -> int:
        try:
            with self.b.engine.connect() as c:
                row = c.execute(select(self.b.config.c.rev).where(self.b.config.c.name == "main")).first()
            return int(row[0]) if row else 0
        except SQLAlchemyError:
            return -1  # unreachable database: report a value that never matches, caller keeps current state

    def read_list(self, fid: int) -> Optional[str]:
        with self.b.engine.connect() as c:
            row = c.execute(select(self.b.lists.c.data).where(self.b.lists.c.id == fid)).first()
        return zlib.decompress(bytes(row[0])).decode("utf-8", errors="replace") if row else None

    def write_list(self, fid: int, text: str) -> None:
        t, blob = self.b.lists, zlib.compress(text.encode("utf-8"), 6)
        with self.b.engine.begin() as c:
            res = c.execute(update(t).where(t.c.id == fid).values(data=blob, updated=time.time()))
            if res.rowcount == 0:
                c.execute(insert(t).values(id=fid, data=blob, updated=time.time()))

    def remove_list(self, fid: int) -> None:
        with self.b.engine.begin() as c:
            c.execute(delete(self.b.lists).where(self.b.lists.c.id == fid))

    def close(self) -> None:
        pass  # the engine is owned by the backend and closed with the query log


class SqlQueryLog(BaseQueryLog):
    kind = "sqlalchemy"

    def __init__(self, backend: SqlBackend, retention_hours: int = 168, enabled: bool = True,
                 anonymize_clients: bool = False) -> None:
        super().__init__(retention_hours, enabled, anonymize_clients)
        self.b = backend
        self.t = backend.queries

    def describe(self) -> str:
        return f"{self.b.dialect} database {self.b.url}"

    def close(self) -> None:
        self.b.close()

    def _insert_rows(self, rows: List[tuple]) -> None:  # type: ignore[type-arg]
        with self.b.engine.begin() as c:
            c.execute(insert(self.t), [dict(zip(ROW_COLUMNS, r)) for r in rows])

    def _purge(self, cutoff: float) -> int:
        with self.b.engine.begin() as c:
            return int(c.execute(delete(self.t).where(self.t.c.ts < cutoff)).rowcount or 0)

    def _clear(self) -> None:
        with self.b.engine.begin() as c:
            c.execute(delete(self.t))

    def _count(self) -> int:
        with self.b.engine.connect() as c:
            return int(c.execute(select(func.count()).select_from(self.t)).scalar() or 0)

    def _raw_summary(self, since: float, ntop: int) -> Dict[str, Any]:
        t = self.t.c
        win = t.ts >= since
        one = lambda cond: func.sum(case((cond, 1), else_=0))  # noqa: E731
        cnt = func.count().label("c")
        with self.b.engine.connect() as c:
            def q(stmt: Any) -> List[Any]:
                return [tuple(r) for r in c.execute(stmt).all()]

            return {
                "totals": q(select(func.count(), one(t.source == "blocked"), one(t.source == "local"), one(t.source == "cache"),
                                   one(t.source == "upstream"), one(t.source.in_(FAILED_SOURCES)), func.avg(t.elapsed)).where(win))[0],
                "buckets": q(select(t.ts_min, t.source, func.count()).where(win).group_by(t.ts_min, t.source)),
                "top_domains": q(select(t.qname, cnt).where(win, t.source != "blocked").group_by(t.qname).order_by(desc("c")).limit(ntop)),
                "top_blocked": q(select(t.qname, cnt).where(win, t.source == "blocked").group_by(t.qname).order_by(desc("c")).limit(ntop)),
                "top_clients": q(select(t.client, cnt, one(t.source == "blocked")).where(win).group_by(t.client).order_by(desc("c")).limit(ntop)),
                "top_upstreams": q(select(t.upstream, cnt, func.avg(t.elapsed)).where(win, t.source == "upstream", t.upstream != "")
                                   .group_by(t.upstream).order_by(desc("c")).limit(ntop)),
                "qtypes": q(select(t.qtype, cnt).where(win).group_by(t.qtype).order_by(desc("c")).limit(8)),
                "rcodes": q(select(t.rcode, cnt).where(win).group_by(t.rcode).order_by(desc("c"))),
            }

    def _raw_search(self, limit: int, before: int, search: str, status: str, client: str) -> List[tuple]:  # type: ignore[type-arg]
        t = self.t.c
        conds: List[Any] = []
        if before:
            conds.append(t.id < before)
        if status == "blocked":
            conds.append(t.source == "blocked")
        elif status == "allowed":
            conds.append(t.source != "blocked")
        elif status == "cached":
            conds.append(t.source == "cache")
        elif status in ("local", "upstream"):
            conds.append(t.source == status)
        elif status == "failed":
            conds.append(t.source.in_(FAILED_SOURCES))
        if search:
            like = like_pattern(search)
            conds.append(func.lower(t.qname).like(like, escape="\\") | func.lower(t.client).like(like, escape="\\")
                         | func.lower(t.answer).like(like, escape="\\"))
        if client:
            conds.append(t.client == client)
        stmt = select(t.id, t.ts, t.client, t.qname, t.qtype, t.rcode, t.source, t.elapsed, t.upstream, t.rule,
                      t.list_id, t.answer, t.transport).where(*conds).order_by(desc(t.id)).limit(limit)
        with self.b.engine.connect() as c:
            return [tuple(r) for r in c.execute(stmt).all()]

    def iter_rows(self, batch: int = 5000):  # type: ignore[no-untyped-def]
        last = 0
        t = self.t.c
        while True:
            stmt = select(t.id, *(getattr(t, n) for n in ROW_COLUMNS)).where(t.id > last).order_by(t.id).limit(batch)
            with self.b.engine.connect() as c:
                rows = [tuple(r) for r in c.execute(stmt).all()]
            if not rows:
                return
            last = rows[-1][0]
            yield [r[1:] for r in rows]

    def insert_rows(self, rows: List[tuple]) -> None:  # type: ignore[type-arg]
        """Bulk insert already-shaped rows (used by migrations)."""
        self._insert_rows(rows)
