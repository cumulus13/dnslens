# File: dnslens/tests/test_sql.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:19 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Database backends. SQLite always runs; set DNSLENS_TEST_PG / DNSLENS_TEST_MYSQL to also run on real servers."""
import os
import time

import dns.message
import dns.rcode
import pytest

pytest.importorskip("sqlalchemy")

from conftest import zone_handler  # noqa: E402
from helpers import LIST, ListServer  # noqa: E402

from dnslens.cli import main  # noqa: E402
from dnslens.manage import Manager  # noqa: E402
from dnslens.migrate import migrate_files_to_db  # noqa: E402
from dnslens.querylog import QueryLog  # noqa: E402
from dnslens.server import ConfigError, DNSHandler, QueryEvent, ServerOptions, ZoneData  # noqa: E402
from dnslens.sqlstore import SqlBackend, SqlQueryLog, SqlStore, mask_url, normalize_url  # noqa: E402
from dnslens.storage import FileStore, open_database  # noqa: E402

PARAMS = ["sqlite"]
if os.environ.get("DNSLENS_TEST_PG"):
    PARAMS.append("postgres")
if os.environ.get("DNSLENS_TEST_MYSQL"):
    PARAMS.append("mysql")


@pytest.fixture(params=PARAMS)
def db_url(request, tmp_path):
    url = {"sqlite": f"sqlite:///{tmp_path / 'dnslens.db'}", "postgres": os.environ.get("DNSLENS_TEST_PG"),
           "mysql": os.environ.get("DNSLENS_TEST_MYSQL")}[request.param]
    b = SqlBackend(url)
    b.meta.drop_all(b.engine)
    b.close()
    yield url
    b = SqlBackend(url)
    b.meta.drop_all(b.engine)
    b.close()


def ev(ts, name, source="upstream", client="10.0.0.9", qtype="A", rcode="NOERROR", **kw):
    return QueryEvent(ts, client, name, qtype, rcode, source, kw.pop("ms", 5.0), **kw)


def ask(handler, name, qtype="A"):
    wire = dns.message.make_query(name, qtype).to_wire()
    return dns.message.from_wire(handler.respond(wire, "127.0.0.1"))


# ------------------------------------------------------------ query log ---

def test_sql_querylog_behaves_like_sqlite(db_url, tmp_path):
    ql = SqlQueryLog(SqlBackend(db_url), retention_hours=1, anonymize_clients=True).start()
    now = time.time()
    ql.record(ev(now, "a.test", upstream="1.1.1.1", answers=["A 1.2.3.4"], ms=10))
    ql.record(ev(now, "b.test", "blocked", qtype="AAAA", rcode="NXDOMAIN", rule="b.test", list_id=3, ms=0.1))
    ql.record(ev(now, "Mixed_Case.test", "cache"))
    ql.record(ev(now, "dead.test", "servfail", rcode="SERVFAIL"))
    ql.record(ev(now - 7200, "old.test", "cache"))
    ql.flush()
    assert ql.count() == 5
    s = ql.summary("24h")
    t = s["totals"]
    assert (t["queries"], t["blocked"], t["cache"], t["upstream"], t["failed"]) == (5, 1, 2, 1, 1)
    assert t["blocked_pct"] == 20.0 and t["avg_ms"] > 0
    assert s["top_clients"][0] == {"name": "10.0.0.0", "count": 5, "blocked": 1}  # anonymized
    assert s["top_blocked"][0]["name"] == "b.test" and s["top_upstreams"][0]["name"] == "1.1.1.1"
    assert {x["name"] for x in s["query_types"]} == {"A", "AAAA"} and {x["name"] for x in s["rcodes"]} >= {"NOERROR", "NXDOMAIN"}
    ser = s["series"]
    assert sum(ser["total"]) == 5 and sum(ser["blocked"]) == 1 and sum(ser["failed"]) == 1 and sum(ser["resolved"]) == 3
    assert [i["name"] for i in ql.search(status="blocked")["items"]] == ["b.test"]
    assert ql.search(status="blocked")["items"][0]["rule"] == "b.test"
    assert ql.search(status="failed")["items"][0]["name"] == "dead.test"
    assert {i["name"] for i in ql.search(status="allowed")["items"]} == {"a.test", "Mixed_Case.test", "dead.test", "old.test"}
    assert [i["name"] for i in ql.search(search="MIXED_case")["items"]] == ["Mixed_Case.test"]  # case-insensitive
    assert ql.search(search="%")["items"] == [] and ql.search(search="_")["items"][0]["name"] == "Mixed_Case.test"
    assert ql.search(search="1.2.3.4")["items"][0]["answers"] == ["A 1.2.3.4"]
    page = ql.search(limit=2)
    assert len(page["items"]) == 2 and page["next"]
    assert len(ql.search(limit=10, before=page["next"])["items"]) == 3
    assert ql.purge() == 1 and ql.count() == 4
    ql.clear()
    assert ql.count() == 0
    ql.stop()


def test_sqlite_log_migrates_old_schema(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("CREATE TABLE queries(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, client TEXT, qname TEXT,"
                      " qtype TEXT, rcode TEXT, source TEXT, elapsed REAL, upstream TEXT, rule TEXT, list_id INTEGER,"
                      " answer TEXT, transport TEXT);")
    con.execute("INSERT INTO queries(ts,client,qname,qtype,rcode,source,elapsed) VALUES (?,?,?,?,?,?,?)",
                (time.time(), "1.1.1.1", "old.test", "A", "NOERROR", "upstream", 3.0))
    con.commit()
    con.close()
    ql = QueryLog(str(path))  # 1.2.x database without ts_min
    assert ql.summary("1h")["totals"]["queries"] == 1 and sum(ql.summary("1h")["series"]["total"]) == 1


# --------------------------------------------------------- config store ---

def test_sql_store_roundtrip(db_url):
    st = SqlStore(SqlBackend(db_url))
    assert st.load() is None and st.revision() == 0
    st.save({"a": 1, "unicode": "dnslens \u2713"})
    r1 = st.revision()
    st.save({"a": 2})
    assert st.load() == {"a": 2} and st.revision() == r1 + 1
    big = "".join(f"ads{i}.example.com\n" for i in range(60000))  # ~1.1 MB, larger than MySQL TEXT/BLOB limits
    st.write_list(7, big)
    assert st.read_list(7) == big and st.read_list(8) is None
    st.write_list(7, "small\n")
    assert st.read_list(7) == "small\n"
    st.remove_list(7)
    assert st.read_list(7) is None
    assert "database" in st.describe() and "dnslens-pw" not in st.describe()


def test_url_helpers():
    assert mask_url("postgresql://u:secret@h/db") == "postgresql://u:***@h/db"
    assert normalize_url("sqlite:///x.db") == "sqlite:///x.db"
    assert normalize_url("postgresql://u:p@h/db").startswith("postgresql+psycopg")
    assert normalize_url("mysql://u:p@h/db").startswith("mysql+pymysql")
    with pytest.raises(ConfigError):
        SqlBackend("not a url")
    with pytest.raises(ConfigError):
        SqlBackend("postgresql+psycopg://nobody:x@127.0.0.1:1/none")


# ------------------------------------------------------ whole manager ---

def make_node(url, upstream_port, tmp_path, name):
    store, qlog = open_database(url)
    h = DNSHandler(ZoneData(), ServerOptions(upstream_timeout=1.0))
    m = Manager("", h, ZoneData(), {"upstreams": [f"127.0.0.1#{upstream_port}"]}, store=store, qlog=qlog)
    return h, m


def test_manager_on_database_and_two_nodes(db_url, tmp_path, serve):
    up = serve(zone_handler({("example.test.", "A"): ["192.0.2.1"], ("ads.bad.test.", "A"): ["203.0.113.66"]}, aa=False))
    lists = ListServer(LIST)
    h1, m1 = make_node(db_url, up.port, tmp_path, "one")
    m1.start(password="db-pass-12345")
    try:
        m1.add_filter("Test list", lists.url)
        m1.add_rewrite({"name": "nas.home", "data": "10.0.0.7"})
        m1.rule_action("block", "example.test")
        assert ask(h1, "ads.bad.test").rcode() == dns.rcode.NXDOMAIN
        assert ask(h1, "example.test").rcode() == dns.rcode.NXDOMAIN
        assert ask(h1, "nas.home").answer[0][0].address == "10.0.0.7"
        m1.qlog.flush()
        s = m1.qlog.summary("1h")["totals"]
        assert s["queries"] == 3 and s["blocked"] == 2 and s["local"] == 1
        info = m1.status()["storage"]
        assert info["mode"] == "database" and "dnslens-pw" not in info["config"] and info["config"] == info["log"]

        # a second server on the same database: sees config, lists (from the DB, no download) and credentials
        lists.close()
        h2, m2 = make_node(db_url, up.port, tmp_path, "two")
        m2.start()
        assert m2.initial_password is None and m2.verify_login("admin", "db-pass-12345")
        assert ask(h2, "ads.bad.test").rcode() == dns.rcode.NXDOMAIN
        assert ask(h2, "nas.home").answer[0][0].address == "10.0.0.7"
        m1.sync_once()  # settle revisions after both nodes started
        m2.sync_once()
        # change on node 2 -> node 1 picks it up
        m2.add_rewrite({"name": "printer.home", "data": "10.0.0.50"})
        assert m1.sync_once() is True
        assert ask(h1, "printer.home").answer[0][0].address == "10.0.0.50"
        assert m1.sync_once() is False
        m2.stop()
    finally:
        m1.stop()
        lists.close()


def test_migrate_files_to_database(db_url, tmp_path, serve):
    up = serve(zone_handler({("example.test.", "A"): ["192.0.2.1"], ("ads.bad.test.", "A"): ["203.0.113.66"]}, aa=False))
    lists = ListServer(LIST)
    d = str(tmp_path / "files")
    h = DNSHandler(ZoneData(), ServerOptions(upstream_timeout=1.0))
    m = Manager(d, h, ZoneData(), {"upstreams": [f"127.0.0.1#{up.port}"]})
    m.start(password="file-pass-12345")
    m.add_filter("Test list", lists.url)
    m.add_rewrite({"name": "nas.home", "data": "10.0.0.7"})
    for n in ("example.test", "ads.bad.test", "nas.home", "example.test"):
        ask(h, n)
    m.qlog.flush()
    m.stop()
    lists.close()

    msgs = []
    res = migrate_files_to_db(d, db_url, progress=msgs.append)
    assert res["lists"] == 1 and res["log_rows"] == 4
    with pytest.raises(ConfigError):  # refuses to overwrite by default
        migrate_files_to_db(d, db_url)
    assert migrate_files_to_db(d, db_url, include_log=False, force=True)["log_rows"] == 0

    h2, m2 = make_node(db_url, up.port, tmp_path, "migrated")
    m2.start()
    try:
        assert m2.verify_login("admin", "file-pass-12345")
        assert ask(h2, "ads.bad.test").rcode() == dns.rcode.NXDOMAIN  # list text came along
        assert ask(h2, "nas.home").answer[0][0].address == "10.0.0.7"
        assert m2.qlog.count() >= 4
    finally:
        m2.stop()
    with pytest.raises(ConfigError):
        migrate_files_to_db(str(tmp_path / "empty"), db_url)


def test_cli_db_flags(db_url, tmp_path, capsys):
    d = tmp_path / "data"
    FileStore(str(d)).save({"version": 1, "auth": {"username": "admin", "password_hash": "x"}, "filters": []})
    assert main(["db", "migrate", "--from-dir", str(d), "--to", db_url]) == 0
    assert "migrated" in capsys.readouterr().out
    assert main(["db", "migrate", "--from-dir", str(d), "--to", db_url]) == 2  # exists, no --force
    assert "already holds" in capsys.readouterr().err
    assert main(["serve", "--port", "0", "--db", db_url]) == 2  # --db needs --web
