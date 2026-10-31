import dns.rdatatype  # noqa: F401
from conftest import zone_handler

from dnslens.core import QueryOpts, Target, norm_value, parse_target, query, txt_join

ZONE = {
    ("example.test.", "A"): ["192.0.2.1", "192.0.2.2"],
    ("example.test.", "TXT"): ['"v=spf1 " "-all"'],
    ("example.test.", "MX"): ["10 mail.example.test."],
}


def opts(srv):
    return QueryOpts(timeout=1.0, retries=0, port=srv.port)


def test_query_a(serve):
    srv = serve(zone_handler(ZONE))
    a = query("example.test", "A", "127.0.0.1", opts(srv))
    assert a.ok and a.error is None
    assert a.values() == {"192.0.2.1", "192.0.2.2"}
    assert a.min_ttl == 300 and "AA" in a.flags.split()


def test_nxdomain(serve):
    srv = serve(zone_handler(ZONE))
    a = query("nope.test", "A", "127.0.0.1", opts(srv))
    assert a.rcode == "NXDOMAIN" and a.responded and not a.ok and not a.records


def test_nodata(serve):
    srv = serve(zone_handler(ZONE))
    a = query("example.test", "AAAA", "127.0.0.1", opts(srv))
    assert a.ok and a.values() == frozenset()


def test_timeout():
    # nothing listens on this port -> ICMP refusal or timeout, both are errors
    a = query("example.test", "A", "127.0.0.1", QueryOpts(timeout=0.3, retries=0, port=9))
    assert a.error is not None and not a.responded


def test_bad_type():
    a = query("example.test", "NOPE", "127.0.0.1", QueryOpts(timeout=0.3, retries=0))
    assert a.error and a.error.startswith("bad query")


def test_txt_normalisation(serve):
    srv = serve(zone_handler(ZONE))
    a = query("example.test", "TXT", "127.0.0.1", opts(srv))
    assert a.values() == {"v=spf1 -all"}
    assert txt_join('"a" "b"') == "ab"
    assert norm_value("CNAME", "Foo.Example.") == "foo.example"


def test_parse_target():
    assert parse_target("1.1.1.1") == Target("1.1.1.1", "1.1.1.1")
    assert parse_target("cf=1.1.1.1") == Target("cf", "1.1.1.1")
    t = parse_target("https://x.test/dns-query?a=b")
    assert t.address == t.name == "https://x.test/dns-query?a=b"
