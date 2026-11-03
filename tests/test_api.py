# File: dnslens/tests/test_api.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

import json
import urllib.error
import urllib.request

import pytest
from conftest import zone_handler

from dnslens.api import ApiConfig, ApiServer
from dnslens.core import Target

ZONE = {
    ("example.test.", "A"): ["192.0.2.1"],
    ("example.test.", "SOA"): ["ns1.example.test. a.example.test. 1 1 1 1 1"],
    ("example.test.", "NS"): ["ns1.example.test."],
    ("ns1.example.test.", "A"): ["127.0.0.1"],
}


def get(srv, path, headers=None, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{srv.port}{path}", headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


@pytest.fixture
def api(serve):
    dns_srv = serve(zone_handler(ZONE))
    cfg = ApiConfig(resolvers={"local": Target("local", f"127.0.0.1#{dns_srv.port}")}, default_timeout=1.0)
    with ApiServer(cfg, "127.0.0.1", 0) as s:
        s.dns_port = dns_srv.port
        yield s


def test_health_index_404(api):
    code, body, _ = get(api, "/healthz")
    assert code == 200 and json.loads(body)["status"] == "ok"
    code, body, _ = get(api, "/")
    assert "/propagate" in json.loads(body)["endpoints"]
    assert get(api, "/nope")[0] == 404
    assert get(api, "/healthz", method="HEAD")[0] == 200
    assert get(api, "/healthz", method="POST")[0] == 405


def test_query(api):
    code, body, _ = get(api, "/query?name=example.test&type=A&retries=0")
    data = json.loads(body)
    assert code == 200 and data[0]["records"][0]["data"] == "192.0.2.1" and data[0]["resolver"] == "local"


def test_validation(api):
    assert get(api, "/query")[0] == 400
    assert get(api, "/query?name=bad%20name!")[0] == 400
    assert get(api, "/query?name=example.test&type=NOPE")[0] == 400
    assert get(api, "/query?name=example.test&timeout=999")[0] == 400
    assert get(api, "/query?name=example.test&resolver=8.8.8.8")[0] == 400  # custom resolvers off
    assert get(api, "/reverse?ip=zzz")[0] == 400


def test_propagate_and_probe(api):
    code, body, _ = get(api, "/propagate?name=example.test&resolver=local&expect=192.0.2.1&retries=0")
    d = json.loads(body)
    assert code == 200 and d["ok"] and d["consistent"]
    code, body, h = get(api, "/probe?kind=propagate&name=example.test&resolver=local&expect=192.0.2.9&retries=0")
    assert code == 200 and "dnslens_probe_success 0" in body and "text/plain" in h["Content-Type"]
    code, body, _ = get(api, "/probe?kind=query&name=example.test&resolver=local&expect=192.0.2.1&retries=0")
    assert "dnslens_probe_success 1" in body
    code, body, _ = get(api, "/probe?kind=audit&domain=example.test&resolver=local&retries=0")
    assert "dnslens_probe_failures" in body
    assert get(api, "/probe?kind=bogus&name=x")[0] == 400


def test_audit_trace_bench(api):
    code, body, _ = get(api, "/audit?domain=example.test&resolver=local&retries=0")
    assert code == 200 and "findings" in json.loads(body)
    code, body, _ = get(api, "/bench?resolver=local&domain=example.test&count=3")
    assert code == 200 and json.loads(body)[0]["answered"] == 3
    assert get(api, "/bench?resolver=local&count=9999")[0] == 400


def test_metrics(api):
    get(api, "/healthz")
    get(api, "/query?name=example.test&retries=0")
    code, body, _ = get(api, "/metrics")
    assert code == 200
    assert 'dnslens_api_requests_total{path="/query",code="200"} 1' in body
    assert "dnslens_build_info" in body


def test_token_auth(serve):
    cfg = ApiConfig(token="s3cret")
    with ApiServer(cfg, "127.0.0.1", 0) as s:
        assert get(s, "/healthz")[0] == 200  # health stays open for probes
        assert get(s, "/query?name=a.test")[0] == 401
        assert get(s, "/metrics")[0] == 401
        assert get(s, "/query?name=%20", {"Authorization": "Bearer wrong"})[0] == 401
        assert get(s, "/query?name=bad!", {"Authorization": "Bearer s3cret"})[0] == 400  # authed, then validated
        assert get(s, "/", {"X-API-Key": "s3cret"})[0] == 200


def test_custom_resolver_flag(serve):
    d = serve(zone_handler(ZONE))
    with ApiServer(ApiConfig(allow_custom=True, default_timeout=1.0), "127.0.0.1", 0) as s:
        code, body, _ = get(s, f"/query?name=example.test&resolver=127.0.0.1%23{d.port}&retries=0")
        assert code == 200 and json.loads(body)[0]["records"]


def test_busy_returns_503(serve):
    import threading

    slow = serve(lambda q: __import__("time").sleep(1.2))  # never answers in time
    cfg = ApiConfig(resolvers={"slow": Target("slow", f"127.0.0.1#{slow.port}")}, max_concurrent=1, default_timeout=1.0)
    with ApiServer(cfg, "127.0.0.1", 0) as s:
        t = threading.Thread(target=get, args=(s, "/query?name=example.test&retries=0"))
        t.start()
        import time
        time.sleep(0.3)
        assert get(s, "/query?name=example.test&retries=0")[0] == 503
        t.join()
