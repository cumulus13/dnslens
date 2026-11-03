# File: dnslens/src/dnslens/api.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""HTTP API (JSON + Prometheus text) exposing the dnslens tools. Standard library only."""
from __future__ import annotations

import hmac
import json
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

import dns.exception
import dns.rdatatype
import dns.reversename

from . import __version__
from .audit import audit
from .core import PUBLIC_RESOLVERS, SYSTEM, QueryOpts, Target, parse_target, query_target
from .dnssec import check_dnssec
from .tools import DEFAULT_BENCH_DOMAINS, bench, propagate
from .trace import trace

log = logging.getLogger("dnslens.api")

_NAME_RE = re.compile(r"^[\w.*\-]{1,253}$")
_TRUE = {"1", "true", "yes", "on", ""}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Raw:
    body: str
    content_type: str = "text/plain; version=0.0.4; charset=utf-8"


@dataclass
class ApiConfig:
    token: Optional[str] = None
    resolvers: Dict[str, Target] = field(default_factory=dict)  # named resolvers (-r), also the defaults
    extra: Dict[str, Target] = field(default_factory=dict)  # selectable by name but never a default
    allow_custom: bool = False
    default_timeout: float = 3.0
    max_concurrent: int = 16
    max_bench: int = 50

    def registry(self) -> Dict[str, Target]:
        reg = {t.name: t for t in PUBLIC_RESOLVERS}
        reg["system"] = SYSTEM
        reg.update(self.extra)
        reg.update(self.resolvers)
        return reg

    def default_targets(self, public: bool) -> List[Target]:
        if self.resolvers:
            return list(self.resolvers.values())
        return list(PUBLIC_RESOLVERS) if public else [SYSTEM]


class Params:
    def __init__(self, qs: Dict[str, List[str]]) -> None:
        self.qs = qs

    def text(self, key: str, required: bool = False, default: Optional[str] = None) -> Optional[str]:
        v = self.qs.get(key)
        if not v or v[0] == "":
            if required:
                raise ApiError(400, f"missing required parameter '{key}'")
            return default
        return v[0]

    def many(self, key: str, limit: int = 20) -> List[str]:
        out = [x for v in self.qs.get(key, []) for x in v.split(",") if x] if key != "expect" else [
            x for x in self.qs.get(key, []) if x
        ]
        if len(out) > limit:
            raise ApiError(400, f"too many '{key}' values (max {limit})")
        return out

    def flag(self, key: str) -> bool:
        v = self.qs.get(key)
        return bool(v) and v is not None and v[-1].lower() in _TRUE

    def num(self, key: str, default: float, lo: float, hi: float, cast: Callable[[Any], Any] = float) -> Any:
        v = self.text(key)
        if v is None:
            return default
        try:
            n = cast(v)
        except ValueError:
            raise ApiError(400, f"parameter '{key}' must be a number") from None
        if not lo <= n <= hi:
            raise ApiError(400, f"parameter '{key}' must be between {lo} and {hi}")
        return n

    def choice(self, key: str, options: Sequence[str], default: Optional[str] = None) -> str:
        v = self.text(key, required=default is None, default=default)
        assert v is not None
        if v not in options:
            raise ApiError(400, f"parameter '{key}' must be one of: {', '.join(options)}")
        return v

    def name(self, key: str = "name") -> str:
        v = self.text(key, required=True)
        assert v is not None
        if not _NAME_RE.match(v):
            raise ApiError(400, f"invalid {key}")
        return v

    def rtype(self, default: str = "A") -> str:
        v = (self.text("type", default=default) or default).upper()
        try:
            dns.rdatatype.from_text(v)
        except Exception:
            raise ApiError(400, f"unknown record type '{v}'") from None
        return v


def _opts(cfg: ApiConfig, p: Params, **kw: Any) -> QueryOpts:
    return QueryOpts(
        timeout=p.num("timeout", cfg.default_timeout, 0.2, 10.0),
        retries=p.num("retries", 1, 0, 2, int),
        transport=p.choice("transport", ("udp", "tcp", "tls"), "udp"),
        **kw,
    )


def _targets(cfg: ApiConfig, p: Params, public_default: bool) -> List[Target]:
    names = p.many("resolver")
    if not names:
        return cfg.default_targets(public_default)
    reg = cfg.registry()
    out: List[Target] = []
    for n in names:
        if n == "public":
            out.extend(PUBLIC_RESOLVERS)
        elif n in reg:
            out.append(reg[n])
        elif cfg.allow_custom:
            out.append(parse_target(n))
        else:
            raise ApiError(400, f"unknown resolver '{n}'; known: {', '.join(sorted(reg))}, public")
    return out


def _server(cfg: ApiConfig, p: Params) -> Optional[str]:
    return _targets(cfg, p, False)[0].address


# ------------------------------------------------------------------ endpoints ---


def ep_health(cfg: ApiConfig, p: Params) -> Any:
    return {"status": "ok", "version": __version__}


def ep_query(cfg: ApiConfig, p: Params) -> Any:
    name = p.name()
    types = [t.upper() for t in (p.text("type", default="A") or "A").split(",") if t]
    if not 1 <= len(types) <= 5:
        raise ApiError(400, "1 to 5 record types allowed")
    for ty in types:
        Params({"type": [ty]}).rtype()
    opts = _opts(cfg, p, dnssec=p.flag("dnssec"))
    rd = not p.flag("norecurse")
    out = []
    for tgt in _targets(cfg, p, False):
        for ty in types:
            out.append(dict(query_target(tgt, name, ty, opts, rd).to_dict(), resolver=tgt.name))
    return out


def ep_reverse(cfg: ApiConfig, p: Params) -> Any:
    ip = p.text("ip", required=True)
    try:
        qname = dns.reversename.from_address(ip or "").to_text()
    except (dns.exception.DNSException, ValueError):
        raise ApiError(400, "invalid IP address") from None
    opts = _opts(cfg, p)
    return [dict(query_target(t, qname, "PTR", opts).to_dict(), resolver=t.name)
            for t in _targets(cfg, p, False)]


def ep_propagate(cfg: ApiConfig, p: Params) -> Any:
    return propagate(_targets(cfg, p, True), p.name(), p.rtype(), _opts(cfg, p),
                     p.many("expect") or None, p.flag("strict")).to_dict()


def ep_trace(cfg: ApiConfig, p: Params) -> Any:
    return trace(p.name(), p.rtype(), _opts(cfg, p)).to_dict()


def ep_audit(cfg: ApiConfig, p: Params) -> Any:
    f = audit(p.name("domain"), _server(cfg, p), _opts(cfg, p), p.many("dkim_selector", 10))
    return {"ok": not any(x.level == "FAIL" for x in f), "findings": [x.to_dict() for x in f]}


def ep_dnssec(cfg: ApiConfig, p: Params) -> Any:
    f = check_dnssec(p.name("domain"), _server(cfg, p), _opts(cfg, p))
    return {"ok": not any(x.level == "FAIL" for x in f), "findings": [x.to_dict() for x in f]}


def ep_bench(cfg: ApiConfig, p: Params) -> Any:
    count = p.num("count", 5, 1, cfg.max_bench, int)
    doms = p.many("domain", 10)
    for d in doms:
        if not _NAME_RE.match(d):
            raise ApiError(400, "invalid domain")
    res = bench(_targets(cfg, p, True), doms or DEFAULT_BENCH_DOMAINS, count, _opts(cfg, p), p.flag("uncached"))
    return [r.to_dict() for r in res]


def _prom(metrics: Sequence[Tuple[str, str, float]]) -> str:
    lines = []
    for name, help_, value in metrics:
        lines += [f"# HELP {name} {help_}", f"# TYPE {name} gauge", f"{name} {value:g}"]
    return "\n".join(lines) + "\n"


def ep_probe(cfg: ApiConfig, p: Params) -> Any:
    """Blackbox-exporter style probe for Prometheus: /probe?kind=propagate&name=...&expect=..."""
    kind = p.choice("kind", ("query", "propagate", "audit", "dnssec"))
    t0 = time.perf_counter()
    m: List[Tuple[str, str, float]] = []
    if kind == "query":
        name, rtype = p.name(), p.rtype()
        expect = p.many("expect")
        a = query_target(_targets(cfg, p, False)[0], name, rtype, _opts(cfg, p))
        ok = a.ok and bool(a.values())
        if expect:
            from .tools import normalise_expected
            ok = ok and a.values() == normalise_expected(rtype, expect)
        m += [("dnslens_probe_success", "1 if the probe passed", float(ok)),
              ("dnslens_probe_answer_records", "number of records of the queried type", float(len(a.values()))),
              ("dnslens_probe_dns_seconds", "time of the DNS query", a.elapsed_ms / 1000)]
    elif kind == "propagate":
        rep = propagate(_targets(cfg, p, True), p.name(), p.rtype(), _opts(cfg, p),
                        p.many("expect") or None, p.flag("strict"))
        match = (max((len(v) for v in rep.groups.values()), default=0) if rep.expected is None else
                 sum(len(v) for g, v in rep.groups.items() if g == rep.expected))
        m += [("dnslens_probe_success", "1 if the probe passed", float(rep.ok)),
              ("dnslens_probe_resolvers_total", "resolvers queried", float(len(rep.results))),
              ("dnslens_probe_resolvers_responding", "resolvers that answered", float(rep.responders)),
              ("dnslens_probe_resolvers_matching", "resolvers returning the expected (or majority) answer", float(match)),
              ("dnslens_probe_distinct_answers", "number of distinct answer sets", float(len(rep.groups)))]
    else:
        dom = p.name("domain")
        f = (audit(dom, _server(cfg, p), _opts(cfg, p), p.many("dkim_selector", 10)) if kind == "audit"
             else check_dnssec(dom, _server(cfg, p), _opts(cfg, p)))
        fails, warns = sum(x.level == "FAIL" for x in f), sum(x.level == "WARN" for x in f)
        m += [("dnslens_probe_success", "1 if the probe passed", float(fails == 0)),
              ("dnslens_probe_failures", "findings with level FAIL", float(fails)),
              ("dnslens_probe_warnings", "findings with level WARN", float(warns))]
    m.append(("dnslens_probe_duration_seconds", "total probe duration", time.perf_counter() - t0))
    return Raw(_prom(m))


ROUTES: Dict[str, Callable[[ApiConfig, Params], Any]] = {
    "/healthz": ep_health, "/query": ep_query, "/reverse": ep_reverse, "/propagate": ep_propagate,
    "/trace": ep_trace, "/audit": ep_audit, "/dnssec": ep_dnssec, "/bench": ep_bench, "/probe": ep_probe,
}


# -------------------------------------------------------------------- server ---


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: Dict[Tuple[str, int], int] = {}
        self.dur_sum: Dict[str, float] = {}
        self.dur_count: Dict[str, int] = {}
        self.inflight = 0
        self.start = time.time()

    def observe(self, path: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(path, status)] = self.requests.get((path, status), 0) + 1
            self.dur_sum[path] = self.dur_sum.get(path, 0.0) + seconds
            self.dur_count[path] = self.dur_count.get(path, 0) + 1

    def render(self) -> str:
        with self._lock:
            out = ["# HELP dnslens_api_requests_total HTTP requests", "# TYPE dnslens_api_requests_total counter"]
            for (path, status), n in sorted(self.requests.items()):
                out.append(f'dnslens_api_requests_total{{path="{path}",code="{status}"}} {n}')
            out += ["# HELP dnslens_api_request_duration_seconds request duration",
                    "# TYPE dnslens_api_request_duration_seconds summary"]
            for path in sorted(self.dur_sum):
                out.append(f'dnslens_api_request_duration_seconds_sum{{path="{path}"}} {self.dur_sum[path]:.6f}')
                out.append(f'dnslens_api_request_duration_seconds_count{{path="{path}"}} {self.dur_count[path]}')
            out += ["# HELP dnslens_api_inflight_requests requests being processed",
                    "# TYPE dnslens_api_inflight_requests gauge", f"dnslens_api_inflight_requests {self.inflight}",
                    "# HELP dnslens_api_uptime_seconds process uptime",
                    "# TYPE dnslens_api_uptime_seconds gauge", f"dnslens_api_uptime_seconds {time.time() - self.start:.0f}",
                    "# HELP dnslens_build_info version", "# TYPE dnslens_build_info gauge",
                    f'dnslens_build_info{{version="{__version__}"}} 1']
        return "\n".join(out) + "\n"


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _HTTPServer6(_HTTPServer):
    address_family = socket.AF_INET6


def _make_handler(cfg: ApiConfig, metrics: Metrics, sem: threading.BoundedSemaphore) -> Any:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"dnslens/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # route to logging
            log.info("%s %s", self.address_string(), fmt % args)

        def _send(self, status: int, body: bytes, ctype: str, head: bool) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _authorized(self) -> bool:
            if not cfg.token:
                return True
            got = self.headers.get("X-API-Key", "")
            auth = self.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                got = auth[7:].strip()
            return hmac.compare_digest(got.encode(), cfg.token.encode())

        def _handle(self, head: bool) -> None:
            t0 = time.perf_counter()
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            status, label = 500, path if (path in ROUTES or path in ("/", "/metrics")) else "other"
            counted = False
            try:
                if path == "/healthz":
                    result: Any = ep_health(cfg, Params({}))
                elif not self._authorized():
                    raise ApiError(401, "missing or invalid token")
                elif path == "/":
                    result = {"name": "dnslens", "version": __version__,
                              "endpoints": sorted(list(ROUTES) + ["/metrics"])}
                elif path == "/metrics":
                    result = Raw(metrics.render())
                elif path in ROUTES:
                    if not sem.acquire(blocking=False):
                        raise ApiError(503, "server busy, retry later")
                    counted = True
                    with metrics._lock:
                        metrics.inflight += 1
                    try:
                        result = ROUTES[path](cfg, Params(parse_qs(parsed.query, keep_blank_values=True)))
                    finally:
                        with metrics._lock:
                            metrics.inflight -= 1
                        sem.release()
                else:
                    raise ApiError(404, "not found")
                status = 200
                if isinstance(result, Raw):
                    body, ctype = result.body.encode(), result.content_type
                else:
                    body, ctype = json.dumps(result, indent=2, default=str).encode(), "application/json"
            except ApiError as e:
                status, body, ctype = e.status, json.dumps({"error": e.message}).encode(), "application/json"
            except Exception:
                log.exception("unhandled error on %s", path)
                status, body, ctype = 500, b'{"error": "internal error"}', "application/json"
            if counted or path in ROUTES or path in ("/", "/metrics"):
                metrics.observe(label, status, time.perf_counter() - t0)  # before replying, so /metrics is never behind
            self._send(status, body, ctype, head)

        def do_GET(self) -> None:
            self._handle(False)

        def do_HEAD(self) -> None:
            self._handle(True)

        def _nope(self) -> None:
            body = b'{"error": "method not allowed"}'
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_PUT = do_DELETE = do_PATCH = _nope  # type: ignore[assignment]

    return Handler


class ApiServer:
    def __init__(self, cfg: ApiConfig, host: str = "127.0.0.1", port: int = 8053) -> None:
        self.cfg = cfg
        self.metrics = Metrics()
        self._sem = threading.BoundedSemaphore(cfg.max_concurrent)
        cls = _HTTPServer6 if ":" in host else _HTTPServer
        self.httpd = cls((host, port), _make_handler(cfg, self.metrics, self._sem))
        self.host, self.port = host, self.httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def start(self) -> ApiServer:
        self._thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.httpd.serve_forever(poll_interval=0.2)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(1)

    def __enter__(self) -> ApiServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
