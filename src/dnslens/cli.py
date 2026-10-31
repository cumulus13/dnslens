"""Command line interface."""
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
import time
from typing import Any, List, Optional, Sequence, Tuple

import dns.exception
import dns.reversename

from . import __version__
from .api import ApiConfig, ApiServer
from .audit import audit
from .core import (
    DOH_RESOLVERS,
    PUBLIC_RESOLVERS,
    SYSTEM,
    Finding,
    QueryOpts,
    Target,
    parse_target,
    query_target,
)
from .dnssec import check_dnssec
from .output import Style, emit_json, render_table, setup_streams, supports_color
from .server import (
    DEFAULT_UPSTREAMS,
    ConfigError,
    DNSHandler,
    DNSServer,
    Reloader,
    ServerOptions,
    build_zone,
    default_allow,
    load_config_file,
)
from .tools import DEFAULT_BENCH_DOMAINS, bench, propagate, wait
from .trace import trace


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("resolver options")
    g.add_argument("-r", "--resolver", action="append", metavar="ADDR",
                   help="resolver IP/host/DoH URL, optionally NAME=ADDR (repeatable)")
    g.add_argument("--public", action="store_true", help="use the built-in public resolver set")
    g.add_argument("-t", "--timeout", type=float, default=3.0, help="per-query timeout in seconds (3)")
    g.add_argument("--retries", type=int, default=1, help="retries on timeout (1)")
    g.add_argument("--transport", choices=["udp", "tcp", "tls", "https"], default="udp")
    g.add_argument("-p", "--port", type=int, help="server port (default depends on transport)")
    o = p.add_argument_group("output options")
    o.add_argument("--json", action="store_true", help="machine-readable JSON output")
    o.add_argument("--no-color", action="store_true")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    ap = argparse.ArgumentParser(
        prog="dnslens",
        description="Cross-platform DNS toolkit: query, trace, propagation, benchmark, audit, DNSSEC.",
    )
    ap.add_argument("-V", "--version", action="version", version=f"dnslens {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    s = sub.add_parser("query", parents=[common], help="query records (dig-like)")
    s.add_argument("name")
    s.add_argument("type", nargs="?", default="A", help="record type, comma-separated for several (A)")
    s.add_argument("--short", action="store_true", help="print record data only")
    s.add_argument("--dnssec", action="store_true", help="request DNSSEC records (DO bit)")
    s.add_argument("--norecurse", action="store_true", help="clear the RD bit")

    s = sub.add_parser("trace", parents=[common], help="iterative resolution from the root")
    s.add_argument("name")
    s.add_argument("type", nargs="?", default="A")

    s = sub.add_parser("propagate", parents=[common], help="compare answers across resolvers")
    s.add_argument("name")
    s.add_argument("type", nargs="?", default="A")
    s.add_argument("--expect", action="append", metavar="VALUE", help="expected record data (repeatable)")
    s.add_argument("--strict", action="store_true", help="unreachable resolvers count as failure")

    s = sub.add_parser("wait", parents=[common], help="block until DNS reaches the desired state")
    s.add_argument("name")
    s.add_argument("type", nargs="?", default="A")
    s.add_argument("--expect", action="append", metavar="VALUE")
    s.add_argument("--subset", action="store_true", help="expected values only need to be present")
    s.add_argument("--absent", action="store_true", help="wait until no records are returned")
    s.add_argument("--interval", type=float, default=5.0)
    s.add_argument("--max-wait", type=float, default=300.0, help="give up after N seconds (300)")

    s = sub.add_parser("bench", parents=[common], help="benchmark resolver latency")
    s.add_argument("-d", "--domain", action="append", help="domain to query (repeatable)")
    s.add_argument("-n", "--count", type=int, default=10, help="queries per resolver (10)")
    s.add_argument("--uncached", action="store_true", help="randomised labels to bypass caches")

    s = sub.add_parser("audit", parents=[common], help="domain health check")
    s.add_argument("domain")
    s.add_argument("--dkim-selector", action="append", default=[], metavar="SEL")

    s = sub.add_parser("dnssec", parents=[common], help="check DS/DNSKEY/RRSIG consistency")
    s.add_argument("domain")

    s = sub.add_parser("reverse", parents=[common], help="PTR lookup for an IP")
    s.add_argument("address")

    s = sub.add_parser("serve", help="run a local DNS server (overrides, blocklist, caching forwarder)")
    s.add_argument("--host", default="127.0.0.1", help="bind address (127.0.0.1)")
    s.add_argument("-p", "--port", type=int, default=5353, help="UDP+TCP port (5353; 53 needs root/Administrator)")
    s.add_argument("-c", "--config", metavar="FILE", help="JSON zone/config file")
    s.add_argument("--record", action="append", default=[], metavar="'NAME TYPE DATA'",
                   help="add a record, e.g. --record 'app.test A 10.0.0.5' (repeatable)")
    s.add_argument("--authoritative", action="append", default=[], metavar="ZONE",
                   help="answer NXDOMAIN for unknown names under ZONE instead of forwarding")
    s.add_argument("--block", action="append", default=[], metavar="DOMAIN", help="block DOMAIN and subdomains")
    s.add_argument("--blocklist", action="append", default=[], metavar="FILE", help="hosts-format or domain list")
    s.add_argument("--block-mode", choices=["nxdomain", "null"], help="reply NXDOMAIN (default) or 0.0.0.0/::")
    s.add_argument("--upstream", action="append", metavar="ADDR", help="upstream resolver, IP or IP#PORT (repeatable)")
    s.add_argument("--upstream-timeout", type=float, default=2.0)
    s.add_argument("--no-forward", action="store_true", help="authoritative only; REFUSE everything else")
    s.add_argument("--cache-size", type=int, default=10000, help="0 disables the cache")
    s.add_argument("--max-ttl", type=int, default=86400, help="cache TTL ceiling in seconds")
    s.add_argument("--allow", action="append", metavar="CIDR",
                   help="allowed client network (repeatable); default: private ranges, or anyone on loopback")
    s.add_argument("--workers", type=int, default=32, help="UDP worker threads")
    s.add_argument("--watch", action="store_true", help="hot-reload config/blocklist files when they change")
    s.add_argument("--log-queries", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")

    s = sub.add_parser("api", help="run the HTTP API (JSON + Prometheus probe endpoints)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("-p", "--port", type=int, default=8053)
    s.add_argument("--token", default=os.environ.get("DNSLENS_API_TOKEN"),
                   help="require this bearer token (or env DNSLENS_API_TOKEN)")
    s.add_argument("-r", "--resolver", action="append", metavar="NAME=ADDR",
                   help="register a named resolver; becomes the default (repeatable)")
    s.add_argument("--allow-custom-resolver", action="store_true",
                   help="let callers pass arbitrary resolver addresses (off by default)")
    s.add_argument("-t", "--timeout", type=float, default=3.0, help="default per-query timeout")
    s.add_argument("--max-concurrent", type=int, default=16, help="concurrent tool requests before 503")
    s.add_argument("-v", "--verbose", action="store_true")
    return ap


# --------------------------------------------------------------------------- #


def _opts(a: argparse.Namespace, **kw: object) -> QueryOpts:
    return QueryOpts(timeout=a.timeout, retries=a.retries, transport=a.transport,
                     port=a.port, **kw)  # type: ignore[arg-type]


def _targets(a: argparse.Namespace, default_public: bool) -> List[Target]:
    if a.resolver:
        return [parse_target(r) for r in a.resolver]
    if a.public or default_public:
        return list(DOH_RESOLVERS if a.transport == "https" else PUBLIC_RESOLVERS)
    if a.transport == "https":
        raise SystemExit("dnslens: --transport https needs -r URL or --public")
    return [SYSTEM]


def _server(a: argparse.Namespace) -> Optional[str]:
    t = _targets(a, False)[0]
    return t.address


def _print_findings(findings: Sequence[Finding], st: Style, as_json: bool) -> int:
    fails = sum(f.level == "FAIL" for f in findings)
    if as_json:
        emit_json({"ok": fails == 0, "findings": [f.to_dict() for f in findings]})
    else:
        for f in findings:
            print(f"{st.level(f.level)}  {f.check:<6} {f.message}")
        warns = sum(f.level == "WARN" for f in findings)
        print(f"\n{fails} failure(s), {warns} warning(s)")
    return 1 if fails else 0


def cmd_query(a: argparse.Namespace, st: Style) -> int:
    types = [t.strip().upper() for t in a.type.split(",") if t.strip()]
    targets = _targets(a, False)
    opts = _opts(a, dnssec=a.dnssec)
    answers = [(t, query_target(t, a.name, ty, opts, rd=not a.norecurse)) for ty in types for t in targets]
    if a.json:
        emit_json([dict(x.to_dict(), resolver=t.name) for t, x in answers])
    rc = 0
    for _t, x in answers:
        if x.error or not x.records:
            rc = 1
        if a.json:
            continue
        if a.short:
            for r in x.records:
                print(r.data)
            continue
        head = f";; {a.name} {x.rdtype} @ {x.server}"
        if x.error:
            print(st.paint(f"{head}  ERROR: {x.error}", "red"))
            continue
        print(st.paint(f"{head}  {x.rcode}  [{x.flags}]  {x.elapsed_ms:.1f} ms  {x.transport}", "dim"))
        if x.records:
            print(render_table(["NAME", "TTL", "TYPE", "DATA"],
                               [(r.name, r.ttl, r.type, r.data) for r in x.records]))
        else:
            print("(no records)" if x.rcode == "NOERROR" else f"({x.rcode})")
        print()
    return rc


def cmd_trace(a: argparse.Namespace, st: Style) -> int:
    res = trace(a.name, a.type, _opts(a))
    if a.json:
        emit_json(res.to_dict())
        return 0 if res.ok else 1
    print(render_table(["#", "ZONE", "SERVER", "RTT", "RESULT"],
                       [(i + 1, h.zone, h.server, f"{h.rtt_ms:.1f} ms", f"{h.outcome} {h.detail}".strip())
                        for i, h in enumerate(res.hops)]))
    if res.error:
        print(st.paint(f"\ntrace failed: {res.error}", "red"))
    elif res.final:
        print()
        for r in res.final.records:
            print(f"{r.name}  {r.ttl}  {r.type}  {r.data}")
        if not res.final.records:
            print(f"({res.final.rcode}, no records)")
    return 0 if res.ok else 1


def cmd_propagate(a: argparse.Namespace, st: Style) -> int:
    rep = propagate(_targets(a, True), a.name, a.type, _opts(a), a.expect, a.strict)
    if a.json:
        emit_json(rep.to_dict())
        return 0 if rep.ok else 1
    rows: List[Tuple[Any, ...]] = []
    for t, x in rep.results:
        if not x.responded:
            rows.append((t.name, st.paint("FAIL", "red"), x.error or x.rcode, "-", "-"))
            continue
        good = rep.expected is None or x.values() == rep.expected
        tag = st.paint("OK", "green") if good else st.paint("DIFF", "yellow")
        rows.append((t.name, tag, ", ".join(sorted(x.values())) or f"({x.rcode}, empty)",
                     x.min_ttl if x.min_ttl is not None else "-", f"{x.elapsed_ms:.0f} ms"))
    print(render_table(["RESOLVER", "STATE", "ANSWER", "TTL", "TIME"], rows))
    print()
    if rep.responders == 0:
        print(st.paint("no resolver responded", "red"))
    elif rep.expected is not None:
        n = sum(len(v) for g, v in rep.groups.items() if g == rep.expected)
        msg = f"{n}/{rep.responders} responding resolvers return the expected answer"
        print(st.paint(msg, "green" if rep.ok else "red"))
    elif rep.consistent:
        print(st.paint(f"CONSISTENT across {rep.responders} resolvers", "green"))
    else:
        print(st.paint(f"INCONSISTENT: {len(rep.groups)} distinct answers "
                       "(expected for round-robin/GeoDNS records)", "red"))
    if rep.failed:
        print(f"unreachable: {', '.join(rep.failed)}")
    return 0 if rep.ok else 1


def cmd_wait(a: argparse.Namespace, st: Style) -> int:
    def progress(elapsed: float, good: int, total: int) -> None:
        if not a.json:
            print(f"[{elapsed:5.0f}s] {good}/{total} resolvers match", file=sys.stderr, flush=True)

    ok, results = wait(_targets(a, False), a.name, a.type, _opts(a), a.expect, a.subset,
                       a.absent, a.interval, a.max_wait, progress)
    if a.json:
        emit_json({"ok": ok, "results": [dict(x.to_dict(), resolver=t.name) for t, x in results]})
    else:
        print(st.paint("condition met" if ok else "timed out", "green" if ok else "red"))
    return 0 if ok else 1


def cmd_bench(a: argparse.Namespace, st: Style) -> int:
    res = bench(_targets(a, True), a.domain or DEFAULT_BENCH_DOMAINS, a.count, _opts(a), a.uncached)
    if a.json:
        emit_json([r.to_dict() for r in res])
        return 0 if any(r.answered for r in res) else 1
    f = lambda v: "-" if v is None else f"{v:.1f}"  # noqa: E731
    rows = []
    for r in res:
        s = r.stats
        rows.append((r.target.name, f"{r.answered}/{r.sent}", f"{r.loss_pct:.0f}%", f(s["min"]),
                     f(s["avg"]), f(s["median"]), f(s["p95"]), f(s["max"]), r.first_error or ""))
    print(render_table(["RESOLVER", "OK", "LOSS", "MIN", "AVG", "MEDIAN", "P95", "MAX", "ERROR"], rows))
    print("\ntimes in ms, sorted by median" + (" (uncached)" if a.uncached else ""))
    return 0 if any(r.answered for r in res) else 1


def cmd_audit(a: argparse.Namespace, st: Style) -> int:
    return _print_findings(audit(a.domain, _server(a), _opts(a), a.dkim_selector), st, a.json)


def cmd_dnssec(a: argparse.Namespace, st: Style) -> int:
    return _print_findings(check_dnssec(a.domain, _server(a), _opts(a)), st, a.json)


def cmd_reverse(a: argparse.Namespace, st: Style) -> int:
    try:
        name = dns.reversename.from_address(a.address).to_text()
    except (dns.exception.DNSException, ValueError):
        print(f"dnslens: invalid IP address: {a.address}", file=sys.stderr)
        return 2
    a2 = argparse.Namespace(**vars(a))
    a2.name, a2.type, a2.short, a2.dnssec, a2.norecurse = name, "PTR", False, False, False
    return cmd_query(a2, st)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")


def _default_upstreams(host: str) -> List[str]:
    from .core import system_nameservers

    out = []
    for n in system_nameservers():
        try:
            if ipaddress.ip_address(n).is_loopback or n == host:
                continue  # avoid forwarding to ourselves
        except ValueError:
            continue
        out.append(n)
    return out or list(DEFAULT_UPSTREAMS)


def cmd_serve(a: argparse.Namespace, st: Style) -> int:
    _setup_logging(a.verbose)
    base = os.path.dirname(os.path.abspath(a.config)) if a.config else "."

    def loader():  # type: ignore[no-untyped-def]
        cfg = load_config_file(a.config) if a.config else {}
        return build_zone(cfg, a.record, a.block, a.blocklist, a.authoritative, a.block_mode, base)

    try:
        raw = load_config_file(a.config) if a.config else {}
        zone = loader()
        allow = [ipaddress.ip_network(c, strict=False) for c in a.allow] if a.allow else default_allow(a.host)
    except (ConfigError, ValueError) as e:
        print(f"dnslens: {e}", file=sys.stderr)
        return 2
    upstreams = a.upstream or raw.get("upstream") or _default_upstreams(a.host)
    opts = ServerOptions(upstreams=list(upstreams), upstream_timeout=a.upstream_timeout,
                         forward=not a.no_forward, cache_size=a.cache_size, max_ttl=a.max_ttl,
                         allow=allow, log_queries=a.log_queries)
    handler = DNSHandler(zone, opts)
    server = DNSServer(handler, a.host, a.port, a.workers)
    try:
        server.start()
    except OSError as e:
        hint = " (ports below 1024 need root/Administrator; try --port 5353)" if a.port < 1024 else ""
        print(f"dnslens: cannot bind {a.host}:{a.port}: {e}{hint}", file=sys.stderr)
        return 1
    c = zone.counts()
    log = logging.getLogger("dnslens.server")
    log.info("listening on %s:%d (udp+tcp)  records=%d blocked=%d", a.host, server.port, c["records"], c["blocked"])
    log.info("forwarding: %s", ", ".join(opts.upstreams) if opts.forward else "disabled")
    if opts.allow is not None:
        log.info("clients limited to: %s", ", ".join(str(n) for n in opts.allow))
    elif a.host not in ("127.0.0.1", "::1"):
        log.warning("no client ACL on a non-loopback address: this is an open resolver")
    reloader = None
    if a.watch:
        paths = ([a.config] if a.config else []) + list(a.blocklist)
        reloader = Reloader(paths, loader, handler.set_zone).start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if reloader:
            reloader.stop()
        server.stop()
        log.info("stats: %s", " ".join(f"{k}={v}" for k, v in handler.stats.snapshot().items()))
    return 0


def cmd_api(a: argparse.Namespace, st: Style) -> int:
    _setup_logging(a.verbose)
    cfg = ApiConfig(token=a.token, allow_custom=a.allow_custom_resolver, default_timeout=a.timeout,
                    max_concurrent=a.max_concurrent)
    for r in a.resolver or []:
        t = parse_target(r)
        cfg.resolvers[t.name] = t
    try:
        server = ApiServer(cfg, a.host, a.port)
    except OSError as e:
        print(f"dnslens: cannot bind {a.host}:{a.port}: {e}", file=sys.stderr)
        return 1
    log = logging.getLogger("dnslens.api")
    log.info("API listening on http://%s:%d  auth=%s", a.host, server.port, "token" if a.token else "none")
    if not a.token and a.host not in ("127.0.0.1", "::1", "localhost"):
        log.warning("no --token on a non-loopback address: anyone who can reach it can trigger DNS queries")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


COMMANDS = {
    "query": cmd_query, "trace": cmd_trace, "propagate": cmd_propagate, "wait": cmd_wait,
    "bench": cmd_bench, "audit": cmd_audit, "dnssec": cmd_dnssec, "reverse": cmd_reverse,
    "serve": cmd_serve, "api": cmd_api,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    setup_streams()
    args = build_parser().parse_args(argv)
    st = Style(not getattr(args, "no_color", False) and not getattr(args, "json", False) and supports_color())
    try:
        return COMMANDS[args.cmd](args, st)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
