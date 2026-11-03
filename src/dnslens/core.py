# File: dnslens/src/dnslens/core.py
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:22:18 SE Asia Standard Time
# Description:
# License: GPL-3.0

"""Core DNS primitives: query execution, targets, answers, findings."""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, NamedTuple, Optional, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #


class Target(NamedTuple):
    """A resolver to talk to. ``address`` None means the OS-configured resolvers."""

    name: str
    address: Optional[str]


SYSTEM = Target("system", None)

PUBLIC_RESOLVERS: List[Target] = [
    Target("google", "8.8.8.8"),
    Target("google-2", "8.8.4.4"),
    Target("cloudflare", "1.1.1.1"),
    Target("cloudflare-2", "1.0.0.1"),
    Target("quad9", "9.9.9.9"),
    Target("opendns", "208.67.222.222"),
    Target("adguard", "94.140.14.14"),
    Target("cleanbrowsing", "185.228.168.9"),
    Target("verisign", "64.6.64.6"),
    Target("dns.watch", "84.200.69.80"),
    Target("yandex", "77.88.8.8"),
]

DOH_RESOLVERS: List[Target] = [
    Target("cloudflare", "https://cloudflare-dns.com/dns-query"),
    Target("google", "https://dns.google/dns-query"),
    Target("quad9", "https://dns.quad9.net/dns-query"),
]


def parse_target(text: str) -> Target:
    """``ADDR`` or ``NAME=ADDR`` (ADDR may be an IP, hostname or DoH URL)."""
    if "=" in text and "://" not in text.split("=", 1)[0]:
        name, addr = text.split("=", 1)
        return Target(name.strip(), addr.strip())
    return Target(text, text)


def system_nameservers() -> List[str]:
    try:
        res = dns.resolver.Resolver(configure=True)
        servers = [str(s) for s in res.nameservers]
        if servers:
            return servers
    except dns.exception.DNSException:
        pass
    return ["1.1.1.1", "8.8.8.8"]


# --------------------------------------------------------------------------- #
# Options / results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QueryOpts:
    timeout: float = 3.0
    retries: int = 1
    transport: str = "udp"  # udp | tcp | tls | https
    port: Optional[int] = None
    dnssec: bool = False


@dataclass
class Record:
    name: str
    ttl: int
    type: str
    data: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ttl": self.ttl, "type": self.type, "data": self.data}


_TXT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def txt_join(data: str) -> str:
    parts = _TXT_RE.findall(data)
    return "".join(parts) if parts else data


def norm_value(rtype: str, data: str) -> str:
    if rtype == "TXT":
        return txt_join(data)
    return data.strip().lower().rstrip(".")


@dataclass
class Answer:
    server: str
    qname: str
    rdtype: str
    rcode: str = ""
    flags: str = ""
    records: List[Record] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    transport: str = "udp"
    message: Optional[dns.message.Message] = field(default=None, repr=False, compare=False)

    @property
    def ok(self) -> bool:
        """Got a well-formed NOERROR response."""
        return self.error is None and self.rcode == "NOERROR"

    @property
    def responded(self) -> bool:
        """Got a definitive answer (NOERROR or NXDOMAIN)."""
        return self.error is None and self.rcode in ("NOERROR", "NXDOMAIN")

    @property
    def min_ttl(self) -> Optional[int]:
        ttls = [r.ttl for r in self.records if r.type == self.rdtype]
        return min(ttls) if ttls else None

    def values(self) -> FrozenSet[str]:
        """Normalised data of records matching the queried type (CNAME chain excluded)."""
        if self.rdtype == "ANY":
            return frozenset(norm_value(r.type, r.data) for r in self.records if r.type != "RRSIG")
        return frozenset(norm_value(r.type, r.data) for r in self.records if r.type == self.rdtype)

    def rdatas(self, rdtype: str) -> List[Any]:
        """Raw rdata objects of ``rdtype`` from the answer section."""
        if self.message is None:
            return []
        want = dns.rdatatype.from_text(rdtype)
        return [rd for rrset in self.message.answer if rrset.rdtype == want for rd in rrset]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "qname": self.qname,
            "type": self.rdtype,
            "rcode": self.rcode,
            "flags": self.flags,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "transport": self.transport,
            "error": self.error,
            "records": [r.to_dict() for r in self.records],
        }


# Finding levels shared by audit / dnssec
OK, INFO, WARN, FAIL = "OK", "INFO", "WARN", "FAIL"


@dataclass
class Finding:
    level: str
    check: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"level": self.level, "check": self.check, "message": self.message}


# --------------------------------------------------------------------------- #
# Query execution
# --------------------------------------------------------------------------- #


def _to_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return str(socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)[0][4][0])


def _send(q: dns.message.Message, server: str, opts: QueryOpts) -> Tuple[dns.message.Message, str]:
    t = opts.transport
    if t == "https":
        return dns.query.https(q, server, timeout=opts.timeout), "https"
    port = opts.port
    if "#" in server:  # "ip#port" selects a non-standard port
        server, _, p = server.rpartition("#")
        port = int(p)
    where = _to_ip(server)
    if t == "udp":
        resp, used_tcp = dns.query.udp_with_fallback(q, where, timeout=opts.timeout, port=port or 53)
        return resp, ("udp+tcp" if used_tcp else "udp")
    if t == "tcp":
        return dns.query.tcp(q, where, timeout=opts.timeout, port=port or 53), "tcp"
    if t == "tls":
        return dns.query.tls(q, where, timeout=opts.timeout, port=port or 853), "tls"
    raise ValueError(f"unknown transport {t!r}")


def _query_one(qname: str, rdtype: str, server: str, opts: QueryOpts, rd: bool) -> Answer:
    ans = Answer(server=server, qname=qname, rdtype=rdtype.upper(), transport=opts.transport)
    start = time.perf_counter()
    try:
        rdt = dns.rdatatype.from_text(ans.rdtype)
        q = dns.message.make_query(
            qname,
            rdt,
            use_edns=0,
            payload=1232,
            want_dnssec=opts.dnssec,
            flags=dns.flags.RD if rd else 0,
        )
    except Exception as e:  # bad name / type
        ans.error = f"bad query: {e}"
        return ans

    resp: Optional[dns.message.Message] = None
    err: Optional[str] = None
    for _ in range(max(0, opts.retries) + 1):
        try:
            resp, ans.transport = _send(q, server, opts)
            err = None
            break
        except dns.exception.Timeout:
            err = "timeout"
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            break
    ans.elapsed_ms = (time.perf_counter() - start) * 1000.0
    if resp is None:
        ans.error = err or "no response"
        return ans

    ans.message = resp
    ans.rcode = dns.rcode.to_text(resp.rcode())
    ans.flags = dns.flags.to_text(resp.flags)
    for rrset in resp.answer:
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            ans.records.append(Record(rrset.name.to_text(), rrset.ttl, rtype, rdata.to_text()))
    return ans


def query(
    qname: str,
    rdtype: str = "A",
    server: Optional[str] = None,
    opts: QueryOpts = QueryOpts(),
    rd: bool = True,
) -> Answer:
    """Send one query. ``server=None`` tries each OS resolver until one answers."""
    servers = [server] if server else system_nameservers()
    last: Optional[Answer] = None
    for s in servers:
        a = _query_one(qname, rdtype, s, opts, rd)
        if a.error is None:
            return a
        last = a
    assert last is not None
    return last


def query_target(
    target: Target, qname: str, rdtype: str, opts: QueryOpts, rd: bool = True
) -> Answer:
    return query(qname, rdtype, target.address, opts, rd)
