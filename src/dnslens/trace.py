"""Iterative resolution from the root servers (like ``dig +trace``)."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

import dns.name
import dns.rdatatype

from .core import Answer, QueryOpts, query

ROOT_SERVERS: List[Tuple[str, str]] = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
]


@dataclass
class Hop:
    zone: str
    server: str
    rtt_ms: float
    outcome: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "zone": self.zone,
            "server": self.server,
            "rtt_ms": round(self.rtt_ms, 2),
            "outcome": self.outcome,
            "detail": self.detail,
        }


@dataclass
class TraceResult:
    qname: str
    rdtype: str
    hops: List[Hop] = field(default_factory=list)
    final: Optional[Answer] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.final is not None and bool(self.final.records)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "qname": self.qname,
            "type": self.rdtype,
            "ok": self.ok,
            "error": self.error,
            "hops": [h.to_dict() for h in self.hops],
            "final": self.final.to_dict() if self.final else None,
        }


def _label(name: str, ip: str) -> str:
    return f"{name} ({ip})" if name != ip else ip


def trace(
    qname: str,
    rdtype: str = "A",
    opts: QueryOpts = QueryOpts(),
    roots: Optional[Sequence[Tuple[str, str]]] = None,
    max_hops: int = 30,
    max_cnames: int = 8,
) -> TraceResult:
    roots = list(roots or ROOT_SERVERS)
    res = TraceResult(qname=qname, rdtype=rdtype.upper())
    want = dns.rdatatype.from_text(res.rdtype)
    sys_opts = replace(opts, port=None, transport="udp")
    target = qname
    zone = "."
    servers: List[Tuple[str, str]] = list(roots)
    cnames = 0

    for _ in range(max_hops):
        ans: Optional[Answer] = None
        for sname, ip in servers[:6]:
            a = query(target, res.rdtype, ip, opts, rd=False)
            if a.error is not None:
                res.hops.append(Hop(zone, _label(sname, ip), a.elapsed_ms, "error", a.error))
                continue
            ans = a
            break
        if ans is None or ans.message is None:
            res.error = f"no server answered for zone {zone}"
            return res
        msg = ans.message
        srv = _label(*next((s for s in servers if s[1] == ans.server), (ans.server, ans.server)))

        if msg.answer:
            has_target = any(rr.rdtype == want for rr in msg.answer)
            cname_sets = [rr for rr in msg.answer if rr.rdtype == dns.rdatatype.CNAME]
            if has_target or want == dns.rdatatype.CNAME or not cname_sets:
                res.hops.append(Hop(zone, srv, ans.elapsed_ms, "answer", f"{len(ans.records)} record(s)"))
                res.final = ans
                return res
            cnames += 1
            nxt = cname_sets[-1][0].target.to_text()  # type: ignore[attr-defined]
            res.hops.append(Hop(zone, srv, ans.elapsed_ms, "cname", f"-> {nxt}"))
            if cnames > max_cnames:
                res.error = "CNAME chain too long"
                return res
            target, zone, servers = nxt, ".", list(roots)
            continue

        ns_sets = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
        if not ns_sets:
            outcome = "nxdomain" if ans.rcode == "NXDOMAIN" else "nodata"
            res.hops.append(Hop(zone, srv, ans.elapsed_ms, outcome, ans.rcode))
            res.final = ans
            return res

        ns_set = ns_sets[0]
        new_zone = ns_set.name.to_text()
        if not (
            ns_set.name.is_subdomain(dns.name.from_text(zone)) and new_zone != zone
        ):
            res.hops.append(Hop(zone, srv, ans.elapsed_ms, "error", f"bad referral to {new_zone}"))
            res.error = f"referral loop or lame delegation at {zone}"
            return res

        ns_names = [rd.target.to_text() for rd in ns_set]  # type: ignore[attr-defined]
        glue: Dict[str, List[str]] = {}
        for rr in msg.additional:
            if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                glue.setdefault(rr.name.to_text().lower(), []).extend(rd.address for rd in rr)  # type: ignore[attr-defined]
        v4: List[Tuple[str, str]] = []
        v6: List[Tuple[str, str]] = []
        for n in ns_names:
            for ip in glue.get(n.lower(), []):
                (v6 if ":" in ip else v4).append((n.rstrip("."), ip))
        new_servers = v4 + v6
        if not new_servers:  # glueless delegation: resolve NS names ourselves
            for n in ns_names[:4]:
                r = query(n, "A", None, sys_opts)
                new_servers += [(n.rstrip("."), x.data) for x in r.records if x.type == "A"]
        res.hops.append(
            Hop(zone, srv, ans.elapsed_ms, "referral", f"-> {new_zone} ({len(ns_names)} NS)")
        )
        if not new_servers:
            res.error = f"no usable nameserver addresses for {new_zone}"
            return res
        zone, servers = new_zone, new_servers

    res.error = "max hops exceeded"
    return res
