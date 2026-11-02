"""Local DNS server: authoritative overrides + blocklist + caching forwarder (UDP and TCP).

Pure standard library + dnspython. Intended for development, staging, CI mocks and
small private networks, not as an internet-facing recursive resolver.
"""
from __future__ import annotations

import collections
import ipaddress
import json
import logging
import os
import re
import socket
import socketserver
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .core import QueryOpts, query

log = logging.getLogger("dnslens.server")

IN = dns.rdataclass.IN
DEFAULT_UPSTREAMS = ["1.1.1.1", "9.9.9.9"]
PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
    )
]
_IGNORED_BLOCK_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "0.0.0.0",
}


class ConfigError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Zone data
# --------------------------------------------------------------------------- #

Node = Dict[int, dns.rrset.RRset]


def _name(text: str) -> dns.name.Name:
    try:
        return dns.name.from_text(text.strip())
    except dns.exception.DNSException as e:
        raise ConfigError(f"invalid name {text!r}: {e}") from e


_DOMAIN_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$")


def norm_domain(text: str) -> Optional[str]:
    """Lower-case ASCII hostname without wildcard/trailing dot, or None if invalid."""
    t = text.strip().lower().lstrip("*.").rstrip(".")
    if not t or ".." in t or not _DOMAIN_RE.match(t):
        return None
    return t


def _txt_text(data: str) -> str:
    if data.lstrip().startswith('"'):
        return data
    chunks = [data[i : i + 255] for i in range(0, len(data), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)


class ZoneData:
    def __init__(self) -> None:
        self.nodes: Dict[dns.name.Name, Node] = {}
        self.wild: Dict[dns.name.Name, Node] = {}  # keyed by the parent of "*"
        self.ent: Set[dns.name.Name] = set()  # empty non-terminals
        self.auth: List[dns.name.Name] = []
        self.block: Dict[str, int] = {}  # domain -> source id (0 static, -1 custom rule, >0 filter list)
        self.allow: Dict[str, int] = {}
        self.block_mode = "nxdomain"  # or "null"

    # ---- building ----
    def add(self, name_text: str, rtype_text: str, data_text: str, ttl: int) -> None:
        name = _name(name_text)
        try:
            rdtype = dns.rdatatype.from_text(rtype_text.upper())
            if rdtype == dns.rdatatype.TXT:
                data_text = _txt_text(data_text)
            rdata = dns.rdata.from_text(IN, rdtype, data_text, origin=dns.name.root, relativize=False)
        except Exception as e:
            raise ConfigError(f"bad {rtype_text} record for {name_text}: {data_text!r}: {e}") from e
        is_wild = bool(name.labels) and name.labels[0] == b"*"
        table, key = (self.wild, name.parent()) if is_wild else (self.nodes, name)
        node = table.setdefault(key, {})
        rrset = node.get(rdtype)
        if rrset is None:
            rrset = node[rdtype] = dns.rrset.RRset(name, IN, rdtype)  # type: ignore[arg-type]
        rrset.add(rdata, ttl)
        if dns.rdatatype.CNAME in node and len(node) > 1:
            raise ConfigError(f"{name_text}: CNAME cannot coexist with other record types")
        if is_wild:
            self.ent.add(key)
        cur = key
        while cur != dns.name.root:
            cur = cur.parent()
            self.ent.add(cur)

    def add_block(self, text: str, source: int = 0) -> bool:
        d = norm_domain(text)
        if d is None or d in _IGNORED_BLOCK_NAMES:
            return False
        self.block.setdefault(d, source)
        return True

    def add_allow(self, text: str, source: int = 0) -> bool:
        d = norm_domain(text)
        if d is None:
            return False
        self.allow.setdefault(d, source)
        return True

    def copy(self) -> ZoneData:
        z = ZoneData()
        z.block_mode, z.auth, z.ent = self.block_mode, list(self.auth), set(self.ent)
        z.block, z.allow = dict(self.block), dict(self.allow)
        for src, dst in ((self.nodes, z.nodes), (self.wild, z.wild)):
            for k, node in src.items():
                dst[k] = {t: rr.copy() for t, rr in node.items()}
        return z

    # ---- lookup ----
    def find(self, name: dns.name.Name) -> Optional[Node]:
        node = self.nodes.get(name)
        if node is not None:
            return node
        cur = name
        while cur != dns.name.root and len(cur.labels) > 1:
            cur = cur.parent()
            w = self.wild.get(cur)
            if w:
                out: Node = {}
                for t, rr in w.items():
                    new = dns.rrset.RRset(name, IN, t)  # type: ignore[arg-type]
                    new.update(rr)
                    out[t] = new
                return out
        return None

    def is_authoritative(self, name: dns.name.Name) -> bool:
        return any(name.is_subdomain(a) for a in self.auth)

    def match(self, name: dns.name.Name) -> Optional[Tuple[str, str, int]]:
        """Filtering verdict for a name: ('allow'|'block', matched rule domain, source id) or None.

        A rule for a domain also covers its subdomains; allow rules win over block rules.
        """
        if not self.block:
            return None
        s = name.to_text(omit_final_dot=True).lower()
        cands = []
        while True:
            cands.append(s)
            i = s.find(".")
            if i < 0:
                break
            s = s[i + 1 :]
        for c in cands:
            if c in self.allow:
                return ("allow", c, self.allow[c])
        for c in cands:
            if c in self.block:
                return ("block", c, self.block[c])
        return None

    def is_blocked(self, name: dns.name.Name) -> bool:
        m = self.match(name)
        return m is not None and m[0] == "block"

    def counts(self) -> Dict[str, int]:
        n = sum(len(rr) for node in self.nodes.values() for rr in node.values())
        n += sum(len(rr) for node in self.wild.values() for rr in node.values())
        return {"records": n, "blocked": len(self.block), "allowed": len(self.allow)}


_CONFIG_KEYS = {"ttl", "records", "authoritative", "block", "blocklists", "block_mode", "upstream"}


def load_config_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON: {e}") from e
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: top level must be an object")
    unknown = set(cfg) - _CONFIG_KEYS
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
    return cfg


def parse_blocklist(text: str) -> Iterator[str]:
    """Plain domain-per-line or hosts-file format; '#' comments."""
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if not parts:
            continue
        try:
            ipaddress.ip_address(parts[0])
            names = parts[1:]
        except ValueError:
            names = parts[:1]
        yield from names


def build_zone(
    config: Optional[Dict[str, Any]] = None,
    records: Sequence[str] = (),
    blocks: Sequence[str] = (),
    blocklist_files: Sequence[str] = (),
    authoritative: Sequence[str] = (),
    block_mode: Optional[str] = None,
    base_dir: str = ".",
) -> ZoneData:
    cfg = config or {}
    z = ZoneData()
    default_ttl = int(cfg.get("ttl", 300))
    mode = block_mode or cfg.get("block_mode", "nxdomain")
    if mode not in ("nxdomain", "null"):
        raise ConfigError("block_mode must be 'nxdomain' or 'null'")
    z.block_mode = mode

    recs = cfg.get("records", {})
    if not isinstance(recs, dict):
        raise ConfigError("'records' must be an object of name -> {TYPE: data}")
    for name, types in recs.items():
        if not isinstance(types, dict):
            raise ConfigError(f"records[{name!r}] must be an object of TYPE -> data")
        for rtype, val in types.items():
            ttl, data = default_ttl, val
            if isinstance(val, dict):
                ttl, data = int(val.get("ttl", default_ttl)), val.get("data", [])
            for item in [data] if isinstance(data, str) else list(data):
                z.add(name, rtype, str(item), ttl)
    for spec in records:
        parts = spec.split(None, 2)
        if len(parts) != 3:
            raise ConfigError(f"--record must be 'NAME TYPE DATA', got {spec!r}")
        z.add(parts[0], parts[1], parts[2], default_ttl)

    for a in list(cfg.get("authoritative", [])) + list(authoritative):
        z.auth.append(_name(a))
    for b in list(cfg.get("block", [])) + list(blocks):
        if not z.add_block(b) and norm_domain(b) is None:
            raise ConfigError(f"invalid block entry {b!r}")
    files = [os.path.join(base_dir, f) for f in cfg.get("blocklists", [])] + list(blocklist_files)
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for n in parse_blocklist(fh.read()):
                    z.add_block(n)
        except OSError as e:
            raise ConfigError(f"cannot read blocklist {f}: {e}") from e
    return z


# --------------------------------------------------------------------------- #
# Cache / stats
# --------------------------------------------------------------------------- #


@dataclass
class CacheEntry:
    rcode: int
    answer: List[dns.rrset.RRset]
    authority: List[dns.rrset.RRset]
    additional: List[dns.rrset.RRset]
    ad: bool
    stored: float
    ttl: int
    upstream: str = ""

    @classmethod
    def from_message(cls, msg: dns.message.Message, max_ttl: int) -> CacheEntry:
        rcode = msg.rcode()
        if msg.answer:
            ttl = min(rr.ttl for rr in msg.answer)
        else:
            soa = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.SOA]
            ttl = min(soa[0].ttl, soa[0][0].minimum) if soa else 30  # type: ignore[attr-defined]
        return cls(rcode, list(msg.answer), list(msg.authority), list(msg.additional),
                   bool(msg.flags & dns.flags.AD), time.monotonic(), min(ttl, max_ttl))

    @property
    def cacheable(self) -> bool:
        return self.rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) and self.ttl > 0

    def render(self, now: float) -> Optional[Tuple[List[Any], List[Any], List[Any]]]:
        age = int(now - self.stored)
        if age >= self.ttl:
            return None

        def adj(sets: List[dns.rrset.RRset]) -> List[dns.rrset.RRset]:
            out = []
            for rr in sets:
                c = rr.copy()
                c.ttl = max(0, rr.ttl - age)
                out.append(c)
            return out

        return adj(self.answer), adj(self.authority), adj(self.additional)


class Cache:
    def __init__(self, size: int) -> None:
        self.size = size
        self._d: collections.OrderedDict[Any, CacheEntry] = collections.OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Tuple[CacheEntry, Tuple[List[Any], List[Any], List[Any]]]]:
        if self.size <= 0:
            return None
        with self._lock:
            e = self._d.get(key)
            if e is None:
                return None
            r = e.render(time.monotonic())
            if r is None:
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return e, r

    def put(self, key: Any, entry: CacheEntry) -> None:
        if self.size <= 0 or not entry.cacheable:
            return
        with self._lock:
            self._d[key] = entry
            self._d.move_to_end(key)
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()

    def __len__(self) -> int:
        return len(self._d)


class Stats:
    NAMES = ("queries", "local", "blocked", "cache_hit", "upstream", "nxdomain",
             "servfail", "refused", "truncated", "tcp")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._c = {n: 0 for n in self.NAMES}

    def inc(self, name: str) -> None:
        with self._lock:
            self._c[name] += 1

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._c)


# --------------------------------------------------------------------------- #
# Request handling
# --------------------------------------------------------------------------- #


@dataclass
class ServerOptions:
    upstreams: List[str] = field(default_factory=lambda: list(DEFAULT_UPSTREAMS))
    upstream_timeout: float = 2.0
    forward: bool = True
    cache_size: int = 10000
    max_ttl: int = 86400
    allow: Optional[List[Any]] = None  # list of ip_network; None = allow all
    log_queries: bool = False


@dataclass
class QueryEvent:
    """One handled query, delivered to observers (query log, statistics)."""

    ts: float
    client: str
    qname: str
    qtype: str
    rcode: str
    source: str  # local | blocked | cache | upstream | servfail | refused | error | ...
    elapsed_ms: float
    transport: str = "udp"
    upstream: str = ""
    rule: str = ""
    list_id: int = 0
    answers: List[str] = field(default_factory=list)


class DNSHandler:
    def __init__(self, zone: ZoneData, opts: Optional[ServerOptions] = None) -> None:
        self.zone = zone
        self.opts = opts or ServerOptions()
        self.cache = Cache(self.opts.cache_size)
        self.stats = Stats()
        self.observers: List[Callable[[QueryEvent], None]] = []
        self.protection = True
        self.protection_until = 0.0  # epoch seconds; 0 = until re-enabled manually
        self.started = time.time()

    def protection_active(self) -> bool:
        if self.protection:
            return True
        if self.protection_until and time.time() >= self.protection_until:
            self.protection, self.protection_until = True, 0.0
            return True
        return False

    # ---- helpers ----
    def set_zone(self, zone: ZoneData) -> None:
        self.zone = zone  # atomic reference swap
        self.cache.clear()

    def _allowed(self, client: str) -> bool:
        if self.opts.allow is None:
            return True
        try:
            ip = ipaddress.ip_address(client.split("%", 1)[0])
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in n for n in self.opts.allow if n.version == ip.version)

    def _new_response(self, q: dns.message.Message) -> dns.message.Message:
        r = dns.message.make_response(q, recursion_available=self.opts.forward, our_payload=1232)
        if q.edns >= 0:
            r.use_edns(0, ednsflags=(dns.flags.DO if q.ednsflags & dns.flags.DO else 0), payload=1232)
        return r

    def _encode(self, r: dns.message.Message, q: dns.message.Message, tcp: bool) -> bytes:
        if tcp:
            return r.to_wire()
        limit = max(512, min(q.payload, 1232)) if q.edns >= 0 else 512
        try:
            return r.to_wire(max_size=limit)
        except dns.exception.TooBig:
            t = self._new_response(q)
            t.flags |= dns.flags.TC | (r.flags & dns.flags.AA)
            t.set_rcode(r.rcode())
            self.stats.inc("truncated")
            return t.to_wire()

    # ---- entry point ----
    def respond(self, wire: bytes, client: str, tcp: bool = False) -> Optional[bytes]:
        t0 = time.perf_counter()
        try:
            q = dns.message.from_wire(wire)
        except Exception:
            if len(wire) >= 12:  # FORMERR with the original id
                return wire[:2] + struct.pack("!H", 0x8001) + b"\x00" * 8
            return None
        if q.flags & dns.flags.QR:
            return None
        self.stats.inc("queries")
        if tcp:
            self.stats.inc("tcp")
        info: Dict[str, str] = {}
        try:
            r, source = self._build(q, client, info)
        except Exception:
            log.exception("internal error handling query from %s", client)
            r = self._new_response(q)
            r.set_rcode(dns.rcode.SERVFAIL)
            source = "error"
        if source in ("refused",):
            self.stats.inc("refused")
        if r.rcode() == dns.rcode.NXDOMAIN:
            self.stats.inc("nxdomain")
        if r.rcode() == dns.rcode.SERVFAIL:
            self.stats.inc("servfail")
        if self.opts.log_queries and q.question:
            qq = q.question[0]
            log.info("%s %s %s -> %s %s %.1fms", client, qq.name.to_text(),
                     dns.rdatatype.to_text(qq.rdtype), dns.rcode.to_text(r.rcode()), source,
                     (time.perf_counter() - t0) * 1000)
        if self.observers and q.question:
            self._notify(q, r, client, source, info, tcp, (time.perf_counter() - t0) * 1000)
        return self._encode(r, q, tcp)

    def _notify(self, q: dns.message.Message, r: dns.message.Message, client: str, source: str,
                info: Dict[str, str], tcp: bool, ms: float) -> None:
        try:
            qq = q.question[0]
            answers = []
            for rr in r.answer:
                t = dns.rdatatype.to_text(rr.rdtype)
                for rd in rr:
                    answers.append(f"{t} {rd.to_text()}"[:200])
                    if len(answers) >= 8:
                        break
            ev = QueryEvent(
                ts=time.time(), client=client.split("%", 1)[0], qname=qq.name.to_text(omit_final_dot=True).lower() or ".",
                qtype=dns.rdatatype.to_text(qq.rdtype), rcode=dns.rcode.to_text(r.rcode()), source=source,
                elapsed_ms=ms, transport="tcp" if tcp else "udp", upstream=info.get("upstream", ""),
                rule=info.get("rule", ""), list_id=int(info.get("list", "0") or 0), answers=answers,
            )
            for ob in self.observers:
                ob(ev)
        except Exception:
            log.debug("observer failed", exc_info=True)

    def _build(self, q: dns.message.Message, client: str, info: Optional[Dict[str, str]] = None) -> Tuple[dns.message.Message, str]:
        info = info if info is not None else {}
        r = self._new_response(q)
        if not self._allowed(client):
            r.set_rcode(dns.rcode.REFUSED)
            return r, "refused"
        if q.opcode() != dns.opcode.QUERY:
            r.set_rcode(dns.rcode.NOTIMP)
            return r, "notimp"
        if len(q.question) != 1:
            r.set_rcode(dns.rcode.FORMERR)
            return r, "formerr"
        qn = q.question[0]
        if qn.rdclass != IN or qn.rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR, dns.rdatatype.OPT):
            r.set_rcode(dns.rcode.REFUSED)
            return r, "refused"
        zone = self.zone
        name, rtype = qn.name, qn.rdtype
        do = bool(q.ednsflags & dns.flags.DO) if q.edns >= 0 else False

        handled = self._local(zone, r, name, rtype, do)
        if handled:
            self.stats.inc("local")
            return r, "local"


        verdict = zone.match(name) if self.protection_active() else None
        if verdict is not None and verdict[0] == "block":
            info["rule"], info["list"] = verdict[1], str(verdict[2])
            self.stats.inc("blocked")
            if zone.block_mode == "null" and rtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                addr = "0.0.0.0" if rtype == dns.rdatatype.A else "::"
                rr = dns.rrset.from_text(name, 60, IN, rtype, addr)
                r.answer.append(rr)
            elif zone.block_mode == "nxdomain":
                r.set_rcode(dns.rcode.NXDOMAIN)
            return r, "blocked"

        if not self.opts.forward:
            r.set_rcode(dns.rcode.REFUSED)
            return r, "refused"
        entry, from_cache = self._forward(name, rtype, do, info)
        if entry is None:
            r.set_rcode(dns.rcode.SERVFAIL)
            return r, "servfail"
        self._fill(r, entry, q, do, from_cache)
        return r, "cache" if from_cache else "upstream"

    # ---- local data ----
    def _local(self, zone: ZoneData, r: dns.message.Message, name: dns.name.Name, rtype: int, do: bool) -> bool:
        cur = name
        tail: Optional[dns.name.Name] = None
        for _ in range(9):
            node = zone.find(cur)
            if node is None:
                if cur == name:
                    if zone.is_authoritative(cur):
                        r.flags |= dns.flags.AA
                        if cur not in zone.ent:
                            r.set_rcode(dns.rcode.NXDOMAIN)
                        return True
                    return False
                tail = cur  # CNAME target outside local data
                break
            r.flags |= dns.flags.AA
            if rtype == dns.rdatatype.ANY:
                r.answer.extend(node.values())
                break
            if rtype in node:
                r.answer.append(node[rtype])
                break
            cn = node.get(dns.rdatatype.CNAME)
            if cn is not None:
                r.answer.append(cn)
                cur = cn[0].target  # type: ignore[attr-defined]
                continue
            break  # NODATA
        else:
            r.set_rcode(dns.rcode.SERVFAIL)
            return True
        if tail is not None and self.opts.forward and rtype != dns.rdatatype.CNAME:
            entry, from_cache = self._forward(tail, rtype, do)
            if entry is not None:
                rendered = entry.render(time.monotonic()) if from_cache else None
                answer = rendered[0] if rendered else entry.answer
                r.answer.extend(answer)
                r.set_rcode(entry.rcode)  # type: ignore[arg-type]
                r.flags &= ~dns.flags.AA
        return True

    # ---- forwarding ----
    def _forward(self, name: dns.name.Name, rtype: int, do: bool,
                 info: Optional[Dict[str, str]] = None) -> Tuple[Optional[CacheEntry], bool]:
        key = (name, rtype, do)
        hit = self.cache.get(key)
        if hit is not None:
            self.stats.inc("cache_hit")
            entry, (ans, auth, add) = hit
            copy = CacheEntry(entry.rcode, ans, auth, add, entry.ad, entry.stored, entry.ttl, entry.upstream)
            if info is not None:
                info["upstream"] = entry.upstream
            return copy, True
        qopts = QueryOpts(timeout=self.opts.upstream_timeout, retries=0, dnssec=do)
        for up in self.opts.upstreams:
            a = query(name.to_text(), dns.rdatatype.to_text(rtype), up, qopts, rd=True)  # type: ignore[arg-type]
            if a.error is None and a.message is not None and a.message.rcode() not in (
                dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.NOTIMP, dns.rcode.FORMERR
            ):
                self.stats.inc("upstream")
                entry = CacheEntry.from_message(a.message, self.opts.max_ttl)
                entry.upstream = up
                if info is not None:
                    info["upstream"] = up
                self.cache.put(key, entry)
                return entry, False
            log.debug("upstream %s failed for %s: %s", up, name, a.error or a.rcode)
        return None, False

    @staticmethod
    def _fill(r: dns.message.Message, e: CacheEntry, q: dns.message.Message, do: bool, from_cache: bool) -> None:
        r.set_rcode(e.rcode)  # type: ignore[arg-type]
        r.answer.extend(e.answer)
        r.authority.extend(e.authority)
        r.additional.extend(e.additional)
        if e.ad and (do or q.flags & dns.flags.AD):
            r.flags |= dns.flags.AD
        if not do:  # never leak DNSSEC records to clients that didn't ask
            for sec in (r.answer, r.authority, r.additional):
                sec[:] = [rr for rr in sec if rr.rdtype not in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)]


# --------------------------------------------------------------------------- #
# Network transports
# --------------------------------------------------------------------------- #


def _recvn(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(10)
        dnsh: DNSHandler = self.server.dns  # type: ignore[attr-defined]
        try:
            while True:
                hdr = _recvn(sock, 2)
                if not hdr:
                    return
                data = _recvn(sock, struct.unpack("!H", hdr)[0])
                if data is None:
                    return
                out = dnsh.respond(data, self.client_address[0], tcp=True)
                if out is None:
                    return
                sock.sendall(struct.pack("!H", len(out)) + out)
        except (OSError, socket.timeout):
            return


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCPServer6(_TCPServer):
    address_family = socket.AF_INET6


class DNSServer:
    def __init__(self, handler: DNSHandler, host: str = "127.0.0.1", port: int = 5353, workers: int = 32) -> None:
        self.handler = handler
        self.host = host
        self._req_port = port
        self.workers = workers
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._usock: Optional[socket.socket] = None
        self._tcp: Optional[socketserver.ThreadingTCPServer] = None
        self._pool: Optional[ThreadPoolExecutor] = None
        self.port = port

    def start(self) -> DNSServer:
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        us = socket.socket(fam, socket.SOCK_DGRAM)
        us.bind((self.host, self._req_port))
        us.settimeout(0.3)
        self.port = us.getsockname()[1]
        self._usock = us
        cls = _TCPServer6 if fam == socket.AF_INET6 else _TCPServer
        try:
            self._tcp = cls((self.host, self.port), _TCPHandler)
        except OSError:
            us.close()
            raise
        self._tcp.dns = self.handler  # type: ignore[attr-defined]
        self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="dnslens-udp")
        for target in (self._udp_loop, lambda: self._tcp.serve_forever(poll_interval=0.2)):  # type: ignore[union-attr]
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def _udp_loop(self) -> None:
        assert self._usock is not None and self._pool is not None
        while not self._stop.is_set():
            try:
                data, addr = self._usock.recvfrom(65535)
            except socket.timeout:
                continue
            except ConnectionResetError:  # Windows: ICMP port-unreachable from a previous reply
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.05)
                continue
            self._pool.submit(self._udp_work, data, addr)

    def _udp_work(self, data: bytes, addr: Tuple[Any, ...]) -> None:
        try:
            out = self.handler.respond(data, addr[0], tcp=False)
            if out and self._usock is not None:
                self._usock.sendto(out, addr)
        except OSError:
            pass
        except Exception:
            log.exception("udp worker error")

    def stop(self) -> None:
        self._stop.set()
        if self._tcp is not None:
            self._tcp.shutdown()
            self._tcp.server_close()
        if self._usock is not None:
            self._usock.close()
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
        for t in self._threads:
            t.join(1)

    def __enter__(self) -> DNSServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


class Reloader:
    """Poll files for changes (portable: no inotify) and rebuild the zone atomically."""

    def __init__(self, paths: Sequence[str], loader: Callable[[], ZoneData],
                 apply: Callable[[ZoneData], None], interval: float = 1.0) -> None:
        self.paths, self.loader, self.apply, self.interval = list(paths), loader, apply, interval
        self._stop = threading.Event()
        self._sig = self._signature()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _signature(self) -> Tuple[Any, ...]:
        sig: List[Tuple[Any, ...]] = []
        for p in self.paths:
            try:
                st = os.stat(p)
                sig.append((p, st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append((p, None, None))
        return tuple(sig)

    def check(self) -> bool:
        sig = self._signature()
        if sig == self._sig:
            return False
        self._sig = sig
        try:
            self.apply(self.loader())
            log.info("configuration reloaded")
            return True
        except ConfigError as e:
            log.error("reload failed, keeping previous configuration: %s", e)
            return False

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.check()

    def start(self) -> Reloader:
        self._t.start()
        return self

    def stop(self) -> None:
        self._stop.set()


def default_allow(host: str) -> Optional[List[Any]]:
    """Loopback bind needs no ACL; anything wider defaults to private networks only."""
    try:
        if ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass
    return list(PRIVATE_NETS)
