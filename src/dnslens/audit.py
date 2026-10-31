"""Domain health audit: delegation, SOA sync, apex CNAME, mail auth, CAA, DNSSEC."""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Sequence, Set, Tuple

from .core import (
    FAIL,
    INFO,
    OK,
    WARN,
    Answer,
    Finding,
    QueryOpts,
    query,
    txt_join,
)
from .dnssec import check_dnssec

QFn = Callable[[str, str], Answer]


def _txt(ans: Answer) -> List[str]:
    return [txt_join(r.data) for r in ans.records if r.type == "TXT"]


def spf_record(domain: str, q: QFn) -> Optional[str]:
    recs = [t for t in _txt(q(domain, "TXT")) if t.lower().startswith("v=spf1")]
    return recs[0] if recs else None


_DIRECT = re.compile(r"^(a|mx|ptr)(:|/|$)")


def spf_lookups(domain: str, q: QFn, depth: int = 0, seen: Optional[Set[str]] = None) -> int:
    """Count DNS-lookup-causing terms (RFC 7208 limit: 10), following include/redirect."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain.lower() in seen:
        return 0
    seen.add(domain.lower())
    rec = spf_record(domain, q)
    if not rec:
        return 0
    n = 0
    for part in rec.split()[1:]:
        low = part.lower().lstrip("+-~?")
        if low.startswith(("include:", "redirect=")):
            n += 1 + spf_lookups(part.split(":", 1)[-1].split("=", 1)[-1], q, depth + 1, seen)
        elif low.startswith("exists:") or _DIRECT.match(low):
            n += 1
    return n


def _soa_serial(ans: Answer) -> Optional[int]:
    rd = ans.rdatas("SOA")
    return int(rd[0].serial) if rd else None


def _check_delegation(domain: str, q: QFn, opts: QueryOpts) -> List[Finding]:
    f: List[Finding] = []
    ns_ans = q(domain, "NS")
    if ns_ans.error:
        return [Finding(FAIL, "ns", f"NS lookup failed: {ns_ans.error}")]
    if ns_ans.rcode == "NXDOMAIN":
        return [Finding(FAIL, "ns", "domain does not exist (NXDOMAIN)")]
    names = sorted({r.data for r in ns_ans.records if r.type == "NS"})
    if not names:
        return [Finding(WARN, "ns", "no NS records at this name (not a zone apex?)")]
    if len(names) < 2:
        f.append(Finding(WARN, "ns", f"only {len(names)} nameserver: no redundancy"))
    else:
        f.append(Finding(OK, "ns", f"{len(names)} nameservers: {', '.join(n.rstrip('.') for n in names)}"))

    addrs: List[Tuple[str, str]] = []
    for n in names:
        found = False
        for rt in ("A", "AAAA"):
            for r in q(n, rt).records:
                if r.type == rt:
                    addrs.append((n.rstrip("."), r.data))
                    found = True
        if not found:
            f.append(Finding(FAIL, "ns", f"{n.rstrip('.')} has no A/AAAA address"))

    serials = {}
    for n, ip in addrs:
        a = query(domain, "SOA", ip, opts, rd=False)
        v6 = ":" in ip
        if a.error:
            lvl = WARN if v6 else FAIL
            note = " (may be missing local IPv6 connectivity)" if v6 else ""
            f.append(Finding(lvl, "ns", f"{n} [{ip}] unreachable: {a.error}{note}"))
            continue
        if "AA" not in a.flags.split():
            f.append(Finding(FAIL, "ns", f"{n} [{ip}] answered non-authoritatively (lame delegation)"))
            continue
        serial = _soa_serial(a)
        if serial is None:
            f.append(Finding(FAIL, "ns", f"{n} [{ip}] returned no SOA ({a.rcode})"))
            continue
        serials[f"{n} [{ip}]"] = serial
    if serials:
        if len(set(serials.values())) == 1:
            f.append(Finding(OK, "soa", f"serial {next(iter(serials.values()))} consistent on all {len(serials)} reachable servers"))
        else:
            detail = ", ".join(f"{k}={v}" for k, v in serials.items())
            f.append(Finding(WARN, "soa", f"serial mismatch between nameservers: {detail}"))
    return f


def _check_mail(domain: str, q: QFn, dkim: Sequence[str]) -> List[Finding]:
    f: List[Finding] = []
    mx = [r.data for r in q(domain, "MX").records if r.type == "MX"]
    has_mail = bool(mx) and mx != ["0 ."]
    if has_mail:
        f.append(Finding(OK, "mx", f"{len(mx)} MX record(s)"))
    else:
        f.append(Finding(INFO, "mx", "no MX (domain does not receive mail)"))
    miss = WARN if has_mail else INFO

    spf = spf_record(domain, q)
    if spf is None:
        f.append(Finding(miss, "spf", "no SPF record"))
    else:
        n_spf = len([t for t in _txt(q(domain, "TXT")) if t.lower().startswith("v=spf1")])
        if n_spf > 1:
            f.append(Finding(FAIL, "spf", "multiple SPF records (permerror)"))
        terms = [p.lower() for p in spf.split()[1:]]
        if "+all" in terms or "all" in terms:
            f.append(Finding(FAIL, "spf", "SPF ends in +all: anyone may send as this domain"))
        elif "?all" in terms:
            f.append(Finding(WARN, "spf", "SPF ends in ?all (neutral)"))
        elif "~all" in terms or "-all" in terms or any(t.startswith("redirect=") for t in terms):
            f.append(Finding(OK, "spf", "SPF present with a restrictive policy"))
        else:
            f.append(Finding(WARN, "spf", "SPF has no terminating 'all' or redirect"))
        n = spf_lookups(domain, q)
        if n > 10:
            f.append(Finding(FAIL, "spf", f"{n} DNS lookups exceeds the limit of 10 (permerror)"))
        else:
            f.append(Finding(OK, "spf", f"{n}/10 DNS lookups"))

    dm = [t for t in _txt(q(f"_dmarc.{domain}", "TXT")) if t.upper().startswith("V=DMARC1")]
    if not dm:
        f.append(Finding(miss, "dmarc", "no DMARC record"))
    else:
        tags = {}
        for part in dm[0].split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip().lower()
        pol = tags.get("p", "")
        if pol in ("quarantine", "reject"):
            f.append(Finding(OK, "dmarc", f"policy p={pol}"))
        else:
            f.append(Finding(WARN, "dmarc", f"policy p={pol or '?'} (monitoring only)"))
        if "rua" not in tags:
            f.append(Finding(INFO, "dmarc", "no rua= reporting address"))

    for sel in dkim:
        recs = _txt(q(f"{sel}._domainkey.{domain}", "TXT"))
        if any("p=" in t for t in recs):
            f.append(Finding(OK, "dkim", f"selector '{sel}' has a key"))
        else:
            f.append(Finding(FAIL, "dkim", f"selector '{sel}' not found"))
    return f


def audit(
    domain: str,
    server: Optional[str] = None,
    opts: QueryOpts = QueryOpts(),
    dkim_selectors: Sequence[str] = (),
) -> List[Finding]:
    def q(name: str, rtype: str) -> Answer:
        return query(name, rtype, server, opts)

    findings = _check_delegation(domain, q, opts)
    if any(x.level == FAIL and "NXDOMAIN" in x.message for x in findings):
        return findings

    cname = q(domain, "CNAME")
    if any(r.type == "CNAME" and r.name.rstrip(".").lower() == domain.rstrip(".").lower() for r in cname.records):
        findings.append(Finding(FAIL, "apex", "CNAME at zone apex conflicts with SOA/NS records"))

    findings += _check_mail(domain, q, dkim_selectors)

    caa = q(domain, "CAA")
    if any(r.type == "CAA" for r in caa.records):
        findings.append(Finding(OK, "caa", "CAA records present"))
    else:
        findings.append(Finding(INFO, "caa", "no CAA records (any CA may issue certificates)"))

    findings += check_dnssec(domain, server, opts)
    return findings
