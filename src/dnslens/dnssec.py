"""Zone-level DNSSEC sanity check: DS <-> DNSKEY match and DNSKEY RRSIG validity."""
from __future__ import annotations

import time
from dataclasses import replace
from typing import List, Optional

import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rdatatype

from .core import FAIL, INFO, OK, WARN, Finding, QueryOpts, query


def check_dnssec(
    domain: str, server: Optional[str] = None, opts: QueryOpts = QueryOpts()
) -> List[Finding]:
    f: List[Finding] = []
    sopts = replace(opts, dnssec=True)
    name = dns.name.from_text(domain)

    ds_ans = query(domain, "DS", server, sopts)
    if ds_ans.error:
        return [Finding(FAIL, "dnssec", f"DS lookup failed: {ds_ans.error}")]
    ds_set = ds_ans.rdatas("DS")
    if not ds_set:
        return [Finding(INFO, "dnssec", "no DS at parent: zone is not DNSSEC-signed")]
    f.append(Finding(OK, "dnssec", f"{len(ds_set)} DS record(s) published at parent"))
    if ds_ans.message is not None and ds_ans.message.flags & dns.flags.AD:
        f.append(Finding(OK, "dnssec", "resolver validated the DS answer (AD flag set)"))

    key_ans = query(domain, "DNSKEY", server, sopts)
    if key_ans.error or key_ans.message is None:
        f.append(Finding(FAIL, "dnssec", f"DNSKEY lookup failed: {key_ans.error}"))
        return f
    msg = key_ans.message
    keyset = next((r for r in msg.answer if r.rdtype == dns.rdatatype.DNSKEY), None)
    sigset = next(
        (
            r
            for r in msg.answer
            if r.rdtype == dns.rdatatype.RRSIG and r.covers == dns.rdatatype.DNSKEY
        ),
        None,
    )
    if keyset is None:
        f.append(
            Finding(FAIL, "dnssec", "DS exists but no DNSKEY served: validating resolvers will SERVFAIL")
        )
        return f

    matched = False
    for ds in ds_set:
        for key in keyset:
            if dns.dnssec.key_id(key) != ds.key_tag or key.algorithm != ds.algorithm:
                continue
            try:
                made = dns.dnssec.make_ds(name, key, dns.dnssec.DSDigest(ds.digest_type))
            except (ValueError, dns.exception.DNSException):
                continue
            if made == ds:
                matched = True
    if matched:
        f.append(Finding(OK, "dnssec", "a DS record matches a published DNSKEY"))
    else:
        f.append(Finding(FAIL, "dnssec", "no DS record matches any DNSKEY (broken chain of trust)"))

    if sigset is None:
        f.append(Finding(FAIL, "dnssec", "DNSKEY RRset is not signed"))
        return f
    try:
        dns.dnssec.validate(keyset, sigset, {name: keyset})
        f.append(Finding(OK, "dnssec", "DNSKEY RRSIG validates"))
    except dns.dnssec.ValidationFailure as e:
        f.append(Finding(FAIL, "dnssec", f"DNSKEY RRSIG invalid: {e}"))
    except Exception as e:  # missing crypto backend, unsupported algorithm...
        f.append(Finding(WARN, "dnssec", f"could not validate RRSIG: {type(e).__name__}: {e}"))

    left = min(s.expiration for s in sigset) - time.time()
    days = left / 86400
    if left <= 0:
        f.append(Finding(FAIL, "dnssec", "signatures are expired"))
    elif days < 3:
        f.append(Finding(WARN, "dnssec", f"signatures expire in {days:.1f} days"))
    else:
        f.append(Finding(OK, "dnssec", f"signatures valid for another {days:.0f} days"))
    return f
