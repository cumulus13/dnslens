import time

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rrset
import pytest
from conftest import zone_handler
from cryptography.hazmat.primitives.asymmetric import ec

from dnslens.audit import audit, spf_lookups
from dnslens.core import QueryOpts, query
from dnslens.dnssec import check_dnssec

SOA = "ns1.example.test. admin.example.test. 7 3600 600 604800 300"
ZONE = {
    ("example.test.", "SOA"): [SOA],
    ("example.test.", "NS"): ["ns1.example.test."],
    ("ns1.example.test.", "A"): ["127.0.0.1"],
    ("example.test.", "MX"): ["10 mail.example.test."],
    ("example.test.", "TXT"): ['"v=spf1 include:_spf.example.test a -all"'],
    ("_spf.example.test.", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 mx ~all"'],
    ("_dmarc.example.test.", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:d@example.test"'],
    ("sel._domainkey.example.test.", "TXT"): ['"v=DKIM1; k=rsa; p=MIGf"'],
    ("example.test.", "CAA"): ['0 issue "letsencrypt.org"'],
}


def levels(findings):
    return {(f.check, f.level) for f in findings}


def test_audit_healthy(serve):
    s = serve(zone_handler(ZONE))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    f = audit("example.test", "127.0.0.1", o, ["sel", "missing"])
    lv = levels(f)
    assert ("soa", "OK") in lv
    assert ("spf", "OK") in lv and ("dmarc", "OK") in lv and ("caa", "OK") in lv
    assert ("dkim", "OK") in lv and ("dkim", "FAIL") in lv
    assert ("dnssec", "INFO") in lv
    assert any("3/10" in x.message for x in f)  # include + a + mx inside include


def test_spf_lookup_count(serve):
    s = serve(zone_handler(ZONE))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    q = lambda n, t: query(n, t, "127.0.0.1", o)
    assert spf_lookups("example.test", q) == 3  # include + a + (mx inside include)


def test_audit_nxdomain(serve):
    s = serve(zone_handler(ZONE))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    f = audit("nope.test", "127.0.0.1", o)
    assert f[0].level == "FAIL" and "NXDOMAIN" in f[0].message


def test_audit_lame_and_apex_cname(serve):
    z = dict(ZONE)
    z[("example.test.", "CNAME")] = ["other.test."]
    s = serve(zone_handler(z, aa=False))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    lv = levels(audit("example.test", "127.0.0.1", o))
    assert ("ns", "FAIL") in lv and ("apex", "FAIL") in lv


def test_spf_over_limit(serve):
    z = dict(ZONE)
    z[("example.test.", "TXT")] = ['"v=spf1 ' + " ".join(f"a:h{i}.example.test" for i in range(11)) + ' -all"']
    s = serve(zone_handler(z))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    assert ("spf", "FAIL") in levels(audit("example.test", "127.0.0.1", o))


# ---------------------------------------------------------------- DNSSEC ---


def _signed_zone(good_ds=True, expired=False):
    name = dns.name.from_text("example.test.")
    priv = ec.generate_private_key(ec.SECP256R1())
    key = dns.dnssec.make_dnskey(priv.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256,
                                 flags=257)
    keyset = dns.rrset.from_rdata_list(name, 300, [key])
    now = int(time.time())
    inc, exp = (now - 7200, now - 3600) if expired else (now - 3600, now + 30 * 86400)
    sig = dns.dnssec.sign(keyset, priv, name, key, inception=inc, expiration=exp)
    sigset = dns.rrset.from_rdata_list(name, 300, [sig])
    ds = dns.dnssec.make_ds(name, key, "SHA256")
    if not good_ds:
        other = ec.generate_private_key(ec.SECP256R1())
        okey = dns.dnssec.make_dnskey(other.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=257)
        ds = dns.dnssec.make_ds(name, okey, "SHA256")
    dsset = dns.rrset.from_rdata_list(name, 300, [ds])
    return keyset, sigset, dsset


def _dnssec_handler(keyset, sigset, dsset):
    import dns.message

    def h(q):
        r = dns.message.make_response(q)
        qt = q.question[0].rdtype
        if qt == dns.rdatatype.DNSKEY:
            r.answer += [keyset, sigset]
        elif qt == dns.rdatatype.DS:
            r.answer.append(dsset)
        return r

    return h


@pytest.mark.parametrize("good,expired,expect", [
    (True, False, {"OK"}),
    (False, False, {"FAIL"}),
    (True, True, {"FAIL"}),
])
def test_dnssec(serve, good, expired, expect):
    s = serve(_dnssec_handler(*_signed_zone(good, expired)))
    o = QueryOpts(timeout=1.0, retries=0, port=s.port)
    f = check_dnssec("example.test", "127.0.0.1", o)
    lv = {x.level for x in f}
    assert expect <= lv
    if expect == {"OK"}:
        assert "FAIL" not in lv
