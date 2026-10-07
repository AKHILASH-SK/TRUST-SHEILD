"""SPF / DKIM / DMARC / evidence-hash tests. All DNS is mocked; no network."""
import hashlib

import pytest

from core_engine import email_forensics as ef


class FakeDns:
    """Maps (name, rtype) -> list[str] or an Exception instance to raise."""

    def __init__(self, table):
        self.table = {(k[0].lower(), k[1]): v for k, v in table.items()}
        self.calls = 0

    def __call__(self, name, rtype, timeout=3.0):
        self.calls += 1
        val = self.table.get((name.lower(), rtype), [])
        if isinstance(val, Exception):
            raise val
        return list(val)


@pytest.fixture
def dns_table(monkeypatch):
    def install(table):
        fake = FakeDns(table)
        monkeypatch.setattr(ef, "_dns_lookup", fake)
        return fake
    return install


# ---------------------------------------------------------------- DMARC / DKIM alignment
DMARC = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; adkim=r; aspf=r"]}


def test_dkim_domain_misaligned_fails_dmarc(dns_table):
    dns_table(DMARC)
    sigs = [{"verified": True, "domain": "evil-attacker.net", "selector": "s1"}]
    res = ef.evaluate_dmarc("example.com", "bounce.evil.net", "fail", sigs, "pass")
    assert res["state"] == "fail"
    assert res["dkim_aligned"] is False
    assert res["policy"] == "reject"


def test_dkim_subdomain_aligned_relaxed_passes(dns_table):
    dns_table(DMARC)
    sigs = [{"verified": True, "domain": "mail.example.com"}]
    res = ef.evaluate_dmarc("example.com", "x.test", "fail", sigs, "pass")
    assert res["state"] == "pass" and res["dkim_aligned"]


def test_dkim_strict_alignment_rejects_subdomain(dns_table):
    dns_table({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; adkim=s"]})
    sigs = [{"verified": True, "domain": "mail.example.com"}]
    assert ef.evaluate_dmarc("example.com", "x.test", "fail", sigs, "pass")["state"] == "fail"


def test_dmarc_dns_timeout_is_indeterminate(dns_table):
    dns_table({("_dmarc.example.com", "TXT"): ef._DnsTempError("Timeout")})
    res = ef.evaluate_dmarc("example.com", "example.com", "pass", [], "fail")
    assert res["state"] == "indeterminate"
    assert ef.audit_dmarc("example.com", "example.com", True, False)[0] is False


# ---------------------------------------------------------------- SPF
IP = "93.184.216.10"


def test_spf_ip4_and_dash_all(dns_table):
    dns_table({("d.test", "TXT"): ["v=spf1 ip4:93.184.216.0/24 -all"]})
    assert ef.evaluate_spf("d.test", IP)["result"] == "pass"
    assert ef.evaluate_spf("d.test", "45.33.32.1")["result"] == "fail"


def test_spf_a_mx_include(dns_table):
    dns_table({
        ("a.test", "TXT"): ["v=spf1 a -all"], ("a.test", "A"): [IP],
        ("m.test", "TXT"): ["v=spf1 mx -all"], ("m.test", "MX"): ["10 mail.m.test"], ("mail.m.test", "A"): [IP],
        ("i.test", "TXT"): ["v=spf1 include:_spf.prov.test -all"],
        ("_spf.prov.test", "TXT"): ["v=spf1 ip4:93.184.216.10 ~all"],
    })
    assert ef.evaluate_spf("a.test", IP)["state"] == "pass"
    assert ef.evaluate_spf("m.test", IP)["state"] == "pass"
    assert ef.evaluate_spf("i.test", IP)["state"] == "pass"
    assert ef.evaluate_spf("i.test", "45.33.32.9")["result"] == "fail"  # include softfail != match -> -all


def test_spf_softfail_and_ipv6(dns_table):
    dns_table({("s.test", "TXT"): ["v=spf1 ip6:2001:db8::/32 ~all"]})
    assert ef.evaluate_spf("s.test", "2001:db8::5")["result"] == "pass"
    assert ef.evaluate_spf("s.test", IP)["result"] == "softfail"


def test_spf_ten_lookup_limit_is_permerror(dns_table):
    table = {("root.test", "TXT"): ["v=spf1 include:l1.test -all"]}
    for i in range(1, 14):
        table[(f"l{i}.test", "TXT")] = [f"v=spf1 include:l{i + 1}.test -all"]
    dns_table(table)
    res = ef.evaluate_spf("root.test", IP)
    assert res["result"] == "permerror"
    assert "limit" in res["explanation"]


def test_spf_dns_error_is_temperror_not_fail(dns_table):
    dns_table({("t.test", "TXT"): ef._DnsTempError("Timeout")})
    res = ef.evaluate_spf("t.test", IP)
    assert res["result"] == "temperror" and res["state"] == "indeterminate"
    assert ef.audit_spf("t.test", IP)[0] is False


def test_spf_redirect_and_exists(dns_table):
    dns_table({
        ("r.test", "TXT"): ["v=spf1 redirect=_spf.r.test"],
        ("_spf.r.test", "TXT"): ["v=spf1 exists:ok.r.test -all"],
        ("ok.r.test", "A"): ["127.0.0.2"],
    })
    assert ef.evaluate_spf("r.test", IP)["result"] == "pass"


def test_connecting_ip_is_topmost_not_bottom():
    hdrs = [
        "from relay.example.org ([93.184.216.7]) by mx.me.test; Mon, 1 Jan 2026",
        "from client ([45.33.32.99]) by relay.example.org; Mon, 1 Jan 2026",
    ]
    assert ef.find_connecting_ip(hdrs) == "93.184.216.7"
    assert ef.trace_originating_ip(hdrs)[0] == "45.33.32.99"


def test_ipv6_and_cgnat_handling():
    assert ef.extract_ips_from_string("from x ([IPv6:2001:db8::1])") == ["2001:db8::1"]
    assert ef.is_public_ip("100.64.1.1") is False
    assert ef.is_public_ip("2606:4700:4700::1111") is True


# ---------------------------------------------------------------- evidence hash
def test_hash_is_over_original_bytes_with_crcrlf(dns_table):
    dns_table({})
    raw = (b"Received: from a ([93.184.216.7]) by b\r\r\n"
           b"From: <a@example.com>\r\r\nTo: x@y.test\r\r\nSubject: hi\r\r\n\r\r\nbody http://93.184.216.5/x\r\r\n")
    res = ef.parse_email_file(raw)
    assert res["evidence_hash_sha256"] == hashlib.sha256(raw).hexdigest()
    assert res["evidence_hash"] == res["evidence_hash_sha256"]
    assert res["raw_size_bytes"] == len(raw)
    assert res["authentication"]["dmarc_state"] in ("fail", "pass", "indeterminate")
    assert "analysis_complete" in res


# ---------------------------------------------------------------- link extraction
def test_link_extraction_cases_and_charset(dns_table):
    dns_table({})
    raw = (b"From: a@example.com\r\nTo: x@y.test\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: text/html; charset=bogus-charset\r\nContent-Disposition: attachment\r\n\r\n"
           b'<a href="HTTP://Upper.example.net/p">x</a><a href="//proto.rel/x">y</a>'
           b"visit 45.33.32.7/login now")
    res = ef.parse_email_file(raw)
    links = res["payload"]["extracted_links"]
    assert any(l.lower().startswith("http://upper.example.net") for l in links)
    assert not any("proto.rel" in l for l in links)
    assert "http://45.33.32.7/login" in links
