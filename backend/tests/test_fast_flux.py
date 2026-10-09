"""Fast-flux detection: rotating attacker infrastructure is flagged, stable sites and CDN-like sites are not."""
from core_engine import fast_flux as ff


def rounds(*pairs):
    return [(list(ips), ttl) for ips, ttl in pairs]


def test_a_domain_that_rotates_widely_with_a_short_ttl_is_fast_flux():
    data = rounds((["198.18.1.1", "203.0.5.5", "100.64.2.2", "45.33.9.9", "91.121.4.4"], 30),
                  (["185.220.1.1", "77.88.3.3", "5.188.7.7", "62.210.8.8", "192.0.2.2"], 30),
                  (["198.51.3.3", "37.139.1.1", "198.19.9.9", "203.0.9.9", "100.65.1.1"], 30))
    out = ff.assess(data)
    assert out["level"] == "fast_flux" and out["distinct_ips"] >= 5 and out["min_ttl"] == 30
    assert len(out["signs"]) >= 3


def test_a_stable_site_is_normal():
    same = (["203.0.113.10", "203.0.113.11"], 3600)
    assert ff.assess(rounds(same, same, same, same))["level"] == "normal"


def test_a_cdn_with_many_addresses_but_long_ttl_and_a_stable_set_is_not_fast_flux():
    cdn = ([f"198.51.100.{i}" for i in range(1, 9)], 3600)
    out = ff.assess(rounds(cdn, cdn, cdn, cdn))
    assert out["level"] != "fast_flux"


def test_short_ttl_alone_is_not_enough():
    one = (["203.0.113.10"], 20)
    assert ff.assess(rounds(one, one, one))["level"] == "normal"


def test_nothing_resolving_is_unknown_not_guilty():
    assert ff.assess(rounds(([], None), ([], None)))["level"] == "unknown"


def test_a_broken_resolver_never_raises():
    def boom(domain):
        raise RuntimeError("dns down")
    out = ff.inspect_domain("example.test", lookup=boom, pause=0)
    assert out["level"] == "unknown"


def test_a_bare_ip_has_nothing_to_watch():
    assert ff.inspect_domain("203.0.113.9")["level"] == "unknown"


def test_the_lab_dns_server_makes_the_difference_visible_over_real_udp():
    from lab import fastflux_dns
    stop = fastflux_dns.start("127.0.0.1", 5391)
    try:
        lookup = ff.system_lookup_factory("127.0.0.1", 5391)
        flux = ff.inspect_domain("flux.bank-verify.test", lookup=lookup, pause=0)
        steady = ff.inspect_domain("steady.shop.test", lookup=lookup, pause=0)
        cdn = ff.inspect_domain("cdn.bigsite.test", lookup=lookup, pause=0)
        assert flux["level"] == "fast_flux", flux
        assert steady["level"] == "normal" and cdn["level"] != "fast_flux"
    finally:
        stop()


def test_email_pipeline_infrastructure_skips_trusted_hosting_and_ip_links_and_flags_rotation(monkeypatch):
    from core_engine import infrastructure
    from lab import fastflux_dns
    from core_engine import email_forensics
    monkeypatch.setattr(email_forensics, "LAB_MODE", True)          # demo mode (the switch infrastructure.py follows)
    stop = fastflux_dns.start("127.0.0.1", 5353)
    try:
        out = infrastructure.inspect_links([
            "https://flux.bank-verify.test/login", "https://steady.shop.test/", "https://mail.google.com/x",
            "https://app.vercel.app/", "http://203.0.113.9/login", "https://docs.google.com/forms/d/e/1/viewform"])
    finally:
        stop()
    domains = {d["domain"]: d for d in out["domains"]}
    assert set(domains) == {"flux.bank-verify.test", "steady.shop.test"}          # the others are skipped
    assert domains["flux.bank-verify.test"]["fast_flux"]["level"] == "fast_flux"
    assert domains["steady.shop.test"]["fast_flux"]["level"] == "normal"
    assert out["flux_domains"] == 1
