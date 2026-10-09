import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core_engine import sandbox_engine as se
from core_engine.sandbox_engine import VirtualSandboxAnalyzer, _keyword_in_text
from core_engine.url_safety import UnsafeUrlError


class FakeResp:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": "text/html"}
        self._body = body
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size=1024):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        self.closed = True

    def json(self):
        import json
        return json.loads(self._body)


def no_dns_guard(url):
    """Stand-in for assert_public_url without DNS: literal private IPs are rejected."""
    import ipaddress
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    try:
        is_global = ipaddress.ip_address(host).is_global
    except ValueError:
        is_global = True
    if not is_global:
        raise UnsafeUrlError("non-public")
    return url


@pytest.fixture
def sb():
    return VirtualSandboxAnalyzer()


@pytest.fixture(autouse=True)
def fresh_age_cache():
    VirtualSandboxAnalyzer._AGE_CACHE.clear()


def fresh_features():
    return {}


# ---- brand keyword matching ---------------------------------------------------
def test_aws_does_not_match_laws():
    assert not _keyword_in_text("aws", "new laws and regulations")
    assert _keyword_in_text("aws", "sign in to aws console")


def test_laws_title_does_not_flag_aws(sb, monkeypatch):
    html = b"<html><title>Employment laws in India</title><body>laws laws login</body></html>"
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, html))
    f = sb._analyze_with_requests("http://not-a-ranked-site-for-tests.test/", {})
    assert f["brand_impersonation"] == 0 and f["impersonated_brand"] is None


def test_generic_bank_title_is_not_title_mismatch(sb, monkeypatch):
    html = (b"<html><title>Secure Bank Login</title><form action='/x'>"
            b"<input type='password'></form></html>")
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, html))
    f = sb._analyze_with_requests("http://not-a-ranked-site-for-tests.test/", {})
    assert f["sandbox_title_mismatch"] == 0


def test_real_brand_title_with_password_form_is_mismatch(sb, monkeypatch):
    html = (b"<html><title>PayPal - Log in</title><form action='/x'>"
            b"<input type='password'></form></html>")
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, html))
    f = sb._analyze_with_requests("http://not-a-ranked-site-for-tests.test/", {})
    assert f["sandbox_title_mismatch"] == 1 and f["sandbox_has_password_field"] == 1


def test_real_brand_title_without_credential_form_is_not_mismatch(sb, monkeypatch):
    html = b"<html><title>I love PayPal news</title><body>article</body></html>"
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, html))
    f = sb._analyze_with_requests("http://not-a-ranked-site-for-tests.test/", {})
    assert f["sandbox_title_mismatch"] == 0


# ---- SSRF ---------------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/"])
def test_ssrf_blocked_without_any_request(sb, monkeypatch, url):
    def boom(*a, **k):
        raise AssertionError("no request may be issued")

    monkeypatch.setattr(se.requests, "get", boom)
    f = sb.analyze_link_in_sandbox(url)
    assert f["sandbox_unreachable"] == 1 and f["sandbox_blocked_unsafe_url"] == 1
    f2 = sb._analyze_with_requests(url, {})
    assert f2["sandbox_unreachable"] == 1 and f2["sandbox_blocked_unsafe_url"] == 1


def test_redirect_to_private_ip_is_blocked(sb, monkeypatch):
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        assert kw["allow_redirects"] is False
        return FakeResp(302, b"", {"Location": "http://127.0.0.1/secret"})

    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", fake_get)
    f = sb._analyze_with_requests("http://8.8.8.8/start", {})
    assert f["sandbox_blocked_unsafe_url"] == 1 and f["sandbox_unreachable"] == 1
    assert seen == ["http://8.8.8.8/start"]  # the private hop was never fetched


def test_redirect_limit(sb, monkeypatch):
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get",
                        lambda url, **kw: FakeResp(302, b"", {"Location": "http://8.8.4.4/next"}))
    f = sb._analyze_with_requests("http://8.8.8.8/", {})
    assert f["sandbox_unreachable"] == 1 and f["sandbox_blocked_unsafe_url"] == 0


def test_body_is_capped_and_non_html_skipped(sb, monkeypatch):
    big = b"<html><title>x</title>" + b"a" * (3 * 1024 * 1024)
    monkeypatch.setattr(se, "assert_public_url", no_dns_guard)
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, big))
    final, text, hops = sb._safe_fetch("http://8.8.8.8/")
    assert len(text) <= sb.MAX_BODY_BYTES
    monkeypatch.setattr(se.requests, "get",
                        lambda url, **kw: FakeResp(200, b"%PDF", {"Content-Type": "application/pdf"}))
    assert sb._safe_fetch("http://8.8.8.8/")[1] == ""


# ---- RDAP domain age -----------------------------------------------------------
def rdap_payload(days_ago):
    dt = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    import json
    return json.dumps({"events": [{"eventAction": "last changed", "eventDate": dt},
                                  {"eventAction": "registration", "eventDate": dt}]}).encode()


def test_rdap_old_domain(sb, monkeypatch):
    calls = []

    def fake_get(url, **kw):
        calls.append((url, kw.get("timeout")))
        return FakeResp(200, rdap_payload(900), {"Content-Type": "application/rdap+json"})

    monkeypatch.setattr(se.requests, "get", fake_get)
    age, newly, risk = sb._query_domain_age("https://www.example-old.com/x")
    assert 899 <= age <= 901 and newly == 0 and risk == 0
    assert calls[0][0] == "https://rdap.org/domain/example-old.com" and calls[0][1] == 3
    sb._query_domain_age("https://example-old.com")
    assert len(calls) == 1  # cached


def test_rdap_new_domain(sb, monkeypatch):
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(200, rdap_payload(3)))
    age, newly, risk = sb._query_domain_age("https://brand-new-site.com")
    assert age == 3 and newly == 1 and risk == 90


def test_rdap_404_is_unknown_not_new(sb, monkeypatch):
    monkeypatch.setattr(se.requests, "get", lambda url, **kw: FakeResp(404, b"{}"))
    assert sb._query_domain_age("https://no-such-registration.com") == (-1, 0, 0)


def test_rdap_exception_is_unknown(sb, monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("slow")

    monkeypatch.setattr(se.requests, "get", boom)
    assert sb._query_domain_age("https://timeout-site.com") == (-1, 0, 0)


def test_rdap_rejects_bad_domain_without_request(sb, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not query")

    monkeypatch.setattr(se.requests, "get", boom)
    assert sb._query_domain_age("http://127.0.0.1/") == (-1, 0, 0)
    assert sb._query_domain_age("http://localhost/") == (-1, 0, 0)


def test_no_global_socket_timeout():
    import socket
    sb = VirtualSandboxAnalyzer()
    before = socket.getdefaulttimeout()
    se.requests  # noqa
    assert before is None or before > 1.2
    src = open(se.__file__, encoding="utf-8").read()
    assert "setdefaulttimeout" not in src and "import whois" not in src
