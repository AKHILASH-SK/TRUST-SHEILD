"""API security tests: auth, ownership, admin keys, lockout, evidence sealing, SSRF guard."""
import contextlib

import pytest

import app as backend_app
import evidence_seal
from core_engine.url_safety import UnsafeUrlError, assert_public_url, is_public_url
from security import issue_token, verify_token


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        out = list(self.rows)
        self.rows.clear()
        return out


@pytest.fixture
def client():
    return backend_app.app.test_client()


@pytest.fixture
def fake_db(monkeypatch):
    holder = {"rows": []}

    @contextlib.contextmanager
    def fake_cursor():
        yield FakeCursor(holder["rows"])

    monkeypatch.setattr(backend_app, "db_cursor", fake_cursor)
    return holder


def auth(user_id):
    return {"Authorization": f"Bearer {issue_token(user_id)}"}


# ---- authentication and ownership ------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("get", "/api/links/history/1"),
    ("post", "/api/links/scan"),
    ("post", "/api/links/explain"),
    ("post", "/api/sandbox-check"),
    ("get", "/api/forensics/cases"),
    ("get", "/api/graph"),
    ("get", "/api/campaigns"),
    ("get", "/api/auth/me"),
])
def test_protected_routes_require_a_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_tampered_token_is_rejected(client):
    token = issue_token(5)
    assert verify_token(token) == 5
    assert verify_token(token[:-2] + "xx") is None
    resp = client.get("/api/links/history/5", headers={"Authorization": f"Bearer {token[:-2]}xx"})
    assert resp.status_code == 401


def test_history_of_another_user_is_forbidden(client, fake_db):
    assert client.get("/api/links/history/8", headers=auth(7)).status_code == 403


def test_scan_for_another_user_is_forbidden(client, fake_db):
    resp = client.post("/api/links/scan", json={"url": "http://example.com", "user_id": 99}, headers=auth(7))
    assert resp.status_code == 403


def test_scan_rejects_non_http_url(client, fake_db):
    resp = client.post("/api/links/scan", json={"url": "file:///etc/passwd"}, headers=auth(7))
    assert resp.status_code == 400


def test_error_responses_do_not_leak_internals(client, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret connection string postgres://user:pw@host")

    monkeypatch.setattr(backend_app, "db_cursor", boom)
    resp = client.get("/api/links/history/7", headers=auth(7))
    assert resp.status_code == 500
    assert "postgres://" not in resp.get_data(as_text=True)
    assert "reference" in resp.get_json()


# ---- admin endpoints --------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("post", "/api/phishing/import"),
    ("post", "/api/phishing/import-feeds"),
    ("get", "/api/phishing/samples"),
])
def test_admin_routes_need_the_admin_key(client, method, path):
    assert getattr(client, method)(path).status_code == 403
    assert getattr(client, method)(path, headers={"X-Admin-Key": "wrong"}).status_code == 403


def test_green_api_simulation_endpoint_is_gone(client):
    assert client.post("/api/simulate/run", json={"phone_number": "9999999999"}).status_code == 404


# ---- login ------------------------------------------------------------------------

def test_login_gives_the_same_error_for_unknown_phone_and_wrong_pin(client, fake_db):
    unknown = client.post("/api/auth/login", json={"phone_number": "9000000001", "pin": "1234"})
    fake_db["rows"].append((1, "A", "a@x.com", "9000000002", backend_app.hash_pin("4321")))
    wrong_pin = client.post("/api/auth/login", json={"phone_number": "9000000002", "pin": "1234"})
    assert unknown.status_code == wrong_pin.status_code == 401
    assert unknown.get_json() == wrong_pin.get_json()


def test_login_success_returns_a_verifiable_token(client, fake_db):
    fake_db["rows"].append((3, "A", "a@x.com", "9000000003", backend_app.hash_pin("4321")))
    resp = client.post("/api/auth/login", json={"phone_number": "9000000003", "pin": "4321"})
    assert resp.status_code == 200
    assert verify_token(resp.get_json()["token"]) == 3


def test_login_locks_out_after_repeated_failures(client, fake_db):
    for _ in range(5):
        client.post("/api/auth/login", json={"phone_number": "9000000009", "pin": "0000"})
    resp = client.post("/api/auth/login", json={"phone_number": "9000000009", "pin": "0000"})
    assert resp.status_code == 429


@pytest.mark.parametrize("pin", ["12", "abcd", "123456789", 1234, None])
def test_register_rejects_bad_pins(client, fake_db, pin):
    body = {"name": "A", "last_name": "B", "email": "a@b.com", "phone_number": "9000000010", "pin": pin}
    assert client.post("/api/auth/register", json=body).status_code == 400


# ---- evidence sealing -------------------------------------------------------------

def test_seal_detects_any_tampering():
    dossier_json = evidence_seal.canonical_json({"verdict": "PHISHING", "score": 91})
    sig = evidence_seal.seal("TSF-AAAA", "ab" * 32, dossier_json, "2026-10-08T10:00:00")
    assert evidence_seal.verify_seal("TSF-AAAA", "ab" * 32, dossier_json, "2026-10-08T10:00:00", sig)
    altered = evidence_seal.canonical_json({"verdict": "CLEAN", "score": 0})
    assert not evidence_seal.verify_seal("TSF-AAAA", "ab" * 32, altered, "2026-10-08T10:00:00", sig)
    assert not evidence_seal.verify_seal("TSF-AAAA", "cd" * 32, dossier_json, "2026-10-08T10:00:00", sig)
    assert not evidence_seal.verify_seal("TSF-AAAA", "ab" * 32, dossier_json, "2026-10-08T10:00:01", sig)
    assert not evidence_seal.verify_seal("TSF-AAAA", "ab" * 32, dossier_json, "2026-10-08T10:00:00", None)


def test_case_record_reports_tampering():
    case_id = "TSF-0123456789ABCDEF"
    dossier_json = evidence_seal.canonical_json({"verdict": "PHISHING"})
    sig = evidence_seal.seal(case_id, "ab" * 32, dossier_json, "2026-10-08T10:00:00")
    good = (case_id, "ab" * 32, "PHISHING", 90.0, "s", "sub", dossier_json, None, 1, sig, "2026-10-08T10:00:00")
    assert backend_app._build_case_record(good)["integrity_status"] == "VERIFIED"

    forged = good[:6] + (evidence_seal.canonical_json({"verdict": "CLEAN"}),) + good[7:]
    record = backend_app._build_case_record(forged)
    assert record["integrity_status"] == "TAMPERED"
    assert record["dossier"]["integrity"]["status"] == "TAMPERED"

    unsealed = good[:9] + (None, None)
    assert backend_app._build_case_record(unsealed)["integrity_status"] == "NOT SEALED"


def test_case_ids_are_unguessable_and_unique():
    ids = {backend_app.new_case_id() for _ in range(500)}
    assert len(ids) == 500
    assert all(len(i) == 20 and i.startswith("TSF-") for i in ids)


def test_legacy_six_digit_case_ids_are_not_served(client):
    assert client.get("/api/forensics/case/TSF-123456").status_code == 404


# ---- SSRF guard -------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost:8000/", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "http://192.168.1.10/login", "http://[::1]/", "http://[::ffff:10.0.0.1]/",
    "http://2130706433/", "file:///etc/passwd", "ftp://example.com/", "http://user:pw@example.com/",
])
def test_ssrf_guard_blocks_internal_targets(url):
    assert not is_public_url(url)
    with pytest.raises(UnsafeUrlError):
        assert_public_url(url)
