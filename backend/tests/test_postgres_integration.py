"""
Real-PostgreSQL integration test (skipped automatically when no test database is reachable).

Start a throwaway database, then run the test:
    docker run -d --rm --name ts-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=trustshield_test -p 55432:5432 postgres:16-alpine
    set TEST_PG_PORT=55432   (PowerShell: $env:TEST_PG_PORT="55432")
    PYTHONPATH=backend python -m pytest backend/tests/test_postgres_integration.py -q
It exercises the real SQL: register/login, ownership, history filters, sealed case insert-only, tamper detection, PDF.
"""
import os

import psycopg
import pytest

import app as backend_app
import db_config
import evidence_seal
from core_engine import email_forensics as ef
from core_engine import unified_email_pipeline as uep
from security import issue_token

PG = {
    "host": os.getenv("TEST_PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("TEST_PG_PORT", "55432")),
    "dbname": os.getenv("TEST_PG_DB", "trustshield_test"),
    "user": os.getenv("TEST_PG_USER", "postgres"),
    "password": os.getenv("TEST_PG_PASSWORD", "pw"),
    "connect_timeout": 2,
}


def _reachable() -> bool:
    try:
        with psycopg.connect(**PG):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason="no test PostgreSQL reachable (see module docstring)")


@pytest.fixture(scope="module")
def db():
    original = dict(db_config.DB_CONFIG)
    db_config.DB_CONFIG.clear()
    db_config.DB_CONFIG.update(PG)
    schema = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sql", "schema.sql")
    with psycopg.connect(**PG, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS scan_features, link_scans, forensic_cases, users, phishing_links, "
                     "phishing_feed_sources, official_brands CASCADE")
        conn.execute(open(schema, encoding="utf-8").read())
    backend_app.ensure_forensic_case_table()      # idempotent: must coexist with schema.sql
    backend_app.ensure_link_scan_columns()
    yield
    db_config.DB_CONFIG.clear()
    db_config.DB_CONFIG.update(original)


@pytest.fixture
def client(db):
    return backend_app.app.test_client()


def _register(client, n):
    import security
    security._rate_hits.clear()        # registration is limited to 5 per 10 minutes per IP; tests create several users
    body = {"name": "T", "last_name": "User", "email": f"t{n}@example.com", "phone_number": f"90000000{n:02d}", "pin": "4321"}
    resp = client.post("/api/auth/register", json=body)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def test_register_login_and_duplicate(client):
    user = _register(client, 1)
    assert user["token"]
    dup = client.post("/api/auth/register", json={"name": "T", "last_name": "U", "email": "t1@example.com",
                                                   "phone_number": "9000000001", "pin": "4321"})
    assert dup.status_code == 409
    ok = client.post("/api/auth/login", json={"phone_number": "9000000001", "pin": "4321"})
    assert ok.status_code == 200 and ok.get_json()["id"] == user["id"]
    with psycopg.connect(**PG) as conn:           # the PIN is stored as a bcrypt hash, never in clear
        stored = conn.execute("SELECT pin FROM users WHERE id = %s", (user["id"],)).fetchone()[0]
    assert stored.startswith("$2") and "4321" not in stored


def test_scan_history_is_per_user_and_filterable(client, monkeypatch):
    a, b = _register(client, 2), _register(client, 3)
    monkeypatch.setattr(backend_app, "run_link_pipeline", lambda url: {
        "verdict": "CRITICAL FRAUD / PHISHING" if "bad" in url else "LEGITIMATE / CLEAN",
        "threat_score": 95.0 if "bad" in url else 3.0, "summary": "s", "analysis_complete": True})
    monkeypatch.setattr(backend_app.phishing_importer, "check_url_in_database", lambda u: (False, None, None))
    headers_a = {"Authorization": f"Bearer {issue_token(a['id'])}"}
    for url in ("https://bad-site.example/login", "https://good-site.example/"):
        r = client.post("/api/links/scan", json={"url": url, "source_app": "com.whatsapp"}, headers=headers_a)
        assert r.status_code == 201, r.get_json()

    hist = client.get(f"/api/links/history/{a['id']}", headers=headers_a).get_json()
    assert hist["total_scans"] == 2
    assert {s["source_app"] for s in hist["scans"]} == {"com.whatsapp"}
    only_bad = client.get(f"/api/links/history/{a['id']}?verdict=DANGEROUS", headers=headers_a).get_json()
    assert [s["url"] for s in only_bad["scans"]] == ["https://bad-site.example/login"]
    searched = client.get(f"/api/links/history/{a['id']}?q=good-site", headers=headers_a).get_json()
    assert searched["total_scans"] == 1

    headers_b = {"Authorization": f"Bearer {issue_token(b['id'])}"}
    assert client.get(f"/api/links/history/{a['id']}", headers=headers_b).status_code == 403   # no cross-user reads
    assert client.get(f"/api/links/history/{b['id']}", headers=headers_b).get_json()["total_scans"] == 0


def _offline_pipeline(monkeypatch):
    monkeypatch.setattr(ef, "_dns_lookup", lambda *a, **k: [])
    monkeypatch.setattr(uep, "generate_route_map", lambda hops: [])
    monkeypatch.setattr(uep, "lookup_whois", lambda d: {})
    monkeypatch.setattr(uep, "analyze_url", lambda url, **k: {"threat_score": 90.0, "verdict": "CRITICAL FRAUD / PHISHING",
                                                              "summary": "bad", "telemetry": {"analysis_complete": True}})


def test_forensic_case_is_sealed_insert_only_and_detects_tampering(client, monkeypatch):
    _offline_pipeline(monkeypatch)
    owner = _register(client, 4)
    raw = (b"From: Billing <billing@paypa1-secure.example>\r\nTo: v@y.test\r\nSubject: Verify\r\n\r\n"
           b"http://paypa1-secure.example/login")
    created = client.post("/api/forensics/analyze-eml", data=raw, content_type="message/rfc822",
                          headers={"Authorization": f"Bearer {issue_token(owner['id'])}"})
    assert created.status_code == 200, created.get_json()
    case_id = created.get_json()["case_id"]
    assert created.get_json()["integrity"]["status"] == "VERIFIED"

    ver = client.post("/api/forensics/verify-hash", json={"query": case_id}).get_json()
    assert ver["integrity_status"] == "VERIFIED"
    assert ver["evidence_hash"] == evidence_seal.sha256_hex(raw)
    file_ver = client.post("/api/forensics/verify-file", data=raw, content_type="message/rfc822").get_json()
    assert file_ver["matched"] and file_ver["case_id"] == case_id
    assert not client.post("/api/forensics/verify-file", data=raw + b" ", content_type="message/rfc822").get_json()["matched"]

    # the owner can fetch the exact original bytes; other users cannot
    evidence = client.get(f"/api/forensics/case/{case_id}/evidence",
                          headers={"Authorization": f"Bearer {issue_token(owner['id'])}"})
    assert evidence.status_code == 200 and evidence.data == raw
    stranger = _register(client, 5)
    assert client.get(f"/api/forensics/case/{case_id}/evidence",
                      headers={"Authorization": f"Bearer {issue_token(stranger['id'])}"}).status_code == 404
    listed = client.get("/api/forensics/cases", headers={"Authorization": f"Bearer {issue_token(owner['id'])}"}).get_json()
    assert [c["case_id"] for c in listed["cases"]] == [case_id]

    pdf = client.post("/api/forensics/export-pdf", json={"case_id": case_id})
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")

    # a database edit to the stored dossier must be caught on the next read
    with psycopg.connect(**PG, autocommit=True) as conn:
        conn.execute("UPDATE forensic_cases SET dossier_json = replace(dossier_json, 'CRITICAL', 'LEGITIMATE') WHERE case_id = %s",
                     (case_id,))
    backend_app.FORENSIC_CASE_CACHE.clear()
    tampered = client.post("/api/forensics/verify-hash", json={"query": case_id}).get_json()
    assert tampered["integrity_status"] == "TAMPERED"
    assert "SEAL INVALID" in tampered["integrity_verdict"]


def test_duplicate_case_id_cannot_overwrite(client):
    case = {"verdict": "X", "overall_threat_score": 1.0, "metadata": {"from": "a", "subject": "s"}}
    backend_app.persist_forensic_case("TSF-0000000000000001", dict(case), b"first")
    with pytest.raises(Exception):
        backend_app.persist_forensic_case("TSF-0000000000000001", dict(case), b"second")
    assert backend_app.fetch_case_raw_bytes("TSF-0000000000000001") == b"first"
