"""The demo (lab) mode of a RUNNING backend: only someone who can read the key file on this machine can switch it, and it switches back."""
import app as backend_app
from core_engine import email_forensics, geo_tracer


def client():
    return backend_app.app.test_client()


def test_demo_mode_cannot_be_switched_without_the_key():
    c = client()
    assert c.post("/api/lab/mode", json={"on": True}).status_code == 403
    assert c.post("/api/lab/mode", json={"on": True}, headers={"X-Lab-Token": "guess"}).status_code == 403
    assert email_forensics.LAB_MODE is False


def test_demo_mode_switches_on_and_off_with_the_key_and_leaves_normal_behaviour_after():
    c = client()
    headers = {"X-Lab-Token": backend_app.LAB_TOKEN}
    assert backend_app.LAB_TOKEN and len(backend_app.LAB_TOKEN) >= 32
    try:
        assert c.post("/api/lab/mode", json={"on": True, "minutes": 1}, headers=headers).status_code == 200
        assert email_forensics.LAB_MODE is True and email_forensics.DNS_OVERRIDE is not None and geo_tracer.GEO_OVERRIDE is not None
        assert c.get("/api/lab/mode").get_json()["lab_mode"] is True
        assert email_forensics.is_public_ip("127.0.0.3") is True              # the simulated senders count while the demo runs
    finally:
        assert c.post("/api/lab/mode", json={"on": False}, headers=headers).status_code == 200
    assert email_forensics.LAB_MODE is False and email_forensics.DNS_OVERRIDE is None and geo_tracer.GEO_OVERRIDE is None
    assert email_forensics.is_public_ip("127.0.0.3") is False                 # back to normal: loopback is never a public sender
    assert c.get("/api/lab/mode").get_json()["lab_mode"] is False


def test_gateway_feed_writes_need_demo_mode_but_the_results_stay_readable_after_it():
    c = client()
    headers = {"X-Lab-Token": backend_app.LAB_TOKEN}
    assert c.post("/api/gateway/events", json={"id": "x"}).status_code == 403          # no demo mode, no key
    try:
        c.post("/api/lab/mode", json={"on": True, "minutes": 1}, headers=headers)
        assert c.post("/api/gateway/events", json={"id": "demo1", "connecting_ip": "127.0.0.3"}).status_code == 201
    finally:
        c.post("/api/lab/mode", json={"on": False}, headers=headers)
    assert c.post("/api/gateway/events", json={"id": "late"}).status_code == 403       # writes stop with the demo
    events = c.get("/api/gateway/events")
    assert events.status_code == 200 and any(e["id"] == "demo1" for e in events.get_json()["events"])   # results stay on screen
    c.get("/api/gateway/events?clear=1")


def test_demo_pages_are_served_on_development_backends_hidden_on_production_unless_a_demo_ran_and_are_self_contained(monkeypatch):
    c = client()
    headers = {"X-Lab-Token": backend_app.LAB_TOKEN}
    used_before = backend_app.LAB_STATE["used"]
    backend_app.LAB_STATE["used"] = False
    try:
        assert c.get("/demo/page/bank").status_code == 200                                   # a development backend shows them at once
        monkeypatch.setenv("TRUSTSHIELD_ENV", "production")
        assert c.get("/demo/page/bank").status_code == 404                                   # a production server never shows them outside a demo
        c.post("/api/lab/mode", json={"on": True, "minutes": 1}, headers=headers)
        monkeypatch.delenv("TRUSTSHIELD_ENV", raising=False)
        for name in ("bank", "relay", "mail-genuine", "mail-forged"):
            res = c.get(f"/demo/page/{name}")
            assert res.status_code == 200 and res.mimetype == "text/html"
            text = res.get_data(as_text=True)
            assert "DEMO PAGE (simulated)" in text and "<script" not in text.lower() and "http://" not in text   # nothing external, nothing to run
        assert c.get("/demo/page/../app").status_code == 404 and c.get("/demo/page/unknown").status_code == 404
        assert "hdfcbank-secure-login.com" in c.get("/demo/page/relay").get_data(as_text=True)
        assert "127.0.0.3" in c.get("/demo/page/mail-forged").get_data(as_text=True)
    finally:
        c.post("/api/lab/mode", json={"on": False}, headers=headers)
        backend_app.LAB_STATE["used"] = used_before
