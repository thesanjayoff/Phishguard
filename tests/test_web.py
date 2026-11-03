"""Web app: auth, host/origin guards, safe rendering, feedback loop, no delete endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import PHISH_EML
from phishguard.web.app import create_app


@pytest.fixture()
def client(cfg, analyzer):
    app = create_app(cfg, analyzer=analyzer, start_poller=False)
    c = TestClient(app, base_url="http://127.0.0.1:8765")
    c.csrf = app.state.csrf
    c.token = cfg.api_token()
    return c


def ui(c):  # headers a page's own JS would send
    return {"X-PG-CSRF": c.csrf}


def bearer(c):
    return {"Authorization": f"Bearer {c.token}"}


def test_pages_render_when_empty(client):
    for path in ("/", "/check", "/dashboard", "/status"):
        r = client.get(path)
        assert r.status_code == 200, path
    assert "pg-csrf" in client.get("/").text


def test_security_headers_and_csp(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"


def test_unexpected_host_header_is_rejected(client):
    r = client.get("/", headers={"Host": "evil.example.com:8765"})  # DNS rebinding shape
    assert r.status_code == 400
    assert client.get("/", headers={"Host": "localhost:8765"}).status_code == 200


def test_api_requires_credentials(client):
    assert client.get("/api/messages").status_code == 401
    assert client.get("/api/messages", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/messages", headers=bearer(client)).status_code == 200
    assert client.get("/api/messages", headers=ui(client)).status_code == 200
    assert client.get("/api/messages", headers={"X-PG-CSRF": "guess"}).status_code == 401


def test_cross_site_post_is_refused(client):
    body = {"text": "hello"}
    assert client.post("/api/check", json=body, headers={**ui(client), "Origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/check", json=body, headers={**ui(client), "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/check", json=body, headers={**ui(client), "Origin": "http://127.0.0.1:8765"}).status_code == 200


def test_check_phish_text_saves_and_defangs(client):
    r = client.post("/api/check", json={"text": PHISH_EML.decode(), "deep": False}, headers=ui(client))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["label"] == "phishing" and d["score"] >= 70 and d["message_id"]
    assert d["quarantined"] is True
    flat = str(d["urls"])
    assert "http://" not in flat and "hxxp" in flat  # the API never hands out clickable links
    page = client.get(f"/message/{d['message_id']}").text
    assert "hxxp" in page and "http://paypa1" not in page
    assert "Mark as safe" in page and "Mark as phishing" in page


def test_untrusted_content_is_escaped(client):
    evil = "From: <script>alert(1)</script> <a@b.co>\nSubject: <img src=x onerror=alert(1)>\n\nverify your password now <b>bold</b>"
    r = client.post("/api/check", json={"text": evil, "kind": "email", "deep": False}, headers=ui(client))
    mid = r.json()["message_id"]
    page = client.get(f"/message/{mid}").text
    assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;" in page


def test_check_without_saving_does_not_touch_inbox(client):
    r = client.post("/api/check", json={"text": "hello there, lunch?", "save": False}, headers=ui(client))
    assert r.json()["message_id"] is None
    assert client.get("/api/messages", headers=bearer(client)).json()["messages"] == []


def test_sms_ingest_needs_bearer_not_ui_header(client):
    body = {"sender": "AX-HDFCBK", "body": "Dear Customer your KYC is expired. Update immediately: http://hdfc-kyc-update.top/x", "id": "sms-1"}
    assert client.post("/api/ingest/sms", json=body, headers=ui(client)).status_code == 401
    r = client.post("/api/ingest/sms", json=body, headers=bearer(client))
    assert r.status_code == 200 and r.json()["duplicate"] is False and r.json()["label"] in ("suspicious", "phishing")
    again = client.post("/api/ingest/sms", json=body, headers=bearer(client)).json()
    assert again["duplicate"] is True
    batch = client.post("/api/ingest/sms/batch", json={"messages": [body, {**body, "id": "sms-2"}]}, headers=bearer(client)).json()
    assert batch["received"] == 2 and batch["new"] == 1


def test_sms_ingest_can_be_disabled(cfg, analyzer):
    cfg.sms.enabled = False
    app = create_app(cfg, analyzer=analyzer, start_poller=False)
    c = TestClient(app, base_url="http://127.0.0.1:8765")
    r = c.post("/api/ingest/sms", json={"body": "hi"}, headers={"Authorization": f"Bearer {cfg.api_token()}"})
    assert r.status_code == 403


def test_share_endpoint_accepts_form_and_json(client):
    r = client.post("/api/share", data={"text": "URGENT your account is blocked, verify at http://sbi-secure-kyc.top/login", "title": ""}, headers=bearer(client))
    assert r.status_code == 200 and r.json()["message_id"]
    r = client.post("/api/share", json={"url": "http://bit.ly/abc123", "text": "check this"}, headers=bearer(client))
    assert r.status_code == 200
    assert client.post("/api/share", json={}, headers=bearer(client)).status_code == 422


def test_feedback_roundtrip_and_release(client):
    mid = client.post("/api/check", json={"text": PHISH_EML.decode(), "deep": False}, headers=ui(client)).json()["message_id"]
    r = client.post(f"/api/messages/{mid}/feedback", json={"label": "safe"}, headers=ui(client)).json()
    assert r["changed"] is True
    m = client.get(f"/api/messages/{mid}", headers=ui(client)).json()
    assert m["user_label"] == "safe" and m["quarantined"] == 0  # marking safe releases it
    assert client.post(f"/api/messages/{mid}/feedback", json={"label": "safe"}, headers=ui(client)).json()["changed"] is False
    assert client.post(f"/api/messages/{mid}/feedback", json={"label": "maybe"}, headers=ui(client)).status_code == 422
    assert client.post("/api/messages/9999/feedback", json={"label": "safe"}, headers=ui(client)).status_code == 404


def test_stats_endpoint_shape(client):
    client.post("/api/check", json={"text": PHISH_EML.decode(), "deep": False}, headers=ui(client))
    d = client.get("/api/stats?days=7", headers=ui(client)).json()
    assert len(d["series"]) == 7 and d["totals"]["scanned"] == 1 and d["totals"]["phishing"] == 1
    assert d["brands"] and d["domains"]
    assert all("[.]" in x["name"] for x in d["domains"])  # domains are defanged for display
    assert client.get("/api/stats?days=100000", headers=ui(client)).json()["days"] == 365


def test_inbox_filters_and_pages(client):
    client.post("/api/check", json={"text": PHISH_EML.decode(), "deep": False}, headers=ui(client))
    client.post("/api/check", json={"text": "Hi, lunch on Thursday?", "kind": "chat", "deep": False}, headers=ui(client))
    assert "Urgent: your account" in client.get("/?label=phishing").text
    assert "Urgent: your account" not in client.get("/?label=safe").text
    assert client.get("/?label=quarantined").status_code == 200
    assert client.get("/?source=%27%3Bdrop").status_code == 200  # junk filter values are ignored, not executed


def test_no_delete_or_destructive_routes_exist(client):
    app = client.app
    for route in app.routes:
        methods = getattr(route, "methods", set()) or set()
        assert not (methods & {"DELETE", "PUT", "PATCH"}), route.path
        assert "delete" not in route.path.lower() and "trash" not in route.path.lower()


def test_screenshot_route_validates_names(client):
    assert client.get("/shots/..%2F..%2Ftoken").status_code == 404
    assert client.get("/shots/notahash.png").status_code == 404


def test_non_loopback_requires_login(cfg, analyzer):
    cfg.server.host = "0.0.0.0"
    cfg.server.allowed_hosts = ["192.168.1.20"]
    app = create_app(cfg, analyzer=analyzer, start_poller=False)
    c = TestClient(app, base_url="http://192.168.1.20:8765", follow_redirects=False)
    assert c.get("/").status_code == 303 and c.get("/").headers["location"] == "/login"
    # the UI CSRF header alone is not enough off-loopback; a session cookie (or bearer token) is required
    assert c.get("/api/messages", headers={"X-PG-CSRF": app.state.csrf}).status_code == 401
    bad = c.post("/login", data={"token": "nope"})
    assert bad.status_code == 200 and "not right" in bad.text
    ok = c.post("/login", data={"token": cfg.api_token()})
    assert ok.status_code == 303 and "pg_session" in ok.headers["set-cookie"] and "httponly" in ok.headers["set-cookie"].lower()
    assert c.get("/api/messages", headers={"X-PG-CSRF": app.state.csrf}).status_code == 200
