"""Link sandbox worker. Network behaviour is tested against servers this test starts itself on 127.0.0.1;
no real or untrusted URL is ever contacted. The real-browser test drives a local browser against those
pages only and is skipped when no browser is available (production runs it in the container)."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from pg_link_worker import expand as expand_mod
from pg_link_worker.policy import Blocked, check_url, is_public, resolve_public
from pg_link_worker.proxy import FilteringProxy

ROOT = Path(__file__).resolve().parents[1]
HOST_SUFFIX = ".phishtest.example"


# ------------------------------------------------------------------ local test site
class Site(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    seen: list[str] = []

    def log_message(self, *a):  # keep test output quiet
        pass

    def _send(self, code=200, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        Site.seen.append(self.path)
        port = self.server.server_address[1]
        if self.path == "/login":
            self._send(body=(f"<html><head><title>Sign in to your account</title></head><body><h1>Secure login</h1>"
                             f"<form action='http://collector{HOST_SUFFIX}:{port}/collect' method='post'>"
                             f"<input name='user' type='text'><input name='pw' type='password'></form></body></html>").encode())
        elif self.path == "/r1":
            self._send(302, headers={"Location": "/r2"})
        elif self.path == "/r2":
            self._send(301, headers={"Location": "/login"})
        elif self.path == "/loop":
            self._send(302, headers={"Location": "/loop2"})
        elif self.path == "/loop2":
            self._send(302, headers={"Location": "/loop"})
        elif self.path == "/js":
            self._send(body=b"<html><body>wait<script>setTimeout(function(){location.replace('/login')},50)</script></body></html>")
        elif self.path == "/meta":
            self._send(body=b"<html><head><meta http-equiv='refresh' content='0;url=/login'></head><body>moved</body></html>")
        elif self.path == "/dl":
            self._send(body=b"PK-not-really", ctype="application/octet-stream", headers={"Content-Disposition": "attachment; filename=invoice.zip"})
        elif self.path == "/probe":  # a page that tries to reach loopback resources from inside the sandbox
            self._send(body=(f"<html><head><title>probe</title></head><body><img src='http://127.0.0.1:{port}/secret.png'>"
                             f"<script>fetch('http://localhost:{port}/secret2').catch(function(){{}});"
                             f"var i=new Image();i.src='http://[::1]:{port}/secret3';</script></body></html>").encode())
        elif self.path == "/ok":
            self._send(body=b"<html><head><title>Hello</title></head><body><p>Nothing to see</p></body></html>")
        else:
            self._send(404, b"nope", "text/plain")


@pytest.fixture(scope="module")
def site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def local_resolver(host, port):
    """Test-only resolver: names under the test suffix 'resolve' to this machine; everything else goes through the real policy."""
    if host.endswith(HOST_SUFFIX):
        return ["127.0.0.1"]
    return resolve_public(host, port)


# ------------------------------------------------------------------ address policy
@pytest.mark.parametrize("addr,ok", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("93.184.216.34", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("172.16.0.1", False), ("192.168.1.1", False), ("169.254.169.254", False),
    ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False), ("255.255.255.255", False), ("198.18.0.5", False),
    ("::1", False), ("fe80::1", False), ("fc00::1", False), ("::ffff:127.0.0.1", False), ("::ffff:10.0.0.9", False),
    ("::ffff:8.8.8.8", True), ("64:ff9b::7f00:1", False), ("2002:c0a8:0101::1", False), ("not-an-ip", False),
])
def test_is_public(addr, ok):
    assert is_public(addr) is ok


def test_resolve_refuses_internal_names_and_mixed_answers(monkeypatch):
    for h in ("localhost", "metadata.google.internal", "printer.local", "router.lan", "x.internal"):
        with pytest.raises(Blocked):
            resolve_public(h, 80)
    with pytest.raises(Blocked):
        resolve_public("127.0.0.1", 80)
    with pytest.raises(Blocked):
        resolve_public("2130706433", 80)  # decimal spelling of 127.0.0.1

    def fake(host, port, type=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(Blocked):  # one private answer taints the whole name (DNS-rebinding style mixes)
        resolve_public("sneaky.example", 80)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))])
    assert resolve_public("fine.example", 80) == ["93.184.216.34"]


def test_check_url():
    assert check_url("https://example.com/a") == ("https", "example.com", 443)
    assert check_url("http://example.com:8080/a") == ("http", "example.com", 8080)
    for bad in ("file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)", "gopher://x/", "http:///nohost", "http://[::1"):
        with pytest.raises(Blocked):
            check_url(bad)


# ------------------------------------------------------------------ filtering proxy
@pytest.fixture()
def proxy():
    p = FilteringProxy(resolver=local_resolver, max_bytes=2_000_000)
    p.start()
    yield p
    p.stop()


def raw(port: int, payload: bytes, read: int = 65536, timeout: float = 5) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(payload)
        s.settimeout(timeout)
        chunks = b""
        try:
            while True:
                d = s.recv(read)
                if not d:
                    break
                chunks += d
        except (socket.timeout, ConnectionError):
            pass
        return chunks


@pytest.mark.parametrize("target", ["127.0.0.1:{p}", "localhost:{p}", "169.254.169.254:80", "10.0.0.1:443", "[::1]:{p}", "metadata.google.internal:80"])
def test_proxy_refuses_internal_destinations(proxy, site, target):
    tgt = target.format(p=site)
    resp = raw(proxy.port, f"CONNECT {tgt} HTTP/1.1\r\nHost: {tgt}\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.1 403")
    assert proxy.internal_attempts >= 1 and proxy.blocked


def test_proxy_refuses_internal_plain_http(proxy, site):
    resp = raw(proxy.port, f"GET http://127.0.0.1:{site}/ok HTTP/1.1\r\nHost: 127.0.0.1:{site}\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.1 403") and "/ok" not in Site.seen[-1:]


def test_proxy_forwards_allowed_plain_http_and_closes_connection(proxy, site):
    resp = raw(proxy.port, (f"GET http://shop{HOST_SUFFIX}:{site}/ok HTTP/1.1\r\nHost: shop{HOST_SUFFIX}:{site}\r\n"
                            "Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n").encode())
    head, _, body = resp.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.0 200") and b"Nothing to see" in body
    assert b"Connection: close" in head and b"keep-alive" not in head.lower()
    assert f"shop{HOST_SUFFIX}" in proxy.hosts and Site.seen[-1] == "/ok"


def test_proxy_connect_tunnel_passes_bytes(proxy, site):
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(f"CONNECT tunnel{HOST_SUFFIX}:{site} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        assert s.recv(200).startswith(b"HTTP/1.1 200")
        s.sendall(b"GET /ok HTTP/1.0\r\n\r\n")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    assert b"Nothing to see" in data


def test_proxy_rejects_garbage_and_non_http_schemes(proxy):
    assert raw(proxy.port, b"NONSENSE\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert raw(proxy.port, b"GET ftp://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert raw(proxy.port, b"CONNECT host:notaport HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")


def test_proxy_stops_at_byte_budget(site):
    p = FilteringProxy(resolver=local_resolver, max_bytes=100)
    p.start()
    try:
        resp = raw(p.port, f"GET http://big{HOST_SUFFIX}:{site}/login HTTP/1.1\r\nHost: big\r\n\r\n".encode())
        assert b"Secure login" not in resp  # cut off at the budget, the page body never arrives
    finally:
        p.stop()


# ------------------------------------------------------------------ shortener expansion (headers only)
def test_expand_follows_redirects_without_reading_content(site):
    r = expand_mod.expand_one(f"http://short{HOST_SUFFIX}:{site}/r1", resolver=local_resolver)
    assert r["final"].endswith("/login") and [h["status"] for h in r["hops"]] == [302, 301, 200] and r["error"] is None


def test_expand_detects_loops_and_private_targets(site):
    assert expand_mod.expand_one(f"http://x{HOST_SUFFIX}:{site}/loop", resolver=local_resolver)["error"] == "redirect loop"
    Site.seen.clear()
    r = expand_mod.expand_one(f"http://127.0.0.1:{site}/ok")  # real policy: must refuse without connecting
    assert r["internal_target"] is True and r["final"] is None and r["hops"] == [] and Site.seen == []


def test_expand_many_caps_and_shapes(site):
    out = expand_mod.expand_many([f"http://a{HOST_SUFFIX}:{site}/ok"] * 3 + ["ftp://nope/"], resolver=local_resolver)
    assert len(out["results"]) == 2 and out["results"]["ftp://nope/"]["error"]


# ------------------------------------------------------------------ entry point
def run_cli(mode: str, payload: dict) -> tuple[int, dict]:
    p = subprocess.run([sys.executable, "-I", "-m", "pg_link_worker", mode], input=json.dumps(payload).encode(),
                       capture_output=True, cwd=ROOT / "src", timeout=90)
    return p.returncode, (json.loads(p.stdout) if p.stdout else {})


def test_cli_refuses_internal_urls_before_any_browser_starts():
    rc, rep = run_cli("browse", {"url": "http://127.0.0.1:9/", "timeout_s": 15})
    assert rc == 0 and rep["internal_target"] is True and "refused" in rep["error"] and rep["screenshot_b64"] == ""
    rc, rep = run_cli("browse", {"url": "file:///etc/passwd"})
    assert rc == 0 and "only http" in rep["error"]
    rc, rep = run_cli("expand", {"urls": ["http://169.254.169.254/latest/meta-data/"]})
    assert rc == 0 and rep["results"]["http://169.254.169.254/latest/meta-data/"]["internal_target"] is True


def test_cli_rejects_bad_requests():
    p = subprocess.run([sys.executable, "-I", "-m", "pg_link_worker", "browse"], input=b"not json", capture_output=True, cwd=ROOT / "src", timeout=30)
    assert p.returncode == 2
    p = subprocess.run([sys.executable, "-I", "-m", "pg_link_worker", "bogus"], input=b"{}", capture_output=True, cwd=ROOT / "src", timeout=30)
    assert p.returncode == 2


def test_host_schema_accepts_everything_the_worker_emits():
    from phishguard.sandbox.link import sanitize_link_report
    from pg_link_worker.browse import browse

    rep = browse("http://127.0.0.1:9/")  # refused early: still must satisfy the host-side schema
    clean = sanitize_link_report(rep)
    assert clean["internal_target"] is True and clean["forms"] == []


def test_worker_has_no_page_interaction_code():
    """The worker may observe but must never click, type, fill or submit anything on a page."""
    text = (ROOT / "src" / "pg_link_worker" / "browse.py").read_text(encoding="utf-8")
    for banned in (".click(", ".fill(", ".type(", ".press(", ".check(", ".select_option(", ".dispatch_event(", ".set_input_files(", "submit()"):
        assert banned not in text, banned


class _FakePWError(Exception):
    pass


class _FlakyPage:
    """Stands in for a Playwright page: raises the queued errors, then returns 'resp'."""

    def __init__(self, errors):
        self.errors, self.goto_calls, self.waits = list(errors), 0, []

    def goto(self, url, wait_until, timeout):
        self.goto_calls += 1
        if self.errors:
            raise _FakePWError(self.errors.pop(0))
        return "resp"

    def wait_for_timeout(self, ms):
        self.waits.append(ms)


def test_goto_retries_network_changed_then_succeeds():
    from pg_link_worker.browse import _goto_with_retry

    page = _FlakyPage(["Page.goto: net::ERR_NETWORK_CHANGED at https://x/"] * 2)
    assert _goto_with_retry(page, "https://x/", 1000, _FakePWError) == "resp"
    assert page.goto_calls == 3 and len(page.waits) == 2


def test_goto_gives_up_after_bounded_retries():
    from pg_link_worker.browse import NAV_RETRIES, _goto_with_retry

    page = _FlakyPage(["net::ERR_NETWORK_CHANGED"] * 10)
    with pytest.raises(_FakePWError):
        _goto_with_retry(page, "https://x/", 1000, _FakePWError)
    assert page.goto_calls == NAV_RETRIES + 1


@pytest.mark.parametrize("msg", ["net::ERR_NAME_NOT_RESOLVED", "net::ERR_CERT_AUTHORITY_INVALID", "net::ERR_CONNECTION_REFUSED",
                                 "Timeout 30000ms exceeded", "net::ERR_BLOCKED_BY_CLIENT"])
def test_goto_does_not_retry_other_errors(msg):
    from pg_link_worker.browse import _goto_with_retry

    page = _FlakyPage([msg])
    with pytest.raises(_FakePWError):
        _goto_with_retry(page, "https://x/", 1000, _FakePWError)
    assert page.goto_calls == 1 and page.waits == []


# ------------------------------------------------------------------ real browser against local pages only
@pytest.fixture(scope="module")
def browser_kwargs():
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    for kw in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
        try:
            with sync_playwright() as pw:
                b = pw.chromium.launch(headless=True, args=["--no-sandbox"], **kw)
                b.close()
            return kw
        except Exception:
            continue
    pytest.skip("no Chromium-family browser available for the local-page test")


def visit(path: str, site: int, kw: dict, host: str = "victim") -> dict:
    from pg_link_worker.browse import browse

    return browse(f"http://{host}{HOST_SUFFIX}:{site}{path}", timeout_s=30, resolver=local_resolver, launch_kwargs=kw)


def test_browse_records_login_form_redirects_and_screenshot(site, browser_kwargs):
    rep = visit("/r1", site, browser_kwargs)
    assert rep["error"] is None and rep["status"] == 200 and rep["final_url"].endswith("/login")
    assert [r["status"] for r in rep["redirects"]] == [302, 301]
    assert rep["has_login_form"] is True and rep["title"] == "Sign in to your account"
    f = rep["forms"][0]
    assert f["has_password"] and f["cross_origin"] and f["method"] == "post" and f["action"].endswith("/collect")
    assert {i["type"] for i in f["inputs"]} == {"text", "password"}
    import base64

    assert base64.b64decode(rep["screenshot_b64"])[:8] == b"\x89PNG\r\n\x1a\n"
    assert not any(p == "/collect" for p in Site.seen)  # nothing was submitted


def test_browse_sees_js_and_meta_redirects(site, browser_kwargs):
    js = visit("/js", site, browser_kwargs)
    assert js["final_url"].endswith("/login") and js["js_redirects"] >= 1 and js["has_login_form"]
    meta = visit("/meta", site, browser_kwargs)
    assert meta["final_url"].endswith("/login") or "0;url=/login" in meta["meta_refresh"]


def test_browse_records_download_attempt_without_saving(site, browser_kwargs):
    rep = visit("/dl", site, browser_kwargs)
    assert rep["downloads"] == ["invoice.zip"]


def test_browser_cannot_reach_loopback_through_the_page(site, browser_kwargs):
    """A page on a public-looking name that tries to load loopback resources is blocked by the proxy."""
    Site.seen.clear()
    rep = visit("/probe", site, browser_kwargs)
    assert rep["title"] == "probe"                      # the page itself (allowed name) loaded
    assert not [p for p in Site.seen if p.startswith("/secret")], Site.seen   # loopback was never contacted
    assert rep["internal_target"] is True and any("127.0.0.1" in b or "localhost" in b for b in rep["blocked_requests"]), rep["blocked_requests"]

    Site.seen.clear()
    from pg_link_worker.browse import browse

    direct = browse(f"http://127.0.0.1:{site}/ok", timeout_s=20, launch_kwargs=browser_kwargs)  # real policy, refused before any browser starts
    assert direct["internal_target"] is True and Site.seen == []
