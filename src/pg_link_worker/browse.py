"""Open one URL in a fresh, empty, headless Chromium and record what happened. Passive only:
nothing is clicked, typed or submitted, no cookies or profile exist, downloads are cancelled, dialogs
are dismissed, popups are closed, and all traffic goes through the filtering proxy (public addresses only)."""
from __future__ import annotations

import base64
from typing import Any, Callable

from .policy import Blocked, check_url, resolve_public
from .proxy import FilteringProxy

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# --no-sandbox: Chromium's own sandbox needs kernel features that a capability-less, read-only container does
# not have. The container (no network but the proxy, no caps, read-only, non-root, resource limits) is the
# boundary instead. The remaining flags keep traffic on the proxy and stop background phoning-home.
CHROMIUM_ARGS = [
    "--no-sandbox", "--disable-gpu", "--disable-extensions", "--disable-background-networking", "--disable-sync",
    "--disable-component-update", "--disable-default-apps", "--no-first-run", "--no-default-browser-check",
    "--disable-breakpad", "--disable-quic", "--mute-audio", "--disable-notifications",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--proxy-bypass-list=<-loopback>",
]

PAGE_SCRIPT = """() => {
  const abs = u => { try { return new URL(u, location.href).href; } catch (e) { return String(u || ''); } };
  const origin = u => { try { return new URL(u, location.href).origin; } catch (e) { return ''; } };
  const forms = Array.from(document.forms).slice(0, 10).map(f => {
    const act = f.getAttribute('action') || location.href;
    const inputs = Array.from(f.elements).filter(e => ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.tagName)).slice(0, 30)
      .map(e => ({type: (e.type || e.tagName).toLowerCase(), name: String(e.name || e.id || '').slice(0, 40)}));
    return {action: abs(act), method: String(f.method || 'get').toLowerCase(), has_password: inputs.some(i => i.type === 'password'),
            cross_origin: origin(act) !== location.origin, inputs};
  });
  const meta = document.querySelector('meta[http-equiv="refresh" i]');
  return {
    title: String(document.title || '').slice(0, 200),
    text: String(document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').trim().slice(0, 600),
    forms, password_inputs: document.querySelectorAll('input[type=password]').length,
    meta_refresh: meta ? String(meta.getAttribute('content') || '').slice(0, 200) : '',
    iframes: document.querySelectorAll('iframe').length,
  };
}"""


def _is_cert_error(msg: str) -> bool:
    m = msg.upper()
    return "ERR_CERT" in m or "ERR_SSL" in m or "SSL_ERROR" in m or "CERTIFICATE" in m


def browse(url: str, timeout_s: int = 45, screenshot: bool = True, resolver: Callable = resolve_public,
           launch_kwargs: dict | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "url": url, "final_url": "", "status": None, "title": "", "text_excerpt": "", "redirects": [], "forms": [],
        "has_login_form": False, "cert_error": False, "downloads": [], "js_redirects": 0, "meta_refresh": "",
        "blocked_requests": [], "third_party_domains": [], "requests_count": 0, "error": None, "internal_target": False,
        "screenshot_b64": "", "popups": 0, "iframes": 0,
    }
    try:  # refuse before any browser or connection exists
        _scheme, host, port = check_url(url)
        resolver(host, port)
    except Blocked as e:
        out["error"] = e.reason
        out["internal_target"] = "private" in e.reason or "internal" in e.reason
        return out

    from playwright.sync_api import Error as PWError, sync_playwright

    proxy = FilteringProxy(resolver=resolver)
    proxy_port = proxy.start()
    try:
        with sync_playwright() as pw:
            kwargs = dict(launch_kwargs or {})
            browser = pw.chromium.launch(headless=True, args=CHROMIUM_ARGS + [f"--proxy-server=http://127.0.0.1:{proxy_port}"], **kwargs)
            try:
                for attempt in (1, 2):
                    ignore_tls = attempt == 2
                    state = _visit(browser, url, timeout_s, screenshot, ignore_tls, out, PWError)
                    if state == "cert" and attempt == 1:
                        out["cert_error"] = True  # look at the page anyway (self-signed phishing kits are common)
                        continue
                    break
            finally:
                browser.close()
    except Exception as e:
        out["error"] = out["error"] or f"browser error: {type(e).__name__}: {str(e)[:160]}"
    finally:
        proxy.stop()
    out["blocked_requests"] = proxy.blocked[:10]
    out["internal_target"] = out["internal_target"] or proxy.internal_attempts > 0
    out["requests_count"] = proxy.requests
    final_host = (check_host(out["final_url"]) or "").lower()
    out["third_party_domains"] = [h for h in proxy.hosts if h != final_host][:20]
    return out


def check_host(url: str) -> str:
    try:
        return check_url(url)[1]
    except Blocked:
        return ""


TRANSIENT_NET_ERRORS = ("ERR_NETWORK_CHANGED",)
NAV_RETRIES = 2  # extra attempts, only for errors that say nothing about the URL itself


def _goto_with_retry(page, url: str, timeout_ms: float, PWError, sleep_ms: int = 400):
    """page.goto, retried a bounded number of times when Chromium reports that the container's network
    interfaces changed mid-request (seen right after a container starts). Any other error is raised at once."""
    for attempt in range(NAV_RETRIES + 1):
        try:
            return page.goto(url, wait_until="load", timeout=timeout_ms)
        except PWError as e:
            if attempt < NAV_RETRIES and any(t in str(e) for t in TRANSIENT_NET_ERRORS):
                page.wait_for_timeout(sleep_ms)
                continue
            raise


def _visit(browser, url: str, timeout_s: int, want_shot: bool, ignore_tls: bool, out: dict, PWError) -> str:
    ctx = browser.new_context(
        ignore_https_errors=ignore_tls, accept_downloads=False, java_script_enabled=True, service_workers="block",
        user_agent=UA, locale="en-US", viewport={"width": 1280, "height": 800}, permissions=[], bypass_csp=False,
    )
    nav = {"count": 0}
    try:
        ctx.set_default_timeout(max(5, timeout_s * 0.6) * 1000)
        ctx.route("**/*", lambda route: route.abort() if route.request.resource_type == "media" else route.continue_())
        page = ctx.new_page()
        page.on("dialog", lambda d: d.dismiss())
        page.on("download", lambda d: (out["downloads"].append((d.suggested_filename or "download")[:200]), _safe(d.cancel)))
        ctx.on("page", lambda p: (out.__setitem__("popups", out["popups"] + 1), _safe(p.close)) if p != page else None)
        page.on("framenavigated", lambda f: nav.__setitem__("count", nav["count"] + 1) if f == page.main_frame else None)
        resp = None
        try:
            resp = _goto_with_retry(page, url, max(5, timeout_s * 0.6) * 1000, PWError)
        except PWError as e:
            msg = str(e)
            if _is_cert_error(msg) and not ignore_tls:
                return "cert"
            if "Download is starting" in msg:
                out["error"] = None  # the link is a file download; recorded below
            elif "ERR_BLOCKED_BY_CLIENT" in msg or "ERR_TUNNEL_CONNECTION_FAILED" in msg or "ERR_PROXY_CONNECTION_FAILED" in msg or "ERR_NAME_NOT_RESOLVED" in msg:
                out["error"] = "the sandbox refused or could not reach this address"
            else:
                out["error"] = _short(msg)
        if resp is not None:
            out["status"] = resp.status
            chain = []
            req = resp.request
            while req.redirected_from:
                req = req.redirected_from
                r = req.response()
                chain.append({"url": req.url, "status": r.status if r else None})
            out["redirects"] = list(reversed(chain))[:15]
        try:
            page.wait_for_load_state("networkidle", timeout=3500)  # let script-driven redirects happen
        except PWError:
            pass
        page.wait_for_timeout(600)
        out["final_url"] = page.url if page.url.startswith(("http://", "https://")) else out["final_url"]
        out["js_redirects"] = max(0, nav["count"] - 1)
        try:
            info = page.evaluate(PAGE_SCRIPT)
            out["title"] = info.get("title", "")
            out["text_excerpt"] = info.get("text", "")
            out["forms"] = info.get("forms", [])
            out["meta_refresh"] = info.get("meta_refresh", "")
            out["iframes"] = info.get("iframes", 0)
            out["has_login_form"] = any(f.get("has_password") for f in out["forms"]) or info.get("password_inputs", 0) > 0
        except PWError:
            pass
        if want_shot and out["final_url"]:
            try:
                png = page.screenshot(type="png", full_page=False, timeout=8000)
                if len(png) <= 3 * 1024 * 1024:
                    out["screenshot_b64"] = base64.b64encode(png).decode("ascii")
            except PWError:
                pass
        return "ok"
    finally:
        try:
            ctx.close()
        except Exception:
            pass


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _short(msg: str) -> str:
    line = msg.strip().splitlines()[0] if msg.strip() else "navigation failed"
    return line.replace("Page.goto: ", "")[:200]
