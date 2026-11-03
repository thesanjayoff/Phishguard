"""Expand shortened links by reading redirect headers only - no page content is fetched or rendered.

Each hop is checked against the public-address policy and the connection is pinned to the checked
address. The body of a response is never read."""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urljoin, urlsplit

from .policy import Blocked, check_url, resolve_public

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
MAX_HEAD = 16 * 1024


def _read_head(sock) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < MAX_HEAD:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\r\n\r\n", 1)[0]


def _hop(url: str, resolver, verify: bool, timeout: float, method: str) -> tuple[int, str | None, bool]:
    """One request. Returns (status, Location or None, cert_failed)."""
    scheme, host, port = check_url(url)
    addrs = resolver(host, port)
    p = urlsplit(url)
    target = (p.path or "/") + (("?" + p.query) if p.query else "")
    last: Exception | None = None
    for ip in addrs[:3]:
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            last = e
            continue
        try:
            raw.settimeout(timeout)
            sock = raw
            if scheme == "https":
                ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # noqa: SLF001 - location header only, never content
                sock = ctx.wrap_socket(raw, server_hostname=host)
            req = f"{method} {target} HTTP/1.1\r\nHost: {p.netloc.rsplit('@', 1)[-1]}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode("latin-1", "replace"))
            head = _read_head(sock).decode("latin-1", "replace")
        except ssl.SSLError:
            raw.close()
            return 0, None, True
        except OSError as e:
            last = e
            continue
        finally:
            try:
                raw.close()
            except OSError:
                pass
        lines = head.split("\r\n")
        try:
            status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError):
            raise Blocked("not an HTTP response") from None
        loc = None
        for ln in lines[1:]:
            if ln.lower().startswith("location:"):
                loc = ln.split(":", 1)[1].strip()
                break
        return status, loc, False
    raise Blocked(f"could not connect ({type(last).__name__ if last else 'no address'})")


def expand_one(url: str, max_hops: int = 8, resolver=resolve_public, timeout: float = 8.0) -> dict:
    hops: list[dict] = []
    cur = url
    seen = {cur}
    cert_error = False
    try:
        for _ in range(max_hops + 1):
            status, loc, cert_failed = _hop(cur, resolver, True, timeout, "HEAD")
            if cert_failed:  # we only want the redirect target, so retry without trust and remember it
                cert_error = True
                status, loc, _ = _hop(cur, resolver, False, timeout, "HEAD")
            if status in (405, 501, 400, 403) and not loc:
                status, loc, _ = _hop(cur, resolver, not cert_error, timeout, "GET")
            hops.append({"url": cur[:2000], "status": status})
            if status in (301, 302, 303, 307, 308) and loc:
                nxt = urljoin(cur, loc)
                if nxt in seen:
                    return {"final": cur, "hops": hops, "error": "redirect loop", "cert_error": cert_error}
                seen.add(nxt)
                cur = nxt
                continue
            return {"final": cur, "hops": hops, "error": None, "cert_error": cert_error}
        return {"final": cur, "hops": hops, "error": "too many redirects", "cert_error": cert_error}
    except Blocked as e:
        return {"final": cur if cur != url else None, "hops": hops, "error": e.reason, "cert_error": cert_error,
                "internal_target": "private" in e.reason or "internal" in e.reason}
    except Exception as e:  # network errors are data, not crashes
        return {"final": cur if cur != url else None, "hops": hops, "error": type(e).__name__, "cert_error": cert_error}


def expand_many(urls: list[str], max_hops: int = 8, resolver=resolve_public) -> dict:
    results = {}
    for u in urls[:20]:
        results[u] = expand_one(u, max_hops=min(max_hops, 10), resolver=resolver)
    return {"results": results}
