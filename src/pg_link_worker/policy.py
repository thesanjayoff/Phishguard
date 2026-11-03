"""Which addresses a sandboxed browser may reach: public internet only.

A phishing link must never be able to make the sandbox talk to the user's LAN, the Docker host,
loopback services or cloud metadata endpoints (SSRF). Names are resolved HERE, the result is checked,
and the connection is made to the checked address (pinned) - so a DNS answer that changes between
"check" and "connect" (DNS rebinding) gets no chance to matter."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class Blocked(Exception):
    """The destination is not allowed. `.reason` is short and safe to put in a report."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15", "240.0.0.0/4",
    "169.254.0.0/16", "fe80::/10", "fc00::/7", "ff00::/8", "::/128", "::1/128",
)]


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv6 forms that carry an IPv4 address which would really be contacted."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip("[]").split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None:
            return is_public(str(inner))
    if any(ip in n for n in _EXTRA_BLOCKED):
        return False
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int) -> list[str]:
    """Resolve `host` and return its addresses, or raise Blocked if ANY of them is not public.

    Requiring every answer to be public (not just the first) means a name that mixes a public and a
    private address cannot be used to steer the connection."""
    host = host.strip("[]").rstrip(".")
    if not host:
        raise Blocked("empty host name")
    try:  # a literal IP; odd spellings such as 2130706433 or 0x7f.1 fall through to getaddrinfo, which normalises them
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if not literal and host.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", "metadata.google.internal"):
        raise Blocked("refused: internal host name")
    if not literal and host.lower().endswith((".local", ".internal", ".localhost", ".lan", ".home.arpa", ".intranet", ".corp")):
        raise Blocked("refused: internal host name")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise Blocked("name does not resolve") from None
    addrs: list[str] = []
    for fam, _t, _p, _c, sa in infos:
        if fam not in (socket.AF_INET, socket.AF_INET6):
            continue
        a = sa[0]
        if not is_public(a):
            raise Blocked("refused: resolves to a private/internal address")
        if a not in addrs:
            addrs.append(a)
    if not addrs:
        raise Blocked("name does not resolve")
    return addrs


def check_url(url: str) -> tuple[str, str, int]:
    """Validate a URL the worker is asked to visit. Returns (scheme, host, port) or raises Blocked."""
    try:
        p = urlsplit(url)
        scheme = (p.scheme or "").lower()
        host = p.hostname or ""
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise Blocked("malformed URL") from None
    if scheme not in ("http", "https"):
        raise Blocked("only http and https links are opened")
    if not host:
        raise Blocked("missing host")
    return scheme, host, port
