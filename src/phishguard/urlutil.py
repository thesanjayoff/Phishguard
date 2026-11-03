"""URL extraction, parsing and defanging. No network access in this module."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote, urlsplit

import tldextract

_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled PSL snapshot, no network


def _reg(ext) -> str:
    # newer tldextract renamed registered_domain (old name warns); support both
    return getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain

_URL_RE = re.compile(
    r"""(?ix)
    (?:\b(?:https?|ftp)://|\bwww\.)           # scheme or www.
    [^\s<>"'`\])}]+                            # up to whitespace / closing bracket
    """
)
# Bare domains such as "bit.ly/abc" or "hdfc-kyc.xyz/login" (common in SMS/chat)
_BARE_RE = re.compile(
    r"(?<![@\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(/[^\s<>\"']*)?(?![\w@-])",
    re.I,
)
_FILE_EXTS = {
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif", "html", "htm",
    "php", "js", "css", "json", "xml", "csv", "exe", "dll", "py", "sh", "bat", "cmd", "ps1", "vbs", "jar",
    "apk", "msi", "rar", "7z", "gz", "tar", "iso", "eml", "log", "md", "ini", "cfg", "sys", "bin",
}
_TRAIL = ".,;:!?)'\"]}>"


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    scheme: str
    host: str  # lower-case, as written (punycode form if given)
    host_unicode: str
    registrable: str  # e.g. "paypal.com"
    subdomain: str
    suffix: str
    port: int | None
    path: str
    query: str
    userinfo: str
    is_ip: bool
    ip: str  # canonical dotted form when is_ip
    is_idn: bool
    explicit_scheme: bool = True

    @property
    def tld(self) -> str:
        return self.suffix.rsplit(".", 1)[-1] if self.suffix else ""

    @property
    def labels(self) -> list[str]:
        return [x for x in self.host.split(".") if x]


def _inet_aton(host: str) -> str | None:
    """Parse legacy IPv4 spellings (decimal int, hex, octal, short forms) like inet_aton."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: list[int] = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif p.startswith("0") and len(p) > 1:
                nums.append(int(p, 8))
            elif p.isdigit():
                nums.append(int(p, 10))
            else:
                return None
        except ValueError:
            return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        return None
    val = 0
    for n in head:
        val = (val << 8) | n
    val = (val << (8 * (5 - len(nums)))) | last
    return str(ipaddress.IPv4Address(val))


def normalize_url(url: str) -> str:
    u = url.strip().strip("<>\"'")
    u = u.rstrip(_TRAIL)
    if re.match(r"(?i)^www\.", u):
        u = "http://" + u
    elif not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", u) and not re.match(r"(?i)^(mailto|tel|javascript|data):", u):
        u = "http://" + u
    return u


@lru_cache(maxsize=4096)
def parse_url(url: str) -> ParsedUrl | None:
    explicit = bool(re.match(r"(?i)^\s*[<\"']?[a-z][a-z0-9+.-]*://", url))
    u = normalize_url(url)
    try:
        sp = urlsplit(u)
        host = (sp.hostname or "").lower().rstrip(".")
        port = sp.port
    except ValueError:
        return None
    if not host:
        return None
    userinfo = sp.netloc.rsplit("@", 1)[0] if "@" in sp.netloc else ""
    is_ip, ip = False, ""
    if ":" in host:  # IPv6 literal
        try:
            ip = str(ipaddress.ip_address(host))
            is_ip = True
        except ValueError:
            pass
    else:
        legacy = _inet_aton(host)
        if legacy:
            is_ip, ip = True, legacy
    try:
        host_unicode = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        host_unicode = host
    if is_ip:
        reg, sub, suffix = ip, "", ""
    else:
        ext = _tld(host)
        reg = _reg(ext) or host
        sub, suffix = ext.subdomain, ext.suffix
    is_idn = "xn--" in host or any(ord(c) > 127 for c in host)
    return ParsedUrl(
        raw=u, scheme=sp.scheme.lower(), host=host, host_unicode=host_unicode, registrable=reg.lower(),
        subdomain=sub.lower(), suffix=suffix.lower(), port=port, path=sp.path, query=sp.query,
        userinfo=unquote(userinfo), is_ip=is_ip, ip=ip, is_idn=is_idn, explicit_scheme=explicit,
    )


def registrable_domain(host_or_email: str) -> str:
    h = host_or_email.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    if not h:
        return ""
    ext = _tld(h)
    return (_reg(ext) or h).lower()


def extract_urls(text: str, allow_bare: bool = True) -> list[str]:
    """Return URLs found in free text, in order, de-duplicated."""
    found: list[str] = []
    spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(_TRAIL)
        if u:
            found.append(u)
            spans.append((m.start(), m.end()))
    if allow_bare:
        for m in _BARE_RE.finditer(text or ""):
            if any(s <= m.start() < e for s, e in spans):
                continue
            dom, path = m.group(1), m.group(2) or ""
            ext = _tld(dom)
            if not ext.suffix or ext.domain == "":
                continue
            last = dom.rsplit(".", 1)[-1].lower()
            if last in _FILE_EXTS and not path:
                continue
            if re.fullmatch(r"\d+(\.\d+)+", dom):  # version numbers
                continue
            found.append((dom + path).rstrip(_TRAIL))
    seen, out = set(), []
    for u in found:
        key = u.lower()
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out


def defang(url: str) -> str:
    """hxxp://evil[.]com/path - safe to display and copy. Idempotent."""
    u = url.strip()
    u = re.sub(r"(?i)^http", "hxxp", u)
    u = re.sub(r"(?i)^ftp", "fxp", u)
    m = re.match(r"^([a-z]+)(?:://|\[://\])([^/?#]*)(.*)$", u, re.I | re.S)
    dot = re.compile(r"(?<!\[)\.(?!\])")
    if m:
        scheme, netloc, rest = m.groups()
        return f"{scheme}://{dot.sub('[.]', netloc)}{rest}"
    head, sep, tail = u.partition("/")
    return dot.sub("[.]", head) + sep + tail


def defang_text(text: str) -> str:
    """Defang every URL / bare domain inside a block of text."""
    def sub(m: re.Match) -> str:
        return defang(m.group(0))

    out = _URL_RE.sub(sub, text or "")
    return out


def refang(s: str) -> str:
    return (s.replace("hxxp", "http").replace("hXXp", "http").replace("[.]", ".").replace("(.)", ".")
             .replace("[://]", "://").replace("fxp://", "ftp://"))
