"""Shared helpers for the static attachment analyser.

Everything here works on bytes in memory. Nothing is executed, imported from the sample, written to disk
under a name taken from the sample, or sent over a network."""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections import Counter
from typing import Any

ENGINE = "pg_re_worker/0.1 (static)"
SEVERITIES = ("info", "low", "medium", "high", "critical")


class BudgetExceeded(Exception):
    pass


class Budget:
    """Work limits shared by every recursive step, so a hostile file cannot make us do unbounded work."""

    def __init__(self, max_total_bytes: int = 160 << 20, max_members: int = 3000, max_depth: int = 3, seconds: float = 70.0):
        self.bytes_left = max_total_bytes
        self.members_left = max_members
        self.max_depth = max_depth
        self.deadline = time.monotonic() + seconds
        self.bytes_processed = 0

    def tick(self) -> None:
        if time.monotonic() > self.deadline:
            raise BudgetExceeded("time budget exhausted")

    def spend(self, n: int) -> None:
        self.bytes_left -= n
        self.bytes_processed += n
        if self.bytes_left < 0:
            raise BudgetExceeded("byte budget exhausted")

    def member(self) -> None:
        self.members_left -= 1
        if self.members_left < 0:
            raise BudgetExceeded("too many archive members")


def entropy(data: bytes, limit: int = 4 << 20) -> float:
    d = data[:limit]
    if not d:
        return 0.0
    n = len(d)
    return -sum((c / n) * math.log2(c / n) for c in Counter(d).values())


def hashes(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()}


def safe_name(name: str, limit: int = 120) -> str:
    """A name taken from inside a sample is data: strip control and bidi-override characters, bound the length."""
    cleaned = "".join(c if (c.isprintable() and c not in "‮‭⁦⁧⁨⁩‎‏") else "?" for c in name)
    return cleaned[:limit]


def ext_of(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


class Report:
    def __init__(self, filename: str, data: bytes):
        self.d: dict[str, Any] = {
            "filename": safe_name(filename, 200), "size": len(data), **hashes(data), "file_type": "", "declared_ext": ext_of(filename),
            "type_mismatch": False, "entropy": round(entropy(data), 3), "packed": False, "encrypted": False,
            "iocs": {k: [] for k in ("urls", "ips", "domains", "emails", "registry", "paths", "commands")},
            "behaviors": [], "imports": [], "strings": [], "macros": [], "children": [], "warnings": [], "errors": [], "engine": ENGINE,
        }
        self._seen: set[tuple[str, str]] = set()

    def behavior(self, id_: str, severity: str, title: str, detail: str = "", snippet: str = "", snippet_kind: str = "", location: str = "") -> None:
        assert severity in SEVERITIES
        key = (id_, location)
        if key in self._seen:
            return
        self._seen.add(key)
        self.d["behaviors"].append({"id": id_, "severity": severity, "title": title, "detail": detail[:500],
                                     "snippet": snippet[:3000], "snippet_kind": snippet_kind, "location": location[:160]})

    def warn(self, msg: str) -> None:
        if msg not in self.d["warnings"]:
            self.d["warnings"].append(msg[:300])

    def error(self, msg: str) -> None:
        self.d["errors"].append(msg[:300])

    def add_iocs(self, text: str, kinds: tuple[str, ...] = ("urls", "ips", "domains", "emails", "registry", "paths", "commands"),
                 binary: bool = False) -> None:
        found = extract_iocs(text, binary=binary)
        for k in kinds:
            cur = self.d["iocs"][k]
            for v in found.get(k, []):
                if v not in cur and len(cur) < 100:
                    cur.append(v)


# ---------------------------------------------------------------------------- indicator extraction
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>\\^`{}|)\]\x00-\x1f]{4,300}")
_IP = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]{2,40}@[a-z0-9-]{2,40}(?:\.[a-z0-9-]{2,20}){1,3}\b")
_REG = re.compile(r"(?i)\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U))\\[^\s\"'<>|]{3,160}")
_PATH = re.compile(r"(?i)(?:\b[a-z]:\\(?:[^\s\"'<>|:*?]{2,}\\?){1,6}|%(?:appdata|localappdata|temp|programdata|userprofile|public|windir|systemroot)%\\[^\s\"'<>|]{2,100})")
_CMD = re.compile(r"(?i)[^\r\n]{0,60}\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?\s+/[ck]|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32|regsvr32|certutil|bitsadmin|schtasks|msiexec|wmic)\b[^\r\n]{0,140}")
_TLDS = ("com|net|org|info|biz|top|xyz|click|link|online|site|shop|club|live|work|support|icu|cc|ru|cn|tk|ml|ga|cf|gq|pw|ws|su|"
         "in|co|me|io|us|uk|de|fr|nl|br|ng|pk|bd|ir|vn|id|tr|ua|pl|ro|kz|lk")
_DOMAIN = re.compile(rf"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{{0,40}}[a-z0-9])?\.){{1,4}}(?:{_TLDS}))\b")
_PRIVATE = re.compile(r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.|2(?:2[4-9]|[3-5]\d)\.)")
_NOT_DOMAIN_SUFFIX = {"dll", "exe", "sys", "drv", "ocx", "so", "py", "js", "vbs", "ps1", "bat", "cmd", "doc", "xls", "pdf"}


def extract_iocs(text: str, binary: bool = False) -> dict[str, list[str]]:
    """`binary=True` is for strings carved out of executables, where bare "1.2.3.4" is usually a version number and
    bare "x.py" a file name: addresses then only count when they appear inside a URL."""
    out: dict[str, list[str]] = {k: [] for k in ("urls", "ips", "domains", "emails", "registry", "paths", "commands")}

    def add(k: str, v: str) -> None:
        v = v.strip().rstrip(".,;:'\")")
        if v and v not in out[k] and len(out[k]) < 100:
            out[k].append(v[:300])

    for m in _URL.finditer(text):
        add("urls", m.group(0))
    url_hosts = {m.group(0).split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower() for m in _URL.finditer(text)}
    for h in url_hosts:
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h):
            if not _PRIVATE.match(h):
                add("ips", h)
        elif h:
            add("domains", h)
    if not binary:
        for m in _IP.finditer(text):
            if not _PRIVATE.match(m.group(1)):
                add("ips", m.group(1))
        for m in _DOMAIN.finditer(text):
            d = m.group(1).lower()
            if d.rsplit(".", 1)[-1] not in _NOT_DOMAIN_SUFFIX:
                add("domains", d)
    for m in _EMAIL.finditer(text):
        add("emails", m.group(0))
    for m in _REG.finditer(text):
        add("registry", m.group(0))
    for m in _PATH.finditer(text):
        add("paths", m.group(0))
    for m in _CMD.finditer(text):
        add("commands", m.group(0)[:200])
    return out


_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_INTERESTING = re.compile(
    r"(?i)(https?://|\.exe\b|\.dll\b|\.ps1\b|\.vbs\b|\.bat\b|powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32|currentversion\\run|"
    r"base64|frombase64|eval\(|shell|download|createobject|virtualalloc|password|login|token|bot\d{5,}:|api\.telegram|discord)")


def printable_strings(data: bytes, limit: int = 2 << 20) -> list[str]:
    d = data[:limit]
    found = [m.group(0).decode("ascii", "replace") for m in _ASCII.finditer(d)]
    found += [m.group(0).decode("utf-16le", "replace") for m in _UTF16.finditer(d)]
    seen: dict[str, None] = {}
    for s in found:
        seen.setdefault(s, None)
    uniq = list(seen)
    interesting = [s for s in uniq if _INTERESTING.search(s)]
    rest = [s for s in uniq if s not in set(interesting)]
    return [s[:200] for s in (interesting + rest)[:60]]


def line_context(text: str, pos: int, before: int = 1, after: int = 1, width: int = 400) -> tuple[str, int]:
    """The lines around a match (for a readable snippet) and the 1-based line number of the match."""
    lines = text.splitlines()
    upto = text[:pos].count("\n")
    lo, hi = max(0, upto - before), min(len(lines), upto + after + 1)
    return "\n".join(l[:width] for l in lines[lo:hi]), upto + 1
