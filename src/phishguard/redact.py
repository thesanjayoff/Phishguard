"""Redaction helpers: used for log lines, stored snippets, and any text that
is allowed to leave the machine (LLM). Aggressive on purpose."""
from __future__ import annotations

import logging
import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"(https?://[^\s/?#<>\"']+)([^\s<>\"']*)", re.I)
_PHONE = re.compile(r"(?<![\w.])(?:\+?\d[\d\s().-]{8,}\d)(?![\w.])")
# "OTP 123456", "OTP: 123456", "OTP is 123456", "your verification code was 123456", "PIN no. 1234"
_OTP = re.compile(r"(?i)\b(otp|code|pin|cvv|cvc|password|passcode)\b((?:[^\w\n]|\b(?:is|was|number|no|your|the)\b){0,24}?)(\d{3,8})\b")
_LONGNUM = re.compile(r"\b\d{9,19}\b")  # card / account / aadhaar-like
_SECRET = re.compile(r"(?i)\b(?:bearer|token|api[_-]?key|secret|password)\b\s*[:=]?\s*[A-Za-z0-9._~+/=-]{8,}")
_LONGTOKEN = re.compile(r"\b[A-Za-z0-9_-]{32,}\b")


def redact(text: str, keep_domains: bool = True) -> str:
    """Remove personal data but keep enough shape to be useful."""
    if not text:
        return text
    t = _SECRET.sub("[secret]", text)
    t = _OTP.sub(lambda m: f"{m.group(1)}{m.group(2)}[num]", t)
    t = _URL.sub(lambda m: (m.group(1) + ("/…" if m.group(2) else "")) if keep_domains else "[url]", t)
    t = _EMAIL.sub(lambda m: f"[email@{m.group(1)}]" if keep_domains else "[email]", t)
    t = _PHONE.sub("[phone]", t)
    t = _LONGNUM.sub("[num]", t)
    t = _LONGTOKEN.sub("[token]", t)
    return t


def snippet(text: str, n: int) -> str:
    t = " ".join((text or "").split())
    return redact(t)[:n]


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - malformed log call
            return True
        record.msg = redact(msg)
        record.args = ()
        return True


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(f, RedactingFilter) for f in root.filters):
        root.addFilter(RedactingFilter())
    if not root.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        h.addFilter(RedactingFilter())
        root.addHandler(h)
    else:
        for h in root.handlers:
            if not any(isinstance(f, RedactingFilter) for f in h.filters):
                h.addFilter(RedactingFilter())
    logging.getLogger("uvicorn.access").addFilter(RedactingFilter())
