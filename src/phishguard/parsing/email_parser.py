"""RFC 5322 / MIME -> Message. Also builds Message objects from SMS and pasted text."""
from __future__ import annotations

import email
import email.policy
import email.utils
import re
from datetime import datetime, timezone
from email.message import EmailMessage, Message as PyMessage

from ..models import Attachment, Message, UrlRef
from ..urlutil import extract_urls
from .html_info import parse_html

_RAW_EMAIL_HINT = re.compile(r"(?im)^(received|from|subject|return-path|message-id|mime-version|content-type|date):")


def _decode_header(v) -> str:
    try:
        return str(v) if v is not None else ""
    except Exception:
        return ""


def _safe_get_content(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        for enc in (part.get_content_charset() or "utf-8", "utf-8", "latin-1"):
            try:
                return payload.decode(enc, errors="replace")
            except (LookupError, UnicodeDecodeError):
                continue
        return ""


def _addr(value: str) -> tuple[str, str]:
    name, addr = email.utils.parseaddr(value or "")
    return name.strip(), addr.strip().lower()


def parse_email(data: bytes | str, source: str = "paste", external_id: str | None = None) -> Message:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    # tolerate mbox "From " envelope line
    if data.startswith(b"From ") and b"\n" in data[:2000]:
        data = data.split(b"\n", 1)[1]
    try:
        em = email.message_from_bytes(data, policy=email.policy.default)
    except Exception:
        em = email.message_from_bytes(data)

    headers: dict[str, list[str]] = {}
    try:
        for k, v in em.raw_items():
            headers.setdefault(k.lower(), []).append(re.sub(r"\s+", " ", _decode_header(v)).strip())
    except Exception:
        pass

    from_name, from_addr = _addr(headers.get("from", [""])[0])
    _, reply_to = _addr(headers.get("reply-to", [""])[0])
    return_path = headers.get("return-path", [""])[0].strip("<> ").lower()

    try:
        received = email.utils.parsedate_to_datetime(headers.get("date", [""])[0])
        if received.tzinfo is None:
            received = received.replace(tzinfo=timezone.utc)
    except Exception:
        received = datetime.now(timezone.utc)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    for part in em.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        if fname or disp == "attachment" or (ctype not in ("text/plain", "text/html") and not ctype.startswith("multipart")):
            if ctype == "message/rfc822":  # forwarded email: analyse its text, keep as attachment too
                payload = part.get_payload()
                if isinstance(payload, list) and payload:
                    inner = payload[0]
                    text_parts.append(_safe_get_content(inner) if inner.get_content_type() == "text/plain" else "")
            data_bytes = part.get_payload(decode=True) or b""
            if isinstance(data_bytes, bytes) and (fname or data_bytes):
                if ctype.startswith("image/") and not fname:
                    continue  # inline logos
                attachments.append(Attachment(filename=_safe_name(fname or "unnamed"), content_type=ctype, data=data_bytes))
            continue
        if ctype == "text/plain":
            text_parts.append(_safe_get_content(part))
        elif ctype == "text/html":
            html_parts.append(_safe_get_content(part))

    html = "\n".join(html_parts)
    text = "\n".join(t for t in text_parts if t).strip()
    info = parse_html(html) if html else None
    if info and (not text or len(info.text) > len(text) * 1.2):
        analysis_text = info.text
    else:
        analysis_text = text

    msg = Message(
        source=source, kind="email", external_id=external_id,
        subject=re.sub(r"\s+", " ", headers.get("subject", [""])[0]).strip(),
        from_name=from_name, from_addr=from_addr, reply_to=reply_to, return_path=return_path,
        to_addr=_addr(headers.get("to", [""])[0])[1],
        text=analysis_text, html=html, headers=headers, received_at=received, attachments=attachments,
    )
    msg.urls = collect_urls(msg, info)
    return msg


def _safe_name(name: str) -> str:
    name = re.sub(r"[\x00-\x1f]", "", name)
    return name[:200]


def collect_urls(msg: Message, info=None) -> list[UrlRef]:
    out: list[UrlRef] = []
    seen: set[str] = set()

    def add(url: str, text: str = "", origin: str = "text") -> None:
        url = url.strip()
        if not url:
            return
        key = url.lower()
        if key in seen:
            # upgrade a text-only reference with anchor info
            if origin == "a":
                for r in out:
                    if r.url.lower() == key and r.origin != "a":
                        r.text, r.origin = text, "a"
            return
        seen.add(key)
        out.append(UrlRef(url=url, text=text, origin=origin))

    if info is None and msg.html:
        info = parse_html(msg.html)
    if info:
        for a in info.anchors:
            if re.match(r"(?i)^(https?:|www\.)", a.href):
                add(a.href, a.text, "a")
        for f in info.forms:
            if re.match(r"(?i)^https?:", f.action):
                add(f.action, "", "form")
        for s in info.iframe_srcs:
            if re.match(r"(?i)^https?:", s):
                add(s, "", "other")
    for u in extract_urls(msg.text, allow_bare=msg.kind != "email"):
        add(u, "", "text")
    if info:
        for u in extract_urls(info.text, allow_bare=False):
            add(u, "", "text")
    return out


def from_sms(body: str, sender: str = "", received_at: datetime | None = None, source: str = "sms",
             external_id: str | None = None) -> Message:
    msg = Message(source=source, kind="sms", external_id=external_id, sender_id=sender.strip(), text=body or "",
                  subject="", received_at=received_at or datetime.now(timezone.utc))
    msg.urls = collect_urls(msg)
    return msg


def from_text(text: str, source: str = "paste", kind: str | None = None, sender: str = "") -> Message:
    """Pasted/shared content: a raw email, a bare URL, or chat/SMS text."""
    t = (text or "").strip()
    if kind in (None, "email") and _looks_like_raw_email(t):
        return parse_email(t, source=source)
    only_url = re.fullmatch(r"\S+", t) and extract_urls(t)
    k = kind or ("url" if only_url else "chat")
    msg = Message(source=source, kind=k, text=t, sender_id=sender.strip())
    msg.urls = collect_urls(msg)
    return msg


def _looks_like_raw_email(t: str) -> bool:
    head = t[:4000]
    if "\n\n" not in head and "\r\n\r\n" not in head:
        return False
    first_block = re.split(r"\r?\n\r?\n", head, 1)[0]
    hits = len(_RAW_EMAIL_HINT.findall(first_block))
    return hits >= 2 and bool(re.search(r"(?im)^(from|subject|received|return-path):", first_block))
