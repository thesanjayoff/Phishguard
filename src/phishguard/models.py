"""Core data types shared by every layer. Plain dataclasses, JSON-serialisable."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SAFE, SUSPICIOUS, PHISHING = "safe", "suspicious", "phishing"

LAYERS = ("headers", "urls", "content", "behavior", "attachments", "feedback")


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes = b""

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class UrlRef:
    """A URL found in a message. `text` is what the user *sees* for HTML anchors."""

    url: str
    text: str = ""
    origin: str = "text"  # text | a | form | img | other


@dataclass
class Message:
    source: str = "paste"  # gmail | imap | outlook | sms | paste | share | cli
    kind: str = "email"  # email | sms | chat | url | text
    external_id: str | None = None
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    sender_id: str = ""  # SMS sender (alphanumeric DLT header or phone number)
    to_addr: str = ""
    text: str = ""
    html: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)  # lower-cased names
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attachments: list[Attachment] = field(default_factory=list)
    urls: list[UrlRef] = field(default_factory=list)
    # body text candidates for archive passwords etc. is derived on demand

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    def header(self, name: str) -> str:
        v = self.headers.get(name.lower())
        return v[0] if v else ""

    def all_headers(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])

    @property
    def is_bulk(self) -> bool:
        """Mailing-list / newsletter style mail. Such mail legitimately uses a different Reply-To, bounce
        domain and off-site links, so those *weak* signals are skipped. Attackers can add these headers too,
        which is why only the weak mismatch signals are suppressed - authentication failures and brand
        spoofing are never skipped."""
        if self.kind != "email":
            return False
        if self.header("list-id") or self.header("list-unsubscribe") or self.header("list-post") or self.header("mailing-list"):
            return True
        return self.header("precedence").strip().lower() in ("list", "bulk")

    @property
    def body_for_analysis(self) -> str:
        return self.text or ""


@dataclass
class Signal:
    """One piece of evidence. `points` is the contribution to its layer's risk
    (negative for mitigating evidence)."""

    layer: str
    id: str
    points: float
    reason: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    score: int
    label: str
    signals: list[Signal]
    layer_scores: dict[str, float]
    summary: str = ""
    notes: list[str] = field(default_factory=list)  # e.g. "sandbox unavailable"
    attachment_reports: list[dict[str, Any]] = field(default_factory=list)
    link_reports: list[dict[str, Any]] = field(default_factory=list)
    urls: list[dict[str, Any]] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # malicious/suspicious domains
    facts: dict[str, Any] = field(default_factory=dict)  # sender_key, auth_ok, ...

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def label_for(score: float, suspicious: int, phishing: int) -> str:
    if score >= phishing:
        return PHISHING
    if score >= suspicious:
        return SUSPICIOUS
    return SAFE
