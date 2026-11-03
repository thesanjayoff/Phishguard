"""Message sources (read-only by default). A source yields `Message` objects and may optionally expose
`quarantine(external_id)`, which only ever *labels or moves* a message - no source has any delete code path.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator

from ..config import Config
from ..models import Message

log = logging.getLogger(__name__)

SOURCE_NAMES = ("gmail", "imap", "outlook")


class SourceError(RuntimeError):
    pass


class Source(ABC):
    name: str = ""

    @abstractmethod
    def fetch(self, seen: "callable") -> Iterable[Message]:
        """Yield recent messages. `seen(external_id) -> bool` lets the source skip already-scanned ones
        *before* downloading their bodies."""

    def quarantine(self, external_id: str) -> str:  # optional; only when enabled in config
        raise NotImplementedError


def build_source(cfg: Config, name: str) -> Source | None:
    """Create a configured source, or None when it is disabled."""
    if name == "gmail" and cfg.gmail.enabled:
        from .gmail import GmailSource

        return GmailSource(cfg)
    if name == "imap" and cfg.imap.enabled:
        from .imap import ImapSource

        return ImapSource(cfg)
    if name == "outlook" and cfg.outlook.enabled:
        from .outlook import OutlookSource

        return OutlookSource(cfg)
    return None


def poll_sources(cfg: Config, scanner, names: list[str] | None = None) -> Iterator[str]:
    """Fetch new mail from the enabled sources, scan it, and yield one summary line per message."""
    wanted = [n for n in (names or SOURCE_NAMES) if n in SOURCE_NAMES]
    if not wanted:
        yield f"unknown source (choose from: {', '.join(SOURCE_NAMES)})"
        return
    any_enabled = False
    for name in wanted:
        try:
            src = build_source(cfg, name)
        except SourceError as e:
            yield f"[{name}] not ready: {e}"
            continue
        if src is None:
            continue
        any_enabled = True
        scanner.register_source(name, src)
        count = 0
        try:
            for msg in src.fetch(lambda ext, _n=name: scanner.store.has_message(_n, ext)):
                res = scanner.scan(msg)
                count += 1
                v = res.verdict
                mark = " [quarantined]" if res.quarantined else ""
                yield f"[{name}] {v.label.upper():10s} {v.score:3d}  {(msg.subject or msg.sender_id or '')[:60]!r}{mark}"
        except SourceError as e:
            yield f"[{name}] error: {e}"
        except Exception as e:  # network/auth hiccup must not kill the other sources
            log.warning("source %s failed: %s", name, type(e).__name__)
            yield f"[{name}] failed: {type(e).__name__}"
        else:
            yield f"[{name}] {count} new message(s) scanned"
    if not any_enabled:
        yield "no sources enabled - set [gmail], [imap] or [outlook] enabled = true in config.toml"


def authenticate(cfg: Config, provider: str) -> str:
    """One-time interactive sign-in (Gmail: browser; Outlook: device code). IMAP needs no sign-in."""
    if provider == "gmail":
        from .gmail import authenticate as auth
    elif provider == "outlook":
        from .outlook import authenticate as auth
    elif provider == "imap":
        return "IMAP uses the password in the environment variable named by imap.password_env; nothing to authorise."
    else:
        return f"unknown provider {provider!r}"
    return auth(cfg)
