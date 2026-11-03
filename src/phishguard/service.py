"""Scan orchestration: analyse a message, store the (minimal) result, quarantine if needed.
NEVER deletes anything - quarantine = a label/folder on the provider side, or a local flag."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .layers.ml import _vectorizer, feature_text
from .models import PHISHING, Message, Verdict
from .pipeline import Analyzer
from .redact import snippet, redact

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    verdict: Verdict
    message_id: int | None
    quarantined: bool = False
    quarantine_note: str = ""


def hashed_features(msg: Message) -> dict[str, int]:
    X = _vectorizer().transform([feature_text(msg)]).tocsr()
    return {str(i): int(v) for i, v in zip(X.indices, X.data)}


class Scanner:
    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer
        self.cfg = analyzer.cfg
        self.store = analyzer.store
        self.sources: dict[str, object] = {}  # name -> source object with .quarantine(external_id)

    def register_source(self, name: str, source: object) -> None:
        self.sources[name] = source

    def scan(self, msg: Message, persist: bool = True, deep: bool = True) -> ScanResult:
        verdict = self.analyzer.analyze(msg, deep=deep)
        if not persist:
            return ScanResult(verdict, None)
        sender = (f"{msg.from_name} <{msg.from_addr}>" if msg.from_addr else msg.sender_id) or ""
        snip = snippet(msg.text, self.cfg.privacy.snippet_chars) if self.cfg.privacy.store_snippet else ""
        mid = self.store.save_message(
            source=msg.source, external_id=msg.external_id, kind=msg.kind,
            received_at=msg.received_at.isoformat(), sender=sender[:200], subject=redact(msg.subject)[:200],
            snippet=snip, verdict=verdict.to_dict(), features=hashed_features(msg),
        )
        res = ScanResult(verdict, mid)
        if verdict.label == PHISHING:
            res.quarantined, res.quarantine_note = self._quarantine(mid, msg)
        return res

    def _quarantine(self, mid: int, msg: Message) -> tuple[bool, str]:
        note = "flagged locally (see Quarantine view)"
        src = self.sources.get(msg.source)
        if src is not None and msg.external_id and hasattr(src, "quarantine"):
            try:
                note = src.quarantine(msg.external_id)  # type: ignore[attr-defined]
            except Exception as e:  # never let a provider hiccup lose the verdict
                log.warning("remote quarantine failed: %s", type(e).__name__)
                note = f"flagged locally; provider quarantine failed ({type(e).__name__})"
        self.store.set_quarantined(mid, True, note)
        return True, note
