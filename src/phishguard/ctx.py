"""Shared analysis context handed to every layer."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .intel import Intel
from .knowledge import Knowledge, load
from .models import Signal
from .store import Store


@dataclass
class Ctx:
    cfg: Config
    store: Store
    intel: Intel
    kb: Knowledge = field(default_factory=load)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # learned multipliers per signal id (from feedback); 1.0 when unknown
    weights: dict[str, float] = field(default_factory=dict)
    sandbox: Any = None  # phishguard.sandbox.runner.Sandbox | None
    re_adapter: Any = None  # phishguard.sandbox.re_adapter.REAdapter | None
    classifier: Any = None  # phishguard.layers.ml.Classifier | None
    llm: Any = None
    notes: list[str] = field(default_factory=list)
    sb_hits: dict[str, str] = field(default_factory=dict)

    def sig(self, layer: str, id_: str, points: float, reason: str, evidence: str = "") -> Signal:
        return Signal(layer=layer, id=id_, points=points, reason=reason, evidence=evidence)
