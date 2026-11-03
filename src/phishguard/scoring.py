"""Weighted evidence combination.

Every signal carries `points` (0..100 = how strongly it alone suggests phishing; negative = evidence
of legitimacy). Positive points are combined with a noisy-OR (independent weak clues add up, but
nothing exceeds 100), scaled by a per-layer weight and by multipliers learned from your feedback.
Negative points are then subtracted (capped)."""
from __future__ import annotations

from math import prod

from .models import LAYERS, Signal, Verdict, label_for

LAYER_WEIGHT = {"headers": 1.0, "urls": 1.0, "content": 0.9, "behavior": 1.0, "attachments": 1.0, "feedback": 1.0}
MAX_MITIGATION = 45.0
MAX_LEARNED_SHIFT = (0.4, 1.6)


def effective_points(s: Signal, learned: dict[str, float]) -> float:
    if s.points <= 0:
        return s.points
    m = learned.get(s.id, 1.0)
    lo, hi = MAX_LEARNED_SHIFT
    return min(100.0, s.points * min(hi, max(lo, m)) * LAYER_WEIGHT.get(s.layer, 1.0))


def noisy_or(points: list[float]) -> float:
    return 100.0 * (1.0 - prod(1.0 - min(max(p, 0.0), 100.0) / 100.0 for p in points)) if points else 0.0


def layer_scores(signals: list[Signal], learned: dict[str, float] | None = None) -> dict[str, float]:
    learned = learned or {}
    out: dict[str, float] = {}
    for layer in LAYERS:
        sigs = [s for s in signals if s.layer == layer]
        if not sigs:
            continue
        pos = [effective_points(s, learned) for s in sigs if s.points > 0]
        neg = max(-MAX_MITIGATION, sum(s.points for s in sigs if s.points < 0))
        out[layer] = round(max(0.0, noisy_or(pos) + neg), 1)
    return out


def combine(signals: list[Signal], suspicious: int, phishing: int, learned: dict[str, float] | None = None) -> tuple[int, str, dict[str, float]]:
    learned = learned or {}
    pos = [effective_points(s, learned) for s in signals if s.points > 0]
    neg = max(-MAX_MITIGATION, sum(s.points for s in signals if s.points < 0))
    score = max(0.0, min(100.0, noisy_or(pos) + neg))
    score_i = int(round(score))
    return score_i, label_for(score_i, suspicious, phishing), layer_scores(signals, learned)


def summarize(signals: list[Signal], label: str, score: int, learned: dict[str, float] | None = None) -> str:
    learned = learned or {}
    top = sorted((s for s in signals if s.points > 0), key=lambda s: -effective_points(s, learned))[:3]
    if label == "safe":
        return "No strong signs of phishing." if not top else "Looks legitimate; minor oddities: " + "; ".join(t.reason for t in top[:2]) + "."
    lead = "Likely phishing" if label == "phishing" else "Suspicious"
    return f"{lead}: " + "; ".join(t.reason.rstrip(".") for t in top) + "."
