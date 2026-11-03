"""What may leave the process as JSON (HTTP API, CLI --json): link targets only ever appear defanged,
so nothing printed or returned can be clicked by accident, in a terminal or in another tool."""
from __future__ import annotations

from typing import Any

from .urlutil import defang_text

_URL_KEYS = ("defanged", "defanged_final", "flags", "final_flags", "brands", "official_brand", "shortener", "age_days", "points")


def defang_deep(obj: Any) -> Any:
    """Defang every URL found in any string inside a JSON-like structure."""
    if isinstance(obj, str):
        return defang_text(obj)
    if isinstance(obj, list):
        return [defang_deep(x) for x in obj]
    if isinstance(obj, dict):
        return {k: defang_deep(v) for k, v in obj.items()}
    return obj


def public_verdict(v: dict[str, Any]) -> dict[str, Any]:
    out = dict(v)
    out["urls"] = [{k: i.get(k) for k in _URL_KEYS} for i in v.get("urls", [])]   # the raw URL, host and link text are dropped
    return defang_deep(out)
