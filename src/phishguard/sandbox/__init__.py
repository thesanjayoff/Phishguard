"""Isolated execution: link sandbox + attachment RE adapter (both Docker-only)."""
from __future__ import annotations

from ..config import Config
from .link import LinkSandbox
from .re_adapter import REAdapter, make_re_adapter  # noqa: F401
from .runner import SandboxUnavailable  # noqa: F401


def make_sandbox(cfg: Config, store=None) -> LinkSandbox:
    return LinkSandbox(cfg, store)
