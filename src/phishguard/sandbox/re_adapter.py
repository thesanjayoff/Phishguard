"""Attachment reverse-engineering behind a small adapter interface.

The rest of the app only knows `REAdapter.analyze(filename, data, passwords) -> report dict`.
Swap the engine by implementing this interface (or use CommandAdapter to drive an external tool
that lives in your own container image). Static analysis ONLY - nothing is ever executed."""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Sequence

from ..config import Config
from .runner import DockerRunner, SandboxUnavailable, docker_runner

log = logging.getLogger(__name__)
SEVERITIES = ("info", "low", "medium", "high", "critical")


class REAdapter(ABC):
    name = "abstract"

    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """(ready, human-readable reason)."""

    @abstractmethod
    def analyze(self, filename: str, data: bytes, passwords: Sequence[str] = ()) -> dict[str, Any]:
        """Return an *Attachment report* (see sanitize_report for the schema). Raise
        SandboxUnavailable when the isolated environment is missing - never analyse on the host."""


# ---- schema enforcement (container output is untrusted) -------------------------------------
def _s(v: Any, n: int) -> str:
    return v[:n] if isinstance(v, str) else ""


def _list_s(v: Any, n_items: int, n_chars: int) -> list[str]:
    return [x[:n_chars] for x in (v or [])[:n_items] if isinstance(x, str)] if isinstance(v, list) else []


def sanitize_report(raw: Any, depth: int = 0) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("attachment report must be an object")
    iocs = raw.get("iocs") if isinstance(raw.get("iocs"), dict) else {}
    behaviors = []
    for b in (raw.get("behaviors") or [])[:60] if isinstance(raw.get("behaviors"), list) else []:
        if not isinstance(b, dict):
            continue
        sev = b.get("severity") if b.get("severity") in SEVERITIES else "low"
        behaviors.append({
            "id": _s(b.get("id"), 60) or "unknown", "severity": sev, "title": _s(b.get("title"), 160),
            "detail": _s(b.get("detail"), 500), "snippet": _s(b.get("snippet"), 3000),
            "snippet_kind": _s(b.get("snippet_kind"), 30), "location": _s(b.get("location"), 160),
        })
    children = []
    if depth < 3 and isinstance(raw.get("children"), list):
        for c in raw["children"][:40]:
            try:
                children.append(sanitize_report(c, depth + 1))
            except ValueError:
                continue
    return {
        "filename": _s(raw.get("filename"), 200), "size": raw.get("size") if isinstance(raw.get("size"), int) else 0,
        "sha256": _s(raw.get("sha256"), 64), "sha1": _s(raw.get("sha1"), 40), "md5": _s(raw.get("md5"), 32),
        "file_type": _s(raw.get("file_type"), 120), "declared_ext": _s(raw.get("declared_ext"), 20),
        "type_mismatch": bool(raw.get("type_mismatch")),
        "entropy": float(raw["entropy"]) if isinstance(raw.get("entropy"), (int, float)) else None,
        "packed": bool(raw.get("packed")), "encrypted": bool(raw.get("encrypted")),
        "iocs": {k: _list_s(iocs.get(k), 100, 300) for k in ("urls", "ips", "domains", "emails", "registry", "paths", "commands")},
        "behaviors": behaviors,
        "imports": _list_s(raw.get("imports"), 150, 80),
        "strings": _list_s(raw.get("strings"), 60, 200),
        "macros": [{"name": _s(m.get("name"), 80), "excerpt": _s(m.get("excerpt"), 1500)}
                   for m in (raw.get("macros") or [])[:10] if isinstance(m, dict)] if isinstance(raw.get("macros"), list) else [],
        "children": children, "warnings": _list_s(raw.get("warnings"), 30, 300),
        "errors": _list_s(raw.get("errors"), 10, 300), "engine": _s(raw.get("engine"), 60),
    }


class BuiltinContainerAdapter(REAdapter):
    """Runs the bundled static analyser (pg_re_worker) inside the no-network re_image container."""

    name = "builtin"

    def __init__(self, cfg: Config, runner: DockerRunner | None = None):
        self.cfg = cfg
        self.runner = runner or docker_runner(cfg)
        self.image = cfg.sandbox.re_image

    def available(self) -> tuple[bool, str]:
        ok, why = self.runner.available()
        if ok and not self.runner.image_exists(self.image):
            return False, f"image '{self.image}' not built (run: phishguard build-images)"
        return ok, why

    def _run(self, cmd: list[str], filename: str, data: bytes, passwords: Sequence[str]) -> dict[str, Any]:
        if len(data) > self.cfg.attachments.max_bytes:
            return {"filename": filename, "size": len(data), "warnings": ["file too large to analyse"], "behaviors": []}
        header = json.dumps({"filename": filename, "passwords": list(passwords)[:8]}).encode() + b"\n"
        res = self.runner.run(self.image, cmd, header + data, network="none", timeout=self.cfg.attachments.timeout_s,
                              memory="768m", cpus="1", pids=96, tmpfs_size="256m", max_stdout=4 * 1024 * 1024)
        if res.timed_out:
            return {"filename": filename, "size": len(data), "errors": ["analysis timed out (killed)"], "behaviors": []}
        if res.truncated or not res.stdout:
            raise RuntimeError(f"worker produced no valid report (rc={res.returncode}): {res.stderr[:200].decode('utf-8', 'replace')}")
        return json.loads(res.stdout.decode("utf-8", "replace"))

    def analyze(self, filename: str, data: bytes, passwords: Sequence[str] = ()) -> dict[str, Any]:
        raw = self._run(["python", "-m", "pg_re_worker"], filename, data, passwords)
        rep = sanitize_report(raw)
        rep["engine"] = rep["engine"] or "builtin"
        return rep


class CommandAdapter(REAdapter):
    """Drive an external RE tool that you baked into your own image.

    Config:  attachments.adapter = "command"
             attachments.external_command = ["mytool", "--headless", "--json", "{input}"]
             sandbox.re_image = "my-re-image:latest"
    `{input}` is replaced by /work/sample (the file is streamed into a tmpfs inside the container;
    network is always disabled). The tool must print a JSON object on stdout. If it follows our
    report schema it is used as-is; otherwise its output is stored under `raw_output`."""

    name = "command"

    def __init__(self, cfg: Config, runner: DockerRunner | None = None):
        self.cfg = cfg
        self.runner = runner or docker_runner(cfg)
        self.image = cfg.sandbox.re_image

    def available(self) -> tuple[bool, str]:
        if not self.cfg.attachments.external_command:
            return False, "attachments.external_command is empty"
        ok, why = self.runner.available()
        if ok and not self.runner.image_exists(self.image):
            return False, f"image '{self.image}' not found"
        return ok, why

    def analyze(self, filename: str, data: bytes, passwords: Sequence[str] = ()) -> dict[str, Any]:
        cmd = [c.replace("{input}", "/work/sample") for c in self.cfg.attachments.external_command]
        shell = 'cat > /work/sample && exec "$@"'
        res = self.runner.run(self.image, ["sh", "-c", shell, "--", *cmd], data, network="none",
                              timeout=self.cfg.attachments.timeout_s, tmpfs_size="256m", max_stdout=4 * 1024 * 1024)
        text = res.stdout.decode("utf-8", "replace").strip()
        try:
            raw = json.loads(text)
        except ValueError:
            raw = {"warnings": ["external tool did not return JSON"], "behaviors": []}
            raw["strings"] = text.splitlines()[:40]
        if isinstance(raw, dict) and ("behaviors" in raw or "iocs" in raw):
            rep = sanitize_report({**raw, "filename": filename, "size": len(data)})
        else:
            rep = sanitize_report({"filename": filename, "size": len(data), "behaviors": [],
                                   "warnings": ["external tool output is not in the report schema; see raw_output"]})
            rep["raw_output"] = text[:4000]
        rep["engine"] = "command:" + (cmd[0] if cmd else "?")
        return rep


def make_re_adapter(cfg: Config) -> REAdapter:
    if cfg.attachments.adapter == "command":
        return CommandAdapter(cfg)
    return BuiltinContainerAdapter(cfg)
