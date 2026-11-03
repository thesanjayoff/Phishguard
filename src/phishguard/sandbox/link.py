"""Host-side client for the link sandbox container (headless Chromium, no cookies, no profile).

The container image is built from docker/linkbox. Everything returned by the container is
treated as untrusted data: it is schema-checked, length-capped and never rendered as HTML."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from ..config import Config
from ..store import Store
from .runner import DockerRunner, SandboxUnavailable, docker_runner

log = logging.getLogger(__name__)
CACHE_TTL = 24 * 3600
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_SHOT = 3 * 1024 * 1024


def _s(v: Any, n: int = 500) -> str:
    return v[:n] if isinstance(v, str) else ""


def _http(v: Any) -> str:
    return v[:2000] if isinstance(v, str) and re.match(r"(?i)^https?://", v) else ""


def sanitize_link_report(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("bad report")
    forms = []
    for f in (raw.get("forms") or [])[:10]:
        if isinstance(f, dict):
            forms.append({
                "action": _s(f.get("action"), 400), "method": _s(f.get("method"), 10),
                "has_password": bool(f.get("has_password")), "cross_origin": bool(f.get("cross_origin")),
                "inputs": [{"type": _s(i.get("type"), 20), "name": _s(i.get("name"), 40)}
                           for i in (f.get("inputs") or [])[:20] if isinstance(i, dict)],
            })
    return {
        "url": _http(raw.get("url")), "final_url": _http(raw.get("final_url")),
        "status": raw.get("status") if isinstance(raw.get("status"), int) else None,
        "title": _s(raw.get("title"), 200), "text_excerpt": _s(raw.get("text_excerpt"), 600),
        "redirects": [{"url": _http(r.get("url")), "status": r.get("status") if isinstance(r.get("status"), int) else None}
                      for r in (raw.get("redirects") or [])[:15] if isinstance(r, dict)],
        "forms": forms, "has_login_form": bool(raw.get("has_login_form")),
        "cert_error": bool(raw.get("cert_error")), "downloads": [_s(d, 200) for d in (raw.get("downloads") or [])[:5]],
        "js_redirects": int(raw.get("js_redirects") or 0) if isinstance(raw.get("js_redirects"), int) else 0,
        "meta_refresh": _s(raw.get("meta_refresh"), 200),
        "blocked_requests": [_s(b, 200) for b in (raw.get("blocked_requests") or [])[:10]],
        "third_party_domains": [_s(d, 100) for d in (raw.get("third_party_domains") or [])[:20]],
        "requests_count": raw.get("requests_count") if isinstance(raw.get("requests_count"), int) else 0,
        "error": _s(raw.get("error"), 300) or None,
        "internal_target": bool(raw.get("internal_target")),
        "_shot_b64": raw.get("screenshot_b64") if isinstance(raw.get("screenshot_b64"), str) else "",
    }


class LinkSandbox:
    def __init__(self, cfg: Config, store: Store | None = None, runner: DockerRunner | None = None):
        self.cfg = cfg
        self.store = store
        self.runner = runner or docker_runner(cfg)
        self.image = cfg.sandbox.link_image
        self.shots_dir = cfg.path("shots")

    def available(self) -> tuple[bool, str]:
        ok, why = self.runner.available()
        if ok and not self.runner.image_exists(self.image):
            return False, f"image '{self.image}' not built (run: phishguard build-images)"
        return ok, why

    def _network(self) -> str:
        return self.cfg.sandbox.link_network or "bridge"

    # ---- shortener expansion ------------------------------------------------------
    def expand(self, urls: list[str]) -> dict[str, str | None]:
        res = self.runner.run(self.image, ["expand"], json.dumps({"urls": urls, "max_hops": 8}).encode(),
                              network=self._network(), timeout=min(60, self.cfg.sandbox.timeout_s), memory="256m",
                              max_stdout=512 * 1024)
        if res.timed_out or res.returncode != 0:
            raise RuntimeError(f"expand failed (rc={res.returncode}, timeout={res.timed_out})")
        data = json.loads(res.stdout.decode("utf-8", "replace"))
        out: dict[str, str | None] = {}
        for u in urls:
            r = (data.get("results") or {}).get(u) or {}
            out[u] = _http(r.get("final")) or None
        return out

    # ---- full browse ------------------------------------------------------------------
    def browse(self, url: str) -> dict[str, Any]:
        key = hashlib.sha256(url.encode()).hexdigest()
        if self.store:
            row = self.store.one("SELECT report_json, at FROM link_cache WHERE url_hash=?", (key,))
            if row and time.time() - row["at"] < CACHE_TTL:
                return json.loads(row["report_json"])
        payload = json.dumps({"url": url, "timeout_s": max(10, self.cfg.sandbox.timeout_s - 15), "screenshot": True}).encode()
        res = self.runner.run(self.image, ["browse"], payload, network=self._network(), timeout=self.cfg.sandbox.timeout_s,
                              memory="1g", cpus="1.5", pids=256, tmpfs_size="256m", shm="512m",
                              max_stdout=8 * 1024 * 1024)
        if res.timed_out:
            report = {"url": url, "error": "timed out", "forms": [], "redirects": []}
        elif res.returncode != 0 and not res.stdout:
            raise RuntimeError(f"browse failed rc={res.returncode}: {res.stderr[:200].decode('utf-8', 'replace')}")
        else:
            report = sanitize_link_report(json.loads(res.stdout.decode("utf-8", "replace")))
        report["screenshot"] = self._save_shot(report.pop("_shot_b64", ""), key)
        if self.store:
            self.store.execute("INSERT OR REPLACE INTO link_cache(url_hash, report_json, at) VALUES(?,?,?)",
                               (key, json.dumps(report), time.time()))
        return report

    def _save_shot(self, b64: str, key: str) -> str | None:
        if not b64:
            return None
        try:
            png = base64.b64decode(b64, validate=True)
        except Exception:
            return None
        if not png.startswith(PNG_MAGIC) or len(png) > MAX_SHOT:
            return None
        self.shots_dir.mkdir(parents=True, exist_ok=True)
        name = key[:24] + ".png"
        (self.shots_dir / name).write_bytes(png)
        return name


def make_link_sandbox(cfg: Config, store: Store | None = None) -> LinkSandbox:
    return LinkSandbox(cfg, store)
