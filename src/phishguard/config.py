"""Configuration: a TOML file merged over safe defaults.

Privacy-relevant defaults are conservative: nothing leaves the machine except
(a) feed downloads, (b) RDAP lookups of *domain names only*, and anything the
user explicitly switches on (Safe Browsing, LLM, Gmail/IMAP/Graph access).
"""
from __future__ import annotations

import dataclasses
import os
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class General:
    data_dir: str = "data"
    log_level: str = "INFO"


@dataclass
class Server:
    host: str = "127.0.0.1"
    port: int = 8765
    token: str = ""  # auto-generated into data_dir/token on first run when empty
    allowed_hosts: list[str] = field(default_factory=list)
    scan_interval_minutes: int = 5  # background mailbox polling


@dataclass
class Privacy:
    store_snippet: bool = True  # keep a short *redacted* preview for the inbox view
    snippet_chars: int = 160
    external_domain_lookups: bool = True  # RDAP (domain only). Off => no domain-age signal
    send_body_to_llm: bool = False  # must be true AND llm.enabled for any body to leave


@dataclass
class Thresholds:
    suspicious: int = 35
    phishing: int = 70


@dataclass
class Intel:
    use_openphish: bool = True
    use_phishtank: bool = True
    phishtank_app_key: str = ""
    safe_browsing_key: str = ""  # empty => disabled. URLs (not bodies) are sent to Google.
    feed_refresh_hours: int = 12
    rdap: bool = True


@dataclass
class Sandbox:
    enabled: bool = True
    docker_bin: str = "docker"
    link_image: str = "phishguard-linkbox:latest"
    re_image: str = "phishguard-rebox:latest"
    link_network: str = ""  # optional dedicated docker network for the browser container
    max_urls_per_message: int = 3
    browse_min_score: int = 20  # only open links when other layers already look off
    timeout_s: int = 60
    expand_shorteners: bool = True


@dataclass
class Attachments:
    enabled: bool = True
    adapter: str = "builtin"  # builtin | command
    external_command: list[str] = field(default_factory=list)  # for adapter=command
    max_bytes: int = 25 * 1024 * 1024
    timeout_s: int = 90


@dataclass
class LLM:
    enabled: bool = False
    provider: str = "anthropic"  # anthropic | openai_compatible (e.g. local Ollama)
    model: str = "claude-opus-5-5"  # or "claude-haiku-5-5" for a cheaper second opinion
    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str = ""  # for openai_compatible, e.g. http://localhost:11434/v1
    max_chars: int = 3000
    weight: float = 0.9


@dataclass
class Gmail:
    enabled: bool = False
    credentials_file: str = "gmail_client_secret.json"
    query: str = "in:inbox newer_than:7d"
    max_per_run: int = 50
    quarantine: bool = False  # needs gmail.modify scope; default scope is read-only
    quarantine_label: str = "PhishGuard-Quarantine"


@dataclass
class Imap:
    enabled: bool = False
    host: str = ""
    port: int = 993
    user: str = ""
    password_env: str = "PHISHGUARD_IMAP_PASSWORD"
    folder: str = "INBOX"
    max_per_run: int = 50
    since_days: int = 7
    quarantine: bool = False
    quarantine_folder: str = "PhishGuard-Quarantine"


@dataclass
class Outlook:
    enabled: bool = False  # optional source, behind this toggle
    client_id: str = ""
    tenant: str = "common"
    max_per_run: int = 50
    quarantine: bool = False  # needs Mail.ReadWrite; default scope is Mail.Read
    quarantine_folder: str = "PhishGuard-Quarantine"


@dataclass
class Sms:
    enabled: bool = True  # accept POST /api/ingest/sms from the Android companion


@dataclass
class Config:
    general: General = field(default_factory=General)
    server: Server = field(default_factory=Server)
    privacy: Privacy = field(default_factory=Privacy)
    thresholds: Thresholds = field(default_factory=Thresholds)
    intel: Intel = field(default_factory=Intel)
    sandbox: Sandbox = field(default_factory=Sandbox)
    attachments: Attachments = field(default_factory=Attachments)
    llm: LLM = field(default_factory=LLM)
    gmail: Gmail = field(default_factory=Gmail)
    imap: Imap = field(default_factory=Imap)
    outlook: Outlook = field(default_factory=Outlook)
    sms: Sms = field(default_factory=Sms)

    # ---- helpers -------------------------------------------------------
    @property
    def data_dir(self) -> Path:
        p = Path(os.environ.get("PHISHGUARD_HOME") or self.general.data_dir).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p

    def path(self, name: str) -> Path:
        return self.data_dir / name

    def api_token(self) -> str:
        if self.server.token:
            return self.server.token
        tok_file = self.path("token")
        if tok_file.exists():
            return tok_file.read_text().strip()
        tok = secrets.token_urlsafe(24)
        tok_file.write_text(tok)
        return tok


def _merge(obj: Any, data: dict[str, Any]) -> None:
    fields = {f.name: f for f in dataclasses.fields(obj)}
    for key, value in data.items():
        if key not in fields:
            raise ValueError(f"unknown config key: {key!r} in [{type(obj).__name__.lower()}]")
        cur = getattr(obj, key)
        if dataclasses.is_dataclass(cur):
            if not isinstance(value, dict):
                raise ValueError(f"[{key}] must be a table")
            _merge(cur, value)
        else:
            if isinstance(cur, bool) and not isinstance(value, bool):
                raise ValueError(f"{key} must be true/false")
            if isinstance(cur, int) and not isinstance(cur, bool) and isinstance(value, float):
                value = int(value)
            setattr(obj, key, value)


def load_config(path: str | os.PathLike | None = None) -> Config:
    """Load config from `path`, $PHISHGUARD_CONFIG, ./config.toml (in that order)."""
    cfg = Config()
    candidates = [path, os.environ.get("PHISHGUARD_CONFIG"), "config.toml"]
    for cand in candidates:
        if cand and Path(cand).is_file():
            with open(cand, "rb") as fh:
                _merge(cfg, tomllib.load(fh))
            break
    return cfg
