"""Gmail via the REST API with OAuth.

Default scope is `gmail.readonly` (read mail only). Labelling suspected phishing needs `gmail.modify`, which the
user must opt into with `gmail.quarantine = true` and re-authorise. There is no code that trashes or deletes."""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from ..models import Message
from ..parsing.email_parser import parse_email
from . import Source, SourceError

log = logging.getLogger(__name__)
API = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE_READ = "https://www.googleapis.com/auth/gmail.readonly"
SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"


def scopes_for(cfg: Config) -> list[str]:
    return [SCOPE_MODIFY] if cfg.gmail.quarantine else [SCOPE_READ]


def _token_path(cfg: Config):
    return cfg.path("gmail_token.json")


def authenticate(cfg: Config) -> str:
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as e:  # pragma: no cover
        raise SourceError("install the Gmail extra: pip install 'phishguard[gmail]'") from e
    secret = Path(cfg.gmail.credentials_file)
    if not secret.is_absolute():
        secret = cfg.path(cfg.gmail.credentials_file)
    if not secret.is_file():
        raise SourceError(f"OAuth client file not found: {secret}. Create a Desktop OAuth client in Google Cloud "
                          "Console (Gmail API enabled) and save its JSON there.")
    scopes = scopes_for(cfg)
    flow = InstalledAppFlow.from_client_secrets_file(str(secret), scopes)
    creds = flow.run_local_server(port=0, open_browser=True)
    _token_path(cfg).write_text(creds.to_json())
    return f"Gmail authorised with scope(s): {', '.join(s.rsplit('/', 1)[-1] for s in scopes)}. Token saved to {_token_path(cfg)}"


def _load_session(cfg: Config):
    try:
        from google.auth.transport.requests import AuthorizedSession, Request
        from google.oauth2.credentials import Credentials
    except ImportError as e:  # pragma: no cover
        raise SourceError("install the Gmail extra: pip install 'phishguard[gmail]'") from e
    tp = _token_path(cfg)
    if not tp.is_file():
        raise SourceError("Gmail is not authorised yet - run: phishguard auth gmail")
    info = json.loads(tp.read_text())
    granted = set(info.get("scopes") or [])
    need = set(scopes_for(cfg))
    if not need <= granted:
        raise SourceError("the saved Gmail token does not cover the configured scope "
                          f"({', '.join(sorted(need))}) - run: phishguard auth gmail")
    creds = Credentials.from_authorized_user_info(info, scopes_for(cfg))
    if not creds.valid:
        creds.refresh(Request())
        tp.write_text(creds.to_json())
    return AuthorizedSession(creds)


class GmailSource(Source):
    name = "gmail"

    def __init__(self, cfg: Config, session=None):
        self.cfg = cfg
        self.s = session or _load_session(cfg)
        self._label_id: str | None = None

    def _get(self, path: str, **params):
        r = self.s.get(f"{API}/{path}", params=params, timeout=30)
        if r.status_code >= 400:
            raise SourceError(f"Gmail API {r.status_code} for {path.split('/')[0]}")
        return r.json()

    def fetch(self, seen):
        g = self.cfg.gmail
        data = self._get("messages", q=g.query, maxResults=min(max(g.max_per_run, 1), 500))
        for item in data.get("messages", []):
            mid = item["id"]
            if seen(mid):
                continue
            raw = self._get(f"messages/{mid}", format="raw")
            try:
                blob = base64.urlsafe_b64decode(raw["raw"] + "=" * (-len(raw["raw"]) % 4))
            except Exception:
                continue
            msg: Message = parse_email(blob, source="gmail", external_id=mid)
            ms = raw.get("internalDate")
            if ms:
                msg.received_at = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
            yield msg

    # --- quarantine = add a label (never delete / trash) ---
    def _ensure_label(self) -> str:
        if self._label_id:
            return self._label_id
        name = self.cfg.gmail.quarantine_label
        for lab in self._get("labels").get("labels", []):
            if lab.get("name") == name:
                self._label_id = lab["id"]
                return self._label_id
        r = self.s.post(f"{API}/labels", json={"name": name, "labelListVisibility": "labelShow",
                                                "messageListVisibility": "show"}, timeout=30)
        if r.status_code >= 400:
            raise SourceError(f"could not create label ({r.status_code})")
        self._label_id = r.json()["id"]
        return self._label_id

    def quarantine(self, external_id: str) -> str:
        if not self.cfg.gmail.quarantine:
            return "flagged locally (Gmail labelling is off; enable gmail.quarantine to label)"
        label = self._ensure_label()
        r = self.s.post(f"{API}/messages/{external_id}/modify", json={"addLabelIds": [label]}, timeout=30)
        if r.status_code >= 400:
            raise SourceError(f"label failed ({r.status_code})")
        return f"labelled '{self.cfg.gmail.quarantine_label}' in Gmail (nothing deleted)"
