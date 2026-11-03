"""Outlook / Microsoft 365 via Microsoft Graph (optional source, off unless `outlook.enabled`).

Default scope is `Mail.Read`. Moving suspected phishing to a folder needs `Mail.ReadWrite`, which the user must opt into
with `outlook.quarantine = true`. Only the *move* endpoint is used - there is no delete call."""
from __future__ import annotations

import logging
from datetime import datetime
from urllib.parse import quote

from ..config import Config
from ..parsing.email_parser import parse_email
from . import Source, SourceError

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"


def scopes_for(cfg: Config) -> list[str]:
    return ["Mail.ReadWrite"] if cfg.outlook.quarantine else ["Mail.Read"]


def _app(cfg: Config):
    try:
        import msal
    except ImportError as e:  # pragma: no cover
        raise SourceError("install the Outlook extra: pip install 'phishguard[outlook]'") from e
    if not cfg.outlook.client_id:
        raise SourceError("set outlook.client_id (an Entra app registration with 'Allow public client flows')")
    cache = msal.SerializableTokenCache()
    cp = cfg.path("outlook_token_cache.json")
    if cp.is_file():
        cache.deserialize(cp.read_text())
    app = msal.PublicClientApplication(cfg.outlook.client_id, authority=f"https://login.microsoftonline.com/{cfg.outlook.tenant}",
                                       token_cache=cache)
    return app, cache, cp


def _save(cache, cp) -> None:
    if cache.has_state_changed:
        cp.write_text(cache.serialize())


def authenticate(cfg: Config) -> str:
    app, cache, cp = _app(cfg)
    flow = app.initiate_device_flow(scopes=scopes_for(cfg))
    if "user_code" not in flow:
        raise SourceError("could not start device sign-in")
    print(flow["message"])
    res = app.acquire_token_by_device_flow(flow)
    if "access_token" not in res:
        raise SourceError(res.get("error_description", "sign-in failed")[:200])
    _save(cache, cp)
    return f"Outlook authorised with scope(s): {', '.join(scopes_for(cfg))}"


def _token(cfg: Config) -> str:
    app, cache, cp = _app(cfg)
    accounts = app.get_accounts()
    if not accounts:
        raise SourceError("Outlook is not authorised yet - run: phishguard auth outlook")
    res = app.acquire_token_silent(scopes_for(cfg), account=accounts[0])
    if not res or "access_token" not in res:
        raise SourceError("Outlook token expired or scope changed - run: phishguard auth outlook")
    _save(cache, cp)
    return res["access_token"]


class OutlookSource(Source):
    name = "outlook"

    def __init__(self, cfg: Config, session=None, token_fn=None):
        import requests

        self.cfg = cfg
        self.s = session or requests.Session()
        self._token = token_fn or (lambda: _token(cfg))
        self._folder_id: str | None = None

    def _h(self, **extra):
        return {"Authorization": f"Bearer {self._token()}", "Prefer": 'IdType="ImmutableId"', **extra}

    def _get(self, url: str, **params):
        r = self.s.get(url if url.startswith("http") else f"{GRAPH}{url}", headers=self._h(), params=params, timeout=30)
        if r.status_code >= 400:
            raise SourceError(f"Graph API {r.status_code}")
        return r

    def fetch(self, seen):
        top = min(max(self.cfg.outlook.max_per_run, 1), 100)
        data = self._get("/me/mailFolders/inbox/messages", **{"$top": top, "$select": "id,receivedDateTime",
                                                              "$orderby": "receivedDateTime desc"}).json()
        for item in data.get("value", []):
            mid = item["id"]
            if seen(mid):
                continue
            blob = self._get(f"/me/messages/{quote(mid, safe='')}/$value").content  # raw MIME
            msg = parse_email(blob, source="outlook", external_id=mid)
            try:
                msg.received_at = datetime.fromisoformat(item["receivedDateTime"].replace("Z", "+00:00"))
            except Exception:
                pass
            yield msg

    def _ensure_folder(self) -> str:
        if self._folder_id:
            return self._folder_id
        name = self.cfg.outlook.quarantine_folder
        safe = name.replace("'", "''")
        found = self._get("/me/mailFolders", **{"$filter": f"displayName eq '{safe}'"}).json().get("value", [])
        if found:
            self._folder_id = found[0]["id"]
        else:
            r = self.s.post(f"{GRAPH}/me/mailFolders", headers=self._h(**{"Content-Type": "application/json"}),
                            json={"displayName": name}, timeout=30)
            if r.status_code >= 400:
                raise SourceError(f"could not create folder ({r.status_code})")
            self._folder_id = r.json()["id"]
        return self._folder_id

    def quarantine(self, external_id: str) -> str:
        if not self.cfg.outlook.quarantine:
            return "flagged locally (Outlook quarantine is off; enable outlook.quarantine to move the message)"
        dest = self._ensure_folder()
        r = self.s.post(f"{GRAPH}/me/messages/{quote(external_id, safe='')}/move", headers=self._h(**{"Content-Type": "application/json"}),
                        json={"destinationId": dest}, timeout=30)
        if r.status_code >= 400:
            raise SourceError(f"move failed ({r.status_code})")
        return f"moved to '{self.cfg.outlook.quarantine_folder}' (nothing deleted)"
