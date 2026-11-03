"""Domain age via RDAP (the modern WHOIS). Only the registrable *domain name* is sent."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

import requests

from ..store import Store

log = logging.getLogger(__name__)
UA = "phishguard/0.1 (personal phishing detector)"
OK_TTL = 30 * 86400
FAIL_TTL = 6 * 3600


def _parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


class RdapClient:
    def __init__(self, store: Store, enabled: bool = True, session: requests.Session | None = None):
        self.store = store
        self.enabled = enabled
        self.http = session or requests.Session()

    def created(self, domain: str) -> datetime | None:
        """Registration datetime, or None when unknown/disabled."""
        domain = domain.lower().strip(".")
        row = self.store.one("SELECT created, fetched_at, ok FROM rdap_cache WHERE domain=?", (domain,))
        if row:
            ttl = OK_TTL if row["ok"] else FAIL_TTL
            if time.time() - row["fetched_at"] < ttl:
                return _parse_dt(row["created"]) if row["created"] else None
        if not self.enabled:
            return _parse_dt(row["created"]) if row and row["created"] else None
        created, ok = None, 0
        try:
            r = self.http.get(f"https://rdap.org/domain/{domain}", headers={"User-Agent": UA,
                              "Accept": "application/rdap+json"}, timeout=8)
            if r.status_code == 200:
                ok = 1
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") in ("registration", "created") and ev.get("eventDate"):
                        created = ev["eventDate"]
                        break
            elif r.status_code == 404:
                ok = 1  # not registered / unknown to RDAP: cache the negative
        except Exception as e:
            log.info("rdap lookup failed for %s: %s", domain, type(e).__name__)
        self.store.execute(
            "INSERT INTO rdap_cache(domain,created,fetched_at,ok) VALUES(?,?,?,?) "
            "ON CONFLICT(domain) DO UPDATE SET created=excluded.created,fetched_at=excluded.fetched_at,ok=excluded.ok",
            (domain, created, time.time(), ok),
        )
        return _parse_dt(created) if created else None

    def age_days(self, domain: str, now: datetime | None = None) -> float | None:
        c = self.created(domain)
        if c is None:
            return None
        now = now or datetime.now(timezone.utc)
        if c.tzinfo is None:
            c = c.replace(tzinfo=timezone.utc)
        return (now - c).total_seconds() / 86400
