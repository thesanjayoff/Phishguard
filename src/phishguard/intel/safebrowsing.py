"""Google Safe Browsing v4 Lookup API (optional; needs your own API key).
Unlike the local feeds, this sends the *URL* to Google, so it is off unless a key is configured."""
from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafeBrowsing:
    def __init__(self, api_key: str, session: requests.Session | None = None):
        self.key = api_key
        self.http = session or requests.Session()

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def check(self, urls: list[str]) -> dict[str, str]:
        """Return {url: threat_type} for URLs Google lists."""
        if not self.enabled or not urls:
            return {}
        body = {
            "client": {"clientId": "phishguard-personal", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[:500]],
            },
        }
        try:
            r = self.http.post(ENDPOINT, params={"key": self.key}, json=body, timeout=8)
            r.raise_for_status()
            return {m["threat"]["url"]: m["threatType"] for m in r.json().get("matches", [])}
        except Exception as e:
            log.warning("safe browsing lookup failed: %s", type(e).__name__)
            return {}
