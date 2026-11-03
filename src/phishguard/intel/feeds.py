"""OpenPhish + PhishTank feeds, mirrored into the local SQLite DB so lookups never leak the
URLs you receive. Feed data is only *read* by this app; it is never redistributed."""
from __future__ import annotations

import csv
import io
import logging
import re
import time
from dataclasses import dataclass

import requests

from ..config import Intel as IntelCfg
from ..store import Store
from ..urlutil import parse_url

log = logging.getLogger(__name__)
UA = "phishguard/0.1 (personal phishing detector)"
OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"


def norm_key(url: str) -> str:
    u = url.strip().lower()
    u = re.sub(r"^[a-z]+://", "", u)
    u = re.sub(r"^www\d?\.", "", u)
    u = u.split("#", 1)[0]
    return u.rstrip("/")


@dataclass
class FeedHit:
    source: str
    exact: bool


class FeedDB:
    def __init__(self, store: Store, cfg: IntelCfg):
        self.store = store
        self.cfg = cfg

    # ---- lookups -------------------------------------------------------
    def lookup(self, url: str) -> FeedHit | None:
        key = norm_key(url)
        row = self.store.one("SELECT source FROM feed_urls WHERE key=?", (key,))
        if row:
            return FeedHit(row["source"], True)
        p = parse_url(url)
        if p is not None:
            row = self.store.one("SELECT source FROM feed_urls WHERE host=? LIMIT 1", (p.host,))
            if row:
                return FeedHit(row["source"], False)
        return None

    def stats(self) -> list[dict]:
        return [dict(r) for r in self.store.query("SELECT source, fetched_at, count, note FROM feed_meta")]

    def is_stale(self) -> bool:
        rows = self.store.query("SELECT fetched_at FROM feed_meta")
        if not rows:
            return True
        return time.time() - min(r["fetched_at"] for r in rows) > self.cfg.feed_refresh_hours * 3600

    # ---- updates ---------------------------------------------------------
    def _replace(self, source: str, urls: list[str], note: str = "") -> int:
        rows = []
        for u in urls:
            p = parse_url(u)
            if p is None:
                continue
            rows.append((norm_key(u), p.host, source))
        with self.store.transaction() as s:
            s.execute("DELETE FROM feed_urls WHERE source=?", (source,))
            s._db.executemany("INSERT OR REPLACE INTO feed_urls(key,host,source) VALUES(?,?,?)", rows)
            s.execute("INSERT INTO feed_meta(source,fetched_at,count,note) VALUES(?,?,?,?) "
                      "ON CONFLICT(source) DO UPDATE SET fetched_at=excluded.fetched_at,count=excluded.count,note=excluded.note",
                      (source, time.time(), len(rows), note))
        return len(rows)

    def update_openphish(self) -> int:
        r = requests.get(OPENPHISH_URL, headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        urls = [ln.strip() for ln in r.text.splitlines() if ln.strip().startswith(("http://", "https://"))]
        return self._replace("openphish", urls)

    def update_phishtank(self) -> int:
        url = PHISHTANK_URL
        if self.cfg.phishtank_app_key:
            url = f"https://data.phishtank.com/data/{self.cfg.phishtank_app_key}/online-valid.csv"
        r = requests.get(url, headers={"User-Agent": "phishtank/phishguard"}, timeout=90)
        r.raise_for_status()
        reader = csv.DictReader(io.StringIO(r.text))
        urls = [row["url"] for row in reader if row.get("url")]
        return self._replace("phishtank", urls)

    def update_all(self) -> dict[str, str]:
        """Best-effort refresh; returns {source: 'N urls' | 'error: ...'}."""
        out: dict[str, str] = {}
        for name, enabled, fn in (
            ("openphish", self.cfg.use_openphish, self.update_openphish),
            ("phishtank", self.cfg.use_phishtank, self.update_phishtank),
        ):
            if not enabled:
                continue
            try:
                out[name] = f"{fn()} urls"
            except Exception as e:  # network / rate-limit / auth
                out[name] = f"error: {type(e).__name__}: {e}"
                log.warning("feed %s update failed: %s", name, e)
        return out
