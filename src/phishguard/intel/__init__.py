"""Threat-intel lookups: local feed DB (OpenPhish/PhishTank), RDAP domain age, optional Safe Browsing.

All network use is gated by config and by `Intel.online`; with online=False (tests, corpus
evaluation, offline CLI) only the local feed database is consulted."""
from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..store import Store
from .feeds import FeedDB
from .rdap import RdapClient
from .safebrowsing import SafeBrowsing


@dataclass
class Intel:
    feeds: FeedDB
    rdap: RdapClient
    safebrowsing: SafeBrowsing
    online: bool = True

    @classmethod
    def from_config(cls, cfg: Config, store: Store, online: bool = True) -> "Intel":
        return cls(
            feeds=FeedDB(store, cfg.intel),
            rdap=RdapClient(store, enabled=online and cfg.intel.rdap and cfg.privacy.external_domain_lookups),
            safebrowsing=SafeBrowsing(cfg.intel.safe_browsing_key if online else ""),
            online=online,
        )

    @classmethod
    def offline(cls, store: Store) -> "Intel":
        from ..config import Config

        cfg = Config()
        return cls(FeedDB(store, cfg.intel), RdapClient(store, enabled=False), SafeBrowsing(""), online=False)
