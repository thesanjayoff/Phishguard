"""Curated knowledge: brands, TLD/shortener/hosting lists. Loaded once."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

# Aliases that are ordinary words; fine for display-name matching (exact), too noisy for body text
AMBIGUOUS_ALIASES = {
    "vi", "dot", "bob", "boi", "cred", "kite", "wise", "chase", "visa", "steam", "booking", "meta", "indeed",
    "apple", "zoom", "lic", "rto", "upi", "x corp", "axis", "union bank", "yes bank", "itr", "uber", "amazon pay",
    "google", "microsoft", "outlook", "skype", "amazon", "aws", "citi", "baroda", "airtel", "jio", "kotak", "naukri",
    "facebook", "instagram", "whatsapp", "messenger", "youtube", "gmail", "twitter", "telegram", "netflix", "spotify",
}
GENERIC_ROLE_WORDS = {"support", "team", "alerts", "alert", "security", "bank", "care", "customer", "service", "services", "help",
                      "helpdesk", "official", "india", "pay", "mail", "notifications", "notification", "billing", "account", "accounts",
                      "noreply", "no", "reply", "info", "update", "updates", "online", "id", "inc", "ltd", "limited", "the", "from",
                      "verification", "order", "orders", "delivery", "payments", "wallet", "card", "cards", "net", "banking", "netbanking"}
# Brand keys that are also ordinary words / other products: a domain containing them needs more evidence.
WEAK_KEYS = {"apple", "outlook", "steam", "booking", "indeed", "zoom", "uber", "visa", "visacard", "adobe", "intuit", "yahoo",
             "github", "wise", "airtel", "amazon", "google", "microsoft", "onedrive", "sharepoint", "hotmail"}
TRUSTED_BRAND_TLDS ={"com", "net", "org", "in", "co.in", "co.uk", "de", "fr", "it", "es", "ca", "com.au", "co.jp",
                      "ae", "com.hk", "gov.in", "org.in", "nic.in", "bank.in", "sbi", "io", "us", "ie", "nl", "se"}


@dataclass
class Brand:
    name: str
    category: str
    domains: frozenset[str]
    aliases: tuple[str, ...]
    keys: tuple[str, ...]
    region: str

    def is_official(self, registrable: str, suffix: str = "") -> bool:
        if registrable in self.domains:
            return True
        label = registrable.split(".")[0]
        suf = registrable[len(label) + 1:]
        return label in self.keys and suf in TRUSTED_BRAND_TLDS and bool(self.domains) and any(
            d.split(".")[0] == label for d in self.domains
        )


@dataclass
class Knowledge:
    brands: list[Brand]
    suspicious_tlds: frozenset[str]
    shorteners: frozenset[str]
    free_hosting: frozenset[str]
    freemail: frozenset[str]
    esp_domains: frozenset[str]
    _domain_index: dict[str, Brand] = field(default_factory=dict)
    _alias_re: re.Pattern | None = None
    _alias_map: dict[str, Brand] = field(default_factory=dict)

    def brand_of_domain(self, registrable: str) -> Brand | None:
        b = self._domain_index.get(registrable)
        if b:
            return b
        for br in self.brands:
            if br.is_official(registrable):
                return br
        return None

    def brand_by_display_name(self, name: str) -> list[Brand]:
        """Brands a sender display name claims to be. Everyday-word aliases ('Bob', 'Apple', 'Visa', 'Vi')
        only count when the name is essentially just the alias plus a generic role word, so that
        'Bob Musser' is not mistaken for Bank of Baroda."""
        n = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 .]+", " ", name.lower())).strip()
        padded = f" {n} "
        rest_ok = set(GENERIC_ROLE_WORDS)
        out: list[Brand] = []
        for alias, br in self._alias_map.items():
            if f" {alias} " not in padded or br in out:
                continue
            if alias in AMBIGUOUS_ALIASES:
                leftover = [w for w in padded.replace(f" {alias} ", " ", 1).split() if w]
                if leftover and not all(w in rest_ok for w in leftover):
                    continue
            out.append(br)
        return out

    def brands_in_text(self, text: str) -> list[Brand]:
        """Brands named in body text, ignoring ambiguous everyday-word aliases."""
        if not self._alias_re:
            return []
        found: list[Brand] = []
        for m in self._alias_re.finditer((text or "").lower()):
            br = self._alias_map.get(m.group(1))
            if br and br not in found:
                found.append(br)
        return found


@lru_cache(maxsize=1)
def load() -> Knowledge:
    base = resources.files("phishguard") / "data"
    brands_raw = json.loads((base / "brands.json").read_text(encoding="utf-8"))
    lists = json.loads((base / "lists.json").read_text(encoding="utf-8"))
    brands = [
        Brand(b["n"], b["c"], frozenset(b["d"]), tuple(b["a"]), tuple(b["k"]), b.get("r", "global"))
        for b in brands_raw
    ]
    k = Knowledge(
        brands=brands,
        suspicious_tlds=frozenset(lists["suspicious_tlds"]),
        shorteners=frozenset(lists["shorteners"]),
        free_hosting=frozenset(lists["free_hosting"]),
        freemail=frozenset(lists["freemail"]),
        esp_domains=frozenset(lists["esp_domains"]),
    )
    for br in brands:
        for d in br.domains:
            k._domain_index.setdefault(d, br)
        for a in br.aliases:
            k._alias_map.setdefault(a, br)
    strong = sorted((a for a in k._alias_map if a not in AMBIGUOUS_ALIASES and len(a) >= 3), key=len, reverse=True)
    if strong:
        k._alias_re = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(a) for a in strong) + r")(?![a-z0-9])")
    return k
