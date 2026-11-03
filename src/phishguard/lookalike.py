"""Lookalike / typosquat detection for domains (original implementation inspired by
the *ideas* in phishing_catcher: keyword + TLD + edit-distance + homoglyph scoring)."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache

from .knowledge import WEAK_KEYS, Brand, load
from .urlutil import ParsedUrl

# Visually-confusable characters -> ASCII skeleton (Cyrillic, Greek and friends)
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ԛ": "q", "ԝ": "w", "ɑ": "a", "ο": "o",
    "α": "a", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "υ": "u", "ɩ": "i", "ᴀ": "a", "ʙ": "b",
    "ℓ": "l", "ｏ": "o", "ａ": "a", "ｅ": "e", "ı": "i", "ȷ": "j", "ƅ": "b", "ǀ": "l", "օ": "o",
}
PHISH_WORDS = (
    "login", "signin", "sign-in", "secure", "security", "verify", "verification", "account", "update", "confirm",
    "banking", "netbanking", "wallet", "support", "helpdesk", "billing", "invoice", "payment", "refund", "kyc",
    "unlock", "suspend", "recover", "authenticate", "validate", "alert", "customer", "service", "official", "portal",
    "reward", "bonus", "claim", "track", "delivery", "parcel", "customs", "reactivate", "limited", "unusual",
)
_DIGIT_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "!": "i"})


def skeleton(label: str) -> str:
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in label.lower())
    s = s.translate(_DIGIT_MAP)
    s = re.sub(r"[-_.]", "", s)
    return s.replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein (adjacent transposition) with early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


@dataclass
class Finding:
    kind: str  # typosquat | homograph | combosquat | brand-subdomain | brand-tld
    brand: Brand
    detail: str
    weak: bool = False  # matched on a keyword that is also an everyday word (apple, outlook, steam...)


def _unicode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def brand_findings(p: ParsedUrl) -> tuple[Finding, ...]:
    return _brand_findings(p)


@lru_cache(maxsize=16384)
def _brand_findings(p: ParsedUrl) -> tuple[Finding, ...]:
    """How (if at all) does this host impersonate a known brand?"""
    if p.is_ip:
        return ()
    k = load()
    reg = p.registrable
    if k.brand_of_domain(reg):
        return ()  # official domain of some brand (e.g. mail.google.com)
    label = _unicode_label(reg.split(".")[0])  # punycode (xn--...) compared as-is would hide every homograph
    label_skel = skeleton(label)
    sub_text = p.subdomain
    out: list[Finding] = []
    seen_brands: set[str] = set()

    cur_key = ""

    def add(kind: str, br: Brand, detail: str) -> None:
        if (br.name, kind) not in seen_brands:
            seen_brands.add((br.name, kind))
            out.append(Finding(kind, br, detail, weak=cur_key in WEAK_KEYS and kind in ("combosquat", "brand-subdomain", "typosquat")))

    for br in k.brands:
        for key in br.keys:
            if len(key) < 3:
                continue
            cur_key = key
            key_skel = skeleton(key)
            tokens = re.split(r"[-_]", label)
            if label == key:
                add("brand-tld", br, f"'{label}' on unofficial domain {reg}")
                continue
            if p.is_idn and label_skel == key_skel and label != key:
                add("homograph", br, f"{p.host_unicode} looks like {key}")
                continue
            if label_skel == key_skel and label != key:
                add("typosquat", br, f"{label} ~ {key} (lookalike characters)")
                continue
            if len(key) >= 5:
                limit = 1 if len(key) < 9 else 2
                if edit_distance(label_skel, key_skel, limit) <= limit and abs(len(label) - len(key)) <= limit:
                    add("typosquat", br, f"{label} is {edit_distance(label_skel, key_skel, limit)} edit(s) from {key}")
                    continue
            if key in tokens or (len(key) >= 6 and key in label) or (len(key) >= 4 and key_skel in [skeleton(t) for t in tokens]):
                add("combosquat", br, f"{label} contains '{key}'")
                continue
            # brand keyword used in the subdomain part of an unrelated registrable domain
            if sub_text and (key in re.split(r"[.\-_]", sub_text) or (len(key) >= 6 and key in sub_text)):
                add("brand-subdomain", br, f"'{key}' used as subdomain of {reg}")
    # Official-looking domain embedded in subdomain: paypal.com.evil.tld (never weak: a full real domain name is embedded)
    cur_key = ""
    for br in k.brands:
        for d in br.domains:
            if f"{d}." in (p.host + ".") and not p.host.endswith(d) and len(d) >= 7:
                add("brand-subdomain", br, f"'{d}' embedded in {p.host}")
    return tuple(out)


def phish_words_in_domain(p: ParsedUrl) -> list[str]:
    text = (p.subdomain + "." + p.registrable.split(".")[0]).lower()
    return [w for w in PHISH_WORDS if w in text]


def looks_generated(label: str) -> bool:
    """High-entropy, digit-mixed labels (DGA-ish or throwaway hosts)."""
    if len(label) < 10:
        return False
    digits = sum(c.isdigit() for c in label)
    vowels = sum(c in "aeiou" for c in label)
    return (shannon_entropy(label) > 3.4 and digits >= 3) or (vowels / len(label) < 0.15 and len(label) > 12)
