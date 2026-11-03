"""URL layer: lookalike domains, domain age, shorteners, IP hosts, TLDs, blocklists."""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, unquote

from ..ctx import Ctx
from ..lookalike import brand_findings, looks_generated, phish_words_in_domain
from ..models import Message, Signal
from ..urlutil import ParsedUrl, defang, parse_url, registrable_domain

_DOMAINISH = re.compile(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/\S*)?")
_LOGIN_PATH = re.compile(r"(?i)(log-?in|sign-?in|verify|verification|secure|account|update|confirm|auth|kyc|wallet|banking|password|reset|unlock|reactivat|recover)")
TRACKING = {"list-manage.com", "mailchi.mp", "sendgrid.net", "mandrillapp.com", "exct.net", "e2ma.net", "hubspotlinks.com",
            "click.pstmrk.it", "pstmrk.it", "linksynergy.com", "doubleclick.net", "awstrack.me", "t.co", "lnkd.in",
            "safelinks.protection.outlook.com", "urldefense.com", "mimecast.com", "proofpoint.com", "google.com"}


def _mixed_script(host_unicode: str) -> bool:
    """True when a single label mixes alphabets (e.g. Latin + Cyrillic)."""
    for label in host_unicode.split("."):
        scripts = set()
        for ch in label:
            if ch.isalpha():
                try:
                    scripts.add(unicodedata.name(ch).split()[0])
                except ValueError:
                    scripts.add("UNKNOWN")
        if len(scripts) > 1:
            return True
    return False


def analyze_url(url: str, ctx: Ctx, text: str = "", origin: str = "text", resolved_from: str | None = None,
                allow_lookups: bool = True) -> tuple[list[Signal], dict]:
    """Signals for one URL plus a per-URL info dict for display."""
    kb = ctx.kb
    sigs: list[Signal] = []
    info: dict = {"url": url, "defanged": defang(url), "text": text, "origin": origin, "flags": [], "brands": [],
                  "resolved_from": resolved_from}
    p = parse_url(url)
    if p is None:
        return sigs, info
    info.update(host=p.host, registrable=p.registrable)

    def add(id_: str, pts: float, reason: str) -> None:
        sigs.append(ctx.sig("urls", id_, pts, reason, defang(url)))
        info["flags"].append(id_)

    scheme_bad = re.match(r"(?i)^(javascript|data|vbscript):", url.strip())
    if scheme_bad:
        add("url.dangerous_scheme", 50, f"Link uses a '{scheme_bad.group(1).lower()}:' scheme that runs code or hides content")
        return sigs, info

    reg = p.registrable
    official = kb.brand_of_domain(reg)
    is_shortener = reg in kb.shorteners or p.host in kb.shorteners
    is_hosting = any(p.host == h or p.host.endswith("." + h) for h in kb.free_hosting)
    is_esp = reg in kb.esp_domains or reg in TRACKING
    info["official_brand"] = official.name if official else None
    info["shortener"] = is_shortener

    # --- blocklists (local feed DB; zero data leaves the machine) ---
    hit = ctx.intel.feeds.lookup(url)
    if hit:
        if hit.exact:
            add("url.blocklist", 95, f"This exact link is listed as phishing in the {hit.source} feed")
        elif not official and not is_hosting and not is_esp and not is_shortener:
            add("url.blocklist_host", 70, f"This site hosts a page listed as phishing in the {hit.source} feed")
    sb = ctx.sb_hits.get(url)
    if sb:
        add("url.safe_browsing", 95, f"Google Safe Browsing flags this link ({sb.replace('_', ' ').lower()})")

    # --- structure ---
    if p.is_ip:
        add("url.ip_host", 40, f"Link points to a raw IP address ({p.ip}) instead of a domain name")
    if p.userinfo and re.search(r"[.]", p.userinfo):
        add("url.userinfo_trick", 60, f"Link hides its real host behind '{p.userinfo}@' — it actually goes to {p.host}")
    if p.port and p.port not in (80, 443):
        add("url.odd_port", 12, f"Link uses an unusual port ({p.port})")
    if p.scheme == "http" and p.explicit_scheme and _LOGIN_PATH.search(p.path + "?" + p.query) and not p.is_ip:
        add("url.http_login", 10, "Login/verification-style link over unencrypted HTTP")
    nsub = len([x for x in p.subdomain.split(".") if x]) if p.subdomain else 0
    if nsub >= 4:
        add("url.deep_subdomains", 15, f"Unusually deep subdomain nesting ({p.host})")
    if len(url) > 150 and not is_esp:
        add("url.very_long", 6, "Unusually long link")
    if p.is_idn:
        if _mixed_script(p.host_unicode):
            add("url.mixed_script", 70, f"Domain mixes alphabets to imitate another name ({p.host_unicode})")
        else:
            add("url.idn", 18, f"Internationalised (punycode) domain: {p.host_unicode}")

    # --- reputation of the place ---
    if is_shortener:
        add("url.shortener", 18, f"Link shortener ({p.host}) hides the real destination")
    if is_hosting and not official:
        brand_words = [b.name for b in kb.brands_in_text(" ".join([p.host, p.path]))]
        if brand_words:
            add("url.hosting_brand", 40, f"Brand name '{brand_words[0]}' on free hosting platform ({p.registrable})")
        else:
            add("url.free_hosting", 12, f"Page hosted on a free/anonymous hosting platform ({p.registrable})")
    tld = p.tld
    if not p.is_ip and tld in kb.suspicious_tlds and not official:
        words = phish_words_in_domain(p)
        if words:
            add("url.tld_keywords", 30, f"Cheap/abused domain ending '.{tld}' combined with '{words[0]}'-style wording")
        else:
            add("url.suspicious_tld", 14, f"Domain ends in '.{tld}', which is heavily abused for phishing")
    elif not p.is_ip and not official and not is_hosting and not is_esp and not is_shortener:
        words = phish_words_in_domain(p)
        if len(words) >= 2:
            add("url.phish_words", 18, f"Domain stuffed with login/security wording ({', '.join(words[:3])})")
    if not p.is_ip and not official and looks_generated(reg.split(".")[0]):
        add("url.generated_domain", 12, "Domain name looks randomly generated")

    # --- brand impersonation ---
    bad_tld = not p.is_ip and tld in kb.suspicious_tlds
    corroborated = bad_tld or len(phish_words_in_domain(p)) >= 1
    for f in brand_findings(p):
        info["brands"].append(f.brand.name)
        # A brand keyword that is also an everyday word (apple, outlook, steam...) needs more evidence than the keyword alone:
        # lone keyword -> 26; keyword + login/secure wording -> capped at 40; keyword + abused TLD -> full strength.
        weak = f.weak and not corroborated
        capped = f.weak and corroborated and not bad_tld
        if f.kind == "homograph":
            add("url.brand_homograph", 80, f"Look-alike of {f.brand.name} using disguised characters ({f.detail})")
        elif f.kind == "typosquat":
            conf = f.detail.endswith("(lookalike characters)")
            add("url.brand_typosquat", 28 if weak else min(40, 60 if conf else 38) if capped else (60 if conf else 38),
                f"Domain imitates {f.brand.name}: {f.detail}")
        elif f.kind == "combosquat":
            add("url.brand_combosquat", 26 if weak else 40 if capped else 55, f"Domain bolts '{f.brand.name}' onto an unrelated site ({reg})")
        elif f.kind == "brand-subdomain":
            add("url.brand_subdomain", 26 if weak else 40 if capped else 60,
                f"{f.brand.name} appears in the subdomain/path of an unrelated domain ({f.detail})")
        elif f.kind == "brand-tld":
            add("url.brand_tld", 55, f"Uses the {f.brand.name} name on a domain that is not theirs ({reg})")
    if not official and not p.is_ip and re.search(r"(?i)(paypal|amazon|microsoft|google|apple|sbi|hdfc|icici|netflix)\.[a-z]{2,3}/", url.split("//", 1)[-1].split("/", 1)[-1] + "/"):
        add("url.brand_in_path", 22, "A well-known brand domain is embedded in the link path of an unrelated site")

    # --- anchor text vs real target ---
    if text and origin == "a":
        m = _DOMAINISH.search(text)
        if m:
            shown = registrable_domain(m.group(1))
            decoded_target = unquote(unquote(url)).lower()
            if shown and shown != reg and shown not in decoded_target:  # a tracker that carries the shown URL is fine
                shown_brand = kb.brand_of_domain(shown)
                if reg in kb.esp_domains or reg in TRACKING:
                    add("url.text_mismatch_tracker", 8, f"Link text shows {shown} but goes through tracking domain {reg}")
                elif shown_brand and not shown_brand.is_official(reg):
                    # the text is bait: a brand's real address placed over a link to somewhere else
                    add("url.text_mismatch", 55, f"Link text says '{m.group(1)}' ({shown_brand.name}) but it really goes to {p.host}")
                else:
                    add("url.text_mismatch_other", 14, f"Link text says '{m.group(1)}' but it goes to {p.host}")
        else:
            brands = [b for b in kb.brands_in_text(text) if not b.is_official(reg)]
            if brands and not official and not is_esp:
                add("url.text_brand_mismatch", 12, f"Link text names {brands[0].name} but goes to {p.host}")

    # --- redirect parameters (open redirect abuse) ---
    for k, v in parse_qsl(p.query, keep_blank_values=False):
        if re.match(r"(?i)^https?://", v):
            inner = parse_url(v)
            if inner and inner.registrable != reg:
                add("url.redirect_param", 10, f"Link passes through {p.host} and then redirects to {inner.host}")
                break

    # --- a recipient address baked into the link (per-victim tracking, common in credential harvesting) ---
    if not official and not is_esp and not is_shortener and re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", p.query + "#" + url.split("#", 1)[-1] if "#" in url else p.query):
        add("url.email_in_link", 12, "The link has an email address built into it (per-recipient tracking)")

    # --- login-ish path on an unrelated domain ---
    if not official and not is_esp and _LOGIN_PATH.search(p.path) and ctx.kb.brands_in_text(p.host + " " + p.path):
        add("url.login_path_brand", 15, "Login-style path that mentions a brand on a domain that isn't theirs")

    # --- domain age (needs network; cached; domain only) ---
    if allow_lookups and not p.is_ip and not official and not is_esp and not is_hosting and not is_shortener:
        age = ctx.intel.rdap.age_days(reg, ctx.now)
        if age is not None:
            info["age_days"] = round(age, 1)
            if age < 7:
                add("url.domain_age", 55, f"Domain {reg} was registered only {int(age)} day(s) ago")
            elif age < 30:
                add("url.domain_age", 45, f"Domain {reg} was registered {int(age)} days ago")
            elif age < 90:
                add("url.domain_age", 22, f"Domain {reg} is only {int(age)} days old")
            elif age < 180:
                add("url.domain_age", 8, f"Domain {reg} is under 6 months old")
    return sigs, info


def analyze(msg: Message, ctx: Ctx, resolved: dict[str, str] | None = None) -> tuple[list[Signal], list[dict]]:
    """Aggregate over all URLs in a message. Keeps the strongest instance of each signal id."""
    resolved = resolved or {}
    best: dict[str, Signal] = {}
    infos: list[dict] = []
    # Safe Browsing (optional; sends URLs, not bodies)
    urls = [u.url for u in msg.urls[:40]]
    ctx.sb_hits = ctx.intel.safebrowsing.check(urls + list(resolved.values())) if ctx.intel.safebrowsing.enabled else {}
    budget = 6  # max RDAP lookups per message
    seen_reg: set[str] = set()
    for ref in msg.urls[:40]:
        p = parse_url(ref.url)
        reg = p.registrable if p else ""
        do_lookup = budget > 0 and reg not in seen_reg
        s, info = analyze_url(ref.url, ctx, ref.text, ref.origin, allow_lookups=do_lookup)
        if do_lookup and reg and ctx.intel.rdap.enabled:
            budget -= 1
        seen_reg.add(reg)
        final = resolved.get(ref.url)
        if final and final != ref.url:
            info["final_url"] = final
            info["defanged_final"] = defang(final)
            s2, info2 = analyze_url(final, ctx, "", "resolved", resolved_from=ref.url, allow_lookups=do_lookup)
            s += s2
            info["final_flags"] = info2["flags"]
            info["brands"] = sorted(set(info["brands"]) | set(info2["brands"]))
        info["points"] = max((x.points for x in s), default=0)
        infos.append(info)
        for sg in s:
            cur = best.get(sg.id)
            if cur is None or sg.points > cur.points:
                best[sg.id] = sg
    # Links that lead somewhere unrelated to the sender (compromised sites, throwaway pages) while the
    # message nags you to act. Newsletters link to their own domain or an ESP tracker, so they don't trip this.
    if msg.kind == "email" and msg.from_addr and infos and not msg.is_bulk:
        from_reg = registrable_domain(msg.from_addr)
        from_label = from_reg.split(".")[0]
        if from_reg and from_reg not in ctx.kb.freemail:
            foreign = [i for i in infos if i.get("registrable") and not i.get("official_brand")
                       and i["registrable"] not in ctx.kb.esp_domains and i["registrable"] not in TRACKING
                       and not i.get("shortener")]
            own = [i for i in infos if i.get("registrable") == from_reg or (i.get("registrable") or "").split(".")[0] == from_label]
            if foreign and not own:
                best["url.offsite_link"] = ctx.sig("urls", "url.offsite_link", 10,
                                                   f"Links go to {foreign[0]['registrable']}, which has nothing to do with the sender ({from_reg})", foreign[0]["defanged"])
    return list(best.values()), infos
