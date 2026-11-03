"""Envelope layer: authentication results, From/Reply-To/Return-Path agreement, display-name
brand spoofing (email) and sender-ID sanity (SMS)."""
from __future__ import annotations

import re

from ..ctx import Ctx
from ..lookalike import brand_findings, edit_distance, skeleton
from ..models import Message, Signal
from ..urlutil import parse_url, registrable_domain

_AR = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

# Known India SMS header (DLT sender-id) bodies -> brand name. The 2-letter prefix (operator/circle) varies.
SMS_HEADERS = {
    "HDFCBK": "HDFC Bank", "HDFCBN": "HDFC Bank", "SBIINB": "State Bank of India", "SBIPSG": "State Bank of India",
    "SBICRD": "State Bank of India", "SBIUPI": "State Bank of India", "SBYONO": "State Bank of India",
    "ICICIB": "ICICI Bank", "ICICIT": "ICICI Bank", "AXISBK": "Axis Bank", "KOTAKB": "Kotak Mahindra Bank",
    "PNBSMS": "Punjab National Bank", "BOIIND": "Bank of India", "CANBNK": "Canara Bank", "UNIONB": "Union Bank of India",
    "IDFCFB": "IDFC FIRST Bank", "YESBNK": "Yes Bank", "INDUSB": "IndusInd Bank", "BOBSMS": "Bank of Baroda",
    "PAYTMB": "Paytm", "PYTM": "Paytm", "PHONPE": "PhonePe", "AIRTEL": "Airtel", "JIOPAY": "Reliance Jio",
    "JIOINF": "Reliance Jio", "IRCTCI": "IRCTC", "UIDAI": "UIDAI / Aadhaar", "INCTAX": "Income Tax Department",
    "EPFOHO": "EPFO", "AMAZON": "Amazon", "FLPKRT": "Flipkart", "SWIGGY": "Swiggy", "ZOMATO": "Zomato",
    "DLHVRY": "Delhivery", "BLDART": "Blue Dart", "DTDCIN": "DTDC", "INDPST": "India Post", "NSDLPB": "NSDL / PAN",
    "FASTAG": "NHAI / FASTag", "NPCIBH": "NPCI / BHIM UPI", "BSNLTL": "BSNL", "TATAPW": "Tata Power",
}
_DLT = re.compile(r"^([A-Z]{2})-([A-Z0-9]{3,8})(?:-[A-Z])?$")


def parse_auth(msg: Message) -> dict[str, str]:
    """Collapse Authentication-Results / Received-SPF into {spf,dkim,dmarc: result}. First hit wins
    (headers are prepended by each hop, so the first is the receiving server's own verdict)."""
    res: dict[str, str] = {}
    for h in msg.all_headers("authentication-results"):
        for k, v in _AR.findall(h):
            k, v = k.lower(), v.lower()
            if k == "arc":
                continue
            # a pass anywhere for dkim is meaningful, but keep the first verdict for spf/dmarc
            if k not in res:
                res[k] = v
            elif k == "dkim" and v == "pass" and res[k] != "pass":
                res[k] = "pass"
    if "spf" not in res:
        for h in msg.all_headers("received-spf"):
            m = re.match(r"\s*([a-z]+)", h, re.I)
            if m:
                res["spf"] = m.group(1).lower()
                break
    return res


def analyze(msg: Message, ctx: Ctx) -> tuple[list[Signal], dict]:
    if msg.kind == "sms":
        return _analyze_sms(msg, ctx)
    if msg.kind != "email":
        return [], {}
    kb = ctx.kb
    sigs: list[Signal] = []
    facts: dict = {}

    def add(id_: str, pts: float, reason: str, ev: str = "") -> None:
        sigs.append(ctx.sig("headers", id_, pts, reason, ev))

    auth = parse_auth(msg)
    facts["auth"] = auth
    from_dom = registrable_domain(msg.from_addr) if msg.from_addr else ""
    facts["from_domain"] = from_dom
    if not msg.from_addr:
        add("hdr.no_from", 20, "The message has no valid sender address")
    if len(msg.all_headers("from")) > 1:
        add("hdr.multiple_from", 45, "The message contains more than one From header (a known spoofing trick)")

    if auth:
        if auth.get("dmarc") == "fail":
            add("hdr.dmarc_fail", 40, "DMARC check failed: the sender domain did not authorise this message", "dmarc=fail")
        if auth.get("spf") in ("fail", "permerror"):
            add("hdr.spf_fail", 30, "SPF failed: the sending server is not allowed to send for this domain", f"spf={auth['spf']}")
        elif auth.get("spf") == "softfail":
            add("hdr.spf_softfail", 15, "SPF soft-fail: the sending server is probably not authorised", "spf=softfail")
        if auth.get("dkim") in ("fail", "permerror"):
            add("hdr.dkim_fail", 28, "DKIM signature is invalid: message may be forged or altered", f"dkim={auth['dkim']}")
        if not any(auth.get(k) == "pass" for k in ("spf", "dkim", "dmarc")) and not sigs:
            add("hdr.no_auth_pass", 10, "No authentication check (SPF/DKIM/DMARC) passed for this sender")
    else:
        ctx.notes.append("No Authentication-Results header: SPF/DKIM/DMARC could not be assessed")
        facts["auth_missing"] = True

    # --- sender field agreement ---
    rt_dom = registrable_domain(msg.return_path) if msg.return_path and msg.return_path != "" else ""
    rp_dom = registrable_domain(msg.reply_to) if msg.reply_to else ""
    facts.update(reply_to_domain=rp_dom, return_path_domain=rt_dom)
    dmarc_ok = auth.get("dmarc") == "pass"
    bulk = msg.is_bulk
    if rp_dom and from_dom and rp_dom != from_dom and rp_dom not in kb.esp_domains:
        if rp_dom in kb.freemail and from_dom not in kb.freemail:
            add("hdr.reply_to_freemail", 40, f"Replies are redirected to a free mailbox ({rp_dom}) instead of {from_dom}", msg.reply_to)
        elif not bulk:
            add("hdr.reply_to_mismatch", 16, f"Replies go to a different domain ({rp_dom}) than the sender ({from_dom})", msg.reply_to)
    if rt_dom and from_dom and rt_dom != from_dom and rt_dom not in kb.esp_domains and not dmarc_ok and not bulk:
        if not (rt_dom.endswith("." + from_dom) or from_dom.endswith("." + rt_dom)):
            add("hdr.return_path_mismatch", 6, f"Bounce address domain ({rt_dom}) differs from sender domain ({from_dom})", msg.return_path)
    mid = msg.header("message-id")
    m = _EMAIL.search(mid or "")
    if m and from_dom and registrable_domain(m.group(1)) not in (from_dom,) and registrable_domain(m.group(1)) not in kb.esp_domains \
            and not dmarc_ok and from_dom not in kb.freemail and not bulk:
        add("hdr.message_id_mismatch", 6, f"Message-ID was generated by {registrable_domain(m.group(1))}, not {from_dom}")

    # --- display-name spoofing ---
    name = msg.from_name
    spoofed: list[str] = []
    if name:
        em = _EMAIL.search(name)
        if em and registrable_domain(em.group(1)) != from_dom:
            shown_dom = registrable_domain(em.group(1))
            # An address of a known brand in the name is a classic spoof. Otherwise on list mail (relayed / anonymised
            # list traffic) it is common and harmless-looking, so it only weighs a little.
            weak_case = msg.is_bulk and not kb.brand_of_domain(shown_dom)
            add("hdr.display_name_email", 20 if weak_case else 50,
                f"Sender name contains an address from another domain ({em.group(0)})", name)
        for br in kb.brand_by_display_name(name):
            if from_dom and not br.is_official(from_dom) and from_dom not in br.domains:
                spoofed.append(br.name)
                if from_dom in kb.freemail:
                    add("hdr.display_name_brand_freemail", 65, f"Sender calls itself '{br.name}' but writes from a free mailbox ({from_dom})", name)
                elif from_dom not in kb.esp_domains:
                    add("hdr.display_name_brand", 55, f"Sender calls itself '{br.name}' but the address is at {from_dom}", name)
        if not spoofed:
            typo = display_name_typo(name, ctx)
            if typo is not None and not (from_dom and typo.is_official(from_dom)):
                spoofed.append(typo.name)
                add("hdr.display_name_typo", 50, f"Sender name is a misspelling of '{typo.name}' ({name[:40]})", name)
    # --- lookalike sender domain ---
    if from_dom:
        p = parse_url("https://" + (msg.from_addr.rsplit("@", 1)[-1] or from_dom))
        if p:
            for f in brand_findings(p):
                spoofed.append(f.brand.name)
                pts = {"homograph": 80, "typosquat": 55, "combosquat": 50, "brand-subdomain": 55, "brand-tld": 50}.get(f.kind, 40)
                if f.weak and p.tld not in kb.suspicious_tlds:
                    pts = min(pts, 28)  # everyday-word brand keyword (apple, outlook...) with nothing else suspicious
                add(f"hdr.from_{f.kind.replace('-', '_')}", pts, f"Sender domain imitates {f.brand.name} ({f.detail})", msg.from_addr)
    facts["spoofed_brands"] = sorted(set(spoofed))

    # Mitigation. Passing authentication only proves the sender owns the domain it writes from, and
    # attackers own domains too - so it only counts for much when that domain is a genuine known brand.
    authenticated = dmarc_ok or (auth.get("spf") == "pass" and auth.get("dkim") == "pass")
    if authenticated and not spoofed and not any(s.points >= 25 for s in sigs):
        if from_dom and kb.brand_of_domain(from_dom):
            add("hdr.auth_pass_brand", -20, f"Sender authenticated as the real {kb.brand_of_domain(from_dom).name} domain ({from_dom})")
        else:
            add("hdr.auth_pass", -3, "Sender passed SPF/DKIM/DMARC (proves the domain, not that it is trustworthy)")
    return sigs, facts


def display_name_typo(name: str, ctx: Ctx):
    """Brand whose name the display name *almost* matches (NETLFLX, Pay-Pal, Paypa1)."""
    letters = re.sub(r"[^a-z0-9 ]+", " ", name.lower())
    toks = [t for t in letters.split() if len(t) >= 5] + ([letters.replace(" ", "")] if len(letters.replace(" ", "")) >= 5 else [])
    # a token that is itself a known brand word/alias ("HDFC Bank", "Axis") is not a misspelling of a neighbour (IDFC)
    all_keys = {k for b in ctx.kb.brands for k in b.keys} | set(ctx.kb._alias_map)
    if ctx.kb.brand_by_display_name(name) or any(t in all_keys for t in toks):
        return None
    for br in ctx.kb.brands:
        for key in br.keys:
            if len(key) < 5:
                continue
            ks = skeleton(key)
            for t in toks:
                if t != key and t not in all_keys and edit_distance(skeleton(t), ks, 1) <= 1 and abs(len(t) - len(key)) <= 1:
                    return br
    return None


def _analyze_sms(msg: Message, ctx: Ctx) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    facts: dict = {"sender_id": msg.sender_id}
    sid = (msg.sender_id or "").strip()
    if not sid:
        return sigs, facts
    body_brands = ctx.kb.brands_in_text(msg.text)
    claimed = body_brands[0].name if body_brands else ""
    m = _DLT.match(sid.upper())
    if m:
        body = m.group(2)
        brand = SMS_HEADERS.get(body)
        facts["header_brand"] = brand
        if brand and body_brands and not any(b.name == brand for b in body_brands):
            sigs.append(ctx.sig("headers", "sms.header_brand_mismatch", 40,
                                f"SMS header '{sid}' belongs to {brand}, but the text talks about {claimed}", sid))
    elif re.fullmatch(r"\+?\d[\d\s-]{7,14}\d", sid):
        if body_brands or re.search(r"(?i)\b(bank|a/c|account|kyc|upi|card|otp)\b", msg.text):
            sigs.append(ctx.sig("headers", "sms.personal_number_sender", 30,
                                f"A bank/payment style message came from an ordinary phone number ({sid}), not a registered sender ID", sid))
        else:
            sigs.append(ctx.sig("headers", "sms.unknown_number", 4, "Message from an unknown phone number", sid))
    else:
        # alphanumeric but not DLT-shaped (e.g. "HDFC-BANK", "SBI KYC")
        brands = ctx.kb.brand_by_display_name(sid.replace("-", " ").replace("_", " "))
        if brands:
            sigs.append(ctx.sig("headers", "sms.nonstandard_sender", 25,
                                f"Sender ID '{sid}' imitates {brands[0].name} but is not in the registered format", sid))
    return sigs, facts
