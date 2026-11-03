"""Content layer: social-engineering language, credential/payment requests, impersonation of
banks/couriers/government, and India-specific scam templates. Rules are original and
deliberately conservative; the trained classifier (layers/ml.py) complements them."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..ctx import Ctx
from ..models import Message, Signal
from ..parsing.html_info import parse_html
from ..urlutil import parse_url, registrable_domain
from .headers import SMS_HEADERS

I = re.I
_ZW = re.compile(r"[​‌‍⁠﻿­͏]")
_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?(?:0?\d{2,4}[\s-]?)?\d{3,5}[\s-]?\d{4,6}(?!\d)|\b1800[\s-]?\d{3}[\s-]?\d{3,4}\b")
_MONEY = r"(?:₹|rs\.?|inr|usd|\$|€|£)\s?\d[\d,]*"


def _norm(s: str) -> str:
    s = _ZW.sub("", s or "")
    s = s.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", s)


def _c(*pats: str) -> list[re.Pattern]:
    return [re.compile(p, I) for p in pats]


@dataclass
class Rule:
    id: str
    base: float
    extra: float
    cap: float
    reason: str
    groups: list[list[re.Pattern]]  # every group must match at least once
    needs_contact: bool = False  # halve unless a URL or phone number is present
    negations: list[re.Pattern] = field(default_factory=list)
    window: int = 0  # >0: all groups must match within this many characters of group 0's match

    def __post_init__(self) -> None:
        # Multi-group scam templates are short-message patterns: their evidence must sit close together,
        # otherwise long newsletters that merely contain both vocabularies would match by chance.
        if not self.window and len(self.groups) > 1 and (
                self.id.startswith("scam.") or self.id in ("content.authority_threat", "content.callback_scam", "content.tech_support")):
            self.window = 260

    def _first(self, pats: list[re.Pattern], text: str, base: int = 0) -> tuple[str, int, int] | None:
        for p in pats:
            for m in p.finditer(text):
                if self.negations and any(n.search(text[max(0, m.start() - 60): m.start()]) for n in self.negations):
                    continue
                return m.group(0), base + m.start(), base + m.end()
        return None

    def run(self, text: str) -> list[str]:
        """First match from every group (all groups must match), or [] if the rule doesn't fire."""
        if not self.window:
            found = []
            for g in self.groups:
                hit = self._first(g, text)
                if hit is None:
                    return []
                found.append(hit[0].strip())
            return found
        # proximity mode: anchor on each match of group 0, require the other groups nearby
        for p in self.groups[0]:
            for m in p.finditer(text):
                lo, hi = max(0, m.start() - self.window), min(len(text), m.end() + self.window)
                found = [m.group(0).strip()]
                for g in self.groups[1:]:
                    hit = self._first(g, text[lo:hi])
                    if hit is None:
                        break
                    found.append(hit[0].strip())
                else:
                    return found
        return []

    def points(self, text: str) -> float:
        """base, plus `extra` for each additional distinct pattern that matched, capped."""
        n = sum(1 for g in self.groups for p in g if p.search(text))
        return min(self.cap, self.base + self.extra * max(0, n - len(self.groups)))


_NEG = _c(r"\b(do ?n[o']?t|never|don't|not|won't|will never|dont|nobody|no one|should ?n[o']?t|avoid|beware|careful|warn\w*|remember|reminder|tip|safe(ty)?)\b[^.]{0,50}$")

RULES: list[Rule] = [
    Rule("content.urgency", 10, 6, 28, "Pressure/urgency wording", [_c(
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact (now|fast|immediately|today)\b",
        r"\bwithin (the next )?(\d+|a|one|two|three|twelve|twenty[- ]four|forty[- ]eight) ?(hours?|hrs?|days?|minutes?|mins?)\b",
        r"\bfinal (notice|warning|reminder)\b", r"\blast (chance|warning|reminder|notice)\b",
        r"\bexpires? (today|tonight|soon|in \d+)\b", r"\bexpiring (today|tonight|soon)\b", r"\bright away\b",
        r"\bfailure to (comply|respond|verify|update|act|complete)\b",
        r"\bor (else )?(your )?(account|service|card|number|sim|connection|access) (will|shall)\b",
        r"\bavoid (suspension|closure|penalty|disconnection|blocking|deactivation|legal)\b",
        r"\bbefore it'?s too late\b", r"\btoday only\b", r"\bhurry\b", r"\baction required\b",
        r"\b(tonight|by tonight|by today)\b", r"\bturant\b", r"\bjaldi\b", r"तुरंत", r"\bimmediate action\b",
    )]),
    Rule("content.account_threat", 22, 8, 40, "Threat that your account/service will be blocked or restricted", [_c(
        r"\b(your )?(account|card|sim|number|service|connection|access|profile|wallet|mailbox|password|id)\b[^.]{0,40}\b(has been|have been|is|was|will be|shall be|may be|is going to be|has got) (temporarily |permanently )?(suspended|blocked|locked|deactivated|disabled|closed|restricted|limited|terminated|expired|disconnected|compromised|cancelled|frozen)\b",
        r"\bunusual (activity|sign[- ]?in|login|transaction)\b", r"\bunauthori[sz]ed (login|transaction|access|activity|attempt|debit)\b",
        r"\bsuspicious (activity|sign[- ]?in|login|transaction|attempt)\b", r"\bsecurity (alert|notice|warning|breach)\b",
        r"\b(will|shall) be (suspended|blocked|deactivated|disabled|terminated|closed|deleted|disconnected)\b",
        r"\bhas been (suspended|blocked|deactivated|disabled|restricted|compromised)\b",
        r"band ho jay(e|ega)", r"block ho jay(e|ega)", r"ब्लॉक", r"बंद (हो|कर)",
    )]),
    Rule("content.credential_request", 32, 8, 50, "Asks you to verify, confirm or update account credentials/details", [_c(
        r"\b(verify|confirm|validate|re-?validate|authenticate|update|re-?activate|restore|unlock|secure|review|complete) (your |the |ur )?(account|identity|password|credentials?|login|sign[- ]?in|billing|payment|card|bank|details|information|profile|e-?mail|mailbox|kyc|security)\b",
        r"\b(log ?in|sign ?in) (to|and|now|here|below)[^.]{0,30}\b(verify|confirm|restore|secure|unlock|continue|review|view|update|keep|avoid)\b",
        r"\b(enter|provide|submit|send|share|type|input) (us |me )?(your |the )?[^.]{0,20}(password|credentials?|card (number|details)|account (number|details)|username|ssn|social security|net ?banking|debit card|credit card|pan\b|aadhaar|aadhar|date of birth)\b",
        r"\bclick (here|below|the (link|button))[^.]{0,40}\b(verify|confirm|update|login|log in|sign in|restore|unlock|claim|activate)\b",
        r"\b(verify|confirm|update|login)[^.]{0,25}\b(click|tap|visit|open) (here|below|the link)\b",
        r"\bkyc (update|verification|pending|expire)", r"update karein", r"अपडेट",
        r"\b(log ?in|sign ?in)\b[^.]{0,15}\bwith your (corporate|network|company|work|email|office|domain|windows)?\s*(user ?name|password|credentials?|login)\b",
        r"\b(web ?mail|e-?mail|mailbox|account|office ?365|outlook|owa)\b[^.]{0,30}\b(needs?|requires?|required|pending|awaiting)\b[^.]{0,15}\b(verif\w+|validat\w+|updat\w+|confirm\w+|re-?activat\w+)\b",
        r"\bverif(y|ication)\b[^.]{0,40}\b(web ?mail|e-?mail account|mailbox|office ?365|ownership|your (identity|account))\b",
        r"\bkeep (your |the )?(e-?mail|mailbox|account|web ?mail)( account)? (active|alive|working|from (closing|deactivation))\b",
    )], needs_contact=True),
    Rule("content.sensitive_request", 50, 6, 60, "Asks you to share an OTP, PIN, CVV or password", [_c(
        r"\b(share|send|tell|provide|give|reply with|forward|read out|disclose)\b(?:\s+(?:us|me|the|your|ur|this|that|with|to|our|a|an|it|us the|us your|me your))*\s+(otp|one[- ]?time (password|pin|code)|cvv|cvc|mpin|upi ?pin|atm ?pin|pin ?number|\bpin\b|password|passcode|verification code|security code|card number)\b",
        r"\b(otp|cvv|mpin|upi ?pin|atm ?pin)\b[^.]{0,15}\b(required|needed|to (verify|confirm|proceed|receive|claim|continue))\b",
    )], negations=_NEG),
    Rule("content.payment_request", 28, 8, 45, "Asks for a fee, payment, gift card or crypto transfer", [_c(
        r"\bpay (a |an |the )?(small |nominal |minimal |one[- ]time )?(fee|charge|charges|fine|penalty|amount|deposit|duty|tax|bill)\b",
        r"\b(customs|import|clearance|redelivery|re-delivery|processing|handling|registration|joining|training|activation|verification|release|insurance|delivery) (fee|charge|charges|duty|tax|payment)\b",
        r"\brefundable (deposit|fee)\b", r"\bgift ?cards?\b", r"\b(itunes|google play|steam|amazon) (gift )?cards?\b",
        r"\b(bitcoin|btc|usdt|ethereum|crypto(currency)?)\b[^.]{0,30}\b(pay|send|transfer|wallet|address|deposit)\b",
        r"\bwire transfer\b", r"\bwestern union\b|\bmoneygram\b", r"\bpay (via|using|through|by) (upi|phonepe|gpay|paytm|qr)\b",
        r"\bscan (the |this )?qr[- ]?code\b", r"\b(transfer|send|deposit|pay)\b[^.]{0,25}" + _MONEY,
        r"\b" + _MONEY + r"[^.]{0,30}\b(to (receive|release|claim|get|deliver|process)|is (pending|due|required))\b",
    )], needs_contact=True),
    Rule("content.lure_prize", 25, 8, 40, "Prize, reward or refund lure", [_c(
        r"\byou(['’]ve| have)? (just )?(won|been selected|been chosen)\b", r"\b(lottery|lucky (draw|winner)|jackpot|sweepstake)\b",
        r"\bclaim (your )?(prize|reward|gift|refund|cashback|bonus|winnings|inheritance)\b", r"\bcongratulations\b[^.]{0,60}\b(won|selected|chosen|eligible|winner)\b",
        r"\bfree (gift|iphone|recharge|voucher|data)\b", r"\bunclaimed (funds|money|prize|reward)\b",
        r"\b(cashback|reward points?|gift voucher)\b[^.]{0,30}\b(expir|credited|waiting|pending|claim|redeem)\w*",
        r"\b(inheritance|beneficiary of|next of kin|million dollars|\$\s?\d{1,3}(,\d{3}){2,})\b",
    )]),
    Rule("content.generic_greeting", 8, 0, 8, "Generic greeting instead of your name", [_c(
        r"^\W*(dear|hello|hi|greetings)[,]? (valued |esteemed |loyal )?(customer|user|member|client|account ?holder|sir|madam|sir/madam|beneficiary|friend|winner|applicant|email user|webmail user|subscriber|cardholder)\b",
        r"\bdear (customer|user|member|account holder|valued customer|bank customer|sir ?/ ?madam|email user)\b",
    )]),
    Rule("content.click_cta", 5, 2, 10, "Pushes you to click a link", [_c(
        r"\bclick (here|below|the link|on the link|this link)\b", r"\btap (here|the link|below)\b", r"\bvisit (the )?(link|site|website) below\b",
        r"\bfollow (the |this )?link\b", r"\bclick on (the )?(link|button)\b", r"\blink par click\b",
    )]),
    Rule("content.authority_threat", 42, 8, 58, "Claims to be police/CBI/customs/regulator threatening arrest or legal action", [
        _c(r"\b(cbi|enforcement directorate|narcotics|ncb|customs|cyber ?(crime|cell|police)|mumbai police|delhi police|police|trai|rbi|supreme court|high court|magistrate|income tax (dept|department|officer)|interpol|fbi|irs|scotland yard)\b"),
        _c(r"\b(arrest|arrested|warrant|non-?bailable|fir\b|case (has been |is )?(registered|filed)|money laundering|illegal (parcel|activities|transaction)|drugs?\b[^.]{0,30}(parcel|found|seized)|digital arrest|summons|legal action|prosecution|your aadhaar[^.]{0,40}(misused|involved|linked)|video call|skype)\b")]),
    Rule("content.enable_macros", 35, 0, 35, "Tells you to enable macros/editing to see a document", [_c(
        r"\benable (the )?(content|macros?|editing)\b", r"\bclick (the )?(enable|\"enable) (content|editing|macros?)\b")]),
    Rule("content.mailbox_lure", 35, 6, 45, "Mailbox/password-expiry lure", [_c(
        r"\b(mailbox|inbox|e-?mail (account|storage|box)|storage|quota)\s+(is |has been |has |are |now )?(almost |nearly |now )?(full|exceeded|over (its |the |your )?limit|out of space)\b",
        r"\b(your )?(email |e-?mail |office ?365 |outlook |network |windows )?password\b[^.]{0,25}\b(will |is about to |has )?(expire|expired|expires|expiring)\b",
        r"\bkeep (the )?same password\b", r"\b(incoming |pending )(e-?mails?|messages?) (are |is )?(on hold|blocked|pending|held)\b",
        r"\bmail ?(box)? (upgrade|migration|verification|deactivat)\w*",
    )]),
    Rule("content.doc_lure", 22, 8, 35, "Shared-document / voicemail / secure-message lure", [_c(
        r"\b(has )?shared (a |an |the )?(secure |important |confidential )?(document|file|folder|invoice|proposal|contract|pdf|spreadsheet|statement)\b",
        r"\byou have (a |an )?(new )?(voice ?mail|fax|encrypted message|secure message|pending (document|invoice)|incoming (document|file))\b",
        r"\b(review|view|open|access) (and sign |the )?(document|invoice|statement|payment advice|remittance|purchase order)\b[^.]{0,30}\b(here|below|online|attached)\b",
        r"\bpayment (advice|receipt|confirmation|remittance)\b[^.]{0,30}\battached\b", r"\bdocusign\b[^.]{0,30}\b(review|sign)\b",
    )]),
    Rule("content.crypto_lure", 30, 8, 45, "Crypto wallet / airdrop lure", [_c(
        r"\b(connect|verify|validate|sync|restore|import) (your )?(crypto )?wallet\b", r"\b(seed|recovery|secret recovery) phrase\b",
        r"\bairdrop\b", r"\b(metamask|trust wallet|ledger|trezor|binance|coinbase)\b[^.]{0,40}\b(suspend|verify|restrict|locked|unusual)\b")]),
    Rule("content.callback_scam", 30, 0, 30, "Pushes you to call a phone number about a charge or problem", [
        _c(r"\b(call|contact|dial|phone|reach)( us| our| the| customer)?[^.]{0,30}(support|helpline|help ?desk|toll[- ]?free|number|hotline|customer care|officer|agent|department|billing)\b",
           r"\bcall (us |now |immediately |at |on )"),
        _c(r"\b(invoice|order|purchase|subscription|renewal|payment|charged|billed|virus|infected|hacked|compromised|suspend\w*|disconnect\w*|block\w*|deactivat\w*|unauthori[sz]ed|refund|cancel|dispute|expire\w*|overdue)\b"),
        [_PHONE]]),
    Rule("content.bec", 28, 8, 40, "Business-email-compromise style request (payment change / gift cards / 'are you available')", [_c(
        r"\b(change|update|new) (of )?(my |our |the )?(bank|payment|account|salary|payroll|direct deposit) (details|account|information|instructions)\b",
        r"\bare you (available|at your desk|free)\b[^.]{0,30}\b(urgent|task|favou?r|quick)\b", r"\b(urgent|quick) (task|favou?r|request)\b[^.]{0,40}\b(gift|card|wire|transfer|payment|purchase)\b",
        r"\bkeep (this|it) (confidential|between us|discreet)\b", r"\bwire (the )?(funds|payment|money)\b")]),
    # ---- India-specific scam templates ----
    Rule("scam.in_kyc", 48, 8, 65, "India bank/wallet KYC-update scam pattern", [
        _c(r"\b(re-?kyc|e-?kyc|kyc|pan (card|number|no\.?)?|aadhaar|aadhar|केवाईसी|आधार|पैन)\b"),
        _c(r"\b(update|updat\w+|expire[sd]?|expiring|pending|incomplete|verif\w+|block\w*|suspend\w*|deactivat\w*|complete|renew\w*|not (updated|completed|linked)|failed|validity|link(ed|ing)? (your )?(aadhaar|pan)|karein|karo|करें|ब्लॉक|बंद)\b")],
        needs_contact=True),
    Rule("scam.in_upi_refund", 48, 8, 65, "UPI refund / collect-request scam pattern", [
        _c(r"\b(upi|bhim|gpay|google ?pay|phonepe|paytm|collect request|qr[- ]?code)\b"),
        _c(r"\b(refund|reversal|received (money |amount )?by mistake|wrongly (sent|transferred|credited)|(accept|approve|authori[sz]e) (the |this |your )?(collect |payment )?request|enter (your )?(upi )?pin (to|for) (receive|get|claim|accept)|scan (the |this )?qr[- ]?code to (receive|get|claim)|money (has been )?(credited|received)[^.]{0,30}(click|accept|pin)|return (the )?(money|amount)|cashback[^.]{0,30}pin)\b")]),
    Rule("scam.in_courier_fee", 38, 8, 58, "Courier / customs-fee / failed-delivery scam pattern", [
        _c(r"\b(courier|parcel|package|shipment|consignment|delivery|india post|speed ?post|dtdc|blue ?dart|delhivery|fedex|dhl|ecom express|xpressbees|customs|ups)\b"),
        _c(r"\bcustoms\b[^.]{0,30}\b(fee|duty|charge|clear\w*|hold|held|pay\w*)\b", r"\baddress (is )?(incomplete|not found|invalid|incorrect|issue|mismatch|not (found|complete))\b",
           r"\b(failed|unsuccessful|pending|held|on hold|undelivered|returned)\b[^.]{0,20}\b(delivery|attempt|parcel|package|shipment)\b",
           r"\b(re-?deliver\w*|re-?schedule|re-?attempt)\b", r"\bupdate (your )?(address|pin ?code|details|delivery)\b", r"\bunable to deliver\b",
           r"\b(pay|payment of|fee of|charge of|charges of)\b[^.]{0,12}" + _MONEY, r"\b(delivery|clearance|redelivery) (fee|charge)s?\b")], needs_contact=True),
    Rule("scam.in_electricity", 48, 8, 62, "Electricity disconnection scam pattern", [
        _c(r"\b(electricity|power (supply|connection|bill)|bijli|बिजली|discom|bescom|mseb|msedcl|tpddl|bses|tata power|adani electricity|electric (bill|connection)|meter)\b"),
        _c(r"\b(disconnect\w*|cut|terminat\w*|tonight|9[:.]?30 ?(pm)?|unpaid|last bill|bill (is |was |has )?(not|pending|overdue|unpaid)|previous bill|(not|wasn't|was not) (paid|updated)|कट|काट)\b",
           r"\b(call|contact)\b[^.]{0,30}\b(officer|helpline|number|mobile|executive|\d{10})\b", r"\bupdate (your )?(bill|details|payment)\b")]),
    Rule("scam.in_job_offer", 42, 8, 60, "Fake job / task-earning scam pattern", [
        _c(r"\b(part[- ]?time|work from home|wfh|online (job|work|task|earning)|data entry|youtube|(like|subscribe)[^.]{0,20}videos?|review (products?|tasks?|hotels?|restaurants?)|hiring|vacanc\w+|recruit\w+|job offer|hr (manager|executive|team|department)|commission|prepaid task|freelanc\w+|typing job|task[- ]based|app (download )?task)\b"),
        _c(r"\b(₹|rs\.?|inr)\s?\d[\d,]*|\b\d[\d,]{2,}\s?(/-|rs|₹|inr)\b", r"\bper (day|hour|task|video|review|week)\b", r"\bdaily (income|salary|payment|pay|earning)s?\b",
           r"\bearn (up ?to )?[^.]{0,15}\d", r"\b(salary|stipend)\b[^.]{0,20}\d"),
        _c(r"\b(telegram|whatsapp|wa\.me|t\.me)\b", r"\b(registration|joining|training|security|refundable) (fee|deposit|amount)\b", r"\bapply (now|here)\b", r"\bsend (your )?(resume|cv|details)\b", r"\bmessage (me|us|hr)\b")]),
    Rule("scam.in_tax_refund", 42, 8, 58, "Income-tax refund scam pattern", [
        _c(r"\b(income[- ]?tax|itr|tax refund|incometax|cbdt|it department)\b"),
        _c(r"\brefund\b[^.]{0,40}\b(credit\w*|approv\w*|pending|claim|click|verify|processed|eligible|rs|₹|inr)\b", r"\b(claim|verify|apply)[^.]{0,20}refund\b")]),
    Rule("scam.in_sim_telecom", 45, 8, 60, "SIM/mobile-number deactivation scam pattern", [_c(
        r"\b(sim|mobile (number|no\.?)|phone number|your number|connection)\b[^.]{0,40}\b(will be |is |has been |shall be )?(blocked|deactivated|disconnected|suspended|cancelled|terminated|barred)\b",
        r"\b(trai|dot|department of telecom\w*)\b[^.]{0,60}\b(disconnect\w*|block\w*|illegal|complaint|harass\w*|misuse\w*)\b",
        r"\b(5g|sim) (upgrade|activation|swap|kyc)\b[^.]{0,30}\b(click|link|pay|call|update|verify)\b")]),
    Rule("scam.in_fastag_challan", 42, 8, 58, "FASTag / e-challan scam pattern", [_c(
        r"\bfastag\b[^.]{0,40}\b(block\w*|deactiv\w*|kyc|suspend\w*|low balance|update|recharge|expire\w*|inactive)\b",
        r"\b(e-?challan|traffic (fine|challan|violation)|challan)\b[^.]{0,60}\b(pay|unpaid|pending|due|overdue|penalty|court|click|link)\b")], needs_contact=True),
    Rule("scam.in_loan", 28, 8, 45, "Instant-loan / loan-app lure", [
        _c(r"\b(pre-?approved|instant|quick|personal|urgent) loan\b", r"\bloan (approved|sanctioned|offer)\b"),
        _c(r"\b(₹|rs\.?|inr)\s?\d[\d,]*", r"\bno (cibil|documents?|collateral|income proof|credit check)\b", r"\b(approved|disburs\w+|credit(ed)?) (in|within) \d+ ?(min\w*|hours?)\b")]),
    Rule("scam.in_reward_points", 42, 8, 58, "Reward-points expiry scam pattern", [
        _c(r"\b(reward|credit card|loyalty|bonus|net ?banking) points?\b"),
        _c(r"\b(expir\w+|redeem\w*|lapse\w*|encash\w*|worth (rs|₹|inr))\b")], needs_contact=True),
    Rule("scam.in_investment", 38, 8, 55, "Investment-tip / guaranteed-return scam pattern", [_c(
        r"\b(guaranteed|assured) (returns?|profits?)\b", r"\bdouble (your|the) money\b", r"\b(stock|share|ipo|trading|crypto|forex|option) (tips?|signals?|calls?|group|channel|club)\b",
        r"\bsebi[- ](registered|approved)\b", r"\b(daily|weekly|monthly) (profit|returns?) of\b", r"\bvip (group|channel|membership)\b", r"\binsider (tips?|info)")]),
    Rule("scam.in_lpg_gas", 38, 8, 55, "LPG / gas-connection KYC or subsidy scam pattern", [
        _c(r"\b(lpg|gas (connection|cylinder|subsidy|booking|agency|consumer)|indane|bharat ?gas|hp ?gas)\b"),
        _c(r"\b(kyc|block\w*|discontinu\w+|cancel\w*|disconnect\w*|update|verify|subsidy|suspend\w*)\b")], needs_contact=True),
    Rule("content.tech_support", 35, 8, 50, "Fake virus/tech-support alert", [
        _c(r"\b(virus|malware|infected|trojan|hacked|compromised|security (threat|breach)|your (computer|device|pc|phone) (is|has been|may be))\b"),
        _c(r"\b(call|contact|toll[- ]?free|helpline|support)\b[^.]{0,30}\d[\d\s().-]{6,}")]),
]

_OTP_NOTICE = re.compile(r"(?i)\b(otp|one[- ]?time password|verification code|login code|security code)\b")
_DO_NOT_SHARE = re.compile(r"(?i)(do ?n[o']?t|never) (share|disclose|reveal|give)|valid for \d+|not (share|disclose)")
_TXN_ALERT = re.compile(r"(?i)\b(debited|credited|spent|withdrawn|txn|transaction)\b.{0,80}\b(a/?c|acct|account|card|upi)\b")
_TXN_BAL = re.compile(r"(?i)\b(avl|avail\w*|bal\w*|ref(erence)? ?(no|#)?)\b")


def analyze(msg: Message, ctx: Ctx, url_infos: list[dict] | None = None) -> tuple[list[Signal], dict]:
    sigs: list[Signal] = []
    facts: dict = {}
    body = _norm(msg.text)
    subj = _norm(msg.subject)
    full = (subj + ". " + body).strip() if subj else body
    low_text = full
    has_url = bool(msg.urls)
    has_phone = bool(_PHONE.search(body)) and len(re.sub(r"\D", "", body)) >= 10
    contact = has_url or has_phone
    demand_hits = 0

    for rule in RULES:
        matches = rule.run(low_text)
        if not matches:
            continue
        pts = rule.points(low_text)
        if rule.needs_contact and not contact:
            pts *= 0.5
        sigs.append(ctx.sig("content", rule.id, round(pts, 1), rule.reason + _evid(matches), "; ".join(matches)[:200]))
        if rule.id in ("content.credential_request", "content.account_threat", "content.sensitive_request",
                       "content.payment_request", "content.urgency") or rule.id.startswith("scam."):
            demand_hits += 1

    # --- HTML-only tricks (email) ---
    if msg.html:
        info = parse_html(msg.html)
        pw_forms = [f for f in info.forms if f.has_password]
        if pw_forms:
            sigs.append(ctx.sig("content", "content.password_form", 60, "The email itself contains a password entry form", pw_forms[0].action[:120]))
        elif info.forms:
            ext = [f for f in info.forms if re.match(r"(?i)https?://", f.action)]
            sensitive = [f for f in ext if any(re.search(r"(?i)card|cvv|ssn|pin|otp|passw|account|aadhaar|pan", n) for n in f.input_names)]
            if sensitive:
                sigs.append(ctx.sig("content", "content.form_sensitive", 45, "The email contains a form asking for card/account/ID details", sensitive[0].action[:120]))
            elif ext:
                sigs.append(ctx.sig("content", "content.form_in_email", 8, "The email contains a web form that submits data to an external site", ext[0].action[:120]))
        if len(info.hidden_text) > 150:
            sigs.append(ctx.sig("content", "content.hidden_text", 18, "Large block of hidden text (used to confuse spam filters)"))
        if info.img_count >= 1 and len(info.text) < 40 and msg.kind == "email":
            sigs.append(ctx.sig("content", "content.image_only", 14, "Message is essentially just an image (hides its text from filters)"))
        if info.script_count:
            sigs.append(ctx.sig("content", "content.script_in_email", 12, "The email contains script code"))
        if info.iframe_srcs:
            sigs.append(ctx.sig("content", "content.iframe_in_email", 12, "The email embeds an external page (iframe)"))
        if info.meta_refresh:
            sigs.append(ctx.sig("content", "content.meta_refresh", 25, "The email tries to redirect you automatically", info.meta_refresh[:100]))
        if info.has_data_uri_link:
            sigs.append(ctx.sig("content", "content.data_uri_link", 30, "A link carries its own page content (data: URI)"))
    mixed = _mixed_script_words(subj + " " + body[:3000])
    if len(mixed) >= 2:
        sigs.append(ctx.sig("content", "content.mixed_script_text", 40,
                            "Words mix Latin and look-alike Cyrillic/Greek letters (disguised wording to slip past filters)", ", ".join(mixed[:3])))
    if len(_ZW.findall(msg.text or "")) > 20:
        sigs.append(ctx.sig("content", "content.zero_width", 14, "Many invisible characters inserted in the text (filter evasion)"))
    if msg.kind == "email" and not msg.is_bulk and re.match(r"(?i)^\s*(re|fwd?)\s*:", msg.subject or "") and not msg.header("in-reply-to") and not msg.header("references"):
        sigs.append(ctx.sig("content", "content.fake_reply", 5, "Subject pretends to be a reply/forward but the message is not part of any conversation", msg.subject[:80]))

    # --- archive-password evasion (password given in text; attachment is an archive) ---
    if any(re.search(r"(?i)\.(zip|rar|7z|iso|img|gz)$", a.filename) for a in msg.attachments) and re.search(
            r"(?i)\b(password|pass|pwd|passcode)\s*(is|:|=|-)\s*[\w@#$!%^&*]{3,}", body):
        sigs.append(ctx.sig("content", "content.archive_password", 28, "An archive attachment comes with its password in the text (a way to slip past scanners)"))

    # --- brand impersonation: names a brand, but sender & links are not theirs ---
    brands = ctx.kb.brands_in_text(full)
    domains_present = set()
    if msg.from_addr:
        domains_present.add(registrable_domain(msg.from_addr))
    for u in msg.urls:
        p = parse_url(u.url)
        if p:
            domains_present.add(p.registrable)
    for ui in url_infos or []:
        if ui.get("final_url"):
            p = parse_url(ui["final_url"])
            if p:
                domains_present.add(p.registrable)
    spoofed: list[str] = []
    sms_brand = None
    if msg.kind == "sms" and msg.sender_id:
        m = re.match(r"^[A-Za-z]{2}-([A-Za-z0-9]{3,8})", msg.sender_id.strip())
        sms_brand = SMS_HEADERS.get((m.group(1) if m else msg.sender_id).upper())
    # In email, the brand has to be what the message is *about* (subject / sender name / opening text); a passing
    # mention deep in a newsletter or article is not impersonation.
    head_names = {b.name for b in ctx.kb.brands_in_text(" ".join([subj or "", msg.from_name or "", body[:300]]))} if msg.kind == "email" else None
    for br in brands[:3]:
        if any(br.is_official(d) or d in br.domains for d in domains_present):
            continue
        if sms_brand == br.name:
            continue
        if not contact and msg.kind != "email":
            continue
        if head_names is not None and br.name not in head_names:
            continue
        spoofed.append(br.name)
    if spoofed:
        br0 = next(b for b in brands if b.name == spoofed[0])
        strong = br0.category in ("bank", "gov", "courier", "payment", "utility", "telecom", "finance")
        if demand_hits:
            pts = 38 if strong else 28
            sigs.append(ctx.sig("content", "content.brand_impersonation", pts,
                                f"Presents itself as {spoofed[0]} and pressures you to act, but the sender/links are not {spoofed[0]}'s", spoofed[0]))
        else:
            sigs.append(ctx.sig("content", "content.brand_mention_offsite", 10,
                                f"Mentions {spoofed[0]} but nothing in it is from {spoofed[0]}'s own domains", spoofed[0]))
    facts["brands_mentioned"] = [b.name for b in brands]
    facts["spoofed_brands"] = spoofed

    # --- mitigating: ordinary transactional SMS/email ---
    if not has_url and msg.kind in ("sms", "chat", "text"):
        if _OTP_NOTICE.search(body) and _DO_NOT_SHARE.search(body):
            sigs = [s for s in sigs if s.id != "content.sensitive_request"]
            sigs.append(ctx.sig("content", "content.otp_notice", -22, "Looks like a normal one-time-code message that warns you not to share it"))
        elif _TXN_ALERT.search(body) and _TXN_BAL.search(body):
            sigs.append(ctx.sig("content", "content.txn_alert", -15, "Looks like a routine transaction alert with no links"))
    return sigs, facts


def _mixed_script_words(text: str) -> list[str]:
    """Words that combine ASCII letters with Cyrillic/Greek letters (e.g. 'раypal')."""
    out = []
    for w in re.findall(r"\w{3,}", text):
        if any(ord(c) > 127 and ("Ͱ" <= c <= "Ͽ" or "Ѐ" <= c <= "ӿ") for c in w) and any(c.isascii() and c.isalpha() for c in w):
            out.append(w)
    return out


def _evid(matches: list[str]) -> str:
    shown = [m for m in matches if not m.startswith("+")][:2]
    return f" (“{' … '.join(x[:40] for x in shown)}”)" if shown else ""
