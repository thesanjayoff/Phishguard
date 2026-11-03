"""Unit tests for the detection building blocks (no network, no containers)."""
from __future__ import annotations

import pytest

from phishguard import redact as R
from phishguard.layers import headers as headers_layer
from phishguard.lookalike import brand_findings, edit_distance, looks_generated, skeleton
from phishguard.models import Message, Signal
from phishguard.parsing.email_parser import from_sms, from_text, parse_email
from phishguard.scoring import MAX_MITIGATION, combine, effective_points, noisy_or
from phishguard.urlutil import defang, defang_text, extract_urls, parse_url, refang, registrable_domain


# ------------------------------------------------------------------ URL parsing
def test_parse_url_splits_registrable_domain_correctly():
    p = parse_url("http://paypal.com.evil-site.top/login?x=1")
    assert p.registrable == "evil-site.top" and p.subdomain == "paypal.com" and p.tld == "top"
    assert parse_url("https://www.shop.co.uk/a").registrable == "shop.co.uk"
    assert parse_url("www.example.com/path").scheme == "http" and not parse_url("www.example.com/path").explicit_scheme


@pytest.mark.parametrize("raw,ip", [("http://192.168.0.1/login", "192.168.0.1"), ("http://2130706433/", "127.0.0.1"),
                                    ("http://0x7f.0.0.1/", "127.0.0.1"), ("http://[2001:db8::1]/x", "2001:db8::1")])
def test_ip_hosts_including_obfuscated_spellings(raw, ip):
    p = parse_url(raw)
    assert p.is_ip and p.ip == ip


def test_idn_and_userinfo_tricks():
    assert parse_url("http://xn--pple-43d.com/").is_idn
    p = parse_url("http://www.paypal.com@evil.example.top/signin")
    assert p.userinfo == "www.paypal.com" and p.registrable == "example.top"
    assert parse_url("http://") is None and parse_url("http://[bad") is None


def test_extract_urls_finds_links_and_skips_look_alike_noise():
    text = "Visit http://a.example.com/x?y=1, or www.b-example.org/path. See report.pdf and version 1.2.3 (sign in at c-example.co.in/login)."
    urls = extract_urls(text)
    assert "http://a.example.com/x?y=1" in urls and "www.b-example.org/path" in urls and "c-example.co.in/login" in urls
    assert not any(u.startswith("report.pdf") or u == "1.2.3" for u in urls)
    assert extract_urls("see http://x.example.com/a http://x.example.com/a") == ["http://x.example.com/a"]


def test_defang_is_idempotent_and_reversible():
    u = "http://evil.example.com/a.b?c=d.e"
    d = defang(u)
    assert d == "hxxp://evil[.]example[.]com/a.b?c=d.e" and defang(d) == d
    assert refang(d) == u
    assert "http://" not in defang_text("click http://bad.example.net/x now") and "[.]" in defang_text("click http://bad.example.net/x now")
    assert registrable_domain("someone@mail.example.co.uk") == "example.co.uk"


# ------------------------------------------------------------------ lookalike domains
def kinds(host: str) -> set[str]:
    p = parse_url("http://" + host + "/")
    return {f.kind for f in brand_findings(p)}


def test_skeleton_and_edit_distance():
    assert skeleton("paypa1") == skeleton("paypal") and skeleton("rnicrosoft") == skeleton("microsoft")
    assert edit_distance("paypal", "paypa1", 2) == 1 and edit_distance("abc", "xyz", 2) > 2


@pytest.mark.parametrize("host,expected", [
    ("paypa1.com", "typosquat"), ("paypal-secure-login.com", "combosquat"), ("paypal.com.evil-site.top", "brand-subdomain"),
    ("secure.paypal.verify-account.xyz", "brand-subdomain"), ("xn--pple-43d.com", "homograph"), ("arnazon.com", "typosquat"),
    ("micros0ft-support.com", "combosquat"),
])
def test_brand_impersonation_is_found(host, expected):
    assert expected in kinds(host), kinds(host)


LEGIT_DOMAINS = [
    "google.com", "mail.google.com", "accounts.google.com", "apple.com", "support.apple.com", "icloud.com", "amazon.com", "amazon.in",
    "amazon.co.uk", "microsoft.com", "login.microsoftonline.com", "outlook.live.com", "office.com", "github.com", "paypal.com", "www.paypal.com",
    "netflix.com", "linkedin.com", "facebook.com", "dropbox.com", "zoom.us", "slack.com", "stackoverflow.com", "wikipedia.org", "python.org",
    "example.com", "nytimes.com", "bbc.co.uk", "cloudflare.com", "dhl.com", "fedex.com", "ups.com", "hdfcbank.com", "netbanking.hdfcbank.com",
    "onlinesbi.sbi", "sbi.co.in", "icicibank.com", "axisbank.com", "irctc.co.in", "flipkart.com", "swiggy.com", "zomato.com", "phonepe.com",
    "paytm.com", "npci.org.in", "incometax.gov.in", "uidai.gov.in", "bluedart.com", "indiapost.gov.in", "kotak.com", "pnbindia.in",
    "jio.com", "airtel.in", "hotstar.com", "myntra.com", "makemytrip.com", "coursera.org", "medium.com", "reddit.com", "twitter.com", "x.com",
    "openai.com", "anthropic.com", "mozilla.org", "adobe.com", "intuit.com", "docusign.com", "stripe.com", "shopify.com", "walmart.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citi.com", "usps.com", "irs.gov", "gov.uk", "nhs.uk", "steampowered.com", "spotify.com",
    "outlook.com", "live.com", "yahoo.com", "protonmail.com", "gmail.com",
]


@pytest.mark.parametrize("host", LEGIT_DOMAINS)
def test_legitimate_domains_are_not_flagged_as_impersonation(host):
    assert not brand_findings(parse_url("https://" + host + "/")), (host, brand_findings(parse_url("https://" + host + "/")))


def test_generated_looking_labels():
    assert looks_generated("xk3j9fq2lzp8vw") and not looks_generated("amazon")


# ------------------------------------------------------------------ redaction (privacy)
def test_redact_removes_personal_data_but_keeps_shape():
    t = ("Dear Ravi, OTP is 482913. Call +91 98765 43210 or mail ravi.k@example.com. Card 4111111111111111. "
         "Visit http://pay.example.net/verify?token=abc123 password: hunter2hunter2 key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    out = R.redact(t)
    for leak in ("482913", "98765", "ravi.k", "4111111111111111", "token=abc123", "hunter2", "AAAAAAAAAAAAAAAAAAAA"):
        assert leak not in out, (leak, out)
    assert "example.com" in out and "pay.example.net" in out        # domains stay: they are what the detector needs
    assert "example" not in R.redact(t, keep_domains=False)


def test_logging_filter_redacts_records(caplog):
    import logging

    log = logging.getLogger("pg-test")
    log.addFilter(R.RedactingFilter())
    with caplog.at_level(logging.INFO, logger="pg-test"):
        log.info("failed for someone@example.org code 123456")
    assert "someone@" not in caplog.text and "123456" not in caplog.text


# ------------------------------------------------------------------ scoring
def sig(layer, id_, pts):
    return Signal(layer=layer, id=id_, points=pts, reason=id_)


def test_noisy_or_adds_independent_evidence_but_never_exceeds_100():
    assert noisy_or([]) == 0 and round(noisy_or([50])) == 50
    assert round(noisy_or([50, 50])) == 75 and noisy_or([100, 100]) == 100 and noisy_or([-5, 0]) == 0


def test_combine_thresholds_and_mitigation_cap():
    s, label, layers = combine([sig("urls", "a", 40)], suspicious=35, phishing=70)
    assert (s, label) == (40, "suspicious") and layers["urls"] == 40
    s, label, _ = combine([sig("urls", "a", 60), sig("headers", "b", 60)], 35, 70)
    assert s == 84 and label == "phishing"
    s, label, _ = combine([sig("urls", "a", 50), sig("headers", "ok", -500)], 35, 70)
    assert s == 50 - MAX_MITIGATION + 0 or s == round(50 - MAX_MITIGATION)   # the cap stops legitimacy clues erasing real evidence
    assert combine([], 35, 70)[:2] == (0, "safe")


def test_learned_multipliers_are_bounded():
    s = sig("urls", "x", 50)
    assert effective_points(s, {"x": 100.0}) == pytest.approx(80.0)    # capped at 1.6x
    assert effective_points(s, {"x": 0.0}) == pytest.approx(20.0)      # floored at 0.4x
    assert effective_points(sig("urls", "y", -10), {"y": 5}) == -10     # mitigations are never amplified


# ------------------------------------------------------------------ parsing
RAW = (b"From: \"Acme Billing\" <billing@acme.example>\r\nReply-To: other@evil.example\r\nReturn-Path: <bounce@mailer.example>\r\n"
       b"To: me@example.com\r\nSubject: =?utf-8?q?Your_invoice?=\r\nMessage-ID: <1@acme.example>\r\nMIME-Version: 1.0\r\n"
       b"Content-Type: multipart/alternative; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlain body http://plain.example.com/a\r\n"
       b"--BB\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><a href=\"http://real-target.example.net/x\">http://shown.example.org/y</a>"
       b"<form action=\"http://post.example.top/\"><input type=password name=p></form></body></html>\r\n--BB--\r\n")


def test_parse_email_extracts_envelope_text_html_and_links():
    m = parse_email(RAW)
    assert m.subject == "Your invoice" and m.from_addr == "billing@acme.example" and m.from_name == "Acme Billing"
    assert m.reply_to.endswith("evil.example") and "bounce@mailer.example" in m.return_path
    urls = {u.url: u for u in m.urls}
    assert "http://real-target.example.net/x" in urls and urls["http://real-target.example.net/x"].text.startswith("http://shown")
    assert any(u.origin == "form" for u in m.urls)


def test_parse_email_survives_garbage_and_bad_charsets():
    for blob in (b"", b"\x00\xff\xfe garbage", b"Subject: =?bogus-charset?q?abc?=\r\n\r\nbody", "naïve text".encode("latin-1")):
        m = parse_email(blob)
        assert isinstance(m.text, str)


def test_from_text_classifies_pasted_input():
    assert from_text("http://x.example.com/a").kind == "url"
    assert from_text("hey, are we on for lunch?").kind == "chat"
    assert from_text(RAW.decode()).kind == "email"
    sms = from_sms("Your a/c is blocked, visit http://bit.example/kyc now", sender="VM-HDFCBK")
    assert sms.kind == "sms" and sms.sender_id == "VM-HDFCBK" and sms.urls


# ------------------------------------------------------------------ headers layer
def msg_with(**kw) -> Message:
    base = dict(kind="email", from_addr="alerts@brand-mail.example", from_name="", text="hello")
    base.update(kw)
    return Message(**base)


def ids_of(sigs):
    return {s.id for s in sigs}


@pytest.fixture()
def ctx(analyzer):
    from phishguard.ctx import Ctx

    return Ctx(cfg=analyzer.cfg, store=analyzer.store, intel=analyzer.intel, weights=analyzer.learned)


def test_authentication_failures_are_flagged(ctx):
    m = msg_with(headers={"authentication-results": ["mx.example; spf=fail smtp.mailfrom=x.example; dkim=fail; dmarc=fail"]})
    sigs, _ = headers_layer.analyze(m, ctx)
    assert any("spf" in i or "dmarc" in i or "dkim" in i for i in ids_of(sigs))
    ok = msg_with(headers={"authentication-results": ["mx.example; spf=pass; dkim=pass; dmarc=pass"]})
    assert headers_layer.parse_auth(ok)["dmarc"] == "pass"


def test_reply_to_mismatch_is_weak_and_suppressed_for_bulk_mail(ctx):
    plain = msg_with(from_addr="news@shop.example", reply_to="x@other-domain.example")
    bulk = msg_with(from_addr="news@shop.example", reply_to="x@other-domain.example", headers={"list-unsubscribe": ["<mailto:u@shop.example>"]})
    assert any("reply" in i for i in ids_of(headers_layer.analyze(plain, ctx)[0]))
    assert not any("reply" in i for i in ids_of(headers_layer.analyze(bulk, ctx)[0]))
    assert bulk.is_bulk and not plain.is_bulk


def test_bulk_headers_never_hide_brand_spoofing_or_auth_failures(ctx):
    m = msg_with(from_name="PayPal Security", from_addr="service@random-mailer.example",
                 headers={"list-id": ["<x.list>"], "authentication-results": ["mx; spf=fail; dkim=fail; dmarc=fail"]})
    got = ids_of(headers_layer.analyze(m, ctx)[0])
    assert any("display" in i or "brand" in i for i in got) and any("dmarc" in i or "spf" in i for i in got)


def test_display_name_brand_spoof_but_not_for_the_real_brand(ctx):
    spoof = msg_with(from_name="PayPal Support", from_addr="help@secure-pay.example.top")
    real = msg_with(from_name="PayPal", from_addr="service@paypal.com")
    assert any("display" in i or "brand" in i for i in ids_of(headers_layer.analyze(spoof, ctx)[0]))
    assert not any("display" in i or "brand" in i for i in ids_of(headers_layer.analyze(real, ctx)[0]))
    assert headers_layer.display_name_typo("HDFC Bank", ctx) is None   # a real brand name is not a typo of a similar brand
