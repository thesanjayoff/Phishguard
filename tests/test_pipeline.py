"""End-to-end behaviour of the engine: scam samples, the feedback loop, privacy gates and the container contracts."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from conftest import LEGIT_EML, PHISH_EML
from phishguard import feedback
from phishguard.llm import LlmClient
from phishguard.models import Attachment, Message
from phishguard.parsing.email_parser import from_sms, from_text, parse_email
from phishguard.redact import redact
from phishguard.sandbox.link import LinkSandbox, sanitize_link_report
from phishguard.sandbox.re_adapter import BuiltinContainerAdapter, CommandAdapter, sanitize_report
from phishguard.sandbox.runner import DockerRunner, RunResult, SandboxUnavailable, hardening_args

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ scam samples (India-specific and generic)
SCAMS = {
    "bank_kyc": ("VM-HDFCBK", "Dear Customer, your HDFC Bank account will be blocked today. Update your KYC immediately: http://hdfc-kyc-update.top/verify"),
    "upi_refund": ("AX-PAYTMB", "UPI refund of Rs 4,999 is pending. Click to claim your refund now http://upi-refund-claim.xyz/r and enter your UPI PIN"),
    "courier_fee": ("BZ-BLUEDT", "Your parcel is held at customs. Pay Rs 49 customs fee to release delivery: http://bluedart-customs-fee.top/pay"),
    "electricity": ("VK-TNEBLT", "Dear consumer, your electricity will be disconnected tonight at 9.30 pm as previous month bill was not updated. "
                                  "Call 9876543210 immediately or pay http://eb-bill-pay.link/x"),
}
LEGIT_SMS = {
    "otp": ("VM-HDFCBK", "123456 is your OTP for login. Do not share it with anyone. -HDFC Bank"),
    "shipping": ("AD-AMAZON", "Your Amazon order #123-456 has shipped and will arrive tomorrow. Track: https://www.amazon.in/gp/your-account/order-details"),
    "friend": ("+919811122233", "Hey, running 10 mins late. Shall we meet at the cafe at 6?"),
}


@pytest.mark.parametrize("name", SCAMS)
def test_indian_scam_sms_are_flagged_as_phishing(analyzer, name):
    sender, text = SCAMS[name]
    v = analyzer.analyze(from_sms(text, sender=sender), deep=False)
    assert v.label == "phishing" and v.score >= 70, (v.score, [s.id for s in v.signals])
    assert any(s.id.startswith("scam.in_") for s in v.signals)       # the India-specific rule fired, not just generic ones
    assert all(s.reason for s in v.signals if s.points > 0)         # every point has a human-readable reason


def test_fake_job_offer_is_at_least_suspicious(analyzer):
    t = ("Part time job offer! Earn Rs 5000 per day working from home. Just like YouTube videos. Contact HR on WhatsApp "
         "wa.me/919812345678 to get registered, registration fee Rs 500")
    v = analyzer.analyze(from_sms(t, sender="+919812345678"), deep=False)
    assert v.label in ("suspicious", "phishing") and any(s.id == "scam.in_job_offer" for s in v.signals)


@pytest.mark.parametrize("name", LEGIT_SMS)
def test_legitimate_sms_are_not_flagged(analyzer, name):
    sender, text = LEGIT_SMS[name]
    v = analyzer.analyze(from_sms(text, sender=sender), deep=False)
    assert v.label == "safe", (v.score, [(s.id, s.points) for s in v.signals])


def test_known_phishing_and_legit_email_fixtures(analyzer):
    bad = analyzer.analyze(parse_email(PHISH_EML), deep=False)
    good = analyzer.analyze(parse_email(LEGIT_EML), deep=False)
    assert bad.label == "phishing" and "paypal" in " ".join(bad.brands).lower()
    assert good.label == "safe" and good.score < 15
    assert {"headers", "urls"} <= set(bad.layer_scores)


def test_encoded_display_name_is_decoded_so_brand_spoofing_is_seen(analyzer):
    name = base64.b64encode(b"PayPal Security").decode()
    eml = (f"From: =?utf-8?b?{name}?= <help@secure-pay-check.example.top>\r\nTo: me@example.com\r\n"
           "Subject: =?utf-8?q?Action_required:_verify_your_account?=\r\nContent-Type: text/plain\r\n\r\nPlease sign in.\r\n")
    m = parse_email(eml)
    assert m.from_name == "PayPal Security" and m.subject == "Action required: verify your account"
    v = analyzer.analyze(m, deep=False)
    assert any("display" in s.id or "brand" in s.id for s in v.signals if s.layer == "headers")


@pytest.mark.parametrize("text", ["Your OTP is 482913", "OTP: 482913", "otp 482913.", "Your verification code was 482913", "PIN no. 4829", "use code 482913 now"])
def test_one_time_codes_never_survive_redaction(text):
    assert not re.search(r"\d{4}", redact(text)), redact(text)


# ------------------------------------------------------------------ privacy
def test_scanning_makes_no_network_calls_when_everything_external_is_off(analyzer, monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for sender, text in list(SCAMS.values()) + list(LEGIT_SMS.values()):
        analyzer.analyze(from_sms(text, sender=sender), deep=False)
    analyzer.analyze(parse_email(PHISH_EML), deep=False)


def test_llm_is_off_unless_both_switches_are_on(cfg, monkeypatch):
    sent = []
    monkeypatch.setattr(LlmClient, "_anthropic", lambda self, prompt: sent.append(prompt) or '{"probability": 0.9, "reason": "x"}')
    m = from_sms("Your OTP is 482913, mail me at a.b@example.com", sender="VM-BANK")
    for llm_on, body_on in ((False, False), (True, False), (False, True)):
        cfg.llm.enabled, cfg.privacy.send_body_to_llm = llm_on, body_on
        assert LlmClient(cfg).assess(m) is None
    assert sent == []
    cfg.llm.enabled = cfg.privacy.send_body_to_llm = True
    out = LlmClient(cfg).assess(m)
    assert out and out["probability"] == pytest.approx(0.9) and len(sent) == 1
    assert "482913" not in sent[0] and "a.b@" not in sent[0]            # even when enabled, the copy that leaves is redacted


def test_stored_snippet_and_subject_are_redacted(scanner):
    m = from_sms("Your OTP is 482913. Card 4111111111111111. Call +91 98765 43210", sender="VM-BANK")
    m.subject = "code 482913 for a.b@example.com"
    res = scanner.scan(m)
    row = scanner.store.get_message(res.message_id)
    stored = row["snippet"] + row["subject"]
    for leak in ("482913", "4111111111111111", "98765", "a.b@"):
        assert leak not in stored, stored


# ------------------------------------------------------------------ scanner: quarantine is local-first and never deletes
def test_phishing_is_quarantined_locally_and_nothing_is_deleted(scanner):
    res = scanner.scan(parse_email(PHISH_EML))
    assert res.verdict.label == "phishing" and res.quarantined
    row = scanner.store.get_message(res.message_id)
    assert row["quarantined"] == 1 and row["quarantine_note"]
    assert scanner.store.list_messages(quarantined=True)[0]["id"] == res.message_id
    good = scanner.scan(parse_email(LEGIT_EML))
    assert not good.quarantined and scanner.store.get_message(good.message_id)["quarantined"] == 0


def test_provider_quarantine_failure_does_not_lose_the_verdict(scanner):
    class Broken:
        def quarantine(self, ext):
            raise RuntimeError("provider down")

    scanner.register_source("imap", Broken())
    m = parse_email(PHISH_EML, source="imap", external_id="9")
    res = scanner.scan(m)
    assert res.quarantined and "failed" in res.quarantine_note and scanner.store.get_message(res.message_id)["label"] == "phishing"


def test_same_external_id_is_stored_once(scanner):
    a = scanner.scan(parse_email(LEGIT_EML, source="imap", external_id="1:1"))
    b = scanner.scan(parse_email(LEGIT_EML, source="imap", external_id="1:1"))
    assert a.message_id == b.message_id and len(scanner.store.list_messages()) == 1


def _code_surface(py: Path) -> tuple[set[str], set[str]]:
    """(attribute/function names used, string literals) of real code - docstrings and comments excluded."""
    import ast

    tree = ast.parse(py.read_text(encoding="utf-8"))
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body and isinstance(node.body[0], ast.Expr) \
                and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
            docs.add(id(node.body[0].value))
    names = {n.attr.lower() for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {n.id.lower() for n in ast.walk(tree) if isinstance(n, ast.Name)}
    strings = {n.value.lower() for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs}
    return names, strings


def test_mail_source_code_has_no_delete_paths():
    """Quarantine may only label or move. No delete/trash/expunge call or flag may exist anywhere in the source adapters."""
    bad_names = {"expunge", "trash", "delete", "batchdelete", "remove_message", "empty_trash", "untrash"}
    exact = {"\\deleted", "delete", "expunge", "trash", "deleteditems", "deleted items", "[gmail]/trash"}   # flags / labels / folder names
    fragments = ("/trash", "batchdelete", "permanentdelete", "/delete")                                      # API path pieces, never prose
    checked = 0
    for py in (ROOT / "src" / "phishguard" / "sources").glob("*.py"):
        names, strings = _code_surface(py)
        assert not (names & bad_names), (py.name, names & bad_names)
        for s in strings:
            assert s.strip() not in exact and not any(f in s for f in fragments), (py.name, s)
        checked += 1
    assert checked >= 3


# ------------------------------------------------------------------ feedback loop
def test_marking_phishing_teaches_about_the_sender_and_can_be_undone(analyzer, scanner):
    def sample(n):
        return parse_email(LEGIT_EML.replace(b"Lunch", b"Hello %d" % n).replace(b"<1@example.org>", b"<%d@example.org>" % n),
                           source="imap", external_id=f"1:{n}")

    first = scanner.scan(sample(1))
    assert first.verdict.label == "safe"
    assert feedback.apply_feedback(analyzer, first.message_id, "phishing")["changed"]
    nxt = analyzer.analyze(sample(2), deep=False)
    assert any(s.id == "feedback.sender_reported" for s in nxt.signals) and nxt.score > first.verdict.score
    assert feedback.apply_feedback(analyzer, first.message_id, "phishing") == {"changed": False}
    feedback.apply_feedback(analyzer, first.message_id, "safe")                                  # change of mind reverses the update
    assert not any(s.id == "feedback.sender_reported" for s in analyzer.analyze(sample(3), deep=False).signals)


def test_marking_safe_releases_quarantine_and_trusts_authenticated_sender(analyzer, scanner):
    res = scanner.scan(parse_email(PHISH_EML))
    assert res.quarantined
    feedback.apply_feedback(analyzer, res.message_id, "safe")
    row = scanner.store.get_message(res.message_id)
    assert row["quarantined"] == 0 and row["user_label"] == "safe"
    assert scanner.store.list_messages(label="safe")[0]["id"] == res.message_id        # your label wins over the automatic one
    auth = LEGIT_EML.replace(b"Message-ID", b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\nMessage-ID")
    r2 = scanner.scan(parse_email(auth, source="imap", external_id="a:1"))
    feedback.apply_feedback(analyzer, r2.message_id, "safe")
    v = analyzer.analyze(parse_email(auth.replace(b"<1@", b"<2@")), deep=False)
    assert any(s.id == "feedback.sender_trusted" and s.points < 0 for s in v.signals)


def test_feedback_never_trusts_unauthenticated_senders_by_name_alone(analyzer, scanner):
    res = scanner.scan(parse_email(PHISH_EML))
    feedback.apply_feedback(analyzer, res.message_id, "safe")
    again = analyzer.analyze(parse_email(PHISH_EML), deep=False)
    assert again.label == "phishing"        # one 'safe' click cannot launder a spoofed, failing-auth sender


def test_learned_weights_shift_gradually_and_stay_bounded(analyzer, scanner):
    ids = []
    for n in range(8):
        eml = PHISH_EML.replace(b"abc@", b"m%d@" % n)
        ids.append(scanner.scan(parse_email(eml, source="imap", external_id=f"p:{n}")).message_id)
    for mid in ids:
        feedback.apply_feedback(analyzer, mid, "phishing")
    assert analyzer.learned and all(0.4 <= w <= 1.6 for w in analyzer.learned.values())
    assert feedback.rescore_all(analyzer) >= 0


def test_feedback_input_validation(analyzer, scanner):
    with pytest.raises(ValueError):
        feedback.apply_feedback(analyzer, 1, "delete")
    with pytest.raises(KeyError):
        feedback.apply_feedback(analyzer, 424242, "safe")


# ------------------------------------------------------------------ container runner contract
def test_hardening_flags_are_always_present():
    a = hardening_args(network="none")
    joined = " ".join(a)
    for needle in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65532:65532", "--pids-limit", "--memory"):
        assert needle in joined, needle
    assert "noexec" in joined and "--privileged" not in joined and "-v " not in joined and "--mount" not in joined and "--volume" not in joined


def test_runner_refuses_instead_of_falling_back_to_the_host(cfg):
    r = DockerRunner("definitely-not-docker-xyz")
    ok, why = r.available()
    assert not ok and "install Docker" in why
    with pytest.raises(SandboxUnavailable):
        r.run("any-image", ["x"], b"data")


class FakeRunner:
    """Records how it was asked to run a container and returns canned output."""

    def __init__(self, stdout=b"", rc=0, timed_out=False, truncated=False):
        self.calls, self.out = [], RunResult(stdout, b"", rc, timed_out, truncated)

    def available(self):
        return True, "fake"

    def image_exists(self, image):
        return True

    def run(self, image, cmd, stdin=b"", **kw):
        self.calls.append({"image": image, "cmd": cmd, "stdin": stdin, **kw})
        return self.out


def test_attachment_adapter_runs_with_no_network_and_bytes_on_stdin(cfg):
    report = json.dumps({"filename": "a.bin", "behaviors": [{"id": "x", "severity": "high", "title": "t"}]}).encode()
    fr = FakeRunner(report)
    rep = BuiltinContainerAdapter(cfg, runner=fr).analyze("a.bin", b"\x00payload", ["infected"])
    call = fr.calls[0]
    assert call["network"] == "none" and call["cmd"] == ["python", "-m", "pg_re_worker"]
    head, _, body = call["stdin"].partition(b"\n")
    assert json.loads(head) == {"filename": "a.bin", "passwords": ["infected"]} and body == b"\x00payload"
    assert rep["behaviors"][0]["severity"] == "high"


def test_attachment_adapter_never_sends_oversize_files(cfg):
    cfg.attachments.max_bytes = 10
    fr = FakeRunner(b"{}")
    rep = BuiltinContainerAdapter(cfg, runner=fr).analyze("big.bin", b"x" * 11)
    assert fr.calls == [] and "too large" in rep["warnings"][0]


def test_command_adapter_wraps_an_external_tool_with_no_network(cfg):
    cfg.attachments.adapter, cfg.attachments.external_command = "command", ["mytool", "--json", "{input}"]
    fr = FakeRunner(json.dumps({"behaviors": [{"id": "t.x", "severity": "medium", "title": "found"}], "iocs": {"urls": ["http://e.example/"]}}).encode())
    rep = CommandAdapter(cfg, runner=fr).analyze("x.bin", b"data")
    assert fr.calls[0]["network"] == "none" and fr.calls[0]["cmd"][-3:] == ["mytool", "--json", "/work/sample"]
    assert rep["engine"] == "command:mytool" and rep["iocs"]["urls"] == ["http://e.example/"] and rep["behaviors"][0]["id"] == "t.x"
    fr2 = FakeRunner(b"plain text, not json")
    rep2 = CommandAdapter(cfg, runner=fr2).analyze("x.bin", b"data")
    assert rep2["behaviors"] == [] and "plain text" in rep2["raw_output"] and rep2["warnings"]


def test_sanitize_report_treats_container_output_as_hostile():
    nasty = {"filename": "x" * 5000, "size": "big", "sha256": 7, "type_mismatch": "yes", "entropy": "NaN?",
             "behaviors": [{"id": "a" * 500, "severity": "catastrophic", "title": "<script>alert(1)</script>", "snippet": "s" * 99999}, "junk", 5],
             "iocs": {"urls": ["http://a.example/" * 300] * 500, "evil_key": ["x"]}, "children": [{"filename": "c", "children": [{"children": [{"children": [{}]}]}]}],
             "unknown_field": {"__class__": 1}, "warnings": "not a list"}
    clean = sanitize_report(nasty)
    assert len(clean["filename"]) == 200 and clean["size"] == 0 and clean["sha256"] == "" and clean["entropy"] is None
    b = clean["behaviors"][0]
    assert b["severity"] == "low" and len(b["id"]) == 60 and len(b["snippet"]) == 3000 and len(clean["behaviors"]) == 1
    assert len(clean["iocs"]["urls"]) == 100 and all(len(u) <= 300 for u in clean["iocs"]["urls"]) and "evil_key" not in clean["iocs"]
    assert "unknown_field" not in clean and clean["warnings"] == []
    depth, c = 0, clean
    while c["children"]:
        c, depth = c["children"][0], depth + 1
    assert depth <= 3
    with pytest.raises(ValueError):
        sanitize_report(["not", "a", "dict"])


def test_attachment_layer_skips_gracefully_when_the_sandbox_is_missing(analyzer):
    class Missing:
        def analyze(self, *a, **k):
            raise SandboxUnavailable("docker not found")

    analyzer.re_adapter = Missing()
    m = parse_email(PHISH_EML)
    m.attachments.append(Attachment("invoice.docm", "application/octet-stream", b"PK\x03\x04 pretend"))
    v = analyzer.analyze(m, deep=True)
    assert any("Attachment analysis skipped" in n for n in v.notes)
    assert v.attachment_reports[0]["engine"] == "none" and v.label == "phishing"      # still scored from everything else


def test_attachment_findings_feed_the_score(analyzer):
    class Canned:
        def analyze(self, filename, data, passwords=()):
            return sanitize_report({"filename": filename, "file_type": "PE executable", "behaviors": [
                {"id": "pe.process_injection", "severity": "critical", "title": "Process injection imports", "snippet": "call [WriteProcessMemory]", "snippet_kind": "disasm"}]})

    analyzer.re_adapter = Canned()
    m = parse_email(LEGIT_EML)
    m.attachments.append(Attachment("report.pdf.exe", "application/octet-stream", b"MZ" + b"\0" * 100))
    v = analyzer.analyze(m, deep=True)
    assert v.label == "phishing" and any(s.id == "att.pe.process_injection" for s in v.signals)
    assert any("WriteProcessMemory" in s.evidence for s in v.signals if s.id == "att.pe.process_injection")


# ------------------------------------------------------------------ link sandbox (host side)
def link_report(**over):
    base = {"url": "http://a.example/", "final_url": "http://b.example/login", "status": 200, "title": "Sign in",
            "forms": [{"action": "http://c.example/x", "method": "post", "has_password": True, "cross_origin": True,
                       "inputs": [{"type": "password", "name": "pw"}]}], "has_login_form": True, "redirects": [{"url": "http://a.example/", "status": 302}]}
    base.update(over)
    return base


def test_sanitize_link_report_drops_non_http_urls_and_caps_everything():
    clean = sanitize_link_report(link_report(final_url="javascript:alert(1)", redirects=[{"url": "file:///etc/passwd", "status": 302}] * 50,
                                             title="t" * 9999, text_excerpt="x" * 9999, forms=[{"action": "a" * 9999}] * 50))
    assert clean["final_url"] == "" and clean["redirects"][0]["url"] == "" and len(clean["redirects"]) == 15
    assert len(clean["title"]) == 200 and len(clean["text_excerpt"]) == 600 and len(clean["forms"]) == 10
    with pytest.raises(ValueError):
        sanitize_link_report("nope")


def test_link_sandbox_browse_runs_networked_container_only_for_links_and_saves_valid_png(cfg, store):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    fr = FakeRunner(json.dumps(link_report(screenshot_b64=base64.b64encode(png).decode())).encode())
    sb = LinkSandbox(cfg, store, runner=fr)
    rep = sb.browse("http://a.example/")
    call = fr.calls[0]
    assert call["cmd"] == ["browse"] and call["network"] == "bridge" and call["image"] == cfg.sandbox.link_image
    assert json.loads(call["stdin"])["url"] == "http://a.example/"
    assert rep["screenshot"] and (cfg.path("shots") / rep["screenshot"]).read_bytes() == png
    assert "screenshot_b64" not in rep and "_shot_b64" not in rep
    sb.browse("http://a.example/")                       # second call is served from the local cache
    assert len(fr.calls) == 1


def test_link_sandbox_rejects_fake_screenshots(cfg, store):
    for bad in (base64.b64encode(b"<html>not a png</html>").decode(), "!!!not base64!!!", base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * (4 << 20)).decode()):
        fr = FakeRunner(json.dumps(link_report(screenshot_b64=bad)).encode())
        rep = LinkSandbox(cfg, None, runner=fr).browse("http://a.example/" + str(len(bad)))
        assert rep["screenshot"] is None
    assert not list((cfg.path("shots")).glob("*")) if cfg.path("shots").exists() else True


def test_link_sandbox_expand_keeps_only_http_results(cfg):
    out = {"results": {"http://s.example/a": {"final": "http://real.example/x"}, "http://s.example/b": {"final": "javascript:evil()"},
                       "http://s.example/c": {"error": "x"}}}
    fr = FakeRunner(json.dumps(out).encode())
    got = LinkSandbox(cfg, None, runner=fr).expand(list(out["results"]))
    assert got == {"http://s.example/a": "http://real.example/x", "http://s.example/b": None, "http://s.example/c": None}
    assert fr.calls[0]["cmd"] == ["expand"]


def test_link_sandbox_unavailable_means_no_browsing_on_the_host(cfg, store):
    sb = LinkSandbox(cfg, store, runner=DockerRunner("definitely-not-docker-xyz"))
    ok, why = sb.available()
    assert not ok
    with pytest.raises(SandboxUnavailable):
        sb.browse("http://a.example/")
