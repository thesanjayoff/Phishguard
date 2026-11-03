"""Mail sources against fakes: they must read without side effects and may only label/move - never delete."""
from __future__ import annotations

import json

import pytest

from conftest import LEGIT_EML, PHISH_EML, b64url
from phishguard.sources import SourceError, poll_sources
from phishguard.sources.gmail import GmailSource
from phishguard.sources.imap import ImapSource
from phishguard.sources.outlook import OutlookSource


# ---------------------------------------------------------------- IMAP
class FakeImap:
    def __init__(self, caps=("IMAP4rev1",)):
        self.calls: list[tuple] = []
        self.capabilities = caps
        self.mail = {b"11": PHISH_EML, b"12": LEGIT_EML}

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [b"2"]

    def response(self, name):
        return "OK", [b"777"]

    def uid(self, cmd, *args):
        self.calls.append(("uid", cmd) + args)
        if cmd == "SEARCH":
            return "OK", [b"11 12"]
        if cmd == "FETCH":
            return "OK", [(b"1 (UID x BODY[] {n}", self.mail[args[0]]), b")"]
        return "OK", [b""]

    def create(self, name):
        self.calls.append(("create", name))
        return "OK", []

    def logout(self):
        self.calls.append(("logout",))

    def expunge(self):  # must never be called
        raise AssertionError("EXPUNGE must never be used")


def _imap(cfg, fake, quarantine=False):
    cfg.imap.enabled, cfg.imap.host, cfg.imap.user, cfg.imap.quarantine = True, "imap.example.com", "me@example.com", quarantine
    return ImapSource(cfg, connect=lambda: fake)


def test_imap_fetch_is_read_only_and_peeks(cfg):
    fake = FakeImap()
    msgs = list(_imap(cfg, fake).fetch(lambda ext: False))
    assert len(msgs) == 2
    assert ("select", '"INBOX"', True) in fake.calls  # read-only SELECT
    fetches = [c for c in fake.calls if c[:2] == ("uid", "FETCH")]
    assert fetches and all(c[3] == "(BODY.PEEK[])" for c in fetches)
    assert {m.external_id for m in msgs} == {"777:11", "777:12"}
    assert not any(c[:2] == ("uid", "STORE") for c in fake.calls)


def test_imap_skips_seen_messages_before_downloading(cfg):
    fake = FakeImap()
    msgs = list(_imap(cfg, fake).fetch(lambda ext: ext.endswith(":11")))
    assert [m.external_id for m in msgs] == ["777:12"]
    assert sum(1 for c in fake.calls if c[:2] == ("uid", "FETCH")) == 1


def test_imap_quarantine_uses_move_when_supported(cfg):
    fake = FakeImap(caps=("IMAP4rev1", "MOVE"))
    note = _imap(cfg, fake, quarantine=True).quarantine("777:11")
    assert "moved" in note
    assert ("uid", "MOVE", "11", '"PhishGuard-Quarantine"') in fake.calls
    assert ("select", '"INBOX"', False) in fake.calls


def test_imap_quarantine_fallback_copies_and_tags_without_deleting(cfg):
    fake = FakeImap()
    note = _imap(cfg, fake, quarantine=True).quarantine("777:11")
    assert "copied" in note
    flat = json.dumps([list(map(str, c)) for c in fake.calls])
    assert "Deleted" not in flat and "EXPUNGE" not in flat.upper()
    assert ("uid", "STORE", "11", "+FLAGS", "($Phishing)") in fake.calls


def test_imap_quarantine_off_does_not_touch_server(cfg):
    fake = FakeImap()
    note = _imap(cfg, fake, quarantine=False).quarantine("777:11")
    assert "locally" in note and fake.calls == []


def test_imap_rejects_hostile_folder_and_uid(cfg):
    fake = FakeImap()
    cfg.imap.folder = 'INBOX" ; evil'
    src = _imap(cfg, fake)
    with pytest.raises(SourceError):
        list(src.fetch(lambda e: False))
    cfg.imap.folder = "INBOX"
    cfg.imap.quarantine = True
    with pytest.raises(SourceError):
        src.quarantine("777:11; DELETE")


def test_imap_requires_host(cfg):
    with pytest.raises(SourceError):
        ImapSource(cfg)


# ---------------------------------------------------------------- Gmail
class Resp:
    def __init__(self, data=None, status=200, content=b""):
        self._d, self.status_code, self.content = data, status, content

    def json(self):
        return self._d


class FakeGmail:
    def __init__(self):
        self.requests: list[tuple[str, str, object]] = []
        self.labels = []

    def get(self, url, params=None, timeout=None):
        self.requests.append(("GET", url, params))
        if url.endswith("/messages"):
            return Resp({"messages": [{"id": "m1"}, {"id": "m2"}]})
        if url.endswith("/labels"):
            return Resp({"labels": self.labels})
        mid = url.rsplit("/", 1)[-1]
        eml = PHISH_EML if mid == "m1" else LEGIT_EML
        return Resp({"raw": b64url(eml), "internalDate": "1762164000000"})

    def post(self, url, json=None, timeout=None):
        self.requests.append(("POST", url, json))
        if url.endswith("/labels"):
            self.labels.append({"id": "L1", "name": json["name"]})
            return Resp({"id": "L1"})
        return Resp({})


def test_gmail_fetch_decodes_raw_and_skips_seen(cfg):
    s = FakeGmail()
    msgs = list(GmailSource(cfg, session=s).fetch(lambda ext: ext == "m2"))
    assert [m.external_id for m in msgs] == ["m1"]
    assert msgs[0].source == "gmail" and "paypa1-secure-login.top" in msgs[0].from_addr
    assert msgs[0].received_at.year == 2025
    assert all(m == "GET" for m, _, _ in s.requests)  # reading never writes


def test_gmail_default_scope_is_readonly(cfg):
    from phishguard.sources.gmail import scopes_for

    assert scopes_for(cfg) == ["https://www.googleapis.com/auth/gmail.readonly"]
    cfg.gmail.quarantine = True
    assert scopes_for(cfg) == ["https://www.googleapis.com/auth/gmail.modify"]


def test_gmail_quarantine_only_adds_a_label(cfg):
    cfg.gmail.quarantine = True
    s = FakeGmail()
    note = GmailSource(cfg, session=s).quarantine("m1")
    assert "nothing deleted" in note
    posts = [(u, b) for m, u, b in s.requests if m == "POST"]
    assert posts[-1][0].endswith("/messages/m1/modify") and posts[-1][1] == {"addLabelIds": ["L1"]}
    assert not any(w in u.lower() for _, u, _ in s.requests for w in ("trash", "delete", "batchdelete"))


def test_gmail_quarantine_disabled_makes_no_calls(cfg):
    s = FakeGmail()
    assert "locally" in GmailSource(cfg, session=s).quarantine("m1")
    assert s.requests == []


# ---------------------------------------------------------------- Outlook / Graph
class FakeGraph:
    def __init__(self):
        self.requests: list[tuple[str, str, object]] = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.requests.append(("GET", url, params))
        assert headers["Authorization"] == "Bearer tok"
        if url.endswith("/inbox/messages"):
            return Resp({"value": [{"id": "A/1=", "receivedDateTime": "2025-11-03T10:00:00Z"}]})
        if url.endswith("/mailFolders"):
            return Resp({"value": []})
        if url.endswith("/$value"):
            return Resp(content=PHISH_EML)
        raise AssertionError(url)

    def post(self, url, headers=None, json=None, timeout=None):
        self.requests.append(("POST", url, json))
        if url.endswith("/mailFolders"):
            return Resp({"id": "F1"})
        return Resp({})


def test_outlook_fetch_and_url_quoting(cfg):
    g = FakeGraph()
    msgs = list(OutlookSource(cfg, session=g, token_fn=lambda: "tok").fetch(lambda e: False))
    assert len(msgs) == 1 and msgs[0].source == "outlook" and msgs[0].received_at.year == 2025
    assert any("/messages/A%2F1%3D/$value" in u for _, u, _ in g.requests)  # ids are percent-encoded


def test_outlook_scopes_and_move_only(cfg):
    from phishguard.sources.outlook import scopes_for

    assert scopes_for(cfg) == ["Mail.Read"]
    cfg.outlook.quarantine = True
    assert scopes_for(cfg) == ["Mail.ReadWrite"]
    g = FakeGraph()
    note = OutlookSource(cfg, session=g, token_fn=lambda: "tok").quarantine("A/1=")
    assert "nothing deleted" in note
    posts = [(u, b) for m, u, b in g.requests if m == "POST"]
    assert posts[-1][0].endswith("/move") and posts[-1][1] == {"destinationId": "F1"}
    assert not any("delete" in u.lower() for _, u, _ in g.requests)


# ---------------------------------------------------------------- polling / scanning integration
def test_poll_scans_dedupes_and_quarantines_locally(cfg, scanner, monkeypatch):
    fake = FakeImap()
    cfg.imap.enabled, cfg.imap.host, cfg.imap.user = True, "h", "u"
    monkeypatch.setattr("phishguard.sources.imap.ImapSource._real_connect", lambda self: fake)
    first = list(poll_sources(cfg, scanner, ["imap"]))
    assert any("2 new message" in l for l in first)
    assert any("PHISHING" in l and "[quarantined]" in l for l in first)
    assert any("SAFE" in l for l in first)
    again = list(poll_sources(cfg, scanner, ["imap"]))
    assert any("0 new message" in l for l in again)  # already scanned: not re-downloaded or re-scored
    rows = scanner.store.list_messages(label="phishing")
    assert len(rows) == 1 and rows[0]["quarantined"]


def test_poll_reports_when_nothing_enabled(cfg, scanner):
    assert any("no sources enabled" in l for l in poll_sources(cfg, scanner, None))
