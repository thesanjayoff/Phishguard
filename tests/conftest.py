from __future__ import annotations

import base64
import logging

import pytest

from phishguard.config import Config
from phishguard.intel import Intel
from phishguard.pipeline import Analyzer
from phishguard.service import Scanner
from phishguard.store import Store

logging.disable(logging.WARNING)

PHISH_EML = (
    b"From: \"PayPal Security\" <service@paypa1-secure-login.top>\r\n"
    b"To: victim@example.com\r\nSubject: Urgent: your account will be suspended\r\n"
    b"Date: Mon, 03 Nov 2025 10:00:00 +0000\r\nMessage-ID: <abc@paypa1-secure-login.top>\r\n"
    b"Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-secure-login.top; dkim=none; dmarc=fail\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Dear Customer, we detected unusual activity. Verify your password immediately or your account will be "
    b"suspended within 24 hours: http://paypa1-secure-login.top/signin?id=1\r\n"
)
LEGIT_EML = (
    b"From: Alice <alice@example.org>\r\nTo: me@example.com\r\nSubject: Lunch on Thursday?\r\n"
    b"Date: Mon, 03 Nov 2025 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nHi, are we still on for lunch on Thursday at 1pm? Alice\r\n"
)


@pytest.fixture()
def cfg(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("PHISHGUARD_HOME", str(tmp_path / "home"))
    c = Config()
    c.sandbox.enabled = False  # unit tests never need Docker
    c.intel.rdap = False
    c.intel.use_openphish = False
    c.intel.use_phishtank = False
    return c


@pytest.fixture()
def store(cfg) -> Store:
    return Store(cfg.path("t.db"))


@pytest.fixture()
def analyzer(cfg, store) -> Analyzer:
    return Analyzer(cfg=cfg, store=store, intel=Intel.offline(store), use_ml=False, use_feedback=True)


@pytest.fixture()
def scanner(analyzer) -> Scanner:
    return Scanner(analyzer)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")
