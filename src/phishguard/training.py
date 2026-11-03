"""Corpus loading, deterministic grouped train/test split, and classifier training."""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from .config import Config
from .layers.ml import Classifier
from .models import Message
from .parsing.email_parser import parse_email
from .synthetic import generate

log = logging.getLogger(__name__)
TEST_FRACTION = 0.30


def _group_key(msg: Message) -> str:
    """Near-duplicate campaigns share a subject: keep each group wholly in train or in test."""
    subj = re.sub(r"[^a-z]+", " ", (msg.subject or "").lower()).strip()[:60]
    return subj or hashlib.md5((msg.text or "")[:200].encode("utf-8", "ignore")).hexdigest()


def bucket(msg: Message) -> str:
    h = int(hashlib.md5(_group_key(msg).encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return "test" if h < TEST_FRACTION else "train"


UNREADABLE: list[str] = []  # corpus files the OS refused to open (reported by the evaluation)
_MBOX_SPLIT = re.compile(rb"(?m)^From [^\r\n]*\r?\n(?=[A-Za-z][A-Za-z0-9-]*:)")


def iter_mbox(path: Path):
    """Read-only mbox splitter (no locking, no writes - `mailbox.mbox` insists on lock files)."""
    try:
        data = path.read_bytes()
    except OSError as e:  # e.g. blocked by antivirus: we skip, never work around a security control
        log.warning("cannot read %s (%s) - skipped", path.name, type(e).__name__)
        UNREADABLE.append(path.name)
        return
    for chunk in _MBOX_SPLIT.split(data):
        if chunk.strip():
            yield chunk


def load_nazario(root: Path, limit: int = 0) -> list[Message]:
    out: list[Message] = []
    for f in sorted((root / "nazario").glob("*")):
        if f.suffix == ".bz2" or not f.is_file() or f.suffix == ".txt":
            continue
        for raw in iter_mbox(f):
            try:
                m = parse_email(raw, source="corpus:nazario", external_id=None)
            except Exception:
                continue
            if m.text or m.html:
                out.append(m)
            if limit and len(out) >= limit:
                return out
    return _dedupe(out)


def load_ham(root: Path, limit: int = 0) -> list[Message]:
    out: list[Message] = []
    for d in sorted((root / "spamassassin").glob("*ham*")):
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file() or f.name == "cmds":
                continue
            try:
                m = parse_email(f.read_bytes(), source="corpus:spamassassin")
            except Exception:
                continue
            if m.text or m.html:
                out.append(m)
            if limit and len(out) >= limit:
                return out
    return _dedupe(out)


def _dedupe(msgs: list[Message]) -> list[Message]:
    seen, out = set(), []
    for m in msgs:
        k = hashlib.md5(((m.subject or "") + (m.text or "")[:400]).encode("utf-8", "ignore")).hexdigest()
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


def split(msgs: list[Message]) -> tuple[list[Message], list[Message]]:
    tr, te = [], []
    for m in msgs:
        (te if bucket(m) == "test" else tr).append(m)
    return tr, te


def train_and_save(cfg: Config, corpora: Path) -> str:
    phish = load_nazario(corpora)
    ham = load_ham(corpora)
    p_tr, p_te = split(phish)
    h_tr, h_te = split(ham)
    synth = generate(n_per_family=8, variants=(0,))  # variant 0 wording only; variant 1 stays held out
    msgs = p_tr + h_tr + [s.msg for s in synth]
    labels = [1] * len(p_tr) + [0] * len(h_tr) + [s.label for s in synth]
    if not msgs or len(set(labels)) < 2:
        return "No corpora found. Run: python scripts/fetch_corpora.py"
    clf = Classifier.train(msgs, labels)
    clf.meta.update(trained_on={"nazario": len(p_tr), "ham": len(h_tr), "synthetic_variant0": len(synth)})
    clf.save(cfg.path("classifier.joblib"))
    return (f"trained on {len(p_tr)} phishing + {len(h_tr)} ham (corpora) + {len(synth)} synthetic; "
            f"held out {len(p_te)} phishing / {len(h_te)} ham. Saved {cfg.path('classifier.joblib')}")
