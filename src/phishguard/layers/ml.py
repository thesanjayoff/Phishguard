"""Trained text classifier (hashed n-grams -> TF-IDF -> logistic SGD).

* Features are hashed, so the model/feedback store holds no readable message text.
* `partial_update` lets your "mark as safe/phishing" clicks nudge the model without retraining
  from the corpora.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import SGDClassifier

from ..models import Message
from ..urlutil import parse_url

log = logging.getLogger(__name__)
N_FEATURES = 2 ** 18
MODEL_FILE = "classifier.joblib"

_DIGITS = re.compile(r"\d+")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+")


def feature_text(msg: Message) -> str:
    """Text the classifier sees. Excludes dates, hop headers and sender domain on purpose:
    corpora from different eras would otherwise teach it era artefacts instead of language."""
    body = msg.text or ""
    body = _URL.sub(" urltoken ", body)
    parts = [msg.subject or "", body]
    toks: list[str] = []
    for ref in msg.urls[:20]:
        p = parse_url(ref.url)
        if not p:
            continue
        toks.append("urlhost" if not p.is_ip else "urlip")
        toks.append(f"urltld_{p.tld}")
        toks.append(f"urldepth_{min(len(p.labels), 5)}")
        if "-" in p.registrable:
            toks.append("urlhyphen")
        toks.append(f"urlscheme_{p.scheme}")
        for w in re.split(r"[^a-z0-9]+", (p.path + " " + p.query).lower())[:12]:
            if 2 < len(w) < 15 and not w.isdigit():
                toks.append(f"urlpath_{w}")
    for a in msg.attachments:
        ext = a.filename.rsplit(".", 1)[-1].lower() if "." in a.filename else "none"
        toks.append(f"attext_{ext}")
    if msg.html and "<form" in msg.html.lower():
        toks.append("htmlform")
    text = " ".join(parts) + " " + " ".join(toks)
    return _DIGITS.sub("0", text.lower())


def _vectorizer() -> HashingVectorizer:
    return HashingVectorizer(n_features=N_FEATURES, ngram_range=(1, 2), alternate_sign=False, norm=None,
                             token_pattern=r"(?u)\b[\w']{2,}\b", lowercase=False, dtype=np.float32)


def points_from_proba(p: float) -> float:
    """Map classifier probability to signal points (negative when confident it's ham)."""
    if p >= 0.5:
        return round(80.0 * ((p - 0.5) / 0.5) ** 1.5, 1)
    return round(-12.0 * ((0.5 - p) / 0.5), 1)


class Classifier:
    def __init__(self, tfidf: TfidfTransformer, clf: SGDClassifier, meta: dict | None = None):
        self.vec = _vectorizer()
        self.tfidf = tfidf
        self.clf = clf
        self.meta = meta or {}

    # ---- features ----------------------------------------------------------
    def counts(self, msgs: Iterable[Message] | Message) -> sparse.csr_matrix:
        if isinstance(msgs, Message):
            msgs = [msgs]
        return self.vec.transform([feature_text(m) for m in msgs])

    @staticmethod
    def counts_to_json(row: sparse.csr_matrix) -> dict[str, int]:
        row = row.tocsr()
        return {str(i): int(v) for i, v in zip(row.indices, row.data)}

    @staticmethod
    def json_to_counts(d: dict[str, int]) -> sparse.csr_matrix:
        idx = np.array([int(k) for k in d], dtype=np.int64)
        val = np.array(list(d.values()), dtype=np.float32)
        return sparse.csr_matrix((val, (np.zeros(len(idx), dtype=np.int64), idx)), shape=(1, N_FEATURES))

    # ---- inference -----------------------------------------------------------
    def proba_counts(self, X: sparse.csr_matrix) -> np.ndarray:
        return self.clf.predict_proba(self.tfidf.transform(X))[:, 1]

    def proba(self, msg: Message) -> float:
        return float(self.proba_counts(self.counts(msg))[0])

    # ---- training ------------------------------------------------------------
    @classmethod
    def train(cls, msgs: list[Message], labels: list[int], sample_weight: list[float] | None = None,
              seed: int = 7) -> "Classifier":
        vec = _vectorizer()
        X = vec.transform([feature_text(m) for m in msgs])
        tfidf = TfidfTransformer(sublinear_tf=True).fit(X)
        clf = SGDClassifier(loss="log_loss", alpha=2e-5, max_iter=40, tol=None, random_state=seed,
                            class_weight="balanced")
        clf.fit(tfidf.transform(X), np.array(labels), sample_weight=sample_weight)
        return cls(tfidf, clf, {"n_train": len(labels), "n_phish": int(sum(labels))})

    def partial_update(self, counts: list[sparse.csr_matrix], labels: list[int], weight: float = 3.0) -> None:
        if not counts:
            return
        X = self.tfidf.transform(sparse.vstack(counts).tocsr())
        for _ in range(3):  # a few passes so a single click has a noticeable (but bounded) effect
            self.clf.partial_fit(X, np.array(labels), classes=np.array([0, 1]),
                                 sample_weight=np.full(len(labels), weight))
        self.meta["n_feedback"] = self.meta.get("n_feedback", 0) + len(labels)

    # ---- persistence -----------------------------------------------------------
    def save(self, path: str | Path) -> None:
        joblib.dump({"tfidf": self.tfidf, "clf": self.clf, "meta": self.meta}, path, compress=3)

    @classmethod
    def load(cls, path: str | Path) -> "Classifier | None":
        p = Path(path)
        if not p.exists():
            return None
        try:
            d = joblib.load(p)  # NOTE: joblib/pickle - only ever load models you trained yourself
            return cls(d["tfidf"], d["clf"], d.get("meta"))
        except Exception as e:
            log.warning("could not load classifier: %s", e)
            return None
