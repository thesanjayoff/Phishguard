"""Learning from 'Mark as safe / phishing' clicks. Three mechanisms, all local:

1. Signal weights   - each signal id keeps counts of firing on messages you called phishing vs safe;
                      a smoothed likelihood ratio becomes a bounded multiplier (0.4x .. 1.6x).
2. Sender reputation - authenticated senders you marked safe get a mitigation; reported ones get a penalty.
3. Classifier        - the stored hashed feature vector is used to nudge the text classifier (partial_fit).
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING

from .models import Message, Signal
from .scoring import combine, summarize
from .store import Store

if TYPE_CHECKING:  # pragma: no cover
    from .ctx import Ctx
    from .pipeline import Analyzer

log = logging.getLogger(__name__)
MIN_OBS = 3


def sender_key(msg: Message) -> str:
    if msg.kind == "email" and msg.from_addr:
        return "email:" + msg.from_addr.lower()
    if msg.kind == "sms" and msg.sender_id:
        sid = msg.sender_id.strip().upper()
        m = re.match(r"^[A-Z]{2}-([A-Z0-9]{3,8})", sid)
        return "sms:" + (m.group(1) if m else sid)
    return ""


def auth_ok(msg: Message) -> bool:
    from .layers.headers import parse_auth

    if msg.kind != "email":
        return False
    a = parse_auth(msg)
    return a.get("dmarc") == "pass" or (a.get("spf") == "pass" and a.get("dkim") == "pass")


def _rep(store: Store, key: str):
    return store.one("SELECT phish, safe FROM sender_rep WHERE sender_key=?", (key,)) if key else None


def sender_signals(store: Store, msg: Message, ctx: "Ctx") -> list[Signal]:
    key = sender_key(msg)
    row = _rep(store, key)
    if not row:
        return []
    if row["phish"] > 0 and row["phish"] >= row["safe"]:
        return [ctx.sig("feedback", "feedback.sender_reported", 50, "You previously reported mail from this sender as phishing", key)]
    if row["safe"] > 0 and row["phish"] == 0:
        if msg.kind == "email" and auth_ok(msg):
            return [ctx.sig("feedback", "feedback.sender_trusted", -25, "You marked this authenticated sender as safe before", key)]
        if msg.kind == "sms":
            return [ctx.sig("feedback", "feedback.sender_trusted", -8, "You marked messages from this sender ID as safe before", key)]
    return []


def learned_weights(store: Store) -> dict[str, float]:
    tot = {r["label"]: r["n"] for r in store.query("SELECT label, COUNT(*) n FROM feedback GROUP BY label")}
    P, S = tot.get("phishing", 0), tot.get("safe", 0)
    if P + S < MIN_OBS:
        return {}
    out: dict[str, float] = {}
    for r in store.query("SELECT signal_id, phish, safe FROM signal_stats"):
        if r["phish"] + r["safe"] < MIN_OBS:
            continue
        lr = ((r["phish"] + 1) / (P + 2)) / ((r["safe"] + 1) / (S + 2))
        out[r["signal_id"]] = round(min(1.6, max(0.4, lr ** 0.5)), 3)
    return out


def _bump(store: Store, mid_signals: list[str], label: str, delta: int) -> None:
    col = "phish" if label == "phishing" else "safe"
    for sid in set(mid_signals):
        store.execute("INSERT INTO signal_stats(signal_id, phish, safe) VALUES(?,0,0) ON CONFLICT(signal_id) DO NOTHING", (sid,))
        store.execute(f"UPDATE signal_stats SET {col}=MAX(0, {col}+?) WHERE signal_id=?", (delta, sid))


def apply_feedback(analyzer: "Analyzer", message_id: int, label: str) -> dict:
    """label: 'safe' | 'phishing'. Idempotent: changing your mind reverses the earlier update."""
    if label not in ("safe", "phishing"):
        raise ValueError("label must be 'safe' or 'phishing'")
    store = analyzer.store
    row = store.get_message(message_id)
    if row is None:
        raise KeyError(message_id)
    verdict = json.loads(row["verdict_json"])
    fired = [s["id"] for s in verdict["signals"] if s["points"] > 0 and not s["id"].startswith("feedback.")]
    skey = (verdict.get("facts") or {}).get("sender_key", "")
    prev = row["user_label"]
    with store.transaction():
        if prev == label:
            return {"changed": False}
        if prev:
            _bump(store, fired, prev, -1)
            if skey:
                store.execute(f"UPDATE sender_rep SET {'phish' if prev == 'phishing' else 'safe'}=MAX(0,{'phish' if prev == 'phishing' else 'safe'}-1) WHERE sender_key=?", (skey,))
            store.execute("DELETE FROM feedback WHERE message_id=?", (message_id,))
        _bump(store, fired, label, +1)
        if skey:
            store.execute("INSERT INTO sender_rep(sender_key, phish, safe, updated) VALUES(?,0,0,?) ON CONFLICT(sender_key) DO NOTHING", (skey, time.time()))
            col = "phish" if label == "phishing" else "safe"
            store.execute(f"UPDATE sender_rep SET {col}={col}+1, updated=? WHERE sender_key=?", (time.time(), skey))
        store.execute("INSERT INTO feedback(message_id,label,at,signal_ids,sender_key,features_json) VALUES(?,?,?,?,?,?)",
                      (message_id, label, time.time(), json.dumps(fired), skey, row["features_json"]))
        store.execute("UPDATE messages SET user_label=?, user_label_at=? WHERE id=?", (label, time.time(), message_id))
        if label == "safe":
            store.execute("UPDATE messages SET quarantined=0, quarantine_note='released by you' WHERE id=?", (message_id,))
    _update_classifier(analyzer, row, label, undo=prev)
    analyzer.reload_learning()
    return {"changed": True, "previous": prev, "weights": len(analyzer.learned)}


def _update_classifier(analyzer: "Analyzer", row, label: str, undo: str | None) -> None:
    clf = analyzer.classifier
    if clf is None or not row["features_json"]:
        return
    try:
        from .layers.ml import Classifier

        X = Classifier.json_to_counts({k: int(v) for k, v in json.loads(row["features_json"]).items()})
        y = 1 if label == "phishing" else 0
        clf.partial_update([X], [y], weight=3.0)
        clf.save(analyzer.cfg.path("classifier.joblib"))
    except Exception as e:  # pragma: no cover
        log.warning("classifier update failed: %s", e)


def rescore_all(analyzer: "Analyzer") -> int:
    """Re-combine stored signals with the current learned weights (no re-fetching, no re-scanning)."""
    store, n = analyzer.store, 0
    th = analyzer.cfg.thresholds
    for r in store.query("SELECT id, verdict_json FROM messages"):
        v = json.loads(r["verdict_json"])
        sigs = [Signal(**s) for s in v["signals"]]
        score, label, layers = combine(sigs, th.suspicious, th.phishing, analyzer.learned)
        if score != v["score"] or label != v["label"]:
            v.update(score=score, label=label, layer_scores=layers, summary=summarize(sigs, label, score, analyzer.learned))
            store.execute("UPDATE messages SET score=?, label=?, verdict_json=? WHERE id=?", (score, label, json.dumps(v), r["id"]))
            n += 1
    return n
