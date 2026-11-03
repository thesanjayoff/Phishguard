"""SQLite persistence. Stores *minimal* content: metadata, verdict, a short redacted snippet,
and a hashed bag-of-words vector used only to retrain the classifier from your feedback."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL, external_id TEXT, kind TEXT,
  received_at TEXT, scanned_at REAL NOT NULL,
  sender TEXT, subject TEXT, snippet TEXT,
  score INTEGER NOT NULL, label TEXT NOT NULL,
  verdict_json TEXT NOT NULL,
  quarantined INTEGER DEFAULT 0, quarantine_note TEXT DEFAULT '',
  user_label TEXT, user_label_at REAL,
  features_json TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_messages_src ON messages(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_messages_scanned ON messages(scanned_at);
CREATE TABLE IF NOT EXISTS msg_brands (message_id INTEGER, brand TEXT);
CREATE TABLE IF NOT EXISTS msg_domains (message_id INTEGER, domain TEXT);
CREATE INDEX IF NOT EXISTS ix_msg_brands ON msg_brands(brand);
CREATE INDEX IF NOT EXISTS ix_msg_domains ON msg_domains(domain);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER, label TEXT NOT NULL, at REAL NOT NULL,
  signal_ids TEXT, sender_key TEXT, features_json TEXT
);
CREATE TABLE IF NOT EXISTS signal_stats (signal_id TEXT PRIMARY KEY, phish INTEGER DEFAULT 0, safe INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sender_rep (sender_key TEXT PRIMARY KEY, phish INTEGER DEFAULT 0, safe INTEGER DEFAULT 0, updated REAL);
CREATE TABLE IF NOT EXISTS feed_urls (key TEXT PRIMARY KEY, host TEXT, source TEXT);
CREATE INDEX IF NOT EXISTS ix_feed_host ON feed_urls(host);
CREATE TABLE IF NOT EXISTS feed_meta (source TEXT PRIMARY KEY, fetched_at REAL, count INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS rdap_cache (domain TEXT PRIMARY KEY, created TEXT, fetched_at REAL, ok INTEGER);
CREATE TABLE IF NOT EXISTS link_cache (url_hash TEXT PRIMARY KEY, report_json TEXT, at REAL);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)

    # -- primitives ------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchone()

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- kv --------------------------------------------------------------
    def kv_get(self, key: str, default: str | None = None) -> str | None:
        r = self.one("SELECT v FROM kv WHERE k=?", (key,))
        return r["v"] if r else default

    def kv_set(self, key: str, value: str) -> None:
        self.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))

    # -- messages --------------------------------------------------------
    def has_message(self, source: str, external_id: str) -> bool:
        return self.one("SELECT 1 FROM messages WHERE source=? AND external_id=?", (source, external_id)) is not None

    def save_message(self, *, source: str, external_id: str | None, kind: str, received_at: str, sender: str,
                     subject: str, snippet: str, verdict: dict[str, Any], features: dict[str, int] | None) -> int:
        with self._lock:
            if external_id:
                row = self.one("SELECT id FROM messages WHERE source=? AND external_id=?", (source, external_id))
                if row:
                    return int(row["id"])
            cur = self.execute(
                "INSERT INTO messages(source,external_id,kind,received_at,scanned_at,sender,subject,snippet,score,label,"
                "verdict_json,features_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (source, external_id, kind, received_at, time.time(), sender, subject, snippet, int(verdict["score"]),
                 verdict["label"], json.dumps(verdict), json.dumps(features) if features else None),
            )
            mid = int(cur.lastrowid)
            for b in set(verdict.get("brands", [])):
                self.execute("INSERT INTO msg_brands VALUES(?,?)", (mid, b))
            for d in set(verdict.get("domains", [])):
                self.execute("INSERT INTO msg_domains VALUES(?,?)", (mid, d))
            return mid

    def get_message(self, mid: int) -> sqlite3.Row | None:
        return self.one("SELECT * FROM messages WHERE id=?", (mid,))

    def list_messages(self, label: str | None = None, source: str | None = None, limit: int = 200,
                      offset: int = 0, quarantined: bool | None = None) -> list[sqlite3.Row]:
        sql = ("SELECT id,source,kind,received_at,scanned_at,sender,subject,snippet,score,label,quarantined,user_label "
               "FROM messages")
        where, params = [], []
        if label:
            where.append("(CASE WHEN user_label='safe' THEN 'safe' WHEN user_label='phishing' THEN 'phishing' ELSE label END)=?")
            params.append(label)
        if source:
            where.append("source=?")
            params.append(source)
        if quarantined is not None:
            where.append("quarantined=?")
            params.append(1 if quarantined else 0)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY scanned_at DESC, id DESC LIMIT ? OFFSET ?"
        return self.query(sql, (*params, limit, offset))

    def set_quarantined(self, mid: int, flag: bool, note: str = "") -> None:
        self.execute("UPDATE messages SET quarantined=?, quarantine_note=? WHERE id=?", (1 if flag else 0, note, mid))


class _Tx:
    def __init__(self, store: Store):
        self.s = store

    def __enter__(self):
        self.s._lock.acquire()
        self.s._db.execute("BEGIN")
        return self.s

    def __exit__(self, et, ev, tb):
        try:
            self.s._db.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.s._lock.release()
        return False
