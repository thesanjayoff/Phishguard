"""Any mailbox over IMAP.

Reading uses a read-only SELECT and `BODY.PEEK[]`, so nothing is marked as read or changed. Optional quarantine moves
(or copies + tags) a message into a separate folder. No `\\Deleted` flag is ever set and EXPUNGE is never called."""
from __future__ import annotations

import imaplib
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from ..config import Config
from ..parsing.email_parser import parse_email
from . import Source, SourceError

log = logging.getLogger(__name__)
_BAD_FOLDER = re.compile(r'[\x00-\x1f"\\]')
MAX_MESSAGE_BYTES = 30 * 1024 * 1024


def _quote_folder(name: str) -> str:
    if _BAD_FOLDER.search(name):
        raise SourceError("folder name contains characters that are not allowed")
    return f'"{name}"'


class ImapSource(Source):
    name = "imap"

    def __init__(self, cfg: Config, connect=None):
        self.cfg = cfg
        self.c = cfg.imap
        if not self.c.host or not self.c.user:
            raise SourceError("imap.host and imap.user must be set")
        self._connect = connect or self._real_connect
        self._conn = None

    def _real_connect(self):
        pw = os.environ.get(self.c.password_env, "")
        if not pw:
            raise SourceError(f"set the mailbox (app) password in the environment variable {self.c.password_env}")
        m = imaplib.IMAP4_SSL(self.c.host, self.c.port, timeout=30)
        m.login(self.c.user, pw)
        return m

    def _open(self, readonly: bool):
        m = self._connect()
        typ, _ = m.select(_quote_folder(self.c.folder), readonly=readonly)
        if typ != "OK":
            raise SourceError(f"cannot open folder {self.c.folder!r}")
        return m

    def fetch(self, seen):
        m = self._open(readonly=True)
        try:
            typ, data = m.uid("SEARCH", None, "SINCE", (datetime.now(timezone.utc) - timedelta(days=self.c.since_days)).strftime("%d-%b-%Y"))
            if typ != "OK" or not data or not data[0]:
                return
            uids = data[0].split()[-max(self.c.max_per_run, 1):]
            validity = self._uidvalidity(m)
            for uid in reversed(uids):
                ext = f"{validity}:{uid.decode()}"
                if seen(ext):
                    continue
                typ, parts = m.uid("FETCH", uid, "(BODY.PEEK[])")
                if typ != "OK" or not parts or not isinstance(parts[0], tuple):
                    continue
                blob = parts[0][1]
                if len(blob) > MAX_MESSAGE_BYTES:
                    continue
                yield parse_email(blob, source="imap", external_id=ext)
        finally:
            try:
                m.logout()
            except Exception:
                pass

    @staticmethod
    def _uidvalidity(m) -> str:
        try:
            typ, d = m.response("UIDVALIDITY")
            if d and d[0]:
                return d[0].decode() if isinstance(d[0], bytes) else str(d[0])
        except Exception:
            pass
        return "0"

    # --- quarantine: MOVE if available, else COPY + keyword. Never delete, never expunge. ---
    def quarantine(self, external_id: str) -> str:
        if not self.c.quarantine:
            return "flagged locally (IMAP quarantine is off; enable imap.quarantine to move the message)"
        uid = external_id.split(":", 1)[-1]
        if not uid.isdigit():
            raise SourceError("bad message id")
        m = self._open(readonly=False)
        try:
            dest = _quote_folder(self.c.quarantine_folder)
            m.create(dest)  # harmless if it already exists
            caps = getattr(m, "capabilities", ()) or ()
            if "MOVE" in caps:
                typ, _ = m.uid("MOVE", uid, dest)
                if typ == "OK":
                    return f"moved to '{self.c.quarantine_folder}' (nothing deleted)"
            typ, _ = m.uid("COPY", uid, dest)
            if typ != "OK":
                raise SourceError("copy to quarantine folder failed")
            m.uid("STORE", uid, "+FLAGS", "($Phishing)")
            return f"copied to '{self.c.quarantine_folder}' and tagged $Phishing; original left in place (server has no MOVE)"
        finally:
            try:
                m.logout()
            except Exception:
                pass
