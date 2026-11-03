"""Local web UI + HTTP API.

Threat model: a personal tool on your own machine. It binds to 127.0.0.1 by default and defends against the two
ways a *website you visit* could reach it: DNS rebinding (Host allow-list) and cross-site requests (Origin /
Sec-Fetch-Site checks plus a per-process CSRF header that only pages served by this app know). Scripts and the
Android companion authenticate with the bearer token in <data_dir>/token. There is no endpoint that deletes mail.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Config
from ..feedback import apply_feedback, rescore_all
from ..models import Message
from ..parsing.email_parser import from_sms, from_text
from ..pipeline import Analyzer
from ..service import Scanner
from ..sources import SOURCE_NAMES, poll_sources
from ..urlutil import defang, defang_text

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "[::1]", "::1"}
MAX_BODY = 4 * 1024 * 1024
SHOT_RE = re.compile(r"^[0-9a-f]{24}\.png$")
PER_PAGE = 50
LAYER_TITLES = {"headers": "Sender & headers", "urls": "Links", "content": "Wording", "behavior": "Link behaviour (sandbox)",
                "attachments": "Attachments", "feedback": "Your feedback"}
EFFECTIVE_LABEL = "(CASE WHEN user_label IN ('safe','phishing') THEN user_label ELSE label END)"


# ------------------------------------------------------------------------------------------------ models
class CheckIn(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    kind: Literal["auto", "email", "sms", "chat", "url", "text"] = "auto"
    sender: str = Field(default="", max_length=200)
    save: bool = True
    deep: bool = True


class SmsIn(BaseModel):
    sender: str = Field(default="", max_length=100)
    body: str = Field(min_length=1, max_length=20_000)
    received_at: str | None = None
    id: str | None = Field(default=None, max_length=120)


class SmsBatchIn(BaseModel):
    messages: list[SmsIn] = Field(max_length=500)


class FeedbackIn(BaseModel):
    label: Literal["safe", "phishing"]


# ------------------------------------------------------------------------------------------------ helpers
def _host_only(h: str) -> str:
    h = (h or "").strip().lower()
    if h.startswith("["):
        return h.split("]")[0] + "]"
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _fmt_ts(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""


def _msg_dict(row) -> dict[str, Any]:
    d = dict(row)
    d["effective"] = d.get("user_label") or d.get("label")
    d["when"] = _fmt_ts(d.get("scanned_at"))
    return d


def public_verdict(v: dict[str, Any]) -> dict[str, Any]:
    """Verdict for API clients: link targets are only ever given defanged."""
    out = dict(v)
    out["urls"] = [{k: i.get(k) for k in ("defanged", "defanged_final", "flags", "final_flags", "brands", "official_brand",
                                           "shortener", "age_days", "points")} for i in v.get("urls", [])]
    return out


def build_message(text: str, kind: str, sender: str, source: str) -> Message:
    if kind == "sms":
        return from_sms(text, sender, source=source)
    return from_text(text, source=source, kind=None if kind == "auto" else kind, sender=sender)


# ------------------------------------------------------------------------------------------------ poller
class Poller(threading.Thread):
    def __init__(self, cfg: Config, scanner: Scanner, lock: threading.RLock):
        super().__init__(daemon=True, name="phishguard-poller")
        self.cfg, self.scanner, self.lock = cfg, scanner, lock
        self.stop_evt = threading.Event()

    def run(self) -> None:
        interval = max(1, self.cfg.server.scan_interval_minutes) * 60
        while not self.stop_evt.wait(interval if getattr(self, "_ran", False) else 5):
            self._ran = True
            try:
                with self.lock:
                    n = sum(1 for _ in poll_sources(self.cfg, self.scanner, None))
                log.info("background scan finished (%d lines)", n)
            except Exception as e:  # never die
                log.warning("background scan failed: %s", type(e).__name__)


# ------------------------------------------------------------------------------------------------ app factory
def create_app(cfg: Config, analyzer: Analyzer | None = None, start_poller: bool = True) -> FastAPI:
    analyzer = analyzer or Analyzer.from_config(cfg)
    scanner = Scanner(analyzer)
    store = analyzer.store
    scan_lock = threading.RLock()  # the analyzer / classifier are not re-entrant; serialise scans & feedback
    token = cfg.api_token()
    session_cookie = hmac.new(token.encode(), b"pg-session", hashlib.sha256).hexdigest()
    csrf = secrets.token_urlsafe(24)
    loopback_bind = cfg.server.host in LOOPBACK_NAMES
    allowed = set(LOOPBACK_NAMES) | {cfg.server.host.lower()} | {h.lower() for h in cfg.server.allowed_hosts}
    poller = Poller(cfg, scanner, scan_lock)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        any_src = cfg.gmail.enabled or cfg.imap.enabled or cfg.outlook.enabled
        if start_poller and any_src and cfg.server.scan_interval_minutes > 0:
            poller.start()
        yield
        poller.stop_evt.set()

    app = FastAPI(title="PhishGuard", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(HERE / "templates"))  # autoescape is on for .html
    templates.env.filters["defang"] = lambda s: defang_text(str(s or ""))
    templates.env.globals.update(csrf=csrf, version=__version__, LAYER_TITLES=LAYER_TITLES)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.state.scanner, app.state.analyzer, app.state.csrf = scanner, analyzer, csrf

    # ---------------------------------------------------------------------------- security middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        host_hdr = request.headers.get("host", "")
        if _host_only(host_hdr) not in allowed:
            return PlainTextResponse("Unexpected Host header (see server.allowed_hosts)", status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin != "null" and urlsplit(origin).netloc.lower() != host_hdr.lower():
                return PlainTextResponse("Cross-origin request refused", status_code=403)
            if origin == "null" or request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
                return PlainTextResponse("Cross-site request refused", status_code=403)
            try:
                if int(request.headers.get("content-length") or 0) > MAX_BODY:
                    return PlainTextResponse("Body too large", status_code=413)
            except ValueError:
                return PlainTextResponse("Bad Content-Length", status_code=400)
        resp = await call_next(request)
        resp.headers.update({
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin",
        })
        return resp

    # ---------------------------------------------------------------------------- auth
    def _bearer(request: Request) -> bool:
        h = request.headers.get("authorization", "")
        return h.lower().startswith("bearer ") and hmac.compare_digest(h[7:].strip(), token)

    def _cookie(request: Request) -> bool:
        return hmac.compare_digest(request.cookies.get("pg_session", ""), session_cookie)

    def api_auth(request: Request) -> None:
        """Scripts: bearer token. The web UI: CSRF header (+ session cookie when not bound to loopback)."""
        if _bearer(request):
            return
        csrf_ok = hmac.compare_digest(request.headers.get("x-pg-csrf", ""), csrf)
        if csrf_ok and (loopback_bind or _cookie(request)):
            return
        raise HTTPException(status_code=401, detail="missing or invalid credentials")

    def token_only(request: Request) -> None:
        if not _bearer(request):
            raise HTTPException(status_code=401, detail="bearer token required")

    def page_gate(request: Request) -> Response | None:
        if loopback_bind or _cookie(request) or _bearer(request):
            return None
        return RedirectResponse("/login", status_code=303)

    # ---------------------------------------------------------------------------- queries
    def counts() -> dict[str, int]:
        rows = store.query(f"SELECT {EFFECTIVE_LABEL} AS l, COUNT(*) AS c FROM messages GROUP BY l")
        out = {"safe": 0, "suspicious": 0, "phishing": 0}
        out.update({r["l"]: r["c"] for r in rows})
        out["quarantined"] = store.one("SELECT COUNT(*) AS c FROM messages WHERE quarantined=1")["c"]
        return out

    def stats(days: int) -> dict[str, Any]:
        since = time.time() - days * 86400
        day_rows = store.query(
            f"SELECT date(scanned_at,'unixepoch','localtime') AS d, {EFFECTIVE_LABEL} AS l, COUNT(*) AS c "
            "FROM messages WHERE scanned_at>=? GROUP BY d, l", (since,))
        by_day: dict[str, dict[str, int]] = {}
        for r in day_rows:
            by_day.setdefault(r["d"], {"safe": 0, "suspicious": 0, "phishing": 0})[r["l"]] = r["c"]
        series = []
        today = datetime.now().date()
        for i in range(days - 1, -1, -1):
            d = (today.fromordinal(today.toordinal() - i)).isoformat()
            c = by_day.get(d, {})
            series.append({"date": d, "safe": c.get("safe", 0), "suspicious": c.get("suspicious", 0), "phishing": c.get("phishing", 0)})
        flagged = f"{EFFECTIVE_LABEL} IN ('suspicious','phishing')"
        brands = store.query(
            f"SELECT b.brand AS name, COUNT(*) AS n FROM msg_brands b JOIN messages m ON m.id=b.message_id "
            f"WHERE m.scanned_at>=? AND {flagged} GROUP BY b.brand ORDER BY n DESC, name LIMIT 10", (since,))
        domains = store.query(
            f"SELECT d.domain AS name, COUNT(*) AS n FROM msg_domains d JOIN messages m ON m.id=d.message_id "
            f"WHERE m.scanned_at>=? AND {flagged} GROUP BY d.domain ORDER BY n DESC, name LIMIT 10", (since,))
        tot = {k: sum(s[k] for s in series) for k in ("safe", "suspicious", "phishing")}
        fp = store.one("SELECT COUNT(*) AS c FROM messages WHERE scanned_at>=? AND user_label='safe' AND label!='safe'", (since,))["c"]
        missed = store.one("SELECT COUNT(*) AS c FROM messages WHERE scanned_at>=? AND user_label='phishing' AND label='safe'", (since,))["c"]
        quarantined = store.one("SELECT COUNT(*) AS c FROM messages WHERE scanned_at>=? AND quarantined=1", (since,))["c"]
        return {"days": days, "series": series, "totals": {**tot, "scanned": sum(tot.values()), "quarantined": quarantined},
                "corrections": {"false_alarms": fp, "missed": missed},
                "brands": [{"name": r["name"], "n": r["n"]} for r in brands],
                "domains": [{"name": defang(r["name"]), "n": r["n"]} for r in domains]}

    def status() -> dict[str, Any]:
        sb, re_ = analyzer.sandbox, analyzer.re_adapter
        def avail(x):
            if x is None:
                return {"ready": False, "reason": "disabled in config"}
            ok, why = x.available()
            return {"ready": ok, "reason": why}
        return {
            "version": __version__, "thresholds": {"suspicious": cfg.thresholds.suspicious, "phishing": cfg.thresholds.phishing},
            "sources": {n: bool(getattr(cfg, n).enabled) for n in SOURCE_NAMES} | {"sms_ingest": cfg.sms.enabled},
            "quarantine_remote": {"gmail": cfg.gmail.quarantine, "imap": cfg.imap.quarantine, "outlook": cfg.outlook.quarantine},
            "link_sandbox": avail(sb), "attachment_sandbox": avail(re_), "attachment_engine": getattr(re_, "name", None),
            "classifier": analyzer.classifier is not None, "learned_weights": len(analyzer.learned),
            "feeds": [dict(r) for r in analyzer.intel.feeds.stats()],
            "privacy": {"llm_enabled": cfg.llm.enabled, "send_body_to_llm": cfg.privacy.send_body_to_llm,
                        "llm_active": bool(cfg.llm.enabled and cfg.privacy.send_body_to_llm),
                        "safe_browsing": bool(cfg.intel.safe_browsing_key), "rdap_lookups": cfg.intel.rdap and cfg.privacy.external_domain_lookups,
                        "store_snippet": cfg.privacy.store_snippet},
            "bind": f"{cfg.server.host}:{cfg.server.port}", "loopback_only": loopback_bind,
        }

    def get_row_or_404(mid: int):
        row = store.get_message(mid)
        if row is None:
            raise HTTPException(status_code=404, detail="no such message")
        return row

    # ---------------------------------------------------------------------------- pages
    def render(request: Request, name: str, page: str, **ctx):
        return templates.TemplateResponse(request, name, {"page": page, **ctx})

    @app.get("/login")
    def login_form(request: Request):
        return render(request, "login.html", "login", error="")

    @app.post("/login")
    async def login_submit(request: Request):
        form = await request.form()
        if hmac.compare_digest(str(form.get("token", "")).strip(), token):
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("pg_session", session_cookie, httponly=True, samesite="strict", max_age=30 * 86400)
            return resp
        time.sleep(0.5)
        return render(request, "login.html", "login", error="That token is not right.")

    @app.get("/")
    def inbox(request: Request, label: str = "", source: str = "", page: int = 1):
        if (r := page_gate(request)) is not None:
            return r
        label = label if label in ("safe", "suspicious", "phishing", "quarantined") else ""
        page = max(1, min(page, 10_000))
        where, params = [], []
        if label == "quarantined":
            where.append("quarantined=1")
        elif label:
            where.append(f"{EFFECTIVE_LABEL}=?")
            params.append(label)
        if source and re.fullmatch(r"[a-z]{2,12}", source):
            where.append("source=?")
            params.append(source)
        sql = ("SELECT id,source,kind,received_at,scanned_at,sender,subject,snippet,score,label,quarantined,user_label,"
               "json_extract(verdict_json,'$.summary') AS summary FROM messages")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY scanned_at DESC, id DESC LIMIT ? OFFSET ?"
        rows = [_msg_dict(r) for r in store.query(sql, (*params, PER_PAGE + 1, (page - 1) * PER_PAGE))]
        sources = [r["source"] for r in store.query("SELECT DISTINCT source FROM messages ORDER BY source")]
        return render(request, "inbox.html", "inbox", rows=rows[:PER_PAGE], has_next=len(rows) > PER_PAGE, pg=page,
                      label=label, source=source, counts=counts(), sources=sources)

    @app.get("/message/{mid}")
    def message_page(request: Request, mid: int):
        if (r := page_gate(request)) is not None:
            return r
        row = get_row_or_404(mid)
        v = json.loads(row["verdict_json"])
        by_layer: dict[str, list] = {}
        for s in v["signals"]:
            by_layer.setdefault(s["layer"], []).append(s)
        return render(request, "message.html", "inbox", m=_msg_dict(row), v=v, by_layer=by_layer, layer_order=list(LAYER_TITLES))

    @app.get("/check")
    def check_page(request: Request):
        if (r := page_gate(request)) is not None:
            return r
        return render(request, "check.html", "check")

    @app.get("/dashboard")
    def dashboard_page(request: Request):
        if (r := page_gate(request)) is not None:
            return r
        return render(request, "dashboard.html", "dashboard")

    @app.get("/status")
    def status_page(request: Request):
        if (r := page_gate(request)) is not None:
            return r
        return render(request, "status.html", "status", s=status(), c=counts())

    @app.get("/shots/{name}")
    def shot(request: Request, name: str):
        if (r := page_gate(request)) is not None:
            return r
        p = cfg.path("shots") / name
        if not SHOT_RE.fullmatch(name) or not p.is_file():
            raise HTTPException(status_code=404)
        return FileResponse(p, media_type="image/png")

    # ---------------------------------------------------------------------------- API
    def _scan_and_pack(msg: Message, save: bool, deep: bool) -> dict[str, Any]:
        with scan_lock:
            res = scanner.scan(msg, persist=save, deep=deep)
        out = public_verdict(res.verdict.to_dict())
        out.update(message_id=res.message_id, quarantined=res.quarantined, quarantine_note=res.quarantine_note)
        return out

    @app.post("/api/check", dependencies=[Depends(api_auth)])
    def api_check(body: CheckIn):
        msg = build_message(body.text, body.kind, body.sender, source="paste")
        return _scan_and_pack(msg, body.save, body.deep)

    @app.post("/api/share", dependencies=[Depends(api_auth)])
    async def api_share(request: Request):
        """Share target for phones/shortcuts: accepts JSON or a form with text / url / title / sender."""
        ctype = request.headers.get("content-type", "")
        data: dict[str, Any]
        if "json" in ctype:
            data = await request.json()
        else:
            data = dict(await request.form())
        if not isinstance(data, dict):
            raise HTTPException(status_code=422, detail="expected an object")
        parts = [str(data.get(k) or "").strip() for k in ("title", "text", "url")]
        text = "\n".join(p for p in parts if p)[:200_000]
        if not text:
            raise HTTPException(status_code=422, detail="nothing to check (send text and/or url)")
        msg = build_message(text, "auto", str(data.get("sender") or "")[:200], source="share")
        return await run_in_threadpool(_scan_and_pack, msg, True, True)

    def _ingest_sms(item: SmsIn) -> dict[str, Any]:
        when = None
        if item.received_at:
            try:
                when = datetime.fromisoformat(item.received_at.replace("Z", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
            except ValueError:
                when = None
        ext = item.id or hashlib.sha256(f"{item.sender}|{item.received_at}|{item.body}".encode()).hexdigest()[:32]
        if store.has_message("sms", ext):
            return {"duplicate": True, "external_id": ext}
        msg = from_sms(item.body, item.sender, received_at=when, source="sms", external_id=ext)
        out = _scan_and_pack(msg, True, True)
        return {"duplicate": False, "external_id": ext, "message_id": out["message_id"], "label": out["label"], "score": out["score"]}

    @app.post("/api/ingest/sms", dependencies=[Depends(token_only)])
    def api_ingest_sms(item: SmsIn):
        if not cfg.sms.enabled:
            raise HTTPException(status_code=403, detail="SMS ingest is disabled in config")
        return _ingest_sms(item)

    @app.post("/api/ingest/sms/batch", dependencies=[Depends(token_only)])
    def api_ingest_sms_batch(batch: SmsBatchIn):
        if not cfg.sms.enabled:
            raise HTTPException(status_code=403, detail="SMS ingest is disabled in config")
        results = [_ingest_sms(i) for i in batch.messages]
        return {"received": len(results), "new": sum(1 for r in results if not r["duplicate"]), "results": results}

    @app.get("/api/messages", dependencies=[Depends(api_auth)])
    def api_messages(label: str = "", source: str = "", limit: int = 100, offset: int = 0):
        rows = store.list_messages(label=label or None, source=source or None, limit=max(1, min(limit, 500)), offset=max(0, offset))
        return {"messages": [_msg_dict(r) for r in rows]}

    @app.get("/api/messages/{mid}", dependencies=[Depends(api_auth)])
    def api_message(mid: int):
        row = get_row_or_404(mid)
        d = _msg_dict({k: row[k] for k in row.keys() if k not in ("features_json", "verdict_json")})
        d["verdict"] = public_verdict(json.loads(row["verdict_json"]))
        return d

    @app.post("/api/messages/{mid}/feedback", dependencies=[Depends(api_auth)])
    def api_feedback(mid: int, body: FeedbackIn):
        get_row_or_404(mid)
        with scan_lock:
            res = apply_feedback(analyzer, mid, body.label)
            rescored = rescore_all(analyzer) if res.get("changed") else 0
        return {**res, "rescored": rescored}

    @app.post("/api/messages/{mid}/release", dependencies=[Depends(api_auth)])
    def api_release(mid: int):
        get_row_or_404(mid)
        store.set_quarantined(mid, False, "released by you (the mail provider copy, if it was moved, is untouched)")
        return {"released": True}

    @app.get("/api/stats", dependencies=[Depends(api_auth)])
    def api_stats(days: int = 30):
        return stats(max(1, min(days, 365)))

    @app.get("/api/status", dependencies=[Depends(api_auth)])
    def api_status():
        return status()

    @app.post("/api/scan", dependencies=[Depends(api_auth)])
    def api_scan(source: str = "all"):
        names = None if source == "all" else [source]
        with scan_lock:
            return {"lines": list(poll_sources(cfg, scanner, names))}

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    return app
