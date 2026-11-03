"""Link-behaviour layer: opens suspicious URLs in the isolated browser container and turns the
observations (redirects, login forms, downloads, certificate problems) into signals."""
from __future__ import annotations

import logging
import re

from ..ctx import Ctx
from ..models import Message, Signal
from ..sandbox.runner import SandboxUnavailable
from ..urlutil import defang, parse_url, registrable_domain
from .urls import TRACKING

log = logging.getLogger(__name__)


def _candidates(url_infos: list[dict], ctx: Ctx) -> list[str]:
    scored: list[tuple[float, str, str]] = []
    for i in url_infos:
        if i.get("official_brand"):
            continue
        reg = i.get("registrable") or ""
        if reg in ctx.kb.esp_domains or reg in TRACKING:
            continue
        target = i.get("final_url") or i["url"]
        p = parse_url(target)
        if not p or not re.match(r"(?i)^https?$|^$", p.scheme or "http"):
            continue
        scored.append((float(i.get("points", 0)), target, p.registrable))
    scored.sort(key=lambda t: -t[0])
    out, seen = [], set()
    for _, target, reg in scored:
        if reg in seen:
            continue
        seen.add(reg)
        out.append(target)
    return out[: ctx.cfg.sandbox.max_urls_per_message]


def run(msg: Message, ctx: Ctx, url_infos: list[dict], pre_score: int, resolved: dict[str, str]) -> tuple[list[Signal], list[dict]]:
    cfg = ctx.cfg.sandbox
    if not url_infos or ctx.sandbox is None or pre_score < cfg.browse_min_score:
        return [], []
    targets = _candidates(url_infos, ctx)
    if not targets:
        return [], []
    sigs: list[Signal] = []
    reports: list[dict] = []
    for url in targets:
        try:
            rep = ctx.sandbox.browse(url)
        except SandboxUnavailable as e:
            ctx.notes.append(f"Link behaviour analysis skipped: {e}")
            break
        except Exception as e:
            ctx.notes.append(f"Link behaviour analysis failed for {defang(url)} ({type(e).__name__})")
            continue
        rep["defanged_url"] = defang(url)
        rep["defanged_final"] = defang(rep.get("final_url") or url)
        reports.append(rep)
        sigs += signals_for_report(rep, ctx)
    return _dedupe(sigs), reports


def _dedupe(sigs: list[Signal]) -> list[Signal]:
    best: dict[str, Signal] = {}
    for s in sigs:
        if s.id not in best or s.points > best[s.id].points:
            best[s.id] = s
    return list(best.values())


def signals_for_report(rep: dict, ctx: Ctx) -> list[Signal]:
    kb = ctx.kb
    out: list[Signal] = []
    start = rep.get("url") or ""
    final = rep.get("final_url") or start
    fp = parse_url(final) if final else None
    sp = parse_url(start) if start else None
    ev = defang(final or start)

    def add(id_: str, pts: float, reason: str) -> None:
        out.append(ctx.sig("behavior", id_, pts, reason, ev))

    if rep.get("internal_target"):
        add("behav.internal_target", 40, "The link points at a private/internal address (blocked by the sandbox)")
    if rep.get("error") and not fp:
        return out  # unreachable: nothing more to say
    official = kb.brand_of_domain(fp.registrable) if fp else None
    page_text = (rep.get("title", "") + " " + rep.get("text_excerpt", "")).strip()
    brands = [b for b in kb.brands_in_text(page_text) if not (fp and b.is_official(fp.registrable))]
    if rep.get("has_login_form") and not official:
        if brands:
            add("behav.brand_login_page", 70, f"The page is a login form that presents itself as {brands[0].name}, hosted on {fp.registrable if fp else '?'}")
        else:
            add("behav.login_form", 32, "The page asks for a password (login form) on a site unrelated to the message")
    elif brands and not official:
        add("behav.brand_text_offsite", 40, f"The page uses the {brands[0].name} name but is not hosted by {brands[0].name}")
    for f in rep.get("forms", []):
        if f.get("has_password") and f.get("cross_origin"):
            add("behav.form_posts_elsewhere", 55, "The login form sends your password to a different website than the page itself")
            break
    chain = [r.get("url") for r in rep.get("redirects", []) if r.get("url")]
    regs = {registrable_domain(urlhost(u)) for u in chain if u}
    if len(chain) >= 5:
        add("behav.long_redirect_chain", 25, f"The link bounces through {len(chain)} redirects before landing")
    elif len(chain) >= 3 and len(regs) >= 2:
        add("behav.redirect_chain", 16, f"The link passes through {len(regs)} different sites before landing")
    if sp and fp and sp.registrable != fp.registrable and not (sp.registrable in kb.shorteners):
        add("behav.landing_differs", 10, f"The link ends up on a different site ({fp.registrable}) than it started on ({sp.registrable})")
    if rep.get("downloads"):
        add("behav.auto_download", 50, "Opening the link tried to download a file (blocked and discarded)")
    if rep.get("cert_error"):
        add("behav.cert_error", 20, "The site's HTTPS certificate is invalid or self-signed")
    if rep.get("meta_refresh") or rep.get("js_redirects"):
        add("behav.client_redirect", 12, "The page redirects you automatically via script/meta-refresh")
    return out


def urlhost(u: str) -> str:
    p = parse_url(u)
    return p.host if p else ""
