"""Attachment layer. File-name/type checks run on the host (they only look at the *name*);
all content analysis is delegated to the REAdapter, which runs in an isolated no-network container."""
from __future__ import annotations

import hashlib
import logging
import re

from ..ctx import Ctx
from ..models import Message, Signal
from ..sandbox.runner import SandboxUnavailable
from .urls import analyze_url

log = logging.getLogger(__name__)

SEV_POINTS = {"info": 0, "low": 15, "medium": 42, "high": 70, "critical": 92}
EXEC_EXT = {"exe", "scr", "com", "pif", "msi", "msp", "dll", "cpl", "jar", "apk", "xapk", "bat", "cmd", "vbs", "vbe", "js", "jse",
            "wsf", "wsh", "hta", "ps1", "psm1", "lnk", "reg", "sct", "gadget", "application", "appx", "msix", "scf", "url"}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "dmg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb", "ppam", "sldm"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "tgz", "bz2", "xz", "cab", "arj", "ace"}
DOUBLE_EXT = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv|mp3|mp4)[\s_.]*\.(exe|scr|com|pif|js|jse|vbs|vbe|bat|cmd|hta|lnk|ps1|jar|msi|wsf)$")
_PASS = re.compile(r"(?i)\b(?:password|passcode|pass|pwd)\s*(?:is|:|=|-)?\s*[:=]?\s*[\"“']?([\w@#$!%^&*.-]{3,32})")


def ext_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def host_checks(att, ctx: Ctx) -> list[Signal]:
    name, ext = att.filename, ext_of(att.filename)
    out: list[Signal] = []

    def add(id_: str, pts: float, reason: str) -> None:
        out.append(ctx.sig("attachments", id_, pts, reason, name[:80]))

    if "‮" in name:
        add("att.rtlo", 78, "The file name uses a hidden right-to-left character to disguise its real extension")
    if DOUBLE_EXT.search(name):
        add("att.double_extension", 72, f"'{name[:60]}' looks like a document but is really an executable/script")
    elif ext in EXEC_EXT:
        add("att.executable", {"url": 25, "lnk": 50}.get(ext, 58), f"Executable or script attachment (.{ext})")
    elif ext in CONTAINER_EXT:
        add("att.disk_image", 35, f"Disk-image attachment (.{ext}) - used to smuggle files past mail scanners")
    elif ext in MACRO_EXT:
        add("att.macro_enabled_ext", 16, f"Macro-enabled Office document (.{ext})")
    elif ext in HTML_EXT:
        add("att.html_attachment", 40, f"HTML attachment (.{ext}) - a common way to deliver fake login pages offline")
    return out


def passwords_from_text(text: str) -> list[str]:
    seen: list[str] = []
    for m in _PASS.finditer(text or ""):
        w = m.group(1).strip(".")
        if w and w.lower() not in ("is", "protected", "for", "the", "to", "and") and w not in seen:
            seen.append(w)
    return seen[:6]


def minimal_report(att) -> dict:
    return {
        "filename": att.filename, "size": att.size, "sha256": hashlib.sha256(att.data).hexdigest(),
        "sha1": hashlib.sha1(att.data).hexdigest(), "md5": hashlib.md5(att.data).hexdigest(),
        "file_type": att.content_type, "declared_ext": ext_of(att.filename), "behaviors": [], "iocs": {},
        "warnings": ["content not analysed (isolated container unavailable)"], "engine": "none",
    }


def signals_for_report(rep: dict, ctx: Ctx, prefix: str = "") -> list[Signal]:
    out: list[Signal] = []
    fname = rep.get("filename", "")
    label = f"{prefix}{fname}" if fname else prefix
    if rep.get("type_mismatch"):
        out.append(ctx.sig("attachments", "att.type_mismatch", 75,
                           f"'{label}' claims to be .{rep.get('declared_ext') or '?'} but is really {rep.get('file_type')}", label[:80]))
    if rep.get("encrypted"):
        out.append(ctx.sig("attachments", "att.encrypted", 28, f"'{label}' is password-protected, so it could not be inspected by mail scanners", label[:80]))
    if rep.get("packed"):
        out.append(ctx.sig("attachments", "att.packed", 40, f"'{label}' looks packed/obfuscated (very high entropy)", f"entropy={rep.get('entropy')}"))
    for b in rep.get("behaviors", []):
        pts = SEV_POINTS.get(b.get("severity", "low"), 15)
        if pts <= 0:
            continue
        snippet = (b.get("snippet") or "").strip().replace("\n", " ")[:160]
        out.append(ctx.sig("attachments", f"att.{b['id']}", pts, f"{b.get('title') or b['id']} in '{label}'" + (f" ({b['location']})" if b.get("location") else ""), snippet))
    for ch in rep.get("children", []):
        out += signals_for_report(ch, ctx, prefix=f"{fname} > ")
    return out


def _ioc_signals(rep: dict, ctx: Ctx) -> list[Signal]:
    out: list[Signal] = []
    urls = list(rep.get("iocs", {}).get("urls", []))
    for ch in rep.get("children", []):
        urls += ch.get("iocs", {}).get("urls", [])
    best = 0.0
    for u in urls[:12]:
        hit = ctx.intel.feeds.lookup(u)
        if hit and hit.exact:
            out.append(ctx.sig("attachments", "att.ioc_blocklisted", 92, f"An address inside the file is listed as phishing/malware in {hit.source}", u[:100]))
            break
        sigs, _ = analyze_url(u, ctx, allow_lookups=False)
        best = max([best] + [s.points for s in sigs if s.points >= 25])
    if best and not out:
        out.append(ctx.sig("attachments", "att.ioc_suspicious_url", round(best * 0.8, 1), "The file contains web addresses that look malicious", urls[0][:100]))
    return out


def run(msg: Message, ctx: Ctx, deep: bool = True) -> tuple[list[Signal], list[dict]]:
    sigs: list[Signal] = []
    reports: list[dict] = []
    pw = passwords_from_text(msg.text)
    skipped_note = False
    for att in msg.attachments[:8]:
        host_sigs = host_checks(att, ctx)
        sigs += host_sigs
        rep = None
        if deep and ctx.re_adapter is not None and ctx.cfg.attachments.enabled:
            try:
                rep = ctx.re_adapter.analyze(att.filename, att.data, pw)
                sigs += signals_for_report(rep, ctx)
                sigs += _ioc_signals(rep, ctx)
            except SandboxUnavailable as e:
                if not skipped_note:
                    ctx.notes.append(f"Attachment analysis skipped: {e}")
                    skipped_note = True
            except Exception as e:
                log.warning("attachment analysis failed: %s", type(e).__name__)
                ctx.notes.append(f"Attachment analysis failed for one file ({type(e).__name__})")
        if rep is None:
            rep = minimal_report(att)
        rep["host_flags"] = [s.id for s in host_sigs]
        reports.append(rep)
    best: dict[str, Signal] = {}
    for s in sigs:
        if s.id not in best or s.points > best[s.id].points:
            best[s.id] = s
    return list(best.values()), reports
