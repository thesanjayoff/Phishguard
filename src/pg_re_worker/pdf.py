"""PDF triage by keyword/structure scan (no PDF renderer is ever invoked, nothing is executed)."""
from __future__ import annotations

import re
import zlib
from typing import Callable

from .core import Budget, Report, safe_name

MAX_STREAMS = 250
MAX_STREAM_OUT = 2 << 20
_NAME_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"(<<(?:(?!endobj).){0,2000}?>>)\s*stream\r?\n", re.S)
_JS_LIT = re.compile(rb"/JS\s*\(((?:\\.|[^\\)]){1,6000})\)", re.S)
_JS_HEX = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]{4,12000})>")
_URI = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){3,500})\)")
_JS_SUSPICIOUS = re.compile(
    r"(?i)(eval\s*\(|unescape\s*\(|String\.fromCharCode|app\.launchURL|exportDataObject|getAnnots|util\.printf|%u[0-9a-f]{4}%u[0-9a-f]{4}|"
    r"this\.submitForm|importDataObject|spawn|\bnew\s+ActiveXObject|collab\.getIcon|media\.newPlayer)")
KEYWORDS = ["JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "URI", "SubmitForm", "AcroForm", "RichMedia", "XFA", "ObjStm", "Encrypt", "JBIG2Decode", "GoToR", "GoToE"]


def _normalise(raw: bytes) -> bytes:
    """Undo #xx escapes inside PDF names (/J#61vaScript) so obfuscated keywords are still found."""
    return _NAME_HEX.sub(lambda m: bytes([int(m.group(1), 16)]), raw)


def _count(blob: bytes, key: str) -> int:
    return len(re.findall(rb"/" + key.encode() + rb"(?![A-Za-z])", blob))


def analyse_pdf(rep: Report, data: bytes, depth: int, budget: Budget, child: Callable) -> None:
    head = data[:1024]
    if not head.startswith(b"%PDF-"):
        rep.behavior("pdf.header_offset", "low", "PDF header is not at the start of the file", "Malformed headers are used to slip past scanners.", head[:60].decode("latin-1", "replace"), "text", "offset 0")
    if b"%%EOF" not in data[-2048:]:
        rep.warn("PDF has no end-of-file marker (truncated or deliberately malformed)")
    norm = _normalise(data)
    counts = {k: _count(norm, k) for k in KEYWORDS}
    obfuscated = [m for m in re.findall(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}[A-Za-z#0-9]*", data[:4 << 20]) if len(m) < 40]
    if obfuscated:
        rep.behavior("pdf.obfuscated_names", "medium", "PDF keywords are written with #-escapes to hide them from scanners", "", b"\n".join(obfuscated[:6]).decode("latin-1", "replace"), "pdf-names", "objects")
    if counts["Encrypt"]:
        rep.d["encrypted"] = True

    # ---- collect JavaScript from literal strings and (decoded) streams
    js_blobs: list[tuple[str, str]] = []
    for m in _JS_LIT.finditer(norm):
        js_blobs.append(("/JS string", m.group(1).decode("latin-1", "replace")))
    for m in _JS_HEX.finditer(norm):
        try:
            js_blobs.append(("/JS hex string", bytes.fromhex(re.sub(r"\s+", "", m.group(1).decode())).decode("latin-1", "replace")))
        except ValueError:
            pass
    decoded_streams = 0
    for m in _STREAM.finditer(norm):
        budget.tick()
        decoded_streams += 1
        if decoded_streams > MAX_STREAMS:
            rep.warn(f"only the first {MAX_STREAMS} streams were inspected")
            break
        d = m.group(1)
        start = m.end()
        end = norm.find(b"endstream", start, start + (12 << 20))
        if end < 0:
            continue
        body = norm[start:end]
        if b"/FlateDecode" in d or b"/Fl " in d:
            try:
                body = zlib.decompressobj().decompress(body.strip(b"\r\n"), MAX_STREAM_OUT)
            except zlib.error:
                continue
        text = body[:MAX_STREAM_OUT]
        if text[:2] == b"MZ" and b"PE\x00\x00" in text[:1024]:
            rep.behavior("pdf.embedded_pe", "critical", "A stream inside the PDF is a Windows executable", "", text[:64].hex(" "), "hex", "stream")
            if depth < budget.max_depth:
                budget.spend(len(text))
                rep.d["children"].append(child("embedded_stream.exe", text, [], depth + 1, budget))
            continue
        if b"/JavaScript" in d or _JS_SUSPICIOUS.search(text[:200000].decode("latin-1", "replace")) and re.search(rb"(?i)function|var |app\.|this\.", text[:4000]):
            js_blobs.append(("stream", text[:200000].decode("latin-1", "replace")))
    for loc, js in js_blobs[:6]:
        sus = _JS_SUSPICIOUS.findall(js)
        rep.add_iocs(js)
        sev = "high" if sus else "medium"
        rep.behavior("pdf.javascript", sev, "PDF contains JavaScript" + (" with obfuscation/exploit-style calls" if sus else ""),
                     "Legitimate documents rarely need script. " + (f"Suspicious calls: {', '.join(sorted(set(s.lower() for s in sus))[:6])}." if sus else ""),
                     js[:700], "javascript", loc)
    if counts["OpenAction"] or counts["AA"]:
        auto_js = bool(js_blobs)
        rep.behavior("pdf.auto_action", "high" if auto_js else "low", "PDF runs an action automatically when opened" + (" (and that action is script)" if auto_js else ""), "",
                     f"/OpenAction x{counts['OpenAction']}, /AA x{counts['AA']}", "keyword-count", "document catalog")
    if counts["Launch"]:
        rep.behavior("pdf.launch", "high", "PDF can launch an external program or file", "", f"/Launch x{counts['Launch']}", "keyword-count", "actions")
    if counts["EmbeddedFile"]:
        rep.behavior("pdf.embedded_file", "medium", "PDF carries an embedded file", "", f"/EmbeddedFile x{counts['EmbeddedFile']}", "keyword-count", "attachments")
    if counts["SubmitForm"]:
        rep.behavior("pdf.submit_form", "medium", "PDF form submits data to a server", "", f"/SubmitForm x{counts['SubmitForm']}", "keyword-count", "actions")
    if counts["RichMedia"] or counts["XFA"]:
        rep.behavior("pdf.rich_content", "low", "PDF uses Flash/XFA rich content (historically exploited)", "", f"/RichMedia x{counts['RichMedia']}, /XFA x{counts['XFA']}", "keyword-count", "objects")
    if counts["JBIG2Decode"]:
        rep.behavior("pdf.jbig2", "low", "PDF uses JBIG2 image compression (source of past parser exploits)", "", f"/JBIG2Decode x{counts['JBIG2Decode']}", "keyword-count", "images")
    uris = [safe_name(m.group(1).decode("latin-1", "replace"), 300) for m in _URI.finditer(norm)]
    if uris:
        rep.add_iocs("\n".join(uris))
        rep.behavior("pdf.uri_action", "low", f"PDF contains {len(set(uris))} clickable link(s)", "Phishing PDFs are often just a picture with a link; the link targets are listed under indicators.",
                     "\n".join(sorted(set(uris))[:8]), "urls", "link annotations")
    rep.d["strings"] = [f"/{k} x{v}" for k, v in counts.items() if v][:30]
