"""Office documents: macros (VBA), remote templates, DDE, embedded objects. Static only - macros are extracted and
read as text, never run."""
from __future__ import annotations

import io
import logging
import re
import zipfile
from typing import Callable

from .core import Budget, Report, safe_name

log = logging.getLogger("pg_re_worker")

# (id, severity, title, regex) - looked for in the extracted VBA source; first matching line is the snippet.
VBA_RULES: list[tuple[str, str, str, re.Pattern]] = [
    ("macro.autoexec", "medium", "Macro runs automatically when the document is opened",
     re.compile(r"(?im)^\s*(?:public\s+|private\s+)?(?:sub|function)\s+(auto_?open|autoexec|autoclose|auto_?close|document_open|document_close|document_new|workbook_open|workbook_activate|workbook_beforeclose|worksheet_activate|autonew|auto_activate)\b")),
    ("macro.download", "high", "Macro can download files from the internet",
     re.compile(r"(?i)(urldownloadtofile|msxml2\.(?:server)?xmlhttp|microsoft\.xmlhttp|winhttp\.winhttprequest|net\.webclient|adodb\.stream|internetopenurl|downloadfile|downloadstring|bitsadmin|certutil)")),
    ("macro.shell_exec", "high", "Macro can start other programs",
     re.compile(r"(?i)(wscript\.shell|shell\.application|\bshell\s*\(|\bshell\s+\"|\.run\s*\(|\.exec\s*\(|createprocess|shellexecute|winexec|mshta|powershell|cmd(?:\.exe)?\s*/c|rundll32|regsvr32|wmic)")),
    ("macro.injection", "critical", "Macro uses Windows memory/thread APIs typical of shellcode loaders",
     re.compile(r"(?i)(virtualalloc|virtualprotect|writeprocessmemory|createremotethread|rtlmovememory|createthread|callwindowproc|enumsystemlocales|enumwindows|setwindowshookex|ntallocatevirtualmemory)")),
    ("macro.persistence", "high", "Macro sets itself up to run again (registry Run key / scheduled task / startup folder)",
     re.compile(r"(?i)(currentversion\\run|schtasks|\\startup\\|scheduledtasks|taskscheduler|wscript\.shell.{0,40}regwrite|regwrite)")),
    ("macro.file_write", "medium", "Macro writes files to disk",
     re.compile(r"(?i)(open\s+.{1,80}\s+for\s+(?:binary|output)|\.savetofile|createtextfile|\bput\s+#|filecopy|\bkill\s+|environ\s*\(\s*\"(?:temp|appdata|tmp|public|userprofile))")),
    ("macro.obfuscation", "medium", "Macro text is heavily obfuscated",
     re.compile(r"(?i)((?:chr[wb]?\s*\(\s*\d+\s*\)\s*&\s*){4,}|strreverse|(?:\bxor\b.{0,30}){3,}|&h[0-9a-f]{2}\s*,\s*&h[0-9a-f]{2}\s*,\s*&h[0-9a-f]{2})")),
    ("macro.api_declare", "medium", "Macro imports native Windows API functions",
     re.compile(r"(?im)^\s*(?:public\s+|private\s+)?declare\s+(?:ptrsafe\s+)?(?:function|sub)\s+\w+\s+lib\s+\"[^\"]+\"")),
    ("macro.environment_probe", "low", "Macro inspects the machine (user, host, sandbox checks)",
     re.compile(r"(?i)(username|computername|userdomain|application\.username|recentfiles\.count|vbaversion|sandbox|vmware|virtualbox)")),
]
_XLM = re.compile(rb"(?i)(EXEC\(|CALL\(|REGISTER\(|FORMULA\(|RUN\(|ALERT\(|HALT\(\))")
_DDE = re.compile(r"(?i)\b(DDEAUTO|DDE)\b[^<]{0,200}")
_REMOTE_REL = re.compile(r'(?is)<Relationship\b[^>]*?Target="([^"]+)"[^>]*?TargetMode="External"[^>]*>|<Relationship\b[^>]*?TargetMode="External"[^>]*?Target="([^"]+)"[^>]*>')


def _scan_vba(rep: Report, name: str, code: str) -> None:
    for id_, sev, title, rx in VBA_RULES:
        m = rx.search(code)
        if not m:
            continue
        lines = code.splitlines()
        upto = code[:m.start()].count("\n")
        snippet = "\n".join(l[:200] for l in lines[max(0, upto - 1): upto + 3])
        rep.behavior(id_, sev, title, f"Found in VBA module '{name}'.", snippet, "vba", f"{name} line {upto + 1}")
    rep.add_iocs(code)


def _analyse_vba_project(rep: Report, blob: bytes, filename: str) -> None:
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        rep.warn("oletools is not installed in this image; VBA macros could not be extracted")
        return
    old = logging.getLogger("olevba").level
    logging.getLogger("olevba").setLevel(logging.CRITICAL)
    try:
        vp = VBA_Parser(filename, data=blob)
        try:
            if not vp.detect_vba_macros():
                return
            rep.behavior("macro.present", "low", "Document contains VBA macros", "", "", "", "vbaProject")
            total = 0
            for (_subfile, _stream, vba_name, code) in vp.extract_macros():
                if not code or not code.strip():
                    continue
                total += 1
                if total > 12:
                    break
                code = code[:200_000]
                _scan_vba(rep, safe_name(vba_name or "module", 60), code)
                if len(rep.d["macros"]) < 10:
                    rep.d["macros"].append({"name": safe_name(vba_name or "module", 80), "excerpt": code[:1500]})
            try:
                for kind, kw, desc in vp.analyze_macros(show_decoded_strings=False):
                    if kind in ("Hex String", "Base64 String", "Dridex string", "VBA string", "VBA obfuscated", "Obfuscated") or "obfus" in (desc or "").lower():
                        rep.behavior("macro.obfuscation", "medium", "Macro contains encoded/obfuscated strings",
                                     f"{kind}: {safe_name(str(desc), 150)}", safe_name(str(kw), 300), "decoded-string", "olevba")
            except Exception:
                pass
        finally:
            vp.close()
    except Exception as e:  # olevba raises many kinds of errors on malformed input
        rep.warn(f"VBA extraction failed ({type(e).__name__})")
    finally:
        logging.getLogger("olevba").setLevel(old)


def analyse_ole(rep: Report, data: bytes, depth: int, budget: Budget, child: Callable) -> None:
    import olefile

    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as e:
        rep.warn(f"OLE structure unreadable ({type(e).__name__})")
        return
    try:
        streams = ["/".join(s) for s in ole.listdir(streams=True, storages=False)]
        low = [s.lower() for s in streams]
        if any(s in ("encryptedpackage", "encryptioninfo") for s in low):
            rep.d["encrypted"] = True
        if "worddocument" in low:
            rep.d["file_type"] = "Word 97-2003 document (OLE2)"
        elif "workbook" in low or "book" in low:
            rep.d["file_type"] = "Excel 97-2003 workbook (OLE2)"
        elif any("powerpoint document" in s for s in low):
            rep.d["file_type"] = "PowerPoint 97-2003 presentation (OLE2)"
        elif any(s.endswith("_summaryinformation") for s in low) and any("msi" in s or "!" in s for s in low):
            rep.d["file_type"] = "Windows Installer / OLE2 package"
        for s, sl in zip(streams, low):
            if sl.startswith("objectpool/") and sl.endswith(("ole10native", "package")):
                rep.behavior("office.embedded_object", "high", "Document embeds a packaged file or object",
                             "Embedded objects are a common way to hide an executable or script inside a document.", s, "stream-name", s)
                try:
                    blob = ole.openstream(s).read(8 << 20)
                    budget.spend(len(blob))
                    if depth < budget.max_depth:
                        rep.d["children"].append(child(f"embedded:{safe_name(s.rsplit('/', 1)[-1], 40)}", blob, [], depth + 1, budget))
                except Exception:
                    pass
        if "macros" in " ".join(low) or "vba" in " ".join(low):
            _analyse_vba_project(rep, data, rep.d["filename"] or "document")
        if re.search(r"(?i)(\\x01)?(ole10native|equation native)", " ".join(streams)) and any("equation" in s for s in low):
            rep.behavior("office.equation_editor", "high", "Document uses the legacy Equation Editor (source of several memory-corruption exploits)")
        # Excel 4.0 (XLM) macro sheets sit in the Workbook stream
        for wb in ("Workbook", "Book"):
            if ole.exists(wb):
                blob = ole.openstream(wb).read(6 << 20)
                if _XLM.search(blob) and re.search(rb"(?i)EXEC|CALL|REGISTER", blob):
                    rep.behavior("office.xlm_macro", "high", "Workbook contains Excel 4.0 (XLM) macro formulas",
                                 "XLM macros do not need VBA and are often missed by scanners.", safe_name(_XLM.search(blob).group(0).decode("latin-1"), 60), "formula-keyword", wb)
                break
    finally:
        ole.close()


def analyse_ooxml(rep: Report, data: bytes, depth: int, budget: Budget, child: Callable) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        rep.warn("Open XML package is damaged")
        return
    names = zf.namelist()
    low = [n.lower() for n in names]
    if any(n in ("encryptioninfo", "encryptedpackage") for n in low):
        rep.d["encrypted"] = True

    def read(n: str, cap: int = 8 << 20) -> bytes:
        with zf.open(n) as fh:
            b = fh.read(cap + 1)
        budget.spend(min(len(b), cap))
        return b[:cap]

    for n in names:
        budget.tick()
        nl = n.lower()
        if nl.endswith("vbaproject.bin"):
            _analyse_vba_project(rep, read(n), rep.d["filename"] or "document")
        elif nl.endswith(".rels"):
            text = read(n, 1 << 20).decode("utf-8", "replace")
            for m in _REMOTE_REL.finditer(text):
                target = (m.group(1) or m.group(2) or "").strip()
                if not target:
                    continue
                kind = "attachedTemplate" if "attachedtemplate" in text[max(0, m.start() - 200): m.end() + 200].lower() else "link"
                if kind == "attachedTemplate" or re.match(r"(?i)^(?:https?|ftp|file|\\\\)", target):
                    sev = "high" if kind == "attachedTemplate" else "medium"
                    title = "Document loads a remote template (template injection)" if kind == "attachedTemplate" else "Document links to an external resource"
                    rep.behavior(f"office.remote_{'template' if kind == 'attachedTemplate' else 'link'}", sev, title,
                                 "The target is fetched when the document opens, so the real payload is not in the file.",
                                 f"{n}: {target[:200]}", "relationship", n)
                    rep.add_iocs(target)
        elif nl.endswith((".xml",)) and (nl.startswith("word/") or nl.startswith("xl/") or nl.startswith("ppt/")):
            if nl.startswith(("word/document", "word/header", "word/footer", "xl/sharedstrings")):
                text = read(n, 3 << 20).decode("utf-8", "replace")
                m = _DDE.search(text)
                if m and re.search(r"(?i)(cmd|powershell|mshta|\.exe)", m.group(0)):
                    rep.behavior("office.dde", "high", "Document uses DDE to run a command", "Dynamic Data Exchange fields can launch programs without macros.",
                                 re.sub(r"<[^>]+>", "", m.group(0))[:300], "field-code", n)
                    rep.add_iocs(m.group(0))
        if nl.startswith("xl/macrosheets/"):
            rep.behavior("office.xlm_macro", "high", "Workbook contains Excel 4.0 (XLM) macro sheets", "", n, "part-name", n)
        if nl.startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) or nl.startswith(("word/activex/", "xl/activex/")):
            rep.behavior("office.embedded_object", "high" if not nl.endswith(".xlsx") else "medium", "Document embeds another file or ActiveX control",
                         "", n, "part-name", n)
            blob = read(n)
            if depth < budget.max_depth:
                rep.d["children"].append(child(f"embedded:{safe_name(n.rsplit('/', 1)[-1], 60)}", blob, [], depth + 1, budget))
        if nl.endswith(".js") or nl.endswith(".vbs") or nl.endswith((".exe", ".dll", ".hta")):
            rep.behavior("office.suspicious_part", "high", "Open XML package contains a script or executable part", "", n, "part-name", n)
