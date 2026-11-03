"""Dispatcher: identify the file, run the matching static analysers, collect everything into one report."""
from __future__ import annotations

import logging
import re
from typing import Sequence

from . import apk, archives, office, pdf, pe, scripts
from .core import Budget, BudgetExceeded, Report, entropy, ext_of, printable_strings, safe_name
from .detect import detect, type_mismatch

log = logging.getLogger("pg_re_worker")
_LNK_CMD = re.compile(rb"(?i)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|\\users\\public|%temp%|%appdata%)")


def _lnk(rep: Report, data: bytes) -> None:
    """Shortcut files are launchers: the interesting part is the command line they run."""
    text16 = data.decode("utf-16le", "ignore")
    strings = printable_strings(data)
    cmd_lines = [s for s in strings if _LNK_CMD.search(s.encode("utf-8", "ignore"))]
    blob = "\n".join(cmd_lines) or "\n".join(re.findall(r"[\x20-\x7e]{12,}", text16)[:10])
    if cmd_lines:
        rep.behavior("lnk.command", "high", "Shortcut runs a command line when opened",
                     "Shortcuts disguised as documents are a common first stage.", blob[:1200], "strings", "shell link data")
    else:
        rep.behavior("lnk.shortcut", "medium", "Windows shortcut file (a launcher, not a document)", "", blob[:600], "strings", "shell link data")
    rep.add_iocs(blob + "\n" + "\n".join(strings))
    rep.d["strings"] = strings


def _rtf(rep: Report, data: bytes) -> None:
    low = data[:6 << 20].lower()
    for key, title, sev in ((b"\\objdata", "RTF embeds an OLE object", "high"), (b"\\objupdate", "RTF forces an embedded object to update/run on open", "high"),
                            (b"equation.3", "RTF references the Equation Editor (CVE-2017-11882 class exploits)", "high"),
                            (b"\\*\\objclass", "RTF declares an embedded object class", "medium")):
        i = low.find(key)
        if i >= 0:
            rep.behavior("rtf." + key.decode().strip("\\*").replace(".", "_"), sev, title, "", data[max(0, i - 40): i + 120].decode("latin-1", "replace"), "source", f"offset {i}")
    if re.search(rb"(?i)\\bin\d{4,}|(?:[0-9a-f]{2}){200,}", low[:4 << 20]):
        rep.behavior("rtf.hex_blob", "medium", "RTF contains a very large hexadecimal blob (hidden embedded data)", "")
    rep.add_iocs(data[:2 << 20].decode("latin-1", "replace"), binary=True)


def _image(rep: Report, data: bytes) -> None:
    end = None
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        i = data.rfind(b"IEND")
        end = i + 8 if i >= 0 else None
    elif data[:3] == b"\xff\xd8\xff":
        i = data.rfind(b"\xff\xd9")
        end = i + 2 if i >= 0 else None
    elif data[:3] == b"GIF":
        i = data.rfind(b"\x3b")
        end = i + 1 if i >= 0 else None
    if end and len(data) - end > 512:
        tail = data[end:]
        rep.behavior("image.trailing_data", "high" if tail[:2] in (b"MZ", b"PK") or tail[:5] == b"%PDF-" else "medium",
                     f"{len(tail):,} bytes follow the end of the image (polyglot / hidden payload)", "", tail[:64].hex(" "), "hex", f"offset {end:#x}")


def analyze_bytes(filename: str, data: bytes, passwords: Sequence[str], depth: int, budget: Budget) -> dict:
    rep = Report(filename, data)
    pw = list(passwords)
    try:
        budget.tick()
        kind, label = detect(filename, data)
        rep.d["file_type"] = label
        rep.d["type_mismatch"] = type_mismatch(filename, kind)
        if kind in ("pe", "elf", "macho", "unknown") and rep.d["entropy"] > 7.2 and len(data) > 4096:
            rep.d["packed"] = True
        if depth > budget.max_depth:
            rep.warn("maximum nesting depth reached; not analysed further")
            return rep.d
        child = analyze_bytes
        if kind == "pe":
            pe.analyse_pe(rep, data, depth, budget, child)
        elif kind == "ole":
            office.analyse_ole(rep, data, depth, budget, child)
            rep.add_iocs("\n".join(printable_strings(data)), binary=True)
        elif kind == "ooxml":
            office.analyse_ooxml(rep, data, depth, budget, child)
        elif kind == "pdf":
            pdf.analyse_pdf(rep, data, depth, budget, child)
        elif kind == "apk":
            apk.analyse_apk(rep, data, depth, budget)
        elif kind in ("zip", "jar"):
            archives.analyse_zip(rep, data, pw, depth, budget, child, kind)
        elif kind == "tar":
            archives.analyse_tar(rep, data, pw, depth, budget, child)
        elif kind in ("gzip", "bz2", "xz"):
            archives.analyse_compressed(rep, data, kind, filename, pw, depth, budget, child)
        elif kind in ("script", "html"):
            scripts.analyse_script(rep, data, kind, filename)
        elif kind == "lnk":
            _lnk(rep, data)
        elif kind == "rtf":
            _rtf(rep, data)
        elif kind == "image":
            _image(rep, data)
        elif kind in ("7z", "rar", "cab"):
            rep.warn(f"{label}: the built-in analyser cannot unpack this format, so its contents were not examined. "
                     "Use a custom adapter (attachments.adapter = \"command\") if you need that.")
            if kind == "rar" and data[:8] == b"Rar!\x1a\x07\x01\x00":
                pass
        elif kind == "iso":
            rep.behavior("disk.iso_image", "medium", "Disk image attachment: its files are not scanned by most mail filters", "The built-in analyser lists no members for ISO images.",
                         "", "", "container")
            rep.warn("ISO contents were not examined.")
        elif kind in ("elf", "macho", "unknown"):
            strings = printable_strings(data)
            rep.d["strings"] = strings
            rep.add_iocs("\n".join(strings), binary=True)
            if kind != "unknown":
                rep.warn(f"{label}: only strings and entropy were examined (no disassembly for this format).")
        else:  # plain text
            rep.d["strings"] = [l.strip()[:200] for l in data[:20000].decode("utf-8", "replace").splitlines() if l.strip()][:20]
            rep.add_iocs(data[:400_000].decode("utf-8", "replace"))
    except BudgetExceeded as e:
        rep.error(f"analysis stopped: {e}")
    except Exception as e:  # one bad parser must not lose the rest of the report
        log.warning("analysis step failed: %s", type(e).__name__)
        rep.error(f"analysis step failed: {type(e).__name__}: {safe_name(str(e), 120)}")
    return rep.d
