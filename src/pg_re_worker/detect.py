"""Identify what a file *really* is from its bytes, and whether that disagrees with its extension."""
from __future__ import annotations

import io
import re
import struct
import zipfile

from .core import ext_of

DOC_EXTS = {"doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlam", "ppt", "pptx", "pptm", "rtf", "odt", "ods"}
PLAIN_EXTS = {"pdf", "jpg", "jpeg", "png", "gif", "bmp", "txt", "csv", "mp3", "mp4", "wav", "avi", "ico", "tif", "tiff", "webp"}
SCRIPT_EXTS = {"js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "bat", "cmd", "sh", "py", "html", "htm", "svg", "xml", "sct"}
EXEC_KINDS = {"pe", "elf", "macho", "lnk", "apk", "iso"}

_HTML = re.compile(rb"(?is)^\s*(?:<!doctype html|<html|<head|<body|<script|<form|<svg|<\?xml)")
_PS = re.compile(rb"(?i)(?:\$[a-z_]\w*\s*=|invoke-expression|\bfunction\s+\w+|-executionpolicy|param\s*\(|write-host|\[system\.)")
_VBS = re.compile(rb"(?i)(?:\bdim\s+\w+|createobject\s*\(|wscript\.|\bsub\s+\w+|\bset\s+\w+\s*=\s*createobject|on error resume next)")
_JS = re.compile(rb"(?i)(?:\bfunction\s*\w*\s*\(|\bvar\s+\w+\s*=|activexobject|wscript\.shell|document\.write|\beval\s*\(|\bconst\s+\w+\s*=)")
_BAT = re.compile(rb"(?im)^\s*(?:@echo\s+off|set\s+\w+=|start\s+|cmd\s+/c|goto\s+|if\s+(?:not\s+)?exist)")


def _looks_text(data: bytes) -> bool:
    head = data[:4096]
    if not head:
        return True
    if b"\x00" in head and not (head[:2] in (b"\xff\xfe", b"\xfe\xff")):
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(head) > 0.92


def detect(filename: str, data: bytes) -> tuple[str, str]:
    """-> (kind, human label). kind in: pe elf macho lnk apk jar ooxml ole pdf rtf zip tar gzip bz2 xz 7z rar cab iso image html script text unknown"""
    h = data[:16]
    ext = ext_of(filename)
    if h[:2] == b"MZ" and len(data) > 0x40:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if off < len(data) - 4 and data[off:off + 4] == b"PE\x00\x00":
            return "pe", "PE executable (Windows EXE/DLL)"
        return "pe", "DOS/MZ executable"
    if h[:4] == b"\x7fELF":
        return "elf", "ELF executable (Linux)"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho", "Mach-O / Java class binary"
    if h[:4] == b"L\x00\x00\x00" and data[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
        return "lnk", "Windows shortcut (.lnk)"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole", "OLE2 compound file (legacy Office / MSI)"
    if h[:5] == b"%PDF-" or b"%PDF-" in data[:1024]:
        return "pdf", "PDF document"
    if h[:5] == b"{\\rtf" or data[:8].lower().startswith(b"{\\rtf"):
        return "rtf", "Rich Text Format"
    if h[:4] == b"PK\x03\x04" or h[:4] == b"PK\x05\x06":
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except Exception:
            return "zip", "ZIP archive (damaged)"
        lower = [n.lower() for n in names]
        if "androidmanifest.xml" in lower and any(n.endswith(".dex") for n in lower):
            return "apk", "Android package (APK)"
        if "meta-inf/manifest.mf" in lower:
            return "jar", "Java archive (JAR)"
        if "[content_types].xml" in lower:
            macro = any(n.endswith("vbaproject.bin") for n in lower)
            for prefix, nm in (("word/", "Word"), ("xl/", "Excel"), ("ppt/", "PowerPoint")):
                if any(n.startswith(prefix) for n in lower):
                    return "ooxml", f"{nm} document (Open XML{', macro-enabled' if macro else ''})"
            return "ooxml", "Open XML document"
        return "zip", "ZIP archive"
    if h[:2] == b"\x1f\x8b":
        return "gzip", "gzip-compressed data"
    if h[:3] == b"BZh":
        return "bz2", "bzip2-compressed data"
    if h[:6] == b"\xfd7zXZ\x00":
        return "xz", "xz-compressed data"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z", "7-Zip archive"
    if h[:7] == b"Rar!\x1a\x07\x00" or h[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar", "RAR archive"
    if h[:4] == b"MSCF":
        return "cab", "Windows cabinet (CAB)"
    if data[257:262] == b"ustar":
        return "tar", "tar archive"
    if data[0x8001:0x8006] == b"CD001" or data[0x9001:0x9006] == b"CD001":
        return "iso", "ISO 9660 disk image"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "image", "PNG image"
    if h[:3] == b"\xff\xd8\xff":
        return "image", "JPEG image"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "image", "GIF image"
    if _looks_text(data):
        head = data[:20000]
        if h[:2] in (b"\xff\xfe", b"\xfe\xff"):
            try:
                head = data[:40000].decode("utf-16", "ignore").encode("utf-8", "ignore")
            except Exception:
                pass
        if _HTML.match(head.lstrip(b"\xef\xbb\xbf")) or ext in ("html", "htm", "svg", "mht", "hta"):
            return "html", "HTML/SVG document" if ext != "hta" else "HTML application (HTA)"
        if ext in ("ps1", "psm1") or (_PS.search(head) and ext not in ("js", "vbs", "bat", "cmd")):
            return "script", "PowerShell script"
        if ext in ("vbs", "vbe", "wsf", "wsh") or (_VBS.search(head) and ext not in ("js", "bat", "cmd")):
            return "script", "VBScript / Windows Script"
        if ext in ("js", "jse") or _JS.search(head):
            return "script", "JavaScript (Windows Script Host or browser)"
        if ext in ("bat", "cmd") or _BAT.search(head):
            return "script", "Windows batch script"
        if ext == "sh" or head.startswith(b"#!"):
            return "script", "Shell script"
        return "text", "Plain text"
    return "unknown", "Unrecognised binary data"


IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "bmp", "ico", "tif", "tiff", "webp"}
OOXML_EXTS = {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xlam", "pptx", "pptm"}
OLE_EXTS = {"doc", "dot", "xls", "ppt"}


def type_mismatch(filename: str, kind: str) -> bool:
    """True when the content is something other than what the extension promises (e.g. 'invoice.pdf' that is an EXE)."""
    ext = ext_of(filename)
    if not ext:
        return False
    if ext in ("txt", "csv"):
        return kind in EXEC_KINDS
    if ext in DOC_EXTS | PLAIN_EXTS:
        if kind in EXEC_KINDS:
            return True
        if ext == "pdf":
            return kind not in ("pdf", "unknown")
        if ext in IMAGE_EXTS:
            return kind in ("pdf", "ole", "ooxml", "zip", "rar", "7z", "script", "html")
        if ext in OOXML_EXTS:
            return kind not in ("ooxml", "ole", "rtf", "unknown", "html", "text")
        if ext in OLE_EXTS:
            return kind not in ("ole", "ooxml", "rtf", "unknown", "html", "text")
        if ext == "rtf":
            return kind not in ("rtf", "unknown", "text")
        return False
    if ext in ("exe", "dll", "scr", "com", "sys"):
        return kind not in ("pe", "unknown")
    if ext == "zip":
        return kind in EXEC_KINDS - {"apk"}
    return False
