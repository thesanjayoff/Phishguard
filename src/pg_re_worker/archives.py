"""Archives are unpacked *in memory only*. Member names are never used as file paths, so path traversal cannot write
anything; it is detected and reported. Size, ratio, count and depth limits stop zip bombs before they are expanded."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import tarfile
import zipfile
import zlib
from typing import Callable

from .core import Budget, BudgetExceeded, Report, ext_of, safe_name

MAX_MEMBER_BYTES = 24 << 20          # one member
MAX_TOTAL_DECLARED = 512 << 20       # sum of declared sizes before we refuse to open it at all
MAX_RATIO = 150                      # declared / compressed
RATIO_MIN_BYTES = 8 << 20            # ratio only matters once the output is big
MAX_ANALYSED_MEMBERS = 25
MAX_LISTED = 4000

Analyse = Callable[[str, bytes, list, int, Budget], dict]

_DRIVE = re.compile(r"^[A-Za-z]:")
_TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)")


def name_problem(name: str) -> str:
    """'' when the member name is an ordinary relative path; otherwise a short description."""
    if "\x00" in name:
        return "NUL byte in name"
    if name.startswith(("/", "\\")) or _DRIVE.match(name):
        return "absolute path"
    if _TRAVERSAL.search(name):
        return "'..' path traversal"
    if "‮" in name:
        return "right-to-left override in name"
    return ""


def _flag_names(rep: Report, names: list[str]) -> None:
    bad = [(n, name_problem(n)) for n in names]
    bad = [(n, p) for n, p in bad if p]
    if bad:
        rep.behavior("archive.path_traversal", "high", "Archive contains member names that try to escape the extraction folder",
                     "A careless extractor would write these files outside the target folder. They were NOT extracted by this analyser.",
                     "\n".join(f"{p}: {safe_name(n, 100)}" for n, p in bad[:15]), "member-names")


def _read_capped(fh, limit: int) -> bytes | None:
    data = fh.read(limit + 1)
    return None if len(data) > limit else data


def analyse_zip(rep: Report, data: bytes, passwords: list[str], depth: int, budget: Budget, child: Analyse, kind: str = "zip") -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        rep.warn(f"damaged ZIP structure ({e})")
        return
    infos = zf.infolist()
    if len(infos) > MAX_LISTED:
        rep.behavior("archive.too_many_members", "medium", f"Archive lists {len(infos)} members", "Possible resource-exhaustion attempt; only the first members were considered.")
        infos = infos[:MAX_LISTED]
    declared = sum(i.file_size for i in infos)
    comp = max(1, len(data))
    ratio = declared / comp
    bomb = declared > MAX_TOTAL_DECLARED or (declared > RATIO_MIN_BYTES and ratio > MAX_RATIO)
    names = [i.filename for i in infos]
    _flag_names(rep, names)
    links = [i.filename for i in infos if ((i.external_attr >> 16) & 0o170000) == 0o120000]
    if links:
        rep.behavior("archive.symlink", "medium", "Archive contains symbolic links", "Symlinks inside archives are used to read or overwrite files outside the extraction folder.",
                     "\n".join(safe_name(n, 100) for n in links[:10]), "member-names")
    if bomb:
        rep.behavior("archive.zip_bomb", "high", "Archive expands to an extreme size (zip bomb)",
                     f"Declares {declared:,} bytes from {len(data):,} compressed bytes (ratio {ratio:,.0f}:1). Not expanded.",
                     f"members={len(infos)} declared={declared} compressed={len(data)}", "archive-header")
        rep.d["children"] = []
        return
    enc = [i for i in infos if i.flag_bits & 0x1]
    if enc:
        rep.d["encrypted"] = True
    listing = [safe_name(n, 100) for n in names[:30]]
    if listing:
        rep.d["strings"] = (rep.d["strings"] + ["member: " + n for n in listing])[:60]
    exe_members = [n for n in names if ext_of(n) in ("exe", "scr", "dll", "js", "vbs", "ps1", "bat", "cmd", "lnk", "hta", "jar", "msi", "iso", "com", "wsf")]
    if exe_members and kind == "zip":
        rep.behavior("archive.executable_member", "medium", "Archive contains executables or scripts", "",
                     "\n".join(safe_name(n, 100) for n in exe_members[:10]), "member-names")

    pw_list = [None] + [p.encode("utf-8", "ignore") for p in passwords]
    analysed = 0
    # interesting members first: executables, documents, scripts; skip noise like directories
    order = sorted((i for i in infos if not i.is_dir()), key=lambda i: (0 if ext_of(i.filename) in (
        "exe", "dll", "scr", "js", "vbs", "ps1", "bat", "cmd", "lnk", "hta", "jar", "docm", "xlsm", "doc", "xls", "pdf", "iso", "html", "htm", "zip", "apk") else 1))
    for info in order:
        if analysed >= MAX_ANALYSED_MEMBERS:
            rep.warn(f"only the first {MAX_ANALYSED_MEMBERS} members were analysed")
            break
        budget.tick()
        if info.file_size > MAX_MEMBER_BYTES:
            rep.warn(f"member '{safe_name(info.filename, 60)}' is larger than {MAX_MEMBER_BYTES >> 20} MB and was skipped")
            continue
        body = None
        is_enc = bool(info.flag_bits & 0x1)
        for pw in (pw_list if is_enc else [None]):
            try:
                with zf.open(info, pwd=pw) as fh:
                    body = _read_capped(fh, MAX_MEMBER_BYTES)
                break
            except NotImplementedError:
                rep.warn("member uses AES encryption or an unsupported method; cannot be opened by the built-in analyser")
                break
            except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
                continue  # wrong password / corrupt: try the next candidate
        if body is None:
            if is_enc:
                rep.warn(f"could not decrypt '{safe_name(info.filename, 60)}' with the password(s) found in the message")
            continue
        if is_enc and pw is not None:
            rep.warn("opened an encrypted member with a password taken from the message text")
            rep.behavior("archive.password_in_message", "medium", "Archive is password-protected and the password is in the message",
                         "Attackers do this so mail scanners cannot open the archive.", "", "", "archive")
        budget.member()
        budget.spend(len(body))
        analysed += 1
        rep.d["children"].append(child(safe_name(info.filename, 150), body, passwords, depth + 1, budget))


def analyse_tar(rep: Report, data: bytes, passwords: list[str], depth: int, budget: Budget, child: Analyse) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as e:
        rep.warn(f"cannot read tar structure ({type(e).__name__})")
        return
    members = []
    for m in tf:
        members.append(m)
        if len(members) >= MAX_LISTED:
            rep.behavior("archive.too_many_members", "medium", "Archive lists an extreme number of members")
            break
    _flag_names(rep, [m.name for m in members])
    odd = [m.name for m in members if m.issym() or m.islnk() or m.isdev()]
    if odd:
        rep.behavior("archive.special_members", "medium", "Archive contains links or device entries", "", "\n".join(safe_name(n, 100) for n in odd[:10]), "member-names")
    declared = sum(max(0, m.size) for m in members)
    if declared > MAX_TOTAL_DECLARED:
        rep.behavior("archive.zip_bomb", "high", "Archive expands to an extreme size", f"Declares {declared:,} bytes. Not expanded.", "", "", "archive-header")
        return
    analysed = 0
    for m in members:
        if not m.isfile() or analysed >= MAX_ANALYSED_MEMBERS or m.size > MAX_MEMBER_BYTES:
            continue
        budget.tick()
        fh = tf.extractfile(m)
        if fh is None:
            continue
        body = _read_capped(fh, MAX_MEMBER_BYTES)
        if body is None:
            continue
        budget.member()
        budget.spend(len(body))
        analysed += 1
        rep.d["children"].append(child(safe_name(m.name, 150), body, passwords, depth + 1, budget))


def analyse_compressed(rep: Report, data: bytes, kind: str, filename: str, passwords: list[str], depth: int, budget: Budget, child: Analyse) -> None:
    """gzip / bzip2 / xz single-stream wrappers, decompressed with a hard output cap (no unbounded expansion)."""
    limit = MAX_MEMBER_BYTES
    try:
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(data, limit + 1)
        elif kind == "bz2":
            d = bz2.BZ2Decompressor()
            out = d.decompress(data, limit + 1)
        else:
            d = lzma.LZMADecompressor()
            out = d.decompress(data, limit + 1)
    except Exception as e:
        rep.warn(f"cannot decompress ({type(e).__name__})")
        return
    if len(out) > limit:
        rep.behavior("archive.zip_bomb", "high", "Compressed stream expands beyond the safe limit", f"More than {limit:,} bytes of output; stopped.", "", "", "stream")
        return
    inner = re.sub(r"(?i)\.(gz|bz2|xz|tgz)$", "", filename) or "decompressed"
    budget.spend(len(out))
    rep.d["children"].append(child(safe_name(inner, 150), out, passwords, depth + 1, budget))
