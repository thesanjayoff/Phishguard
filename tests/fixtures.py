"""Harmless, self-made test samples, built IN MEMORY (nothing is written to disk).

Every sample is inert: macros only contain *strings and a MsgBox*, the PE returns immediately from its entry point and
its "dangerous" calls sit in dead code after the `ret`, the APK/DEX are not installable, the PDF only calls app.alert,
and all addresses use the reserved `.invalid` / `example.invalid` names. They exist so the analyser has features to flag."""
from __future__ import annotations

import io
import struct
import zipfile

ENDOFCHAIN, FREESECT, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
SECTOR, MINI = 512, 64


# ---------------------------------------------------------------------------------------- OLE / CFB + VBA project
def _dir_entry(name: str, etype: int, left: int, right: int, child: int, start: int, size: int) -> bytes:
    nm = (name.encode("utf-16le") + b"\x00\x00") if name else b""
    return (nm.ljust(64, b"\x00") + struct.pack("<HBB", len(nm), etype, 1) + struct.pack("<III", left, right, child)
            + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<QQ", 0, 0) + struct.pack("<IQ", start, size))


def build_cfb(tree: dict) -> bytes:
    """Minimal Compound File Binary (v3) writer. `tree` = {name: bytes | {name: bytes}} (one storage level)."""
    entries: list[dict] = [{"name": "Root Entry", "type": 5, "data": None, "kids": []}]

    def add(parent: dict, name: str, node) -> None:
        e = {"name": name, "type": 1 if isinstance(node, dict) else 2, "data": None if isinstance(node, dict) else node, "kids": []}
        entries.append(e)
        parent["kids"].append(e)
        if isinstance(node, dict):
            for k, v in node.items():
                add(e, k, v)

    for k, v in tree.items():
        add(entries[0], k, v)
    blocks: list[bytes] = []
    fat: list[int] = []

    def chain(data: bytes) -> int:
        n = max(1, -(-len(data) // SECTOR))
        start = len(blocks)
        for i in range(n):
            blocks.append(data[i * SECTOR:(i + 1) * SECTOR].ljust(SECTOR, b"\x00"))
            fat.append(start + i + 1 if i < n - 1 else ENDOFCHAIN)
        return start

    mini_data, mini_fat = bytearray(), []
    for e in entries:
        d = e["data"]
        if d is None:
            e["start"], e["size"] = 0, 0
        elif len(d) < 4096:
            e["start"], e["size"] = len(mini_fat), len(d)
            n = max(1, -(-len(d) // MINI))
            for i in range(n):
                mini_fat.append(len(mini_fat) + 1 if i < n - 1 else ENDOFCHAIN)
            mini_data += d.ljust(n * MINI, b"\x00")
        else:
            e["start"], e["size"] = chain(d), len(d)
    root = entries[0]
    root["start"], root["size"] = (chain(bytes(mini_data)) if mini_data else ENDOFCHAIN), len(mini_data)
    mini_fat_start, n_mini_fat = ENDOFCHAIN, 0
    if mini_fat:
        raw = struct.pack(f"<{len(mini_fat)}I", *mini_fat).ljust(-(-len(mini_fat) * 4 // SECTOR) * SECTOR, b"\xff")
        mini_fat_start, n_mini_fat = chain(raw), len(raw) // SECTOR

    for i, e in enumerate(entries):
        e["id"] = i

    def key(e):  # CFB directory ordering: shorter names first, then upper-case compare
        return (len(e["name"]), e["name"].upper())

    for e in entries:
        kids = sorted(e["kids"], key=key)
        e["child"] = kids[0]["id"] if kids else FREESECT
        for a, b in zip(kids, kids[1:]):
            a["right"] = b["id"]
    dirb = bytearray()
    for e in entries:
        dirb += _dir_entry(e["name"], e["type"], FREESECT, e.get("right", FREESECT), e["child"], e["start"], e["size"])
    while len(dirb) % SECTOR:  # unused directory slots
        dirb += _dir_entry("", 0, FREESECT, FREESECT, FREESECT, 0, 0)
    dir_start = chain(bytes(dirb))
    n_fat = 1
    while n_fat * 128 < len(blocks) + n_fat:
        n_fat += 1
    fat_start = len(blocks)
    for _ in range(n_fat):
        blocks.append(b"")
        fat.append(FATSECT)
    table = (fat + [FREESECT] * (n_fat * 128 - len(fat)))
    for i in range(n_fat):
        blocks[fat_start + i] = struct.pack("<128I", *table[i * 128:(i + 1) * 128])
    difat = [fat_start + i for i in range(n_fat)] + [FREESECT] * (109 - n_fat)
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, 4096, mini_fat_start, n_mini_fat, ENDOFCHAIN, 0)
              + struct.pack("<109I", *difat))
    return header + b"".join(blocks)


def ovba_compress(raw: bytes) -> bytes:
    """MS-OVBA container using literal-only tokens (valid, just not small). Keep `raw` under ~3600 bytes (one chunk)."""
    assert len(raw) <= 3600, "fixture too large for a single literal chunk"
    body = bytearray()
    for i in range(0, len(raw), 8):
        body += b"\x00" + raw[i:i + 8]
    return b"\x01" + struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + bytes(body)


def _rec(rid: int, data: bytes) -> bytes:
    return struct.pack("<HI", rid, len(data)) + data


def build_vba_project(modules: dict[str, str]) -> bytes:
    """vbaProject.bin with the given standard modules (name -> source). Source is stored but is never executed here."""
    d = bytearray()
    d += _rec(0x0001, struct.pack("<I", 1)) + _rec(0x0002, struct.pack("<I", 0x409)) + _rec(0x0014, struct.pack("<I", 0x409))
    d += _rec(0x0003, struct.pack("<H", 1252)) + _rec(0x0004, b"VBAProject")
    d += _rec(0x0005, b"") + _rec(0x0040, b"") + _rec(0x0006, b"") + _rec(0x003D, b"")
    d += _rec(0x0007, struct.pack("<I", 0)) + _rec(0x0008, struct.pack("<I", 0))
    d += struct.pack("<HIIH", 0x0009, 4, 1, 0)
    d += _rec(0x000C, b"") + _rec(0x003C, b"")
    d += _rec(0x000F, struct.pack("<H", len(modules))) + _rec(0x0013, struct.pack("<H", 0xFFFF))
    for name in modules:
        n = name.encode("ascii")
        d += _rec(0x0019, n) + _rec(0x0047, name.encode("utf-16le")) + _rec(0x001A, n) + _rec(0x0032, name.encode("utf-16le"))
        d += _rec(0x001C, b"") + _rec(0x0048, b"") + _rec(0x0031, struct.pack("<I", 0)) + _rec(0x001E, struct.pack("<I", 0))
        d += _rec(0x002C, struct.pack("<H", 0xFFFF)) + _rec(0x0021, b"") + _rec(0x002B, b"")
    d += _rec(0x0010, b"")
    vba = {"dir": ovba_compress(bytes(d)), "_VBA_PROJECT": bytes.fromhex("cc61ffff000000")}
    for name, src in modules.items():
        vba[name] = ovba_compress(src.replace("\n", "\r\n").encode("ascii"))
    project = "ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n" + "".join(f"Module={n}\r\n" for n in modules) + "Name=\"VBAProject\"\r\n"
    return build_cfb({"PROJECT": project.encode(), "VBA": vba})


INERT_VBA = '''Attribute VB_Name = "Module1"
Sub AutoOpen()
    MsgBox "PhishGuard test document - harmless"
End Sub

Sub NeverCalled()
    ' Inert: the strings below exist only so a static analyser has something to flag. Nothing here is ever executed.
    Dim a As String, b As String, c As String, d As String
    a = "http://example.invalid/test/payload.exe"
    b = "URLDownloadToFileA"
    c = "WScript.Shell"
    d = "powershell -nop -w hidden"
End Sub
'''


def build_docx(vba_modules: dict[str, str] | None = None, remote_template: str | None = None, dde: str | None = None) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        body = "<w:p><w:r><w:t>Hello</w:t></w:r></w:p>"
        if dde:
            body += f'<w:p><w:r><w:instrText xml:space="preserve"> DDEAUTO {dde} </w:instrText></w:r></w:p>'
        z.writestr("word/document.xml", f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>')
        rels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        if remote_template:
            rels += ('<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                     f'Target="{remote_template}" TargetMode="External"/>')
        rels += "</Relationships>"
        z.writestr("word/_rels/settings.xml.rels", rels)
        if vba_modules:
            z.writestr("word/vbaProject.bin", build_vba_project(vba_modules))
    return bio.getvalue()


# ---------------------------------------------------------------------------------------- PE (never executed)
def build_pe(imports: dict[str, list[str]], dead_calls: bool = True, section_names: tuple[str, str] = (".text", ".idata"),
             text_flags: int = 0x60000020) -> bytes:
    """A tiny PE32 whose entry point is `xor eax,eax; ret`. Calls to the listed imports exist only as dead code after the ret."""
    base, text_rva, idata_rva = 0x400000, 0x1000, 0x2000
    # --- .idata
    dlls = list(imports)
    desc_size = 20 * (len(dlls) + 1)
    blob = bytearray(desc_size)
    pos = desc_size
    layout: dict[str, tuple[int, int]] = {}  # dll -> (ilt_off, iat_off)
    thunks_total = sum(len(v) + 1 for v in imports.values())
    ilt_base = pos
    iat_base = pos + 4 * thunks_total
    blob += b"\x00" * (8 * thunks_total)
    pos = len(blob)
    name_rva: dict[str, int] = {}
    iat_va: dict[str, int] = {}
    t = 0
    for dll in dlls:
        layout[dll] = (ilt_base + 4 * t, iat_base + 4 * t)
        for j, fn in enumerate(imports[dll]):
            hn = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(hn) % 2:
                hn += b"\x00"
            rva = idata_rva + len(blob)
            blob += hn
            struct.pack_into("<I", blob, ilt_base + 4 * (t + j), rva)
            struct.pack_into("<I", blob, iat_base + 4 * (t + j), rva)
            iat_va[fn] = base + idata_rva + iat_base + 4 * (t + j)
        t += len(imports[dll]) + 1
    for i, dll in enumerate(dlls):
        name_rva[dll] = idata_rva + len(blob)
        blob += dll.encode() + b"\x00"
        ilt, iat = layout[dll]
        struct.pack_into("<IIIII", blob, 20 * i, idata_rva + ilt, 0, 0, name_rva[dll], idata_rva + iat)
    idata = bytes(blob).ljust(-(-len(blob) // 0x200) * 0x200, b"\x00")
    # --- .text: entry = xor eax,eax ; ret   (then dead code)
    code = bytearray(b"\x31\xc0\xc3" + b"\x90" * 5)
    if dead_calls:
        for fn in [f for v in imports.values() for f in v]:
            code += b"\x6a\x00" + b"\xff\x15" + struct.pack("<I", iat_va[fn]) + b"\x85\xc0"  # push 0 ; call [IAT] ; test eax,eax
    text = bytes(code).ljust(-(-len(code) // 0x200) * 0x200, b"\x00")
    # --- headers
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    stub = b"This program cannot be run in DOS mode.\r\r\n$".ljust(0x40, b"\x00")
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0x5F000000, 0, 0, 224, 0x0102)
    size_image = idata_rva + (-(-len(idata) // 0x1000) + 1) * 0x1000
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, len(text), len(idata), 0, text_rva, text_rva, idata_rva, base,
                      0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, size_image, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 8, idata_rva + 0, desc_size)  # import directory
    sec1 = section_names[0].encode().ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", len(code), text_rva, len(text), 0x200, 0, 0, 0, 0, text_flags)
    sec2 = section_names[1].encode().ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", len(blob), idata_rva, len(idata), 0x200 + len(text), 0, 0, 0, 0, 0xC0000040)
    hdr = dos + stub + b"PE\x00\x00" + coff + opt + bytes(dirs) + sec1 + sec2
    return hdr.ljust(0x200, b"\x00") + text + idata


# ---------------------------------------------------------------------------------------- APK (not installable)
def _axml(tags: list[tuple[str, dict[str, str]]]) -> bytes:
    strs: list[str] = []

    def idx(s: str) -> int:
        if s not in strs:
            strs.append(s)
        return strs.index(s)

    body = bytearray()
    for tag, attrs in tags:
        n = idx(tag)
        at = [(idx(k), idx(v)) for k, v in attrs.items()]
        # start-tag chunk: header(8) + lineNumber + comment + ns + name + attrStart/Size/Count + id/class/style = 36 bytes
        body += struct.pack("<HHIIiiiHHHHHH", 0x0102, 16, 36 + 20 * len(at), 1, -1, -1, n, 20, 20, len(at), 0, 0, 0)
        for k, v in at:
            body += struct.pack("<iiiHBBI", -1, k, v, 8, 0, 3, v)
        body += struct.pack("<HHIIiii", 0x0103, 16, 24, 1, -1, -1, n)
    pool = bytearray()
    offs = []
    for s in strs:
        offs.append(len(pool))
        pool += struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\x00\x00"
    while len(pool) % 4:
        pool += b"\x00"
    pool_hdr_size = 28 + 4 * len(strs)
    pool_chunk = struct.pack("<HHIIIIII", 0x0001, 28, pool_hdr_size + len(pool), len(strs), 0, 0, pool_hdr_size, 0) + struct.pack(f"<{len(offs)}I", *offs) + bytes(pool)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool_chunk) + len(body)) + pool_chunk + bytes(body)


def _dex(strings: list[str]) -> bytes:
    off = 0x70 + 4 * len(strings)
    data, offs = bytearray(), []
    for s in strings:
        offs.append(off + len(data))
        b = s.encode("utf-8")
        data += bytes([len(s)]) + b + b"\x00"
    total = off + len(data)
    hdr = b"dex\n035\x00" + b"\x00" * 24 + struct.pack("<IIIIIII", total, 0x70, 0x12345678, 0, 0, 0, len(strings)) + struct.pack("<I", 0x70)
    return hdr.ljust(0x70, b"\x00") + struct.pack(f"<{len(offs)}I", *offs) + bytes(data)


def build_fake_apk() -> bytes:
    perms = ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"]
    tags = [("manifest", {"package": "invalid.phishguard.test"})] + [("uses-permission", {"name": p}) for p in perms]
    tags += [("receiver", {"name": "invalid.phishguard.test.Rx"}), ("action", {"name": "android.provider.Telephony.SMS_RECEIVED"})]
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("AndroidManifest.xml", _axml(tags))
        z.writestr("classes.dex", _dex(["Landroid/telephony/SmsManager;", "sendTextMessage", "Ldalvik/system/DexClassLoader;", "http://example.invalid/c2"]))
    return bio.getvalue()


# ---------------------------------------------------------------------------------------- PDF, scripts, archives
def build_pdf(js: str | None = "app.alert('PhishGuard test');", uri: str | None = "http://example.invalid/pdf-test", obfuscate: bool = False) -> bytes:
    key = "/J#53" if obfuscate else "/JS"
    parts = ["%PDF-1.4", "1 0 obj << /Type /Catalog /Pages 2 0 R " + ("/OpenAction 4 0 R " if js else "") + ">> endobj",
             "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
             "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] " + ("/Annots [5 0 R] " if uri else "") + ">> endobj"]
    if js:
        parts.append(f"4 0 obj << /S /JavaScript {key} ({js}) >> endobj")
    if uri:
        parts.append(f"5 0 obj << /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A << /S /URI /URI ({uri}) >> >> endobj")
    parts += ["trailer << /Root 1 0 R >>", "%%EOF"]
    return "\n".join(parts).encode()


def zip_bytes(members: dict[str, bytes], flag_encrypted: set[str] | None = None) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            zi = zipfile.ZipInfo(name)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
            if flag_encrypted and name in flag_encrypted:
                z.infolist()[-1].flag_bits |= 0x1
    return bio.getvalue()
