"""Windows PE files: imports, sections, packing, embedded payloads - with disassembly of the code around the calls
that justify each flag. The file is parsed, never loaded or run."""
from __future__ import annotations

import re
import struct
import time
from typing import Callable

from .core import Budget, Report, entropy, printable_strings, safe_name

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None
try:
    import capstone
except ImportError:  # pragma: no cover
    capstone = None

# normalised (lower-case, no A/W/Ex suffix) API names grouped by what they allow
G_INJECT_CORE = {"writeprocessmemory", "ntwritevirtualmemory", "setthreadcontext", "queueuserapc", "createremotethread", "ntcreatethread", "rtlcreateuserthread", "ntunmapviewofsection"}
G_INJECT_AUX = {"virtualalloc", "virtualallocex", "openprocess", "resumethread", "ntcreatethreadex", "virtualprotect", "ntallocatevirtualmemory", "getthreadcontext", "suspendthread"}
G_DOWNLOAD = {"urldownloadtofile", "internetopenurl", "internetreadfile", "httpsendrequest", "winhttpopen", "winhttpsendrequest", "winhttpreaddata", "internetopen", "internetconnect", "urldownloadtocachefile"}
G_EXEC = {"winexec", "shellexecute", "createprocess", "createprocessasuser", "createprocesswithlogon", "shellexecuteex"}
G_ANTIDEBUG = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring", "ntsetinformationthread", "zwqueryinformationprocess"}
G_KEYLOG = {"setwindowshook", "getasynckeystate", "getkeyboardstate", "getkeystate", "registerrawinputdevices", "getrawinputdata"}
G_CRYPT = {"cryptencrypt", "cryptgenkey", "cryptacquirecontext", "bcryptencrypt", "cryptderivekey", "cryptimportkey"}
G_FILES = {"findfirstfile", "findnextfile", "movefile", "deletefile", "setfileattributes"}
G_REGISTRY = {"regsetvalue", "regcreatekey", "regopenkey"}
G_SERVICE = {"createservice", "startservice", "changeserviceconfig", "openscmanager"}
ALL_KNOWN = (G_INJECT_CORE | G_INJECT_AUX | G_DOWNLOAD | G_EXEC | G_ANTIDEBUG | G_KEYLOG | G_CRYPT | G_FILES | G_REGISTRY | G_SERVICE
             | {"loadlibrary", "getprocaddress", "adjusttokenprivileges"})
PACKER_SECTIONS = {"upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".vmp2", ".petite", ".mpress1", ".mpress2",
                   ".nsp0", ".nsp1", ".enigma1", ".enigma2", "pec1", "pec2", ".yp", ".packed", ".rmnet"}
IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE = 0x20000000, 0x80000000
RUN_KEY = re.compile(rb"(?i)(?:C\x00?U\x00?R\x00?R\x00?E\x00?N\x00?T\x00?V\x00?E\x00?R\x00?S\x00?I\x00?O\x00?N\x00?\\\x00?R\x00?U\x00?N)")


def norm(name: str) -> str:
    n = name.lower()
    for suf in ("a", "w", "ex", "exa", "exw"):
        if n.endswith(suf) and n[: -len(suf)] in ALL_KNOWN:
            return n[: -len(suf)]
    return n


class _Disasm:
    def __init__(self, pe, data: bytes):
        self.ok = capstone is not None
        self.pe, self.data = pe, data
        if not self.ok:
            return
        is64 = pe.FILE_HEADER.Machine == 0x8664
        if pe.FILE_HEADER.Machine not in (0x14C, 0x8664):
            self.ok = False
            return
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
        self.is64 = is64

    def at_offset(self, off: int, count: int = 14, va: int | None = None) -> str:
        if not self.ok or off < 0 or off >= len(self.data):
            return ""
        va = va if va is not None else self.pe.OPTIONAL_HEADER.ImageBase + (self.pe.get_rva_from_offset(off) or 0)
        lines = []
        for i in self.md.disasm(self.data[off: off + 15 * count], va):
            lines.append(f"{i.address:08x}  {i.bytes.hex():<18} {i.mnemonic} {i.op_str}".rstrip())
            if len(lines) >= count:
                break
        return "\n".join(lines)

    def around_call(self, off: int, va: int, before: int = 5, after: int = 5) -> str:
        """Disassemble a window that contains the instruction at `off`, choosing a start that lands on an instruction boundary."""
        if not self.ok:
            return ""
        for back in range(28, -1, -1):
            start = off - back
            if start < 0:
                continue
            insns = list(self.md.disasm(self.data[start: off + 15 * (after + 1)], va - back))
            idx = next((k for k, i in enumerate(insns) if i.address == va), None)
            if idx is None:
                continue
            sel = insns[max(0, idx - before): idx + after + 1]
            return "\n".join(f"{('=> ' if i.address == va else '   ')}{i.address:08x}  {i.mnemonic} {i.op_str}".rstrip() for i in sel)
        return ""


def _call_sites(pe, data: bytes, budget: Budget) -> dict[str, tuple[int, int]]:
    """import name (normalised) -> (file offset, VA) of the first `call/jmp [IAT slot]` that uses it."""
    slots: dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name and imp.address:
                slots[imp.address] = norm(imp.name.decode("latin-1", "replace"))
    out: dict[str, tuple[int, int]] = {}
    if not slots:
        return out
    is64 = pe.FILE_HEADER.Machine == 0x8664
    base = pe.OPTIONAL_HEADER.ImageBase
    for sec in pe.sections:
        if not sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            continue
        raw = data[sec.PointerToRawData: sec.PointerToRawData + sec.SizeOfRawData]
        for m in re.finditer(rb"\xff[\x15\x25]", raw):
            budget.tick()
            p = m.start()
            if p + 6 > len(raw):
                break
            operand = struct.unpack_from("<i" if is64 else "<I", raw, p + 2)[0]
            va = base + sec.VirtualAddress + p
            target = (va + 6 + operand) if is64 else operand
            name = slots.get(target)
            if name and name not in out:
                out[name] = (sec.PointerToRawData + p, va)
    return out


def analyse_pe(rep: Report, data: bytes, depth: int, budget: Budget, child: Callable) -> None:
    if pefile is None:
        rep.warn("pefile is not installed in this image; PE structure was not parsed")
        return
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        rep.behavior("pe.malformed", "medium", "Executable header is malformed", f"The PE parser rejected it ({type(e).__name__}). Malformed headers are used to confuse analysis tools.", "", "", "headers")
        return
    try:
        dis = _Disasm(pe, data)
        m = pe.FILE_HEADER.Machine
        arch = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(m, hex(m))
        kind = "DLL" if pe.FILE_HEADER.Characteristics & 0x2000 else "EXE"
        rep.d["file_type"] = f"PE32{'+' if pe.OPTIONAL_HEADER.Magic == 0x20B else ''} {kind} ({arch})"
        # --- imports
        imports: list[str] = []
        names: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("latin-1", "replace").lower()
            for imp in entry.imports:
                nm = imp.name.decode("latin-1", "replace") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append(f"{dll}!{nm}")
                names.add(norm(nm))
        rep.d["imports"] = imports[:150]
        sites = _call_sites(pe, data, budget) if dis.ok else {}

        def snippet_for(group: set[str]) -> tuple[str, str, str]:
            hits = sorted(n for n in names if n in group)
            for n in hits:
                if n in sites:
                    off, va = sites[n]
                    txt = dis.around_call(off, va)
                    if txt:
                        return f"imports: {', '.join(hits[:8])}\n--- code that calls {n} ---\n{txt}", "imports+disasm", f"call site {va:#x}"
            return "imports: " + ", ".join(hits[:12]), "imports", "import table"

        inj_core, inj_aux = names & G_INJECT_CORE, names & G_INJECT_AUX
        if inj_core and len(inj_core | inj_aux) >= 3:
            s, k, loc = snippet_for(G_INJECT_CORE | G_INJECT_AUX)
            rep.behavior("pe.process_injection", "critical", "Imports the functions needed to inject code into other processes",
                         f"Writes into another process's memory and starts or redirects a thread there: {', '.join(sorted(inj_core | inj_aux))}.", s, k, loc)
        dl, ex = names & G_DOWNLOAD, names & G_EXEC
        if dl and ex:
            s, k, loc = snippet_for(G_DOWNLOAD)
            rep.behavior("pe.download_exec", "high", "Can download data from the internet and launch programs",
                         f"Network: {', '.join(sorted(dl))}; execution: {', '.join(sorted(ex))}.", s, k, loc)
        elif dl:
            s, k, loc = snippet_for(G_DOWNLOAD)
            rep.behavior("pe.network", "low", "Uses internet download functions", ", ".join(sorted(dl)), s, k, loc)
        if len(names & G_ANTIDEBUG) >= 2:
            s, k, loc = snippet_for(G_ANTIDEBUG)
            rep.behavior("pe.anti_debug", "medium", "Checks whether it is being debugged", ", ".join(sorted(names & G_ANTIDEBUG)), s, k, loc)
        if "setwindowshook" in names and (names & {"getasynckeystate", "getkeyboardstate"}):
            s, k, loc = snippet_for(G_KEYLOG)
            rep.behavior("pe.keylogger", "high", "Imports keyboard-hooking functions (keylogger behaviour)", ", ".join(sorted(names & G_KEYLOG)), s, k, loc)
        if names & G_CRYPT and names & G_FILES:
            s, k, loc = snippet_for(G_CRYPT)
            rep.behavior("pe.file_encryption", "medium", "Can encrypt files it finds (ransomware-like combination)", ", ".join(sorted(names & (G_CRYPT | G_FILES))), s, k, loc)
        if names & G_SERVICE and "createservice" in names:
            s, k, loc = snippet_for(G_SERVICE)
            rep.behavior("pe.service_install", "medium", "Can install a Windows service", ", ".join(sorted(names & G_SERVICE)), s, k, loc)
        if names & G_REGISTRY and RUN_KEY.search(data):
            s, k, loc = snippet_for(G_REGISTRY)
            rep.behavior("pe.persistence", "high", "Writes to the registry and mentions the Windows start-up 'Run' key",
                         "Programs add themselves here to run at every log-on.", s, k, loc)
        if len(imports) <= 6 and ("loadlibrary" in names or "getprocaddress" in names):
            rep.behavior("pe.minimal_imports", "medium", "Almost no imports: resolves functions at run time",
                         f"Only {len(imports)} imported function(s). Packed programs and shellcode loaders look like this.",
                         "imports: " + ", ".join(imports[:10]), "imports", "import table")

        # --- sections / packing
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_off = pe.get_offset_from_rva(ep_rva) if ep_rva else None
        ep_disasm = dis.at_offset(ep_off) if (dis.ok and ep_off is not None) else ""
        sec_lines, hot = [], []
        for s in pe.sections:
            nm = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            e = entropy(s.get_data())
            ex_flag = bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            wr_flag = bool(s.Characteristics & IMAGE_SCN_MEM_WRITE)
            sec_lines.append(f"{nm:<10} vsize={s.Misc_VirtualSize:<9} rsize={s.SizeOfRawData:<9} entropy={e:.2f} {'X' if ex_flag else '-'}{'W' if wr_flag else '-'}")
            if nm.lower() in PACKER_SECTIONS:
                hot.append(("pe.packer_section", "high", f"Section '{safe_name(nm, 12)}' is the signature of an executable packer", nm))
            if ex_flag and wr_flag:
                hot.append(("pe.wx_section", "medium", f"Section '{safe_name(nm, 12)}' is both writable and executable (self-modifying code)", nm))
            if ex_flag and e > 7.2 and s.SizeOfRawData > 2048:
                hot.append(("pe.high_entropy_code", "high", f"Code section '{safe_name(nm, 12)}' is encrypted or compressed (entropy {e:.2f}/8)", nm))
            if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000 and ex_flag:
                hot.append(("pe.empty_raw_code", "medium", f"Section '{safe_name(nm, 12)}' is empty on disk but large in memory (unpacks itself at run time)", nm))
        sec_table = "\n".join(sec_lines)
        for id_, sev, title, nm in hot:
            rep.behavior(id_, sev, title, "", f"sections:\n{sec_table}" + (f"\n--- entry point ---\n{ep_disasm}" if ep_disasm else ""),
                         "sections+disasm" if ep_disasm else "sections", f"section {safe_name(nm, 12)}")
            if id_ in ("pe.packer_section", "pe.high_entropy_code", "pe.empty_raw_code"):
                rep.d["packed"] = True
        if ep_rva:
            sec = pe.get_section_by_rva(ep_rva)
            if sec is not None and sec is pe.sections[-1] and len(pe.sections) > 1:
                rep.behavior("pe.entry_in_last_section", "medium", "Program starts running in the last section (typical of packers and infectors)", "",
                             (f"entry point RVA {ep_rva:#x} in section {safe_name(sec.Name.rstrip(chr(0).encode()).decode('latin-1'), 12)}\n" + ep_disasm).strip(),
                             "disasm", f"entry {ep_rva:#x}")
        # --- overlay & embedded payloads
        overlay_off = pe.get_overlay_data_start_offset()
        overlay = data[overlay_off:] if overlay_off else b""
        if len(overlay) > 65536 or (overlay and len(overlay) > 0.25 * len(data)):
            oe = entropy(overlay)
            rep.behavior("pe.overlay", "medium" if oe > 7.0 else "low", f"{len(overlay):,} bytes appended after the program (overlay, entropy {oe:.2f}/8)",
                         "Droppers carry their real payload here.", overlay[:96].hex(" "), "hex", f"offset {overlay_off:#x}")
        marker = b"This program cannot be run in DOS mode"
        found, start = 0, 0x400
        while found < 2 and depth < budget.max_depth:
            budget.tick()
            pos = data.find(marker, start)
            if pos < 0:
                break
            start = pos + 1
            mz = pos - 0x4E
            if mz > 0x200 and data[mz: mz + 2] == b"MZ":
                found += 1
                rep.behavior("pe.embedded_pe", "high", "Contains another Windows executable inside it", "A dropper typically carries its payload this way.",
                             data[mz: mz + 64].hex(" "), "hex", f"offset {mz:#x}")
                rep.d["children"].append(child(f"embedded_pe_{mz:#x}.bin", data[mz: mz + (8 << 20)], [], depth + 1, budget))
        # --- other anomalies
        if getattr(pe, "DIRECTORY_ENTRY_TLS", None):
            cb = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            if cb:
                rep.behavior("pe.tls_callbacks", "medium", "Has TLS callbacks (code that runs before the entry point, used for anti-debugging)", "", f"AddressOfCallBacks={cb:#x}", "header", "TLS directory")
        if getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None) or (len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size):
            rep.d["file_type"] += " - managed .NET assembly"
            rep.warn("Managed (.NET) assembly: the IL code is not decompiled by this analyser; only strings and metadata are examined.")
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0 or ts > time.time() + 86400:
            rep.behavior("pe.bad_timestamp", "low", "Compile timestamp is zero or in the future (forged or scrubbed)", "", f"TimeDateStamp={ts}", "header", "file header")
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:
            rep.warn("Has an Authenticode signature block (the signature was NOT verified here)")
        strings = printable_strings(data)
        rep.d["strings"] = strings
        rep.add_iocs("\n".join(strings), binary=True)
        if rep.d["iocs"]["urls"]:
            rep.behavior("pe.embedded_urls", "low", "Contains hard-coded web addresses", "", "\n".join(rep.d["iocs"]["urls"][:8]), "strings", "string table")
    finally:
        try:
            pe.close()
        except Exception:
            pass
