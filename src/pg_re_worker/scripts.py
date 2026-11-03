"""Script and HTML attachments: rule-based static review (never evaluated). Encoded PowerShell is *decoded as text*
and re-scanned one level deep, so the code behind an '-EncodedCommand' blob is visible."""
from __future__ import annotations

import base64
import re

from .core import Report, line_context, safe_name

_DL = r"(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b|net\.webclient|xmlhttp|urldownloadtofile|bitsadmin|certutil[^\n]{0,40}-urlcache|start-bitstransfer|webrequest\]::create)"
_EX = r"(?:invoke-expression|\biex\b|start-process|wscript\.shell|\.run\s*\(|\.exec\s*\(|shell\.application|cmd(?:\.exe)?\s*/c|rundll32|regsvr32|mshta|\bstart\s+/b|createprocess|&\s*\$)"

# (id, severity, title, regex, kinds) - kinds None means every text-like file
RULES: list[tuple[str, str, str, str, set | None]] = [
    ("script.encoded_command", "high", "PowerShell runs a base64-encoded command", r"(?i)-(?:e|ec|enc|encodedcommand)\s+[\"']?([A-Za-z0-9+/=]{40,})", None),
    ("script.download_exec", "high", "Downloads something and runs it", "", None),  # handled specially in _scan (needs both parts)
    ("script.download", "medium", "Downloads data from the internet", _DL, None),
    ("script.persistence", "high", "Sets itself up to run again (Run key / scheduled task / start-up folder / WMI)",
     r"(?i)(currentversion\\run|schtasks(?:\.exe)?\s+/create|\\start menu\\programs\\startup|new-scheduledtask|register-scheduledtask|__eventfilter|reg\s+add\s+[^\n]*\\run\b|sc(?:\.exe)?\s+create)", None),
    ("script.defense_evasion", "high", "Tries to weaken or evade security tools",
     r"(?i)(set-mppreference\s+-disable|add-mppreference\s+-exclusion|amsiinitfailed|amsi\.dll|-executionpolicy\s+bypass|-ep\s+bypass|-windowstyle\s+hidden|-w\s+hidden|netsh\s+advfirewall[^\n]*off|vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit[^\n]*recoveryenabled\s+no)", None),
    ("script.process_injection", "critical", "Allocates and runs raw code in memory (shellcode-loader pattern)",
     r"(?i)(virtualalloc|add-type[^\n]{0,80}dllimport|\[system\.runtime\.interopservices\.marshal\]::copy|invoke-reflectivepeinjection|\[reflection\.assembly\]::load\s*\()", None),
    ("script.credential_theft", "high", "References credential-stealing tools or credential stores",
     r"(?i)(mimikatz|sekurlsa|lsass(?:\.exe)?|login\s+data|logins\.json|key[34]\.db|passwordvault|get-credential\b|cookies\.sqlite|\\microsoft\\credentials)", None),
    ("script.exfil_webhook", "high", "Sends data to a chat-service webhook / bot (common stealer exfiltration)",
     r"(?i)(api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/api)", None),
    ("script.wsh_objects", "medium", "Uses Windows Script Host objects that can run programs or touch files",
     r"(?i)(new\s+activexobject\s*\(|createobject\s*\(\s*[\"'](?:wscript\.shell|scripting\.filesystemobject|shell\.application|adodb\.stream|msxml2\.xmlhttp))", {"script"}),
    ("script.obfuscation_calls", "medium", "Code is built or decoded at run time (eval / char-code / base64 decode)",
     r"(?i)((?:string\.)?fromcharcode\s*\(|\bunescape\s*\(|\batob\s*\(|frombase64string|\[char\]\s*\d+|\bchr[wb]?\s*\(\s*\d+\s*\)\s*&|-join\s*\(|\.replace\s*\([^)]*\)\s*\.replace\s*\()", None),
]
_HTML_RULES = [
    ("html.password_form", "high", "Web page asks for a password", r"(?is)<input[^>]+type\s*=\s*[\"']?password"),
    ("html.smuggling", "high", "HTML builds a file in the browser and saves it (HTML smuggling)",
     r"(?is)(new\s+blob\s*\(|msSaveOrOpenBlob|URL\.createObjectURL|download\s*=\s*[\"'][^\"']+\.(?:exe|zip|iso|js|vbs|scr|msi|img|lnk))"),
    ("html.data_uri_payload", "medium", "HTML embeds a large base64 payload", r"(?is)(?:data:[a-z/+.-]+;base64,|atob\s*\(\s*[\"'])[A-Za-z0-9+/=]{800,}"),
    ("html.external_form", "medium", "Form posts to another website", r"(?is)<form[^>]+action\s*=\s*[\"']?https?://[^\s\"'>]+"),
    ("html.auto_redirect", "medium", "Page redirects the visitor automatically",
     r"(?is)(<meta[^>]+http-equiv\s*=\s*[\"']?refresh|window\.location(?:\.href)?\s*=|location\.replace\s*\()"),
    ("html.hidden_iframe", "medium", "Page embeds a hidden frame", r"(?is)<iframe[^>]+(?:display\s*:\s*none|width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)"),
]


def _decode_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:200]:
        return data.decode("utf-16le", "replace")
    return data.decode("utf-8", "replace") if data[:3] == b"\xef\xbb\xbf" else data.decode("utf-8", "replace")


def _decode_ps(b64: str) -> str | None:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
    except Exception:
        return None
    for enc in ("utf-16le", "utf-8"):
        try:
            t = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if sum(c.isprintable() or c in "\r\n\t" for c in t) / max(1, len(t)) > 0.9:
            return t
    return None


def _scan(rep: Report, text: str, kind: str, location_prefix: str, depth: int = 0) -> None:
    for id_, sev, title, rx, kinds in RULES:
        if kinds and kind not in kinds:
            continue
        if id_ == "script.download_exec":
            dl = re.search(_DL, text, re.I)
            ex = re.search(_EX, text, re.I)
            if not (dl and ex):
                continue
            m = dl
        else:
            m = re.search(rx, text)
        if not m:
            continue
        snip, line = line_context(text, m.start())
        detail = ""
        if id_ == "script.encoded_command" and depth == 0:
            dec = _decode_ps(m.group(1))
            if dec:
                detail = "The base64 text was decoded statically (not run); it is shown below and was scanned as well."
                snip = snip[:300] + "\n--- decoded command ---\n" + dec[:2000]
                rep.add_iocs(dec)
                _scan(rep, dec, "script", location_prefix + "decoded: ", depth=1)
        rep.behavior(id_, sev, title, detail, snip[:3000], "decoded" if "decoded command" in snip else "source", f"{location_prefix}line {line}")
    rep.add_iocs(text[:400_000])


def analyse_script(rep: Report, data: bytes, kind: str, filename: str) -> None:
    text = _decode_text(data[:3 << 20])
    if kind == "html":
        for id_, sev, title, rx in _HTML_RULES:
            m = re.search(rx, text)
            if m:
                snip, line = line_context(text, m.start(), 0, 1)
                rep.behavior(id_, sev, title, "", snip[:1200], "html", f"line {line}")
        scripts = re.findall(r"(?is)<script[^>]*>(.*?)</script>", text)
        if scripts:
            _scan(rep, "\n".join(scripts)[:800_000], "script", "inline script ")
        rep.add_iocs(text[:400_000])
    else:
        _scan(rep, text, "script", "")
    lines = text.splitlines()
    if lines:
        longest = max(len(l) for l in lines)
        non_alpha = sum(1 for c in text[:50000] if not (c.isalnum() or c.isspace())) / max(1, len(text[:50000]))
        if longest > 4000 and non_alpha > 0.35:
            rep.behavior("script.dense_line", "medium", "A single very long, symbol-heavy line (packed or obfuscated code)",
                         f"Longest line is {longest:,} characters; {non_alpha:.0%} of characters are symbols.",
                         safe_name(max(lines, key=len)[:400], 400), "source", "longest line")
            rep.d["packed"] = True
    rep.d["strings"] = [l.strip()[:200] for l in lines if l.strip()][:20]
