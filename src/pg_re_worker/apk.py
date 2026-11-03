"""Android packages: permission/component analysis from the binary manifest and an API-string scan of classes.dex.
This is metadata + string-table analysis, NOT decompilation: Dalvik bytecode is not translated to Java here."""
from __future__ import annotations

import io
import re
import struct
import zipfile

from .core import Budget, Report, safe_name

MAX_AXML = 2 << 20
MAX_DEX = 40 << 20

PERM_RULES: list[tuple[str, str, str, set[str], str]] = [
    # id, severity, title, any-of permissions, detail
    ("apk.sms_read", "high", "Can read your text messages (OTP theft)", {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}, "Banking trojans read SMS to steal one-time passwords."),
    ("apk.sms_send", "medium", "Can send text messages", {"android.permission.SEND_SMS"}, "Used for premium-rate fraud and spreading to contacts."),
    ("apk.accessibility", "high", "Asks to be an accessibility service", {"android.permission.BIND_ACCESSIBILITY_SERVICE"}, "Lets an app read the screen and tap buttons for you."),
    ("apk.device_admin", "medium", "Asks to be a device administrator", {"android.permission.BIND_DEVICE_ADMIN"}, "Makes the app hard to uninstall."),
    ("apk.overlay", "medium", "Can draw over other apps", {"android.permission.SYSTEM_ALERT_WINDOW"}, "Used for fake login screens on top of real banking apps."),
    ("apk.install_packages", "high", "Can install other apps", {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INSTALL_PACKAGES"}, "Droppers install their real payload this way."),
    ("apk.contacts_calls", "medium", "Can read contacts or call history", {"android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"}, ""),
    ("apk.call_control", "medium", "Can place or redirect calls", {"android.permission.CALL_PHONE", "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.ANSWER_PHONE_CALLS"}, ""),
    ("apk.boot_persist", "low", "Starts itself when the phone boots", {"android.permission.RECEIVE_BOOT_COMPLETED"}, ""),
    ("apk.storage_wide", "low", "Wants access to all files", {"android.permission.MANAGE_EXTERNAL_STORAGE"}, ""),
]
DEX_STRINGS: list[tuple[str, str, str, re.Pattern]] = [
    ("apk.dex_sms_api", "high", "Code calls the SMS APIs", re.compile(r"Landroid/telephony/SmsManager;|sendTextMessage|abortBroadcast|SMS_RECEIVED")),
    ("apk.dex_dynamic_load", "high", "Loads code at run time (hides the real payload)", re.compile(r"Ldalvik/system/(?:Dex|Path)ClassLoader;|Ldalvik/system/InMemoryDexClassLoader;|loadDex")),
    ("apk.dex_exec", "medium", "Can run shell commands", re.compile(r"Ljava/lang/Runtime;|/system/(?:x)?bin/su\b|\bsu\b -c|ProcessBuilder")),
    ("apk.dex_device_ids", "medium", "Reads device identifiers", re.compile(r"getDeviceId|getSubscriberId|getImei|getLine1Number|getSimSerialNumber")),
    ("apk.dex_crypto", "low", "Uses encryption APIs (strings are probably encrypted)", re.compile(r"Ljavax/crypto/Cipher;|AES/CBC|AES/ECB")),
    ("apk.dex_webview_bridge", "medium", "Exposes native code to web content", re.compile(r"addJavascriptInterface|setJavaScriptEnabled")),
    ("apk.dex_overlay", "medium", "Draws overlays / reads the screen", re.compile(r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|AccessibilityNodeInfo|performGlobalAction|dispatchGesture")),
]


def _parse_axml(b: bytes) -> list[tuple[str, dict[str, str]]]:
    """Minimal Android binary-XML reader -> [(tag, {attr: value})]. Enough for manifest permissions/components."""
    if len(b) < 8 or struct.unpack_from("<H", b, 0)[0] != 0x0003:
        raise ValueError("not binary XML")
    pos, strings, out = struct.unpack_from("<H", b, 2)[0], [], []
    while pos + 8 <= len(b):
        ctype, hsize, size = struct.unpack_from("<HHI", b, pos)
        if size < 8 or pos + size > len(b):
            break
        if ctype == 0x0001:  # string pool
            n, _styles, flags, s_start = struct.unpack_from("<IIII", b, pos + 8)
            n = min(n, 20000)
            offs = struct.unpack_from(f"<{n}I", b, pos + 28)
            base = pos + s_start
            utf8 = bool(flags & 0x100)
            for o in offs:
                p = base + o
                try:
                    if utf8:
                        # UTF-8 pool entry: char count (1-2 bytes), byte count (1-2 bytes), then the bytes
                        ulen = b[p]
                        p += 2 if ulen & 0x80 else 1
                        blen = b[p]
                        if blen & 0x80:
                            blen = ((blen & 0x7F) << 8) | b[p + 1]
                            p += 2
                        else:
                            p += 1
                        strings.append(b[p:p + blen].decode("utf-8", "replace"))
                    else:
                        ln = struct.unpack_from("<H", b, p)[0]
                        p += 2
                        if ln & 0x8000:
                            ln = ((ln & 0x7FFF) << 16) | struct.unpack_from("<H", b, p)[0]
                            p += 2
                        strings.append(b[p:p + ln * 2].decode("utf-16le", "replace"))
                except Exception:
                    strings.append("")
        elif ctype == 0x0102:  # start tag
            _ln, _cm, _ns, name, _astart, _asize, acount = struct.unpack_from("<IIiiHHH", b, pos + 8)
            attrs: dict[str, str] = {}
            ap = pos + 36
            for _ in range(min(acount, 64)):
                _ans, an, raw, _tsz, _r0, dtype, data = struct.unpack_from("<iiiHBBI", b, ap)
                ap += 20
                key = strings[an] if 0 <= an < len(strings) else ""
                if raw >= 0 and raw < len(strings):
                    val = strings[raw]
                elif dtype == 0x12:
                    val = "true" if data else "false"
                else:
                    val = str(data)
                attrs[key] = val
            out.append((strings[name] if 0 <= name < len(strings) else "", attrs))
        pos += size
    return out


def _dex_strings(b: bytes, cap: int = 120000) -> list[str]:
    if b[:4] != b"dex\n" or len(b) < 0x70:
        return []
    n, off = struct.unpack_from("<II", b, 0x38)
    out = []
    for i in range(min(n, cap)):
        try:
            (d,) = struct.unpack_from("<I", b, off + 4 * i)
            p, shift, ln = d, 0, 0
            while True:  # ULEB128 length
                byte = b[p]
                p += 1
                ln |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            out.append(b[p:p + ln].decode("utf-8", "replace"))
        except Exception:
            continue
    return out


def analyse_apk(rep: Report, data: bytes, depth: int, budget: Budget) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        rep.warn("APK container is damaged")
        return
    rep.d["file_type"] = "Android package (APK)"
    names = zf.namelist()
    pkg = ""
    perms: set[str] = set()
    comps: list[str] = []
    try:
        with zf.open("AndroidManifest.xml") as fh:
            tags = _parse_axml(fh.read(MAX_AXML))
        for tag, attrs in tags:
            if tag == "manifest":
                pkg = attrs.get("package", "")
            elif tag in ("uses-permission", "uses-permission-sdk-23"):
                perms.add(attrs.get("name", ""))
            elif tag in ("service", "receiver", "activity"):
                comps.append(f"{tag}: {attrs.get('name', '')}")
                if attrs.get("permission"):
                    perms.add(attrs["permission"])
            elif tag == "action" and attrs.get("name"):
                comps.append(f"action: {attrs['name']}")
        rep.d["strings"] = ([f"package: {safe_name(pkg, 80)}"] + [f"permission: {safe_name(p, 80)}" for p in sorted(perms)])[:60]
    except KeyError:
        rep.warn("APK has no AndroidManifest.xml")
    except Exception as e:
        rep.warn(f"binary manifest could not be parsed ({type(e).__name__})")
    for id_, sev, title, want, detail in PERM_RULES:
        hit = sorted(perms & want)
        if hit:
            rep.behavior(id_, sev, title, detail, "\n".join(hit), "manifest-permissions", "AndroidManifest.xml")
    if {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"} & perms and "android.permission.INTERNET" in perms and any("SMS_RECEIVED" in c for c in comps):
        rep.behavior("apk.sms_interceptor", "critical", "Reads incoming SMS and has network access (OTP-stealer pattern)",
                     "Declares an SMS receiver, SMS permission and INTERNET together.", "\n".join(c for c in comps if "SMS" in c)[:600], "manifest-components", "AndroidManifest.xml")

    total = 0
    for n in names:
        if re.fullmatch(r"classes\d*\.dex", n):
            budget.tick()
            with zf.open(n) as fh:
                blob = fh.read(MAX_DEX + 1)
            if len(blob) > MAX_DEX:
                rep.warn(f"{n} is larger than {MAX_DEX >> 20} MB and was not scanned")
                continue
            budget.spend(len(blob))
            strs = _dex_strings(blob)
            total += len(strs)
            joined = "\n".join(strs)
            rep.add_iocs(joined[:600_000], binary=True)
            for id_, sev, title, rx in DEX_STRINGS:
                hits = sorted({m.group(0) for s in strs for m in [rx.search(s)] if m})[:10]
                if hits:
                    rep.behavior(id_, sev, title, "Found in the string/method table of " + n + ". Bytecode was not decompiled.", "\n".join(hits), "dex-strings", n)
    if total == 0:
        rep.warn("no readable classes.dex string table")
    for n in names:
        if re.search(r"(?i)^(?:assets|res/raw|lib)/.*\.(apk|dex|jar|so|bin)$", n) and not n.startswith("lib/"):
            rep.behavior("apk.embedded_payload", "high", "APK carries another package or code blob in its assets", "Droppers hide the real malware here.", safe_name(n, 120), "member-names", n)
