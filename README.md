# PhishGuard - a personal, local-first phishing detector

PhishGuard reads your messages (read-only), runs them through several independent detection layers and gives each one a
**0-100 risk score**, a verdict (**safe / suspicious / phishing**) and plain-language **reasons**. It runs on your own
machine. Suspected phishing is labelled or moved aside, **never deleted**.

```
Gmail / IMAP / Outlook ─┐                              ┌─ headers: SPF/DKIM/DMARC, From vs Reply-To vs Return-Path, display-name spoofing
Android: SMS + share ───┼─►  normalise  ─►  layers  ───┼─ links:   lookalike/typosquat/homograph, domain age, shorteners, IP hosts, feeds
Paste / share / CLI ────┘                              ├─ wording: urgency, credential/payment asks, India-specific scams + classifier (+ optional LLM)
                                                       ├─ behaviour: isolated headless browser (redirects, login forms, screenshot)   [Docker]
                                                       └─ attachments: static analysis, no network, nothing executed                   [Docker]
                                          weighted score + reasons  ─►  inbox / dashboard / CLI
```

## What was actually verified (read this first)

| Area | Status |
|---|---|
| Detection engine, scoring, parsing, redaction, feedback loop, web app, CLI | **Tested**: 293 automated tests pass on Windows / Python 3.12 |
| Attachment analyser (`pg_re_worker`) | **Tested as a library** on harmless samples built in memory (macro doc, PE with injection imports, APK, PDF, scripts, zip bombs, path traversal), **and run inside its real container** (Podman on WSL2) on a harmless macro document, a PDF, a zip, a clean docx and a text file: the macro was extracted, the controls were clean. |
| Link worker (`pg_link_worker`) incl. filtering proxy | **Tested with a real browser (Edge) against local pages the tests serve themselves**: redirects, forms, login detection, screenshot, download cancel, and loopback blocking (a mutation check proved the test fails if the guard is removed). **Also run inside its real container**: visits to `example.com` (the only external page tried) and refusals of loopback, the cloud-metadata IP, a LAN address and `localhost`. |
| **Container images and flags** (`docker/`, `phishguard/sandbox/`) | **Built and run with Podman 5.8.3 on WSL2 (Windows 11)**, see *Windows: Podman on WSL2*. The enforced isolation was probed from inside the container: uid 65532, no capabilities, no-new-privileges, seccomp filter on, read-only root, no network or DNS for attachments, 512 MiB / 128 PIDs limits, no Windows drives visible. **Not tried: Docker itself** (Docker Desktop / Engine). The flags are standard and Podman accepted them, but that is not proof for Docker. **Not tried: real phishing pages** in the link container, and nothing hostile has been run through either container. |
| Gmail / Microsoft Graph / IMAP | **Tested against fakes only.** No real mailbox was connected. OAuth sign-in flows are untested. |
| Android companion (`android/`) | **Never built or run** (no Android SDK here). The pure protocol logic has JVM unit tests that were written but not executed. Treat as a starting point. |
| Web UI | Both themes checked in a real browser against the running server (screenshots of inbox, report, dashboard, check page); the dashboard axis ticks were fixed after that check. |

Without a container runtime (Docker or Podman) the app still works: links and attachments are then **not opened or analysed
at all** (there is deliberately no fallback that touches them on your computer) and the verdict says so.

## Quick start

Requires Python 3.11+ (developed on 3.12). Docker is optional but needed for the link and attachment layers.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"            # Windows: .venv\Scripts\pip install -e ".[dev]"
#   extras: ".[gmail]"  ".[outlook]"  ".[llm]"  ".[worker]" (only to run the worker's own tests)  ".[browser]"
.venv/bin/phishguard init                     # writes config.toml from config.example.toml
.venv/bin/phishguard feeds update             # downloads the OpenPhish / PhishTank lists (mirrored locally)
.venv/bin/phishguard build-images             # builds the two isolated Docker images (needs Docker)
.venv/bin/phishguard doctor                   # shows what is available
.venv/bin/phishguard serve                    # http://127.0.0.1:8765
```

### Windows: Podman on WSL2 (low memory instead of Docker Desktop)

This is the setup the containers were verified on. Run the installs in an **Administrator** PowerShell, then reboot:

```powershell
wsl --install --no-distribution
winget install RedHat.Podman
```

1. Cap the VM in `%USERPROFILE%\.wslconfig` (on WSL the Podman VM size comes from here, not from `podman machine init`):
   ```ini
   [wsl2]
   memory=3GB
   processors=2
   swap=0
   [experimental]
   autoMemoryReclaim=gradual
   ```
2. `podman machine init` then `podman machine start`. If the image download is cut off with "connection aborted", run it again.
3. **Make the machine rootful:** `podman machine stop`, `podman machine set --rootful`, `podman machine start`.
   Why: in a *rootless* machine every container failed to start with `crun: open memory.max for writing: No such file or directory`.
   The WSL cgroup layout has no memory controller delegated to the unprivileged user (WSL's own processes sit directly in
   `/non-systemd`, so controllers can't be enabled below it). The memory limit is a safety feature, so it was not removed.
4. **Shrink what the VM can reach.** By default it mounts `C:\` and `D:\` read-write and can launch Windows programs. PhishGuard
   needs neither (everything goes in over stdin, nothing is bind-mounted), so switch both off in the VM's `/etc/wsl.conf`
   (`podman machine ssh`, then edit as root) and restart the machine:
   ```ini
   [user]
   default=user
   [automount]
   enabled=false
   mountFsTab=false
   [interop]
   enabled=false
   appendWindowsPath=false
   ```
   Verified afterwards: no drvfs mounts, `/mnt/c` empty, `cmd.exe` not found inside the VM.
5. In `config.toml`: `[sandbox]` `docker_bin = "podman"`. Then `phishguard build-images` and `phishguard doctor`.

`.dockerignore` limits the build context to the two worker packages, so your mail database, corpora and `.venv` are never sent
to the build daemon.

**Memory measured** (Windows 11, 15.4 GB RAM; a coarse once-a-second sample while running 5 browser visits to `example.com` and
5 attachment scans; not a heavy page, so treat it as a floor):

| State | Used inside the VM | Notes |
|---|---|---|
| Idle (machine up, no containers) | about 420 MB | Windows reports the VM at about 2 GB. The gap is cache and pages Windows hasn't reclaimed yet; it did **not** shrink during this short measurement, so `autoMemoryReclaim` is unproven here |
| During scans | peak about 640 MB | the Chromium container peaked near 190 MB (limit 1 GB). Attachment containers live about a second and were not caught by the sampling |
| After | about 430 MB | no containers left behind |

The 3 GB cap was never approached (the Windows-side figure peaked at about 2 GB). `podman machine stop` shuts the VM down when you are not scanning.

### Check something right now

```bash
phishguard check suspicious.eml                       # an email file
phishguard check "http://paypa1-secure-login.top/x"   # a link
phishguard check "Your KYC is pending, update now http://hdfc-kyc.top"   # pasted text / SMS / chat
phishguard check mail.eml --json --no-sandbox         # machine-readable, skip Docker
```
Exit code: `0` safe, `1` suspicious, `2` phishing. Links are always printed **defanged** (`hxxp://evil[.]com`), in the
text report and in the JSON.

### The web app

`phishguard serve` opens a local inbox of scanned messages (verdict, score, reasons), a **Check** page (paste or share
text, link or a raw email), a per-message report (reasons per layer, defanged links, sandbox screenshot, attachment
reports) with **Mark as safe / Mark as phishing** buttons, and a dashboard (trends, top spoofed brands, top malicious
domains). Each button press changes future scoring - see *Learning from your feedback*.

**Look and feel.** Dark with a warm gold accent by default, and a light "champagne paper" theme that follows your OS
setting. Server-rendered Jinja + plain CSS/JS, no framework and no build step. Everything is self-hosted: the page makes no
request to any other origin (checked in the browser). The verdict colours (green / orange / red) are always paired with an
icon and a word, so colour is never the only signal. Animations (the score ring, the dashboard bars, page transitions) run only
when your OS has not asked for reduced motion. The layout has been checked, with screenshots and a script, at 1440 px, 375 px
and 320 px wide with no sideways scrolling, and text contrast was computed for both themes. It has not been tested on a
physical phone, in Safari or in Firefox, and I did not run a screen reader against it.

Your phone, WhatsApp, Telegram etc.: forward or **share** the text to the app (the Android companion adds a share target) or paste it on the Check page. PhishGuard
does not read chat apps and does not try to get around their APIs.

## Sources (all read-only by default)

| Source | Setup |
|---|---|
| **Gmail** (API, OAuth) | Create a Google Cloud OAuth client of type *Desktop app*, save the JSON as `data/gmail_client_secret.json`, set `[gmail] enabled = true`, run `phishguard auth gmail`. Default scope is `gmail.readonly`. |
| **Any mailbox via IMAP** | Set `[imap] host/user`, export the app password in `PHISHGUARD_IMAP_PASSWORD`. Uses a read-only `SELECT` and `BODY.PEEK[]`, so nothing is marked read. |
| **Outlook / Microsoft 365** (optional) | Register an Entra app ("allow public client flows"), set `[outlook] enabled = true` and `client_id`, run `phishguard auth outlook`. Default scope is `Mail.Read`. |
| **SMS** (Android) | See [`android/README.md`](android/README.md). The phone sends to `/api/ingest/sms` with the bearer token in `data/token`. |
| **Paste / share / forward** | The Check page, `POST /api/share`, or `phishguard check`. |

Poll once with `phishguard scan gmail|imap|outlook|all`; `phishguard serve` polls enabled sources every
`server.scan_interval_minutes`.

**Quarantine never deletes.** Suspected phishing is always flagged in PhishGuard's own inbox. Optionally it is also
labelled/moved at the provider: Gmail needs the broader `gmail.modify` scope to add a label, Outlook needs `Mail.ReadWrite`
to move, IMAP copies into a folder. These are off by default (`quarantine = false`), so the default scopes stay read-only.
There is no delete, trash or expunge code anywhere in the sources (a test inspects the code for it).

## Detection layers

1. **Headers** - SPF/DKIM/DMARC from `Authentication-Results`, From vs Reply-To vs Return-Path, brand spoofing in the display
   name. Mailing-list headers silence only the *weak* mismatch signals; authentication failures and brand spoofing are never
   suppressed. Encoded (`=?utf-8?b?..?=`) names and subjects are decoded first.
2. **URLs** - lookalike/typosquat/combosquat/homograph (punycode decoded) domains, brand-in-subdomain, IP-address and
   obfuscated-IP hosts, suspicious TLDs, `@` tricks, shorteners expanded in the container (redirect headers only), domain age
   via RDAP (domain name only), and local copies of **OpenPhish**, **PhishTank** and optionally Google Safe Browsing (your own key; URLs only).
3. **Wording** - urgency, credential and payment requests, bank/courier/government impersonation, plus rules for the common
   Indian scams: **bank KYC**, **UPI refund**, **courier customs fee**, **electricity disconnection**, **fake job offers**. A
   small trained text classifier (hashed features, updated by your feedback) and an optional LLM second opinion.
4. **Link behaviour** (Docker) - suspicious links are opened in headless Chromium in a container with an empty profile (no
   cookies or personal data). It records redirects, forms, login/password fields and a screenshot, and **never clicks, types or
   submits anything**.
5. **Attachments** (Docker, no network) - see below.

Scores combine per-layer evidence with a noisy-OR (independent weak clues add up, nothing exceeds 100), scaled by layer
weights and by multipliers learned from your feedback (bounded 0.4-1.6); legitimacy evidence is subtracted (capped at 45).
Thresholds: `>= 35` suspicious, `>= 70` phishing (configurable). The design borrows *ideas* (rule scoring from
rspamd/SpamAssassin, keyword + edit-distance lookalikes from phishing_catcher, the report shape of urlscan.io); the code is original.

### Attachment analysis

A small adapter interface (`phishguard/sandbox/re_adapter.py`): `analyze(filename, data, passwords) -> report`.
The built-in implementation, `pg_re_worker`, runs in the container started with `--network none --read-only --cap-drop ALL
--security-opt no-new-privileges`, memory/PID/CPU limits and an unprivileged user. The file arrives on stdin and is never written to
disk; nothing is executed, detonated or loaded. It covers:

- **Office** (OLE and OOXML): VBA/XLM macros with auto-exec, download, shell-execution and obfuscation findings, remote templates, DDE - the macro lines behind each flag are shown.
- **PE/EXE/DLL**: hashes, imports grouped by behaviour (injection, download-and-exec, persistence, ...), entropy/packer sections, and the **disassembly around the call site** that triggers a flag.
- **PDF** (JavaScript, auto-actions, launch/URI actions, hex-obfuscated names), **scripts / HTML** (PowerShell `-enc` decoded statically, download-exec, HTML smuggling, password forms), **APK** (permissions, SMS interception/overlay, DEX API strings; *not* decompiled), LNK, RTF, images with appended payloads.
- **Archives**: zip/tar/gz/bz2/xz unpacked **in memory** with zip-bomb limits (ratio, declared size, member count, depth, time, bytes), path-traversal names reported and never used as paths, encrypted members opened with passwords found in the message text ("password: infected").
- For every file: SHA-256/SHA-1/MD5, type by content vs extension (a `.pdf` that is really an EXE is flagged), entropy, strings, and **IOCs** (URLs, IPs, domains, emails, registry keys, paths, commands). Findings feed the message score.

**Using your own reverse-engineering tool.** The request mentioned a specific tool, but the name was left as a blank
placeholder (`[RE_TOOL]`), so the built-in analyser is what ships. To drive your own tool: build an image `FROM phishguard-rebox`
(or your own) that contains it, then set

```toml
[sandbox]      re_image = "my-re-image:latest"
[attachments]  adapter = "command"
               external_command = ["mytool", "--headless", "--json", "{input}"]
```
The sample is streamed into a tmpfs inside a no-network container as `/work/sample`; the tool must print one JSON object.
If it follows the report schema (`behaviors`, `iocs`, ...; see `sanitize_report`) it is merged into the verdict, otherwise
its raw output is shown. Container output is always treated as untrusted and schema-checked.

## Privacy

- **Read-only** access to every mailbox by default; quarantine permissions are opt-in.
- **Data stays local.** Messages are stored in `data/phishguard.db` with only a *redacted* snippet (emails/phones/OTPs/cards/tokens masked) and a subject; the full body is not kept. Feedback stores hashed features, not text. Logs are redacted.
- **Nothing about your messages is sent anywhere by default.** The only network traffic is: downloading the public feeds, RDAP lookups of **domain names only** (switch off with `privacy.external_domain_lookups = false`), and whatever you enable: Gmail/Graph/IMAP access, your own Safe Browsing key (URLs only).
- **The LLM is off.** A message body is sent to an LLM only if **both** `llm.enabled` and `privacy.send_body_to_llm` are `true`, and then only a redacted, length-capped copy. For a fully local option use `provider = "openai_compatible"` with a local server such as Ollama.
- **Links and attachments are only ever processed in containers.** If Docker is missing they are skipped; there is no host fallback.
- The web app binds to `127.0.0.1`, rejects unexpected `Host` headers (DNS rebinding), checks `Origin` / `Sec-Fetch-Site` and a CSRF header on writes, uses a strict CSP, autoescapes everything, and never returns clickable links. Scripts and the phone use the bearer token in `data/token`.
- **Phone / LAN access:** set `server.host = "0.0.0.0"` and `server.allowed_hosts = ["<your LAN IP or name>"]`. The UI then asks for the token. Add a firewall rule so only your devices can reach the port; the connection is plain HTTP, so use a trusted network (or put it behind your own HTTPS/VPN).

### Network isolation of the link container

Inside the link container Chromium is forced through a small filtering proxy (`pg_link_worker/proxy.py`) that resolves names
itself, refuses anything that is not a public address (loopback, LAN, link-local, metadata, IPv4 hidden in IPv6, names that mix
public and private answers) and connects to the address it checked. This is the main guard. **Residual risk:** a Chromium
exploit could bypass an in-container proxy. For defence in depth give the container its own Docker network
(`sandbox.link_network`) and block private ranges and the host at your firewall for that network. Docker can't do that for you.

## Learning from your feedback

*Mark as safe / phishing* (in the UI or `POST /api/messages/{id}/feedback`) updates, idempotently and reversibly:
per-signal multipliers (a signal that keeps firing on mail you call safe loses weight, bounded), a sender/brand reputation (a *safe*
mark only trusts a sender whose mail **passes authentication** - one click cannot launder a spoofed sender), and the classifier
(`partial_fit` on hashed features). Marking safe also releases the local quarantine flag.

## Tests, evaluation and honest numbers

```bash
.venv/bin/pytest                                 # 293 tests; the real-browser tests skip if no Chromium-family browser is installed
python scripts/fetch_corpora.py                  # Nazario (CC BY 4.0), SpamAssassin ham, OpenPhish feed -> data/corpora (git-ignored)
phishguard train && phishguard eval --out reports/eval.md
```

Latest run (`reports/eval.md`, static layers only: no network lookups, no containers), held-out by grouped subject split:

| Set | Mode | Precision | Recall | False positives |
|---|---|---|---|---|
| Nazario phishing (699) vs SpamAssassin ham (1163) | rules only | 0.935 | 0.744 | 36 (3.1%) |
| same | rules + classifier | **0.976** | **0.977** | 17 (1.46%) |
| same | rules + classifier, counting only the "phishing" verdict (not "suspicious") | 1.000 | 0.850 | 0 |
| 300 live OpenPhish URLs (bare) vs 461 links from legit mail | rules only | 0.875 | **0.047** | 2 (0.43%) |
| same | rules + classifier | 0.986 | 0.477 | 2 (0.43%) |

**How much to trust this:**

- **Era confound.** Nazario's phishing is 2005-2025 mail, the legitimate set is 2002-2005 mail, so part of the 0.976/0.977 is the classifier learning *era* (formatting, HTML, URL style), not phishing. The same applies to the 0.477 URL figure: I would not expect it on real modern mail.
- **Tuning contamination.** I tuned rules while looking at false positives on the held-out Nazario/SpamAssassin split (e.g. cut false positives from 24% to 3% by fixing rules). Those numbers are optimistic. The **OpenPhish URL set was never used for tuning**, which is why its result is the more honest one.
- **Bare URLs without context are the weak spot.** Static rules alone catch only ~5% of fresh phishing URLs, because most use ordinary-looking domains. What catches them in real use is domain age, the feeds, the isolated browser visit (a login form on a young unrelated domain) and the surrounding wording - none of which could be measured here. The verdict says **"Not verified"** when a link looks clean but those layers were unavailable. `safe` on a bare link means "no static red flags", not "verified safe".
- The synthetic sets (1.000 on rules) are **my own wording** and only check for regressions; they say nothing about real-world generalisation.
- **Three Nazario files could not be read** (`20051114.mbox`, `phishing-2015`, `phishing-2023`: permission denied, most likely antivirus real-time protection). They were skipped, not worked around.
- PhishTank's bulk file answered HTTP 429 without an application key, so the URL evaluation uses OpenPhish only. The app still supports a PhishTank mirror when you provide a key.
- The attachment module was tested only on harmless files I built, per the testing rules - no malware detection rates are claimed.

## Layout

```
src/phishguard/      app: models, layers/, sandbox/ (host side of the containers), sources/, web/, cli, scoring, feedback, evaluation
src/pg_re_worker/    attachment analyser (runs only inside docker/rebox)
src/pg_link_worker/  browser + filtering proxy + shortener expander (runs only inside docker/linkbox)
docker/              the two Dockerfiles        android/  companion app (unbuilt)
tests/               pytest suite               reports/  latest evaluation
```

## Known limitations

- `Brand.is_official` treats `brand-label.<common TLD>` (e.g. `paypal.net`) as official; a squatter on another TLD of a real brand label will not be flagged by lookalike checks alone.
- Static analysis only: APK bytecode is not decompiled; 7z/RAR/CAB/ISO contents are not opened by the built-in analyser (it says so); encrypted members need a password from the message text.
- The classifier is small and trained on public corpora plus synthetic examples; teach it with the feedback buttons.
- No mailbox or Android build was exercised for real, and the containers have only been run under Podman (see the table at the top).
- The Podman machine has to be **rootful** on WSL2 (see below): that is a weaker isolation setup than rootless, partly offset by the hardening described there.
- Chromium occasionally reported `ERR_NETWORK_CHANGED` right after a container started (2 of 5 visits). The worker now retries that one error up to twice; 12 of 12 visits then succeeded. The root cause was not investigated further.

## Licences and attribution

Original code. Evaluation data is downloaded by you and not redistributed: Nazario phishing corpus, Jose Nazario,
<https://monkey.org/~jose/phishing/> (**CC BY 4.0**); Apache SpamAssassin public corpus; OpenPhish community feed
(<https://openphish.com/>, community/non-commercial terms) and PhishTank (<https://phishtank.org/>, subject to their terms).
rspamd, SpamAssassin, phishing_catcher, GoPhish and urlscan.io were studied for *ideas* only; no code was copied.

Fonts, bundled in `src/phishguard/web/static/fonts/` and served from your own machine: **Manrope** and **DM Mono**, both under the
SIL Open Font License 1.1 (licence texts sit next to the font files).
