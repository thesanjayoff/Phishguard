# PhishGuard Companion (Android)

> **Status: never built, never run.** This was written without an Android SDK. The pure protocol logic
> (`Protocol.kt`) has JVM unit tests in `app/src/test`, also **not executed**. Expect to fix small compile errors
> and dependency versions when you first open it in Android Studio.

## What it does

- Sends **new SMS** and, on request, the last N days of the inbox to *your* PhishGuard server (`POST /api/ingest/sms/batch`, bearer token).
- Adds a **Share target**: in WhatsApp, Telegram, a browser, ... choose *Check with PhishGuard* to send the shared text to
  `POST /api/share` and see the verdict. That is the only way chat content leaves those apps, and only because you chose to share it.
- **Read-only**: it reads SMS (`RECEIVE_SMS`, `READ_SMS`). It never sends, changes or deletes a message, never aborts the
  broadcast (your messaging app still receives everything) and has no analytics or other network endpoint.

## Privacy and safety choices

- The server address must be **HTTPS**, or plain HTTP to an address that cannot leave your network (loopback, 10.x, 172.16-31.x,
  192.168.x, link-local, Tailscale 100.64/10, `*.local`, `*.lan`, `*.ts.net`). Anything else is refused, because the token is a password for your PC.
- The token and server are stored with `EncryptedSharedPreferences` (Android Keystore). Backup and device-transfer are disabled.
- Queued messages are kept in the app's private storage until the server accepts them, then removed.
- Redirects are never followed, so the token cannot be forwarded to another host.
- Sideloaded personal use only: Google Play restricts SMS permissions to default SMS apps.

## Setup

1. On the PC: `phishguard serve` with `server.host = "0.0.0.0"` and `server.allowed_hosts = ["<PC LAN IP>"]` (see the main README), allow the port for your phone only.
2. Open `android/` in Android Studio (it creates the Gradle wrapper), build and install the debug APK.
3. In the app: enter `http://<PC LAN IP>:8765` and the token from `data/token`, tick *Send new SMS automatically*, press *Save and test connection*, then *Allow SMS access*.
4. Optional: *Send the last 7 days of SMS now* to backfill. Duplicates are ignored by the server (stable ids).

Unit tests (once Gradle works): `./gradlew :app:testDebugUnitTest`.
