package app.phishguard.companion

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import kotlin.concurrent.thread

/**
 * Target of Android's Share sheet. In WhatsApp, Telegram, a browser, ... choose "Check with PhishGuard" to send the
 * shared text to your own server. WhatsApp/Telegram are not accessed any other way - only what you choose to share.
 */
class ShareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = intent?.takeIf { it.action == Intent.ACTION_SEND }?.getStringExtra(Intent.EXTRA_TEXT)?.trim().orEmpty()
        val title = intent?.getStringExtra(Intent.EXTRA_SUBJECT)
        if (text.isEmpty()) return finishWith("Nothing to check: the shared item has no text.")
        if (!Prefs.isConfigured(this)) return finishWith("Open PhishGuard Companion first and enter your server address and token.")
        setFinishOnTouchOutside(false)
        thread {
            val msg = try {
                Protocol.summarise(Api.post(this, "/api/share", Protocol.shareJson(text, title)))
            } catch (e: ApiException) {
                e.message ?: "The check failed."
            } catch (e: Exception) {
                "Could not reach your PhishGuard server (${e.javaClass.simpleName}). Is your PC on and on the same network?"
            }
            runOnUiThread { finishWith(msg) }
        }
    }

    private fun finishWith(message: String) {
        AlertDialog.Builder(this)
            .setTitle("PhishGuard")
            .setMessage(message)
            .setPositiveButton("OK") { _, _ -> finish() }
            .setOnCancelListener { finish() }
            .show()
    }
}
