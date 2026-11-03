package app.phishguard.companion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/** Receives new SMS (read-only: the broadcast is never aborted, so the normal messaging app still gets every message). */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (parts.isNullOrEmpty()) return
        if (!Prefs.isConfigured(context) || !Prefs.liveSync(context)) return
        val sender = parts[0].originatingAddress ?: ""
        val body = parts.joinToString("") { it.messageBody ?: "" }
        if (body.isBlank()) return
        Outbox.add(context, listOf(Sms(sender, body, parts[0].timestampMillis)))
        UploadWorker.enqueue(context)
    }
}
