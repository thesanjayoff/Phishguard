package app.phishguard.companion

import android.content.Context
import android.provider.Telephony

/** One-off read of existing inbox messages (read-only query; nothing on the phone is changed). */
object InboxSync {
    /** Queue the inbox messages from the last [days] days for upload. Returns how many were queued. */
    fun queueRecent(ctx: Context, days: Int, limit: Int = 1000): Int {
        val since = System.currentTimeMillis() - days.coerceIn(1, 365) * 86_400_000L
        val found = mutableListOf<Sms>()
        val cursor = ctx.contentResolver.query(
            Telephony.Sms.Inbox.CONTENT_URI,
            arrayOf(Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
            "${Telephony.Sms.DATE} >= ?", arrayOf(since.toString()),
            "${Telephony.Sms.DATE} DESC",
        ) ?: return 0
        cursor.use {
            val a = it.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)
            val b = it.getColumnIndexOrThrow(Telephony.Sms.BODY)
            val d = it.getColumnIndexOrThrow(Telephony.Sms.DATE)
            while (it.moveToNext() && found.size < limit) {
                val body = it.getString(b) ?: continue
                if (body.isNotBlank()) found.add(Sms(it.getString(a) ?: "", body, it.getLong(d)))
            }
        }
        Outbox.add(ctx, found.reversed())
        if (found.isNotEmpty()) UploadWorker.enqueue(ctx)
        return found.size
    }
}
