package app.phishguard.companion

import android.content.Context
import java.io.File
import org.json.JSONObject

/**
 * Messages waiting to be uploaded, kept as JSON lines in the app's private storage and removed as soon as the
 * server has accepted them. (WorkManager input data is capped at 10 KB, too small for long multipart SMS.)
 */
object Outbox {
    private const val MAX_ENTRIES = 2000
    private val lock = Any()

    private fun file(ctx: Context) = File(ctx.applicationContext.filesDir, "outbox.jsonl")

    fun add(ctx: Context, items: List<Sms>) = synchronized(lock) {
        val existing = readLines(ctx)
        val merged = (existing + items.map { toLine(it) }).takeLast(MAX_ENTRIES)
        file(ctx).writeText(merged.joinToString("\n") + if (merged.isEmpty()) "" else "\n")
    }

    fun peek(ctx: Context, n: Int): List<Sms> = synchronized(lock) { readLines(ctx).take(n).mapNotNull { fromLine(it) } }

    fun drop(ctx: Context, n: Int) = synchronized(lock) {
        val rest = readLines(ctx).drop(n)
        file(ctx).writeText(rest.joinToString("\n") + if (rest.isEmpty()) "" else "\n")
    }

    fun size(ctx: Context): Int = synchronized(lock) { readLines(ctx).size }

    private fun readLines(ctx: Context): List<String> = file(ctx).takeIf { it.exists() }?.readLines()?.filter { it.isNotBlank() } ?: emptyList()

    private fun toLine(s: Sms) = JSONObject().put("s", s.sender).put("b", s.body).put("t", s.epochMs).toString()

    private fun fromLine(line: String): Sms? = try {
        JSONObject(line).let { Sms(it.getString("s"), it.getString("b"), it.getLong("t")) }
    } catch (e: Exception) { null }
}
