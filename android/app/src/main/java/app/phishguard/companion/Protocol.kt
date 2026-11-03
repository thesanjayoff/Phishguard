package app.phishguard.companion

import java.net.URI
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/** One text message as read from the phone. */
data class Sms(val sender: String, val body: String, val epochMs: Long)

/**
 * Everything here is plain Kotlin with no Android classes, so it can be unit-tested on a normal JVM
 * (see app/src/test). The wire format matches PhishGuard's /api/ingest/sms/batch and /api/share endpoints.
 */
object Protocol {
    const val MAX_BATCH = 100

    /** Remove whitespace and a trailing slash: "http://192.168.1.20:8765/ " -> "http://192.168.1.20:8765". */
    fun normalizeBase(raw: String): String = raw.trim().trimEnd('/')

    /**
     * The token is a password for your PC, so it is only ever sent over HTTPS, or over plain HTTP to an
     * address that cannot leave your own network: loopback, RFC 1918 LAN ranges, link-local, Tailscale's
     * 100.64.0.0/10, or names ending in .local / .lan / .ts.net. Anything else is refused outright.
     */
    fun isAllowedServer(raw: String): Boolean {
        val uri = try { URI(normalizeBase(raw)) } catch (e: Exception) { return false }
        val scheme = uri.scheme?.lowercase() ?: return false
        val host = uri.host?.lowercase()?.trim('[', ']') ?: return false
        if (uri.userInfo != null || host.isEmpty()) return false
        if (scheme == "https") return true
        if (scheme != "http") return false
        if (host == "localhost" || host.endsWith(".local") || host.endsWith(".lan") || host.endsWith(".ts.net")) return true
        parseIpv4(host)?.let { (a, b) ->
            return a == 10 || a == 127 || (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 100 && b in 64..127)
        }
        if (host == "::1" || host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) return host.contains(':')
        return false
    }

    private fun parseIpv4(host: String): Pair<Int, Int>? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val nums = parts.map { it.toIntOrNull() ?: return null }
        if (nums.any { it !in 0..255 }) return null
        return nums[0] to nums[1]
    }

    /** Stable id so re-sending the same message (retries, a second backfill) never creates duplicates on the server. */
    fun smsId(sms: Sms): String {
        val digest = MessageDigest.getInstance("SHA-256").digest("${sms.sender}|${sms.epochMs}|${sms.body}".toByteArray(Charsets.UTF_8))
        return "a-" + digest.joinToString("") { "%02x".format(it) }.take(32)
    }

    fun isoUtc(epochMs: Long): String = java.time.Instant.ofEpochMilli(epochMs).toString()

    fun smsJson(sms: Sms): JSONObject = JSONObject()
        .put("sender", sms.sender.take(100))
        .put("body", sms.body.take(20_000))
        .put("received_at", isoUtc(sms.epochMs))
        .put("id", smsId(sms))

    fun batchJson(items: List<Sms>): JSONObject =
        JSONObject().put("messages", JSONArray(items.take(MAX_BATCH).map { smsJson(it) }))

    fun shareJson(text: String, title: String?): JSONObject {
        val o = JSONObject().put("text", text.take(100_000))
        if (!title.isNullOrBlank()) o.put("title", title.take(300))
        return o
    }

    /** A one-line result for the share dialog, from the server's JSON verdict. */
    fun summarise(responseBody: String): String = try {
        val o = JSONObject(responseBody)
        val label = o.optString("label", "unknown").uppercase()
        val score = o.optInt("score", -1)
        val why = o.optString("summary", "")
        "$label ($score/100)\n$why".trim()
    } catch (e: Exception) {
        "The server replied, but not in the expected format."
    }
}
