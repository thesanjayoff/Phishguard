package app.phishguard.companion

import android.content.Context
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

class ApiException(message: String, val status: Int = -1) : Exception(message)

/** Minimal HTTP client for your own PhishGuard server. No third-party services, no redirects followed (the token must never be forwarded). */
object Api {
    private const val MAX_RESPONSE = 1 shl 20

    private fun open(ctx: Context, path: String): HttpURLConnection {
        val base = Prefs.server(ctx)
        if (!Protocol.isAllowedServer(base)) throw ApiException("The server address is not allowed (use https, or an address on your own network).")
        val token = Prefs.token(ctx)
        if (token.isEmpty()) throw ApiException("No token set.")
        val c = URL(base + path).openConnection() as HttpURLConnection
        c.instanceFollowRedirects = false
        c.connectTimeout = 8_000
        c.readTimeout = 120_000   // a deep check can include an isolated browser visit
        c.setRequestProperty("Authorization", "Bearer $token")
        c.setRequestProperty("Accept", "application/json")
        return c
    }

    private fun read(c: HttpURLConnection): Pair<Int, String> {
        val code = c.responseCode
        val stream = if (code in 200..299) c.inputStream else (c.errorStream ?: return code to "")
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        stream.use { s ->
            while (out.size() < MAX_RESPONSE) {
                val n = s.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
        }
        return code to out.toString("UTF-8")
    }

    fun get(ctx: Context, path: String): String {
        val c = open(ctx, path)
        try {
            val (code, body) = read(c)
            if (code !in 200..299) throw ApiException(errorText(code, body), code)
            return body
        } finally { c.disconnect() }
    }

    fun post(ctx: Context, path: String, json: JSONObject): String {
        val c = open(ctx, path)
        try {
            c.requestMethod = "POST"
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            c.outputStream.use { it.write(json.toString().toByteArray(Charsets.UTF_8)) }
            val (code, body) = read(c)
            if (code !in 200..299) throw ApiException(errorText(code, body), code)
            return body
        } finally { c.disconnect() }
    }

    private fun errorText(code: Int, body: String): String = when (code) {
        401 -> "The server rejected the token (HTTP 401). Copy it again from data/token on your PC."
        403 -> "The server refused this (HTTP 403). Is SMS ingest enabled in its config?"
        else -> "HTTP $code" + if (body.isNotBlank()) ": " + body.take(160) else ""
    }
}
