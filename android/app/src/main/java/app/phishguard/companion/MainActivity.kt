package app.phishguard.companion

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import kotlin.concurrent.thread

/** One screen: where your PhishGuard server is, the token, and whether new SMS are sent automatically. */
class MainActivity : Activity() {
    private lateinit var server: EditText
    private lateinit var token: EditText
    private lateinit var live: Switch
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }

        fun label(t: String) = TextView(this).apply { text = t; setPadding(0, pad / 2, 0, 0) }
        fun button(t: String, onClick: () -> Unit) = Button(this).apply { text = t; setOnClickListener { onClick() } }

        root.addView(TextView(this).apply {
            text = "Sends text messages to YOUR PhishGuard server on your own PC or network, and nowhere else. " +
                "It only reads SMS; it never sends, changes or deletes them."
        })
        server = EditText(this).apply { hint = "http://192.168.1.20:8765"; inputType = InputType.TYPE_TEXT_VARIATION_URI; setSingleLine() }
        token = EditText(this).apply { hint = "token (contents of data/token on your PC)"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD; setSingleLine() }
        live = Switch(this).apply { text = "Send new SMS automatically" }
        status = TextView(this).apply { setPadding(0, pad, 0, 0) }

        root.addView(label("Server address")); root.addView(server)
        root.addView(label("Token")); root.addView(token)
        root.addView(live)
        root.addView(button("Save and test connection") { saveAndTest() })
        root.addView(button("Allow SMS access") { requestSms() })
        root.addView(button("Send the last 7 days of SMS now") { backfill(7) })
        root.addView(status)

        setContentView(ScrollView(this).apply { addView(root, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)) })

        server.setText(Prefs.server(this))
        token.setText(Prefs.token(this))
        live.isChecked = Prefs.liveSync(this)
        refreshStatus()
    }

    private fun smsGranted() =
        checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED &&
            checkSelfPermission(Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED

    private fun refreshStatus(extra: String = "") {
        val lines = mutableListOf<String>()
        lines += if (Prefs.isConfigured(this)) "Server: ${Prefs.server(this)}" else "Not configured yet."
        lines += if (smsGranted()) "SMS access: allowed" else "SMS access: not allowed yet"
        lines += "Waiting to upload: ${Outbox.size(this)}"
        if (extra.isNotEmpty()) lines += extra
        status.text = lines.joinToString("\n")
    }

    private fun requestSms() {
        requestPermissions(arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS), 1)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        refreshStatus()
    }

    private fun saveAndTest() {
        val base = Protocol.normalizeBase(server.text.toString())
        if (!Protocol.isAllowedServer(base)) {
            refreshStatus("Refused: use https://, or an http:// address on your own network (192.168.x.x, 10.x.x.x, 172.16-31.x.x, *.local, Tailscale 100.x).")
            return
        }
        Prefs.save(this, base, token.text.toString(), live.isChecked)
        refreshStatus("Testing...")
        thread {
            val result = try {
                Api.get(this, "/api/status"); "Connected. The token works."
            } catch (e: ApiException) {
                e.message ?: "Failed."
            } catch (e: Exception) {
                "Could not reach the server (${e.javaClass.simpleName})."
            }
            runOnUiThread { refreshStatus(result) }
        }
    }

    private fun backfill(days: Int) {
        if (!Prefs.isConfigured(this)) return refreshStatus("Save the server address and token first.")
        if (!smsGranted()) return refreshStatus("Allow SMS access first.")
        thread {
            val n = try { InboxSync.queueRecent(this, days) } catch (e: Exception) { -1 }
            runOnUiThread { refreshStatus(if (n < 0) "Could not read the inbox." else "Queued $n messages from the last $days days.") }
        }
    }
}
