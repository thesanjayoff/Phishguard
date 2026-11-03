package app.phishguard.companion

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/** Server address and token, stored encrypted with a key that lives in the Android Keystore. */
object Prefs {
    private fun sp(ctx: Context): SharedPreferences {
        val key = MasterKey.Builder(ctx.applicationContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            ctx.applicationContext, "phishguard_companion", key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun server(ctx: Context): String = sp(ctx).getString("server", "") ?: ""
    fun token(ctx: Context): String = sp(ctx).getString("token", "") ?: ""
    fun liveSync(ctx: Context): Boolean = sp(ctx).getBoolean("live", false)

    fun save(ctx: Context, server: String, token: String, live: Boolean) {
        sp(ctx).edit().putString("server", Protocol.normalizeBase(server)).putString("token", token.trim()).putBoolean("live", live).apply()
    }

    fun isConfigured(ctx: Context): Boolean = Protocol.isAllowedServer(server(ctx)) && token(ctx).isNotEmpty()
}
