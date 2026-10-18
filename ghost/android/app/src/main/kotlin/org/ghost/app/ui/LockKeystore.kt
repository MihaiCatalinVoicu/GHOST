package org.ghost.app.ui

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.ghost.storage.SqlExecutor
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Phase 13 design §5.2's byte-level verifier, production halves.
 *
 * [KeystorePinMac] is the `tag = HMAC-SHA256(K_pin, "ghost/v1/app-pin" ‖ 0x00 ‖ salt ‖ digits)`
 * step: `K_pin` a non-exportable Keystore HMAC-SHA256 key, alias "ghost.v1.pin-mac", StrongBox
 * when [strongBox] (the platform's FEATURE_STRONGBOX_KEYSTORE signal, read once by the wiring),
 * with no user-authentication requirement. Without the device's Keystore a copied database gives
 * no PIN (each guess needs `K_pin`); with root, guesses run at Keystore speed (V-U10 measures
 * it — declared, L11-U8).
 */
class KeystorePinMac(private val strongBox: Boolean) : LockController.Mac {
    private val mac: Mac = Mac.getInstance("HmacSHA256").apply {
        init(pinKey())
    }

    override fun tag(salt: ByteArray, digits: CharArray): ByteArray {
        val label = LABEL
        val input = ByteArray(label.size + 1 + salt.size + digits.size)
        try {
            System.arraycopy(label, 0, input, 0, label.size)
            input[label.size] = 0
            System.arraycopy(salt, 0, input, label.size + 1, salt.size)
            for (i in digits.indices) input[label.size + 1 + salt.size + i] = digits[i].code.toByte()
            return mac.doFinal(input)
        } finally {
            input.fill(0)
        }
    }

    private fun pinKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            // No setUserAuthenticationRequired: the app lock, not device auth, guards the PIN
            // record (§5.2; the strict binding is its own deferred design, Q6).
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "ghost.v1.pin-mac"
        private val LABEL = "ghost/v1/app-pin".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * The `ui_lock` half of §5.2: the salt, the tag and the failure counter, the counter committed
 * before the check (the [LockController] orders the calls; this store only persists). No retry
 * time exists in this table (T33).
 */
class LockStore(private val executor: () -> SqlExecutor?) : LockController.Store {
    override fun read(): LockController.PinRecord? {
        val db = executor() ?: return null
        var record: LockController.PinRecord? = null
        db.query("SELECT salt, tag, failures FROM ui_lock WHERE id = 1") { row ->
            record = LockController.PinRecord(row.blob(0), row.blob(1), row.long(2).toInt())
        }
        return record
    }

    override fun write(record: LockController.PinRecord) {
        val db = executor() ?: return
        db.transaction {
            db.execUpdate(
                "INSERT INTO ui_lock (id, salt, tag, failures) VALUES (1, ?, ?, ?) " +
                    "ON CONFLICT(id) DO UPDATE SET salt = excluded.salt, tag = excluded.tag, failures = excluded.failures",
                listOf(record.salt, record.tag, record.failures.toLong()),
            )
        }
    }
}
