package org.ghost.messaging.android

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.ghost.messaging.port.KeyWrapper
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The envelope both DM device keys are stored in (Phase 9 design §13.8, C-23):
 * `nonce(12) ‖ AES-256-GCM(32) ‖ tag(16)`, **60 bytes** — the size §13.8 names for the reference
 * provider, inside the 40..256 bytes the `dm_self` CHECKs admit.
 *
 * It is the pure half of [KeystoreContentKeyWrapper] and [KeystoreStateKeyWrapper]: the Keystore
 * supplies [key], and everything that decides the stored bytes is here, where
 * `KeyEnvelopeTest` runs it on the JVM over a software key.
 *
 * **Associated data.** Each envelope is bound to its purpose ([purpose] is the AEAD's AAD), so the
 * content-key envelope cannot be presented as the state key or the other way round, even under a
 * provider that let one Keystore key serve both.
 *
 * **Failures are one type.** [unwrap] answers every way an envelope can fail to open — a wrong
 * length, a flipped bit, the Keystore key deleted by a device reset, an authentication-bound key
 * outside its window, a provider fault — with [IllegalArgumentException], which is what the
 * [KeyWrapper] port promises its callers (`SelfContexts` reads it as "`dm_self` does not open
 * here", `DmKeys` as `STATE_KEY_UNAVAILABLE`); neither is ever a crash loop. [wrap] fails only when
 * the platform cannot create or use the key at all, as [IllegalStateException].
 */
internal class KeyEnvelope(
    private val purpose: ByteArray,
    private val key: () -> SecretKey,
) {
    fun wrap(plain: ByteArray): ByteArray {
        require(plain.size == KEY_BYTES) { "a DM device key is 32 bytes" }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(purpose)
            val sealed = cipher.doFinal(plain)
            val nonce = cipher.iv
            check(nonce.size == NONCE_BYTES) { "the provider chose a nonce of an unexpected size" }
            nonce + sealed
        } catch (e: GeneralSecurityException) {
            throw IllegalStateException("the DM key wrapper is unavailable", e)
        } catch (e: ProviderException) {
            throw IllegalStateException("the DM key wrapper is unavailable", e)
        }
    }

    fun unwrap(wrapped: ByteArray): ByteArray {
        require(wrapped.size == ENVELOPE_BYTES) { "not a wrapped DM device key" }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key(),
                GCMParameterSpec(TAG_BITS, wrapped, 0, NONCE_BYTES),
            )
            cipher.updateAAD(purpose)
            cipher.doFinal(wrapped, NONCE_BYTES, wrapped.size - NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            throw IllegalArgumentException("the wrapped DM device key does not open", e)
        } catch (e: ProviderException) {
            throw IllegalArgumentException("the wrapped DM device key does not open", e)
        }
    }

    override fun toString(): String = "KeyEnvelope"

    companion object {
        const val KEY_BYTES: Int = 32
        const val NONCE_BYTES: Int = 12
        const val TAG_BITS: Int = 128

        /** `nonce(12) ‖ ciphertext(32) ‖ tag(16)` (§13.8). */
        const val ENVELOPE_BYTES: Int = NONCE_BYTES + KEY_BYTES + TAG_BITS / 8
        const val TRANSFORMATION: String = "AES/GCM/NoPadding"
    }
}

/**
 * A non-exportable AES-256-GCM key in the Android Keystore under [alias], created on first use with
 * **the database key's authentication policy** (§13.8, ADR-20 Q6): not authentication-bound unless
 * [requireUserAuthentication], which the app sets from the same constant as its database key
 * (`DatabaseAccess.AUTH_BOUND`). StrongBox when the device has one, the TEE otherwise — the same
 * choice `AndroidKeystoreWrapper` makes for the seed.
 */
internal class KeystoreSecretKey(
    private val alias: String,
    private val requireUserAuthentication: Boolean,
) {
    fun get(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (requireUserAuthentication) {
            spec.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                spec.setUserAuthenticationParameters(
                    AUTH_VALIDITY_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
            }
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generator.init(spec.setIsStrongBoxBacked(true).build())
                return generator.generateKey()
            } catch (e: GeneralSecurityException) {
                // No StrongBox on this device: the TEE-backed Keystore below (still non-exportable).
                Unit
            } catch (e: ProviderException) {
                // StrongBox refused the key (`StrongBoxUnavailableException` is a ProviderException).
                Unit
            }
        }
        generator.init(spec.setIsStrongBoxBacked(false).build())
        return generator.generateKey()
    }

    override fun toString(): String = "KeystoreSecretKey"

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** The database key's window when it is authentication-bound (`AndroidKeystoreWrapper`). */
        const val AUTH_VALIDITY_SECONDS = 30
    }
}

/**
 * `KeystoreContentKeyWrapper` of §13.1 `…messaging.android` and §13.8: wraps the 32-byte content
 * key of `dm_self.content_key_wrapped`, under which `body_env`, `card_env`, `name_env`,
 * `grapheme_env` and `l1_env` are sealed. Deferred to this slice by §22.11 item 9(b).
 */
class KeystoreContentKeyWrapper(requireUserAuthentication: Boolean) : KeyWrapper {
    private val envelope = KeyEnvelope(PURPOSE, KeystoreSecretKey(ALIAS, requireUserAuthentication)::get)

    override fun wrap(key: ByteArray): ByteArray = envelope.wrap(key)

    override fun unwrap(wrapped: ByteArray): ByteArray = envelope.unwrap(wrapped)

    override fun toString(): String = "KeystoreContentKeyWrapper"

    companion object {
        /** The Keystore alias; distinct from the seed's and the database key's. */
        const val ALIAS: String = "ghost.v1.dm-content-key"
        internal val PURPOSE: ByteArray = "ghost/v1/dm/wrap/content-key".toByteArray(Charsets.US_ASCII)
    }
}

/**
 * `KeystoreStateKeyWrapper` of §13.1 `…messaging.android` and §2.5: wraps `session_state_key`
 * (`dm_self.state_key_wrapped`), which is unwrapped only into the native DM context at unlock
 * (`DmKeys`). Deferred to this slice by §22.11 item 9(b).
 */
class KeystoreStateKeyWrapper(requireUserAuthentication: Boolean) : KeyWrapper {
    private val envelope = KeyEnvelope(PURPOSE, KeystoreSecretKey(ALIAS, requireUserAuthentication)::get)

    override fun wrap(key: ByteArray): ByteArray = envelope.wrap(key)

    override fun unwrap(wrapped: ByteArray): ByteArray = envelope.unwrap(wrapped)

    override fun toString(): String = "KeystoreStateKeyWrapper"

    companion object {
        /** The Keystore alias; distinct from the content key's, so a key serves one purpose. */
        const val ALIAS: String = "ghost.v1.dm-state-key"
        internal val PURPOSE: ByteArray = "ghost/v1/dm/wrap/state-key".toByteArray(Charsets.US_ASCII)
    }
}
