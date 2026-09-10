package org.ghost.identity

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM wrapping key generated inside the Android Keystore (StrongBox when available),
 * non-exportable (FR-1.7, ADR-14). `requireUserAuthentication` binds unwrapping to a recent
 * biometric/PIN unlock; the policy is configurable per FR-1.7.
 */
class AndroidKeystoreWrapper(
    private val alias: String = DEFAULT_ALIAS,
    private val requireUserAuthentication: Boolean = false,
    private val authValiditySeconds: Int = 30,
) : SecretWrapper {

    override fun wrap(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, obtainKey())
        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv
        return byteArrayOf(ENVELOPE_VERSION, iv.size.toByte()) + iv + ciphertext
    }

    override fun unwrap(envelope: ByteArray): ByteArray {
        if (envelope.size < 2 || envelope[0] != ENVELOPE_VERSION) throw IllegalArgumentException("envelope version unsupported")
        val ivLen = envelope[1].toInt() and 0xff
        if (ivLen != IV_BYTES || envelope.size <= 2 + ivLen) throw IllegalArgumentException("envelope malformed")
        val iv = envelope.copyOfRange(2, 2 + ivLen)
        val ciphertext = envelope.copyOfRange(2 + ivLen, envelope.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, obtainKey(), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun obtainKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (requireUserAuthentication) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    authValiditySeconds,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(authValiditySeconds)
            }
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generator.init(builder.setIsStrongBoxBacked(true).build())
                return generator.generateKey()
            } catch (e: Exception) {
                // No StrongBox on this device: fall back to the TEE-backed Keystore (still non-exportable).
            }
        }
        generator.init(builder.setIsStrongBoxBacked(false).build())
        return generator.generateKey()
    }

    companion object {
        const val DEFAULT_ALIAS = "ghost.v1.secret-wrap"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val ENVELOPE_VERSION: Byte = 1
    }
}

/**
 * Stores envelopes under `noBackupFilesDir`, which Android excludes from auto-backup and
 * device-to-device transfer regardless of manifest rules (FR-7.9, defence in depth).
 */
class NoBackupFileSecretStore(context: Context) : WrappedSecretStore {
    private val dir: File = File(context.noBackupFilesDir, "secrets").apply { mkdirs() }

    override fun write(name: String, envelope: ByteArray) {
        val target = File(dir, name)
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(envelope)
        if (!tmp.renameTo(target)) {
            target.writeBytes(envelope)
            tmp.delete()
        }
    }

    override fun read(name: String): ByteArray? = File(dir, name).takeIf { it.isFile }?.readBytes()

    override fun delete(name: String) {
        File(dir, name).delete()
    }
}
