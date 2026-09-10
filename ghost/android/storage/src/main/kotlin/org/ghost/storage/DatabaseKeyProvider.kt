package org.ghost.storage

import org.ghost.identity.SecretWrapper
import org.ghost.identity.WrappedSecretStore
import java.security.SecureRandom

/**
 * The SQLCipher database key: 32 random bytes generated once, kept only as a Keystore-wrapped
 * envelope in no-backup storage (FR-7.2 "Keystore-wrapped database key"). The raw key exists in
 * memory only while the database is open; callers zeroize it after passing it to SQLCipher.
 */
class DatabaseKeyProvider(
    private val wrapper: SecretWrapper,
    private val store: WrappedSecretStore,
    private val random: SecureRandom = SecureRandom(),
) {
    fun exists(): Boolean = store.read(ENVELOPE_NAME) != null

    fun getOrCreate(): ByteArray {
        store.read(ENVELOPE_NAME)?.let { return wrapper.unwrap(it) }
        val key = ByteArray(KEY_BYTES).also(random::nextBytes)
        store.write(ENVELOPE_NAME, wrapper.wrap(key))
        return key
    }

    /** Local wipe: without the envelope the database file is unreadable ciphertext. */
    fun destroy() = store.delete(ENVELOPE_NAME)

    companion object {
        const val ENVELOPE_NAME = "db-key.v1"
        const val KEY_BYTES = 32
    }
}
