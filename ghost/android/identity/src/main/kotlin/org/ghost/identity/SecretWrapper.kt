package org.ghost.identity

/**
 * Wraps long-lived local secrets (root entropy, later the DB key) with a key that never leaves
 * the platform Keystore (FR-1.7, TB-1). The Android implementation lives in
 * [AndroidKeystoreWrapper]; tests use an in-process AES-GCM implementation with the same contract.
 */
interface SecretWrapper {
    /** Returns an opaque envelope: only [unwrap] on the same device/key can open it. */
    fun wrap(plaintext: ByteArray): ByteArray

    /** Throws if the envelope was tampered with or the wrapping key is gone (device reset). */
    fun unwrap(envelope: ByteArray): ByteArray
}

/** Persists wrapped envelopes. Implementations must use no-backup storage (FR-7.9). */
interface WrappedSecretStore {
    fun write(name: String, envelope: ByteArray)
    fun read(name: String): ByteArray?
    fun delete(name: String)
}

class InMemoryWrappedSecretStore : WrappedSecretStore {
    private val map = HashMap<String, ByteArray>()
    override fun write(name: String, envelope: ByteArray) { map[name] = envelope.copyOf() }
    override fun read(name: String): ByteArray? = map[name]?.copyOf()
    override fun delete(name: String) { map.remove(name) }
}
