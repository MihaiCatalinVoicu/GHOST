package org.ghost.messaging.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * The envelope of the two DM device keys (Phase 9 design §13.8; slice S12), on the JVM over a
 * software AES key: the Keystore half — a non-exportable key under an alias — is the platform's
 * and runs on the emulator and the devices, while every byte of the stored envelope is decided here.
 */
class KeyEnvelopeTest {

    private val aes: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val other: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val key = ByteArray(32) { (it * 3 + 1).toByte() }

    private fun content(k: SecretKey = aes) = KeyEnvelope(KeystoreContentKeyWrapper.PURPOSE) { k }

    private fun state(k: SecretKey = aes) = KeyEnvelope(KeystoreStateKeyWrapper.PURPOSE) { k }

    @Test
    fun theEnvelopeIsSixtyBytesAndOpensToTheKey() {
        val wrapped = content().wrap(key)
        assertEquals("nonce(12) ‖ AES-256-GCM(32) ‖ tag(16), §13.8", 60, wrapped.size)
        assertEquals(KeyEnvelope.ENVELOPE_BYTES, wrapped.size)
        assertArrayEquals(key, content().unwrap(wrapped))
    }

    @Test
    fun theSchemaAdmitsTheEnvelope() {
        // `dm_self.content_key_wrapped` and `state_key_wrapped` carry a 40..256-byte CHECK.
        assertEquals(true, KeyEnvelope.ENVELOPE_BYTES in 40..256)
    }

    @Test
    fun everyWrapDrawsAFreshNonce() {
        val a = content().wrap(key)
        val b = content().wrap(key)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun aContentKeyEnvelopeDoesNotOpenAsTheStateKey() {
        // The purpose is the AEAD's associated data, so the two envelopes cannot be swapped even
        // under a provider that let one key serve both.
        val wrapped = content().wrap(key)
        assertThrows(IllegalArgumentException::class.java) { state().unwrap(wrapped) }
    }

    @Test
    fun everyWayAnEnvelopeFailsIsOneType() {
        val wrapped = content().wrap(key)
        for (i in wrapped.indices) {
            val flipped = wrapped.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) { content().unwrap(flipped) }
        }
        assertThrows(IllegalArgumentException::class.java) { content().unwrap(wrapped.copyOf(59)) }
        assertThrows(IllegalArgumentException::class.java) { content().unwrap(wrapped + byteArrayOf(0)) }
        // The Keystore key a device reset deleted: another key under the same alias.
        assertThrows(IllegalArgumentException::class.java) { content(other).unwrap(wrapped) }
    }

    @Test
    fun onlyAThirtyTwoByteKeyIsWrapped() {
        assertThrows(IllegalArgumentException::class.java) { content().wrap(ByteArray(31)) }
    }
}
