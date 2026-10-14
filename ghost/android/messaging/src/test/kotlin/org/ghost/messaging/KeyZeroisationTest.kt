package org.ghost.messaging

import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.engine.RecognitionKeys
import org.ghost.messaging.engine.SelfContext
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.store.ContentCipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

/**
 * §13.7 "Lock and wipe … zeroize the Kotlin-side key material" (L7-D19; S12 review): the objects
 * that hold that material in `:messaging` fill it with zeros when the context closes, rather than
 * only dropping their references. Until the review, `RecognitionKeys.clear()` emptied its maps and
 * `SelfContexts.invalidate()` cleared the content key alone, so `seen_key`, the own card (with
 * `card_secret_0`) and the recognition keys stayed in the heap after a lock.
 */
class KeyZeroisationTest {

    private fun filled(size: Int, value: Int) = ByteArray(size) { value.toByte() }

    private fun zero(bytes: ByteArray): Boolean = bytes.all { it == 0.toByte() }

    @Test
    fun aClearedSelfContextHoldsNoSecret() {
        val card = DmSessions.OwnCard(
            card = filled(131, 1),
            inboxNamespace = filled(32, 2),
            bundleNamespace = filled(32, 3),
            mediaNamespace = filled(32, 9),
            recognitionIntro = filled(32, 4),
            recognitionBundle = filled(32, 5),
            olmIdentity = filled(32, 6),
            publicationOffsetSeconds = 60,
        )
        val self = SelfContext(cardIndex = 0, card = card, content = ContentCipher(filled(32, 7)), seenKey = filled(32, 8))
        self.clear()
        assertTrue("the card carries card_secret_0 (§3.3)", zero(card.card))
        assertTrue(zero(card.recognitionIntro))
        assertTrue(zero(card.recognitionBundle))
        assertTrue("seen_key", zero(self.seenKey))
        // Relay-visible or public values are not secrets and stay.
        assertArrayEquals(filled(32, 2), card.inboxNamespace)
        assertArrayEquals(filled(32, 6), card.olmIdentity)
    }

    private fun recognition(): RecognitionKeys = RecognitionKeys(
        Proxy.newProxyInstance(DmEnvelopes::class.java.classLoader, arrayOf(DmEnvelopes::class.java)) { _, method, _ ->
            if (method.name == "toString") "NoEnvelopes" else throw UnsupportedOperationException(method.name)
        } as DmEnvelopes,
    )

    @Suppress("UNCHECKED_CAST")
    private fun cache(keys: RecognitionKeys): MutableMap<List<Byte>, DmPairing.Provisional> =
        RecognitionKeys::class.java.getDeclaredField("provisional").apply { isAccessible = true }.get(keys)
            as MutableMap<List<Byte>, DmPairing.Provisional>

    private fun provisional(seed: Int) = DmPairing.Provisional(
        outEnv = filled(48, seed),
        outDirection = 0,
        inEnv = filled(48, seed + 1),
        inDirection = 1,
        recognitionOut = filled(32, seed + 2),
        recognitionIn = filled(32, seed + 3),
    )

    @Test
    fun clearZeroisesEveryCachedRecognitionKey() {
        val keys = recognition()
        val a = provisional(0x10)
        val b = provisional(0x20)
        cache(keys)[listOf<Byte>(1)] = a
        cache(keys)[listOf<Byte>(2)] = b
        keys.clear()
        for (p in listOf(a, b)) {
            assertTrue(zero(p.recognitionIn))
            assertTrue(zero(p.recognitionOut))
        }
        assertTrue(cache(keys).isEmpty())
    }

    @Test
    fun aForgottenSessionsRecognitionKeysAreZeroised() {
        val keys = recognition()
        val gone = provisional(0x30)
        val kept = provisional(0x40)
        cache(keys)[byteArrayOf(9, 9).toList()] = gone
        cache(keys)[byteArrayOf(8, 8).toList()] = kept
        keys.forgetSession(byteArrayOf(9, 9))
        assertTrue(zero(gone.recognitionIn))
        assertTrue(zero(gone.recognitionOut))
        assertArrayEquals("another session's keys are untouched", filled(32, 0x43), kept.recognitionIn)
    }
}
