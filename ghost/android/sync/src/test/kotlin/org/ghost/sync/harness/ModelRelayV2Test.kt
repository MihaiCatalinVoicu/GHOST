package org.ghost.sync.harness

import org.ghost.sync.api.NamespaceId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The model relay reads write capabilities v2 (Phase 8 design §10.3, §19.17 point 5): a redeemed
 * capability (98 bytes, a 16-byte serial after the v1 header, MAC over bytes 0..66) authorizes
 * stores and reads of its namespace like a v1 one, each serial has its own quota ledger entry, and
 * a changed serial, MAC or length is refused. `relay_semantics.txt` and its replay are unchanged.
 */
class ModelRelayV2Test {
    private val key = ByteArray(32) { (it * 3 + 1).toByte() }
    private val ns = NamespaceId(MessageDigest.getInstance("SHA-256").digest("v2".toByteArray()))
    private val now = 1_800_000_000L

    private fun v2(serial: Int, quota: Long = 1L shl 28, expiry: Long = now + 86_400, namespace: NamespaceId = ns): ByteArray {
        val body = ByteBuffer.allocate(ModelRelay.BODY_V2_BYTES).put(ModelRelay.VERSION_2).put(ModelRelay.KIND_WRITE.toByte())
            .put(namespace.toByteArray()).putLong(quota).putLong(expiry).put(ByteArray(16) { serial.toByte() }).array()
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(body)
        return body + mac
    }

    @Test
    fun aV2CapabilityWritesAndReadsItsNamespaceWithItsOwnLedger() {
        val relay = ModelRelay("r", key)
        val cap = v2(1, quota = 1024)
        assertEquals(ModelRelay.TOKEN_V2_BYTES, cap.size)
        assertNotNull(ModelRelay.header(cap))
        val header = checkNotNull(ModelRelay.header(cap))
        assertEquals(ModelRelay.KIND_WRITE, header.kind)
        assertEquals(ns, header.namespace)
        val a = ByteArray(1024) { 1 }
        val stored = relay.store(ns, a, cap, 3_600, now)
        assertTrue("a v2 write capability stores", stored is ModelRelay.Reply.Ok)
        assertTrue("write grants read", relay.get(ModelRelay.sha256(a), cap, now) is ModelRelay.Reply.Ok)
        // The ledger is per capability: the first one is spent, a second serial still stores.
        val b = ByteArray(1024) { 2 }
        assertEquals("quota", (relay.store(ns, b, cap, 3_600, now) as ModelRelay.Reply.Err).category)
        assertTrue(relay.store(ns, b, v2(2, quota = 1024), 3_600, now) is ModelRelay.Reply.Ok)
    }

    @Test
    fun aChangedSerialMacOrLengthIsRefused() {
        val relay = ModelRelay("r", key)
        val data = ByteArray(1024) { 3 }
        for (i in listOf(50, 65, 66, 97)) {
            val bad = v2(1).also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertEquals("byte $i", "unauthorized", (relay.store(ns, data, bad, 3_600, now) as ModelRelay.Reply.Err).category)
        }
        assertNull(ModelRelay.header(v2(1).copyOf(97)))
        assertNull(ModelRelay.header(v2(1) + byteArrayOf(0)))
        val otherNs = NamespaceId(ByteArray(32) { 9 })
        assertEquals("unauthorized", (relay.store(ns, data, v2(1, namespace = otherNs), 3_600, now) as ModelRelay.Reply.Err).category)
        assertEquals("unauthorized", (relay.store(ns, data, v2(1, expiry = now), 3_600, now) as ModelRelay.Reply.Err).category)
        // A v1 capability still verifies.
        assertTrue(relay.store(ns, data, relay.mint(ModelRelay.KIND_WRITE, ns, 1L shl 20, now + 3_600), 3_600, now) is ModelRelay.Reply.Ok)
    }
}
