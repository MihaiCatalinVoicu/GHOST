package org.ghost.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Decoders of the native wire formats (client-core/net/src/jni_bridge.rs), the argument checks
 * made before a native call, and the interface overloads without a deadline. Pure JVM: nothing
 * here loads the native library.
 */
class RelayWireTest {
    private fun hash(b: Int) = ByteArray(32) { b.toByte() }

    private fun long8(v: Long) = ByteArray(8) { i -> (v ushr (8 * (7 - i))).toByte() }

    private fun malformed(block: () -> Unit) {
        val e = assertThrows(NetworkException::class.java) { block() }
        assertEquals("malformed_response", e.category)
    }

    @Test
    fun receiptDecoding() {
        val h = hash(7)
        val r = TorRelayTransport.decodeReceipt(h + byteArrayOf(0, 0, 0, 0, 0x68, 0xC1.toByte(), 0x2E, 0x10))
        assertEquals(0x68C12E10L, r.expiryUnixSeconds)
        assertTrue(r.blobHash.contentEquals(h))
        malformed { TorRelayTransport.decodeReceipt(ByteArray(39)) }
        malformed { TorRelayTransport.decodeReceipt(ByteArray(41)) }
        // An expiry beyond Long.MAX_VALUE (top bit set) is not a valid unix time.
        malformed { TorRelayTransport.decodeReceipt(h + long8(-1L)) }
    }

    @Test
    fun fetchedBlobDecoding() {
        for (size in TorRelayTransport.BUCKET_SIZES) {
            val data = ByteArray(size) { (it % 251).toByte() }
            val blob = TorRelayTransport.decodeFetched(long8(1_800_000_000L) + data)
            assertEquals(1_800_000_000L, blob.expiryUnixSeconds)
            assertArrayEquals(data, blob.ciphertext)
        }
        assertEquals(0L, TorRelayTransport.decodeFetched(long8(0) + ByteArray(1024)).expiryUnixSeconds)
        val bad = listOf(
            ByteArray(0),
            ByteArray(7),
            ByteArray(8), // expiry without data
            long8(1) + ByteArray(1000), // not a bucket
            long8(1) + ByteArray(1025),
            long8(1) + ByteArray(65536 + 1),
            long8(Long.MIN_VALUE) + ByteArray(1024), // negative expiry
        )
        for (b in bad) malformed { TorRelayTransport.decodeFetched(b) }
        // toString never shows ciphertext bytes.
        val shown = TorRelayTransport.decodeFetched(long8(5) + ByteArray(1024) { 0x41 }).toString()
        assertEquals("FetchedBlob(size=1024)", shown)
    }

    @Test
    fun pageDecodingIsStrict() {
        val cursor = ByteArray(8) { 1 }
        val h1 = hash(2)
        val page = TorRelayTransport.decodePage(byteArrayOf(8) + cursor + h1, 1)
        assertEquals(1, page.hashes.size)
        assertEquals(8, page.nextCursor.size)
        assertEquals(0, TorRelayTransport.decodePage(byteArrayOf(0), 1).hashes.size)
        val bad = listOf(
            ByteArray(0),
            byteArrayOf(0, 1, 2),
            byteArrayOf(3, 1, 2, 3) + h1,
            // 32-aligned bodies with a cursor length other than 0/8 (accepted by a "% 32" check alone)
            byteArrayOf(16) + ByteArray(16) + h1,
            byteArrayOf(32) + ByteArray(32),
            // more hashes than the requested limit
            byteArrayOf(0) + h1 + h1,
        )
        for (b in bad) malformed { TorRelayTransport.decodePage(b, 1) }
    }

    @Test
    fun checkDecodingIsStrict() {
        val a = hash(1)
        val b = hash(2)
        val c = hash(3)
        val asked = listOf(a, b)
        assertEquals(0, TorRelayTransport.decodeCheck(ByteArray(0), asked).size)
        val held = TorRelayTransport.decodeCheck(b + a, asked)
        assertEquals(2, held.size)
        assertArrayEquals(b, held[0])
        assertArrayEquals(a, held[1])
        val bad = listOf(
            ByteArray(31), // not whole hashes
            a + ByteArray(1),
            a + b + a, // more than requested
            a + a, // a requested hash twice, within the requested count
            c, // never requested
            a + c,
        )
        for (raw in bad) malformed { TorRelayTransport.decodeCheck(raw, asked) }
    }

    @Test
    fun checkRequestPacking() {
        val packed = TorRelayTransport.packHashes(listOf(hash(1), hash(2)))
        assertArrayEquals(hash(1) + hash(2), packed)
        assertEquals(256 * 32, TorRelayTransport.packHashes(List(256) { hash(it) }).size)
        assertThrows(IllegalArgumentException::class.java) { TorRelayTransport.packHashes(emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { TorRelayTransport.packHashes(List(257) { hash(it) }) }
        assertThrows(IllegalArgumentException::class.java) { TorRelayTransport.packHashes(listOf(ByteArray(31))) }
        // A repeated hash (equal content, distinct arrays) is refused before the native call.
        assertThrows(IllegalArgumentException::class.java) { TorRelayTransport.packHashes(listOf(hash(1), hash(2), hash(1))) }
    }

    /** `RegisterKey` answers (Phase 9 design §4.2, §4.4): 25 bytes, validity exactly on OK. */
    @Test
    fun registerDecodingIsStrict() {
        val validUntil = 1_791_000_000L
        val ok = TorRelayTransport.decodeRegister(byteArrayOf(1) + long8(2959) + long8(29_850_000) + long8(validUntil))
        assertEquals(TorRelayTransport.REGISTER_OK, ok.result)
        assertEquals(2959L, ok.relayPeriodId)
        assertEquals(29_850_000L, ok.relayMinute)
        assertEquals(validUntil, ok.validUntilUnixSeconds)
        assertEquals("RegisterAnswer(result=1)", ok.toString())
        val wrongPeriod = TorRelayTransport.decodeRegister(byteArrayOf(2) + long8(2959) + long8(29_850_000) + long8(0))
        assertEquals(TorRelayTransport.REGISTER_WRONG_PERIOD, wrongPeriod.result)
        assertEquals(0L, wrongPeriod.validUntilUnixSeconds)
        val bad = listOf(
            ByteArray(24),
            ByteArray(26),
            byteArrayOf(0) + long8(2959) + long8(1) + long8(0), // REGISTER_RESULT_UNSPECIFIED
            byteArrayOf(3) + long8(2959) + long8(1) + long8(validUntil), // no such result
            byteArrayOf(1) + long8(2959) + long8(1) + long8(0), // OK without a validity
            byteArrayOf(2) + long8(2959) + long8(1) + long8(validUntil), // WRONG_PERIOD with one
            byteArrayOf(1) + long8(-1L) + long8(1) + long8(validUntil), // negative period
            byteArrayOf(1) + long8(2959) + long8(-1L) + long8(validUntil), // negative minute
            byteArrayOf(1) + long8(2959) + long8(1) + long8(-1L), // negative validity
        )
        for (b in bad) malformed { TorRelayTransport.decodeRegister(b) }
    }

    /** The key kinds are the `KeyKind` values of `relay.proto`; 2 is Write and is never one. */
    @Test
    fun keyKindCodes() {
        assertEquals(1, TorRelayTransport.KeyKind.READ.code)
        assertEquals(3, TorRelayTransport.KeyKind.DEPOSIT.code)
        assertEquals(4, TorRelayTransport.KeyKind.FETCH.code)
        assertEquals(3, TorRelayTransport.KeyKind.entries.size)
        assertTrue(TorRelayTransport.KeyKind.entries.none { it.code == 0 || it.code == 2 })
    }

    @Test
    fun deadlinesAreOneToSixtyThousandMillis() {
        TorRelayTransport.requireDeadline(1)
        TorRelayTransport.requireDeadline(20_000)
        TorRelayTransport.requireDeadline(RelayTransport.MAX_DEADLINE_MILLIS)
        for (bad in listOf(0, -1, Int.MIN_VALUE, 60_001, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { TorRelayTransport.requireDeadline(bad) }
        }
        assertEquals(60_000, RelayTransport.MAX_DEADLINE_MILLIS)
    }

    /** Records the deadline each call received; answers with fixed values. */
    private class RecordingTransport : RelayTransport {
        val deadlines = ArrayList<Int>()

        override fun bootstrap() {}

        override fun store(
            relay: OnionAddress,
            namespace: ByteArray,
            capability: ByteArray,
            ciphertext: ByteArray,
            ttlSeconds: Int,
            deadlineMillis: Int,
        ): RelayTransport.StoreReceipt {
            deadlines += deadlineMillis
            return RelayTransport.StoreReceipt(ByteArray(32), 1L)
        }

        override fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): RelayTransport.FetchedBlob {
            deadlines += deadlineMillis
            return RelayTransport.FetchedBlob(ByteArray(1024), 2L)
        }

        override fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): RelayTransport.Page {
            deadlines += deadlineMillis
            return RelayTransport.Page(emptyList(), ByteArray(0))
        }

        override fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray> {
            deadlines += deadlineMillis
            return hashes
        }

        override fun rotateCircuits() {}

        override fun close() {}
    }

    @Test
    fun overloadsWithoutDeadlineUseTheMaximum() {
        val relay = OnionAddress.parse("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443")
        val t: RelayTransport = RecordingTransport()
        val ns = ByteArray(32)
        t.store(relay, ns, ByteArray(82), ByteArray(1024), 86_400)
        t.get(relay, ns, ByteArray(82), ByteArray(32))
        t.list(relay, ns, ByteArray(82), ByteArray(0), 128)
        t.store(relay, ns, ByteArray(82), ByteArray(1024), 86_400, 1_234)
        t.get(relay, ns, ByteArray(82), ByteArray(32), 20_000)
        t.list(relay, ns, ByteArray(82), ByteArray(0), 128, 20_000)
        t.check(relay, ns, ByteArray(82), listOf(ByteArray(32)), 5_000)
        assertEquals(listOf(60_000, 60_000, 60_000, 1_234, 20_000, 20_000, 5_000), (t as RecordingTransport).deadlines)
    }
}
