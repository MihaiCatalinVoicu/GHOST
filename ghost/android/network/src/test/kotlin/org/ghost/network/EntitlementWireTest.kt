package org.ghost.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Decoders of the `EntitlementCrypto` native layouts (client-core/net/src/entitlement.rs) and the
 * argument checks made before a native call. Pure JVM: nothing here loads the native library.
 */
class EntitlementWireTest {
    private fun u64(v: Long) = ByteArray(8) { i -> (v ushr (8 * (7 - i))).toByte() }

    private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private val onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443"

    private fun malformed(block: () -> Unit) {
        val e = assertThrows(NetworkException::class.java) { block() }
        assertEquals("malformed_response", e.category)
    }

    /** A summary in the layout of `schedule_summary`: 1 slot, 1 price, 2 keys, 1 revocation. */
    private fun summary(
        seq: Long = 1,
        network: Int = 2,
        slot: Int = 3,
        until: Long = 0,
        onionText: String = onion,
        keyKind: Int = 1,
        revokedKind: Int = 3,
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val o = onionText.toByteArray(Charsets.US_ASCII)
        return ByteArray(32) { 7 } + u64(seq) + byteArrayOf(network.toByte()) + u64(2957) + u64(2989) +
            byteArrayOf(10) + u16(720) + u16(2160) + byteArrayOf(16, 8, 2, 10, 10, 50, 24) + u64(268_435_456) +
            byteArrayOf(1, slot.toByte()) + u64(2957) + u64(until) + byteArrayOf(o.size.toByte()) + o +
            u16(1) + u64(227) + u64(200_000_000_000) +
            u16(2) + byteArrayOf(keyKind.toByte()) + u64(2957) + ByteArray(32) { 1 } + byteArrayOf(2) + u64(739) + ByteArray(32) { 2 } +
            u16(1) + byteArrayOf(revokedKind.toByte()) + u64(228) + trailing
    }

    @Test
    fun summaryDecoding() {
        val s = EntitlementCrypto.decodeSummary(summary())
        assertArrayEquals(ByteArray(32) { 7 }, s.digest())
        assertEquals(1L, s.seq)
        assertEquals(2, s.network)
        assertEquals(2957L, s.firstWeek)
        assertEquals(2989L, s.lastWeek)
        assertEquals(EntitlementCrypto.Constants(10, 720, 2160, 16, 8, 2, 10, 10, 50, 24, 268_435_456L), s.constants)
        assertEquals(listOf(EntitlementCrypto.Slot(3, 2957, 0, OnionAddress.parse(onion))), s.slots)
        assertEquals(listOf(3), s.slotsInWeek(3000))
        assertEquals(emptyList<Int>(), s.slotsInWeek(2956))
        assertEquals(listOf(EntitlementCrypto.Price(227, 200_000_000_000)), s.prices)
        assertEquals(
            listOf(
                EntitlementCrypto.KeyId(1, 2957, ByteArray(32) { 1 }),
                EntitlementCrypto.KeyId(2, 739, ByteArray(32) { 2 }),
            ),
            s.keys,
        )
        assertEquals(listOf(EntitlementCrypto.Revoked(3, 228)), s.revoked)
        // A slot with an end week.
        val ending = EntitlementCrypto.decodeSummary(summary(until = 2967))
        assertEquals(listOf(3), ending.slotsInWeek(2966))
        assertEquals(emptyList<Int>(), ending.slotsInWeek(2967))

        val good = summary()
        val bad = listOf(
            good.copyOf(good.size - 1), // truncated
            summary(trailing = byteArrayOf(0)),
            summary(seq = 0),
            summary(seq = -1), // above Long.MAX_VALUE
            summary(network = 0),
            summary(network = 4),
            summary(slot = 32),
            summary(until = 2957), // ends before it starts
            summary(onionText = "example.com:443"),
            summary(onionText = "DUCKduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczae.onion:443"),
            summary(keyKind = 0),
            summary(keyKind = 4),
            summary(revokedKind = 9),
            ByteArray(0),
        )
        for (b in bad) malformed { EntitlementCrypto.decodeSummary(b) }
    }

    @Test
    fun layoutDecoding() {
        val l = EntitlementCrypto.decodeLayout(ByteArray(32) { 5 } + byteArrayOf(0, 0, 0, 243.toByte()))
        assertEquals(243, l.positions)
        assertArrayEquals(ByteArray(32) { 5 }, l.digest())
        assertEquals(2563, EntitlementCrypto.decodeLayout(ByteArray(32) + byteArrayOf(0, 0, 0x0A, 0x03)).positions)
        for (b in listOf(ByteArray(35), ByteArray(37), ByteArray(32) + byteArrayOf(0, 0, 0, 0), ByteArray(32) + byteArrayOf(0x80.toByte(), 0, 0, 1))) {
            malformed { EntitlementCrypto.decodeLayout(b) }
        }
    }

    @Test
    fun verifiedTokenDecoding() {
        val n = ByteArray(32) { (it + 100).toByte() }
        val access = EntitlementCrypto.decodeVerified(byteArrayOf(1) + u64(2959) + byteArrayOf(1) + n, EntitlementCrypto.KIND_ACCESS)
        assertEquals(1, access.kind)
        assertEquals(2959L, access.epoch)
        assertEquals(1, access.slot)
        assertArrayEquals(n, access.nullifier())
        val invite = EntitlementCrypto.decodeVerified(byteArrayOf(2) + u64(739) + byteArrayOf(0xFF.toByte()) + n, EntitlementCrypto.KIND_INVITE)
        assertNull(invite.slot)
        assertFalse(invite.toString().contains(hex(n)))
        val bad = listOf(
            (byteArrayOf(1) + u64(2959) + byteArrayOf(1) + n) to EntitlementCrypto.KIND_INVITE, // another kind
            (byteArrayOf(1) + u64(2959) + byteArrayOf(0xFF.toByte()) + n) to EntitlementCrypto.KIND_ACCESS, // access without slot
            (byteArrayOf(1) + u64(2959) + byteArrayOf(32) + n) to EntitlementCrypto.KIND_ACCESS, // slot 32
            (byteArrayOf(3) + u64(227) + byteArrayOf(0) + n) to EntitlementCrypto.KIND_CREDIT, // credit with a slot
            (byteArrayOf(2) + u64(-1) + byteArrayOf(0xFF.toByte()) + n) to EntitlementCrypto.KIND_INVITE, // negative epoch
            (byteArrayOf(2) + u64(739) + byteArrayOf(0xFF.toByte()) + n.copyOf(31)) to EntitlementCrypto.KIND_INVITE,
            (byteArrayOf(2) + u64(739) + byteArrayOf(0xFF.toByte()) + n + byteArrayOf(0)) to EntitlementCrypto.KIND_INVITE,
        )
        for ((raw, kind) in bad) malformed { EntitlementCrypto.decodeVerified(raw, kind) }
    }

    @Test
    fun addressCodes() {
        assertEquals(EntitlementCrypto.AddressInfo(2, EntitlementCrypto.ADDRESS_SUBADDRESS), EntitlementCrypto.decodeAddress(0x0202))
        assertEquals(EntitlementCrypto.AddressInfo(3, EntitlementCrypto.ADDRESS_STANDARD), EntitlementCrypto.decodeAddress(0x0301))
        for (code in listOf(0, 0x0003, 0x0200, 0x0400, 0x0103, -1)) malformed { EntitlementCrypto.decodeAddress(code) }
    }

    @Test
    fun argumentsAreCheckedBeforeTheNativeCall() {
        val iae = IllegalArgumentException::class.java
        assertThrows(iae) { EntitlementCrypto.layout(0, 2957) }
        assertThrows(iae) { EntitlementCrypto.layout(5, 2957) }
        assertThrows(iae) { EntitlementCrypto.layout(EntitlementCrypto.PRODUCT_PACK_XMR, -1) }
        assertThrows(iae) { EntitlementCrypto.verifyToken(ByteArray(354), 0) }
        assertThrows(iae) { EntitlementCrypto.verifyToken(ByteArray(354), 4) }
        assertThrows(iae) { EntitlementCrypto.validateAddress("4", 3) }
        assertThrows(iae) { EntitlementCrypto.paymentUri("8", 0) }
        assertThrows(iae) { EntitlementCrypto.paymentUri("8", -5) }
    }
}
