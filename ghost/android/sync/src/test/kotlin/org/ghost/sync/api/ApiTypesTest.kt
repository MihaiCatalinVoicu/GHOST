package org.ghost.sync.api

import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.StoreReceipt
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/** Public types: validation, content equality and redacted toString (T3). */
class ApiTypesTest {
    private val canaryOp = ByteArray(16) { 0x5a }
    private val canaryNs = ByteArray(32) { 0x6b }
    private val canaryHash = ByteArray(32) { 0x7c }
    private val canaryCiphertext = ByteArray(1024) { 0x3d }
    private val onion = TestBytes.onion(3)

    private fun assertRedacted(value: Any) {
        val text = value.toString()
        for (canary in listOf(canaryOp, canaryNs, canaryHash, canaryCiphertext)) {
            val hex = canary.joinToString("") { "%02x".format(it) }
            assertFalse(text, text.contains(hex.substring(0, 16), ignoreCase = true))
            assertFalse(text, text.contains(Base64.getEncoder().encodeToString(canary).substring(0, 12)))
        }
        assertFalse(text, text.contains(onion.host.substring(0, 16)))
        assertFalse(text, text.contains("[B@"))
    }

    @Test
    fun identifiersValidateCopyAndCompareByContent() {
        assertThrows(IllegalArgumentException::class.java) { OperationId(ByteArray(15)) }
        assertThrows(IllegalArgumentException::class.java) { NamespaceId(ByteArray(16)) }
        assertThrows(IllegalArgumentException::class.java) { BlobHash(ByteArray(33)) }
        val source = canaryOp.copyOf()
        val op = OperationId(source)
        source[0] = 0
        assertArrayEquals(canaryOp, op.toByteArray())
        op.toByteArray()[1] = 0
        assertArrayEquals(canaryOp, op.toByteArray())
        assertEquals(OperationId(canaryOp), op)
        assertEquals(OperationId(canaryOp).hashCode(), op.hashCode())
        assertFalse(NamespaceId(canaryNs).equals(BlobHash(canaryNs)))
        assertEquals("OperationId(redacted)", op.toString())
        assertEquals("NamespaceId(redacted)", NamespaceId(canaryNs).toString())
        assertEquals("BlobHash(redacted)", BlobHash(canaryHash).toString())
        assertEquals("RelayId(redacted)", RelayId(42).toString())
    }

    @Test
    fun everyPublicValueTypeIsRedacted() {
        val op = OperationId(canaryOp)
        val ns = NamespaceId(canaryNs)
        val hash = BlobHash(canaryHash)
        val values = listOf<Any>(
            op, ns, hash, RelayId(7),
            OutboundBlob(op, ns, canaryCiphertext, TtlBucket.DAYS_7),
            OutboundOutcome(op, ns, Outcome.INDETERMINATE, 123L),
            OutboxProgress(1, 0, 2, null),
            InboundBlob(ns, hash, canaryCiphertext),
            CapabilityNeed(RelayId(1), ns, CapabilityKind.READ, CapabilityNeed.Reason.MISSING),
            RelayEntry(onion, ByteArray(16) { 0x5a }, RelayEntry.Source.CONFIG),
            SyncStatus(TransportStatus.READY, PrivacyMode.STANDARD, setOf(StatusFlag.BUG), SyncCounts.EMPTY),
            StoreReceipt(hash, 1L),
            FetchedBlob(canaryCiphertext, 1L),
            ListPage(listOf(hash), ByteArray(8) { 0x6b }),
            PairKey(RelayId(1), ns),
            EnqueueResult.Enqueued,
            InsufficientReplicasException(),
        )
        values.forEach(::assertRedacted)
    }

    @Test
    fun payloadsAreCopiedAndBucketSized() {
        val op = OperationId(canaryOp)
        val ns = NamespaceId(canaryNs)
        for (size in listOf(0, 1, 1023, 1025, 2048, 65537)) {
            assertThrows(IllegalArgumentException::class.java) { OutboundBlob(op, ns, ByteArray(size), TtlBucket.DAY_1) }
        }
        for (size in Buckets.SIZES) OutboundBlob(op, ns, ByteArray(size), TtlBucket.DAY_1)
        val bytes = canaryCiphertext.copyOf()
        val blob = OutboundBlob(op, ns, bytes, TtlBucket.DAY_1)
        bytes[0] = 0
        assertArrayEquals(canaryCiphertext, blob.ciphertext)
        blob.ciphertext[0] = 0
        assertArrayEquals(canaryCiphertext, blob.ciphertext)
        assertThrows(IllegalArgumentException::class.java) { RelayEntry(TestBytes.onion(1), ByteArray(15), RelayEntry.Source.CONFIG) }
    }

    @Test
    fun enumCodesMatchTheSchema() {
        assertEquals(listOf("dm", "prekeys", "channel", "media", "identity"), Consumer.entries.map { it.code })
        assertEquals(listOf(86_400, 604_800, 2_592_000, 7_776_000), TtlBucket.entries.map { it.seconds })
        assertEquals(TtlBucket.DAYS_30, TtlBucket.ofSeconds(2_592_000))
        assertTrue(Outcome.ofCode("pending") == null)
        assertEquals(listOf("default", "on", "off"), SendDelay.entries.map { it.code })
    }
}
