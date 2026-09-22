package org.ghost.app.gate

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The pure half of the gate's order digest export (Phase 9 design §15.10 steps 2 and 3; S12 review:
 * the orchestrator's self-test runs against a fake phone whose digests are its own, so until this
 * test nothing checked what `OrderDigests` computes).
 *
 * The expected values are **not** computed with the code under test: they were produced with .NET's
 * `SHA256` (PowerShell) over the byte strings named in each case, so a change of framing, order or
 * sort is a failure here and not a new expected value.
 */
class OrderDigestsTest {

    private fun id(hex: String) = ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private val a = id("000102030405060708090a0b0c0d0e0f")

    /** Starts with 0x80: negative as a signed byte, so a signed sort would put it first. */
    private val b = id("80ffeeddccbbaa998877665544332211")

    @Test
    fun theOrderDigestIsSha256OverTheIdsInRenderedOrder() {
        val ab = OrderDigests.of(listOf(a, b))
        assertEquals("08833d1f0fe3dd795d28de015c42e94e4be8b2099d3c650797197f90fadd0fd5", ab.order)
        val ba = OrderDigests.of(listOf(b, a))
        assertEquals("cee314ed4fea27892a00b273836f7b67fd329ec05de3c3fe59e5ac7495a01e4e", ba.order)
        assertNotEquals("two orders, two order digests (CS-4)", ab.order, ba.order)
    }

    @Test
    fun theMultisetDigestSortsUnsignedAndIgnoresOrder() {
        val ab = OrderDigests.of(listOf(a, b))
        val ba = OrderDigests.of(listOf(b, a))
        assertEquals("sha256(a ‖ b): 0x00… sorts before 0x80…", "08833d1f0fe3dd795d28de015c42e94e4be8b2099d3c650797197f90fadd0fd5", ba.multiset)
        assertEquals(ab.multiset, ba.multiset)
        assertEquals(2, ba.count)
        assertEquals(0, ba.duplicates)
    }

    @Test
    fun aDuplicateIsCountedAndChangesTheMultiset() {
        val d = OrderDigests.of(listOf(a, b, a))
        assertEquals("sha256(a ‖ a ‖ b)", "196b98a689e5267dcb6730c46325877e66f3c8ff1402270ff2ae8e535d23b9a0", d.multiset)
        assertEquals(3, d.count)
        assertEquals(1, d.duplicates)
    }

    @Test
    fun anEmptyConversationHasTheEmptyDigests() {
        val empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val d = OrderDigests.of(emptyList())
        assertEquals(empty, d.order)
        assertEquals(empty, d.multiset)
        assertEquals(0, d.count)
    }

    @Test
    fun theSafetyDigestIsSha256OfTheDigitsAndHidesThem() {
        assertEquals(
            "530b9f04f4e9e33c4b2234d5d841b9adc76096c455301b98b930dd82106a2a9b",
            OrderDigests.safetyDigest("0123 4567 8901"),
        )
    }

    @Test
    fun theDigestsNeverShowContentInToString() {
        val text = OrderDigests.of(listOf(a, b)).toString()
        assertEquals("Digests(count=2, duplicates=0)", text)
    }
}
