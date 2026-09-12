package org.ghost.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DerivationLabelsTest {
    @Test
    fun labelsAreDistinctAndVersioned() {
        assertEquals(DerivationLabels.ALL.size, DerivationLabels.ALL.toSet().size)
        assertTrue(DerivationLabels.ALL.all { it.startsWith("ghost/v${DerivationLabels.DERIVATION_VERSION}/") })
    }

    @Test
    fun noLabelIsAPrefixOfAnother() {
        // Prevents ambiguous `info` values when a label is concatenated with a channel id (ADR-04).
        for (a in DerivationLabels.ALL) for (b in DerivationLabels.ALL) {
            if (a != b) assertTrue("$b must not start with $a", !b.startsWith(a))
        }
    }

    @Test
    fun phase8LabelsAreDefinedAndRetiredOnesStayReserved() {
        assertEquals("ghost/v1/invite-drop-namespace", DerivationLabels.INVITE_DROP_NAMESPACE)
        assertEquals("ghost/v1/invite-drop-key", DerivationLabels.INVITE_DROP_KEY)
        assertTrue(DerivationLabels.ALL.containsAll(listOf(DerivationLabels.INVITE_DROP_NAMESPACE, DerivationLabels.INVITE_DROP_KEY)))
        // Compatibility contract (design §8.4): retired labels are never removed, so never reused.
        assertTrue(DerivationLabels.ALL.containsAll(listOf(DerivationLabels.REFERRAL_SECRET, DerivationLabels.INVITE_SIGNING)))
        assertEquals(9, DerivationLabels.ALL.size)
    }

    @Test
    fun perInviteInfoEncodingIsInjective() {
        // info = label || u16_be(index): the suffix has a fixed length and no label is a prefix of
        // another, so no (label, index) pair collides with another pair or with a bare label.
        val indexed = listOf(DerivationLabels.INVITE_SIGNING, DerivationLabels.INVITE_DROP_NAMESPACE, DerivationLabels.INVITE_DROP_KEY)
        val infos = ArrayList<List<Byte>>()
        for (label in indexed) for (i in listOf(0, 1, 255, 256, 0x2d6b, 65535)) {
            infos += (label.toByteArray() + byteArrayOf((i ushr 8).toByte(), i.toByte())).toList()
        }
        infos += DerivationLabels.ALL.map { it.toByteArray().toList() }
        assertEquals(infos.size, infos.toSet().size)
    }
}
