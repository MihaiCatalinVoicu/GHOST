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
}
