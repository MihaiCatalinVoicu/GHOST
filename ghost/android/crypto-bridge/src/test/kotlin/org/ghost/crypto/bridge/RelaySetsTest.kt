package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * `order(ns, w)` and `set(ns, w)` (Phase 9 design §5.2, §21.1).
 *
 * The expected order is computed here with a **hand-written HMAC-SHA256** over `MessageDigest`,
 * not with `javax.crypto.Mac`, which is what [RelaySets] uses: the point of the check is that the
 * transcript is `label || u8(slot)` keyed by the namespace with **no week**, and a test that
 * called the same `Mac` with the same bytes would agree with any transcript.
 */
class RelaySetsTest {

    private val nsA = ByteArray(32) { (it * 3 + 1).toByte() }
    private val nsB = ByteArray(32) { (it * 7 + 2).toByte() }

    private fun op(id: Int) = ByteArray(16) { id.toByte() }

    /** 32 slots, one relay each, operators repeating every 4 slots (8 operators). */
    private fun table(count: Int = 32): List<RelaySets.Slot> =
        (0 until count).map { RelaySets.Slot(it, 100L + it, op(it % 8)) }

    // ---- an independent HMAC-SHA256, so the transcript is checked and not assumed ----

    private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val block = 64
        val digest = MessageDigest.getInstance("SHA-256")
        var k = if (key.size > block) digest.digest(key) else key
        if (k.size < block) k = k.copyOf(block)
        val inner = ByteArray(block) { (k[it].toInt() xor 0x36).toByte() }
        val outer = ByteArray(block) { (k[it].toInt() xor 0x5c).toByte() }
        digest.reset()
        digest.update(inner)
        val innerHash = digest.digest(message)
        digest.reset()
        digest.update(outer)
        return digest.digest(innerHash)
    }

    private fun expectedOrder(ns: ByteArray, slots: List<RelaySets.Slot>): List<Int> =
        slots.map { slot ->
            slot.slot to hmacSha256(
                ns,
                RelaySets.SLOT_ORDER_LABEL.toByteArray(Charsets.US_ASCII) + byteArrayOf(slot.slot.toByte()),
            )
        }.sortedWith(
            Comparator { l, r ->
                for (i in l.second.indices) {
                    val d = (l.second[i].toInt() and 0xff) - (r.second[i].toInt() and 0xff)
                    if (d != 0) return@Comparator d
                }
                l.first.compareTo(r.first)
            },
        ).map { it.first }

    @Test
    fun theOrderIsTheHmacOrderOfTheDesignsTranscript() {
        val slots = table()
        assertEquals(
            expectedOrder(nsA, slots),
            RelaySets.order(nsA, slots).map { it.slot },
        )
        assertEquals(
            expectedOrder(nsB, slots),
            RelaySets.order(nsB, slots).map { it.slot },
        )
        // The two namespaces really do get different orders, so the previous assertion is not
        // trivially true for every input.
        assertNotEquals(
            RelaySets.order(nsA, slots).map { it.slot },
            RelaySets.order(nsB, slots).map { it.slot },
        )
    }

    @Test
    fun theOrderIsAPermutationAndDoesNotDependOnTheInputOrder() {
        val slots = table()
        val ordered = RelaySets.order(nsA, slots).map { it.slot }
        assertEquals(slots.map { it.slot }.toSet(), ordered.toSet())
        assertEquals(slots.size, ordered.size)
        assertEquals(ordered, RelaySets.order(nsA, slots.reversed()).map { it.slot })
        assertEquals(ordered, RelaySets.order(nsA, slots.shuffled(java.util.Random(7))).map { it.slot })
    }

    /**
     * §21.1, mutant MC-22: the week is **not** in the HMAC. A set that moved every week would cost
     * a union of six weeks of read pairs on the owner's side and would lose mail for a recipient
     * offline across the roll. The only way the week enters [RelaySets] is by selecting the slot
     * table, so the same table gives the same set whichever week asked for it — which this asserts
     * by the absence of a week parameter and by the identity below.
     */
    @Test
    fun theSameSlotTableGivesTheSameSetInEveryWeek() {
        val week12 = table()
        val week13 = table() // the same ES slots, a different week
        assertEquals(
            RelaySets.forNamespace(nsA, week12).map { it.slot },
            RelaySets.forNamespace(nsA, week13).map { it.slot },
        )
    }

    @Test
    fun theSetIsThreeRelaysOfAtLeastTwoOperators() {
        for (ns in listOf(nsA, nsB)) {
            val set = RelaySets.forNamespace(ns, table())
            assertEquals(3, set.size)
            assertTrue(set.map { it.operatorKey }.toSet().size >= 2)
            assertEquals(3, set.map { it.relay }.toSet().size)
            // It is the prefix of the order, not an arbitrary choice of three.
            assertEquals(RelaySets.order(ns, table()).take(3).map { it.slot }, set.map { it.slot })
        }
    }

    /**
     * The stopping rule of §5.2 is a conjunction. With the first three slots of the order all on
     * one operator the walk continues, and it continues **only** for a new operator: the set is
     * four relays, not the whole table.
     */
    @Test
    fun aRunOfOneOperatorGrowsTheSetByExactlyOneRelay() {
        val ordered = RelaySets.order(nsA, table()).map { it.slot }
        val single = op(1)
        val other = op(2)
        val slots = table().map { slot ->
            val rank = ordered.indexOf(slot.slot)
            // The first four of the order belong to one operator; everything after to another.
            RelaySets.Slot(slot.slot, slot.relay, if (rank < 4) single else other)
        }
        val set = RelaySets.forNamespace(nsA, slots)
        assertEquals(4, set.size)
        assertEquals(ordered.take(3) + ordered[4], set.map { it.slot })
        assertEquals(2, set.map { it.operatorKey }.toSet().size)
    }

    /** One relay serving several slots of a week counts once: the set is a set of relays. */
    @Test
    fun aRelayServingSeveralSlotsIsTakenOnce() {
        val slots = (0 until 8).map { RelaySets.Slot(it, 500L + (it % 2), op(it % 2)) }
        val set = RelaySets.forNamespace(nsA, slots)
        assertEquals(2, set.size)
        assertEquals(2, set.map { it.relay }.toSet().size)
        assertEquals(2, set.map { it.operatorKey }.toSet().size)
    }

    /**
     * A week whose table cannot satisfy ADR-11 gives what it has, loudly to the caller by its size
     * rather than by an exception here: §5.2 puts the refusal at `Outbox.enqueue`
     * (`InsufficientReplicasException`), so a namespace can still be registered and repaired.
     *
     * A table of a single operator stops at three relays and does **not** walk the rest of the
     * week's slots looking for a second operator that cannot exist: the extra-relay rule exists to
     * buy an operator, and where none is on offer it buys nothing.
     */
    @Test
    fun aTooSmallOrSingleOperatorTableGivesWhatItHas() {
        val oneOperator = (0 until 5).map { RelaySets.Slot(it, 900L + it, op(3)) }
        val set = RelaySets.forNamespace(nsA, oneOperator)
        assertEquals(3, set.size)
        assertEquals(1, set.map { it.operatorKey }.toSet().size)

        val two = listOf(RelaySets.Slot(0, 1, op(1)), RelaySets.Slot(1, 2, op(2)))
        assertEquals(2, RelaySets.forNamespace(nsA, two).size)
        assertEquals(0, RelaySets.forNamespace(nsA, emptyList()).size)
    }

    @Test
    fun aDuplicatedSlotNumberOrAWrongLengthNamespaceIsRefused() {
        val duplicated = listOf(RelaySets.Slot(3, 1, op(1)), RelaySets.Slot(3, 2, op(2)))
        assertThrows(IllegalArgumentException::class.java) { RelaySets.order(nsA, duplicated) }
        assertThrows(IllegalArgumentException::class.java) { RelaySets.order(ByteArray(31), table()) }
        assertThrows(IllegalArgumentException::class.java) { RelaySets.Slot(256, 1, op(1)) }
        assertThrows(IllegalArgumentException::class.java) { RelaySets.Slot(0, 1, ByteArray(0)) }
    }

    /**
     * T26 in the small: the order is keyed by the **namespace**, which is an HKDF output of the
     * card secret, so nothing public decides it. Two namespaces of the same owner therefore get
     * unrelated sets, which is what stops a relay from joining `X_0` and `P_0` by their sets alone.
     */
    @Test
    fun twoNamespacesOfOneOwnerGetUnrelatedSets() {
        val inbox = RelaySets.forNamespace(nsA, table()).map { it.slot }
        val bundle = RelaySets.forNamespace(nsB, table()).map { it.slot }
        assertNotEquals(inbox, bundle)
    }
}
