package org.ghost.crypto.bridge

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The relay set of a DM namespace (Phase 9 design §5.2, as corrected by §21.1).
 *
 * ```
 * order(ns, w) = the ES slots of week w sorted by HMAC-SHA256(key = ns, "ghost/v1/dm/slot-order" || u8(slot))
 * set(ns, w)   = the relays of the first slots in order(ns, w) until 3 are taken
 *                and they span >= 2 distinct operators
 * ```
 *
 * **Why a public function and not a list in the card.** Anyone who knows the namespace and the
 * signed ES computes the same set, so a sender needs no relay list from the card, and the set
 * carries nothing about its owner. A client that chose its own 3 of 32 slots would be a
 * `C(32, 3) = 4 960`-way fingerprint across its namespaces (RP F11, judge error E-15).
 *
 * **Why the week is not in the HMAC (§21.1, mutant MC-22).** The order is a permutation of the
 * *slots*, not of the weeks: `set(ns, w)` changes only when the ES slot table changes, so the
 * owner's readers do not have to union a fresh set every week. The week is still a parameter of
 * this call because it selects **which slot table** is valid, and that is all it does.
 *
 * **Recorded deviation (S6).** §13.1 lists `RelaySets.forNamespace` in `:crypto-bridge`, and
 * `:crypto-bridge` has no production dependency (§22.9 item 3). The signature therefore takes
 * [Slot] values carrying a caller-side relay handle as a `Long` and an operator id as bytes,
 * instead of `:sync`'s `RelayId`; `:messaging` maps them. Everything the rule needs — the slot
 * number, the serving relay and its operator — is in those three fields.
 */
object RelaySets {

    /** The HMAC's domain-separation label (§5.2). */
    const val SLOT_ORDER_LABEL: String = "ghost/v1/dm/slot-order"

    /** How many relays a DM namespace's set holds when the ES offers enough of them. */
    const val TARGET_RELAYS: Int = 3

    /** The least number of distinct operators a set must span (ADR-11). */
    const val MIN_OPERATORS: Int = 2

    /**
     * One ES slot of a week, as the caller sees it: the slot number the credentials are bound to
     * (§4.3), the relay that serves it, and that relay's operator.
     *
     * A slot the directory has no active relay for is simply not passed in; it then takes no place
     * in the set, which is the "a relay that left the ES gets no new capability" case of §5.2.
     */
    class Slot(
        /** The ES slot number, `0..255`: the value the credential and the verifier carry. */
        val slot: Int,
        /** The caller's handle for the relay serving this slot (`:sync`'s `RelayId.value`). */
        val relay: Long,
        operatorId: ByteArray,
    ) {
        private val operator: ByteArray = operatorId.copyOf()

        init {
            require(slot in 0..255) { "slot is not a byte" }
            require(operatorId.isNotEmpty()) { "operator id is empty" }
        }

        /** The operator that runs the relay; two slots of one operator count once towards [MIN_OPERATORS]. */
        val operatorKey: List<Byte> get() = operator.toList()

        /** Never shows the operator id (T3). */
        override fun toString(): String = "Slot(redacted)"
    }

    /**
     * `order(ns, w)`: [slots] sorted by their HMAC under the namespace, ascending, comparing the
     * 32 HMAC bytes as **unsigned** values.
     *
     * Two distinct slots collide only on a full SHA-256 collision, but the order still has to be a
     * total one on every input a caller can build, so equal tags fall back to the slot number:
     * without a tiebreak, two devices could compute different sets from the same ES and lose each
     * other's mail. A slot number repeated in [slots] is refused rather than ordered, because the
     * ES gives one relay per slot per week and a duplicate means the caller built the table wrong.
     */
    fun order(namespace: ByteArray, slots: List<Slot>): List<Slot> {
        require(namespace.size == 32) { "namespace has the wrong length" }
        require(slots.map { it.slot }.distinct().size == slots.size) { "a slot number appears twice" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(namespace, "HmacSHA256"))
        val label = SLOT_ORDER_LABEL.toByteArray(Charsets.US_ASCII)
        val tagged = slots.map { slot ->
            mac.reset()
            mac.update(label)
            mac.update(slot.slot.toByte())
            slot to mac.doFinal()
        }
        return tagged.sortedWith(
            Comparator { left, right ->
                val byTag = compareUnsigned(left.second, right.second)
                if (byTag != 0) byTag else left.first.slot.compareTo(right.first.slot)
            },
        ).map { it.first }
    }

    /**
     * `set(ns, w)`: the relays of the first slots of [order], taken until there are
     * [TARGET_RELAYS] of them **and** they span [MIN_OPERATORS] distinct operators.
     *
     * The stopping rule of §5.2 is a conjunction, and it is read as one here: with three relays of
     * a single operator the walk continues to the next slot whose operator is a new one, so the set
     * may hold four relays. The alternative — stopping at three and reporting a set that cannot
     * satisfy ADR-11 — would turn a recoverable ES shape into `InsufficientReplicasException` at
     * every enqueue.
     *
     * One relay serving several slots of the week counts once: the set is a set of relays.
     *
     * Returns fewer relays, or too few operators, when the week's slot table cannot do better; the
     * caller registers what it got and `Outbox.enqueue` raises `InsufficientReplicasException`
     * where ADR-11 requires it (§5.2), which is the rare-by-ES-design case and never silent here.
     */
    fun forNamespace(namespace: ByteArray, slots: List<Slot>): List<Slot> {
        val chosen = ArrayList<Slot>(TARGET_RELAYS + 1)
        val relays = HashSet<Long>()
        val operators = HashSet<List<Byte>>()
        for (slot in order(namespace, slots)) {
            if (chosen.size >= TARGET_RELAYS && operators.size >= MIN_OPERATORS) break
            if (slot.relay in relays) continue
            // Past the third relay only a **new operator** is worth taking: the walk continues for
            // the operator span alone, so a week whose slots are all one operator adds one relay,
            // not the whole table.
            if (chosen.size >= TARGET_RELAYS && slot.operatorKey in operators) continue
            relays += slot.relay
            chosen += slot
            operators += slot.operatorKey
        }
        return chosen
    }

    /** Lexicographic comparison of two equal-length digests, byte by byte, as unsigned values. */
    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        for (i in left.indices) {
            val diff = (left[i].toInt() and 0xff) - (right[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return 0
    }
}
