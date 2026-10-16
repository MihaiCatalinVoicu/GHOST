package org.ghost.messaging.channel.engine

/**
 * **Peek ordering and the gap hold** of channel posts (Phase 10 design §6.3.3, §19.18; the F9 §7.7 idea for MLS).
 *
 * Within an epoch OpenMLS decrypts a sender's application messages out of order within the sender ratchet's tolerance
 * (16), and blobs arrive in blob-hash order (Phase 7). The receive step therefore decrypts the openable application
 * messages of an epoch sorted by `(epoch, sender_leaf, seq)` — the `ChannelOrder` its author put in the MLS AAD, which
 * the seal's `order` must repeat (`open` refuses a mismatch, CS-S7) — in batches of up to 32 (S0-17), and holds a
 * **gap** (a missing `seq` of a sender) for at most 12 minutes before decrypting past it.
 *
 * **The expected `seq` is in memory** (a deviation from F9's stored chain position, recorded in §19.37): OpenMLS does not
 * expose a sender ratchet's generation (`ProcessedMessage` carries none, §19.18 (a)) and §9 has no per-sender column, so
 * the next `seq` of a `(channel, epoch, leaf)` is what this object learnt from the posts it saw decrypt. Unknown — a new
 * sender in the epoch, or the first pass of a process — means no hold: the batch starts at the lowest `seq` present, which
 * costs nothing within the ratchet's tolerance and never a 12-minute wait after a restart. `first_seen` is in memory too
 * (T33), as in F9; a restart costs at most a fresh hold.
 *
 * **Pressure: when the receiver cannot see everything it holds** (§19.38, the review of S4). The 12-minute hold is for a
 * post that is *late*; it assumes the receiver sees every blob it has fetched. It does not when the peek returned a full
 * window (the next blob of a sender may sit beyond it, in arrival order, which Phase 7's `(retain_until_day, blob_hash)`
 * fetch order makes unrelated to `seq`), or when a namespace holds as many due rows as Phase 7's `FETCHED_CAP` (its
 * remaining blobs are listed and **not fetched** until rows are consumed — and a held row is not consumed). Decrypting
 * past such a gap after 12 minutes put the sender's still-unseen posts more than 16 generations behind: lost (measured:
 * 18 of 160, 68 of 200, 110 of 250 posts of one backlog). So an entry is **under pressure** when its namespace is (the
 * caller decides it per pass), and a gap under pressure is not held in place: the sender's entries beyond it are
 * **deferred** ([Plan.deferrals], `Inbox.defer` for [GAP_DEFER_SECONDS]) — a deferred row leaves the window and does not
 * count against `FETCHED_CAP` (Phase 10 §7.5 item 5), so the window advances and the fetch resumes — and **remembered
 * with their order**: once the sender decrypts the `seq` they wait for, they are re-offered ([reofferDue]) and offered
 * back to the plan by their key ([Entry.value] null), so the caller claims them directly, wherever the window is — a
 * re-offer makes the namespace's deferred rows due again, and the window would show the earliest of them first, not
 * these. A sender with deferred entries outstanding stays under pressure until they are back. Under pressure a sender
 * whose next `seq` is unknown waits for its `seq` 0 (every epoch starts its senders there; the lowest one in view need not
 * be the lowest one fetched), and a gap is decrypted past only after [PRESSURE_HOLD_SECONDS] (a post that never comes: a
 * failed send, F-S4-9; a sender's earlier posts consumed by a process that has since restarted), measured from the
 * earliest `first_seen` of what the gap holds back, which a deferral keeps.
 *
 * **The peek cursor (slice S13a, §19.54 row 3 — Q-F4-13's relief valve).** A pass that drained its full window under
 * pressure leaves, in the receive step, a per-namespace cursor (in memory, cleared with the context). A deferred row
 * may come back into the due set before its gap fills — its deferral ended, or a decrypt of the `seq` it waits for
 * re-offered its namespace ([reofferDue]). The next pass leaves a row the cursor covers, that this object still
 * remembers as a gap deferral within its grace ([isDeferredInGrace]), out of its window — but not out of the plan:
 * [plan]'s [skipped] argument hands it over as a **by-key entry**, so the caller takes it (claimed by key, wherever
 * the window is) or defers it again. Neither path re-opens it in the window — that is the relief. A row this object
 * does *not* remember (a deferral past its grace, a row a pass left unopened) is re-examined from the start, which
 * resets the cursor — after a restart or a lock the map is empty and everything is re-derived from the beginning,
 * matching the behavior before the cursor existed.
 */
internal class ChannelPeekOrder {

    /** One openable application message of an epoch, with its order key. */
    class Entry<T>(
        val channelId: ByteArray,
        val epoch: Long,
        val leaf: Long,
        val seq: Long,
        /** `(namespace ‖ hash)`: the blob's identity across passes. */
        val key: List<Byte>,
        /** The blob's namespace. */
        val namespace: List<Byte>,
        /** What the caller opened from the peek; null for a deferred row the plan offers back by its [key] alone. */
        val value: T?,
        /** The namespace is under pressure this pass (see the class note). */
        val pressure: Boolean = false,
    ) {
        override fun toString(): String = "Entry(epoch=$epoch, leaf=$leaf, seq=$seq)"
    }

    /** What to do with a pass's entries: the batches to decrypt, in order, and the entries to defer behind a gap. */
    class Plan<T>(
        val batches: List<List<Entry<T>>>,
        /** Each entry with the `seq` its sender waits for (the gap's first missing one). */
        val deferrals: List<Pair<Entry<T>, Long>>,
    )

    /** `(channel ‖ epoch ‖ leaf)` → the next `seq` a decrypted post of that sender makes expected. */
    private val nextSeq = HashMap<List<Byte>, Long>()

    /** `(namespace ‖ hash)` → the second this object first saw the blob. */
    private val firstSeen = HashMap<List<Byte>, Long>()

    /** A row deferred behind a gap (see the class note): its order, what it waits for, and until when. */
    private class Deferred(
        val channelId: ByteArray,
        val epoch: Long,
        val leaf: Long,
        val seq: Long,
        val sender: List<Byte>,
        val namespace: List<Byte>,
        val waitingFor: Long,
        val until: Long,
    ) {
        /** Its sender decrypted past [waitingFor] and the namespace was re-offered: the row is due, and claimed by key. */
        var reoffered = false
    }

    /** `(namespace ‖ hash)` → the deferral of a row that is not back in the inbox's due set yet, or not consumed. */
    private val gapDeferred = HashMap<List<Byte>, Deferred>()

    /** The second the earliest gap hold or deferral of the last [plan] ends, or null when it held nothing. */
    private var holdEnds: Long? = null

    /**
     * The batches to decrypt, in order — per channel and epoch ascending, each sorted by `(leaf, seq)` and cut at 32 — with
     * the held entries left out and the deferred ones named. [present] is the **window's** keys — the peeked blobs the
     * caller classified; a blob the caller's peek cursor left out (S13a's [skipped]) is deliberately NOT in it, so
     * `gapDeferred.keys.removeAll(present)` below cannot drop a skipped row: it stays remembered and re-enters through
     * the by-key entries. A blob that left the inbox stops being remembered (a deferred one is remembered until it is
     * back, consumed, or long overdue). The rows a re-offer or the cursor brought back that the window does not show
     * are entries too, with a null value.
     */
    fun <T> plan(entries: List<Entry<T>>, present: Set<List<Byte>>, now: Long, skipped: Set<List<Byte>> = emptySet()): Plan<T> {
        // A deferred row back in view is an ordinary entry again; a deferral long overdue lost its row (consumed
        // elsewhere, its namespace removed) and is forgotten.
        gapDeferred.keys.removeAll(present)
        gapDeferred.values.removeIf { now > it.until + DEFERRAL_GRACE_SECONDS }
        firstSeen.keys.retainAll { it in present || it in gapDeferred }
        // A clock stepped back restarts a hold from the new time (F9's ENG-8): `first_seen` is a wall time.
        firstSeen.replaceAll { _, since -> minOf(since, now) }
        for (e in entries) firstSeen.putIfAbsent(e.key, now)
        // A deferral wakes the actor when it falls due (the rows come back then, if nothing re-offered them earlier).
        holdEnds = gapDeferred.values.filter { !it.reoffered }.minOfOrNull { it.until }
        val sticky = gapDeferred.values.mapTo(HashSet()) { it.sender }
        // Rows the caller left out of the window ([skipped]: deferrals its peek cursor covers) join the reoffered
        // ones as by-key entries — the plan takes them (claimed by key wherever the window is) or defers them again;
        // neither path re-opens them in the window (S13a, §19.54 row 3).
        val remote = gapDeferred.entries.filter { it.value.reoffered || it.key in skipped }.map { (key, d) ->
            Entry<T>(d.channelId, d.epoch, d.leaf, d.seq, key, d.namespace, null, pressure = true)
        }
        val byEpoch = LinkedHashMap<List<Byte>, MutableList<Entry<T>>>()
        for (e in (entries + remote).sortedWith(compareBy<Entry<T>>({ it.channelId.toHex() }, { it.epoch }))) {
            byEpoch.getOrPut(e.channelId.toList() + ChannelAd.u64(e.epoch).toList()) { ArrayList() } += e
        }
        val out = ArrayList<List<Entry<T>>>()
        val deferrals = ArrayList<Pair<Entry<T>, Long>>()
        for (group in byEpoch.values) {
            val taken = ArrayList<Entry<T>>()
            for (sender in group.groupBy { it.leaf }.toSortedMap().values) {
                val sorted = sender.sortedBy { it.seq }
                val who = senderKey(sorted.first())
                val pressured = who in sticky || sorted.any { it.pressure }
                // Unknown under pressure is not "the lowest present": the sender's `seq` starts at 0 in each epoch, and
                // its lower posts may be the ones this pass cannot see. (Without pressure every fetched blob is in view.)
                var expected = nextSeq[who] ?: if (pressured) 0L else sorted.first().seq
                for ((index, e) in sorted.withIndex()) {
                    if (e.seq < expected) {
                        // A repeat or a post past its turn: decrypting it is harmless (MLS refuses a replay, layer 2).
                        taken += e
                        continue
                    }
                    if (e.seq > expected) {
                        val rest = sorted.subList(index, sorted.size)
                        if (pressured) {
                            // How long the gap has been waited for: the earliest sighting of what it holds back.
                            val since = rest.minOf { firstSeen[it.key] ?: now }
                            if (now - since < PRESSURE_HOLD_SECONDS) {
                                // The missing `seq` may be a blob this pass cannot see: make room instead of waiting.
                                for (r in rest) deferrals += r to expected
                                break
                            }
                        } else {
                            val since = firstSeen[e.key] ?: now
                            if (now - since < ChannelTime.GAP_HOLD_SECONDS) {
                                val ends = since + ChannelTime.GAP_HOLD_SECONDS
                                holdEnds = holdEnds?.let { minOf(it, ends) } ?: ends
                                break
                            }
                        }
                    }
                    taken += e
                    expected = e.seq + 1
                }
            }
            taken.sortWith(compareBy<Entry<T>>({ it.leaf }, { it.seq }))
            out += taken.chunked(BATCH)
        }
        return Plan(out, deferrals)
    }

    /**
     * S13a (§19.54 row 3): does the plan still remember [key] as a gap deferral within its grace — the receive
     * step's peek cursor may leave such a row out of its window (no classification, no native open); the row is
     * offered back through the [Plan] **by its key** and either taken (its `seq` has come due) or deferred again,
     * so the frontier can never wait on a row the window hides. A deferral past its grace is not remembered: the
     * row is re-examined from the start.
     */
    fun isDeferredInGrace(key: List<Byte>, now: Long): Boolean {
        val d = gapDeferred[key] ?: return false
        return now <= d.until + DEFERRAL_GRACE_SECONDS
    }

    /** The second the earliest gap hold or deferral of the last pass ends (the actor's next wake), or null. */
    fun holdEnds(): Long? = holdEnds

    /**
     * A pass whose peek was empty: nothing is held in place any more, only the deferrals wait (the review of S4 noted that
     * the hold of the last non-empty pass otherwise stayed as the actor's next wake).
     */
    fun idle(now: Long) {
        gapDeferred.values.removeIf { now > it.until + DEFERRAL_GRACE_SECONDS }
        firstSeen.keys.retainAll { it in gapDeferred }
        holdEnds = gapDeferred.values.filter { !it.reoffered }.minOfOrNull { it.until }
    }

    /** [e] was deferred until [until] behind the gap at [waitingFor] (the receive step's `Inbox.defer` committed). */
    fun deferred(e: Entry<*>, waitingFor: Long, until: Long) {
        gapDeferred[e.key] = Deferred(e.channelId, e.epoch, e.leaf, e.seq, senderKey(e), e.namespace, waitingFor, until)
        holdEnds = holdEnds?.let { minOf(it, until) } ?: until
    }

    /** The row [key] is gone — consumed, or no longer in the inbox: nothing to wait for or offer back. */
    fun forget(key: List<Byte>) {
        gapDeferred.remove(key)
        firstSeen.remove(key)
    }

    /**
     * The namespaces of [channelId] whose deferred rows' sender has decrypted past the `seq` they waited for: the caller
     * re-offers them (`Inbox.reofferDeferred`) in the transaction that decrypted it, and the next [plan] offers those rows
     * back by their key. Each deferral is reported once.
     */
    fun reofferDue(channelId: ByteArray): Set<List<Byte>> {
        val prefix = channelId.toList()
        val out = HashSet<List<Byte>>()
        for (d in gapDeferred.values) {
            if (d.reoffered || d.sender.subList(0, prefix.size) != prefix) continue
            val next = nextSeq[d.sender] ?: continue
            if (next > d.waitingFor) {
                d.reoffered = true
                out += d.namespace
            }
        }
        return out
    }


    /** A post of [leaf] with [seq] decrypted in [epoch]: the next one expected is `seq + 1`. */
    fun decrypted(channelId: ByteArray, epoch: Long, leaf: Long, seq: Long) {
        val key = channelId.toList() + ChannelAd.u64(epoch).toList() + ChannelAd.u64(leaf).toList()
        val known = nextSeq[key]
        if (known == null || seq + 1 > known) nextSeq[key] = seq + 1
    }

    /** Forgets what the passes remembered: the context closed. */
    fun clear() {
        nextSeq.clear()
        firstSeen.clear()
        gapDeferred.clear()
        holdEnds = null
    }

    private fun senderKey(e: Entry<*>): List<Byte> =
        e.channelId.toList() + ChannelAd.u64(e.epoch).toList() + ChannelAd.u64(e.leaf).toList()

    /** Lowercase hex, table-driven: [plan]'s sort key calls this per comparison — the per-byte
     *  `"%02x".format` it used ran `java.util.Formatter` (and its regex) per byte. Identical output. */
    private fun ByteArray.toHex(): String {
        val digits = "0123456789abcdef"
        val out = CharArray(size * 2)
        for (i in indices) {
            val b = this[i].toInt() and 0xff
            out[2 * i] = digits[b shr 4]
            out[2 * i + 1] = digits[b and 0x0f]
        }
        return String(out)
    }

    override fun toString(): String = "ChannelPeekOrder"

    companion object {
        /** §6.3.5, S0-17: one `receive` call decrypts at most 32 messages of one epoch. */
        const val BATCH: Int = 32

        /**
         * How long a row deferred behind a gap under pressure stays out of the window unless its sender's gap fills first
         * (which re-offers it at once): the pressure hold, so that rows already seen do not come back into the window
         * before the rows not yet seen have had their turn in it.
         */
        const val GAP_DEFER_SECONDS: Int = 60 * 60

        /** Under pressure, how long a gap is held before the receiver decrypts past it (§19.38; in place, 12 minutes). */
        const val PRESSURE_HOLD_SECONDS: Long = 60 * 60

        /** A deferral whose row has not come back this long after its time is forgotten. */
        const val DEFERRAL_GRACE_SECONDS: Long = 60 * 60
    }
}
