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
        val value: T,
    ) {
        override fun toString(): String = "Entry(epoch=$epoch, leaf=$leaf, seq=$seq)"
    }

    /** `(channel ‖ epoch ‖ leaf)` → the next `seq` a decrypted post of that sender makes expected. */
    private val nextSeq = HashMap<List<Byte>, Long>()

    /** `(namespace ‖ hash)` → the second this object first saw the blob. */
    private val firstSeen = HashMap<List<Byte>, Long>()

    /** The second the earliest gap hold of the last [batches] ends, or null when it held nothing. */
    private var holdEnds: Long? = null

    /**
     * The batches to decrypt, in order — per channel and epoch ascending, each sorted by `(leaf, seq)` and cut at 32 — with
     * the held entries left out. [present] is every peeked blob's key, so a blob that left the inbox stops being
     * remembered.
     */
    fun <T> batches(entries: List<Entry<T>>, present: Set<List<Byte>>, now: Long): List<List<Entry<T>>> {
        firstSeen.keys.retainAll(present)
        // A clock stepped back restarts a hold from the new time (F9's ENG-8): `first_seen` is a wall time.
        firstSeen.replaceAll { _, since -> minOf(since, now) }
        for (e in entries) firstSeen.putIfAbsent(e.key, now)
        holdEnds = null
        val byEpoch = LinkedHashMap<List<Byte>, MutableList<Entry<T>>>()
        for (e in entries.sortedWith(compareBy<Entry<T>>({ it.channelId.toHex() }, { it.epoch }))) {
            byEpoch.getOrPut(e.channelId.toList() + ChannelAd.u64(e.epoch).toList()) { ArrayList() } += e
        }
        val out = ArrayList<List<Entry<T>>>()
        for (group in byEpoch.values) {
            val taken = ArrayList<Entry<T>>()
            for (sender in group.groupBy { it.leaf }.toSortedMap().values) {
                val sorted = sender.sortedBy { it.seq }
                var expected = nextSeq[senderKey(sorted.first())] ?: sorted.first().seq
                for (e in sorted) {
                    if (e.seq < expected) {
                        // A repeat or a post past its turn: decrypting it is harmless (MLS refuses a replay, layer 2).
                        taken += e
                        continue
                    }
                    val since = firstSeen[e.key] ?: now
                    if (e.seq > expected && now - since < ChannelTime.GAP_HOLD_SECONDS) {
                        val ends = since + ChannelTime.GAP_HOLD_SECONDS
                        holdEnds = holdEnds?.let { minOf(it, ends) } ?: ends
                        break
                    }
                    taken += e
                    expected = e.seq + 1
                }
            }
            taken.sortWith(compareBy<Entry<T>>({ it.leaf }, { it.seq }))
            out += taken.chunked(BATCH)
        }
        return out
    }

    /** The second the earliest gap hold of the last pass ends (the actor's next wake), or null. */
    fun holdEnds(): Long? = holdEnds

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
        holdEnds = null
    }

    private fun senderKey(e: Entry<*>): List<Byte> =
        e.channelId.toList() + ChannelAd.u64(e.epoch).toList() + ChannelAd.u64(e.leaf).toList()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    override fun toString(): String = "ChannelPeekOrder"

    companion object {
        /** §6.3.5, S0-17: one `receive` call decrypts at most 32 messages of one epoch. */
        const val BATCH: Int = 32
    }
}
