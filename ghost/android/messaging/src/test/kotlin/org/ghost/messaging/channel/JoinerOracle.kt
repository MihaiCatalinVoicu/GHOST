package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.engine.DmTime

/**
 * **The joiner oracle** (Phase 10 design §12.8, T39, P-C5; slice S4): everything a joiner holds after its join — every
 * epoch key of `ch_epoch` and every generation's join key `JK_g` — is tried against **every** blob the relays ever stored
 * in the channel's namespaces, the joiner's own native context doing the opening. A mode-0x11 blob whose MLS header
 * names an epoch before the join epoch must open **0** times; the generation's join traffic (modes 0x12 and 0x13, the
 * outer layer only), which `JK_g` opens, is the declared exception (L8-C3, §19.22) and is counted and reported, not
 * hidden. Posts are checked too: the joiner holds no post of an epoch before its join.
 */
internal object JoinerOracle {

    class Report(
        /** Blobs of the channel's namespaces the relays stored. */
        val blobs: Int,
        /** Mode-0x11 blobs of an epoch before the join that a key of the joiner opened: must be 0. */
        val openedBeforeJoin: Int,
        /** Mode-0x11 blobs of the join epoch or later that it opened (its own epochs: allowed). */
        val openedSinceJoin: Int,
        /** Join requests and Welcomes its `JK_g` opened: the declared exception, reported. */
        val joinTraffic: Int,
        /** Posts the joiner holds of an epoch before its join: must be 0. */
        val postsBeforeJoin: Long,
    ) {
        override fun toString(): String =
            "JoinerOracle(blobs=$blobs, openedBeforeJoin=$openedBeforeJoin, openedSinceJoin=$openedSinceJoin, " +
                "joinTraffic=$joinTraffic, postsBeforeJoin=$postsBeforeJoin)"
    }

    fun run(w: ChannelWorld, joiner: ChannelClient, id: ChannelId, joinEpoch: Long): Report {
        val c = id.toByteArray()
        val day = DmTime.day(joiner.clock.now)
        val crypto = (joiner.contexts.open(c) ?: error("the joiner's channel does not open")).crypto
        val (epochs, generations) = joiner.database.transaction { tx ->
            joiner.channelStores.epochs.retained(tx.sql, c, day) to joiner.channelStores.generations.live(tx.sql, c, day)
        }
        val namespaces = generations.map { ModelChannelRelay.hex(it.namespaceId) }.toSet()
        val blobs = w.relay.stored.filter { ModelChannelRelay.hex(it.namespace) in namespaces }
            .distinctBy { ModelChannelRelay.hex(it.namespace) + ModelChannelRelay.hex(it.hash) }
        var before = 0
        var since = 0
        var join = 0
        for (blob in blobs) {
            for (e in epochs) {
                val o = crypto.open(c, e.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, blob.namespace, ChannelCrypto.MODE_EPOCH, blob.ciphertext)
                if (o is MlsOutcome.Ok) {
                    if ((o.value.headerEpoch ?: o.value.order.epoch) < joinEpoch) before++ else since++
                }
            }
            for (g in generations) {
                for (mode in listOf(ChannelCrypto.MODE_JOIN, ChannelCrypto.MODE_WELCOME)) {
                    val o = crypto.open(c, g.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, blob.namespace, mode, blob.ciphertext)
                    if (o is MlsOutcome.Ok) join++
                }
            }
        }
        val posts = joiner.count("ch_post", "channel_id = ? AND epoch < ?", c, joinEpoch)
        return Report(blobs.size, before, since, join, posts)
    }
}
