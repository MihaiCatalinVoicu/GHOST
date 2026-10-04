package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.JoinStore
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId

/**
 * **`CH-JOIN`** (Phase 10 design §6.2.5, §10.4), on a WELCOME blob (mode 0x13) fetched from the namespace of a pending
 * join, **one transaction**, and the joiner's half of the join state machine (§6.11: `joining → active`).
 *
 * The blob is opened with the invite's `JK_g` (an invite's class-6 envelope, which opens mode 0x13 and nothing else) and
 * handed to `welcomeJoin` (§10.2 fn 5) with **only the KeyPackage's global rows**, the invite's generation and namespace
 * (the bootstrap check of §5.4) and **the committers anchor** — the invite's `committers_digest` — which the native side
 * checks **first**, on the unverified GroupInfo, before `JoinBuilder::build()` validates the tree (S0-15, §19.27 TR-7,
 * §19.29.2), then the constant lifetimes, §5.3's validity of the joined context and the bootstrap. A Welcome that fails
 * any of them writes **nothing**: the KeyPackage and its private keys stay and the joiner keeps waiting for the real one
 * (V10-8: an applied forgery would consume the KeyPackage and the real Welcome would then fail). The blob is consumed and
 * counted (`INVALID_WELCOME`). A Welcome of another joiner's KeyPackage (`NOT_FOR_ME`) is consumed and ignored.
 *
 * On success, in one transaction: the group rows of the change-set (the KeyPackage's rows go with it), the channel
 * `joining → active` at its joined epoch and generation with the joined context's timer, class, password flag and name,
 * the bootstrap's generation — `current` when it is the invite's, `pending_switch` with no hour when it is newer (§19.8:
 * the switch is `CH-SWITCH`'s at the next session start, slice S6) —, the joined epoch's keys, the committers digest the
 * anchor proved (§19.37 F-S4-2), the join state deleted, the blob consumed and the namespace's deferred blobs re-offered
 * (`Inbox.reofferDeferred`, §7.5 item 6: the posts of the joined epoch that arrived before the Welcome).
 *
 * **No traffic** (T40, §6.2.5): this file calls no `Namespaces`, `Outbox`, `Registrations`, `Funding` or `Capabilities`
 * method — gate G-M5 refuses one here. The joiner's first store is its user's first post; its listening of the namespace
 * began at `CH-ACCEPT` (LC-5).
 */
internal class ChannelJoinStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** What [join] did with a Welcome blob. */
    enum class Outcome {
        /** The member joined; the blob was consumed in the same transaction. */
        JOINED,

        /** Consumed and counted: a Welcome for another joiner, or one that failed a check, or a forged seal. */
        CONSUMED,

        /** Left for a later pass: the stored state did not load (deferred) or the context is closed. */
        LEFT,
    }

    /** [blob] was fetched from the namespace of [join] and its hint is `R_join` in mode 0x13. */
    fun join(blob: InboundBlob, join: JoinStore.JoinRow): Outcome {
        val now = env.now()
        val day = DmTime.day(now)
        val c = join.channelId
        val ns = join.ns ?: return consume(blob, ChannelCounters.Reason.UNROUTED)
        val jkEnv = join.jkEnv ?: return consume(blob, ChannelCounters.Reason.UNROUTED)
        val content = env.keys.content() ?: return Outcome.LEFT
        val opened = env.contexts.open(c) ?: return Outcome.LEFT
        val body = when (val o = opened.crypto.open(c, jkEnv, ChannelCrypto.KEY_CLASS_INVITE_JOIN, ns, ChannelCrypto.MODE_WELCOME, blob.ciphertext)) {
            is MlsOutcome.Ok -> o.value.body
            is MlsOutcome.Refused -> return when (o.code) {
                MlsCode.CRYPTO_UNAVAILABLE -> Outcome.LEFT
                MlsCode.NOT_OPEN -> consume(blob, ChannelCounters.Reason.FORGED_SEAL)
                else -> consume(blob, ChannelCounters.Reason.NON_CANONICAL)
            }
        }
        val joins = env.database.transaction { tx -> stores.joins.joins(tx.sql, c, day) }.filter { it.ns != null }
        for (candidate in joins) {
            val digest = candidate.committersDigest ?: continue
            val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.globalRows(tx.sql, c, day) })
            val joined = when (
                val r = opened.crypto.welcomeJoin(
                    c, rows, body, day.toInt(), candidate.generation.toInt(), candidate.ns!!,
                    ChannelCrypto.Anchor.Invite(digest),
                )
            ) {
                is MlsOutcome.Ok -> r.value
                is MlsOutcome.Refused -> when (r.code) {
                    MlsCode.NOT_FOR_ME -> continue
                    MlsCode.CRYPTO_UNAVAILABLE -> return Outcome.LEFT
                    MlsCode.STATE_CORRUPT -> return defer(blob)
                    // INVALID_WELCOME (the anchor among its causes), INVALID_BOOTSTRAP, INVALID_POLICY, NON_CANONICAL:
                    // nothing is written, the KeyPackage stays for the real Welcome (V10-8, PC-19).
                    else -> return consume(blob, ChannelCounters.Reason.INVALID_WELCOME)
                }
            }
            return env.database.transaction { tx ->
                val channel = stores.channels.channel(tx.sql, c)
                if (channel == null || channel.state != ChannelState.JOINING) {
                    // Already joined by another copy of the Welcome, or the join expired meanwhile: nothing to apply.
                    sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
                    return@transaction Outcome.CONSUMED
                }
                val context = joined.context
                val g = joined.generation
                stores.mls.apply(tx, c, MlsRows.changes(joined.changes))
                stores.channels.transition(tx, c, ChannelState.JOINING, ChannelState.ACTIVE)
                stores.channels.setJoined(tx, c, joined.epoch.epoch, g.generation)
                stores.channels.setPolicy(
                    tx, c, context.timerCode, context.sizeClass, context.flags and ChannelEnv.FLAG_PASSWORD != 0,
                    if (context.name.isEmpty()) null else env.seal(content, ChannelAd.name(c), context.name),
                )
                // §5.4: a bootstrap that names the invite's generation is checked against its namespace natively; a newer one
                // (a rotation between the invite and the admission) is switched to by CH-SWITCH, not here (§19.8, S6).
                val state = if (g.generation == candidate.generation) GenerationState.CURRENT else GenerationState.PENDING_SWITCH
                stores.generations.insert(tx, c, g.generation, g.ns, state, g.gEnv, g.jkEnv, g.rJoin, g.openEpoch)
                stores.epochs.insert(tx, c, joined.epoch.epoch, joined.epoch.kEnv, joined.epoch.rEp)
                stores.channels.setCommittersDigest(tx, c, digest)
                stores.joins.deleteJoins(tx, c)
                sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
                sync.inbox.reofferDeferred(tx, NamespaceId(ns))
                Outcome.JOINED
            }
        }
        return consume(blob, ChannelCounters.Reason.NOT_FOR_ME)
    }

    private fun consume(blob: InboundBlob, reason: ChannelCounters.Reason): Outcome {
        env.database.transaction { tx -> sync.inbox.markConsumed(tx, blob.namespace, blob.hash) }
        env.counters.count(reason)
        return Outcome.CONSUMED
    }

    private fun defer(blob: InboundBlob): Outcome {
        env.database.transaction { tx -> sync.inbox.defer(tx, blob.namespace, blob.hash, STATE_CORRUPT_DEFER_SECONDS) }
        env.counters.count(ChannelCounters.Reason.STATE_CORRUPT)
        return Outcome.LEFT
    }

    override fun toString(): String = "ChannelJoinStep"

    companion object {
        /** A blob whose stored state did not load waits an hour, never consumed (it is not the blob's fault). */
        const val STATE_CORRUPT_DEFER_SECONDS: Int = 3_600
    }
}
