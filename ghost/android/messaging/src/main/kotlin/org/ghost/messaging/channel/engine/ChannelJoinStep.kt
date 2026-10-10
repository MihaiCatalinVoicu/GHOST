package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.EpochStore
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.channel.store.GenerationStore
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
    private val liveness: ChannelLivenessStep,
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
                // §19.16 (d): a rejoin's or restore's Welcome joins over the KeyPackage's global rows
                // only (nothing of the old group was passed to `welcomeJoin`); the old group rows are
                // deleted in the same transaction. A fresh join has none — the delete is a no-op.
                stores.mls.deleteGroupRows(tx, c)
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
                // CO-12's clock starts at the join day: the admission commit is the last
                // committer commit the joiner's branch reflects (a joiner never settles it —
                // CH-JOIN applies the Welcome), and the 9-day flags read this column.
                stores.channels.setLastCommitterCommitDay(tx, c, day)
                stores.joins.deleteJoins(tx, c)
                // CO-8, CO-9's schedule, seeded like CH-CREATE's (the PCS clock starts at the join day).
                seedSchedule(env, tx, c, day)
                // §19.44 F-S7-6: the join restarts the channel — CO-11's window state belonged to
                // the old leaf; carried over it would refire the moment the channel is active again.
                liveness.reset(tx, c, content)
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

    /**
     * The rejoin's answer (§6.7, §19.16 (d), §19.29.2): [blob] was fetched from [generation]'s
     * namespace and its hint is `R_join` in mode 0x13 — a committer's answer to this member's
     * rejoin. The blob opens under the generation's `JK_g`; each pending rejoin KeyPackage (every rejoin
     * row whose give-up deadline has not passed — §6.7 keeps the row, the state and the keys until day 14,
     * not the 7-day re-send, §19.44) is tried with `welcomeJoin` over the KeyPackage's global rows only and
     * the rejoin anchor — the
     * GroupInfo signature must verify under one of the committers of the member's last final epoch,
     * which the stored state's context is (no digest comparison) — and the member keeps its rank
     * (its key is unchanged). A Welcome that fails a check writes nothing (the KeyPackage stays,
     * §6.2.5); one of another KeyPackage is `NOT_FOR_ME`. In the success transaction: the old
     * group rows are deleted (the rows were not passed to `welcomeJoin`: no `GroupAlreadyExists`),
     * the change-set applies, `resync_needed`/`reinvite_needed` return to `active`, a newer
     * bootstrap generation becomes `pending_switch` (§19.8), and the displayed posts stay.
     */
    fun joinWelcome(blob: InboundBlob, channelId: ByteArray, generation: GenerationStore.GenerationRow): Outcome {
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return Outcome.LEFT
        val opened = env.contexts.open(channelId) ?: return Outcome.LEFT
        val body = when (
            val o = opened.crypto.open(
                channelId, generation.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, generation.namespaceId,
                ChannelCrypto.MODE_WELCOME, blob.ciphertext,
            )
        ) {
            is MlsOutcome.Ok -> o.value.body
            is MlsOutcome.Refused -> return when (o.code) {
                MlsCode.CRYPTO_UNAVAILABLE -> Outcome.LEFT
                MlsCode.NOT_OPEN -> consume(blob, ChannelCounters.Reason.FORGED_SEAL)
                else -> consume(blob, ChannelCounters.Reason.NON_CANONICAL)
            }
        }
        val joinRows = env.database.transaction { tx -> stores.joins.rejoinsUntilDeadline(tx.sql, channelId, day) }
        if (joinRows.isEmpty()) return consume(blob, ChannelCounters.Reason.NOT_FOR_ME)
        // The anchor: the committers of the member's last final epoch — the context its stored state
        // holds, the state as of its last merged commit (§6.2.5, §19.29.2).
        val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.rows(tx.sql, channelId, day) })
        val committers = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull()
            ?.context?.committers ?: return Outcome.LEFT
        val global = MlsRows.of(env.database.transaction { tx -> stores.mls.globalRows(tx.sql, channelId, day) })
        for (join in joinRows) {
            val joined = when (
                val r = opened.crypto.welcomeJoin(
                    channelId, global, body, day.toInt(), join.generation.toInt(), generation.namespaceId,
                    ChannelCrypto.Anchor.Rejoin(committers),
                )
            ) {
                is MlsOutcome.Ok -> r.value
                is MlsOutcome.Refused -> when (r.code) {
                    MlsCode.NOT_FOR_ME -> continue
                    MlsCode.CRYPTO_UNAVAILABLE -> return Outcome.LEFT
                    MlsCode.STATE_CORRUPT -> return defer(blob)
                    // INVALID_WELCOME (the anchor among its causes), INVALID_BOOTSTRAP, INVALID_POLICY:
                    // nothing is written, the KeyPackage stays for the real one (V10-8, PC-19).
                    else -> return consume(blob, ChannelCounters.Reason.INVALID_WELCOME)
                }
            }
            return env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                val rejoins = stores.joins.rejoinsUntilDeadline(tx.sql, channelId, day)
                if (fresh == null || rejoins.isEmpty() ||
                    (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.RESYNC_NEEDED &&
                        fresh.state != ChannelState.REINVITE_NEEDED)
                ) {
                    // Joined by a copy, restored by an invite meanwhile, or gone: nothing to apply.
                    sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
                    return@transaction Outcome.CONSUMED
                }
                // §19.16 (d): the old group's rows are not passed to `welcomeJoin` and are deleted in
                // the same transaction; the Welcome's change-set replaces them.
                stores.mls.deleteGroupRows(tx, channelId)
                stores.mls.apply(tx, channelId, MlsRows.changes(joined.changes))
                if (fresh.state == ChannelState.RESYNC_NEEDED) {
                    stores.channels.transition(tx, channelId, ChannelState.RESYNC_NEEDED, ChannelState.ACTIVE)
                } else if (fresh.state == ChannelState.REINVITE_NEEDED) {
                    stores.channels.transition(tx, channelId, ChannelState.REINVITE_NEEDED, ChannelState.ACTIVE)
                }
                // §19.44 F-S7-6: the rejoin restarts the channel — CO-11's window state belonged to
                // the old leaf; carried over it would refire the moment the channel is active again.
                liveness.reset(tx, channelId, content)
                val g = joined.generation
                if (g.generation != fresh.generation) {
                    // A newer bootstrap (a rotation on the live branch): `CH-SWITCH` adopts it at the
                    // next session start or switch hour (§19.8).
                    stores.generations.insert(
                        tx, channelId, g.generation, g.ns, GenerationState.PENDING_SWITCH, g.gEnv, g.jkEnv,
                        g.rJoin, g.openEpoch,
                    )
                }
                // Room for the joined epoch's row (the schema keeps the current and 16 past, S0-6).
                for (k in stores.epochs.expired(tx.sql, day, EpochStore.MAX_EPOCHS * 4)) {
                    if (k.channelId.contentEquals(channelId)) {
                        stores.epochs.deleteForkSignals(tx, channelId, k.epoch)
                        stores.epochs.delete(tx, channelId, k.epoch)
                    }
                }
                val retained = stores.epochs.retained(tx.sql, channelId, day)
                if (retained.size >= EpochStore.MAX_EPOCHS) {
                    retained.filter { it.finalDay != null }.minByOrNull { it.epoch }?.let {
                        stores.epochs.deleteForkSignals(tx, channelId, it.epoch)
                        stores.epochs.delete(tx, channelId, it.epoch)
                    }
                }
                stores.epochs.insert(tx, channelId, joined.epoch.epoch, joined.epoch.kEnv, joined.epoch.rEp)
                // §19.17 (slice S9): a completed rejoin or restore replaced the member's own leaf —
                // its fresh KeyPackage carried a fresh box key, inserted (current) at resync or
                // accept time. The admission commit settled joined.epoch - 1, the last epoch whose
                // tree held the old leaf: every other still-current box key — the old leaf's, and
                // an abandoned earlier attempt's — is retired with that epoch, and the sweep
                // deletes it when the epoch's retention ends (PC-18's forward secrecy). A first
                // join finds only its own key and retires nothing.
                if (joined.epoch.epoch >= 1) {
                    val ownBox = joined.roster.firstOrNull { it.leaf == joined.leaf }?.boxPk
                    if (ownBox != null) {
                        for (key in stores.members.boxKeys(tx.sql, channelId, day)) {
                            if (key.lastEpoch == null && !key.boxPk.contentEquals(ownBox)) {
                                stores.members.retireBoxKey(tx, channelId, key.boxPk, joined.epoch.epoch - 1)
                            }
                        }
                    }
                }
                stores.channels.setPosition(tx, channelId, g.generation, joined.epoch.epoch)
                // The admission commit is the last committer commit the branch reflects (CO-12's clock,
                // as at a join).
                stores.channels.setLastCommitterCommitDay(tx, channelId, day)
                val schedule = stores.channels.schedule(tx.sql, channelId)
                if (schedule != null) {
                    // The new leaf is fresh: the PCS clock restarts, the slot stays.
                    stores.channels.putSchedule(tx, channelId, schedule.nextSelfupdateDay, day, schedule.nextPassMinute)
                }
                stores.joins.deleteJoins(tx, channelId)
                sync.inbox.markConsumed(tx, blob.namespace, blob.hash)
                sync.inbox.reofferDeferred(tx, NamespaceId(generation.namespaceId))
                Outcome.JOINED
            }
        }
        return consume(blob, ChannelCounters.Reason.NOT_FOR_ME)
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
