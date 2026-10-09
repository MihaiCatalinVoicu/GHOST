package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SendDelay

/**
 * **`CH-SWITCH`** (Phase 10 design §6.5, §19.8 (a), §10.4), **one transaction per switched channel**:
 * the generation switch a `pending_switch` row has waited for.
 *
 * **When it runs.** At the first pass at or after the commit's `switch_hour` (a pass necessarily follows
 * the listing steps that fetched the commit — the hour is the commit's own claim, so the switch is
 * commit-fixed time, never a received blob's: T40, LC-4), or at the next **session start** for a pending
 * row with no hour (§19.8: a joiner that joined into a newer generation). A hint pass may run it: its
 * time is the commit's hour, not the hint's.
 *
 * **What one switch writes**, in its one transaction:
 *  - `Namespaces.register(ns_{g+1}, CHANNEL, set(ns_{g+1}, w), listen = true, LOCAL)` and the READ and
 *    DEPOSIT credentials of every slot of the week's set (`Capabilities.put`, no local expiry — §19.37
 *    F-6 option (c)), minted by `generation` (fn 13) **before** the transaction opens (a native refusal
 *    must not commit a half-written switch);
 *  - the pending generation becomes `current` and the old one `draining` with
 *    `drain_until_day = day(switch_hour) + 14` (§6.5: the day of the commit's switch hour, so a member
 *    that switches late ends the drain on the same day as everyone; a joiner's hour-less row uses the day
 *    it switches — recorded in §19.41);
 *  - **a switch while a generation is already draining ends the older drain at once** (§6.5: its unfetched
 *    posts are the declared loss, §6.3.6): the older namespace is removed here when it has no open op
 *    (its still-deferred fetched rows marked consumed first, §19.23), else its `drain_until_day` moves to
 *    the day before today — the schema lets a drain's end move only earlier — and `CH-SWEEP` owns the
 *    removal retry; the older drain is read without the drain filter, so a drain whose end already moved
 *    takes the same end-or-defer path instead of aborting the demotion (the double-rotation deadlock,
 *    §19.42);
 *  - **the rotating committer funds**: when the pending row's `own_rotation` marks the member's own commit
 *    (§6.5 "Funding at a rotation", §19.8 (d): the time is the committer's own switch hour, never the
 *    settle's), `Funding.set(ns_{g+1}, true)` and the READ and DEPOSIT registration rows of the current
 *    week (the `{c, c + 1}` rows of a registration capability are the funder renewal step's, like
 *    `CH-CREATE`'s);
 *  - the channel's position (generation number) and `Inbox.reofferDeferred(ns_{g+1})` (§7.5 item 6).
 *
 * Posts composed between the settle and the switch were kept plaintext by `CH-POST`'s "current" check
 * (§6.3.1); the switch is the first pass where the channel holds no `pending_switch` row, so the pending
 * posts encrypt into `ns_{g+1}` in the same pass. Ops already enqueued for `ns_g` complete there (§6.5).
 *
 * Gate G-M5 lists this file for `Namespaces.register`, `Capabilities.put`, `Registrations.keep` and
 * `Funding.set`.
 */
internal class ChannelSwitchStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** Switches every due pending generation; returns how many switched. */
    fun switchDue(sessionStart: Boolean): Int {
        val now = env.now()
        val nowHour = DmTime.floorHour(now)
        val day = DmTime.day(now)
        val channels = env.database.transaction { tx ->
            (stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) + stores.channels.channelsIn(tx.sql, ChannelState.LEAVING))
                .map { it.channelId }
        }
        var switched = 0
        for (channelId in channels) {
            val pending = env.database.transaction { tx ->
                stores.generations.duePending(tx.sql, channelId, nowHour, day)
                    .filter { it.switchHour != null || sessionStart }
            }
            for (g in pending) if (switch(channelId, g.generation)) switched++
        }
        return switched
    }

    /** The second the earliest hour-announced pending switch comes (the actor's next wake), or null. */
    fun nextDue(): Long? {
        val day = DmTime.day(env.now())
        return env.database.transaction { tx ->
            (stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) + stores.channels.channelsIn(tx.sql, ChannelState.LEAVING))
                .mapNotNull { ch ->
                    stores.generations.duePending(tx.sql, ch.channelId, Long.MAX_VALUE, day)
                        .mapNotNull { it.switchHour }
                        .minOrNull()
                }
                .minOrNull()
        }
    }

    /** One switch of [generation] of [channelId]; false when the relay set or the context is unavailable. */
    private fun switch(channelId: ByteArray, generation: Long): Boolean {
        val now = env.now()
        val day = DmTime.day(now)
        val week = DmTime.week(now)
        val opened = env.contexts.open(channelId) ?: return false
        val snapshot = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId)
            if (channel == null || (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.LEAVING)) {
                return@transaction null
            }
            val g = stores.generations.generation(tx.sql, channelId, generation, day) ?: return@transaction null
            val current = stores.generations.current(tx.sql, channelId, day) // null: a joiner's first generation pends
            val older = stores.generations.live(tx.sql, channelId, day).firstOrNull { it.state == GenerationState.DRAINING }
            val set = env.relaySet(g.namespaceId, week) ?: return@transaction null
            SwitchView(g, current, older, set)
        } ?: return false
        // The native half before the transaction: the credentials and verifiers of every slot (a refusal
        // here writes nothing, like CH-CREATE).
        val slots = ByteArray(snapshot.set.size) { snapshot.set[it].slot.toByte() }
        val credentials = when (val c = opened.crypto.generation(channelId, snapshot.pending.gEnv, snapshot.pending.generation.toInt(), snapshot.pending.openEpoch, slots)) {
            is MlsOutcome.Ok -> c.value.slots
            is MlsOutcome.Refused -> return false
        }
        // §19.23: the older drain's still-deferred fetched rows are marked consumed before the removal is
        // tried (by then unopenable: the epoch keys are past retention). `held` runs its own short
        // transaction, so the loop stays outside the switch transaction.
        val olderNs = snapshot.older?.let { NamespaceId(it.namespaceId) }
        if (olderNs != null) {
            while (true) {
                val held = sync.inbox.held(olderNs, now, HELD_BATCH)
                if (held.isEmpty()) break
                env.database.transaction { tx ->
                    for (h in held) sync.inbox.markConsumed(tx, h.namespace, h.hash)
                }
            }
        }
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || (fresh.state != ChannelState.ACTIVE && fresh.state != ChannelState.LEAVING)) return@transaction false
                val pending = stores.generations.generation(tx.sql, channelId, generation, day)
                    ?: return@transaction false // switched meanwhile (a crash retried it)
                // The current generation demotes to draining — null for a joiner whose first generation is
                // still pending (CH-JOIN inserted it with no hour): there is nothing to demote.
                val current = stores.generations.current(tx.sql, channelId, day)
                val ns = NamespaceId(pending.namespaceId)
                // A switch while a generation drains ends the older drain at once (§6.5): its unfetched
                // posts are the declared loss. The schema keeps at most one draining generation, so the
                // demotion below needs the older row gone: when an open op refuses the removal, the older
                // drain's end moves to the day before today and the switch waits — CH-SWEEP owns the
                // removal retry and the next pass completes the switch.
                //
                // The older drain is read without the drain filter too (the review of S6, §19.42): once
                // its end moved to before today, no live() read names it, but its row still reads
                // `draining` — and the demotion's at-most-one-draining trigger would abort the whole
                // switch transaction on it, every pass, for ever (CH-SWITCH runs before CH-SWEEP, so the
                // sweep's removal retry never runs: a permanent engine deadlock). The end-or-defer shape
                // is the same — the removal is retried here and, while it stays refused, left to the sweep.
                val older = stores.generations.live(tx.sql, channelId, day).firstOrNull { it.state == GenerationState.DRAINING }
                    ?: stores.generations.draining(tx.sql, channelId)
                if (older != null) {
                    val oldNs = NamespaceId(older.namespaceId)
                    if (sync.namespaces.remove(tx, oldNs)) {
                        stores.generations.delete(tx, channelId, older.generation)
                    } else {
                        stores.generations.endDrainEarly(tx, channelId, older.generation, day)
                        sync.namespaces.setListening(tx, oldNs, false)
                        return@transaction false
                    }
                }
                val switchAt = pending.switchHour ?: DmTime.ceilHour(now)
                if (current != null) {
                    stores.generations.demote(tx, channelId, current.generation, DmTime.day(switchAt) + ChannelSettleStep.DRAIN_DAYS)
                }
                if (!stores.generations.promote(tx, channelId, pending.generation)) return@transaction false
                sync.namespaces.register(
                    tx = tx,
                    namespace = ns,
                    consumer = Consumer.CHANNEL,
                    relays = snapshot.set.map { it.relay }.toSet(),
                    listen = true,
                    sendDelay = SendDelay.DEFAULT,
                    capabilitySource = CapabilitySource.LOCAL,
                )
                for (slot in snapshot.set) {
                    val c = credentials.firstOrNull { it.slot == slot.slot }
                        ?: throw IllegalStateException("generation returned no credential for a slot it was asked for")
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.READ, c.readCredential, null)
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.WRITE, c.depositCredential, null)
                }
                if (pending.ownRotation) {
                    // §6.5: the member whose commit rotated funds ns_{g+1} for the current week at its switch.
                    sync.funding.set(tx, ns, true)
                    for (slot in snapshot.set) {
                        val c = credentials.firstOrNull { it.slot == slot.slot } ?: continue
                        sync.registrations.keep(tx, slot.relay, ns, week, KeyKind.READ, c.readVerifier)
                        sync.registrations.keep(tx, slot.relay, ns, week, KeyKind.DEPOSIT, c.depositVerifier)
                    }
                }
                stores.channels.setPosition(tx, channelId, pending.generation, fresh.epoch)
                sync.inbox.reofferDeferred(tx, ns)
                true
            }
        } catch (e: org.ghost.storage.StorageFullException) {
            false
        }
    }

    /** What the pre-transaction snapshot read: the pending row, the current one (null: a joiner), an older drain, the set. */
    private class SwitchView(
        val pending: org.ghost.messaging.channel.store.GenerationStore.GenerationRow,
        val current: org.ghost.messaging.channel.store.GenerationStore.GenerationRow?,
        val older: org.ghost.messaging.channel.store.GenerationStore.GenerationRow?,
        val set: List<org.ghost.messaging.port.EsSlot>,
    )

    override fun toString() = "ChannelSwitchStep"

    companion object {
        /** The held rows consumed per round while an older drain ends (a namespace's fetched cap is 256). */
        const val HELD_BATCH: Int = 256
    }
}
