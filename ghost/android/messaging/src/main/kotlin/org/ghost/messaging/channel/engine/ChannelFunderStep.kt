package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.engine.DmTime
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId

/**
 * **The funder renewal step** (Phase 10 design §6.5 "Funding at a rotation", §7.4, §7.5 item 7, §19.8 (d);
 * the channel half of the DM's `REGROWS`): the listed funders of a channel keep its namespaces'
 * registrations — created only here, never at a settle or a switch of a *received* rotation (otherwise F9
 * Q31's "redeem as soon as eligible" makes it a reflex: mutant PC-6).
 *
 * **When it runs.** On a **time-triggered** pass in the last [RENEWAL_WINDOW_SECONDS] of the ISO week (F8
 * §12.4's EXPIRING renewal: a PRF time in the last 23 h of the week), for every channel whose current
 * context names the member a funder — `active` ones and a `leaving` member's own channel while the
 * context still names it (the removal merges at the settle; until then the registrations are still its
 * to keep, §19.42). `Registrations.keep` inserts only the missing rows, so a pass in the
 * window repeats nothing; the step stays cheap on later passes.
 *
 * **What it renews.** For every generation the member listens to that is `current` or `pending_switch`
 * (§19.8: the renewal step covers the current generation and creates the **next** generation's registration
 * while a switch pends — the rotating committer's `CH-SWITCH` funds and registers the week of the switch
 * itself; a draining generation is **not** renewed: "Funders stop renewing `ns_g`", its registrations lapse
 * at `start(w + 2) + 1 h`): for each relay of the week's set, a READ and a DEPOSIT registration row for
 * **`week(now)` always** — so a pending row is there to be served, and the planner redeems for it — and for
 * **`c` and `c + 1` of the pair's usable registration capability** (graft G-3: the `c + 1` row buys the
 * offline tolerance; `c` is read from the capability's declared expiry, as the relay judges the period, not
 * from the clock). The verifiers come from `generation` (fn 13) over the generation the member holds —
 * computed **before** the transaction, like `CH-CREATE`.
 *
 * **`Funding.set`.** A member the context names a funder whose flag is not set (named by a policy change)
 * sets it here — never on a received commit (`CH-SETTLE`), which §7.5 item 7 forbids. A **pending**
 * generation's namespace is registered **write-only** here (no listening before the commit's switch hour,
 * LC-4) so the flag and the registration rows have a namespace; `CH-SWITCH` turns the listening on.
 *
 * Gate G-M5 lists this file for `Namespaces.register`, `Registrations.keep` and `Funding.set`.
 */
internal class ChannelFunderStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    /** Whether the renewal window (the week's last [RENEWAL_WINDOW_SECONDS]) is open. */
    fun renewalDue(now: Long): Boolean = DmTime.weekStart(DmTime.week(now) + 1) - now <= RENEWAL_WINDOW_SECONDS

    /**
     * The next instant the renewal window opens (the actor's next wake), or null when nothing is funded
     * or the window is open now.
     */
    fun nextDue(now: Long): Long? {
        if (renewalDue(now)) return null
        val funded = env.database.transaction { tx ->
            var n = 0L
            tx.sql.query("SELECT count(*) FROM sync_namespace_fund") { r -> n = r.long(0) }
            n
        }
        if (funded == 0L) return null
        return DmTime.weekStart(DmTime.week(now) + 1) - RENEWAL_WINDOW_SECONDS
    }

    /** Renews the registrations of every funded channel; returns how many channels it kept rows for. */
    fun renewDue(): Int {
        val now = env.now()
        if (!renewalDue(now)) return 0
        val day = DmTime.day(now)
        val week = DmTime.week(now)
        // A LEAVING member the current context still names a funder keeps renewing until the removing
        // commit merges (the review of S6, §19.42): its funders key drops only at that settle's context
        // change, and the namespace's registrations must bridge the gap.
        val channels = env.database.transaction { tx ->
            stores.channels.channelsIn(tx.sql, ChannelState.ACTIVE) + stores.channels.channelsIn(tx.sql, ChannelState.LEAVING)
        }
        var renewed = 0
        for (channel in channels) {
            if (renew(channel.channelId, day, week, now)) renewed++
        }
        return renewed
    }

    /** One channel's renewal; false when the member is no listed funder or the half fails. */
    private fun renew(channelId: ByteArray, day: Long, week: Long, now: Long): Boolean {
        val opened = env.contexts.open(channelId) ?: return false
        // The generations to renew and the relay sets: read first (the relay set can be absent this week).
        val view = env.database.transaction { tx ->
            val channel = stores.channels.channel(tx.sql, channelId)
            if (channel == null || (channel.state != ChannelState.ACTIVE && channel.state != ChannelState.LEAVING)) {
                return@transaction null
            }
            val generations = stores.generations.live(tx.sql, channelId, day)
                .filter { it.state == GenerationState.CURRENT || it.state == GenerationState.PENDING_SWITCH }
            if (generations.isEmpty()) return@transaction null
            val sets = generations.map { g -> g to env.relaySet(g.namespaceId, week) }
            if (sets.any { it.second == null }) return@transaction null
            val funded = generations.map { sync.funding.isFunded(tx, NamespaceId(it.namespaceId)) }
            RenewalView(generations, sets.map { it.second!! }, funded)
        } ?: return false
        // The member must be a listed funder of the current context: read the roster (cheap native call,
        // no change-set) before the transaction.
        val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.rows(tx.sql, channelId, day) })
        val context = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull()?.context ?: return false
        if (context.funders.none { it.contentEquals(opened.pseudonym) }) return false
        // The verifiers of every generation and slot, before the transaction.
        val credentials = view.generations.map { g ->
            val slots = ByteArray(view.setOf(g.generation).size) { view.setOf(g.generation)[it].slot.toByte() }
            when (val c = opened.crypto.generation(channelId, g.gEnv, g.generation.toInt(), g.openEpoch, slots)) {
                is MlsOutcome.Ok -> g.generation to c.value.slots
                is MlsOutcome.Refused -> return false
            }
        }.toMap()
        return env.database.transaction { tx ->
            var changed = false
            for ((i, g) in view.generations.withIndex()) {
                val ns = NamespaceId(g.namespaceId)
                if (!view.funded[i]) {
                    // Named a funder by a policy change: the flag is this step's to set (§7.5 item 7),
                    // never a received commit's. A pending generation's namespace is not registered yet
                    // (CH-SWITCH listens to it at the switch hour, LC-4): register it write-only so the
                    // flag and the rows have a namespace, without listening a minute early.
                    if (g.state == GenerationState.PENDING_SWITCH && sync.namespaces.listening(tx, ns) == null) {
                        sync.namespaces.register(
                            tx = tx,
                            namespace = ns,
                            consumer = org.ghost.sync.api.Consumer.CHANNEL,
                            relays = view.setOf(g.generation).map { it.relay }.toSet(),
                            listen = false,
                            sendDelay = org.ghost.sync.api.SendDelay.DEFAULT,
                            capabilitySource = org.ghost.sync.api.CapabilitySource.LOCAL,
                        )
                    }
                    sync.funding.set(tx, ns, true)
                    changed = true
                }
                for (slot in view.setOf(g.generation)) {
                    val creds = credentials[g.generation]
                        ?: throw IllegalStateException("generation returned no credentials for a generation it was asked for")
                    val c = creds.firstOrNull { it.slot == slot.slot }
                        ?: throw IllegalStateException("generation returned no credential for a slot it was asked for")
                    for (period in periodsFor(tx, slot.relay, ns, week)) {
                        changed = sync.registrations.keep(tx, slot.relay, ns, period, KeyKind.READ, c.readVerifier) || changed
                        changed = sync.registrations.keep(tx, slot.relay, ns, period, KeyKind.DEPOSIT, c.depositVerifier) || changed
                    }
                }
            }
            changed
        }
    }

    /** The periods a pair must hold rows for (§4.8's graft G-3, the DM's `periodsFor`): `week` always, `{c, c + 1}` of the usable registration capability. */
    private fun periodsFor(tx: org.ghost.sync.api.SyncTransaction, relay: org.ghost.sync.api.RelayId, ns: NamespaceId, week: Long): List<Long> {
        val periods = linkedSetOf(week)
        val capability = sync.capabilities.installed(tx, relay, ns, CapabilityKind.REGISTER)
        if (capability != null && capability.state == InstalledCapability.State.USABLE) {
            capability.expiresHour?.let { expiry ->
                val c = DmTime.week(expiry - DmTime.HOUR - 1)
                periods += c
                periods += c + 1
            }
        }
        return periods.filter { it >= week - 1 }
    }

    /** What the pre-transaction read gathered. */
    private class RenewalView(
        val generations: List<org.ghost.messaging.channel.store.GenerationStore.GenerationRow>,
        val sets: List<List<org.ghost.messaging.port.EsSlot>>,
        val funded: List<Boolean>,
    ) {
        fun setOf(generation: Long): List<org.ghost.messaging.port.EsSlot> =
            sets[generations.indexOfFirst { it.generation == generation }]
    }

    override fun toString() = "ChannelFunderStep"

    companion object {
        /** F8 §12.4: the EXPIRING renewal is a PRF time in the last 23 h of the week. */
        const val RENEWAL_WINDOW_SECONDS: Long = 23 * DmTime.HOUR
    }
}
