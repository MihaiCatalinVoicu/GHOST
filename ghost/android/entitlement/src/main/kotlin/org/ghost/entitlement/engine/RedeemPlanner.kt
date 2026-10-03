package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.store.SyncTables
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.network.OnionAddress
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import java.nio.ByteBuffer

/**
 * Redemption timing per need (design §12.4, §11.6, §19.12), a pure function of the need, the relay,
 * the schedule, the relay-facing clock and client randomness:
 *
 * | need | token week | when |
 * |---|---|---|
 * | EXPIRING (write, read or register), within the last 23 h of week p | p + 1 | `PRF(pair, p)` in `[start(p+1) − 23 h, start(p+1) − 1 h]` |
 * | EXPIRING earlier in week p (a capability that ends before `start(p+1)`) | p | at once |
 * | WRITE or REGISTER MISSING, EXHAUSTED, REJECTED | p | at once (as soon as an eligible token exists) |
 * | READ MISSING | p | `PRF(pair, p)` in `[first seen, first seen + 6 h]` |
 * | any, of a namespace whose capabilities are LOCAL | — | never (`LOCAL_SKIPPED`, Phase 9 §13.4) |
 * | any, within ±1 h of a week boundary or without a trusted clock | — | deferred |
 * | any, on a relay listed in no ES slot for the week | — | never (`NO_SLOT`) |
 * | any, whose pair holds a usable capability of the need's own class reaching `start(target + 1)` | — | skipped |
 *
 * **REGISTER needs** (Phase 10 design §7.5, §7.6) are WRITE needs of a REDEEM namespace in every row
 * above: the sync layer reports them with source REDEEM whatever the funded namespace's own source is
 * (a channel's is LOCAL, because its members install the shared bearer credentials themselves), so the
 * LOCAL row never applies to them. Their "own class" is the registration capability: the covering
 * expiry the caller passes is the pair's usable **registration** capability, not its write slot, which
 * holds the channel's DEPOSIT credential and says nothing about whether a token of this week would
 * extend a registration capability. Their PRF input carries its own kind byte, so a REGISTER need and a
 * READ or WRITE need of the same pair and week draw different times.
 *
 * The PRF is keyed per process and never persisted (`relay_id ‖ namespace ‖ kind ‖ week`). Every
 * redemption yields a write capability expiring at the end of its token's week plus 1 h (§10.3), and
 * a write capability serves reads too (interim, §10.7), so a need whose pair already holds a usable
 * write capability reaching the end of the target week is skipped: a token of that week could not
 * extend it. This also covers the second row: the device clock (which raises EXPIRING 24 h ahead) may
 * run ahead of the relay-facing clock, and a week-aligned capability whose need arrives before the
 * renewal window then waits for it instead of spending current-week tokens that renew nothing.
 */
internal class RedeemPlanner(private val random: EntitlementRandom) {

    sealed class Decision {
        class Redeem(val need: CapabilityNeed, val relay: SyncTables.Relay, val week: Long, val slots: List<Int>, val dueSeconds: Long) : Decision() {
            override fun toString(): String = "Redeem(week=$week)"
        }

        /** Not now: the clock is untrusted or a week boundary is within 1 h. */
        object Deferred : Decision()

        /** The relay holds no ES slot in the token week (counted, never raises ENTITLEMENT_NEEDED). */
        object NoSlot : Decision()

        /**
         * The namespace installs its own credentials (Phase 9 design §13.4): a contact's inbox or
         * bundle, whose write access is a bearer credential derived from the contact's card. It is
         * counted and never redeemed for, so DM breadth costs no token (§4.8 token accounting).
         */
        object LocalSkipped : Decision()

        /** Nothing to do: the relay is not active in the directory, or a write capability already covers the need. */
        object Skip : Decision()
    }

    fun plan(
        need: CapabilityNeed,
        relay: SyncTables.Relay?,
        summary: ScheduleSummary,
        nowEst: Long,
        relayWeek: Long,
        trusted: Boolean,
        firstSeen: Long,
        coveringExpiryHour: Long?,
    ): Decision {
        // A LOCAL need is decided before anything else, so no token is ever reserved for it and no
        // unmet need of it raises ENTITLEMENT_NEEDED (Phase 9 design §13.4, mutant PM-1b).
        if (need.source == CapabilitySource.LOCAL) return Decision.LocalSkipped
        if (relay == null) return Decision.Skip
        if (!trusted || nearBoundary(nowEst)) return Decision.Deferred
        val p = relayWeek
        val nextStart = Grid.start(p + 1)
        val target: Long
        val due: Long
        when {
            need.reason == CapabilityNeed.Reason.EXPIRING && nowEst >= nextStart - EXPIRING_LEAD -> {
                target = p + 1
                due = nextStart - EXPIRING_LEAD + (prf(need, p) * EXPIRING_SPAN).toLong()
            }
            need.kind == CapabilityKind.READ && need.reason == CapabilityNeed.Reason.MISSING -> {
                target = p
                due = firstSeen + (prf(need, p) * READ_SPAN).toLong()
            }
            else -> {
                target = p
                due = nowEst
            }
        }
        if (coveringExpiryHour != null && coveringExpiryHour >= Grid.start(target + 1)) return Decision.Skip
        val slots = slotsFor(summary, relay.address, target)
        if (slots.isEmpty()) return Decision.NoSlot
        return Decision.Redeem(need, relay, target, slots, due)
    }

    /** Uniform in [0, 1) for (relay, namespace, kind, week). */
    private fun prf(need: CapabilityNeed, week: Long): Double {
        val ns = need.namespace.toByteArray()
        val input = ByteBuffer.allocate(8 + ns.size + 1 + 8)
            .putLong(need.relay.value).put(ns).put(kindByte(need.kind)).putLong(week).array()
        return random.prf(EntitlementRandom.DOMAIN_REDEEM, input)
    }

    override fun toString(): String = "RedeemPlanner"

    /** The kind byte of the PRF input: 1 for READ and 2 for WRITE (Phase 8, pinned by the policy vectors), 3 for REGISTER. */
    private fun kindByte(kind: CapabilityKind): Byte = when (kind) {
        CapabilityKind.READ -> 1
        CapabilityKind.WRITE -> 2
        CapabilityKind.REGISTER -> 3
    }

    companion object {
        private const val EXPIRING_LEAD: Long = 23 * Grid.HOUR
        private const val EXPIRING_SPAN: Long = 22 * Grid.HOUR
        private const val READ_SPAN: Long = 6 * Grid.HOUR

        /** Within ±1 h of a week boundary (R9: no redeem there). */
        fun nearBoundary(t: Long): Boolean {
            val p = Grid.week(t)
            return t - Grid.start(p) < Grid.HOUR || Grid.start(p + 1) - t < Grid.HOUR
        }

        /**
         * The ES slots [relay] serves in [week] (design §19.22 point 3, as the native pre-I/O check):
         * the slots listed under its exact `onion:port`, otherwise the single slot listed under its
         * service key; a key holding several slots in the week with an unlisted port serves none.
         */
        fun slotsFor(summary: ScheduleSummary, relay: OnionAddress, week: Long): List<Int> {
            val valid = summary.slots.filter { it.validIn(week) }
            val exact = valid.filter { it.onion == relay }.map { it.slot }.distinct().sorted()
            if (exact.isNotEmpty()) return exact
            val byKey = valid.filter { it.onion.host == relay.host }.map { it.slot }.distinct()
            return if (byKey.size == 1) byKey else emptyList()
        }
    }
}
