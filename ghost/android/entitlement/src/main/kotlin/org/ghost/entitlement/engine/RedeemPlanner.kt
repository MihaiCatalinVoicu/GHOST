package org.ghost.entitlement.engine

import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.store.SyncTables
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.network.OnionAddress
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import java.nio.ByteBuffer

/**
 * Redemption timing per need (design §12.4, §11.6, §19.12), a pure function of the need, the relay,
 * the schedule, the relay-facing clock and client randomness:
 *
 * | need | token week | when |
 * |---|---|---|
 * | EXPIRING (write or read), within the last 23 h of week p | p + 1 | `PRF(pair, p)` in `[start(p+1) − 23 h, start(p+1) − 1 h]` |
 * | EXPIRING of a capability that is not week-aligned | p | at once |
 * | WRITE MISSING, EXHAUSTED, REJECTED | p | at once (as soon as an eligible token exists) |
 * | READ MISSING | p | `PRF(pair, p)` in `[first seen, first seen + 6 h]` |
 * | any, within ±1 h of a week boundary or without a trusted clock | — | deferred |
 * | any, on a relay listed in no ES slot for the week | — | never (`NO_SLOT`) |
 *
 * The PRF is keyed per process and never persisted (`relay_id ‖ namespace ‖ kind ‖ week`). A READ
 * need is met by a write capability (interim, §10.7), so one whose pair already holds a usable write
 * capability reaching past the target week is skipped.
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
        writeExpiryHour: Long?,
    ): Decision {
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
        if (need.kind == CapabilityKind.READ && writeExpiryHour != null && writeExpiryHour >= Grid.start(target + 1)) return Decision.Skip
        val slots = slotsFor(summary, relay.address, target)
        if (slots.isEmpty()) return Decision.NoSlot
        return Decision.Redeem(need, relay, target, slots, due)
    }

    /** Uniform in [0, 1) for (relay, namespace, kind, week). */
    private fun prf(need: CapabilityNeed, week: Long): Double {
        val ns = need.namespace.toByteArray()
        val input = ByteBuffer.allocate(8 + ns.size + 1 + 8)
            .putLong(need.relay.value).put(ns).put(if (need.kind == CapabilityKind.WRITE) 2 else 1).putLong(week).array()
        return random.prf(EntitlementRandom.DOMAIN_REDEEM, input)
    }

    override fun toString(): String = "RedeemPlanner"

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
