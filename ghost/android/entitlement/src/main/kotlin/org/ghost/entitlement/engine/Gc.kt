package org.ghost.entitlement.engine

import org.ghost.entitlement.store.InviteStore
import org.ghost.sync.api.NamespaceId

/**
 * Garbage collection and retention (design §11.3, §11.4, §19.15): terminal purchase and claim rows
 * at `terminal_day + 7` (GC keys on `terminal_day` only; the terminal transaction already wiped every
 * secret and finer time); tokens out of their acceptance window (ACCESS weeks closed at
 * `start(p + 1) + 1 h` by both the device clock and the relay-facing estimate the redeem lane plans
 * with (§19.4 point 3), so neither a device clock ahead of the relays nor relays claiming a later time
 * delete a token the other side still accepts; INVITE epochs before `e_now − 1`, CREDIT epochs before `c_now − 4`); used
 * payout-address hashes at `until_day`; invites at `listen_until_day` (their drop namespace retired,
 * then the closed row deleted), the drops a restore scans included, and the restore scan itself at its
 * end, in the same pass (§8.4); a drop target never written by `until_day`; the payment-screen moment
 * once the longest hold (60 min) is over.
 */
internal class Gc(private val c: EngineContext) {

    fun runIfDue(now: Long) {
        if (c.memory.gcDue(c.clock.monotonicMillis())) run(now)
    }

    fun run(now: Long) {
        val today = Grid.day(now)
        val week = Grid.week(now)
        val lastClosedAccessWeek = minOf(Grid.week(now - Grid.HOUR), Grid.week(c.memory.clock.now(now) - Grid.HOUR)) - 1
        c.tx { tx ->
            c.purchases.deleteTerminal(tx, today)
            c.tokens.collect(tx, lastClosedAccessWeek, Grid.inviteEpoch(week) - 1, Grid.creditEpoch(week) - CREDIT_EPOCHS_KEPT)
            c.claims.deleteTerminal(tx, today)
            c.claims.deletePayoutUsed(tx, today)
            for (invite in c.invites.all(tx)) {
                when {
                    invite.state == InviteStore.CLOSED -> c.invites.deleteClosed(tx, invite.index)
                    invite.listenUntilDay <= today -> {
                        c.retireNamespace(tx, NamespaceId(invite.dropNamespace()))
                        c.invites.close(tx, invite.index)
                    }
                }
            }
            val target = c.invites.dropTarget(tx)
            if (target != null && target.state == InviteStore.WAITING && target.untilDay <= today) {
                c.retireNamespace(tx, NamespaceId(target.dropNamespace()))
                c.invites.deleteDropTarget(tx)
            }
            c.state.clearRestoreScanUpTo(tx, today)
            c.state.clearPaymentShownUpTo(tx, now - PAYMENT_HOLD_MAX_SECONDS)
        }
    }

    override fun toString(): String = "Gc"

    private companion object {
        const val CREDIT_EPOCHS_KEPT = 4L
        const val PAYMENT_HOLD_MAX_SECONDS = 60 * 60L
    }
}
