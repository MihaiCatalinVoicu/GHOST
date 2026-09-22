package org.ghost.messaging.engine

import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.OwnerStore
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncDatabase

/**
 * **`now_e`** — the expiry clock of Phase 9 design §10.3 and rule **R-T7**, in one place.
 *
 * > `now_e = max(floor_minute(wall), dm_self.expiry_clock_minute)`, and every sweep raises the
 * > stored half.
 *
 * A clock stepped backwards — by the user, by NTP, across a reboot — must never delay a deletion.
 * That is a property of the **number every deadline is compared against**, so it belongs to every
 * comparison of a `_minute` deadline and not to SWEEP alone: §21.10 point 6 says DISPLAY ignores
 * ids whose `delete_at_minute ≤ now_e`, §10.7 point 4's read filter hides a row the same way, and
 * §21.10 point 5 refuses a held message released past its own unread cap. Before the S9 review
 * every one of those read the raw wall clock, so a device whose clock had been moved back showed
 * — and re-armed — rows SWEEP had already decided were gone. The window is narrow and the rows
 * were still under SQLCipher, but it is the exact deviation R-T7 exists to close.
 *
 * **It is not cached.** The stored half lives in `dm_self`, which a wipe deletes and an ACTIVATE
 * rewrites, so a memo held across either would be a *future* minute applied to a new identity —
 * deleting its messages early. The read is one indexed single-row query and every caller already
 * holds or opens a transaction.
 *
 * **Two overloads, because both shapes of caller exist.** A step that is already inside its
 * transaction passes its `sql` and sees the value that transaction sees; a caller outside one gets
 * a transaction of its own. `SyncDatabase` refuses a nested transaction outright, so the two are
 * not interchangeable.
 */
internal class ExpiryClock(
    private val database: SyncDatabase,
    private val clock: DmClock,
) {
    private val owner = OwnerStore()

    /** `now_e` with a transaction of its own. Never call this from inside one. */
    fun nowMinute(): Long = database.transaction { tx -> nowMinute(tx.sql) }

    /** `now_e` from inside an open transaction. */
    fun nowMinute(sql: SqlExecutor): Long = DmTime.floorMinute(nowSeconds(sql))

    /**
     * The same clock, **unfloored**: `max(wall, dm_self.expiry_clock_minute)` in seconds.
     *
     * It is what a *delay* is measured from, and flooring first would be wrong in the unsafe
     * direction — `next − floor_minute(wall)` is up to 59 seconds longer than `next − wall`, so a
     * wake computed on the minute grid fires **after** its deadline. Flooring this value gives
     * [nowMinute] exactly, because the stored half is already on the grid.
     */
    fun nowSeconds(sql: SqlExecutor): Long {
        val wall = clock.nowEpochSeconds()
        val stored = owner.self(sql)?.expiryClockMinute
        return maxOf(wall, stored ?: wall)
    }

    /** [nowSeconds] with a transaction of its own. Never call this from inside one. */
    fun nowSeconds(): Long = database.transaction { tx -> nowSeconds(tx.sql) }
}
