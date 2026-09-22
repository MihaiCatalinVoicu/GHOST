package org.ghost.app

import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.network.EntitlementCrypto
import org.ghost.network.OnionAddress
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncDatabase

/**
 * The DM layer's ES slot table (Phase 9 design §5.2, §13.1 `EsSlots`; slice S12): for an ISO week,
 * each slot the **accepted** Entitlement Schedule lists as valid, with the active relay directory
 * entry that serves it and that relay's operator.
 *
 * > `:app` wires this to the schedule summary the entitlement engine already holds, exactly as it
 * > wires the activation hook in the other direction (§13.4). — `EsSlots`
 *
 * **Why the accepted schedule and not the embedded one.** The entitlement engine accepts the
 * built-in schedule against the one this database remembered (ES rule 5) and goes inert on a
 * conflict. A replaced schedule is the supply-chain signal rule 5 exists for, and a DM layer that
 * kept routing by it would send deposits and registrations to the relays of the schedule the rest
 * of the app refused. So [schedule] answers the accepted summary's slots or nothing, and nothing
 * means an empty table: the owner steps then report `NO_RELAYS` and change nothing (§5.2).
 *
 * **Why it reads the directory itself, and how.** Several steps resolve relay sets from inside
 * their own transaction (`SendStep`'s planning read is one), and a `SyncDatabase` transaction is
 * not reentrant. So the read runs through the transaction the calling thread already holds when
 * there is one — the executor below *is* that transaction's connection, and the thread holds the
 * database's lock — and through a short read transaction of its own otherwise. It never caches:
 * the directory is Phase 14's to change, and a cached relay id would outlive a retirement.
 *
 * **The slot→relay rule** is the inverse of the entitlement engine's `RedeemPlanner.slotsFor`
 * (Phase 8 design §19.22 point 3): the active entry listed under the slot's exact `onion:port`,
 * otherwise the single active entry on the slot's service key; a service key with several active
 * entries and no exact match serves the slot with none of them, and the slot is left out.
 */
internal class DirectoryEsSlots(
    private val database: SyncDatabase,
    /** The accepted schedule's slots, or null while it is not accepted (see the class note). */
    private val schedule: () -> List<EntitlementCrypto.Slot>?,
) : EsSlots {

    /**
     * The database's own connection. Read once, outside any transaction, when the stack is built;
     * used only while this thread holds the database's lock (see the class note).
     */
    private val executor: SqlExecutor = database.transaction { tx -> tx.sql }

    override fun slotsInWeek(week: Long): List<EsSlot> {
        val slots = schedule() ?: return emptyList()
        val relays = if (database.inTransaction) {
            activeRelays(executor)
        } else {
            database.transaction { tx -> activeRelays(tx.sql) }
        }
        return map(slots, week, relays)
    }

    /** One active relay directory row. Never shows the address or the operator (T3). */
    class Relay(val id: RelayId, val address: OnionAddress, operatorId: ByteArray) {
        private val operator = operatorId.copyOf()
        val operatorId: ByteArray get() = operator.copyOf()

        override fun toString(): String = "Relay(redacted)"
    }

    override fun toString(): String = "DirectoryEsSlots"

    companion object {
        /** The active rows of `relay_directory` (Phase 7 schema v2), in relay id order. */
        fun activeRelays(sql: SqlExecutor): List<Relay> {
            val out = ArrayList<Relay>()
            sql.query(
                "SELECT relay_id, onion_address, operator_id FROM relay_directory WHERE state = 'active' ORDER BY relay_id",
            ) { row -> out += Relay(RelayId(row.long(0)), OnionAddress.parse(row.string(1)), row.blob(2)) }
            return out
        }

        /** The slot table of [week]: see the class note for the rule. Ordered by slot number. */
        fun map(slots: List<EntitlementCrypto.Slot>, week: Long, relays: List<Relay>): List<EsSlot> {
            val out = ArrayList<EsSlot>()
            for (slot in slots.filter { it.validIn(week) }.sortedBy { it.slot }) {
                val exact = relays.filter { it.address == slot.onion }
                val chosen = when {
                    exact.size == 1 -> exact.single()
                    exact.isEmpty() -> relays.filter { it.address.host == slot.onion.host }.singleOrNull()
                    else -> null
                } ?: continue
                if (out.any { it.slot == slot.slot }) continue
                out += EsSlot(slot.slot, chosen.id, chosen.operatorId)
            }
            return out
        }
    }
}
