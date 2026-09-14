package org.ghost.entitlement.engine

import org.ghost.entitlement.api.RestoreResult
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.SyncTables
import org.ghost.identity.RootEntropy
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The drop scan after an identity restore (design §8.4, §19.26). `next_invite_index` is not
 * recoverable from the seed, so a restored identity listens to the drops of invite indices 0..7 for
 * 5 weeks (`ent_state.restore_scan_until_day`), then stops; credits sent to other drops are lost
 * (E11). New invites continue at index 8.
 *
 * A scanned drop is an `ent_invite` row of an invite that may have been created before the restore:
 * state `created`, payload unknown (NULL), its drop namespace re-derived from the root entropy (the
 * drop key too, when a blob is opened; neither is stored), listened until the scan's end. The receive
 * path, the refresh flow of a received credit and the invite GC then treat it as any invite. Its drop
 * slots are unknown, so it is listened on the active directory relays of every ES slot valid in some
 * week of the scan, a superset of the three relays its invitee writes to at `t_drop` (§19.12).
 *
 * Crash safety (§11.5): [restore] records the scan as owed before the identity is stored, and the
 * install derives the namespaces from the stored identity; a process that finds the scan owed and an
 * identity installs it once ([resume]: at the next foreground, relay session or invite creation).
 * A crash anywhere in [restore] thus ends with the scan installed, or with no identity (the user
 * restores again); an identity created by another path after such a crash scans its own drops. The
 * install is idempotent: rows of this root are kept (a scanned one listened on the current relays and
 * until the current end), rows of another root (an earlier identity of this database) are replaced.
 */
internal class RestoreScan(private val c: EngineContext) {

    /** The install ran, or nothing was owed, in this process (one instance per open database). */
    private val settled = AtomicBoolean()

    fun restore(mnemonic: List<String>, now: Long): RestoreResult {
        if (c.identity.hasIdentity() || c.trialSteps.onboardingPending()) return RestoreResult.ALREADY_ACTIVE
        if (!wellFormed(mnemonic)) return RestoreResult.REFUSED_MNEMONIC
        c.tx { tx -> c.state.oweRestoreScan(tx, Grid.day(now) + SCAN_DAYS) }
        c.identity.restore(mnemonic)
        install(now)
        return RestoreResult.RESTORED
    }

    private fun wellFormed(mnemonic: List<String>): Boolean = try {
        RootEntropy.fromMnemonic(mnemonic).zeroize()
        true
    } catch (e: IllegalArgumentException) {
        false
    }

    /** Installs a scan a crash left owed, once per process; cheap once settled. */
    fun resume(now: Long) {
        if (settled.get()) return
        val owed = c.tx { tx -> c.state.read(tx)?.restoreScanUntilDay }
        if (owed == null || owed <= Grid.day(now)) {
            settled.set(true)
            return
        }
        if (c.identity.hasIdentity()) install(now)
    }

    private fun install(now: Long) {
        val namespaces = List(SCANNED_INVITES) { c.identity.inviteKeys(it).dropNamespace }
        c.tx { tx -> install(tx, namespaces, now) }
        settled.set(true)
    }

    private fun install(tx: SyncTransaction, namespaces: List<ByteArray>, now: Long) {
        val until = c.state.read(tx)?.restoreScanUntilDay ?: return
        if (until <= Grid.day(now)) return
        val relays = relays(tx, now, until)
        namespaces.forEachIndexed { index, ns ->
            val row = c.invites.get(tx, index)
            when {
                row == null -> add(tx, index, ns, relays, until)
                !row.dropNamespace().contentEquals(ns) -> {
                    // A row of another root (an earlier identity of this database): its drop is not ours.
                    if (row.state != InviteStore.CLOSED) {
                        c.retireNamespace(tx, NamespaceId(row.dropNamespace()))
                        c.invites.close(tx, index)
                    }
                    c.invites.deleteClosed(tx, index)
                    add(tx, index, ns, relays, until)
                }
                row.state == InviteStore.CLOSED -> {
                    c.invites.deleteClosed(tx, index)
                    add(tx, index, ns, relays, until)
                }
                row.state == InviteStore.CREATED && row.payload() == null -> {
                    c.invites.extendScanned(tx, index, until)
                    listen(tx, ns, relays)
                }
                // A credited drop, or an invite this root created on this device: its own rules apply.
                else -> Unit
            }
        }
        c.state.reserveInviteIndices(tx, SCANNED_INVITES)
    }

    private fun add(tx: SyncTransaction, index: Int, ns: ByteArray, relays: Set<RelayId>, until: Long) {
        c.invites.insertScanned(tx, index, ns, until)
        c.sync.namespaces.register(tx, NamespaceId(ns), Consumer.IDENTITY, relays, listen = true)
    }

    /** A scanned drop listens on [relays] (the directory or the schedule may have changed since). */
    private fun listen(tx: SyncTransaction, ns: ByteArray, relays: Set<RelayId>) {
        val id = NamespaceId(ns)
        if (SyncTables.listenedRelays(tx, id) != relays) c.sync.namespaces.register(tx, id, Consumer.IDENTITY, relays, listen = true)
    }

    /**
     * The active directory relays of every ES slot valid in some week from now through the scan's last
     * listened day (`until − 1`): an invitee writes its drop blob to the relays of its three drop slots
     * in the week of its `t_drop`, and those slots were valid through the invite's listening end.
     */
    private fun relays(tx: SyncTransaction, now: Long, until: Long): Set<RelayId> {
        val weeks = Grid.week(now)..Grid.week(until * Grid.DAY - 1)
        val onions = c.summary.slots.filter { slot -> weeks.any { slot.validIn(it) } }.map { it.onion }.toSet()
        return SyncTables.relays(tx).filter { it.active && it.address in onions }.map { it.id }.toSet()
    }

    override fun toString(): String = "RestoreScan"

    companion object {
        /** Invite indices 0..7 are scanned (§8.4); new invites after a restore start at 8. */
        const val SCANNED_INVITES = 8

        /** 5 weeks. */
        const val SCAN_DAYS = 35L
    }
}
