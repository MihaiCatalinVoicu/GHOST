package org.ghost.entitlement.engine

import org.ghost.entitlement.api.RestoreResult
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.SyncTables
import org.ghost.entitlement.store.sha256
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
 * drop key too, when a blob is opened; neither is stored), listened until the scan's end. Its refresh
 * time is drawn as every drop's, 1–14 days after its listening (the scan) ends ([RefreshPlan.time],
 * §19.29), and re-drawn when a later restore extends the scan: every read precedes it. The receive path, the refresh flow of a received credit and the invite GC then treat it as any
 * invite. Its drop
 * slots are unknown, so it is listened on the active directory relays of every ES slot valid in some
 * week from one drop-blob lifetime before now through the scan's end: a superset of the three relays
 * its invitee wrote to at `t_drop` (§19.12) for every blob still stored at the install, and for every
 * blob written until the scan's end.
 *
 * The scan belongs to the restored root and to a trusted clock (§19.26 point 15). [restore] records it
 * as owed with a commitment to the restored root (`restore_scan_root`) and no end, reserves invite
 * indices 0..7, and only then stores the identity. The install runs from a relay session's tick, which
 * runs only while the sync engine trusts the device clock ([resume]), once per process: when the stored
 * identity is the restored root, one transaction fixes the end at that day + 35 and records the drops
 * from the identity's derivations; an identity of another root (a genesis after a crash) drops the owe
 * instead, and an invite activation drops it in its own transaction. A crash anywhere in [restore] thus
 * ends with the scan owed for the restored root (installed by the next trusted relay session) or with
 * no identity (the user restores again). The install is idempotent: rows of this root are kept (a
 * scanned one listened on the current relays), rows of another root (an earlier identity of this
 * database) are replaced.
 */
internal class RestoreScan(private val c: EngineContext) {

    /** The install ran, or nothing is owed, in this process (one instance per open database). */
    private val settled = AtomicBoolean()

    fun restore(mnemonic: List<String>): RestoreResult {
        if (c.identity.hasIdentity() || c.trialSteps.onboardingPending()) return RestoreResult.ALREADY_ACTIVE
        val root = rootOf(mnemonic) ?: return RestoreResult.REFUSED_MNEMONIC
        synchronized(this) {
            c.tx { tx ->
                c.state.oweRestoreScan(tx, root)
                // Now, not at the install: an invite created before the install never takes a scanned index.
                c.state.reserveInviteIndices(tx, SCANNED_INVITES)
            }
            settled.set(false)
        }
        c.identity.restore(mnemonic)
        return RestoreResult.RESTORED
    }

    /** The commitment to the root of [mnemonic], or null for words that are not a 24-word GHOST backup. */
    private fun rootOf(mnemonic: List<String>): ByteArray? {
        val root = try {
            RootEntropy.fromMnemonic(mnemonic)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return try {
            commitment(root.inviteDropNamespace(0))
        } finally {
            root.zeroize()
        }
    }

    /**
     * Installs an owed scan, or drops an owe of another root, once per process; cheap once settled.
     * Called only from a relay session's tick under a trusted clock, which fixes the scan's end.
     */
    @Synchronized
    fun resume(now: Long) {
        if (settled.get()) return
        val st = c.tx { tx -> c.state.read(tx) }
        val until = st?.restoreScanUntilDay
        if (st?.restoreScanRoot() == null || (until != null && until <= Grid.day(now))) {
            settled.set(true)
            return
        }
        if (!c.identity.hasIdentity()) return
        val namespaces = List(SCANNED_INVITES) { c.identity.inviteKeys(it).dropNamespace }
        c.tx { tx -> install(tx, namespaces, now) }
        settled.set(true)
    }

    private fun install(tx: SyncTransaction, namespaces: List<ByteArray>, now: Long) {
        val st = c.state.read(tx) ?: return
        val root = st.restoreScanRoot() ?: return
        if (!root.contentEquals(commitment(namespaces[0]))) {
            // The stored identity is not the restored root: its own drops 0..7 hold nothing to find.
            c.state.dropRestoreScan(tx)
            return
        }
        val today = Grid.day(now)
        val until = st.restoreScanUntilDay ?: (today + SCAN_DAYS).also { c.state.fixRestoreScanEnd(tx, it) }
        if (until <= today) return
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
                    if (row.listenUntilDay < until) {
                        c.invites.extendScanned(tx, index, until, RefreshPlan.time(until, c.random))
                    }
                    listen(tx, ns, relays)
                }
                // A credited drop, or an invite this root created on this device: its own rules apply.
                else -> Unit
            }
        }
    }

    private fun add(tx: SyncTransaction, index: Int, ns: ByteArray, relays: Set<RelayId>, until: Long) {
        c.invites.insertScanned(tx, index, ns, until, RefreshPlan.time(until, c.random))
        c.sync.namespaces.register(tx, NamespaceId(ns), Consumer.IDENTITY, relays, listen = true)
    }

    /** A scanned drop listens on [relays] (the directory or the schedule may have changed since). */
    private fun listen(tx: SyncTransaction, ns: ByteArray, relays: Set<RelayId>) {
        val id = NamespaceId(ns)
        if (SyncTables.listenedRelays(tx, id) != relays) c.sync.namespaces.register(tx, id, Consumer.IDENTITY, relays, listen = true)
    }

    /**
     * The active directory relays of every ES slot valid in some week from one drop-blob lifetime
     * ([DropSteps.BLOB_TTL]) before now through the scan's last listened day (`until − 1`): an invitee
     * writes its drop blob to the relays of its three drop slots in the week of its `t_drop`, and a
     * blob written in the lifetime before now is still stored there.
     */
    private fun relays(tx: SyncTransaction, now: Long, until: Long): Set<RelayId> {
        val weeks = Grid.week(now - DropSteps.BLOB_TTL.seconds)..Grid.week(until * Grid.DAY - 1)
        val onions = c.summary.slots.filter { slot -> weeks.any { slot.validIn(it) } }.map { it.onion }.toSet()
        return SyncTables.relays(tx).filter { it.active && it.address in onions }.map { it.id }.toSet()
    }

    override fun toString(): String = "RestoreScan"

    companion object {
        /** Invite indices 0..7 are scanned (§8.4); new invites after a restore start at 8. */
        const val SCANNED_INVITES = 8

        /** 5 weeks. */
        const val SCAN_DAYS = 35L

        private val ROOT_LABEL = "ghost/v1/restore-scan-root".toByteArray(Charsets.US_ASCII)

        /** `restore_scan_root`: binds an owed scan to one root, by the drop namespace of its invite 0. */
        private fun commitment(dropNamespace0: ByteArray): ByteArray = sha256(ROOT_LABEL, dropNamespace0)
    }
}
