package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.store.ContactStore
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncDatabase

/**
 * The contact half of **KEEPER** (Phase 9 design §7.2's KEEPER row, §4.8, §21.2 point 7;
 * deferred to S7 by §22.11 item 7).
 *
 * > `KEEPER` … contacts' deposit and bundle read credentials per relay slot, refreshed before
 * > expiry, a refused one re-put at most once per session start (§21.2).
 *
 * The owner's own READ credential is [OwnerSteps.keeper]'s. This is the other side: one **deposit**
 * credential per (contact, relay slot), installed with an 8-day expiry and refreshed inside its
 * last 7 days, so a send never has to mint one on the critical path — SEND still ensures it,
 * because the first send to a contact happens before any KEEPER pass has seen it (§7.3 S7).
 *
 * **Why the credential is static per (card, relay slot), and what that buys (§21.2, P-2).** It
 * carries no week and no MAC; its authority is the verifier the recipient registered. So every
 * depositor of one inbox sends **identical bytes** at one relay, `capability_scope` is one value
 * per (relay, namespace, kind) across every sender and every week, and a relay cannot partition
 * an inbox by sender — which is what "no sender field, in substance" means.
 *
 * **The bound on a re-put of a refused credential** (§21.2 point 7, mutant MC-15). A relay that
 * refuses a deposit credential leaves the row `rejected`, and `Capabilities.put` sets it back to
 * `usable` while bumping the generation and re-arming every parked delivery. Re-putting on every
 * hint would be a retry loop the relay controls, so this step re-puts a refused credential at
 * most **once per pass**, and a pass runs at a session start, a week change or a `CAPABILITIES`
 * hint (§7.2's KEEPER triggers) — never on an inbound blob (T28).
 *
 * **The bundle fetch credential is not here**, and §7.2's KEEPER row mentions one. §4.8 gives the
 * owner's `P_0` a FETCH registration; a **contact's** `P_c` credential is minted by `EST-START`,
 * for that attempt window, and this step never renews it — a credential this step kept fresh
 * between establishments would be a standing read scope for a namespace the device is not
 * listening to, which is the opposite of what L7-D6 bounds.
 *
 * What it does **not** mean is that the credential is gone between establishments, and an earlier
 * version of this comment claimed it was ("removed with the namespace at `EST-END`"). On the
 * success path there is no `EST-END`: `EST-READY` sets `establishment = ready` and
 * `setListening(P_c, false)` and calls no `Namespaces.remove`, so a `ready` contact keeps its
 * `P_c` registration and the 8-day READ credential `EST-START` installed until it lapses. §21.7
 * point 4 does not remove it either, so the code follows the design — but the reason this step
 * omits the credential is the one above, not a removal that happens somewhere else.
 */
internal class ContactKeeper(
    private val database: SyncDatabase,
    private val sync: DmSyncPorts,
    private val material: ContactMaterial,
    private val relays: RelaySetResolver,
    private val clock: DmClock,
    private val contexts: SelfContexts,
) {
    private val contacts = ContactStore()

    /** What the pass did; counts and enums only (T3). */
    enum class Result {
        /** At least one credential was installed or refreshed. */
        DONE,

        /** Every contact's credentials are installed, usable and not near expiry. */
        UNCHANGED,

        /** The DM context is closed or the native library is missing. */
        CRYPTO_UNAVAILABLE,
    }

    /**
     * One KEEPER pass over the contacts.
     *
     * Every credential is minted **before** its transaction opens, for the reason §22.11 item 17
     * gives: a `CRYPTO_UNAVAILABLE` decided inside one would be a normal return, and a normal
     * return commits what the earlier iterations already wrote while reporting an error.
     */
    fun run(): Result {
        contexts.get() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        val rows = database.transaction { tx ->
            contacts.contacts(tx.sql).filter { sendable(it.trust) }
        }
        var changed = false
        for (contact in rows) {
            when (install(contact, week, now)) {
                Result.DONE -> changed = true
                Result.CRYPTO_UNAVAILABLE -> return Result.CRYPTO_UNAVAILABLE
                Result.UNCHANGED -> Unit
            }
        }
        return if (changed) Result.DONE else Result.UNCHANGED
    }

    @Suppress("ReturnCount")
    private fun install(contact: ContactStore.ContactRow, week: Long, now: Long): Result {
        val card = material.card(contact) ?: return Result.UNCHANGED
        val namespaces = material.namespaces(card) ?: return Result.CRYPTO_UNAVAILABLE
        val set = relays.forNamespace(namespaces.inbox, week) ?: return Result.UNCHANGED
        val inboxNs = NamespaceId(namespaces.inbox)

        val needed = database.transaction { tx ->
            set.filter { slot ->
                when (
                    val installed =
                        sync.capabilities.installed(tx, slot.relay, inboxNs, CapabilityKind.WRITE)
                ) {
                    null -> true
                    else -> when (installed.state) {
                        // Refused: re-put, at most once per pass (§21.2 point 7, mutant MC-15).
                        InstalledCapability.State.REJECTED -> true
                        // Exhausted is the recipient's quota, not this device's credential: a new
                        // generation of the same bytes would not buy anything (§4.5).
                        InstalledCapability.State.EXHAUSTED -> false
                        InstalledCapability.State.USABLE ->
                            (installed.expiresHour ?: Long.MAX_VALUE) - now <
                                SendStep.CREDENTIAL_REFRESH_SECONDS
                    }
                }
            }
        }
        if (needed.isEmpty()) return Result.UNCHANGED

        val credentials = LinkedHashMap<Long, ByteArray>()
        for (slot in needed) {
            val derived = material.fromCard(card, slot.slot) ?: return Result.CRYPTO_UNAVAILABLE
            credentials[slot.relay.value] = try {
                CredentialV3.credential(
                    CredentialV3.Kind.DEPOSIT,
                    slot.slot,
                    namespaces.inbox,
                    derived.deposit,
                )
            } finally {
                derived.clearSecrets()
            }
        }

        return database.transaction { tx ->
            // A capability is scoped to a **registered** namespace (`Capabilities.put` refuses an
            // unknown one), and this pass may be the first thing that ever touches a contact's
            // inbox: KEEPER runs at a session start, before any send. So the write-only
            // registration is made here exactly as SEND makes it (§7.3 step S7, §13.3 item 3) —
            // same arguments, so whichever step runs first the row is the same and the other is a
            // no-op. `listen = false`: this device deposits into `X_c`, it never reads it.
            sync.namespaces.register(
                tx = tx,
                namespace = inboxNs,
                consumer = Consumer.DM,
                relays = set.map { it.relay }.toSet(),
                listen = false,
                sendDelay = SendDelay.DEFAULT,
                capabilitySource = CapabilitySource.LOCAL,
            )
            for (slot in needed) {
                sync.capabilities.put(
                    tx,
                    slot.relay,
                    inboxNs,
                    CapabilityKind.WRITE,
                    credentials.getValue(slot.relay.value),
                    DmTime.ceilHour(now) + SendStep.CREDENTIAL_LIFETIME_SECONDS,
                )
            }
            Result.DONE
        }
    }

    /** A credential is kept only for a contact this device may still write to (§8.2 rule 6). */
    private fun sendable(trust: ContactStore.Trust): Boolean =
        trust == ContactStore.Trust.UNVERIFIED ||
            trust == ContactStore.Trust.VERIFIED ||
            // A `changed` contact still has parked deliveries of messages sent before the change,
            // and §8.3 blocks **sending**, not the ops already enqueued (CS-5 is about ciphertext
            // produced, and none is produced here).
            trust == ContactStore.Trust.CHANGED
}
