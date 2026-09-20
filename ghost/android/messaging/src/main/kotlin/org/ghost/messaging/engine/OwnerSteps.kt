package org.ghost.messaging.engine

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.DmSessions
import org.ghost.crypto.bridge.RelaySets
import org.ghost.identity.ZBase32
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.KeyWrapper
import org.ghost.messaging.store.OwnerStore
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.InstalledCapability
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket

/**
 * The owner-side transactions of Phase 9 design §7.2: **ACTIVATE**, **OWNER-WEEK**, **KEEPER** and
 * **REGROWS**, and the owner's own card (`myCard`, §13.2).
 *
 * Each public method here is exactly **one** `SyncDatabase.transaction`, as §7.2's first sentence
 * requires, and each is **idempotent against re-execution after a crash** by the guard §7.2's last
 * sentence names for it:
 *
 *  - ACTIVATE **per identity**: it does nothing when a `dm_self` row exists. §21.12 point 2 makes
 *    it resumable from every actor start and database open for the same reason, which is what
 *    covers a crash between the identity's creation in `:entitlement` and this commit.
 *  - OWNER-WEEK **per week**: `UPDATE dm_self SET bundle_week = w WHERE bundle_week IS NULL OR
 *    bundle_week < w` is the guard, and only the pass whose update changed the row goes on to
 *    create a generation and enqueue a bundle.
 *  - KEEPER **puts only a differing token**: a credential already installed, usable and not inside
 *    its refresh window is left alone, so a pass costs no capability generation and re-arms no
 *    parked delivery.
 *  - REGROWS **inserts only missing rows**: `Registrations.request` is idempotent on
 *    (relay, namespace, period, kind) and refuses a second verifier for a row that exists.
 *
 * **Timing (§21.9 rule 1, T31, mutants PM-11 and PM-30).** All four are *time-triggered* steps:
 * they run from the actor timer, from a database open and from a relay session start, and never
 * from an `INBOX` hint or a user send. Nothing about contacts, fetches or messages may enter the
 * moment a bundle is stored or a registration is made — which is why [ownerWeek] takes the week's
 * publication offset from the card (a fixed value per card, §5.4) and not from "the first wake
 * after something happened".
 *
 * **`bundle_rank` (§5.3, mutant PM-35).** The rank must not be derivable from the sealing time.
 * OWNER-WEEK publishes at rank **0**; an ACTIVATE or restore publication uses **1**, the "or 1 if
 * none" branch of §5.3. See the note on [activate] for the branch S6 could not build.
 *
 * **No network, ever.** Nothing here opens a transport: `Outbox.enqueue` records an operation the
 * sync engine sends later, and `Capabilities.put` stores a credential the owner minted itself
 * (gate G-DM1, G-DM2).
 */
class OwnerSteps(
    private val database: SyncDatabase,
    private val sync: SyncPorts,
    private val crypto: DmCrypto,
    private val clock: DmClock,
    private val random: DmRandom,
    private val keyWrapper: KeyWrapper,
    private val esSlots: EsSlots,
    private val cardIndex: Int = 0,
) {
    private val store = OwnerStore()

    /** What this module needs from `:sync` (design §13.3), gathered so tests can supply fakes. */
    class SyncPorts(
        val namespaces: org.ghost.sync.api.Namespaces,
        val capabilities: org.ghost.sync.api.Capabilities,
        val registrations: org.ghost.sync.api.Registrations,
        val outbox: org.ghost.sync.api.Outbox,
    )

    /** What a step did. Counts and enums only, never a time or a key (T3, §13.2 `status`). */
    enum class Result {
        /** The step ran and changed something. */
        DONE,

        /** The step's guard held: nothing to do, and nothing was written. */
        UNCHANGED,

        /** The DM context is closed or the native library is missing (§13.2). */
        CRYPTO_UNAVAILABLE,

        /** ACTIVATE has not run yet, so there is no identity to act for. */
        NOT_ACTIVATED,

        /** The week's ES slot table yields no relay set; the step made no change (§5.2). */
        NO_RELAYS,
    }

    /** The owner's own card and link, before the facade's value type wraps it (§3.3). */
    class OwnCardExport(val card: ByteArray, val link: String) {
        /** Never shows the card: it is a bearer secret for "may message me" (§3.3). */
        override fun toString(): String = "OwnCardExport(redacted)"
    }

    // ---------------------------------------------------------------- myCard

    /**
     * The 131-byte contact card v2 and its `ghost://contact/` link (§3.3). No network, no
     * transaction, no state: the card is a pure function of the seed and the card index, so a
     * restored device shows the same card and every contact keeps working.
     *
     * Null when the DM context is closed (`CRYPTO_UNAVAILABLE` at the facade).
     */
    fun myCard(): OwnCardExport? {
        val own = ownCard() ?: return null
        return OwnCardExport(own.card, CARD_LINK_PREFIX + ZBase32.encode(own.card))
    }

    // --------------------------------------------------------------- ACTIVATE

    /**
     * **ACTIVATE** (§7.2, §21.12 point 2): the `:entitlement` K20 hook, an actor start, or a
     * database open.
     *
     * Writes `dm_self` (with `state_key_wrapped` and a fresh `content_key`), the two own
     * namespaces, registers them with `:sync`, and creates the first bundle generation and its
     * bundle. [restored] is the restore variant: it also sets `accept_after_minute` to this
     * minute, so content authored before the restore is refused at `RECV` R9 — `dm_seen` and the
     * pair keys are gone, so it could not be deduplicated (§7.6 "Restore").
     *
     * **Idempotent per identity:** a `dm_self` row already present means a previous ACTIVATE
     * committed, and this returns [Result.UNCHANGED] without touching anything. A crash anywhere
     * inside leaves no row and the next start runs it again.
     *
     * **Deferred (recorded in §22.11).** §5.3's off-schedule rank rule is
     * `1 + max(rank)` over the valid bundles of weeks `w−1 … w+1` that the device **lists in its
     * own `P_0`**. That list is a relay read, which cannot happen inside this transaction and
     * which has no read path before S7's `BUNDLE` step; S6 therefore takes §5.3's own "or 1 if
     * none" branch. It is right whenever at most one off-schedule publication happens in a week —
     * an activation, or a restore after a device that published at rank 0 — and wrong only for a
     * second off-schedule publication inside one week, where two bundles of equal rank are ordered
     * by the smaller blob hash instead of by recency.
     */
    fun activate(restored: Boolean): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val stateKeyWrapped = crypto.stateKeyWrapped() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        val inboxSlots = slotsOrEmpty(week)
        if (inboxSlots.isEmpty()) return Result.NO_RELAYS

        val contentKey = random.bytes(32)
        val contentKeyWrapped = try {
            keyWrapper.wrap(contentKey)
        } finally {
            contentKey.fill(0)
        }
        val seenKey = random.bytes(32)

        return database.transaction { tx ->
            if (store.self(tx.sql) != null) return@transaction Result.UNCHANGED
            store.insertSelf(
                tx = tx,
                cardIndex = cardIndex,
                seenKey = seenKey,
                contentKeyWrapped = contentKeyWrapped,
                stateKeyWrapped = stateKeyWrapped,
                expiryClockMinute = DmTime.floorMinute(now),
                acceptAfterMinute = if (restored) DmTime.floorMinute(now) else null,
            )
            registerOwnNamespaces(tx, own, inboxSlots)
            // The week is claimed here too, not only at OWNER-WEEK: an activation publishes a
            // bundle for week w, so a time-triggered pass a minute later must not rotate the
            // generation again. `bundle_week` is the one guard both steps share (§5.4).
            check(store.claimBundleWeek(tx, week)) { "a fresh dm_self row cannot already hold a week" }
            // The first generation is an off-schedule publication: rank 1 (§5.3).
            publishBundle(tx, week = week, rank = 1, now = now, bundleNamespace = own.bundleNamespace)
            Result.DONE
        }
    }

    // ------------------------------------------------------------- OWNER-WEEK

    /**
     * **OWNER-WEEK** (§7.2, §5.4): the first time-triggered pass at or after `t_pub(w)`.
     *
     * Rotates the generation — a new `olm_prekey_gen` row, the previous one superseded today with
     * `delete_after_day = superseded_day + 91` — moves `dm_self.bundle_week`, and enqueues the
     * week's bundle at rank 0 with `TtlBucket.DAYS_30` and deadline `start(w + 2)`.
     *
     * Before `t_pub(w)` it does nothing at all, which is the whole of PM-11 and PM-30: the minute
     * is a fixed function of the card, so a card holder that deposits a probe during the owner's
     * session sees no publication follow it.
     *
     * A missed week publishes at the next time-triggered pass (§5.4), which falls out of the guard:
     * `bundle_week < w` holds for every week after the last published one.
     */
    fun ownerWeek(): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        if (now < publicationMinute(week, own.publicationOffsetSeconds)) return Result.UNCHANGED

        return database.transaction { tx ->
            store.self(tx.sql) ?: return@transaction Result.NOT_ACTIVATED
            if (!store.claimBundleWeek(tx, week)) return@transaction Result.UNCHANGED
            store.currentGeneration(tx.sql)?.let { previous ->
                store.supersede(tx, previous.genId, DmTime.day(now))
            }
            publishBundle(tx, week = week, rank = 0, now = now, bundleNamespace = own.bundleNamespace)
            Result.DONE
        }
    }

    // ----------------------------------------------------------------- KEEPER

    /**
     * **KEEPER** (§7.2, §4.8 "Credentials the owner installs", §5.2 "Slot-table changes"):
     * session start, week change, a `CAPABILITIES` hint.
     *
     * Two effects, both local:
     *  1. the owner's **own READ credential** v3 per relay of `X_0`'s set, with an 8-day expiry,
     *     refreshed when fewer than 7 days remain and re-put once when the installed one is
     *     rejected (§21.2). Reads then prefer it over the write capability (§13.3 item 7), so the
     *     relay sees the owner's read scope and not its write one;
     *  2. `setRelays` when a set changed. The owner, **as a reader**, keeps the union of the sets
     *     of weeks `w − 5 … w` (§5.2): a blob stored in week `w′` may live until `w′ + 6` weeks, so
     *     dropping an old relay from the set would abandon mail that is still there. The bundle
     *     namespace `P_0` is written, not read, so it takes the current week's set alone.
     *
     * Contacts' deposit and bundle-read credentials — the other half of §7.2's KEEPER row — are
     * **S7**: no contact exists before `addContact`, and their credentials are card-derived, which
     * needs `cardDerive` (§2.6 function 3, declared for S7). Recorded in §22.11.
     */
    fun keeper(): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        val bundleSet = relaySet(own.bundleNamespace, week) ?: return Result.NO_RELAYS
        val inboxUnion = readerUnion(own.inboxNamespace, week)
        if (inboxUnion.isEmpty()) return Result.NO_RELAYS

        return database.transaction { tx ->
            store.self(tx.sql) ?: return@transaction Result.NOT_ACTIVATED
            var changed = false
            val inboxNs = NamespaceId(own.inboxNamespace)
            val bundleNs = NamespaceId(own.bundleNamespace)

            // 1. Relay sets. The reader union for the inbox, the week's set for the bundle.
            sync.namespaces.setRelays(tx, inboxNs, inboxUnion.map { it.relay }.toSet())
            sync.namespaces.setRelays(tx, bundleNs, bundleSet.map { it.relay }.toSet())

            // 2. The own READ credential, on every relay the owner reads the inbox from — which is
            //    the union, not only this week's set: a relay that left the ES still holds blobs
            //    the owner has a valid read key for (§5.2).
            for (slot in inboxUnion) {
                if (!needsReadCredential(tx, slot.relay, inboxNs, now)) continue
                val secrets = crypto.ownSecrets(cardIndex, slot.slot)
                    ?: return@transaction Result.CRYPTO_UNAVAILABLE
                val credential = try {
                    CredentialV3.credential(CredentialV3.Kind.READ, slot.slot, own.inboxNamespace, secrets.read)
                } finally {
                    secrets.clear()
                }
                sync.capabilities.put(
                    tx,
                    slot.relay,
                    inboxNs,
                    CapabilityKind.READ,
                    credential,
                    DmTime.ceilHour(now) + READ_CREDENTIAL_LIFETIME_SECONDS,
                )
                changed = true
            }
            if (changed) Result.DONE else Result.UNCHANGED
        }
    }

    // ---------------------------------------------------------------- REGROWS

    /**
     * **REGROWS** (§7.2, §4.8 "Registrations the owner keeps"): session start, week change, a
     * `CAPABILITIES` hint, or a rejected own READ credential.
     *
     * For each own namespace, each relay of its current set and each kind it needs — `X_0`:
     * DEPOSIT and READ; `P_0`: FETCH (§22.8.7) — a `relay_key_registration` row must exist for
     * week `w`, whether or not a capability exists, so that a pending row is there to be served
     * (and, under Q31's default, counts as write work so the planner redeems for it), **and for
     * `c` and `c + 1` of the pair's usable write capability's week `c`** (graft G-3). See
     * [periodsFor] for why the `c + 1` row is what buys the offline tolerance of E-8.
     *
     * `Registrations.request` inserts only what is missing and refuses a **differing** verifier for
     * a row that already exists, which is §7.2's "REGROWS inserts only missing rows" in one call.
     * Stale rows are dropped with `forget`, whose bound is `week(now) − 1`: §4.8 deletes pending
     * rows older than that, and `done` rows outlive their `valid_until_hour` only briefly.
     *
     * **Healing (§4.8).** A **rejected** own READ credential for `(r, X_0)` means the relay lost
     * its `keys.redb` — registrations are soft state it re-creates (§4.6) — so every `done` row of
     * that pair from week `w` on goes back to pending in this same transaction, and reads fall
     * back to the write capability until they are done again (`:sync` already prefers a usable
     * READ credential and falls back, §13.3 item 7).
     *
     * The registration **call** itself is `:sync`'s work lane (§13.3 item 5), never this step: a
     * step that registered inline would put an RPC inside a transaction.
     */
    fun regrows(): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        val inboxSet = relaySet(own.inboxNamespace, week) ?: return Result.NO_RELAYS
        val bundleSet = relaySet(own.bundleNamespace, week) ?: return Result.NO_RELAYS

        return database.transaction { tx ->
            store.self(tx.sql) ?: return@transaction Result.NOT_ACTIVATED
            val inboxNs = NamespaceId(own.inboxNamespace)
            val bundleNs = NamespaceId(own.bundleNamespace)
            var changed = false

            for (slot in inboxSet) {
                val secrets = crypto.ownSecrets(cardIndex, slot.slot)
                    ?: return@transaction Result.CRYPTO_UNAVAILABLE
                try {
                    for (period in periodsFor(tx, slot.relay, inboxNs, week)) {
                        // DEPOSIT: card-derived, so every card holder presents one value (P-2).
                        changed = request(tx, slot, inboxNs, period, KeyKind.DEPOSIT, CredentialV3.Kind.DEPOSIT, own.inboxNamespace, secrets.deposit) || changed
                        // READ: seed-derived, the D11 key no card holder can compute (C-5).
                        changed = request(tx, slot, inboxNs, period, KeyKind.READ, CredentialV3.Kind.READ, own.inboxNamespace, secrets.read) || changed
                    }
                } finally {
                    secrets.clear()
                }
                changed = healIfReadRejected(tx, slot.relay, inboxNs, week) || changed
            }
            for (slot in bundleSet) {
                val secrets = crypto.ownSecrets(cardIndex, slot.slot)
                    ?: return@transaction Result.CRYPTO_UNAVAILABLE
                try {
                    for (period in periodsFor(tx, slot.relay, bundleNs, week)) {
                        changed = request(tx, slot, bundleNs, period, KeyKind.FETCH, CredentialV3.Kind.FETCH, own.bundleNamespace, secrets.fetch) || changed
                    }
                } finally {
                    secrets.clear()
                }
            }
            // Rows of weeks before `w - 1` can no longer be served: §4.8 deletes a pending row once
            // `week < week(now) - 1`, because no capability the relay would accept still names it.
            for (slot in inboxSet) {
                changed = sync.registrations.forget(tx, slot.relay, inboxNs, week - 1) > 0 || changed
            }
            for (slot in bundleSet) {
                changed = sync.registrations.forget(tx, slot.relay, bundleNs, week - 1) > 0 || changed
            }
            if (changed) Result.DONE else Result.UNCHANGED
        }
    }

    // ------------------------------------------------------------- internals

    private fun ownCard(): DmSessions.OwnCard? = crypto.ownCard(cardIndex)

    /** `t_pub(w) = start(w) + offset`, already floored to the minute on the native side (§5.4). */
    private fun publicationMinute(week: Long, offsetSeconds: Long): Long =
        DmTime.weekStart(week) + offsetSeconds

    private fun slotsOrEmpty(week: Long): List<EsSlot> = esSlots.slotsInWeek(week)

    /** `set(ns, w)` over the week's ES slots, or null when the week offers none (§5.2). */
    private fun relaySet(namespace: ByteArray, week: Long): List<EsSlot>? {
        val slots = slotsOrEmpty(week)
        if (slots.isEmpty()) return null
        val chosen = RelaySets.forNamespace(namespace, slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) })
        if (chosen.isEmpty()) return null
        return chosen.map { picked -> slots.first { it.slot == picked.slot } }
    }

    /**
     * The reader's union `⋃ set(ns, w′)` over `w′ ∈ [w − 5, w]` (§5.2), deduplicated by relay.
     * A week whose slot table is unknown contributes nothing, which is the right failure: a set
     * that cannot be computed must not silently shrink the union.
     */
    private fun readerUnion(namespace: ByteArray, week: Long): List<EsSlot> {
        val out = LinkedHashMap<Long, EsSlot>()
        for (w in (week - RELAY_UNION_WEEKS)..week) {
            relaySet(namespace, w)?.forEach { out.putIfAbsent(it.relay.value, it) }
        }
        return out.values.toList()
    }

    /**
     * True when the READ credential of the pair is missing, rejected, or inside its refresh window
     * — "refreshed when fewer than 7 days remain" (§4.8). An installed, usable credential with
     * more than that left is left exactly as it is, which is §7.2's "KEEPER puts only a differing
     * token": a re-put would bump the capability generation and re-arm parked deliveries for
     * nothing.
     */
    private fun needsReadCredential(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, now: Long): Boolean {
        val installed = sync.capabilities.installed(tx, relay, ns, CapabilityKind.READ) ?: return true
        if (installed.state != InstalledCapability.State.USABLE) return true
        val expires = installed.expiresHour ?: return false
        return expires - now < READ_CREDENTIAL_REFRESH_SECONDS
    }

    /**
     * The periods a pair must hold rows for (§4.8, graft G-3): **`week(now)` always**, whether or
     * not a capability exists — so a pending row is there to be served, and under Q31's default
     * counts as write work that makes the planner redeem — **and `c`, `c + 1` for the week `c` of
     * the pair's usable write capability**.
     *
     * The `c + 1` row is what buys the offline tolerance of E-8: an owner online in week `w`
     * registers `{w, w + 1}`, so a sender's deposits keep succeeding until `start(c + 3) + 1 h`,
     * about two to three weeks of absence. Without it the registration would lapse a week sooner
     * and the sender, which has no week choice and no fallback (§21.2), would simply be refused.
     *
     * `c` comes from the capability's **declared expiry**, not from the clock: a redeemed
     * capability of week `c` expires at `start(c + 1) + 1 h`, and §4.4 point 3 has the relay judge
     * the period the same way, so client and relay agree without either reading the other's clock.
     * A capability whose expiry is unknown names no week and contributes nothing.
     */
    private fun periodsFor(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, week: Long): List<Long> {
        val periods = linkedSetOf(week)
        val write = sync.capabilities.installed(tx, relay, ns, CapabilityKind.WRITE)
        if (write != null && write.state == InstalledCapability.State.USABLE) {
            write.expiresHour?.let { expiry ->
                val c = DmTime.week(expiry - DmTime.HOUR - 1)
                periods += c
                periods += c + 1
            }
        }
        // A period before `w - 1` is one `forget` deletes in this same pass; requesting it would
        // insert a row this step then removes, and would report a change that is not one.
        return periods.filter { it >= week - 1 }
    }

    /**
     * §4.8's healing rule. A **rejected** own READ credential is the signal that the relay lost
     * its `keys.redb` (§4.6: registrations are soft state, and losing the file is healed by the
     * owners within a session), so every `done` row of that pair from this week on returns to
     * pending and is registered again.
     */
    private fun healIfReadRejected(tx: SyncTransaction, relay: RelayId, ns: NamespaceId, week: Long): Boolean {
        val installed = sync.capabilities.installed(tx, relay, ns, CapabilityKind.READ) ?: return false
        if (installed.state != InstalledCapability.State.REJECTED) return false
        return sync.registrations.rearm(tx, relay, ns, week) > 0
    }

    /**
     * One `relay_key_registration` row. The **verifier** is what the row carries and what the
     * relay stores; the secret never leaves this frame and is the caller's to zeroise.
     */
    private fun request(
        tx: SyncTransaction,
        slot: EsSlot,
        ns: NamespaceId,
        week: Long,
        keyKind: KeyKind,
        credentialKind: CredentialV3.Kind,
        namespaceBytes: ByteArray,
        secret: ByteArray,
    ): Boolean {
        val verifier = CredentialV3.verifier(credentialKind, slot.slot, namespaceBytes, secret)
        return sync.registrations.request(tx, slot.relay, ns, week, keyKind, verifier)
    }

    private fun registerOwnNamespaces(tx: SyncTransaction, own: DmSessions.OwnCard, slots: List<EsSlot>) {
        val inbox = own.inboxNamespace
        val bundle = own.bundleNamespace
        store.putOwnNamespace(tx, inbox, OwnerStore.ROLE_INBOX, cardIndex)
        store.putOwnNamespace(tx, bundle, OwnerStore.ROLE_BUNDLE, cardIndex)
        val inboxSet = RelaySets.forNamespace(inbox, slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) })
        val bundleSet = RelaySets.forNamespace(bundle, slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) })
        // `X_0` listens (it is the inbox); `P_0` does not (the owner writes bundles and verifies
        // them with `check`, §5.1). Both are REDEEM: they are the owner's own namespaces, the only
        // two DM namespaces a token is ever spent on (§4.8 token accounting).
        sync.namespaces.register(
            tx, NamespaceId(inbox), Consumer.DM, inboxSet.map { RelayId(it.relay) }.toSet(),
            listen = true,
        )
        sync.namespaces.register(
            tx, NamespaceId(bundle), Consumer.PREKEYS, bundleSet.map { RelayId(it.relay) }.toSet(),
            listen = false,
        )
    }

    /**
     * Creates a generation, seals its bundle and enqueues it (§5.3, §5.4).
     *
     * TTL `DAYS_30` and deadline `start(w + 2)`: a bundle is useless once its validity ends, so
     * the operation must not outlive it. `gen_id` is drawn random and distinct from every retained
     * generation (§3.1): a repeat would collide with the primary key and, worse, would let a
     * fetcher's `olm_prekey_used` tuple of an old generation refuse a new first flight.
     */
    private fun publishBundle(
        tx: SyncTransaction,
        week: Long,
        rank: Int,
        now: Long,
        bundleNamespace: ByteArray,
    ) {
        val used = store.generationIds(tx.sql)
        var genId = random.u32()
        var attempts = 0
        while (genId in used) {
            genId = random.u32()
            if (++attempts > GEN_ID_ATTEMPTS) throw IllegalStateException("no free generation id")
        }
        val generation = crypto.bundleCreate(cardIndex, week, rank, genId.toInt())
            ?: throw IllegalStateException("bundleCreate failed inside ACTIVATE or OWNER-WEEK")
        store.insertGeneration(tx, genId, week, generation.fallbackPublic, generation.secretsEnv)
        val operationId = random.bytes(OperationId.SIZE)
        val deadlineHour = DmTime.floorHour(DmTime.weekStart(week + 2))
        store.insertBundleOp(tx, operationId, week, generation.blob, deadlineHour)
        try {
            sync.outbox.enqueue(
                tx,
                OutboundBlob(
                    OperationId(operationId),
                    NamespaceId(bundleNamespace),
                    generation.blob,
                    TtlBucket.DAYS_30,
                    deadlineEpochSeconds = DmTime.weekStart(week + 2),
                ),
            )
        } catch (e: InsufficientReplicasException) {
            // ADR-11: fewer than two operators this week. The whole transaction rolls back, so the
            // week is not claimed and the next pass tries again with a fresh set (§5.2).
            throw e
        }
    }

    companion object {
        /** `ghost://contact/` (§3.3). */
        const val CARD_LINK_PREFIX: String = "ghost://contact/"

        /** The READ credential's lifetime, 8 days (§4.8). */
        const val READ_CREDENTIAL_LIFETIME_SECONDS: Long = 8 * DmTime.DAY

        /** Refreshed when fewer than 7 days remain (§4.8). */
        const val READ_CREDENTIAL_REFRESH_SECONDS: Long = 7 * DmTime.DAY

        /** The reader keeps the union of the sets of `w − 5 … w` (§5.2). */
        const val RELAY_UNION_WEEKS: Long = 5

        private const val GEN_ID_ATTEMPTS = 64
    }
}
