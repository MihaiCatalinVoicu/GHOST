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
 *    its refresh window is left alone, so a pass costs no capability generation.
 *  - REGROWS **inserts only missing rows**: `Registrations.keep` is idempotent on
 *    (relay, namespace, period, kind), and replaces a row's verifier only when the relay's ES slot
 *    number — which the verifier binds — has changed under it (§5.2, §21.2 point 2).
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
     * **"The next start" is `DmActor.runPass`'s `resumeActivation`** (§21.12 point 2, wired by the
     * S8 review; it did not exist while this paragraph claimed it). It is what makes the two
     * no-write refusals above survivable: [Result.NO_RELAYS] — this week's ES slot table is empty,
     * which is the normal state of a fresh install for the minutes after a restore, before the
     * relay directory has synced — and [Result.CRYPTO_UNAVAILABLE]. Without it the K20 hook was
     * the only tap and a restore that hit either one left the identity mute for good.
     *
     * **"Per identity" is checked, not assumed (§22.11 item 11, S8).** `dm_self` carries no
     * identity column and nothing in it could: `seen_key`, `content_key_wrapped` and
     * `state_key_wrapped` are random. What does name the identity is `dm_own_namespace`, whose two
     * rows are HKDF outputs of `card_secret_0` — so a row set that does not match the namespaces
     * **this** context derives belongs to somebody else. A restore onto such a database is the one
     * case that has to act rather than report `UNCHANGED`: it would otherwise set no
     * `accept_after_minute`, publish no bundle and leave the restored identity mute while the old
     * identity's contacts, sessions and generations sat in the tables. Nothing on the device can
     * use any of it — the sessions are the lost device's, the pinned identities are its contacts'
     * views of *it*, and §8.6 lists contacts and cards among what a restore loses anyway — so the
     * DM tables are cleared and ACTIVATE runs for real. The two stale `:sync` namespaces become
     * `dm_orphan_namespace` rows, which is where §21.12 point 3 sends every namespace whose card
     * is gone.
     *
     * `RestoreScan.restore` refuses while `identity.hasIdentity()` and no path in the tree removes
     * an identity while keeping the DM tables, so this is **armed rather than exercised** on the
     * device; it is written because §22.11 item 11 assigned it here and because the alternative —
     * a silent `UNCHANGED` — is the failure mode nobody would see.
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
            if (store.self(tx.sql) != null) {
                if (!restored || ownNamespacesMatch(tx, own)) return@transaction Result.UNCHANGED
                clearForeignIdentity(tx)
            }
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
     * Before `t_pub(w)` it does nothing at all **while the owner's last bundle is still valid**,
     * which is the whole of PM-11 and PM-30: the minute is a fixed function of the card, so a card
     * holder that deposits a probe during the owner's session sees no publication follow it.
     *
     * A missed week publishes at the next time-triggered pass (§5.4), and that is [publicationDue],
     * not the week guard: an owner back online in week `w` whose newest bundle is of week `w − 2`
     * or older holds **no valid bundle** (§5.4 "Validity"), and waiting for `t_pub(w)` — up to
     * seven more days of it being online — would extend the two-week offline tolerance of L7-D10
     * and E-8 by a week of establishment failures. The due minute is `t_pub` of the first week the
     * owner did not publish, which is `t_pub(w)` itself whenever nothing was missed.
     *
     * Nothing about contacts, fetches or messages enters either half: the offset is the card's, and
     * the only state the decision reads is `dm_self.bundle_week` (T31).
     *
     * **What it does *not* do, and why** (§21.8 point 5, deferred in §22.12). The week guard is
     * claimed at *attempt* time, so a publication op that ends FAILED or INDETERMINATE costs the
     * owner the whole week: `bundle_published_week` records that the bundle never landed, and
     * nothing re-publishes it. §21.8 point 5's remedy is to "re-seal the current bundle (new salt,
     * same generation and `bundle_rank`)", and neither half of that is reachable from here.
     * `bundleCreate` is the only bundle function on the closed surface of §2.6 and it draws a
     * **fresh** generation, so the same generation cannot be re-sealed; and re-depositing the
     * identical bytes instead is refused by Phase 7's own `outbox_op UNIQUE (namespace_id,
     * blob_hash)` — "these bytes are already queued under another operation" — which is what makes
     * the *new salt* of the rule load-bearing rather than cosmetic. The fix is a new closed-list
     * function, which is a deliberate act the JNI gate exists to make deliberate, and it belongs
     * to a slice that opens that surface.
     */
    fun ownerWeek(): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)

        return database.transaction { tx ->
            val self = store.self(tx.sql) ?: return@transaction Result.NOT_ACTIVATED
            if (now < publicationDue(self.bundleWeek, week, own.publicationOffsetSeconds)) {
                return@transaction Result.UNCHANGED
            }
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
     *     refreshed when fewer than 7 days remain, and — when the installed one was refused —
     *     healed and re-put under the bound of [readCredentialAction] (§4.8, §21.2 point 8). Reads
     *     prefer a usable one over the write capability (§13.3 item 7), so the relay sees the
     *     owner's read scope and not its write one;
     *  2. `setRelays` when a set changed. The owner, **as a reader**, keeps the union of the sets
     *     of weeks `w − 5 … w` (§5.2): a blob stored in week `w′` may live until `w′ + 6` weeks, so
     *     dropping an old relay from the set would abandon mail that is still there. The bundle
     *     namespace `P_0` is written, not read, so it takes the current week's set alone.
     *
     * **Every credential is minted before the transaction opens.** A `CRYPTO_UNAVAILABLE` decided
     * inside it would be a normal return, and a normal return **commits** what the earlier loop
     * iterations already wrote — a `setRelays` and the credentials of the first relays — while
     * reporting an error. §7.2's "each step is exactly one transaction" means all or nothing, so
     * the closed context is found first and the transaction holds database work only.
     *
     * Contacts' deposit credentials — the other half of §7.2's KEEPER row — are [contactKeeper]'s,
     * added in S7 once `cardDerive` existed.
     */
    fun keeper(): Result {
        val own = ownCard() ?: return Result.CRYPTO_UNAVAILABLE
        val now = clock.nowEpochSeconds()
        val week = DmTime.week(now)
        val bundleSet = relaySet(own.bundleNamespace, week) ?: return Result.NO_RELAYS
        val inboxUnion = readerUnion(own.inboxNamespace, week)
        if (inboxUnion.isEmpty()) return Result.NO_RELAYS
        // Minted here, never inside the transaction: see the note above.
        val credentials = LinkedHashMap<Long, ByteArray>()
        for (slot in inboxUnion) {
            val secrets = crypto.ownSecrets(cardIndex, slot.slot) ?: return Result.CRYPTO_UNAVAILABLE
            credentials[slot.relay.value] = try {
                CredentialV3.credential(CredentialV3.Kind.READ, slot.slot, own.inboxNamespace, secrets.read)
            } finally {
                secrets.clear()
            }
        }

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
                when (readCredentialAction(tx, slot.relay, inboxNs, week, now)) {
                    ReadCredential.LEAVE -> continue
                    ReadCredential.HEAL_AND_PUT ->
                        changed = sync.registrations.rearm(tx, slot.relay, inboxNs, week) > 0 || changed
                    ReadCredential.PUT -> Unit
                }
                sync.capabilities.put(
                    tx,
                    slot.relay,
                    inboxNs,
                    CapabilityKind.READ,
                    credentials.getValue(slot.relay.value),
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
     * `Registrations.keep` inserts only what is missing, which is §7.2's "REGROWS inserts only
     * missing rows" in one call. It also **replaces** a row whose verifier is not the one this
     * slot yields any more: a verifier binds the relay's slot number (§21.2 point 2), a relay may
     * keep a namespace's set while moving to another of its slots (§5.2), and the rows of `c` and
     * `c + 1` below are of earlier weeks. `Registrations.request`'s "a registration keeps the
     * verifier it was created with" would then abort this whole transaction — the `forget` loop
     * included, so the offending rows would never be dropped — on every pass until the period
     * lapsed, taking the rest of the owner's maintenance with it.
     *
     * Stale rows are dropped with `forget`, whose bound is `week(now) − 1`: §4.8 deletes pending
     * rows older than that, and `done` rows outlive their `valid_until_hour` only briefly.
     *
     * **Healing (§4.8) is not here; it is [keeper]'s.** §4.8 states the rule under this step and
     * §21.2 point 8 under the owner's credential, and it has to live where the credential is
     * decided: `rejected` is a level and not an edge — it stays set until a re-put installs a new
     * generation — so a step that re-armed without re-putting would re-arm again at the next pass,
     * and would send the rows the work lane had just finished back to pending for ever. See
     * [readCredentialAction] for the rule as it is implemented. A `regrows()` triggered by a
     * rejected credential (§7.2 lists it) is still right to run: it keeps the rows that must exist,
     * and KEEPER's pass is what re-arms the ones that were lost.
     *
     * **All the crypto happens before the transaction opens**, for the reason spelled out on
     * [keeper]: a `CRYPTO_UNAVAILABLE` returned from inside would commit the rows already written.
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
        // DEPOSIT: card-derived, so every card holder presents one value (P-2). READ: seed-derived,
        // the D11 key no card holder can compute (C-5). FETCH: the bundle namespace's (§22.8.7).
        val inbox = inboxSet.map {
            verifiersOf(it, own.inboxNamespace, INBOX_KINDS) ?: return Result.CRYPTO_UNAVAILABLE
        }
        val bundle = bundleSet.map {
            verifiersOf(it, own.bundleNamespace, BUNDLE_KINDS) ?: return Result.CRYPTO_UNAVAILABLE
        }

        return database.transaction { tx ->
            store.self(tx.sql) ?: return@transaction Result.NOT_ACTIVATED
            val inboxNs = NamespaceId(own.inboxNamespace)
            val bundleNs = NamespaceId(own.bundleNamespace)
            var changed = false

            for (relayVerifiers in inbox) {
                changed = keepRows(tx, relayVerifiers, inboxNs, week) || changed
            }
            for (relayVerifiers in bundle) {
                changed = keepRows(tx, relayVerifiers, bundleNs, week) || changed
            }
            // Rows of weeks before `w - 1` can no longer be served: §4.8 deletes a pending row once
            // `week < week(now) - 1`, because no capability the relay would accept still names it.
            for (relayVerifiers in inbox) {
                changed = sync.registrations.forget(tx, relayVerifiers.slot.relay, inboxNs, week - 1) > 0 || changed
            }
            for (relayVerifiers in bundle) {
                changed = sync.registrations.forget(tx, relayVerifiers.slot.relay, bundleNs, week - 1) > 0 || changed
            }
            if (changed) Result.DONE else Result.UNCHANGED
        }
    }

    // ------------------------------------------------------------- internals

    private fun ownCard(): DmSessions.OwnCard? = crypto.ownCard(cardIndex)

    /** `t_pub(w) = start(w) + offset`, already floored to the minute on the native side (§5.4). */
    private fun publicationMinute(week: Long, offsetSeconds: Long): Long =
        DmTime.weekStart(week) + offsetSeconds

    /**
     * The minute the publication of week [week] is due: `t_pub` of the **first week that was not
     * published**, which for an owner that published last week is `t_pub(week)` itself (§5.4).
     *
     * A device that was offline over `t_pub(w − 1)` comes back holding a bundle of week `w − 2` or
     * older, which is valid in no week at all (§5.4 "Validity"), and the due minute it gets here is
     * already past — so it publishes at that first pass, not up to a week later. The value reads
     * `dm_self.bundle_week` and the card's fixed offset and nothing else, so no contact, fetch or
     * message can move it (T31, mutants PM-11 and PM-30).
     */
    private fun publicationDue(lastPublishedWeek: Long?, week: Long, offsetSeconds: Long): Long {
        // No bundle was ever published: there is nothing valid to wait behind.
        if (lastPublishedWeek == null) return DmTime.weekStart(week)
        return publicationMinute(minOf(lastPublishedWeek + 1, week), offsetSeconds)
    }

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

    /** What KEEPER does with the READ credential of one pair this pass ([readCredentialAction]). */
    private enum class ReadCredential {
        /** Nothing: it is installed, usable, and more than the refresh window is left. */
        LEAVE,

        /** Put it: it is missing, or fewer than 7 days remain (§4.8). */
        PUT,

        /** It was refused: re-arm the pair's `done` rows (§4.8's healing rule) and put it again. */
        HEAL_AND_PUT,
    }

    /**
     * What to do with the pair's READ credential.
     *
     * **Fresh:** an installed, usable credential with more than the refresh window left is left
     * exactly as it is, which is §7.2's "KEEPER puts only a differing token": a re-put would bump
     * the capability generation for nothing. Missing, or "fewer than 7 days remain" (§4.8) → [PUT].
     *
     * **Refused** (the relay lost its `keys.redb`, §4.6) → §4.8's healing rule, and §21.2 point 8's
     * bound on it. Two rules together, and they have to be decided in one place:
     *  - while the pair still has a **pending** registration row from this week on, the healing is
     *    under way and nothing is done at all. Reads use the write capability meanwhile, which is
     *    §21.2 point 8's "until a row is done again", and the credential is **not** re-put — that
     *    is what bounds the re-put to one per registration round trip instead of one per
     *    `CAPABILITIES` hint (mutant MC-15);
     *  - otherwise the `done` rows go back to pending and the credential is re-put in the same
     *    transaction ([HEAL_AND_PUT]). Doing both at once is what makes the loop terminate: the
     *    refusal is a level, not an edge — it stays `rejected` until something puts a new
     *    generation — so a step that only re-armed would re-arm again at every later pass, and
     *    would send the rows the work lane had just finished back to pending for ever.
     *
     * Which is also why the rule is **here** and not in REGROWS, where §4.8 writes it: the pass of
     * §13.7 runs KEEPER first, so a healing that came after it would only ever see the credential
     * this step had just made usable again, and would never fire at all — mutant MC-14, and what
     * the S6 code did before the review.
     */
    private fun readCredentialAction(
        tx: SyncTransaction,
        relay: RelayId,
        ns: NamespaceId,
        week: Long,
        now: Long,
    ): ReadCredential {
        val installed = sync.capabilities.installed(tx, relay, ns, CapabilityKind.READ) ?: return ReadCredential.PUT
        if (installed.state != InstalledCapability.State.USABLE) {
            if (sync.registrations.pending(tx, relay, ns, week) > 0) return ReadCredential.LEAVE
            return ReadCredential.HEAL_AND_PUT
        }
        val expires = installed.expiresHour ?: return ReadCredential.LEAVE
        return if (expires - now < READ_CREDENTIAL_REFRESH_SECONDS) ReadCredential.PUT else ReadCredential.LEAVE
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

    /** One relay's registration verifiers, one per kind the namespace needs at it. */
    private class SlotVerifiers(val slot: EsSlot, val byKind: Map<KeyKind, ByteArray>)

    /**
     * The verifiers of one slot, computed **outside** any transaction. The **verifier** is what the
     * row carries and what the relay stores; the secrets never leave this frame, and they are
     * zeroised here whatever happens. Null when the DM context is closed.
     */
    private fun verifiersOf(
        slot: EsSlot,
        namespace: ByteArray,
        kinds: Map<KeyKind, CredentialV3.Kind>,
    ): SlotVerifiers? {
        val secrets = crypto.ownSecrets(cardIndex, slot.slot) ?: return null
        return try {
            SlotVerifiers(
                slot,
                kinds.entries.associate { (keyKind, credentialKind) ->
                    val secret = when (keyKind) {
                        KeyKind.READ -> secrets.read
                        KeyKind.DEPOSIT -> secrets.deposit
                        KeyKind.FETCH -> secrets.fetch
                    }
                    keyKind to CredentialV3.verifier(credentialKind, slot.slot, namespace, secret)
                },
            )
        } finally {
            secrets.clear()
        }
    }

    /** Every row one relay must hold for [ns] this pass: each period × each kind. */
    private fun keepRows(tx: SyncTransaction, verifiers: SlotVerifiers, ns: NamespaceId, week: Long): Boolean {
        var changed = false
        for (period in periodsFor(tx, verifiers.slot.relay, ns, week)) {
            for ((kind, verifier) in verifiers.byKind) {
                changed = sync.registrations.keep(tx, verifiers.slot.relay, ns, period, kind, verifier) || changed
            }
        }
        return changed
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
     * §22.11 item 11: whether the stored own namespaces are **this** identity's.
     *
     * `X_0` and `P_0` are HKDF outputs of `card_secret_0`, which is a seed derivation, so the pair
     * is a name for the identity that wrote them. A database with no rows at all is treated as
     * matching, so a half-written activation resumed by §21.12 point 2 is completed rather than
     * wiped.
     */
    private fun ownNamespacesMatch(tx: SyncTransaction, own: DmSessions.OwnCard): Boolean {
        val stored = store.ownNamespaces(tx.sql, cardIndex)
        if (stored.isEmpty()) return true
        val inbox = stored[OwnerStore.ROLE_INBOX] ?: return false
        val bundle = stored[OwnerStore.ROLE_BUNDLE] ?: return false
        return inbox.contentEquals(own.inboxNamespace) && bundle.contentEquals(own.bundleNamespace)
    }

    /**
     * §22.11 item 11: clears the DM tables of an identity this context cannot speak for.
     *
     * The two stale namespaces become `dm_orphan_namespace` rows **first**, because everything
     * after this erases what names them, and SWEEP is what calls `Namespaces.remove` once their
     * ops are released (§21.12 point 3; the same fail-closed order `ContactSteps` uses for a block).
     * `dm_contact` then cascades the whole contact side — conversations, messages, items, ops,
     * pending sends, pair keys and offers, peer keys, held rows, scheduled controls, sessions —
     * and the generations, the reuse tuples and the D3 tags go with `dm_self`'s own erasure.
     */
    private fun clearForeignIdentity(tx: SyncTransaction) {
        for (namespace in store.ownNamespaces(tx.sql, cardIndex).values) {
            val changed = tx.sql.execUpdate(
                "UPDATE dm_orphan_namespace SET namespace_id = ? WHERE namespace_id = ?",
                listOf(namespace, namespace),
            )
            if (changed == 0) {
                tx.sql.exec(
                    "INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)",
                    listOf(namespace),
                )
            }
        }
        tx.sql.exec("DELETE FROM dm_contact")
        tx.sql.exec("DELETE FROM olm_prekey_gen")
        tx.sql.exec("DELETE FROM dm_seen")
        tx.sql.exec("DELETE FROM dm_own_namespace")
        tx.sql.exec("DELETE FROM dm_self")
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
        // An `InsufficientReplicasException` here (ADR-11: fewer than two operators this week) is
        // deliberately not caught: it leaves the transaction, the whole of it rolls back — the week
        // is not claimed and no generation is superseded — and the next pass tries again with a
        // fresh set (§5.2, §21.12 point 2).
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

        /** `X_0` needs DEPOSIT and READ rows at each of its relays (§4.8). */
        private val INBOX_KINDS: Map<KeyKind, CredentialV3.Kind> = linkedMapOf(
            KeyKind.DEPOSIT to CredentialV3.Kind.DEPOSIT,
            KeyKind.READ to CredentialV3.Kind.READ,
        )

        /** `P_0` needs FETCH rows (§22.8.7). */
        private val BUNDLE_KINDS: Map<KeyKind, CredentialV3.Kind> = linkedMapOf(
            KeyKind.FETCH to CredentialV3.Kind.FETCH,
        )

        private const val GEN_ID_ATTEMPTS = 64
    }
}
