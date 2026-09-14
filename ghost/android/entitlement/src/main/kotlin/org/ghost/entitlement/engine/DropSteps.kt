package org.ghost.entitlement.engine

import org.ghost.entitlement.store.InviteRow
import org.ghost.entitlement.store.InviteStore
import org.ghost.entitlement.store.PurchaseStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.SyncTables
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.identity.InviteKeys
import org.ghost.identity.RootEntropy
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.Time

/**
 * Invites and their drops (design §8.5, §9.3, §19.12).
 *
 * Inviter: `createInvite` reserves and spends one fresh INVITE token, takes the next invite index,
 * draws 3 drop slots spanning at least two operators and the two refresh times of a credit sent to
 * the drop ([RefreshPlan], Q31, §19.26), and registers the drop namespace as listening; `receive`
 * opens drop blobs taken while the drop is listened, and a valid credit of an accepted epoch becomes
 * a `refresh` flow due at the first of those times if read before it, else at the second, cut to the
 * issuer's refresh window; the read moment, which the relays see, never sets the due time. A received
 * credit is never presented before its refresh (§19.8).
 *
 * Invitee: at the pre-drawn `t_drop` (never tied to a purchase, NI-1d) exactly one blob is sealed and
 * enqueued: a fresh own credit if one exists, else a dummy sealed identically. Credits are fungible
 * bearer tokens with no purchase link at rest (`ent_token`), so the credit sent is any fresh own
 * credit of an accepted epoch; one minted after `t_drop` stays with the payer. Without coverage (no
 * access token of the week or later and no write capability through the week) nothing is written.
 */
internal class DropSteps(private val c: EngineContext) {

    private enum class Send { DONE, NO_RELAYS }

    // ------------------------------------------------------------------ invitee

    fun sendDue(now: Long) {
        val target = c.tx { tx -> c.invites.dropTarget(tx) } ?: return
        if (target.state != InviteStore.WAITING || now < target.dropMinute) return
        val result = try {
            c.tx { tx -> send(tx, now) }
        } catch (e: InsufficientReplicasException) {
            Send.NO_RELAYS
        }
        if (result == Send.NO_RELAYS) {
            c.tx { tx ->
                c.alarm(tx, StateStore.ALARM_REFUSED_BY_RELAY)
                c.invites.deleteDropTarget(tx)
            }
        }
    }

    private fun send(tx: SyncTransaction, now: Long): Send {
        val t = c.invites.dropTarget(tx) ?: return Send.DONE
        if (t.state != InviteStore.WAITING || now < t.dropMinute) return Send.DONE
        val week = Grid.week(now)
        if (Grid.day(now) >= t.untilDay || !covered(tx, week)) {
            c.invites.deleteDropTarget(tx)
            return Send.DONE
        }
        val relays = dropRelays(tx, t.dropSlots, week) ?: return Send.NO_RELAYS
        val ns = NamespaceId(t.dropNamespace())
        c.sync.namespaces.register(tx, ns, Consumer.IDENTITY, relays, listen = false)
        val credit = c.tokens.freshCredits(tx).firstOrNull { Pricing.accepted(it.epoch, week) }
        val blob = if (credit != null) {
            c.tokens.delete(tx, credit.nullifier())
            c.seal.sealCredit(credit.token(), t.dropKey(), t.dropNamespace())
        } else {
            c.seal.sealDummy(t.dropKey(), t.dropNamespace())
        }
        val op = c.random.bytes(EngineContext.ID_BYTES)
        c.sync.outbox.enqueue(tx, OutboundBlob(OperationId(op), ns, blob, BLOB_TTL))
        c.invites.markEnqueued(tx, op)
        return Send.DONE
    }

    /**
     * Coverage at `t_drop` (§9.3, §19.12): an ACCESS token of [week] or later, fresh or reserved, or a
     * write capability (usable or exhausted) reaching the end of [week]. A token leaves `ent_token`
     * when redeemed (§11.4), so an identity that spent every token of the week holds its capabilities
     * instead: it is active, not silent, and writes its one blob.
     */
    private fun covered(tx: SyncTransaction, week: Long): Boolean =
        c.tokens.hasAccessFrom(tx, week) || SyncTables.writeCapabilityReaching(tx, Grid.start(week + 1))

    /** The active directory relays serving the three drop slots in [week], or null if any is missing. */
    private fun dropRelays(tx: SyncTransaction, slots: List<Int>, week: Long): Set<RelayId>? {
        val active = SyncTables.relays(tx).filter { it.active }
        val out = LinkedHashSet<RelayId>()
        for (slot in slots) {
            val onion = c.summary.slots.firstOrNull { it.slot == slot && it.validIn(week) }?.onion ?: return null
            out += (active.firstOrNull { it.address == onion } ?: return null).id
        }
        return out
    }

    /** Once the blob's outcome is decided, it is released and the drop namespace and target go (§9.3). */
    fun settleSent() {
        val t = c.tx { tx -> c.invites.dropTarget(tx) } ?: return
        if (t.state != InviteStore.ENQUEUED) return
        val op = OperationId(checkNotNull(t.operationId()))
        val progress = c.sync.outbox.progress(op)
        if (progress != null && progress.outcome == null) return
        c.tx { tx ->
            if (progress != null) c.sync.outbox.release(tx, op)
            c.retireNamespace(tx, NamespaceId(t.dropNamespace()))
            c.invites.deleteDropTarget(tx)
        }
    }

    // ------------------------------------------------------------------ inviter

    fun receive(now: Long) {
        val listening = c.tx { tx -> c.invites.all(tx).any { it.state != InviteStore.CLOSED } }
        if (!listening || !c.identity.hasIdentity()) return
        for (blob in c.sync.inbox.claim(Consumer.IDENTITY, CLAIM_LIMIT)) take(blob, now)
    }

    private fun take(blob: InboundBlob, now: Long) {
        val invite = c.tx { tx -> c.invites.byNamespace(tx, blob.namespace.toByteArray()) }
        // Nothing is taken once the listening ended (§9.3), also before GC closed the invite: every
        // read precedes the second refresh time (§19.26).
        if (invite == null || invite.state == InviteStore.CLOSED || invite.listenUntilDay <= Grid.day(now)) {
            consume(blob)
            return
        }
        when (val opened = c.seal.open(invite.index, blob.ciphertext, invite.dropNamespace())) {
            is DropSeal.Opened.Credit -> credit(blob, invite, opened.token, now)
            DropSeal.Opened.Dummy -> {
                c.memory.count(Counters.DROP_DUMMY)
                consume(blob)
            }
            DropSeal.Opened.Invalid -> {
                c.memory.count(Counters.DROP_INVALID)
                consume(blob)
            }
        }
    }

    private fun credit(blob: InboundBlob, invite: InviteRow, token: ByteArray, now: Long) {
        val week = Grid.week(now)
        val verified = try {
            c.crypto.verifyToken(token, EntitlementCrypto.KIND_CREDIT)
        } catch (e: NetworkException) {
            return
        }
        val current = Grid.creditEpoch(week)
        // Due at a refresh time drawn with the invite (Q31, §19.26): this read only picks which one,
        // and a credit whose due time would precede the read is dropped, never refreshed at the read.
        val due = verified?.let { RefreshPlan.due(invite.refreshMinute, invite.lateRefreshMinute, it.epoch, now) }
        if (verified == null || due == null || verified.epoch !in (current - 1)..current || invite.state != InviteStore.CREATED) {
            c.memory.count(Counters.CREDIT_DROPPED)
            consume(blob)
            return
        }
        val layout = try {
            c.crypto.layout(EntitlementCrypto.PRODUCT_REFRESH, verified.epoch)
        } catch (e: NetworkException) {
            return
        }
        val id = c.random.bytes(EngineContext.ID_BYTES)
        val seed = c.random.bytes(EngineContext.SECRET_BYTES)
        c.tx { tx ->
            val current = c.invites.get(tx, invite.index)
            if (c.sync.inbox.markConsumed(tx, blob.namespace, blob.hash) && current != null && current.state == InviteStore.CREATED) {
                c.purchases.insert(tx, id, PurchaseStore.REFRESH, PurchaseStore.CREDIT, seed, null, token, week, c.summary.seq, layout.digest(), Time.floorHour(now), due)
                c.invites.credit(tx, invite.index)
                c.retireNamespace(tx, blob.namespace)
            }
        }
    }

    private fun consume(blob: InboundBlob) {
        c.tx { tx -> c.sync.inbox.markConsumed(tx, blob.namespace, blob.hash) }
    }

    // ------------------------------------------------------------------ invite creation

    /** `createInvite` (§8.5): null without an identity, a fresh invite token, a valid expiry or usable drop relays. */
    fun createInvite(expiryDay: Long, now: Long): String? {
        if (!c.identity.hasIdentity()) return null
        val index = c.tx { tx -> c.state.read(tx)?.nextInviteIndex } ?: return null
        if (index >= RootEntropy.MAX_INVITE_INDEX) return null
        val keys = c.identity.inviteKeys(index)
        return c.tx { tx -> create(tx, index, keys, expiryDay, now) }
    }

    private fun create(tx: SyncTransaction, index: Int, keys: InviteKeys, expiryDay: Long, now: Long): String? {
        val st = c.state.read(tx) ?: return null
        if (st.nextInviteIndex != index) return null
        val token = c.tokens.freshInvite(tx) ?: return null
        if (expiryDay <= Grid.day(now) || expiryDay > Invite.maxExpiryDay(token.epoch)) return null
        val listenUntil = expiryDay + INVITER_LISTEN_DAYS
        val drop = chooseDropSlots(tx, now, listenUntil) ?: return null
        // The refresh times of a credit an invitee sends to this drop: drawn now, as the listening
        // starts, never at a read (Q31, §19.26).
        val refresh = RefreshPlan.times(expiryDay, listenUntil, c.random)
        val invite = Invite.create(token.token(), token.epoch, expiryDay, drop.map { it.first }, keys)
        c.sync.namespaces.register(tx, NamespaceId(keys.dropNamespace), Consumer.IDENTITY, drop.map { it.second }.toSet(), listen = true)
        c.invites.insert(tx, index, invite.bytes(), keys.dropNamespace, listenUntil, refresh.first, refresh.second)
        c.state.takeInviteIndex(tx, index)
        c.tokens.delete(tx, token.nullifier())
        return invite.encode()
    }

    /**
     * Three distinct ES slots, drawn uniformly (client randomness), each served by one relay entry for
     * every week from now through [listenUntilDay] whose onion is active in the relay directory, the
     * three relays spanning at least two operators (the ADR-11 quorum of `Outbox.enqueue`); redrawn
     * otherwise, null if impossible (§19.12).
     */
    private fun chooseDropSlots(tx: SyncTransaction, now: Long, listenUntilDay: Long): List<Triple<Int, RelayId, List<Byte>>>? {
        val first = Grid.week(now)
        val last = Grid.week(listenUntilDay * Grid.DAY)
        val active = SyncTables.relays(tx).filter { it.active }
        val candidates = c.summary.slots.map { it.slot }.distinct().sorted().mapNotNull { slot ->
            val entry = c.summary.slots.firstOrNull { it.slot == slot && it.validFromWeek <= first && (it.validUntilWeek == 0L || it.validUntilWeek > last) }
            val relay = entry?.let { e -> active.firstOrNull { it.address == e.onion } }
            relay?.let { Triple(slot, it.id, it.operatorKey()) }
        }
        if (candidates.size < Invite.DROP_SLOTS) return null
        repeat(DRAWS) {
            val pool = candidates.toMutableList()
            val drawn = List(Invite.DROP_SLOTS) { pool.removeAt(minOf(pool.size - 1, (c.random.uniform() * pool.size).toInt())) }
            if (drawn.map { it.third }.toSet().size >= MIN_OPERATORS) return drawn
        }
        return null
    }

    override fun toString(): String = "DropSteps"

    companion object {
        /** A drop blob's TTL: its relays store it this long after the write (the restore scan's relay window, §19.26). */
        val BLOB_TTL: TtlBucket = TtlBucket.DAYS_30

        private const val CLAIM_LIMIT = 16
        private const val INVITER_LISTEN_DAYS = 56L
        private const val DRAWS = 32
        private const val MIN_OPERATORS = 2
    }
}
