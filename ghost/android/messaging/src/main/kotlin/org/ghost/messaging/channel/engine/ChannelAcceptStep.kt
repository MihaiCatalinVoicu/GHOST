package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelInvite
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.JoinType
import org.ghost.messaging.channel.store.OpPurpose
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.SendDelay

/**
 * **`CH-ACCEPT`** (Phase 10 design §6.2.2, §10.4; the password of §19.28.4 step 3), a user action, **one transaction**.
 *
 * 1. **Parse strictly.** The link's V2 header first: a `kdf_code ≥ 1` link without a password is `PASSWORD_REQUIRED`
 *    before any native call, a wrong password or a tampered link `WRONG_PASSWORD` with nothing written; an unknown suite
 *    `UNSUPPORTED_SUITE`; an expired invite `EXPIRED`. The invite's namespace is inside the sealed body, so the parse is
 *    asked for the credentials of **every slot of the week's table** and the step keeps those of `set(ns, w)`.
 * 2. **`ALREADY_MEMBER` is decided after the parse** (the review of S2b, §19.36 row 3, asked for it before): the channel
 *    id is inside the sealed body too, so no decision can precede the parse. Nothing is written then, and the class-6
 *    envelope the parse minted — which seals a join request and opens a Welcome and nothing else (§19.36 row 3) — is
 *    dropped unused. A channel this client left, was removed from or was replaced in, or that is `resync_needed` or
 *    `reinvite_needed`, is `ALREADY_MEMBER` in this slice: the re-entry and the restore purpose of §6.2.2 step 2 come with
 *    the flows that create those states (S6, S7). A join that **expired** re-enters `joining` (§6.11).
 * 3. **The KeyPackage** (fn 4, purpose join): the canonical one of §6.2.4 (B), 395 bytes; its private keys are global rows
 *    that die with the join (`ch_join.expiry_day`), except the leaf's key pairs, which a Welcome hands to the group.
 * 4. **One transaction:** `ch_channel(joining)` — or `join_expired → joining` —, `ch_join` with the invite's state
 *    (amended by this slice, §19.35 F-8: its namespace, `JK_g` as an invite's envelope, `R_join(g)` and the committers
 *    digest of the anchor), the KeyPackage's rows, its box key, the namespace (`listen = true`, `LOCAL`), the READ and
 *    DEPOSIT credentials of each slot of the set, and the join request sealed in mode 0x12 under the invite's `JK_g`
 *    with the invite's handshake TTL and the class floor, enqueued (§6.2.2 step 3). No registration and no funding: the
 *    invitee pays nothing (§7.4).
 *
 * The password follows `ChannelPassword`'s rule (§19.36 row 6): this step makes no copy, the facade's NFKD bytes are
 * zeroed after the call, the caller's array stays the caller's.
 *
 * Gate G-M5 lists this file for `Namespaces.register`, `Capabilities.put` and `Outbox.enqueue`.
 */
internal class ChannelAcceptStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    fun accept(link: ByteArray, password: CharArray?): AcceptResult {
        val invite = ChannelInvite.fromLink(String(link, Charsets.US_ASCII)) ?: return AcceptResult.INVALID
        try {
            if (ChannelInvite.needsPassword(invite) && password == null) return AcceptResult.PASSWORD_REQUIRED
            return acceptParsed(invite, password)
        } finally {
            invite.fill(0)
        }
    }

    private fun acceptParsed(invite: ByteArray, password: CharArray?): AcceptResult {
        val now = env.now()
        val day = DmTime.day(now)
        val week = DmTime.week(now)
        val content = env.keys.content() ?: return AcceptResult.CRYPTO_UNAVAILABLE
        val context = env.contexts.crypto(create = true) ?: return AcceptResult.CRYPTO_UNAVAILABLE
        val weekSlots = env.weekSlots(week).map { it.slot }.distinct()
        if (weekSlots.isEmpty()) return AcceptResult.NO_REPLICAS
        val parsed = when (val r = context.inviteParse(invite, password, ByteArray(weekSlots.size) { weekSlots[it].toByte() })) {
            is MlsOutcome.Ok -> r.value
            is MlsOutcome.Refused -> return when (r.code) {
                MlsCode.PASSWORD_REQUIRED -> AcceptResult.PASSWORD_REQUIRED
                MlsCode.WRONG_PASSWORD -> AcceptResult.WRONG_PASSWORD
                MlsCode.UNSUPPORTED_SUITE -> AcceptResult.UNSUPPORTED_SUITE
                MlsCode.CRYPTO_UNAVAILABLE -> AcceptResult.CRYPTO_UNAVAILABLE
                else -> AcceptResult.INVALID
            }
        }
        if (parsed.expiryDay < day) return AcceptResult.EXPIRED
        val channelId = parsed.channelId
        val existing = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) }
        if (existing != null && existing.state != ChannelState.JOIN_EXPIRED) return AcceptResult.ALREADY_MEMBER
        if (existing == null && env.database.transaction { tx -> env.liveChannels(tx.sql) } >= ChannelEnv.MAX_CHANNELS) {
            return AcceptResult.LIMIT_REACHED
        }
        val set = env.relaySet(parsed.ns, week) ?: return AcceptResult.NO_REPLICAS
        val opened = env.contexts.open(channelId) ?: return AcceptResult.CRYPTO_UNAVAILABLE
        val p = opened.pseudonym
        if (existing != null && !existing.myPseudonym.contentEquals(p)) return AcceptResult.CRYPTO_UNAVAILABLE
        val keyPackage = opened.crypto.keyPackage(channelId, PURPOSE_JOIN, day.toInt()).valueOrNull()
            ?: return AcceptResult.CRYPTO_UNAVAILABLE
        val body = when (val b = opened.crypto.joinRequest(channelId, parsed.inviteId, parsed.inviteSeedEnv, keyPackage.keyPackage)) {
            is MlsOutcome.Ok -> b.value
            is MlsOutcome.Refused -> return if (b.code == MlsCode.CRYPTO_UNAVAILABLE) AcceptResult.CRYPTO_UNAVAILABLE else AcceptResult.INVALID
        }
        val floor = ChannelTime.floor(parsed.sizeClass)
        val blob = when (
            val s = opened.crypto.seal(
                channelId, parsed.jkEnv, ChannelCrypto.KEY_CLASS_INVITE_JOIN, parsed.ns, floor, ChannelCrypto.MODE_JOIN,
                ChannelCrypto.SealOrder.NONE, body,
            )
        ) {
            is MlsOutcome.Ok -> s.value
            is MlsOutcome.Refused -> return AcceptResult.INVALID
        }
        val timerCode = parsed.handshakeTtlCode
        val nameEnv = if (parsed.name.isEmpty()) null else env.seal(content, ChannelAd.name(channelId), parsed.name)
        val credentials = set.map { slot ->
            slot to (parsed.slots.firstOrNull { it.slot == slot.slot } ?: return AcceptResult.CRYPTO_UNAVAILABLE)
        }
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null) {
                    stores.channels.insert(
                        tx,
                        ChannelStore.NewChannel(
                            channelId = channelId,
                            state = ChannelState.JOINING,
                            generation = parsed.generation,
                            epoch = 0,
                            joinedEpoch = 0,
                            sizeClass = parsed.sizeClass,
                            timerCode = timerCode,
                            myPseudonym = p,
                            nameEnv = nameEnv,
                            pwRequired = parsed.kdfCode != 0,
                        ),
                    )
                } else {
                    if (fresh.state != ChannelState.JOIN_EXPIRED) return@transaction AcceptResult.ALREADY_MEMBER
                    stores.channels.transition(tx, channelId, ChannelState.JOIN_EXPIRED, ChannelState.JOINING)
                    stores.channels.setPosition(tx, channelId, parsed.generation, 0)
                    stores.channels.setPolicy(tx, channelId, timerCode, parsed.sizeClass, parsed.kdfCode != 0, nameEnv)
                    // The expired join's row may still name the namespace (its removal waits for its op, CH-SWEEP).
                    stores.joins.deleteJoins(tx, channelId)
                }
                stores.joins.insertJoin(
                    tx, channelId, keyPackage.kpRef, JoinType.JOIN, parsed.inviteId, parsed.generation, parsed.expiryDay,
                    ns = parsed.ns, jkEnv = parsed.jkEnv, rJoin = parsed.rJoin, committersDigest = parsed.committersDigest,
                )
                stores.mls.apply(
                    tx, channelId, MlsRows.changes(keyPackage.changes), globalDeleteAfterDay = parsed.expiryDay,
                    keyPackagesOnly = true,
                )
                stores.members.insertBoxKey(tx, channelId, keyPackage.boxPk, keyPackage.boxEnv)
                val ns = NamespaceId(parsed.ns)
                sync.namespaces.register(
                    tx = tx,
                    namespace = ns,
                    consumer = Consumer.CHANNEL,
                    relays = set.map { it.relay }.toSet(),
                    listen = true,
                    sendDelay = SendDelay.DEFAULT,
                    capabilitySource = CapabilitySource.LOCAL,
                )
                for ((slot, c) in credentials) {
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.READ, c.readCredential, null)
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.WRITE, c.depositCredential, null)
                }
                val operationId = env.random.bytes(OperationId.SIZE)
                sync.outbox.enqueue(
                    tx,
                    OutboundBlob(
                        OperationId(operationId), ns, blob, ChannelTime.handshakeTtl(timerCode),
                        deadlineEpochSeconds = ChannelTime.handshakeDeadline(DmTime.floorMinute(now)),
                    ),
                )
                stores.posts.insertOp(tx, operationId, channelId, OpPurpose.JOIN, keyPackage.kpRef)
                AcceptResult.PENDING
            }
        } catch (e: InsufficientReplicasException) {
            AcceptResult.NO_REPLICAS
        } catch (e: StorageFullException) {
            AcceptResult.STORAGE_FULL
        } finally {
            body.fill(0)
        }
    }

    override fun toString(): String = "ChannelAcceptStep"

    companion object {
        /** `GhostKpBind.purpose` (§5.4): 1 join, 2 rejoin, 3 restore. */
        const val PURPOSE_JOIN: Int = 1
    }
}
