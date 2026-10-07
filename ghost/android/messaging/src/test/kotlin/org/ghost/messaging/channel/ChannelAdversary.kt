package org.ghost.messaging.channel

import org.ghost.crypto.bridge.AdmitEvidence
import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.CommitRequest
import org.ghost.crypto.bridge.MlsChange
import org.ghost.crypto.bridge.MlsField
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.crypto.bridge.MlsRow
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelTime
import org.ghost.messaging.channel.engine.MlsRows
import org.ghost.messaging.engine.DmTime

/**
 * What an insider of a channel can build with what a member holds (Phase 10 design §12.1's hostile modes that need more
 * than a relay): a member holds `JK_g`, so it can **open** every join request of its generation and **seal** a Welcome or
 * a request into the generation's namespace; a member that sponsored an invite holds its signature. The relay serves what
 * this builds ([ModelChannelRelay.inject]); every byte of it goes through the member's own native context, so nothing here
 * is a capability a modified client would not have.
 */
internal object ChannelAdversary {

    private fun <T> MlsOutcome<T>.ok(): T = when (this) {
        is MlsOutcome.Ok -> value
        is MlsOutcome.Refused -> throw AssertionError("refused: $refusal")
    }

    /** The member's view of the channel: its native channel, its generation row, its day. */
    private class View(val crypto: ChannelCrypto, val p: ByteArray, val gNs: ByteArray, val jkEnv: ByteArray, val generation: Long, val day: Long)

    private fun view(member: ChannelClient, id: ChannelId): View {
        val c = id.toByteArray()
        val opened = member.contexts.open(c) ?: error("the member's channel does not open")
        val day = DmTime.day(member.clock.now)
        val g = member.database.transaction { tx -> member.channelStores.generations.current(tx.sql, c, day) } ?: error("no generation")
        return View(opened.crypto, opened.pseudonym, g.namespaceId, g.jkEnv, g.generation, day)
    }

    /** Opens a join request blob (mode 0x12) as any member can: its body. */
    fun openRequest(member: ChannelClient, id: ChannelId, blob: ByteArray): ByteArray {
        val v = view(member, id)
        return v.crypto.open(id.toByteArray(), v.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, v.gNs, ChannelCrypto.MODE_JOIN, blob).ok().body
    }

    /**
     * REPLAY_JOIN by an insider: the request [blob] opened and **sealed again** under a fresh salt — the same request, new
     * bytes, a new blob hash, so no tombstone stops it.
     */
    fun resealRequest(member: ChannelClient, id: ChannelId, blob: ByteArray): ByteArray {
        val v = view(member, id)
        val body = openRequest(member, id, blob)
        return v.crypto.seal(
            id.toByteArray(), v.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, v.gNs, ChannelTime.SMALL_FLOOR, ChannelCrypto.MODE_JOIN,
            ChannelCrypto.SealOrder.NONE, body,
        ).ok()
    }

    /**
     * FAKE_WELCOME with the forger's own committers list (S0-15; §12.6 JN): [forger], a member that sponsored the invite the
     * joiner accepted, opens the joiner's request, builds **its own group under the channel's id** with itself as the only
     * committer, admits the joiner's KeyPackage with valid evidence (it is the sponsor) and seals the Welcome under the
     * generation's real `JK_g` into the real namespace — so the joiner opens it, and only the anchor (the invite's committers
     * digest) can refuse it. Returns the sealed blob.
     */
    fun forgeWelcome(forger: ChannelClient, id: ChannelId, requestBlob: ByteArray): ByteArray {
        val v = view(forger, id)
        val c = id.toByteArray()
        val body = openRequest(forger, id, requestBlob)
        val invite = forger.database.transaction { tx -> forger.channelStores.invites.issuedOf(tx.sql, c, v.day) }
            .firstOrNull { it.sponsor.contentEquals(v.p) } ?: error("the forger sponsored no invite")
        val verified = v.crypto.joinVerify(c, body, invite.invitePk, null, v.generation.toInt()).ok()
        // The fork: a group of the forger's alone, under the channel's id, in rows the forger keeps to itself.
        val policy = ChannelPolicy(c, 0, 4, 0, 0, 1, 63, 0, ByteArray(0), listOf(v.p), listOf(v.p))
        val created = v.crypto.groupCreate(c, policy, v.day.toInt()).ok()
        val rows = apply(emptyList(), created.changes)
        val evidence = AdmitEvidence(
            verified.kpRef, invite.inviteId, invite.invitePk, invite.expiryDay, invite.sponsor, invite.sponsorSig,
            verified.auth.bytes(MlsField.INVITE_SIG),
        )
        val committed = v.crypto.commit(
            c, rows,
            CommitRequest(
                adds = listOf(verified.keyPackage to evidence),
                commitMinute = Math.floorDiv(forger.clock.now, DmTime.MINUTE),
                floor = ChannelTime.SMALL_FLOOR.toLong(),
                generation = created.generation.generation,
                openEpoch = created.generation.openEpoch,
                gEnv = created.generation.gEnv,
            ),
            v.day.toInt(),
        ).ok()
        val welcome = committed.welcomes.single()
        val bucket = ChannelTime.bucket(welcome.size, 0) ?: error("a Welcome larger than any bucket")
        return v.crypto.seal(c, v.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, v.gNs, bucket, ChannelCrypto.MODE_WELCOME, ChannelCrypto.SealOrder.NONE, welcome).ok()
    }

    /** The namespace of the channel's current generation at [member]. */
    fun namespace(member: ChannelClient, id: ChannelId): ByteArray = view(member, id).gNs

    /**
     * A member posts content of its own choosing — any kind, any op id, any `INVITE_ISSUED` record — through its own
     * engine's `CH-POST` (`compose`): what a modified client can send, encrypted and enqueued like any post of its.
     */
    fun postAs(member: ChannelClient, id: ChannelId, fields: org.ghost.crypto.bridge.ChannelContentFields, handshake: Boolean) {
        val encoded = ChannelCrypto.contentEncode(fields).ok()
        member.database.transaction { tx ->
            val channel = member.channelStores.channels.channel(tx.sql, id.toByteArray()) ?: error("not a member")
            val opened = member.contexts.open(id.toByteArray()) ?: error("the member's channel does not open")
            member.engine.postStep.compose(tx, channel, opened, member.content, fields, encoded, handshake, member.clock.now)
        }
    }

    // ------------------------------------------------------------------------------- mode 0x11 (posts and commits)

    /** The epoch keys the member holds, newest first: `(epoch, K_ep envelope)`. */
    private fun epochKeys(member: ChannelClient, id: ChannelId, day: Long): List<Pair<Long, ByteArray>> =
        member.database.transaction { tx -> member.channelStores.epochs.retained(tx.sql, id.toByteArray(), day) }
            .map { it.epoch to it.kEnv }

    /** Opens a mode-0x11 blob as any member of its epoch can (every epoch key it holds is tried): its order and MLS body. */
    fun openEpochBlob(member: ChannelClient, id: ChannelId, blob: ByteArray): ChannelCrypto.OpenedBlob {
        val v = view(member, id)
        for ((_, kEnv) in epochKeys(member, id, v.day)) {
            val o = v.crypto.open(id.toByteArray(), kEnv, ChannelCrypto.KEY_CLASS_EPOCH, v.gNs, ChannelCrypto.MODE_EPOCH, blob)
            if (o is MlsOutcome.Ok) return o.value
        }
        throw AssertionError("no epoch key of ${member.name} opens the blob")
    }

    /**
     * A member **re-seals** a mode-0x11 blob: its MLS body, changed by [mutate], sealed again under the epoch's key with
     * [order] (the original's when null) and a fresh salt — new bytes, a new blob hash, so no tombstone stops it. With the
     * body and the order unchanged this is the replay of §6.3.4 layer 2 (and FORGE_OWN when served to the post's author);
     * with a false order it is RESEAL_ORDER (§19.18); [asProposal] and [corrupt] are the other two mutations.
     */
    fun reseal(
        member: ChannelClient,
        id: ChannelId,
        blob: ByteArray,
        order: ChannelCrypto.SealOrder? = null,
        mutate: (ByteArray) -> ByteArray = { it },
        /** The epoch whose key seals it (the order's when null): another epoch's key is the forgery CS-S7 refuses. */
        keyEpoch: Long? = null,
    ): ByteArray {
        val v = view(member, id)
        val opened = openEpochBlob(member, id, blob)
        val o = order ?: opened.order
        val sealEpoch = keyEpoch ?: o.epoch
        val kEnv = epochKeys(member, id, v.day).firstOrNull { it.first == sealEpoch }?.second
            ?: throw AssertionError("${member.name} holds no key of epoch $sealEpoch")
        val body = mutate(opened.body.copyOf())
        val bucket = ChannelTime.bucket(body.size, 0) ?: error("a body larger than any bucket")
        return v.crypto.seal(id.toByteArray(), kEnv, ChannelCrypto.KEY_CLASS_EPOCH, v.gNs, bucket, ChannelCrypto.MODE_EPOCH, o, body).ok()
    }

    /** The facade's answer when a member asks it to seal [blob]'s body, with its own order, under [keyEpoch]'s key. */
    fun trySealUnder(member: ChannelClient, id: ChannelId, blob: ByteArray, keyEpoch: Long): MlsOutcome<ByteArray> {
        val v = view(member, id)
        val opened = openEpochBlob(member, id, blob)
        val kEnv = epochKeys(member, id, v.day).first { it.first == keyEpoch }.second
        val bucket = ChannelTime.bucket(opened.body.size, 0) ?: error("a body larger than any bucket")
        return v.crypto.seal(id.toByteArray(), kEnv, ChannelCrypto.KEY_CLASS_EPOCH, v.gNs, bucket, ChannelCrypto.MODE_EPOCH, opened.order, opened.body)
    }

    /**
     * The offset of a PrivateMessage's `content_type` in its `MLSMessage` encoding (RFC 9420 §6.3.2): `version(2) ‖
     * wire_format(2) ‖ group_id<V> ‖ epoch(8)`, the length of `group_id` an MLS variable-length integer (§2.1.2).
     */
    private fun contentTypeOffset(mls: ByteArray): Int {
        val first = mls[4].toInt() and 0xff
        val (lengthBytes, length) = when (first ushr 6) {
            0 -> 1 to (first and 0x3f)
            1 -> 2 to (((first and 0x3f) shl 8) or (mls[5].toInt() and 0xff))
            else -> throw AssertionError("a group id longer than this harness reads")
        }
        return 4 + lengthBytes + length + 8
    }

    /**
     * PROPOSE (§19.16), as far as the facade lets a member build one (finding F-S4-6: no proposal function): the message's
     * header content type set to `proposal` (RFC 9420: 2), to be sealed with the order `(epoch, 0, 0)` a handshake
     * message carries. Its ciphertext no longer decrypts (the content type is authenticated); the engine must drop it by
     * its header before `process_message`, which is what the counter tells apart from a decryption failure.
     */
    fun asProposal(mls: ByteArray): ByteArray {
        val out = mls.copyOf()
        val at = contentTypeOffset(out)
        check(out[at].toInt() == 1) { "not an application message" }
        out[at] = 2
        return out
    }

    /** An undecryptable copy: the last byte of the ciphertext (its AEAD tag) flipped; the header and the order intact. */
    fun corrupt(mls: ByteArray): ByteArray {
        val out = mls.copyOf()
        out[out.size - 1] = (out[out.size - 1].toInt() xor 1).toByte()
        return out
    }

    private fun apply(rows: List<MlsRow>, changes: List<MlsChange>): List<MlsRow> = MlsRows.applied(rows, changes)
}
