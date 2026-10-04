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

    private fun apply(rows: List<MlsRow>, changes: List<MlsChange>): List<MlsRow> = MlsRows.applied(rows, changes)
}
