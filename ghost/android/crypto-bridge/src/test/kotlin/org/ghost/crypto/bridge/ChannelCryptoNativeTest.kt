package org.ghost.crypto.bridge

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * A channel round through the closed surface (Phase 10 design §6.1 … §6.3, §10.2; slice S2b):
 * three members, each its own context — create, two invites (an open one and, in a password
 * channel, the password path), accept (parse, KeyPackage, join request sealed under `JK_g`),
 * verify and admit both in one commit, settle, join from the Welcome blobs, a post sealed under
 * `K_ep` and received by the others, a committer's self-update with its trial count and its
 * settle everywhere, the roster's epoch authenticators equal at every member, the sweep and the
 * clearing of a pending commit — every function of §10.2 but the reserved 16, with Kotlin holding
 * nothing but wrapped rows, envelopes and recognition keys (value semantics, §3.4).
 */
class ChannelCryptoNativeTest {

    private val day = 20_725
    private val channel = ByteArray(32) { (0x40 + it).toByte() }
    private val members = ArrayList<Member>()

    /** One member: its context, its rows, its current epoch and generation. */
    private class Member(val crypto: ChannelCrypto, val seed: ByteArray) {
        val rows = LinkedHashMap<String, MlsRow>()
        lateinit var p: ByteArray
        var epoch: EpochKeys? = null
        var generation: GenerationValues? = null
        var seq = 0

        fun rows(): List<MlsRow> = rows.values.toList()

        fun apply(changes: List<MlsChange>) {
            for (c in changes) {
                val k = "${c.scope}:${c.key.joinToString("") { "%02x".format(it) }}"
                if (c.env == null) rows.remove(k) else rows[k] = MlsRow(c.scope, c.key, c.env)
            }
        }
    }

    @Before
    fun setUp() {
        val path = System.getProperty(MlsNative.HOST_LIBRARY_PROPERTY)
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", !path.isNullOrEmpty() && MlsNative.isAvailable())
    }

    @After
    fun tearDown() {
        for (m in members) m.crypto.close()
    }

    private fun <T> MlsOutcome<T>.ok(): T = when (this) {
        is MlsOutcome.Ok -> value
        is MlsOutcome.Refused -> throw AssertionError("refused: $refusal")
    }

    private fun member(i: Int): Member {
        val crypto = ChannelCrypto.open(ByteArray(32) { (i * 13 + it).toByte() }).ok()
        val m = Member(crypto, ByteArray(32) { (i * 31 + it + 1).toByte() })
        m.p = crypto.openChannel(channel, m.seed).ok()
        members.add(m)
        return m
    }

    /** An invite by [sponsor], accepted by a new member: its KeyPackage and the commit's evidence. */
    private fun invite(sponsor: Member, joiner: Member, password: CharArray?): Pair<ByteArray, AdmitEvidence> {
        val g = sponsor.generation!!
        val built = sponsor.crypto.inviteBuild(channel, sponsor.rows(), g.gEnv, g.generation.toInt(), day + 7, password, false, day).ok()
        assertEquals(ChannelInvite.INVITE_BYTES, built.invite.size)
        assertEquals(if (password == null) 0 else 1, built.kdfCode)
        val link = ChannelInvite.toLink(built.invite)
        val parsed = joiner.crypto.inviteParse(ChannelInvite.fromLink(link)!!, password, byteArrayOf(0)).ok()
        assertArrayEquals(channel, parsed.channelId)
        assertArrayEquals(g.ns, parsed.ns)
        assertArrayEquals(g.rJoin, parsed.rJoin)
        assertArrayEquals(built.invitePk, parsed.invitePk)
        val kp = joiner.crypto.keyPackage(channel, 1, day).ok()
        assertEquals(395, kp.keyPackage.size)
        joiner.apply(kp.changes)
        val body = joiner.crypto.joinRequest(channel, parsed.inviteId, parsed.inviteSeedEnv, kp.keyPackage).ok()
        // The request travels sealed under JK_g (mode 0x12), recognised by R_join, opened by the sponsor.
        // The invitee's JK_g is an invite's (class 6, §19.36): never the channel's own class 3, and
        // it opens no join request.
        val blob = joiner.crypto.seal(channel, parsed.jkEnv, ChannelCrypto.KEY_CLASS_INVITE_JOIN, parsed.ns, 4096, ChannelCrypto.MODE_JOIN, ChannelCrypto.SealOrder.NONE, body).ok()
        assertEquals(
            MlsCode.STATE_CORRUPT,
            joiner.crypto.seal(channel, parsed.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, parsed.ns, 4096, ChannelCrypto.MODE_JOIN, ChannelCrypto.SealOrder.NONE, body).code,
        )
        assertEquals(
            MlsCode.INVALID_POLICY,
            joiner.crypto.open(channel, parsed.jkEnv, ChannelCrypto.KEY_CLASS_INVITE_JOIN, parsed.ns, ChannelCrypto.MODE_JOIN, blob).code,
        )
        assertTrue(ChannelRecognition.matches(blob, g.rJoin, ChannelCrypto.MODE_JOIN))
        val opened = sponsor.crypto.open(channel, g.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, g.ns, ChannelCrypto.MODE_JOIN, blob).ok()
        assertArrayEquals(body, opened.body)
        val verified = sponsor.crypto.joinVerify(channel, opened.body, built.inviteId + built.invitePk, null, g.generation.toInt()).ok()
        assertArrayEquals(joiner.p, verified.pseudonym)
        assertArrayEquals(kp.kpRef, verified.kpRef)
        val evidence = AdmitEvidence(
            verified.kpRef, built.inviteId, built.invitePk, built.expiryDay, sponsor.p, built.sponsorSig,
            verified.auth.bytes(MlsField.INVITE_SIG),
        )
        // The INVITE_ISSUED record the sponsor posts round-trips through the content codec.
        val issued = ChannelContentFields(
            kind = 3, opId = ByteArray(16) { 3 }, authorMinute = day * 1440L, timerCode = 4,
            inviteId = built.inviteId, invitePk = built.invitePk, expiryDay = built.expiryDay,
            sponsorSig = built.sponsorSig, committersDigest = built.committersDigest, pwVersion = built.pwVersion,
        )
        val encoded = ChannelCrypto.contentEncode(issued).ok()
        assertArrayEquals(built.sponsorSig, ChannelCrypto.contentDecode(encoded).ok().sponsorSig)
        joiner.generation = GenerationValues(parsed.generation, 0, ByteArray(0), parsed.ns, parsed.jkEnv, parsed.rJoin)
        inviteState[joiner] = parsed
        return kp.keyPackage to evidence
    }

    private val inviteState = HashMap<Member, ChannelCrypto.InviteParsed>()

    private fun policy(owner: Member, flags: Int, pwVersion: Int) =
        ChannelPolicy(channel, 0, 4, 0, 0, flags, 63, pwVersion, ByteArray(0), listOf(owner.p), listOf(owner.p))

    @Test
    fun threeMembersCreateAdmitPostSelfUpdateAndAgree() {
        val a = member(1)
        val b = member(2)
        val c = member(3)
        val created = a.crypto.groupCreate(channel, policy(a, 1, 0), day).ok()
        a.apply(created.changes)
        a.epoch = created.epoch
        a.generation = created.generation
        assertEquals(0L, created.epoch.epoch)
        assertEquals(32, created.boxPk.size)

        val (kpB, evB) = invite(a, b, null)
        val (kpC, evC) = invite(a, c, null)
        val g0 = a.generation!!
        val request = CommitRequest(
            adds = listOf(kpB to evB, kpC to evC), commitMinute = day * 1440L, floor = 4096,
            generation = g0.generation, openEpoch = g0.openEpoch, gEnv = g0.gEnv,
        )
        val committed = a.crypto.commit(channel, a.rows(), request, day).ok()
        assertTrue(committed.summary.isValid)
        assertEquals(listOf(0L, 1L), committed.keptAdds)
        assertEquals(2, committed.welcomes.size)
        assertEquals(2, committed.joiners.size)
        a.apply(committed.changes)
        // The owner settles its own commit; the joiners join from their Welcome blobs, which travel
        // sealed in mode 0x13 under JK_g.
        val settled = a.crypto.settle(channel, a.rows(), ChannelCrypto.Winner.Own(committed.commit), 0, day).ok()
        a.apply(settled.changes)
        assertEquals(1, settled.standing)
        a.epoch = settled.epoch
        assertEquals(1L, settled.epoch!!.epoch)
        assertEquals(2, settled.added.size)
        for ((joiner, blobBody) in listOf(b, c).zip(committed.welcomes)) {
            val sealed = a.crypto.seal(channel, g0.jkEnv, ChannelCrypto.KEY_CLASS_JOIN, g0.ns, 16384, ChannelCrypto.MODE_WELCOME, ChannelCrypto.SealOrder.NONE, blobBody).ok()
            val parsed = inviteState.getValue(joiner)
            assertTrue(ChannelRecognition.matches(sealed, parsed.rJoin, ChannelCrypto.MODE_WELCOME))
            val welcome = joiner.crypto.open(channel, parsed.jkEnv, ChannelCrypto.KEY_CLASS_INVITE_JOIN, parsed.ns, ChannelCrypto.MODE_WELCOME, sealed).ok().body
            val joined = joiner.crypto.welcomeJoin(
                channel, joiner.rows(), welcome, day, parsed.generation.toInt(), parsed.ns,
                ChannelCrypto.Anchor.Invite(parsed.committersDigest),
            ).ok()
            joiner.apply(joined.changes)
            joiner.epoch = joined.epoch
            joiner.generation = joined.generation
            assertEquals(3, joined.roster.size)
            assertArrayEquals(a.p, joined.context.committers.single())
            assertArrayEquals(settled.epoch?.epochAuthenticator, joined.epoch.epochAuthenticator)
        }

        // A post: encoded natively, encrypted with ChannelOrder, sealed under K_ep(1), recognised by
        // R_ep(1), opened and received by the others.
        val content = ChannelContentFields(kind = 1, opId = ByteArray(16) { 7 }, authorMinute = day * 1440L + 5, timerCode = 4, text = "salut, canal".toByteArray())
        val encoded = ChannelCrypto.contentEncode(content).ok()
        a.seq++
        val encrypted = a.crypto.encrypt(channel, a.rows(), encoded, a.seq, day).ok()
        a.apply(encrypted.changes)
        val epoch = a.epoch!!
        val blob = a.crypto.seal(
            channel, epoch.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, a.generation!!.ns, 4096, ChannelCrypto.MODE_EPOCH,
            ChannelCrypto.SealOrder(epoch.epoch, encrypted.senderLeaf.toInt(), a.seq), encrypted.mls,
        ).ok()
        for (m in listOf(b, c)) {
            val e = m.epoch!!
            val candidate = ChannelRecognition.matchFirst(
                blob,
                sequenceOf(
                    ChannelRecognition.Candidate(m.generation!!.rJoin, ChannelCrypto.MODE_JOIN, "join"),
                    ChannelRecognition.Candidate(e.rEp, ChannelCrypto.MODE_EPOCH, "epoch"),
                ),
            )
            assertEquals("epoch", candidate?.value)
            val opened = m.crypto.open(channel, e.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, m.generation!!.ns, ChannelCrypto.MODE_EPOCH, blob).ok()
            assertEquals(1L, opened.headerEpoch)
            assertEquals(1, opened.contentType)
            assertEquals(encrypted.senderLeaf, opened.aadLeaf)
            val received = m.crypto.receive(channel, m.rows(), 1, listOf(opened.body), day).ok()
            m.apply(received.changes)
            val item = received.items.single() as ChannelCrypto.Item.App
            assertArrayEquals(a.p, item.sender)
            assertEquals("salut, canal", String(item.content.text!!))
            // The same message again is consumed: refused inside the batch, nothing to apply.
            val replay = m.crypto.receive(channel, m.rows(), 1, listOf(opened.body), day).ok()
            assertTrue(replay.items.single() is ChannelCrypto.Item.Failed)
        }

        // A committer's self-update (a PCS commit): validated by the others, counted by a trial,
        // settled everywhere; the epoch authenticators agree.
        val g = a.generation!!
        val update = a.crypto.commit(
            channel, a.rows(),
            CommitRequest(commitMinute = day * 1440L + 9, floor = 4096, generation = g.generation, openEpoch = g.openEpoch, gEnv = g.gEnv),
            day,
        ).ok()
        a.apply(update.changes)
        for (m in listOf(b, c)) {
            val summary = (m.crypto.receive(channel, m.rows(), 1, listOf(update.commit), day).ok().items.single() as ChannelCrypto.Item.Commit).summary
            assertTrue(summary.isValid)
            assertEquals(0, summary.rank)
            assertArrayEquals(a.p, summary.sender)
            val trial = m.crypto.trialCount(channel, m.rows(), ChannelCrypto.Winner.Foreign(update.commit), emptyList(), day).ok()
            assertArrayEquals(a.p, trial.committer)
            assertTrue(trial.senders.isEmpty())
            val s = m.crypto.settle(channel, m.rows(), ChannelCrypto.Winner.Foreign(update.commit), 0, day).ok()
            m.apply(s.changes)
            m.epoch = s.epoch
        }
        val own = a.crypto.settle(channel, a.rows(), ChannelCrypto.Winner.Own(update.commit), 0, day).ok()
        a.apply(own.changes)
        a.epoch = own.epoch
        val authenticators = listOf(a, b, c).map { m ->
            val roster = m.crypto.roster(channel, m.rows(), day).ok()
            assertEquals(2L, roster.epoch)
            assertEquals(3, roster.members.size)
            assertArrayEquals(roster.epochAuthenticator, m.epoch!!.epochAuthenticator)
            roster.epochAuthenticator
        }
        assertArrayEquals(authenticators[0], authenticators[1])
        assertArrayEquals(authenticators[0], authenticators[2])

        // The sweep of past epochs and the clearing of a pending commit write change-sets.
        b.apply(b.crypto.sweepPast(channel, b.rows(), 0, day).ok())
        assertEquals(MlsCode.OK, b.crypto.roster(channel, b.rows(), day).code)
        val pending = a.crypto.commit(
            channel, a.rows(),
            CommitRequest(commitMinute = day * 1440L + 11, floor = 4096, generation = g.generation, openEpoch = g.openEpoch, gEnv = g.gEnv),
            day,
        ).ok()
        a.apply(pending.changes)
        assertEquals(MlsCode.PENDING_COMMIT, a.crypto.commit(
            channel, a.rows(),
            CommitRequest(commitMinute = day * 1440L + 12, floor = 4096, generation = g.generation, openEpoch = g.openEpoch, gEnv = g.gEnv),
            day,
        ).code)
        a.apply(a.crypto.clearOwn(channel, a.rows(), day).ok())
        assertEquals(MlsCode.OK, a.crypto.roster(channel, a.rows(), day).code)
        // A floor that is not the class's is refused before anything runs (§19.31 M2).
        val wrongFloor = a.crypto.commit(
            channel, a.rows(),
            CommitRequest(commitMinute = day * 1440L + 13, floor = 16384, generation = g.generation, openEpoch = g.openEpoch, gEnv = g.gEnv),
            day,
        )
        assertEquals(MlsCode.INVALID_POLICY, wrongFloor.code)
    }

    @Test
    fun aPasswordChannelInvitesWithItsPasswordOnly() {
        val a = member(4)
        val b = member(5)
        // A password channel: flag bit 2, pw_version 1, members may not invite (Q46 (b)).
        val created = a.crypto.groupCreate(channel, policy(a, 4, 1), day).ok()
        a.apply(created.changes)
        a.epoch = created.epoch
        a.generation = created.generation
        val g = created.generation
        // No password, or kdf 0, in a password channel: refused (the flag decides, §19.29.3).
        assertEquals(MlsCode.INVALID_POLICY, a.crypto.inviteBuild(channel, a.rows(), g.gEnv, 0, day + 7, null, false, day).code)
        assertEquals(MlsCode.PASSWORD_REQUIRED, a.crypto.inviteBuild(channel, a.rows(), g.gEnv, 0, day + 7, CharArray(0), false, day).code)
        // An expiry beyond seven days is refused.
        assertEquals(MlsCode.INVALID_POLICY, a.crypto.inviteBuild(channel, a.rows(), g.gEnv, 0, day + 8, "parola".toCharArray(), false, day).code)
        val password = "cabin frost ladder margin orbit".toCharArray()
        val built = a.crypto.inviteBuild(channel, a.rows(), g.gEnv, 0, day + 7, password, true, day).ok()
        assertEquals(1, built.kdfCode)
        assertEquals(1, built.pwVersion)
        assertTrue(ChannelInvite.needsPassword(built.invite))
        assertEquals(MlsCode.PASSWORD_REQUIRED, b.crypto.inviteParse(built.invite, null, ByteArray(0)).code)
        assertEquals(MlsCode.WRONG_PASSWORD, b.crypto.inviteParse(built.invite, "cabin frost".toCharArray(), ByteArray(0)).code)
        val parsed = b.crypto.inviteParse(built.invite, password, ByteArray(0)).ok()
        assertEquals(1, parsed.kdfCode)
        assertTrue(parsed.slots.isEmpty())
        assertArrayEquals(g.ns, parsed.ns)
        // The facade zeroes its own copy, never the caller's array.
        assertEquals("cabin frost ladder margin orbit", String(password))
        // NFKD: a precomposed and a decomposed spelling are one password.
        val composed = "pârolă".toCharArray()
        val decomposed = java.text.Normalizer.normalize("pârolă", java.text.Normalizer.Form.NFD).toCharArray()
        assertFalse(composed.contentEquals(decomposed))
        assertArrayEquals(ChannelPassword.nfkdUtf8(composed), ChannelPassword.nfkdUtf8(decomposed))
        assertNull(ChannelPassword.nfkdUtf8(charArrayOf('\uDC00')))
        assertNotNull(ChannelPassword.nfkdUtf8(charArrayOf('\uD83D', '\uDC4D')))
    }
}
