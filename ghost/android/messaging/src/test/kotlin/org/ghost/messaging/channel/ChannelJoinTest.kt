package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelContentFields
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.ChannelAdmissionTest.Companion.create
import org.ghost.messaging.channel.ChannelAdmissionTest.Companion.invite
import org.ghost.messaging.channel.engine.ChannelCounters.Reason
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **JN, the join suite** (Phase 10 design §12.6; slice S4's part of it), over the real OpenMLS and the model relay's
 * hostile modes of admission and join: a forged Welcome of a member's own group (FAKE_WELCOME, S0-15), a substituted
 * Welcome (REPLACE_BOOTSTRAP, PC-17), a lost Welcome and the join's expiry (DROP_WELCOME), a request copied into another
 * namespace (COPY_JOIN), a request replayed by an insider (REPLAY_JOIN), the password of §19.28, the single use of an
 * invite, a member's invite admitted by the owner, a request that reaches the committer before its `INVITE_ISSUED`, and
 * the refusals of `CH-ACCEPT`; and (§19.38) a member's `INVITE_ISSUED` planted under a lower id with the real key, which
 * must not capture the request, and the records no admission could use, which are not kept.
 */
class ChannelJoinTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** [joiner] accepts [link] and the owner admits it: the request, the pass, the settle, the Welcome. */
    private fun join(w: ChannelWorld, owner: ChannelClient, joiner: ChannelClient, link: ByteArray, password: CharArray? = null) {
        assertEquals(AcceptResult.PENDING, joiner.engine.accept(link, password))
        admitPending(w, owner)
    }

    private fun admitPending(w: ChannelWorld, owner: ChannelClient) {
        w.quiesce()
        // CO-8: a scheduled pass at most once per 6 hours, so a second admission comes a session later
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
    }

    /** The world of most cases: an open channel of the owner's, and charlie, a member admitted by the owner's invite. */
    private fun withMember(w: ChannelWorld): Triple<ChannelClient, ChannelClient, ChannelId> {
        val owner = w.client("owner")
        val charlie = w.client("charlie")
        val id = create(owner)
        join(w, owner, charlie, invite(owner, id))
        assertEquals(ChannelState.ACTIVE, charlie.channel(id)!!.state)
        return Triple(owner, charlie, id)
    }

    private fun requestBlob(w: ChannelWorld, from: String): ByteArray =
        w.relay.stored.last { it.purpose == "join" && it.from == from }.ciphertext

    @Test
    fun aForgedWelcomeOfAMembersOwnGroupIsRefusedByTheAnchorAndTheRealOneThenJoins() = ChannelWorld().use { w ->
        val (owner, charlie, id) = withMember(w)
        val bob = w.client("bob")
        // charlie, a member, sponsors bob: charlie's INVITE_ISSUED reaches the owner, bob's request reaches everyone
        val link = invite(charlie, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        assertEquals("the owner recorded charlie's invite", 2L, owner.count("ch_invite_issued"))
        assertEquals("the owner recorded bob's request", 1L, owner.count("ch_join_request"))
        assertEquals("charlie, no committer, recorded none", 0L, charlie.count("ch_join_request"))
        val keyRows = bob.count("mls_global_kv")
        // FAKE_WELCOME: charlie forks the channel into a group of its own and Welcomes bob's KeyPackage into it
        val forged = ChannelAdversary.forgeWelcome(charlie, id, requestBlob(w, "bob"))
        w.relay.modes = setOf(ModelChannelRelay.Mode.FAKE_WELCOME)
        w.relay.inject(ChannelAdversary.namespace(charlie, id), forged, w.now, "welcome")
        w.quiesce()
        assertEquals("the anchor refused the forgery", 1, bob.counters[Reason.INVALID_WELCOME])
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        assertEquals("nothing of the forgery was written: the KeyPackage is intact", keyRows, bob.count("mls_global_kv"))
        assertEquals(1L, bob.count("ch_join"))
        // the real Welcome then joins
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertEquals(PostResult.QUEUED, bob.engine.post(id, "acasă".toByteArray(), null))
        w.quiesce()
        assertTrue(owner.displayed(id).contains("acasă"))
        assertTrue(charlie.displayed(id).contains("acasă"))
    }

    @Test
    fun aSubstitutedWelcomeIsRefusedAndTheJoinerWaitsForTheRealOne() = ChannelWorld().use { w ->
        val (owner, charlie, id) = withMember(w)
        val bob = w.client("bob")
        val link = invite(charlie, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        // REPLACE_BOOTSTRAP: the relay holds the honest Welcome back and serves charlie's substitute in its place
        w.relay.modes = setOf(ModelChannelRelay.Mode.REPLACE_BOOTSTRAP)
        w.relay.inject(ChannelAdversary.namespace(charlie, id), ChannelAdversary.forgeWelcome(charlie, id, requestBlob(w, "bob")), w.now, "welcome")
        admitPending(w, owner)
        assertEquals(1, bob.counters[Reason.INVALID_WELCOME])
        assertEquals("the joiner keeps waiting (PC-17)", ChannelState.JOINING, bob.channel(id)!!.state)
        w.relay.modes = emptySet()
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertEquals("the joiner is at the owner's epoch", owner.channel(id)!!.epoch, bob.channel(id)!!.epoch)
    }

    @Test
    fun aDroppedWelcomeExpiresTheJoinAndTheGhostLeafIsNotReadmittedByAJoin() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = create(owner)
        val link = owner.engine.invite(id, 1, null).link!!
        w.relay.modes = setOf(ModelChannelRelay.Mode.DROP_WELCOME)
        join(w, owner, bob, link)
        assertEquals(1, w.relay.dropped)
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        assertTrue(bob.count("mls_global_kv") > 0)
        // at expiry_day + 1 without a Welcome the join expires (§6.2.2 step 4): the KeyPackage's keys go, listening stops
        w.advance(2 * DmWorld.DAY)
        bob.timePass()
        assertEquals(ChannelState.JOIN_EXPIRED, bob.channel(id)!!.state)
        assertEquals(0L, bob.count("mls_global_kv"))
        assertEquals(0L, bob.count("ch_box_key"))
        assertEquals(0L, bob.count("sync_namespace", "consumer = 'channel' AND listening = 1"))
        // a new invite re-enters joining (§6.11) ...
        w.relay.modes = emptySet()
        val again = invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(again, null))
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
        assertEquals(1L, bob.count("ch_join"))
        // ... but the commit that lost its Welcome merged at the owner: bob's pseudonym is a current member, and a join of a
        // current member is refused (§6.2.4 (A)); the way back is the restore of S7 or the eviction of S6 (§19.37 F-S4-8)
        admitPending(w, owner)
        assertEquals(1, owner.counters[Reason.ADMISSION_REFUSED])
        assertEquals(ChannelState.JOINING, bob.channel(id)!!.state)
    }

    @Test
    fun aJoinRequestCopiedToAnotherNamespaceOpensNowhereAndIsAdmittedOnce() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val first = create(owner)
        w.advance(DmWorld.MINUTE)
        val second = owner.engine.create("altul".toByteArray(), 4, 0, false).channel!!
        val link = invite(owner, first)
        // a blob in the second channel's namespace, so the relay knows it
        assertEquals(PostResult.QUEUED, owner.engine.post(second, "aici".toByteArray(), null))
        w.quiesce()
        w.relay.modes = setOf(ModelChannelRelay.Mode.COPY_JOIN)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        assertTrue("the relay copied the request", w.relay.copies >= 1)
        assertEquals("one request, in the first channel", 1L, owner.count("ch_join_request"))
        val firstId = first.toByteArray()
        assertEquals(1L, owner.count("ch_join_request", "channel_id = ?", firstId))
        w.relay.modes = emptySet()
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, bob.channel(first)!!.state)
        assertNull("the copy made bob nothing of the second channel", bob.channel(second))
        assertEquals("the second channel admitted nobody", 0L, owner.count("ch_sponsor", "channel_id = ?", second.toByteArray()))
        assertEquals(1L, owner.count("ch_sponsor", "channel_id = ?", firstId))
    }

    @Test
    fun aReplayedJoinRequestIsIgnoredWhilePendingAndRefusedOnceItsInviteIsConsumed() = ChannelWorld().use { w ->
        val (owner, charlie, id) = withMember(w)
        val bob = w.client("bob")
        val link = invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        val original = requestBlob(w, "bob")
        // REPLAY_JOIN while the request is pending: a second request for one invite is ignored (§6.2.4)
        w.relay.modes = setOf(ModelChannelRelay.Mode.REPLAY_JOIN)
        w.relay.inject(ChannelAdversary.namespace(charlie, id), ChannelAdversary.resealRequest(charlie, id, original), w.now, "join")
        w.quiesce()
        assertEquals(1, owner.counters[Reason.DUPLICATE])
        assertEquals(1L, owner.count("ch_join_request"))
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        // ... and after the admission: the invite is consumed and the KeyPackage's tag is held
        assertEquals("charlie's invite and bob's", 2L, owner.count("ch_invite_issued", "consumed = 1"))
        assertTrue(owner.count("ch_kp_seen") >= 1)
        w.relay.inject(ChannelAdversary.namespace(charlie, id), ChannelAdversary.resealRequest(charlie, id, original), w.now, "join")
        w.quiesce()
        assertEquals(1, owner.counters[Reason.JOIN_REFUSED])
        assertEquals(0L, owner.count("ch_join_request"))
        assertEquals("one admission", 3, w.clients.count { it.channel(id)?.state == ChannelState.ACTIVE })
    }

    @Test
    fun aPasswordChannelAdmitsWithItsPasswordOnly() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = create(owner, password = true)
        assertTrue(owner.channel(id)!!.pwRequired)
        // the committer's invite needs the password; without one it is refused before any native call
        assertEquals(InviteResult.Status.PASSWORD_REQUIRED, owner.engine.invite(id, 7, null).status)
        val password = "cabin frost ladder margin orbit".toCharArray()
        val link = invite(owner, id, password)
        // the invitee: no password, a wrong one, then the right one (§19.28.4 step 3)
        assertEquals(AcceptResult.PASSWORD_REQUIRED, bob.engine.accept(link, null))
        assertEquals(AcceptResult.WRONG_PASSWORD, bob.engine.accept(link, "cabin frost".toCharArray()))
        assertNull("nothing written by a wrong password", bob.channel(id))
        join(w, owner, bob, link, password)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertTrue(bob.channel(id)!!.pwRequired)
        assertEquals("the caller's array is the caller's (§19.36 row 6)", "cabin frost ladder margin orbit", String(password))
        // a member that is no committer may not invite in a password channel (Q46 (b))
        assertEquals(InviteResult.Status.NOT_ALLOWED, bob.engine.invite(id, 7, "x".toCharArray()).status)
        // the sponsor's own link of a password invite is not kept (Q50 (a))
        assertEquals(1L, owner.count("ch_invite_own", "invite_env IS NULL"))
        assertEquals(0L, owner.count("ch_invite_own", "invite_env IS NOT NULL"))
    }

    @Test
    fun anInviteIsSingleUseAndTheSecondRequestForItIsIgnored() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val dave = w.client("dave")
        val id = create(owner)
        val link = invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        assertEquals(AcceptResult.PENDING, dave.engine.accept(link, null))
        admitPending(w, owner)
        val states = listOf(bob, dave).map { it.channel(id)!!.state }
        assertEquals("exactly one of the two joined", 1, states.count { it == ChannelState.ACTIVE })
        assertEquals(1, states.count { it == ChannelState.JOINING })
        assertEquals(1, owner.counters[Reason.DUPLICATE])
        assertEquals(1L, owner.count("ch_sponsor"))
    }

    @Test
    fun aRequestThatArrivesBeforeItsInviteIssuedWaitsForTheRecord() = ChannelWorld().use { w ->
        val (owner, charlie, id) = withMember(w)
        val bob = w.client("bob")
        // the relay keeps charlie's INVITE_ISSUED back: bob's request reaches the owner first
        w.relay.hold = { it.from == "charlie" && it.purpose == "request" }
        val link = invite(charlie, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        w.quiesce()
        assertTrue(owner.counters[Reason.JOIN_UNKNOWN_INVITE] >= 1)
        assertEquals("deferred, not recorded", 0L, owner.count("ch_join_request"))
        w.relay.hold = { false }
        w.quiesce()
        assertEquals("the record re-offered the request", 1L, owner.count("ch_join_request"))
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
    }

    /** An `INVITE_ISSUED` record as a modified member's client could post it. */
    private fun issued(w: ChannelWorld, inviteId: ByteArray, invitePk: ByteArray, expiryDay: Long, digest: ByteArray, pwVersion: Int? = null) =
        ChannelContentFields(
            kind = 3, opId = ChannelWorld.sha256("op:" + ChannelWorld.hex(inviteId)).copyOf(16), authorMinute = Math.floorDiv(w.now, DmWorld.MINUTE),
            timerCode = 4, inviteId = inviteId, invitePk = invitePk, expiryDay = expiryDay, sponsorSig = ByteArray(64) { 1 },
            committersDigest = digest, pwVersion = pwVersion,
        )

    /**
     * §19.38 (the review of S4, finding 2): bob, a member, plants an `INVITE_ISSUED` under an invite id that sorts first,
     * with the real invite's public key. The first version bound dave's request to the first record whose key verified
     * it — bob's — and the admission then refused it (the invitee's signature names the real id) and spent dave's
     * KeyPackage: any member could capture any invite for the price of one post. The request is bound to the record of
     * the id the invitee signed.
     */
    @Test
    fun aRecordPlantedUnderALowerInviteIdDoesNotCaptureTheJoinRequest() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val link = invite(owner, id)
        w.quiesce()
        val real = bob.database.transaction { tx -> bob.channelStores.invites.issuedOf(tx.sql, id.toByteArray(), DmTime.day(w.now)) }.single()
        ChannelAdversary.postAs(bob, id, issued(w, ByteArray(16), real.invitePk, real.expiryDay, real.committersDigest), handshake = true)
        w.quiesce()
        assertEquals("the owner records both (bob may invite: members may)", 2L, owner.count("ch_invite_issued", "consumed = 0"))
        assertEquals(AcceptResult.PENDING, dave.engine.accept(link, null))
        w.quiesce()
        assertEquals("the request names the invite dave signed", 1L, owner.count("ch_join_request", "invite_id = ?", real.inviteId))
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertEquals(0, owner.counters[Reason.ADMISSION_REFUSED])
        assertEquals("the real invite is spent", 1L, owner.count("ch_invite_issued", "consumed = 1 AND invite_id = ?", real.inviteId))
        assertEquals("the planted record admitted nobody", 1L, owner.count("ch_invite_issued", "consumed = 0"))
    }

    /**
     * §19.38: a record no admission could use is not recorded — an expiry beyond §5.9's `issue day + 7` (the first version
     * kept such a record for ever), and in a password channel a member's, who may not invite there (Q46 (b), CO-2 (A)).
     */
    @Test
    fun anInviteIssuedNoAdmissionCouldUseIsNotRecorded() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val day = DmTime.day(w.now)
        val held = owner.count("ch_invite_issued")
        ChannelAdversary.postAs(bob, id, issued(w, ByteArray(16) { 3 }, ByteArray(32) { 5 }, day + 4_000_000L, ByteArray(32) { 6 }), handshake = true)
        w.quiesce()
        assertEquals("an expiry past issue day + 7", held, owner.count("ch_invite_issued"))
        assertEquals(1, owner.counters[Reason.INVITE_REFUSED])
        // a password channel of the owner's, carol a member who is no committer
        val carol = w.client("carol")
        w.advance(DmWorld.MINUTE)
        val pid = create(owner, password = true)
        val password = "cabin frost ladder margin orbit".toCharArray()
        join(w, owner, carol, invite(owner, pid, password), password)
        assertEquals(ChannelState.ACTIVE, carol.channel(pid)!!.state)
        val pc = pid.toByteArray()
        val before = owner.count("ch_invite_issued", "channel_id = ?", pc)
        ChannelAdversary.postAs(
            carol, pid, issued(w, ByteArray(16) { 4 }, ByteArray(32) { 5 }, DmTime.day(w.now) + 7, ByteArray(32) { 6 }, pwVersion = 1),
            handshake = true,
        )
        w.quiesce()
        assertEquals("a member's record in a password channel", before, owner.count("ch_invite_issued", "channel_id = ?", pc))
        assertEquals(2, owner.counters[Reason.INVITE_REFUSED])
    }

    @Test
    fun acceptRefusesWhatItMust() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = create(owner)
        assertEquals(AcceptResult.INVALID, bob.engine.accept("ghost://channel/abc".toByteArray(), null))
        assertEquals(AcceptResult.INVALID, bob.engine.accept(ByteArray(552) { 'a'.code.toByte() }, null))
        // an expired invite
        val short = owner.engine.invite(id, 1, null).link!!
        w.advance(2 * DmWorld.DAY)
        assertEquals(AcceptResult.EXPIRED, bob.engine.accept(short, null))
        assertNull(bob.channel(id))
        // a channel the client is joining, then a member of: ALREADY_MEMBER, decided after the parse (§19.36 row 3)
        val link = invite(owner, id)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, null))
        assertEquals(AcceptResult.ALREADY_MEMBER, bob.engine.accept(invite(owner, id), null))
        admitPending(w, owner)
        assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
        val before = bob.count("outbox_op")
        assertEquals(AcceptResult.ALREADY_MEMBER, bob.engine.accept(invite(owner, id), null))
        assertEquals("nothing written", before, bob.count("outbox_op"))
        // the limit of 9 channels (§19.8 (e), Q4)
        val carol = w.client("carol")
        repeat(9) { i ->
            w.advance(DmWorld.MINUTE)
            assertEquals(org.ghost.messaging.api.CreateResult.Status.CREATED, carol.engine.create("c$i".toByteArray(), 4, 0, false).status)
        }
        assertEquals(AcceptResult.LIMIT_REACHED, carol.engine.accept(invite(owner, id), null))
        assertEquals(org.ghost.messaging.api.CreateResult.Status.LIMIT_REACHED, carol.engine.create("c9".toByteArray(), 4, 0, false).status)
    }
}
