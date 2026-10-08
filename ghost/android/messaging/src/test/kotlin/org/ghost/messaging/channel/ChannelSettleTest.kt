package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.FakeKeyWrapper
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.MlsRows
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The full commit arbitration (SCN-CD's engine half)** — Phase 10 design §6.4 CO-3 … CO-6 with the
 * owner decisions D-4/D-5 of 2026-10-05, over the real OpenMLS: two candidates on one epoch decided
 * by successor senders after a trial settle (CO-3, §6.3.5's bounds: one `trialCount` call per
 * candidate over ≤ 32 held blobs); abandonment (a candidate whose committer moved on is excluded,
 * even ahead on the plain tie-break); the unverified own candidate demoted below a foreign one with
 * equal successors (§19.13); the unverified own commit **adopted** from its successor senders when
 * its op closed INDETERMINATE but a copy reached the relays (MM-32's shape, CO-4 (a)); a fetched
 * copy of the own commit verifying it by hash (D-5); a late commit of a final epoch recorded as a
 * fork signal and never merged (MM-16's shape, CO-6); a finite-lifetime (`LifetimeError`) commit
 * dropped, counted and never blocking (MM-46's shape, §19.29.1); CO-5's invite voiding when the
 * winner changed the committers (S0-15) and when it bumped the password (§19.29.3); and CO-4 (ii):
 * no settle before one listing pass over every relay of the set has completed after the window
 * opened. The commits a scene races are built with the facade ([ChannelAdversary.commit]) — what a
 * modified client can send — and injected through the model relay; the engine-made own commits run
 * through the pass and the outbox outcomes like production.
 *
 * The world's passes run when a test drives them, so a scene's order is load-bearing: a blob a
 * relay serves is **recorded** (sighted, §6.4 CO-4 (i)) only by the receive step of a client's
 * pass — [deliver] runs those receives while the window is still closed; the advances then open
 * the window and a relay round satisfies CO-4 (ii) before the settling pass.
 */
class ChannelSettleTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    // --------------------------------------------------------------------------- the winner (CO-3)

    /** Two candidates on one epoch: the rank-1 one wins because a successor sender's post opens under its trial state. */
    @Test
    fun twoCandidatesOnOneEpochTheOneWithSuccessorSendersWinsTheTrial() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, alice, carol)
        // epoch 2: a rank-0 context change makes bob a committer (rank 1), so his concurrent commit
        // is not a rank-255 self-update (CO-14 would refuse it on his fresh leaf).
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        val b = ChannelAdversary.commit(bob, id)
        val o = ChannelAdversary.commit(owner, id)
        // bob settles his commit before he sees the owner's; carol — holding bob's only — settles it
        // too; alice and the owner hold both. Each author stages its own commit like its pass would
        // ([ChannelAdversary.stageOwn]: at its author the blob is its own message and can never be a
        // foreign candidate); the blobs are held from their authors, and the owner's is held from
        // carol as well (so her branch is bob's).
        w.relay.holdAt = { name, s ->
            (s.purpose == "trial-B" && name == "bob") ||
                (s.purpose == "trial-O" && (name == "owner" || name == "bob" || name == "carol"))
        }
        ChannelAdversary.stageOwn(bob, id, b, rank = 1)
        ChannelAdversary.stageOwn(owner, id, o, rank = 0)
        ChannelAdversary.inject(w, bob, id, b, "trial-B")
        ChannelAdversary.inject(w, owner, id, o, "trial-O")
        deliver(w, owner, bob, alice, carol)
        assertEquals("bob holds his candidate only", 1L, bob.count("ch_candidate"))
        assertEquals("carol holds bob's only", 1L, carol.count("ch_candidate"))
        assertEquals("alice holds both", 2L, alice.count("ch_candidate"))
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        bob.timePass()
        assertEquals(3L, bob.channel(id)!!.epoch)
        assertArrayEquals(b.hash, winnerOf(bob, id, 2))
        carol.timePass()
        assertEquals(3L, carol.channel(id)!!.epoch)
        assertArrayEquals(b.hash, winnerOf(carol, id, 2))
        // bob and carol post on the branch bob's commit opened; the owner and alice cannot open the
        // posts yet (they are of epoch 3) — their receive defers them, which is CO-3's trial input.
        // carol's post is a successor sender of bob's candidate (bob's own post is not — CO-3 counts
        // senders other than the candidate's committer, §6.4).
        ChannelScenes.post(bob, id, "ramura lui bob")
        ChannelScenes.post(carol, id, "de la carol")
        w.pump()
        // the other joiners' requests and Welcomes of the admission are deferred at alice too (she
        // is no committer): what the trial needs is the posts among the held blobs.
        var held = 0L
        alice.sql.query("SELECT count(*) FROM inbox_blob WHERE state = 'fetched'") { held = it.long(0) }
        assertTrue("the posts are held at alice (held=$held)", held >= 2)
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        alice.timePass()
        assertEquals(
            "the successor count, not the rank, decides (CO-3): counters=${alice.counters.snapshot().filter { it.value > 0}} " +
                "winner=" + winnerOf(alice, id, 2)?.joinToString("") { "%02x".format(it) },
            3L, alice.channel(id)!!.epoch,
        )
        val win = winnerOf(alice, id, 2)
        assertArrayEquals(
            "the rank-1 commit with the successors wins over rank 0: counters=${alice.counters.snapshot().filter { it.value > 0}} " +
                "b=${b.hash.joinToString("") { "%02x".format(it) }} o=${o.hash.joinToString("") { "%02x".format(it) }} winner=" +
                win?.joinToString("") { "%02x".format(it) },
            b.hash, win,
        )
        owner.timePass()
        assertArrayEquals(b.hash, winnerOf(owner, id, 2))
        w.quiesce()
        assertTrue(alice.displayed(id).containsAll(listOf("ramura lui bob", "de la carol")))
        assertTrue(alice.integrity().isEmpty())
    }

    /** A candidate whose own committer has a message under another candidate's trial state is excluded — even ahead on rank and tied on successors. */
    @Test
    fun aCandidateWhoseCommitterMovedOnIsAbandonedEvenWithSuccessors() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, bob, alice, carol)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        val o = ChannelAdversary.commit(owner, id)
        val b = ChannelAdversary.commit(bob, id)
        // O reaches the owner (its author) and alice; B reaches bob (its author), carol, alice and the
        // owner; each author stages its own commit like its pass would (at its own device the blob is
        // its own message and can never be a foreign candidate).
        w.relay.holdAt = { name, s ->
            (s.purpose == "ab-O" && (name == "bob" || name == "carol")) ||
                (s.purpose == "ab-B" && name == "bob")
        }
        ChannelAdversary.stageOwn(owner, id, o, rank = 0)
        ChannelAdversary.stageOwn(bob, id, b, rank = 1)
        ChannelAdversary.inject(w, owner, id, o, "ab-O")
        ChannelAdversary.inject(w, bob, id, b, "ab-B")
        deliver(w, owner, bob, alice, carol)
        // carol settles B alone and posts on the branch it opened; the owner — whose staged O has no
        // successor where B has carol's post — settles B as well and posts on B's branch.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        carol.timePass()
        assertArrayEquals(b.hash, winnerOf(carol, id, 2))
        ChannelScenes.post(carol, id, "ramura lui carol")
        w.pump()
        owner.hintPass()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertArrayEquals("B's successor beats the verified own O at the owner (CO-3)", b.hash, winnerOf(owner, id, 2))
        ChannelScenes.post(owner, id, "ramura owner")
        w.pump()
        // alice holds O and B and both posts (of B's branch): the trials give B two successor senders
        // (carol and the owner — B's committer does not count) and O none — and O is abandoned, its
        // committer (the owner) having a message under B's trial state.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        alice.timePass()
        assertEquals(3L, alice.channel(id)!!.epoch)
        assertArrayEquals("abandonment excludes O, which would else win on rank 0", b.hash, winnerOf(alice, id, 2))
        // carol, already settled at epoch 3 on B, receives O late: a fork signal, never a merge (CO-6).
        w.relay.holdAt = { _, _ -> false }
        w.pump()
        carol.hintPass()
        assertEquals("no merge", 3L, carol.channel(id)!!.epoch)
        assertEquals(1, carol[ChannelCounters.Reason.LATE_CANDIDATE])
        assertEquals(1L, carol.count("ch_fork_signal"))
        assertArrayEquals(b.hash, winnerOf(carol, id, 2))
        assertTrue(alice.integrity().isEmpty())
    }

    // ------------------------------------------------------------- the own candidate (CO-4, §19.13)

    /** An own candidate without a verified copy ranks below every held foreign candidate with as many successors. */
    @Test
    fun anUnverifiedOwnCandidateIsDemotedBelowAForeignOneWithEqualSuccessors() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // two owner epochs (2, 3), so bob's rank-255 self-update passes CO-14 (his leaf's
        // refresh_epoch 1 <= e - k with k = min(8, 2) = 2).
        for (e in 1..2) {
            val next = ChannelAdversary.commit(owner, id)
            w.relay.holdAt = { name, s -> s.purpose == "advance-$e" && name == "owner" }
            ChannelAdversary.stageOwn(owner, id, next, rank = 0)
            ChannelAdversary.inject(w, owner, id, next, "advance-$e")
            settleEveryone(w, owner, bob)
        }
        assertEquals(3L, owner.channel(id)!!.epoch)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val f = ChannelAdversary.commit(bob, id)
        // the owner's admission commit and bob's self-update race on epoch 3; the owner's op closes
        // INDETERMINATE, so its own commit stays unverified.
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        assertEquals(1L, owner.count("ch_candidate", "own = 1"))
        w.relay.holdAt = { name, s -> s.purpose == "demote-F" && name == "bob" }
        ChannelAdversary.stageOwn(bob, id, f, rank = 255)
        ChannelAdversary.inject(w, bob, id, f, "demote-F")
        deliver(w, owner, bob)
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        assertEquals(2L, owner.count("ch_candidate"))
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        // no held blob: no trial, every count 0 — the demotion rule alone decides.
        assertEquals(4L, owner.channel(id)!!.epoch)
        assertArrayEquals("the foreign self-update wins over the unverified own commit", f.hash, winnerOf(owner, id, 3))
        assertEquals(0L, owner.count("ch_candidate"))
        assertEquals("dave's request waits for the owner's next pass", 1L, owner.count("ch_join_request"))
        assertEquals(ChannelState.JOINING, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /** MM-32's shape: the op closed INDETERMINATE but a copy reached the relays; others merged it and posted, and the committer adopts its own commit from their successors. */
    @Test
    fun anUnverifiedOwnCommitIsAdoptedFromItsSuccessorSenders() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val id = ChannelScenes.channelOf(w, owner, bob, alice)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        // INDETERMINATE is not FAILED: the relays kept a copy, and everyone but the owner records it.
        deliver(w, owner, bob, alice)
        assertEquals(1L, bob.count("ch_candidate"))
        assertEquals(1L, alice.count("ch_candidate"))
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        // bob and alice settle it and post on the branch it opened.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        bob.timePass()
        alice.timePass()
        assertEquals(2L, bob.channel(id)!!.epoch)
        ChannelScenes.post(bob, id, "de la bob")
        ChannelScenes.post(alice, id, "de la alice")
        w.pump()
        // the owner's op never verified; the receive of the posts defers them, and the trial of its
        // own commit shows the successors: adopted (CO-4 (a)).
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertArrayEquals("the own commit, adopted from its successors", winnerOf(bob, id, 1), winnerOf(owner, id, 1))
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.displayed(id).containsAll(listOf("de la bob", "de la alice")))
        assertTrue(owner.integrity().isEmpty())
    }

    /** D-5: a copy of the own commit that a listing pass fetched verifies the pending commit by its hash and ends the INDETERMINATE wait. */
    @Test
    fun aFetchedCopyOfTheOwnCommitVerifiesItAndEndsTheIndeterminateWait() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        // a listing pass of the owner's fetches a copy of its own commit (its tombstone is gone —
        // swept, say): recognised by its hash (D-5), it verifies the pending commit.
        val stored = w.relay.stored.last { it.from == "owner" && it.purpose == "commit" }
        owner.sql.exec(
            "DELETE FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?",
            listOf(stored.namespace, stored.hash),
        )
        w.relay.inject(stored.namespace, stored.ciphertext, w.now, "own-copy")
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 1"))
        assertEquals(0, owner[ChannelCounters.Reason.FORGED_OWN])
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        assertEquals(2L, owner.channel(id)!!.epoch)
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    // ----------------------------------------------------------------- finality and invalidity (CO-6, §19.29.1)

    /** MM-16's shape at the engine: a valid commit of a final epoch that arrives late is a fork signal — recorded, never validated, never merged. */
    @Test
    fun aLateCommitOfAFinalEpochIsAForkSignalNeverMerged() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val id = ChannelScenes.channelOf(w, owner, bob, alice)
        // an epoch-1 commit built before the admission below, injected after the epoch settled.
        val late = ChannelAdversary.commit(owner, id)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        val winner = winnerOf(owner, id, 1)!!
        // the late blob is the owner's own message at the owner: held from it, judged at the others.
        w.relay.holdAt = { name, s -> s.purpose == "late" && name == "owner" }
        ChannelAdversary.inject(w, owner, id, late, "late")
        w.pump()
        for (client in listOf(bob, alice)) {
            client.hintPass()
            assertEquals("a late candidate never moves a settled member", 2L, client.channel(id)!!.epoch)
            assertEquals(1, client[ChannelCounters.Reason.LATE_CANDIDATE])
            assertEquals(1L, client.count("ch_fork_signal"))
            assertArrayEquals(winner, winnerOf(client, id, 1))
        }
        assertTrue(owner.integrity().isEmpty())
    }

    /** MM-46's shape: a commit carrying a finite-lifetime KeyPackage is a `LifetimeError` refusal — invalid for every member on both branches: dropped, counted, never a candidate, and the settle proceeds. */
    @Test
    fun aCommitWithAFiniteLifetimeKeyPackageIsDroppedCountedAndNeverBlocks() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val id = ChannelScenes.channelOf(w, owner, bob, alice)
        val c = id.toByteArray()
        // bob (a member of any rank) deposits a commit adding a finite-lifetime KeyPackage, expired
        // for every clock, so OpenMLS's refusal branch fires (§19.29.1).
        val day = DmTime.day(bob.clock.now)
        val rows = MlsRows.of(bob.database.transaction { tx -> bob.channelStores.mls.rows(tx.sql, c, day) })
        val stateKey = stateKeyOf(bob)
        val seed = bob.seeds.pseudonymSeed(c) ?: error("no seed")
        val hostNow = System.currentTimeMillis() / 1000
        val out = org.ghost.crypto.bridge.MlsVectors.call(
            org.ghost.crypto.bridge.MlsVectors.FINITE_KP_COMMIT,
            stateKey, c, seed,
            org.ghost.crypto.bridge.MlsVectors.u64(hostNow - 7_200), org.ghost.crypto.bridge.MlsVectors.u64(hostNow + 2),
            org.ghost.crypto.bridge.MlsVectors.rows(rows), org.ghost.crypto.bridge.MlsVectors.u32(day),
        )
        stateKey.fill(0)
        seed.fill(0)
        // the KeyPackage is valid at the build (OpenMLS validates the Add then) and must be expired
        // by the receive, so OpenMLS's refusal branch fires and masks every other defect (V10-11;
        // the Rust probe sleeps the same three seconds).
        Thread.sleep(3_100)
        val finite = ChannelAdversary.Built(out[1], ChannelAdversary.sealHandshake(bob, id, out[1]), emptyList(), null, ByteArray(32))
        // at bob the blob is his own message (his device built it): he can never record it; the
        // owner and alice classify it by the refusal.
        w.relay.holdAt = { name, s -> s.purpose == "finite" && name == "bob" }
        w.relay.inject(ChannelAdversary.namespace(bob, id), finite.blob, w.now, "finite")
        // the owner's admission commits the same epoch.
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        deliver(w, owner, alice)
        for (client in listOf(owner, alice)) {
            assertEquals(
                "the lifetime refusal is counted by its name: counters=${client.counters.snapshot().filter { it.value > 0}}",
                1, client[ChannelCounters.Reason.INVALID_LIFETIME],
            )
            assertEquals(0, client[ChannelCounters.Reason.INVALID_COMMIT])
            // the only candidate of the epoch is the owner's admission; the finite commit is none
            val rows = client.database.transaction { tx ->
                val epoch = client.channelStores.channels.channel(tx.sql, c)!!.epoch
                client.channelStores.candidates.candidates(tx.sql, c, epoch)
            }
            assertEquals("one candidate (the owner's admission)", 1, rows.size)
            assertTrue("the finite commit is never a candidate", rows.none { it.hash.contentEquals(finite.hash) })
        }
        // the settle proceeds: the admission wins, dave joins.
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        w.quiesce()
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    // -------------------------------------------------------------------------------- CO-5's voiding

    /** S0-15: a winner that changed the committers voids every unconsumed invite of the old digest, at every member. */
    @Test
    fun aWinnerThatChangesCommittersVoidsTheUnconsumedInvitesOfTheOldDigest() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val c = id.toByteArray()
        // an unconsumed invite of the current committers.
        ChannelAdmissionTest.invite(owner, id)
        w.quiesce()
        assertEquals(1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 0"))
        val before = ChannelAdversary.policy(owner, id)
        assertEquals(1, before.committers.size)
        val ownerP = owner.contexts.open(c)!!.pseudonym
        val bobP = bob.contexts.open(c)!!.pseudonym
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name, listOf(ownerP, bobP), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        settleEveryone(w, owner, bob)
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)
        assertEquals("the invite of the old digest is void, not consumed", 1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 1"))
        assertEquals(1L, bob.count("ch_invite_issued", "consumed = 0 AND void = 1"))
        assertEquals(1, owner[ChannelCounters.Reason.INVITE_VOIDED])
        assertEquals(1, bob[ChannelCounters.Reason.INVITE_VOIDED])
        assertTrue(owner.integrity().isEmpty())
    }

    /** §19.29.3: a winner that bumped the password voids every unconsumed invite of the older version. */
    @Test
    fun aWinnerThatBumpsThePasswordVoidsTheUnconsumedInvitesOfTheOlderVersion() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val password = "parola-canalului".toCharArray()
        val id = ChannelAdmissionTest.create(owner, password = true)
        val link = ChannelAdmissionTest.invite(owner, id, password)
        assertEquals(AcceptResult.PENDING, bob.engine.accept(link, password))
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        password.fill(0.toChar())
        assertEquals(1L, owner.channel(id)!!.epoch)
        // an invite of pw_version 1, unconsumed.
        val result = owner.engine.invite(id, 7, "parola-canalului".toCharArray())
        assertEquals(org.ghost.messaging.api.InviteResult.Status.CREATED, result.status)
        w.quiesce()
        assertEquals(1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 0 AND pw_version = 1"))
        val before = ChannelAdversary.policy(owner, id)
        assertEquals(1, before.pwVersion)
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, 2, before.name, before.committers, before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "pw-bump" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "pw-bump")
        settleEveryone(w, owner, bob)
        assertEquals(2L, owner.channel(id)!!.epoch)
        assertEquals(2, ChannelAdversary.policy(owner, id).pwVersion)
        assertEquals(1L, owner.count("ch_invite_issued", "consumed = 0 AND void = 1"))
        assertEquals(1, owner[ChannelCounters.Reason.INVITE_VOIDED])
        assertTrue(owner.integrity().isEmpty())
    }

    // ---------------------------------------------------------------------------------- CO-4 (ii)

    /** No settle before one listing pass over every relay of the set has completed after the window opened. */
    @Test
    fun theSettleWaitsForAListingPassOverEveryRelayAfterTheWindow() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        assertEquals("the commit is verified", 1L, owner.count("ch_candidate", "own = 1 AND verified = 1"))
        // (i) holds now — the window is 20 minutes and the sighting is minutes old — but no listing
        // pass has completed since it opened: the time-triggered pass settles nothing.
        w.advance(21 * DmWorld.MINUTE)
        owner.timePass()
        assertEquals("CO-4 (ii) is not met: no listing pass after the window", 1L, owner.channel(id)!!.epoch)
        // one relay round (a completed pass over every relay) and the next pass settles.
        w.pump()
        owner.timePass()
        assertEquals(2L, owner.channel(id)!!.epoch)
        w.quiesce()
        assertEquals(ChannelState.ACTIVE, dave.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    // --------------------------------------------------------------------------------------- helpers

    /**
     * Serves everything the relay holds and lets each named client **record** what it received (a
     * hint pass: the window is closed, so nothing settles): a candidate's sighting is its pass
     * that records it, so the advances that follow open the window on a sighted candidate.
     */
    private fun deliver(w: ChannelWorld, vararg cs: ChannelClient) {
        w.pump()
        for (client in cs) client.hintPass()
    }

    /** A rank-0 context-change commit adding [bob] to the committers; recorded and settled everywhere (one epoch). */
    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val c = id.toByteArray()
        val before = ChannelAdversary.policy(owner, id)
        val ownerP = owner.contexts.open(c)!!.pseudonym
        val bobP = bob.contexts.open(c)!!.pseudonym
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name, listOf(ownerP, bobP), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        settleEveryone(w, *w.clients.toTypedArray())
    }

    /** The injected commits recorded, every settle window passed, one relay round, a time-triggered pass of each client, then quiesce. */
    private fun settleEveryone(w: ChannelWorld, vararg cs: ChannelClient) {
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in cs) client.timePass()
        w.quiesce()
    }

    private fun winnerOf(client: ChannelClient, id: ChannelId, epoch: Long): ByteArray? =
        client.database.transaction { tx -> client.channelStores.epochs.logged(tx.sql, id.toByteArray(), epoch)?.winnerHash }

    /** The member's channel state key, unwrapped like `ChannelContexts.crypto` does. */
    private fun stateKeyOf(client: ChannelClient): ByteArray {
        val wrapped = client.database.transaction { tx -> client.channelStores.self.stateKeyWrapped(tx.sql) }
            ?: error("no state key stored")
        return FakeKeyWrapper().unwrap(wrapped)
    }
}
