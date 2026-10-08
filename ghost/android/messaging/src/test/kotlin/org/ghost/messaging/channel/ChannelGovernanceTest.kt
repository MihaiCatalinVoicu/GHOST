package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.SwapEvidence
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **GV, the CO-2 governance suite** (Phase 10 design §12.6 GV, §6.4 CO-1/CO-2, §19.13, §19.14;
 * slice S5c) — the rule cases S5's engine can reach. The commits are what a modified client can
 * send: built through the facade ([ChannelAdversary]) or the native test entries, injected through
 * the model relay, judged by every member's native CO-2 (the refusal surfaces as the facade's
 * `INVALID_COMMIT(reason)` at the build or as the receiver's `INVALID_COMMIT` counter).
 *
 * Covered: the rank basis read from the **pre-commit** context (a commit that reorders
 * `committers` is judged, and ranked, by the ranks it found; a rank-0 transfer accepted); a
 * context change by rank ≥ 1 refused; the rotation flag from rank 255 refused; a rank-255 commit
 * covering a proposal (a Remove) refused; a resignation by a moderator accepted and by the last
 * committer refused; a swap without evidence refused (the positive halves — swaps of any rank with
 * rejoin or restore evidence — need S6/S7's rejoin/restore builders and recorders, §19.37 row 46;
 * recorded as deferred); NEW_SIGNER — a commit whose update-path leaf's credential names another
 * identity than its key is invalid everywhere (MM-31, the native test entry of §19.39's F-S5-9);
 * the work-age rule (MM-34's scheduled-pass halves) is S5b2's [ChannelPassTest]; CO-14's rate at
 * the pass is S5b2's skip test, at the receiver the native check (the copies of one commit are one
 * candidate, S5b2's flood shape). Not facade-reachable, covered natively: an update-path leaf with
 * a wrong `refresh_epoch` (the builder always sets the commit's epoch) and an inflated leaf
 * (MM-38, the canonical checks).
 */
class ChannelGovernanceTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** CO-1: a commit that reorders `committers` is judged by the pre-commit context; a rank-0 transfer is accepted. */
    @Test
    fun aRankZeroTransferIsAcceptedAndTheRankIsReadFromThePreCommitContext() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val before = ChannelAdversary.policy(owner, id)
        assertCommitters("one committer at first", listOf(pseudonymOf(owner, id)), before.committers)
        // The transfer: bob moves to rank 0. The commit carries the new order; its own rank —
        // what CO-3 ranks it by, what the receivers record — is the pre-commit one (0, the owner).
        val transfer = ChannelAdversary.commit(
            owner, id,
            ChannelPolicy(
                before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                before.flags, before.idleEvictDays, before.pwVersion, before.name,
                listOf(pseudonymOf(bob, id), pseudonymOf(owner, id)), before.funders,
            ),
        )
        w.relay.holdAt = { name, s -> s.purpose == "transfer" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, transfer, rank = 0)
        ChannelAdversary.inject(w, owner, id, transfer, "transfer")
        w.pump()
        for (client in listOf(owner, bob)) client.hintPass()
        assertEquals(
            "the candidate is ranked by the pre-commit context (CO-1)",
            1L, owner.count("ch_candidate", "epoch = 1 AND rank = 0"),
        )
        settleEveryone(w, owner, bob)
        assertEquals(2L, owner.channel(id)!!.epoch)
        val after = ChannelAdversary.policy(owner, id)
        assertCommitters("the transfer holds", listOf(pseudonymOf(bob, id), pseudonymOf(owner, id)), after.committers)
        // bob is rank 0 now: his next commit is recorded rank 0.
        val bobCommit = ChannelAdversary.commit(bob, id)
        w.relay.holdAt = { name, s -> s.purpose == "bob-r0" && name == "bob" }
        ChannelAdversary.stageOwn(bob, id, bobCommit, rank = 0)
        ChannelAdversary.inject(w, bob, id, bobCommit, "bob-r0")
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_candidate", "epoch = 2 AND rank = 0"))
        settleEveryone(w, owner, bob)
        assertTrue(owner.integrity().isEmpty())
    }

    /** CO-2: a context change committed by rank 1 is refused (the native build runs the committer's own CO-2). */
    @Test
    fun aContextChangeByRankOneIsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        val before = ChannelAdversary.policy(bob, id)
        val refused = try {
            ChannelAdversary.commit(
                bob, id,
                ChannelPolicy(
                    before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                    before.flags, before.idleEvictDays, before.pwVersion, before.name,
                    listOf(pseudonymOf(bob, id), pseudonymOf(owner, id)), before.funders,
                ),
            )
            null
        } catch (e: AssertionError) {
            e.message
        }
        assertTrue("the build is refused (a transfer by rank 1): $refused", refused != null && "INVALID_COMMIT" in refused)
        // Nothing was staged or sent; the channel is untouched.
        assertEquals(0L, bob.count("ch_candidate", "own = 1"))
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)
        assertTrue(bob.integrity().isEmpty())
    }

    /** CO-2: the rotation flag from a rank-255 member is refused. */
    @Test
    fun aRotationFlagFromRank255IsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val refused = try {
            ChannelAdversary.commit(bob, id, rotate = true)
            null
        } catch (e: AssertionError) {
            e.message
        }
        assertTrue("a non-committer cannot rotate: $refused", refused != null)
        assertEquals(0L, bob.count("ch_candidate", "own = 1"))
        assertTrue(bob.integrity().isEmpty())
    }

    /** CO-1/CO-2: a rank-255 commit covering a proposal (a Remove) is refused. */
    @Test
    fun aRank255CommitCoveringAProposalIsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val refused = try {
            ChannelAdversary.commit(bob, id, removes = listOf(pseudonymOf(owner, id)))
            null
        } catch (e: AssertionError) {
            e.message
        }
        assertTrue("a rank-255 commit with a proposal is refused: $refused", refused != null && "INVALID_COMMIT" in refused)
        assertTrue(bob.integrity().isEmpty())
    }

    /** §19.13: a moderator's resignation (dropping its own key from `committers`) is accepted. */
    @Test
    fun aModeratorsResignationIsAccepted() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        makeCommitter(w, owner, bob, id)
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)
        val before = ChannelAdversary.policy(bob, id)
        val resignation = ChannelAdversary.commit(
            bob, id,
            ChannelPolicy(
                before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                before.flags, before.idleEvictDays, before.pwVersion, before.name,
                listOf(pseudonymOf(owner, id)), before.funders,
            ),
        )
        w.relay.holdAt = { name, s -> s.purpose == "resign" && name == "bob" }
        ChannelAdversary.stageOwn(bob, id, resignation, rank = 1)
        ChannelAdversary.inject(w, bob, id, resignation, "resign")
        settleEveryone(w, owner, bob)
        assertEquals(3L, owner.channel(id)!!.epoch)
        assertEquals("bob resigned: one committer", 1, ChannelAdversary.policy(owner, id).committers.size)
        assertEquals("bob is still a member", ChannelState.ACTIVE, bob.channel(id)!!.state)
        assertTrue(owner.integrity().isEmpty())
    }

    /** §19.13: the last committer's resignation is refused (no safe succession, Q37/L8-C16). */
    @Test
    fun theLastCommittersResignationIsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val before = ChannelAdversary.policy(owner, id)
        val refused = try {
            ChannelAdversary.commit(
                owner, id,
                ChannelPolicy(
                    before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                    before.flags, before.idleEvictDays, before.pwVersion, before.name,
                    emptyList(), emptyList(),
                ),
            )
            null
        } catch (e: AssertionError) {
            e.message
        }
        assertTrue("the last committer cannot resign: $refused", refused != null && "INVALID_COMMIT" in refused)
        assertTrue(owner.integrity().isEmpty())
    }

    /** CO-2 (A): a swap without valid evidence is refused at the build (the evidence never verifies). */
    @Test
    fun aSwapWithoutEvidenceIsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        val c = id.toByteArray()
        val day = DmTime.day(bob.clock.now)
        // A modified client pairs a Remove of bob with an Add of a KeyPackage carrying bogus
        // rejoin evidence. The committer's own CO-2 runs `verify_swap` over the pending commit —
        // the evidence does not verify, the build is refused before anything is staged.
        val opened = bob.contexts.open(c) ?: error("not a member")
        val kp = when (val o = opened.crypto.keyPackage(c, PURPOSE_REJOIN, day.toInt())) {
            is org.ghost.crypto.bridge.MlsOutcome.Ok -> o.value
            is org.ghost.crypto.bridge.MlsOutcome.Refused -> error("refused: ${o.refusal}")
        }
        val bogus = SwapEvidence.Rejoin(kp.kpRef, 0, day, 0, ByteArray(32), ByteArray(64))
        val generation = bob.database.transaction { tx -> bob.channelStores.generations.current(tx.sql, c, day) }!!
        val channel = bob.channel(id)!!
        val rows = org.ghost.messaging.channel.engine.MlsRows.of(
            bob.database.transaction { tx -> bob.channelStores.mls.rows(tx.sql, c, day) },
        )
        val outcome = opened.crypto.commit(
            c, rows,
            org.ghost.crypto.bridge.CommitRequest(
                swaps = listOf(Triple(pseudonymOf(bob, id), kp.keyPackage, bogus)),
                commitMinute = Math.floorDiv(bob.clock.now, DmTime.MINUTE),
                floor = org.ghost.messaging.channel.engine.ChannelTime.floor(channel.sizeClass).toLong(),
                generation = generation.generation,
                openEpoch = generation.openEpoch,
                gEnv = generation.gEnv,
            ),
            day.toInt(),
        )
        val refused = (outcome as? org.ghost.crypto.bridge.MlsOutcome.Refused)?.refusal
        assertTrue(
            "the swap without evidence is refused at the build: $outcome",
            refused != null && (refused.code == org.ghost.crypto.bridge.MlsCode.INVALID_COMMIT ||
                refused.code == org.ghost.crypto.bridge.MlsCode.INVALID_EVIDENCE),
        )
        assertEquals(0L, bob.count("ch_candidate", "own = 1"))
        assertTrue(bob.integrity().isEmpty())
    }

    /** MM-31 / §19.14 (NEW_SIGNER): a commit whose update-path leaf's credential names another identity is invalid everywhere. */
    @Test
    fun aNewSignerCommitIsInvalidEverywhere() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val alice = w.client("alice")
        val id = ChannelScenes.channelOf(w, owner, bob, alice)
        makeCommitter(w, owner, bob, id)
        assertEquals(2L, owner.channel(id)!!.epoch)
        // bob's own commit, every MLS check passing, but the new leaf's BasicCredential identity
        // is a stranger's key (the native test entry, kind 15).
        val wrong = pseudonymOf(alice, id)
        val commit = ChannelAdversary.newSignerCommit(bob, id, wrong)
        val built = ChannelAdversary.Built(commit, ChannelAdversary.sealHandshake(bob, id, commit), emptyList(), null, ByteArray(32))
        w.relay.holdAt = { name, s -> s.purpose == "new-signer" && name == "bob" }
        w.relay.inject(ChannelAdversary.namespace(bob, id), built.blob, w.now, "new-signer")
        deliver(w, owner, alice)
        for (client in listOf(owner, alice)) {
            assertEquals("CO-2's leaf continuity refuses it (MM-31)", 1, client[ChannelCounters.Reason.INVALID_COMMIT])
            assertEquals(0, client[ChannelCounters.Reason.INVALID_LIFETIME])
            assertEquals(0L, client.count("ch_candidate"))
            assertEquals(2L, client.channel(id)!!.epoch)
        }
        // The channel then advances normally: the invalid commit blocked nobody.
        settleEveryone(w, owner, bob, alice)
        ChannelScenes.post(owner, id, "dupa refuz")
        w.quiesce()
        assertTrue(alice.displayed(id).contains("dupa refuz"))
        assertTrue(owner.integrity().isEmpty())
    }

    companion object {
        /** `GhostKpBind.purpose` (§5.4): 2 rejoin — the swap evidence kind this suite stages. */
        private const val PURPOSE_REJOIN: Int = 2
    }

    // --------------------------------------------------------------------------------------------- helpers

    private fun assertCommitters(what: String, expected: List<ByteArray>, actual: List<ByteArray>) {
        assertEquals("$what: ${actual.size} committers", expected.size, actual.size)
        for (i in expected.indices) assertArrayEquals("$what: committer $i", expected[i], actual[i])
    }

    /** Serves everything and lets each named client record what it received (a hint pass: the window is closed). */
    private fun deliver(w: ChannelWorld, vararg cs: ChannelClient) {
        w.pump()
        for (client in cs) client.hintPass()
    }

    private fun settleEveryone(w: ChannelWorld, vararg cs: ChannelClient) {
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in cs) client.timePass()
        w.quiesce()
    }

    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        settleEveryone(w, *w.clients.toTypedArray())
    }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym
}
