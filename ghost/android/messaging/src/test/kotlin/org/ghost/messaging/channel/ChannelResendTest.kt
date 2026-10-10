package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.ChannelScenes.get
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.store.PostState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The **INDETERMINATE resends** (Phase 10 design §19.37 row 47, the deferred half of §7.5 over channels;
 * slice S8): a channel op that closed INDETERMINATE is enqueued again with **the identical bytes** — the
 * retained [org.ghost.messaging.channel.store.PostStore.OpRow.blob], never a re-seal — at most twice
 * ([org.ghost.messaging.channel.store.PostStore.MAX_RESENDS]), only inside the resend bound and the op's
 * deadline, in the outcome's transaction. A post stays `indeterminate` through the resends; a commit stays
 * pending under CO-4 — the resend is exactly what may yet produce the verified copy CO-4 (a) needs.
 *
 * The world raises no receipts (the model relay decides outcomes on the raw rows, as its header says), so
 * the own tombstone that a real receipt would raise (§11.2 #6) is raised by the test itself — the same
 * recipe `EnqueueTest.anExistingOwnTombstoneIsRaisedAndBoundsTheResendOfIdenticalBytes` pins — before the
 * outcome lands; without it the second resend bound is already closed and the op ends terminal, which the
 * pre-existing suites exercise incidentally.
 */
class ChannelResendTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** What identifies the op's bytes at the outbox and its tombstone, for the tombstone raise. */
    private class OpBytes(val operation: ByteArray, val namespace: ByteArray, val hash: ByteArray)

    private fun opBytes(client: ChannelClient, where: String, vararg args: Any?): OpBytes {
        var found: OpBytes? = null
        client.sql.query(
            "SELECT o.operation_id, o.namespace_id, o.blob_hash FROM outbox_op o JOIN ch_outbound_op c " +
                "ON c.operation_id = o.operation_id WHERE $where ORDER BY o.operation_id DESC LIMIT 1",
            listOf(*args),
        ) { r -> found = OpBytes(r.blob(0), r.blob(1), r.blob(2)) }
        return found ?: error("no outbox op for: $where")
    }

    /** The receipt a real relay would have written: the done row's retention to `ceil7(day(expiry) + 24)`. */
    private fun raiseTombstone(client: ChannelClient, bytes: OpBytes, ttlSeconds: Long) {
        val expiry = client.clock.now + ttlSeconds
        val day = org.ghost.messaging.engine.DmTime.day(expiry) + 24
        val retain = (day / 7 + if (day % 7 == 0L) 0 else 1) * 7
        client.sql.exec(
            "UPDATE inbox_blob SET retain_until_day = ? WHERE namespace_id = ? AND blob_hash = ? AND state = 'done'",
            listOf(retain, bytes.namespace, bytes.hash),
        )
    }

    private fun resendsOf(client: ChannelClient, ref: ByteArray): Pair<Long, Long> {
        var n = 0L
        var resends = 0L
        client.sql.query(
            "SELECT count(*), ifnull(max(resends), -1) FROM ch_outbound_op WHERE ref = ?",
            listOf(ref),
        ) { n = it.long(0); resends = it.long(1) }
        return n to resends
    }

    private fun pendingCopiesOf(client: ChannelClient, hash: ByteArray): Long =
        client.count("outbox_op", "blob_hash = ? AND outcome = 'pending' AND ciphertext IS NOT NULL", hash)

    @Test
    fun anIndeterminatePostResendsItsIdenticalBytesAtMostTwiceAndStaysIndeterminate() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        w.relay.outcomeFor = { client, purpose -> if (client.name == "bob" && purpose == "post") "indeterminate" else "sent" }
        ChannelScenes.post(bob, id, "hello")
        val opId = ChannelScenes.opIdOf(bob, id, "hello")
        // the copy a real receipt would raise, before the outcome is applied
        val op = opBytes(bob, "c.ref = ? AND c.purpose = 'post'", opId)
        raiseTombstone(bob, op, 7 * DmWorld.DAY)
        // round 1: the op closes INDETERMINATE; the outcome's transaction resends the identical bytes
        w.pump()
        bob.hintPass()
        assertEquals(PostState.INDETERMINATE, bob.database.transaction { tx ->
            bob.channelStores.posts.post(tx.sql, opId, bob.clock.now)!!.state
        })
        var counts = resendsOf(bob, opId)
        assertEquals("the old op row went, one resend row stands", 1L, counts.first)
        assertEquals(1L, counts.second)
        assertEquals(1L, pendingCopiesOf(bob, op.hash))
        assertEquals(0L, bob.count("ch_post", "state <> 'indeterminate' AND op_id = ?", opId))
        // the resent bytes are the identical bytes: the relay collects the same hash again
        val storedBefore = w.relay.stored.count { it.hash.contentEquals(op.hash) }
        w.pump()
        assertEquals(storedBefore + 1, w.relay.stored.count { it.hash.contentEquals(op.hash) })
        // round 2: the second INDETERMINATE resends once more
        bob.hintPass()
        counts = resendsOf(bob, opId)
        assertEquals(1L, counts.first)
        assertEquals(2L, counts.second)
        assertEquals(1L, pendingCopiesOf(bob, op.hash))
        // round 3: the bound is spent — no third resend; the post stays indeterminate
        w.pump()
        bob.hintPass()
        counts = resendsOf(bob, opId)
        assertEquals("no third op", 0L, counts.first)
        assertEquals(0L, pendingCopiesOf(bob, op.hash))
        assertEquals(PostState.INDETERMINATE, bob.database.transaction { tx ->
            bob.channelStores.posts.post(tx.sql, opId, bob.clock.now)!!.state
        })
        // the resend machinery moved nothing at the receiver's view beyond the one post
        w.advance(21 * DmWorld.MINUTE)
        owner.timePass()
        assertEquals(listOf("hello"), owner.displayed(id))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    @Test
    fun anIndeterminateCommitResendsAndStaysPendingUnderCustody() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // the owner's PCS commit of a quiet week, closing INDETERMINATE at the relay
        w.advance(7 * DmWorld.DAY + DmWorld.HOUR)
        w.admissionPass(owner)
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        val commit = opBytes(owner, "c.channel_id = ? AND c.purpose = 'commit'", id.toByteArray())
        val candidateHash = owner.database.transaction { tx -> owner.channelStores.posts.op(tx.sql, commit.operation)!!.ref }!!
        raiseTombstone(owner, commit, 7 * DmWorld.DAY)
        w.pump()
        owner.hintPass()
        // the identical bytes went out again under a fresh op; the candidate stays pending and unverified
        val counts = resendsOf(owner, candidateHash)
        assertEquals(1L, counts.first)
        assertEquals(1L, counts.second)
        assertEquals(1L, pendingCopiesOf(owner, commit.hash))
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        // and a day of sweeps does not touch the pending commit (custody is the settle's, CO-4)
        w.advance(DmWorld.DAY)
        owner.timePass()
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        assertTrue(owner.integrity().isEmpty())
    }

    /**
     * Review probe A (§19.46 FIX 1): an op closes INDETERMINATE while its bytes' own tombstone is still
     * `listed` — listed from a relay before the `done` tombstone existed, a documented real state the
     * enqueue's upsert leaves alone. `Outbox.enqueue` refuses the resend ("these bytes were received from
     * a relay"), and the refusal is the resend's terminal state: the release stands, nothing is resent, the
     * pass completes. The unfixed catch let the refusal roll the whole outcome transaction back — release
     * included — and every later pass stalled on the same outcome, a permanent stall (the outcome step is
     * the pass's first step).
     */
    @Test
    fun aListedTombstoneEndsTheResendWithoutPoisoningThePass() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        var indeterminateOnce = true
        w.relay.outcomeFor = { client, purpose ->
            if (client.name == "bob" && purpose == "post" && indeterminateOnce) {
                indeterminateOnce = false
                "indeterminate"
            } else {
                "sent"
            }
        }
        ChannelScenes.post(bob, id, "hello")
        val opId = ChannelScenes.opIdOf(bob, id, "hello")
        val op = opBytes(bob, "c.ref = ? AND c.purpose = 'post'", opId)
        // the documented real state: the (namespace, hash) row a relay's listing raised — 'listed',
        // the done tombstone not yet (schema: 'done' is final, so the row stands alone)
        val day = org.ghost.messaging.engine.DmTime.day(bob.clock.now)
        val retain = (day / 7 + 1) * 7
        bob.sql.exec("DELETE FROM inbox_blob WHERE namespace_id = ? AND blob_hash = ?", listOf(op.namespace, op.hash))
        bob.sql.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?)",
            listOf(op.namespace, op.hash, retain),
        )
        // pass 1: the outcome applies — released, the post stays indeterminate, no resend, no throw
        w.pump()
        bob.hintPass()
        assertEquals(PostState.INDETERMINATE, bob.database.transaction { tx ->
            bob.channelStores.posts.post(tx.sql, opId, bob.clock.now)!!.state
        })
        assertEquals("the release stands despite the refusal", 1L, bob.count("outbox_op", "operation_id = ? AND released = 1", op.operation))
        assertEquals(0L, bob.count("ch_outbound_op", "ref = ?", opId))
        assertEquals(0L, pendingCopiesOf(bob, op.hash))
        // pass 2 does not throw and the channel keeps making progress
        bob.hintPass()
        ChannelScenes.post(bob, id, "still alive")
        w.quiesce()
        assertEquals(listOf("still alive", "hello"), owner.displayed(id))
        assertEquals(emptyList<String>(), bob.integrity())
    }

    /**
     * Review probe B (§19.46 FIX 2): a commit whose own candidate was cleared under CO-4 (b) — a foreign
     * candidate won at a settle — is not resent. The resend's custody check is the candidate's existence
     * (§19.45 row 3's own text); here the original outcome legitimately resends once (its candidate stood
     * when the outcome applied), the settle then clears the candidate, and the resend op's own INDETERMINATE
     * outcome releases with nothing resent: zero new COMMIT ops, zero pending copies.
     */
    @Test
    fun aCommitWhoseCandidateWasClearedUnderCo4bIsNotResent() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // two owner epochs, so bob's rank-255 self-update passes CO-14 (the settle suites' shape)
        for (e in 1..2) {
            val next = ChannelAdversary.commit(owner, id)
            w.relay.holdAt = { name, s -> s.purpose == "advance-$e" && name == "owner" }
            ChannelAdversary.stageOwn(owner, id, next, rank = 0)
            ChannelAdversary.inject(w, owner, id, next, "advance-$e")
            settleEveryone(w, owner, bob)
        }
        val dave = w.client("dave")
        assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
        w.quiesce()
        val f = ChannelAdversary.commit(bob, id)
        // bob's self-update waits at the relay, held from bob (its author — there it would count
        // FORGE_OWN), until the owner's admission commit exists: CO-7 refuses a committer's pass
        // over any held candidate, so the admission must come first
        w.relay.holdAt = { name, s -> s.purpose == "probeB-F" && name == "bob" }
        ChannelAdversary.stageOwn(bob, id, f, rank = 255)
        ChannelAdversary.inject(w, bob, id, f, "probeB-F")
        // the owner's admission commit closes INDETERMINATE at the relay
        w.relay.outcomeFor = { client, purpose -> if (client.name == "owner" && purpose == "commit") "indeterminate" else "sent" }
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        val op = opBytes(owner, "c.channel_id = ? AND c.purpose = 'commit' AND c.resends = 0", id.toByteArray())
        val candidateHash = owner.database.transaction { tx -> owner.channelStores.posts.op(tx.sql, op.operation)!!.ref }!!
        // the copy a real receipt would raise (the enqueue-time tombstone's retention already closed
        // the resend bound — the suite's recipe), before the outcome is applied
        raiseTombstone(owner, op, 7 * DmWorld.DAY)
        // the relay decides the op and serves bob's self-update in one round; no pass applies the
        // outcome yet — the next pass applies it AND settles, in one actor step
        w.pump()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        owner.timePass()
        // the original outcome applied while the candidate stood: one legitimate resend; then the
        // settle of the same pass cleared the candidate under CO-4 (b) — bob's self-update won
        assertEquals(4L, owner.channel(id)!!.epoch)
        assertEquals(0L, owner.count("ch_candidate"))
        var counts = resendsOf(owner, candidateHash)
        assertEquals("the outcome that applied before the clearing resent once", 1L, counts.first)
        assertEquals(1L, counts.second)
        // the resend op closes INDETERMINATE with its candidate gone: released, nothing resent
        w.pump()
        owner.hintPass()
        counts = resendsOf(owner, candidateHash)
        assertEquals("a commit whose candidate is gone is not resent", 0L, counts.first)
        assertEquals(0L, pendingCopiesOf(owner, op.hash))
        assertEquals("dave's request waits for the owner's next pass", 1L, owner.count("ch_join_request"))
        assertTrue(owner.integrity().isEmpty())
    }

    /**
     * The review's probe of FIX 3 (§19.46): a resend op that closes FAILED must not clear the own pending
     * commit. F7's no-copy-can-exist contract is the original send's alone; the original INDETERMINATE
     * verdict leaves copy-existence open (§19.13: an own commit that may have reached a relay is never
     * cleared on its own). A resend op's FAILED is terminal-INDETERMINATE of a kind: release, keep the
     * commit pending, and the custody at the settle is its bound.
     */
    @Test
    fun aFailedResendKeepsTheOwnCommitPending() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val bob = w.client("bob")
        val id = ChannelScenes.channelOf(w, owner, bob)
        // the owner's PCS commit of a quiet week: first op INDETERMINATE, the resend op FAILED
        w.advance(7 * DmWorld.DAY + DmWorld.HOUR)
        w.admissionPass(owner)
        w.relay.outcomeFor = { client, purpose ->
            // the original op's row went when its outcome applied: what is collected after it is the resend
            if (client.name == "owner" && purpose == "commit") {
                if (owner.count("ch_outbound_op", "purpose = 'commit' AND resends = 0") == 0L) "failed" else "indeterminate"
            } else {
                "sent"
            }
        }
        val op = opBytes(owner, "c.channel_id = ? AND c.purpose = 'commit' AND c.resends = 0", id.toByteArray())
        val candidateHash = owner.database.transaction { tx -> owner.channelStores.posts.op(tx.sql, op.operation)!!.ref }!!
        raiseTombstone(owner, op, 7 * DmWorld.DAY)
        w.pump()
        owner.hintPass()
        // round 1: INDETERMINATE resent the identical bytes once; the candidate stays pending
        assertEquals(1L, resendsOf(owner, candidateHash).first)
        assertEquals(1L, resendsOf(owner, candidateHash).second)
        assertEquals(1L, pendingCopiesOf(owner, op.hash))
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND verified = 0"))
        // round 2: the resend op closes FAILED — the commit stays pending, no copy can be declared gone
        w.pump()
        owner.hintPass()
        assertEquals(
            "a resend op's FAILED is not F7's contract: the own commit stays pending (§19.13)",
            1L, owner.count("ch_candidate", "own = 1 AND verified = 0"),
        )
        assertEquals(0, owner[ChannelCounters.Reason.OWN_COMMIT_CLEARED])
        assertEquals(0L, resendsOf(owner, candidateHash).first)
        assertEquals(0L, pendingCopiesOf(owner, op.hash))
        assertTrue(owner.integrity().isEmpty())
    }

    /** The injected commits recorded, every settle window passed, one relay round, a time-triggered pass of each named client, then quiesce. */
    private fun settleEveryone(w: ChannelWorld, vararg cs: ChannelClient) {
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in cs) client.timePass()
        w.quiesce()
    }
}
