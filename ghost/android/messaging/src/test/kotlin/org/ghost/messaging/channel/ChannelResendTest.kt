package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.PostResult
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
}
