package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelRevealStep
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.storage.StorageFullException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * **RV — the reveal suite** (Phase 10 design §12.6's row, §6.9, §19.17; slice S9):
 *
 *  - the happy path: the author reveals to one member M; M opens it (one HPKE open, the box key of
 *    the post's epoch), verifies both signatures natively (fn 16 — the transferable proof: anyone
 *    M shows the opened payload to can verify `sig_id` under the card's identity key and `sig_ps`
 *    under `P_author`, and the REVEAL post's MLS signature proves which pseudonym sent it; the
 *    strict-verification half is the Rust crate's `reveal` module's round trip, where a separate
 *    context — anyone, not the author — verifies every binding), and is offered the author's card;
 *  - the wrong recipient: every other member tries its box key once, opens nothing, counts
 *    `REVEAL_NOT_FOR_ME` — what members learn is that the author revealed to *someone* (L8-C8);
 *  - the relay-visible shape (LC-6): a REVEAL travels as a normal post — the post TTL (not the
 *    handshake TTL) and the class floor's bucket, indistinguishable from any post of its length;
 *  - the replay: a copy of the REVEAL blob is counted by the dedup layers and offers nothing twice;
 *  - the rotated leaf (PC-18): a reveal sealed to the leaf the recipient has since replaced still
 *    opens with the retired key while the old epoch is within retention, and the key is deleted
 *    with that epoch's retention — a later compromise opens nothing;
 *  - the retention (§8.5): `ch_reveal` rows follow the REVEAL post's timer and the sweep takes them;
 *  - the refusals: a non-member recipient, the member itself, a locked identity;
 *  - the aborted batch (FIX 2 of §19.48): a `StorageFull` rollback after the card was queued
 *    never offers, and the blob's re-delivery does not double-offer;
 *  - the refused offer (FIX 3 of §19.48): a DM context that is not there (`NOT_ACTIVATED`) loses
 *    the card with the offer, counted `REVEAL_OFFER_FAILED`, and the author can reveal again.
 *
 * The signature forgeries (a wrong identity key, a wrong pseudonym key, a claimed MLS sender that
 * is not `P_author`) are native-level refusals — Kotlin never holds either signing key, so a JVM
 * world cannot mint them; they are the Rust crate's `reveal` module's cases (`BAD_SIGNATURE` on
 * each), and the engine-side killers of §12.9's RV-C1/Rv-C2 mutants read the native checks.
 */
class ChannelRevealTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** The member's pseudonym in [id] (what the roster and the reveal name). */
    private fun p(c: ChannelClient, id: ChannelId): ByteArray = c.channel(id)!!.myPseudonym

    /** The reveal ops [author] has at the relay (their op's purpose is `request`, like a leave's). */
    private fun revealBlobs(w: ChannelWorld, author: ChannelClient): List<ModelChannelRelay.Stored> =
        w.relay.stored.filter { it.from == author.name && it.purpose == "request" && !it.injected }

    private fun revealRows(c: ChannelClient, id: ChannelId): List<Pair<String, String>> =
        c.database.transaction { tx ->
            c.channelStores.posts.reveals(tx.sql, id.toByteArray(), c.clock.now)
                .map { it.direction.sql to ChannelWorld.hex(it.peer) }
        }

    private fun pHex(c: ChannelClient, id: ChannelId): String = ChannelWorld.hex(p(c, id))

    @Test
    fun theHappyPathRevealsToOneMemberWhoIsOfferedTheAuthorsCard() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val frank = w.client("frank")
        val id = ChannelScenes.channelOf(w, owner, dave, frank)

        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        assertEquals("the sender's row, its only time the deletion deadline", listOf("out" to pHex(dave, id)), revealRows(owner, id))

        w.quiesce()
        // M: the open, the verification, the row and the offer.
        assertEquals("M's row, the author as its peer", listOf("in" to pHex(owner, id)), revealRows(dave, id))
        assertEquals("one offer", 1, dave.offeredCards.size)
        assertEquals("the offer's source is link (§19.17: no CHANNEL_REVEAL exists)", org.ghost.messaging.store.ContactStore.Source.LINK, dave.offeredCards[0].second)
        assertArrayEquals("the author's own card — what addContact dedups against (R-E3)", owner.ownCard(), dave.offeredCards[0].first)
        // The others: one HPKE open each, nothing opened, no identity learned.
        assertEquals("frank learned that someone was revealed to, no more", 1, frank.counters[ChannelCounters.Reason.REVEAL_NOT_FOR_ME])
        assertTrue("no row, no card, no identity", revealRows(frank, id).isEmpty())
        assertTrue(frank.offeredCards.isEmpty())
        assertEquals(0, dave.counters[ChannelCounters.Reason.REVEAL_NOT_FOR_ME])
        assertEquals(0, owner.counters[ChannelCounters.Reason.REVEAL_NOT_FOR_ME])
        // The channel shows nothing of it: a REVEAL derives only its ch_reveal row (§8.5).
        assertTrue(owner.displayed(id).isEmpty())
        assertTrue(dave.integrity().isEmpty())
        assertTrue(frank.integrity().isEmpty())
    }

    @Test
    fun aRevealTravelsAsANormalPostForTheRelay() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        // A 5-minute channel: the post TTL (1 h) is distinguishable from the handshake TTL (7 d).
        val created = owner.engine.create("salon".toByteArray(), 1, 0, false)
        val id = created.channel!!
        val link = ChannelAdmissionTest.invite(owner, id)
        assertEquals(org.ghost.messaging.api.AcceptResult.PENDING, dave.engine.accept(link, null))
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()

        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.pump()
        val blobs = revealBlobs(w, owner)
        val dump = w.relay.stored.filter { it.from == "owner" }.map { "${it.purpose} ttl=${it.ttl} size=${it.ciphertext.size} storedAt=${it.storedAt}" }
        assertTrue("the reveal is at the relay as a request op: pending=${owner.count("ch_pending_post")} ops=${owner.count("ch_outbound_op")} blobs=$dump", blobs.isNotEmpty())
        val reveal = blobs.last()
        assertEquals("the post TTL of the timer version, not the handshake TTL (LC-6): $dump", 3_600L, reveal.ttl)
        assertEquals("the class floor's bucket, as any post of its length", 4_096, reveal.ciphertext.size)
        w.quiesce()
        assertEquals(1, dave.offeredCards.size)
    }

    @Test
    fun aReplayedRevealBlobIsCountedAndOffersNothingTwice() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)
        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.pump()
        val blob = revealBlobs(w, owner).last().ciphertext
        w.quiesce()
        assertEquals(1, dave.offeredCards.size)
        val undecryptable = dave.counters[ChannelCounters.Reason.UNDECRYPTABLE]

        // A copy with a fresh seal (a new blob hash — the identical bytes die at the inbox
        // tombstone, the relay-TTL layer): the MLS replay layer (§6.3.4 layer 2) drops the message
        // before its content is seen; the op-id seen tag (layer 4) is the second fence for a
        // re-encrypted copy — neither offers the card again.
        val resealed = ChannelAdversary.reseal(dave, id, blob)
        ChannelAdversary.inject(w, dave, id, ChannelAdversary.Built(ByteArray(0), resealed, emptyList(), null, ByteArray(32)), "replayed-reveal")
        w.pump()
        dave.hintPass()
        assertEquals(
            "the replay died at the MLS layer: ${dave.counters.snapshot()}",
            undecryptable + 1, dave.counters[ChannelCounters.Reason.UNDECRYPTABLE],
        )
        assertEquals(1, dave.offeredCards.size)
        assertEquals(listOf("in" to pHex(owner, id)), revealRows(dave, id))
    }

    @Test
    fun aRevealSealedToAReplacedLeafKeyOpensUntilTheEpochsRetentionEnds() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val frank = w.client("frank")
        val carol = w.client("carol")
        val id = ChannelScenes.channelOf(w, owner, dave, frank, carol)

        // dave reveals to the owner and the blob waits at the relay, unprocessed.
        assertEquals(ChannelRevealStep.RevealResult.REVEALED, dave.engine.reveal(id, p(owner, id)))
        w.relay.holdAt = { name, s -> name == "owner" && s.purpose == "request" }
        w.pump()

        // The owner's leaf rotates the same day: a user-action Remove commits at once, and every
        // own winning commit refreshes the update path's leaf (§6.8) — the old box key is retired
        // with the settled epoch, the last whose tree held the old leaf (§19.17).
        assertEquals(org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED, owner.engine.remove(id, p(carol, id)))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        val epoch = owner.channel(id)!!.epoch
        val keys = owner.database.transaction { tx -> owner.channelStores.members.boxKeys(tx.sql, id.toByteArray(), DmTime.day(owner.clock.now)) }
        // three: the create-time key (retired at the admission), the replaced leaf's (retired at
        // this settle), the current one.
        assertEquals(3, keys.size)
        assertEquals(
            "the retired key of the replaced leaf",
            epoch - 1,
            keys.filter { it.lastEpoch != null }.single { it.lastEpoch == epoch - 1 }.lastEpoch,
        )

        // The reveal arrives now, epochs later in count but inside the old epoch's retention and
        // the blob's TTL: the retired key opens it (one try — the eligibility filter names it).
        w.relay.holdAt = { _, _ -> false }
        w.pump()
        owner.hintPass()
        assertEquals("the old leaf's key opens the reveal within retention", 1, owner.offeredCards.size)
        assertArrayEquals(dave.ownCard(), owner.offeredCards[0].first)
        assertEquals(listOf("in" to pHex(dave, id)), revealRows(owner, id))

        // Past the old epoch's retention (2 days at timer 7 d) the sweep deletes the retired key
        // with the epoch (§19.17): a later compromise of this device opens no reveal addressed to
        // the replaced leaf, and a reveal that arrived that late would find no key (REVEAL_NO_KEY).
        w.advance(3 * DmWorld.DAY)
        owner.timePass()
        val after = owner.database.transaction { tx -> owner.channelStores.members.boxKeys(tx.sql, id.toByteArray(), DmTime.day(owner.clock.now)) }
        assertEquals("the retired keys left with their epochs' retention", 1, after.size)
        assertNull(after[0].lastEpoch)
        assertTrue(owner.integrity().isEmpty())
    }

    @Test
    fun theRevealRowsFollowTheRevealPostsTimer() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        // A 5-minute channel.
        val created = owner.engine.create("salon".toByteArray(), 1, 0, false)
        val id = created.channel!!
        val link = ChannelAdmissionTest.invite(owner, id)
        assertEquals(org.ghost.messaging.api.AcceptResult.PENDING, dave.engine.accept(link, null))
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()

        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.quiesce()
        assertEquals(1, revealRows(owner, id).size)
        assertEquals(1, revealRows(dave, id).size)

        // Past the post's lives on both sides (the sender's countdown is author + 5 min, the
        // receiver's is min(E, consume + bucket + 1 h), E the hour-aligned relay expiry): the
        // sweep takes the rows with the REVEAL post's timer (§8.5, §19.21).
        w.advance(2 * DmWorld.HOUR)
        owner.timePass()
        dave.timePass()
        assertTrue("owner's rows: ${revealRows(owner, id)}", revealRows(owner, id).isEmpty())
        assertTrue("dave's rows: ${revealRows(dave, id)}", revealRows(dave, id).isEmpty())
    }

    @Test
    fun aNonMembersDeviceNeverHoldsTheCardBytes() = ChannelWorld().use { w ->
        val ownerFile = folder.newFile("owner-rv.db").also { it.delete() }
        val daveFile = folder.newFile("dave-rv.db").also { it.delete() }
        val frankFile = folder.newFile("frank-rv.db").also { it.delete() }
        val owner = w.client("owner", path = ownerFile.absolutePath)
        val dave = w.client("dave", path = daveFile.absolutePath)
        val frank = w.client("frank", path = frankFile.absolutePath)
        val id = ChannelScenes.channelOf(w, owner, dave, frank)
        val card = owner.ownCard()!!

        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.quiesce()

        // L8-C8: frank learns that the author revealed to someone. Nothing of the payload — the
        // author's identity key, the card's bytes — is written to his device; the physical half
        // scans his database file for the card (T25's method).
        assertEquals(1, frank.counters[ChannelCounters.Reason.REVEAL_NOT_FOR_ME])
        assertTrue(frank.offeredCards.isEmpty())
        assertTrue(revealRows(frank, id).isEmpty())
        org.ghost.storage.Checkpoint.truncate(frank.sql) { }
        val bytes = frankFile.readBytes()
        assertNull("the card's bytes are not in the non-recipient's database", indexOf(bytes, card))
        // And the recipient's offer is the card — what M keeps (§6.9 point 4).
        assertArrayEquals(card, dave.offeredCards[0].first)
    }

    @Test
    fun aRevealToANonMemberOrOneselfOrLockedIsRefused() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave")
        val id = ChannelScenes.channelOf(w, owner, dave)

        val blobsBefore = revealBlobs(w, owner).size
        assertEquals(ChannelRevealStep.RevealResult.NOTHING, owner.engine.reveal(id, ByteArray(32) { 0x5c }))
        assertEquals(ChannelRevealStep.RevealResult.NOTHING, owner.engine.reveal(id, p(owner, id)))
        assertEquals("a refused reveal enqueues nothing", blobsBefore, revealBlobs(w, owner).size)

        dave.unlocked = false
        assertEquals(ChannelRevealStep.RevealResult.UNAVAILABLE, dave.engine.reveal(id, p(owner, id)))
        dave.unlocked = true
        assertEquals(ChannelRevealStep.RevealResult.REVEALED, dave.engine.reveal(id, p(owner, id)))
        w.quiesce()
        assertEquals(1, owner.offeredCards.size)
    }

    /**
     * FIX 2 of §19.48 (review of S9): a batch that rolls back **after** `applyReveal` queued the
     * card — a `StorageFullException` on a later write of the same transaction — never offers and
     * leaves no row; the blob's re-delivery does not double-offer. The queued card's zeroization
     * on this abort path is the receive step's `finally` ([FullAfterRevealInsertSqlExecutor]
     * cannot see it — a heap probe is overkill), so the fail-without-fix half of this check is
     * recorded done-by-inspection in §19.48.
     */
    @Test
    fun aRolledBackBatchNeverOffersAndARedeliveryDoesNotDoubleOffer() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        // Dave's database answers SQLITE_FULL at the first write after the reveal's ch_reveal
        // insert: the receive transaction rolls back with the card already queued at the step.
        val daveSql = FullAfterRevealInsertSqlExecutor(
            JdbcSqlExecutor(":memory:").also { MigrationRunner(it).migrate() },
        )
        val dave = w.client("dave", sql = daveSql)
        val id = ChannelScenes.channelOf(w, owner, dave)
        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.pump()

        daveSql.armed = true
        assertThrows(StorageFullException::class.java) { dave.hintPass() }
        daveSql.armed = false
        assertTrue("a rolled-back batch offers nothing", dave.offeredCards.isEmpty())
        assertTrue("the row rolled back with its transaction", revealRows(dave, id).isEmpty())

        // SQLITE_FULL is a state of the device, not of the blob (§13.1): it was not consumed.
        // The re-delivered reveal opens and offers exactly once.
        dave.hintPass()
        assertEquals("the re-delivery offers once — no double-offer", 1, dave.offeredCards.size)
        assertArrayEquals(owner.ownCard(), dave.offeredCards[0].first)
        assertEquals(listOf("in" to pHex(owner, id)), revealRows(dave, id))
    }

    /**
     * FIX 3 of §19.48 (review of S9): an opened reveal whose offer the DM context refuses
     * (`addContact` answers `NOT_ACTIVATED` — a locked or wiped DM library) loses the card with
     * the offer: counted `REVEAL_OFFER_FAILED`, the row standing, and the author can reveal
     * again — the same loss shape as the crash-between edge of §19.47.
     */
    @Test
    fun anOfferTheDmContextRefusesIsCountedAndTheAuthorCanRevealAgain() = ChannelWorld().use { w ->
        val owner = w.client("owner")
        val dave = w.client("dave").apply { offerOutcome = ContactSteps.AddResult.NOT_ACTIVATED }
        val id = ChannelScenes.channelOf(w, owner, dave)

        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.quiesce()
        assertEquals("the offer was attempted and refused by the DM layer", 1, dave.offeredCards.size)
        assertEquals(1, dave.counters[ChannelCounters.Reason.REVEAL_OFFER_FAILED])
        assertEquals(
            "the loss is the offer's, not the open's — the row stands",
            listOf("in" to pHex(owner, id)),
            revealRows(dave, id),
        )

        // A fresh reveal is a fresh op id: no retry of the lost card, and the refusal is counted
        // every time it happens.
        assertEquals(ChannelRevealStep.RevealResult.REVEALED, owner.engine.reveal(id, p(dave, id)))
        w.quiesce()
        assertEquals(2, dave.offeredCards.size)
        assertEquals(2, dave.counters[ChannelCounters.Reason.REVEAL_OFFER_FAILED])
    }

    /**
     * A [SqlExecutor] that throws [StorageFullException] at the first write after the receive
     * inserted the reveal's `ch_reveal` row (`putReveal`'s INSERT goes through [exec]): the
     * receive transaction rolls back with the card already queued at the step — abort path (a)
     * of FIX 2 (§19.48).
     */
    private class FullAfterRevealInsertSqlExecutor(val delegate: JdbcSqlExecutor) : SqlExecutor {
        /** When true, the first [execUpdate] after a `ch_reveal` insert fails with `SQLITE_FULL`. */
        var armed: Boolean = false
        private var sawRevealInsert = false

        override fun exec(sql: String, args: List<Any?>) {
            if (sql.startsWith("INSERT INTO ch_reveal")) sawRevealInsert = true
            delegate.exec(sql, args)
        }

        override fun execUpdate(sql: String, args: List<Any?>): Int {
            if (armed && sawRevealInsert) throw StorageFullException(IllegalStateException("[SQLITE_FULL] regression test"))
            return delegate.execUpdate(sql, args)
        }

        override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) = delegate.query(sql, args, onRow)

        override fun <T> transaction(block: () -> T): T = delegate.transaction(block)

        override val inTransaction: Boolean get() = delegate.inTransaction

        override var userVersion: Int
            get() = delegate.userVersion
            set(value) {
                delegate.userVersion = value
            }
    }

    /** The first index of [needle] in [haystack], or null. */
    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int? {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return null
    }
}
