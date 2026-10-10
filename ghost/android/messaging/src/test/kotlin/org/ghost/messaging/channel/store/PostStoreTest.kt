package org.ghost.messaging.channel.store

import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ch_post`, `ch_reaction`, `ch_pending_post`, `ch_seen`, `ch_reveal` and `ch_outbound_op` through [PostStore]
 * (Phase 10 design §6.3, §8.2, §8.5, §9; slice S3): the posts of a channel in the order every member shares,
 * the state machine and the countdown, the cascade, and **the expiry filter on every read** — each case here
 * has an expired row beside a live one and asks the read for the live one only. The behavioural twin over
 * every registered query is `:storage`'s `ChannelExpiredRowLintTest`.
 */
class PostStoreTest {

    private val now = 1_800_000_000L
    private val hour = 1_800_000_000L

    private fun id(i: Int) = chBytes(16, i)
    private fun author(i: Int) = chBytes(32, 0x80 + i)

    private fun PostStore.incoming(
        w: StoreWorld,
        i: Int,
        authorMinute: Long = now - 3_600,
        deleteAt: Long? = now + 3_600,
        by: Int = i,
        relay: Long? = null,
        timer: Int = 4,
    ) = w.tx {
        insertIncomingIfAbsent(it, id(i), w.ch, author(by), 1, null, timer, 0, chBytes(60, i), authorMinute, deleteAt, relay)
    }

    private fun PostStore.outgoing(w: StoreWorld, i: Int, authorMinute: Long = now - 3_600, deleteAt: Long? = now + 3_600) = w.tx {
        insertOutgoing(it, id(i), w.ch, author(0), 1, null, 4, 0, chBytes(60, i), authorMinute, deleteAt)
    }

    @Test
    fun thePostsOfAChannelAreInTheOrderEveryMemberHoldsNewestFirst() = StoreWorld().use { w ->
        w.channel()
        // the same author minute, three authors, two posts of one author: (author_minute, author, op_id), descending
        w.stores.posts.incoming(w, 1, authorMinute = now - 120, by = 2)
        w.stores.posts.incoming(w, 2, authorMinute = now - 120, by = 1)
        w.stores.posts.incoming(w, 3, authorMinute = now - 60, by = 1)
        w.stores.posts.incoming(w, 4, authorMinute = now - 120, by = 1)
        w.stores.posts.incoming(w, 5, authorMinute = now - 180, by = 3)
        val ids = w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }
        assertEquals(listOf(3, 1, 4, 2, 5), ids)
        // a page of two, and the page before the second one's cursor: no post twice, none missed
        val first = w.stores.posts.page(w.db, w.ch, now, 2)
        assertEquals(listOf(3, 1), first.map { it.opId[0].toInt() })
        val cursor = PostStore.PostCursor(first.last().authorMinute, first.last().author, first.last().opId)
        assertEquals(listOf(4, 2, 5), w.stores.posts.pageBefore(w.db, w.ch, now, 50, cursor).map { it.opId[0].toInt() })
        assertEquals(listOf(4, 2), w.stores.posts.pageBefore(w.db, w.ch, now, 2, cursor).map { it.opId[0].toInt() })
        assertEquals(emptyList<Int>(), w.stores.posts.pageBefore(w.db, w.ch, now, 50, PostStore.PostCursor(0, chBytes(32, 0), id(0))).map { it.opId[0].toInt() })
        // another channel's posts are not on this page
        w.channel(w.ch2)
        w.tx { w.stores.posts.insertIncomingIfAbsent(it, id(9), w.ch2, author(1), 1, null, 4, 0, chBytes(60, 9), now - 60, now + 3_600, null) }
        assertEquals(5, w.stores.posts.page(w.db, w.ch, now, 50).size)
    }

    @Test
    fun aPostKeepsItsCountdownAndTheDeletionTimeOnlyMovesEarlier() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = now + 7_200, relay = hour + 7_200)
        var post = w.stores.posts.post(w.db, id(1), now)!!
        assertEquals(PostState.UNREAD, post.state)
        assertEquals(Direction.IN, post.direction)
        assertNull(post.displayedMinute)
        assertEquals(hour + 7_200, post.relayExpiryHour)
        assertEquals(1, w.stores.posts.unreadCount(w.db, w.ch, now))
        // markDisplayed: read, the display minute, the earlier of the two deadlines, the relay expiry forgotten
        assertTrue(w.tx { w.stores.posts.markDisplayed(it, id(1), now, now + 3_600) })
        post = w.stores.posts.post(w.db, id(1), now)!!
        assertEquals(PostState.READ, post.state)
        assertEquals(now, post.displayedMinute)
        assertEquals(now + 3_600, post.deleteAtMinute)
        assertNull(post.relayExpiryHour)
        assertEquals(0, w.stores.posts.unreadCount(w.db, w.ch, now))
        // a second display matches nothing; a later deadline never replaces an earlier one
        assertFalse(w.tx { w.stores.posts.markDisplayed(it, id(1), now + 60, now + 9_999_960) })
        assertTrue(w.tx { w.stores.posts.lowerDeleteAt(it, id(1), now + 1_800) })
        assertFalse(w.tx { w.stores.posts.lowerDeleteAt(it, id(1), now + 3_600) })
        assertEquals(now + 1_800, w.stores.posts.post(w.db, id(1), now)!!.deleteAtMinute)
        // a post with no deadline (a channel whose timer is off) takes the first one it is given
        w.stores.posts.incoming(w, 2, deleteAt = null)
        assertTrue(w.tx { w.stores.posts.markDisplayed(it, id(2), now, null) })
        assertNull(w.stores.posts.post(w.db, id(2), now)!!.deleteAtMinute)
        assertTrue(w.tx { w.stores.posts.lowerDeleteAt(it, id(2), now + 600) })
        assertEquals(now + 600, w.stores.posts.post(w.db, id(2), now)!!.deleteAtMinute)
    }

    /**
     * §8.2: "an unread post is deleted at min(relay expiry E, consume + bucket + 1 h)". E is a deadline of its own, and
     * every read, the unread count, the alarm's next time and the sweep apply it beside `delete_at_minute`. The
     * review of S3 wrote the row that the first version got wrong: a post whose own deadline is ahead and whose E is
     * an hour gone was shown as unread, counted, and left out of the sweep's batch; and one of a channel whose timer
     * is off (no deadline of its own) lived for ever.
     */
    @Test
    fun anUnreadPostIsGoneAtItsRelayExpiryWhateverItsOtherDeadlineIs() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = now + 3_600, relay = now - 3_600)               // E passed, own deadline ahead
        w.stores.posts.incoming(w, 2, deleteAt = null, relay = now - 3_600, timer = 0)           // timer off: E is the only deadline
        w.stores.posts.incoming(w, 3, deleteAt = now + 3_600, relay = now + 3_600)               // both ahead
        w.stores.posts.incoming(w, 4, deleteAt = null, relay = now + 7_200, timer = 0)           // timer off, E ahead
        w.stores.posts.incoming(w, 5, deleteAt = now - 60, relay = now + 3_600)                  // own deadline passed, E ahead
        w.stores.posts.incoming(w, 6, deleteAt = now + 3_600, relay = now)                       // E exactly now: gone
        val live = setOf(3, 4)
        assertEquals(live, w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }.toSet())
        val cursor = PostStore.PostCursor(now + 60, chBytes(32, 0xFF), id(0xFF))
        assertEquals(live, w.stores.posts.pageBefore(w.db, w.ch, now, 50, cursor).map { it.opId[0].toInt() }.toSet())
        for (gone in listOf(1, 2, 5, 6)) assertNull(gone.toString(), w.stores.posts.post(w.db, id(gone), now))
        for (alive in live) assertEquals(alive.toString(), id(alive).toList(), w.stores.posts.post(w.db, id(alive), now)!!.opId.toList())
        assertEquals("the unread badge counts the live ones", 2, w.stores.posts.unreadCount(w.db, w.ch, now))
        // the alarm: the earlier of the two deadlines of the live posts, and nothing past a row's E
        assertEquals(now + 3_600, w.stores.posts.nextDeleteAt(w.db, now))
        assertEquals("post 3's E and its deadline are the same hour", now + 7_200, w.stores.posts.nextDeleteAt(w.db, now + 3_600))
        assertNull(w.stores.posts.nextDeleteAt(w.db, now + 7_200))
        // the sweep names every post either deadline has expired, soonest first
        assertEquals(listOf(1, 2, 5, 6), w.stores.posts.expiredPosts(w.db, now, 10).map { it[0].toInt() })
        assertEquals(listOf(1), w.stores.posts.expiredPosts(w.db, now, 1).map { it[0].toInt() })
        assertEquals(emptyList<Int>(), w.stores.posts.expiredPosts(w.db, now - 3_601, 10).map { it[0].toInt() })
        for (id in w.stores.posts.expiredPosts(w.db, now, 10)) assertTrue(w.tx { w.stores.posts.deletePost(it, id) })
        assertEquals(live, w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }.toSet())
        assertEquals(emptyList<Int>(), w.stores.posts.expiredPosts(w.db, now, 10).map { it[0].toInt() })
        // later, E of post 4 passes in its turn, and the sweep takes it
        assertEquals(listOf(3, 4), w.stores.posts.expiredPosts(w.db, now + 7_200, 10).map { it[0].toInt() })
    }

    @Test
    fun aPostPastADeadlineIsNotDisplayedAndAUnreadOneKeepsItsRelayExpiryUntilItIs() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = now + 3_600, relay = now - 3_600)   // its relay copy is gone
        w.stores.posts.incoming(w, 2, deleteAt = now - 60, relay = now + 3_600)      // its own deadline passed
        w.stores.posts.incoming(w, 3, deleteAt = now + 3_600, relay = now + 3_600)   // live
        // A stale display (a list held across the expiry, a phone unfrozen after a day) must not forget E and give
        // the post back the life its relay copy no longer has; nothing is written for it.
        assertFalse(w.tx { w.stores.posts.markDisplayed(it, id(1), now, now + 600) })
        assertFalse(w.tx { w.stores.posts.markDisplayed(it, id(2), now, now + 600) })
        assertTrue(w.tx { w.stores.posts.markDisplayed(it, id(3), now, now + 600) })
        w.db.query("SELECT op_id, state, relay_expiry_hour FROM ch_post ORDER BY op_id") { r ->
            val n = r.blob(0)[0].toInt()
            if (n == 3) assertEquals("read", r.string(1)) else assertEquals("unread", r.string(1))
            if (n == 3) assertTrue(r.isNull(2)) else assertFalse("E of post $n was forgotten", r.isNull(2))
        }
    }

    /**
     * T33: with the timer off F9's `dm_message` stores no time at all; this table stores the minute a post was read
     * only where a countdown needs it. The first version stored it for every read post, and the schema made it
     * permanent (a coherence CHECK, then write-once), so a timer-off channel kept when the user opened each post for
     * the post's whole life (the review of S3).
     */
    @Test
    fun aTimerOffPostKeepsNoDisplayedMinuteAndATimedOneKeepsIt() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = null, relay = now + 3_600, timer = 0)
        w.stores.posts.incoming(w, 2, deleteAt = now + 3_600, relay = now + 3_600, timer = 4)
        assertTrue(w.tx { w.stores.posts.markDisplayed(it, id(1), now - 3_540, null) })
        assertTrue(w.tx { w.stores.posts.markDisplayed(it, id(2), now - 3_540, now + 600) })
        val off = w.stores.posts.post(w.db, id(1), now)!!
        assertEquals(PostState.READ, off.state)
        assertNull("a read post of a timer-off channel stores no minute", off.displayedMinute)
        assertNull("and no deadline: it lives on", off.deleteAtMinute)
        assertNull(off.relayExpiryHour)
        assertEquals(now - 3_540, w.stores.posts.post(w.db, id(2), now)!!.displayedMinute)
        assertEquals(1L, w.db.queryLong("SELECT count(*) FROM ch_post WHERE displayed_minute IS NOT NULL"))
    }

    @Test
    fun anOutgoingPostRunsTheOutcomeMachineAndAFailedOneIsRetriedUnderTheEpochThenCurrent() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.outgoing(w, 1)
        w.stores.posts.outgoing(w, 2)
        assertEquals(PostState.QUEUED, w.stores.posts.post(w.db, id(1), now)!!.state)
        assertTrue(w.tx { w.stores.posts.setState(it, id(1), PostState.QUEUED, PostState.SENT) })
        assertFalse("the outcome is decided once", w.tx { w.stores.posts.setState(it, id(1), PostState.QUEUED, PostState.FAILED) })
        assertEquals(ChannelStoreError.ILLEGAL_TRANSITION, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.setState(it, id(1), PostState.SENT, PostState.QUEUED) }
        }.error)
        // the display transition has its own method, so the countdown starts with it
        assertEquals(ChannelStoreError.ILLEGAL_TRANSITION, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.setState(it, id(1), PostState.UNREAD, PostState.READ) }
        }.error)
        assertTrue(w.tx { w.stores.posts.setState(it, id(2), PostState.QUEUED, PostState.FAILED) })
        assertTrue(w.tx { w.stores.posts.retry(it, id(2), 4, 2, now - 60, now + 600) })
        val retried = w.stores.posts.post(w.db, id(2), now)!!
        assertEquals(PostState.QUEUED, retried.state)
        assertEquals(4L, retried.epoch)
        assertEquals(2, retried.timerCode)
        assertEquals(now - 60, retried.authorMinute)
        assertEquals("a retry never extends the life of a post", now + 600, retried.deleteAtMinute)
        assertFalse("only a failed post is retried", w.tx { w.stores.posts.retry(it, id(1), 5, 2, now, now + 600) })
        assertEquals(PostState.SENT, w.stores.posts.post(w.db, id(1), now)!!.state)
    }

    @Test
    fun everyReadOfPostsHidesAnExpiredPostAndTheSweepNamesExactlyThatSet() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = now)            // expires this minute
        w.stores.posts.incoming(w, 2, deleteAt = now - 60)       // expired
        w.stores.posts.incoming(w, 3, deleteAt = now + 60)       // live
        w.stores.posts.incoming(w, 4, deleteAt = null)           // live: the timer is off
        w.stores.posts.outgoing(w, 5, deleteAt = now - 3_600)    // expired
        w.stores.posts.outgoing(w, 6, deleteAt = now + 3_600)    // live
        val live = listOf(3, 4, 6)
        assertEquals(3, w.stores.posts.page(w.db, w.ch, now, 50).size)
        assertEquals(live.toSet(), w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }.toSet())
        val cursor = PostStore.PostCursor(now + 60, chBytes(32, 0xFF), id(0xFF))
        assertEquals(live.toSet(), w.stores.posts.pageBefore(w.db, w.ch, now, 50, cursor).map { it.opId[0].toInt() }.toSet())
        for (expired in listOf(1, 2, 5)) assertNull(expired.toString(), w.stores.posts.post(w.db, id(expired), now))
        for (alive in live) assertEquals(alive.toString(), id(alive).toList(), w.stores.posts.post(w.db, id(alive), now)!!.opId.toList())
        assertEquals("the unread badge counts live rows only", 2, w.stores.posts.unreadCount(w.db, w.ch, now))
        assertEquals(now + 60, w.stores.posts.nextDeleteAt(w.db, now))
        assertEquals(now + 3_600, w.stores.posts.nextDeleteAt(w.db, now + 60))
        assertNull(w.stores.posts.nextDeleteAt(w.db, now + 3_600))
        // the sweep: the expired ones, soonest first, bounded by the batch
        assertEquals(listOf(5, 2, 1), w.stores.posts.expiredPosts(w.db, now, 10).map { it[0].toInt() })
        assertEquals(listOf(5), w.stores.posts.expiredPosts(w.db, now, 1).map { it[0].toInt() })
        assertEquals(emptyList<Int>(), w.stores.posts.expiredPosts(w.db, now - 3_601, 10).map { it[0].toInt() })
        // deleting the expired posts leaves the others and the reads agree before and after
        for (id in w.stores.posts.expiredPosts(w.db, now, 10)) assertTrue(w.tx { w.stores.posts.deletePost(it, id) })
        assertEquals(live.toSet(), w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }.toSet())
        assertEquals(emptyList<Int>(), w.stores.posts.expiredPosts(w.db, now, 10).map { it[0].toInt() })
    }

    @Test
    fun anIncomingPostWhoseIdIsTakenIsNotInsertedAndDoesNotTripTheGuard() = StoreWorld().use { w ->
        w.channel()
        assertTrue(w.stores.posts.incoming(w, 1))
        val before = w.stores.posts.post(w.db, id(1), now)!!
        // a second post with the same id from another author, an expired row that holds the id, an own post's id
        assertFalse(w.tx { w.stores.posts.insertIncomingIfAbsent(it, id(1), w.ch, author(9), 1, null, 4, 0, chBytes(60, 9), now, now + 60, null) })
        w.stores.posts.outgoing(w, 2, deleteAt = now - 60)
        assertFalse(w.tx { w.stores.posts.insertIncomingIfAbsent(it, id(2), w.ch, author(9), 1, null, 4, 0, chBytes(60, 9), now, now + 60, null) })
        assertArrayEquals(before.bodyEnv, w.stores.posts.post(w.db, id(1), now)!!.bodyEnv)
        assertEquals(2L, w.count("ch_post"))
        // an own post inserted twice is a bug and says so
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.stores.posts.outgoing(w, 2) }.error)
    }

    @Test
    fun reactionsAreOnePerAuthorAndTargetAndNeverOutliveThePostInAnyView() = StoreWorld().use { w ->
        w.channel()
        w.stores.posts.incoming(w, 1, deleteAt = now + 600)
        w.stores.posts.incoming(w, 2, deleteAt = now - 60)
        w.tx { w.stores.posts.putReaction(it, id(1), author(1), w.ch, chBytes(30, 1)) }
        w.tx { w.stores.posts.putReaction(it, id(1), author(2), w.ch, chBytes(31, 2)) }
        w.tx { w.stores.posts.putReaction(it, id(1), author(1), w.ch, chBytes(32, 3)) }
        w.tx { w.stores.posts.putReaction(it, id(2), author(1), w.ch, chBytes(30, 4)) }
        val onFirst = w.stores.posts.reactions(w.db, id(1), now)
        assertEquals(listOf(author(1).toList(), author(2).toList()), onFirst.map { it.author.toList() })
        assertArrayEquals("the second reaction of an author replaces the first", chBytes(32, 3), onFirst[0].graphemeEnv)
        assertEquals("a reaction to an expired post is not shown", emptyList<Any>(), w.stores.posts.reactions(w.db, id(2), now))
        assertEquals(3L, w.count("ch_reaction"))
        assertTrue(w.tx { w.stores.posts.deleteReaction(it, id(1), author(2)) })
        assertFalse(w.tx { w.stores.posts.deleteReaction(it, id(1), author(2)) })
        // the cascade: the post goes, its reactions with it
        assertTrue(w.tx { w.stores.posts.deletePost(it, id(1)) })
        assertEquals(1L, w.count("ch_reaction"))
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.putReaction(it, id(2), author(5), w.ch, chBytes(61, 1)) }
        }.error)
        assertRedacted(onFirst[0], chBytes(32, 3), author(1))
    }

    @Test
    fun aReactionThatReachesTheDeviceBeforeItsPostIsRefusedAsAnAnswerNotAsAFailure() = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        w.stores.posts.incoming(w, 1)
        // no post holds the target yet: false, nothing written, and the transaction is still usable
        assertFalse(w.tx { w.stores.posts.putReaction(it, id(9), author(1), w.ch, chBytes(30, 1)) })
        assertEquals(0L, w.count("ch_reaction"))
        // a post of another channel is not a target: the reaction hangs on a post of its own channel only
        assertFalse(w.tx { w.stores.posts.putReaction(it, id(1), author(1), w.ch2, chBytes(30, 1)) })
        assertEquals(0L, w.count("ch_reaction"))
        // the post arrives, the reaction is stored; the same author reacting again is an update (true, one row)
        assertTrue(w.tx { w.stores.posts.putReaction(it, id(1), author(1), w.ch, chBytes(30, 1)) })
        assertTrue(w.tx { w.stores.posts.putReaction(it, id(1), author(1), w.ch, chBytes(31, 2)) })
        assertEquals(1L, w.count("ch_reaction"))
    }

    @Test
    fun aPendingPostIsReadUntilItsDeadlineThenFailsAndTheQueueIsBounded() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.posts.insertPending(it, id(1), w.ch, 1, chBytes(50, 1), hour + 3_600) }
        w.tx { w.stores.posts.insertPending(it, id(2), w.ch, 1, chBytes(50, 2), hour) }
        w.tx { w.stores.posts.insertPending(it, id(3), w.ch, 2, chBytes(50, 3), hour - 3_600) }
        assertEquals(listOf(1), w.stores.posts.pending(w.db, w.ch, now).map { it.opId[0].toInt() })
        assertEquals(listOf(2, 1), w.stores.posts.pending(w.db, w.ch, hour - 3_599).map { it.opId[0].toInt() })
        assertEquals(listOf(3, 2), w.stores.posts.expiredPending(w.db, now, 10).map { it.opId[0].toInt() })
        assertEquals(listOf(3), w.stores.posts.expiredPending(w.db, now, 1).map { it.opId[0].toInt() })
        assertTrue(w.tx { w.stores.posts.deletePending(it, id(3)) })
        assertFalse(w.tx { w.stores.posts.deletePending(it, id(3)) })
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.insertPending(it, id(1), w.ch, 1, chBytes(50, 1), hour + 3_600) }
        }.error)
        // 256 per channel (§6.3.5): the 257th is a typed error, not a trigger abort
        for (i in 0 until 254) {
            w.tx { w.stores.posts.insertPending(it, ByteArray(16).also { b -> b[0] = 0x70; b[1] = (i / 200).toByte(); b[2] = (i % 200).toByte() }, w.ch, 1, chBytes(40, 1), hour + 3_600) }
        }
        assertEquals(256L, w.count("ch_pending_post"))
        assertEquals(ChannelStoreError.LIMIT, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.insertPending(it, id(0x7E), w.ch, 1, chBytes(40, 1), hour + 3_600) }
        }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) {
            w.tx { w.stores.posts.insertPending(it, id(0x7F), w.ch2, 8, chBytes(40, 1), hour) }
        }.error)
    }

    @Test
    fun aSeenTagIsWrittenWithInsertOrIgnoreAndReadWhileItIsWithinItsDay() = StoreWorld().use { w ->
        w.channel()
        val tag = chBytes(16, 5)
        val week = 19_999L // 7 x 2 857: the retention of a tag is a week, as dm_seen's (F9 section 7.6 D3)
        assertFalse(w.stores.posts.isSeen(w.db, w.ch, tag, 19_990))
        assertTrue(w.tx { w.stores.posts.markSeen(it, w.ch, tag, week) })
        assertFalse("a second sighting adds nothing", w.tx { w.stores.posts.markSeen(it, w.ch, tag, week + 28) })
        assertTrue(w.stores.posts.isSeen(w.db, w.ch, tag, week))
        assertFalse("past its day the tag is no evidence", w.stores.posts.isSeen(w.db, w.ch, tag, week + 1))
        assertFalse("another channel has its own tags", w.stores.posts.isSeen(w.db, w.ch2, tag, 19_990))
        assertEquals(0, w.tx { w.stores.posts.deleteSeenTags(it, week) })
        assertEquals(1, w.tx { w.stores.posts.deleteSeenTags(it, week + 1) })
        assertEquals(0L, w.count("ch_seen"))
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.markSeen(it, w.ch, chBytes(15, 1), week) } }.error)
    }

    /**
     * The retention of a tag is a week (`ceil7`), as `dm_seen`'s: a seizer learns the week a post was displayed in and
     * not the day. The first version stored any day (the review of S3: 20 833 was accepted where `dm_seen` refuses it).
     */
    @Test
    fun aSeenTagIsKeptUntilAWeekAndNoFinerThanThat() = StoreWorld().use { w ->
        w.channel()
        for (day in listOf(20_000L, 20_833L, 20_005L, 1L)) {
            assertEquals(day.toString(), ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) {
                w.tx { w.stores.posts.markSeen(it, w.ch, chBytes(16, 5), day) }
            }.error)
        }
        assertEquals(0L, w.count("ch_seen"))
        assertTrue(w.tx { w.stores.posts.markSeen(it, w.ch, chBytes(16, 5), 20_832) })
        assertTrue(w.tx { w.stores.posts.markSeen(it, w.ch, chBytes(16, 6), 0) })
        // the table says the same: the store is not the only line
        assertEquals(1, w.db.execUpdate("UPDATE ch_seen SET until_day = 20839 WHERE tag = ?", listOf(chBytes(16, 5))))
        val refused = assertThrows(java.sql.SQLException::class.java) {
            w.db.execUpdate("UPDATE ch_seen SET until_day = 20833 WHERE tag = ?", listOf(chBytes(16, 5)))
        }
        assertTrue(refused.message.orEmpty(), refused.message.orEmpty().contains("CHECK constraint failed"))
    }

    @Test
    fun aRevealIsKeptUntilItsPostsTimerAndNeverLongerAndATimerOffChannelHasNoDeadline() = StoreWorld().use { w ->
        w.channel()
        w.tx { w.stores.posts.putReveal(it, w.ch, Direction.OUT, author(1), now + 600) }
        w.tx { w.stores.posts.putReveal(it, w.ch, Direction.IN, author(1), now - 60) }
        w.tx { w.stores.posts.putReveal(it, w.ch, Direction.IN, author(2), null) }
        assertEquals(
            listOf(Direction.IN to author(2).toList(), Direction.OUT to author(1).toList()),
            w.stores.posts.reveals(w.db, w.ch, now).map { it.direction to it.peer.toList() }.sortedBy { it.first.sql },
        )
        // putting the same (direction, peer) again moves its deadline, it does not add a row
        w.tx { w.stores.posts.putReveal(it, w.ch, Direction.OUT, author(1), now + 1_200) }
        assertEquals(3L, w.count("ch_reveal"))
        assertEquals(1, w.stores.posts.expiredReveals(w.db, now, 10).size)
        assertEquals(1, w.tx { w.stores.posts.deleteExpiredReveals(it, now) })
        assertEquals(2L, w.count("ch_reveal"))
        assertRedacted(w.stores.posts.reveals(w.db, w.ch, now).first(), author(1), author(2), w.ch)
    }

    @Test
    fun theOperationsOfAChannelAreMappedToTheObjectTheyCarry() = StoreWorld().use { w ->
        w.channel()
        val hash = chBytes(32, 0x42)
        val blob = chBytes(4096, 0x42)
        w.tx { w.stores.posts.insertOp(it, id(1), w.ch, OpPurpose.COMMIT, hash, blob, 7_200) }
        w.tx { w.stores.posts.insertOp(it, id(2), w.ch, OpPurpose.POST, id(7), chBytes(4096, 0x43), 7_200) }
        w.tx { w.stores.posts.insertOp(it, id(3), w.ch, OpPurpose.REQUEST, null, chBytes(4096, 0x44), 7_200) }
        assertEquals(OpPurpose.COMMIT, w.stores.posts.op(w.db, id(1))!!.purpose)
        assertArrayEquals(hash, w.stores.posts.op(w.db, id(1))!!.ref)
        assertNull(w.stores.posts.op(w.db, id(3))!!.ref)
        assertArrayEquals(blob, w.stores.posts.op(w.db, id(1))!!.blob)
        assertEquals(7_200L, w.stores.posts.op(w.db, id(1))!!.deadlineHour)
        assertEquals(0, w.stores.posts.op(w.db, id(1))!!.resends)
        assertEquals(listOf(id(1).toList()), w.stores.posts.opsFor(w.db, w.ch, OpPurpose.COMMIT, hash).map { it.operationId.toList() })
        assertEquals(emptyList<Any>(), w.stores.posts.opsFor(w.db, w.ch, OpPurpose.POST, hash))
        assertEquals(1, w.stores.posts.opsOf(w.db, w.ch, OpPurpose.POST).size)
        assertTrue(w.tx { w.stores.posts.deleteOp(it, id(1)) })
        assertNull(w.stores.posts.op(w.db, id(1)))
        assertEquals(ChannelStoreError.ROW_EXISTS, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(2), w.ch, OpPurpose.POST, null, chBytes(4096, 0x45), 7_200) } }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(4), w.ch, OpPurpose.POST, chBytes(65, 1), chBytes(4096, 0x46), 7_200) } }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(5), w.ch, OpPurpose.POST, null, chBytes(100, 1), 7_200) } }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(6), w.ch, OpPurpose.POST, null, chBytes(4096, 0x47), 60) } }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(7), w.ch, OpPurpose.POST, null, chBytes(4096, 0x48), 7_200, resends = 3) } }.error)
        // the blob is a floor-sized bucket of §5.6, not a range (§19.46 FIX 6): a non-bucket size is
        // the typed BAD_VALUE before the statement runs — without the check the schema's CHECK refuses
        // it as a raw SQLException, which no typed catch of the engine can name
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(8), w.ch, OpPurpose.POST, null, chBytes(4097, 0x49), 7_200) } }.error)
        assertEquals(ChannelStoreError.BAD_VALUE, assertThrows(ChannelStoreException::class.java) { w.tx { w.stores.posts.insertOp(it, id(9), w.ch, OpPurpose.POST, null, chBytes(65_537, 0x4a), 7_200) } }.error)
        w.tx { w.stores.posts.insertOp(it, id(10), w.ch, OpPurpose.POST, null, chBytes(16_384, 0x4b), 7_200) }
        w.tx { w.stores.posts.insertOp(it, id(11), w.ch, OpPurpose.POST, null, chBytes(65_536, 0x4c), 7_200) }
        assertEquals(16_384, w.stores.posts.op(w.db, id(10))!!.blob.size)
        assertEquals(65_536, w.stores.posts.op(w.db, id(11))!!.blob.size)
        assertRedacted(w.stores.posts.op(w.db, id(2))!!, id(7), w.ch)
    }

    @Test
    fun noPostShowsABodyAnAuthorOrAReplyTargetInItsToString() = StoreWorld().use { w ->
        w.channel()
        val body = chBytes(60, 0x33)
        w.tx { w.stores.posts.insertIncomingIfAbsent(it, id(1), w.ch, author(1), 1, id(7), 4, 0, body, now, now + 60, null) }
        val post = w.stores.posts.post(w.db, id(1), now)!!
        assertRedacted(post, body, author(1), id(7), id(1), w.ch)
        assertRedacted(PostStore.PostCursor(now, author(1), id(1)), author(1), id(1))
        assertRedacted(w.stores.posts.page(w.db, w.ch, now, 1).single(), body)
        assertArrayEquals(id(7), post.replyTo)
    }
}
