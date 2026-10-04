package org.ghost.messaging.channel.store

import org.ghost.storage.ChannelSchema
import org.ghost.storage.Checkpoint
import org.ghost.storage.SqlExecutor
import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **R-M1 for channels** (Phase 10 design §8.5 "Rows derived from posts", §9 last paragraph, §11.2 T25 and T33;
 * the twin of Phase 9's `DmForensicResidueTest`, slice S3): after every post and every row derived from a post
 * has expired and the sweep has run, a full dump of the database shows only what the design declares as
 * membership metadata, key material within retention and the per-channel state — and no time but the ones §9
 * lists.
 *
 * Unlike the DM twin this runs the sweep **through the DAOs**: the test composes `CH-SWEEP` from the sweep
 * reads and the deletes the stores offer (the real step is S8's), so it also proves that the stores give the
 * sweep a way to delete every table that has a deadline — a table whose rows the stores cannot take away is a
 * residue nobody can remove. The physical half (T25's scan of the file for a canary after the expiry) runs on a
 * database file, with `secure_delete` on as the connection pragmas set it, **in WAL mode as the device runs** and
 * with the sweep's last step, `wal_checkpoint(TRUNCATE)` (§8.2, §10.4 `CH-SWEEP`): without it the body stays in the
 * log (shown by the second test of the physical half), and the scan covers the `-wal` file as well as the database.
 */
class ChannelResidueTest {

    private val now = 1_800_000_000L
    private val today = 20_833L

    private fun id(n: Int) = chBytes(16, n)
    private fun key(n: Int) = chBytes(32, n)

    /** A channel that has lived: every table has rows, and every row with a deadline is past it. */
    private fun live(w: StoreWorld, canary: ByteArray = chBytes(48, 0x5A)) {
        val s = w.stores
        w.channel()
        w.tx { tx ->
            s.channels.setLastCommitterCommitDay(tx, w.ch, today - 3)
            s.channels.putLiveness(tx, w.ch, 2, 0b011, 1, chBytes(60, 3), now - 3_600)
            s.channels.putSchedule(tx, w.ch, today + 20, today - 3, now + 7_200)
            // generations: g1 drained yesterday, g2 current, g3 pending its switch
            s.generations.insert(tx, w.ch, 1, key(0xA1), GenerationState.DRAINING, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4), openEpoch = 0, drainUntilDay = today - 1)
            s.generations.insert(tx, w.ch, 2, key(0xA2), GenerationState.CURRENT, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4), openEpoch = 1)
            s.generations.insert(tx, w.ch, 3, key(0xA3), GenerationState.PENDING_SWITCH, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4), openEpoch = 2, switchHour = now + 3_600)
            // epochs: 0 past its retention, 1 retained, 2 open with candidates; the log and the fork signals
            s.epochs.insert(tx, w.ch, 0, chBytes(68, 5), chBytes(32, 6))
            s.epochs.finalize(tx, w.ch, 0, key(7), today - 12, today - 1)
            s.epochs.insert(tx, w.ch, 1, chBytes(68, 5), chBytes(32, 6))
            // 25 own posts in epoch 1: its count is the seq of the next one, and must not outlive the epoch's use
            repeat(25) { s.epochs.nextOwnSeq(tx, w.ch, 1, today) }
            s.epochs.finalize(tx, w.ch, 1, key(8), today - 3, today + 1)
            s.epochs.insert(tx, w.ch, 2, chBytes(68, 5), chBytes(32, 6), anchorMinute = now - 600)
            s.epochs.appendLog(tx, w.ch, 0, key(7), today - 12)
            s.epochs.appendLog(tx, w.ch, 1, key(8), today - 3)
            s.epochs.addForkSignal(tx, w.ch, 0, key(30), today - 11)
            s.epochs.addForkSignal(tx, w.ch, 1, key(31), today - 2)
            s.candidates.insert(tx, w.ch, 2, key(40), key(41), 0, true, chBytes(300, 1), now - 600, welcomeEnv = chBytes(900, 2), boxEnv = chBytes(60, 3))
            s.candidates.insert(tx, w.ch, 2, key(42), key(43), 255, false, chBytes(300, 4), now - 540)
            // keys of OpenMLS, a KeyPackage past its day, the member's box keys (one replaced in epoch 0)
            s.mls.apply(tx, w.ch, (0 until 11).map { i -> MlsKvStore.KvChange(MlsKvStore.Scope.GROUP, "Tree".toByteArray() + byteArrayOf(0, i.toByte()), chBytes(200, i)) })
            s.mls.apply(tx, w.ch, listOf(MlsKvStore.KvChange(MlsKvStore.Scope.GLOBAL, "KeyPackage".toByteArray() + byteArrayOf(0, 1), chBytes(900, 1))), globalDeleteAfterDay = today - 1)
            s.members.insertBoxKey(tx, w.ch, key(0x71), chBytes(60, 1))
            s.members.insertBoxKey(tx, w.ch, key(0x72), chBytes(60, 2))
            s.members.retireBoxKey(tx, w.ch, key(0x71), 0)
            // posts: three expired, one with a reaction, a pending one and a revealed one
            // post 1 is expired by its relay expiry E alone: its own deadline is an hour ahead (the review of S3 wrote
            // the row the other way round, where both deadlines were past and the sweep could not tell E from the rest)
            s.posts.insertIncomingIfAbsent(tx, id(1), w.ch, key(0x81), 1, null, 4, 1, canary, now - 7_200, now + 3_600, now - 3_600)
            s.posts.insertIncomingIfAbsent(tx, id(2), w.ch, key(0x82), 1, id(1), 4, 1, chBytes(60, 2), now - 7_140, now - 120, null)
            s.posts.markDisplayed(tx, id(2), now - 7_020, now - 60)
            s.posts.insertOutgoing(tx, id(3), w.ch, key(0x80), 1, null, 4, 1, chBytes(60, 3), now - 7_080, now - 3_600)
            s.posts.setState(tx, id(3), PostState.QUEUED, PostState.SENT)
            s.posts.putReaction(tx, id(1), key(0x82), w.ch, chBytes(30, 5))
            s.posts.insertPending(tx, id(4), w.ch, 1, chBytes(60, 4), now - 3_600)
            s.posts.putReveal(tx, w.ch, Direction.OUT, key(0x82), now - 60)
            s.posts.markSeen(tx, w.ch, chBytes(16, 6), today - 1)
            s.posts.insertOp(tx, id(5), w.ch, OpPurpose.POST, id(3))
            s.posts.insertOp(tx, id(6), w.ch, OpPurpose.COMMIT, key(40))
            // joins, requests, invites, tags: all past their day
            s.joins.insertJoin(
                tx, w.ch, key(0x91), JoinType.JOIN, id(0x31), 0, today - 1,
                ns = key(0x92), jkEnv = chBytes(60, 0x93), rJoin = key(0x94), committersDigest = key(0x95),
            )
            s.joins.insertRequest(tx, w.ch, key(0x92), 0, JoinType.JOIN, id(0x31), chBytes(500, 1), today - 1)
            s.joins.markKpSeen(tx, w.ch, chBytes(16, 7), today - 1)
            s.invites.insertIssued(tx, w.ch, id(0x31), key(0x93), key(0x94), chBytes(64, 1), chBytes(32, 2), null, today - 1)
            s.invites.insertOwn(tx, id(0x31), w.ch, chBytes(363, 1), today - 1)
            s.members.record(tx, w.ch, RequestKind.LEAVE, key(0x95), null, today - 1)
            // membership metadata that outlives them
            s.invites.putSponsor(tx, w.ch, key(0x82), key(0x94), id(0x31), today - 20)
            s.members.putRefresh(tx, w.ch, key(0x82), today - 2)
            s.members.noteMemberSeen(tx, w.ch, key(0x82), 1)
            // the channel state key (slice S4, §10.4 "State key"): one for every channel, never swept
            s.self.insertIfAbsent(tx, chBytes(48, 0x66))
        }
    }

    /** `CH-SWEEP` composed from the stores' sweep reads and deletes, the way S8 will compose it (§10.4). */
    private fun sweep(w: StoreWorld, checkpoint: Boolean = true) {
        val s = w.stores
        w.tx { tx ->
            val expired = s.posts.expiredPosts(w.db, now, 500)
            check(expired.any { it.contentEquals(id(1)) }) { "the sweep's read does not name the post that only E has expired" }
            for (post in expired) s.posts.deletePost(tx, post)
            for (pending in s.posts.expiredPending(w.db, now, 500)) s.posts.deletePending(tx, pending.opId)
            s.posts.deleteExpiredReveals(tx, now)
            s.posts.deleteSeenTags(tx, today)
            s.joins.deleteKpTags(tx, today)
            for (g in s.generations.drained(w.db, today, 500)) s.generations.delete(tx, g.channelId, g.generation)
            for (e in s.epochs.expired(w.db, today, 500)) {
                s.epochs.deleteForkSignals(tx, e.channelId, e.epoch)
                s.epochs.delete(tx, e.channelId, e.epoch)
            }
            // the epoch 0 left retention, so the box keys that only epoch 0 held leave with it (the oldest retained is 1)
            s.members.deleteRetiredBefore(tx, w.ch, 1)
            for (j in s.joins.expiredJoins(w.db, today, 500)) {
                s.joins.deleteJoin(tx, j.channelId, j.kpRef)
                s.mls.deleteGlobalRows(tx, j.channelId)
            }
            for (r in s.joins.expiredRequests(w.db, today, 500)) s.joins.deleteRequest(tx, r.channelId, r.hash)
            for (i in s.invites.expiredIssued(w.db, today, 500)) s.invites.deleteIssued(tx, i.channelId, i.inviteId)
            s.invites.deleteExpiredOwn(tx, today)
            for (r in s.members.expiredRequests(w.db, today, 500)) s.members.deleteRequest(tx, r.channelId, r.kind, r.subject)
            for (k in s.mls.expiredGlobal(w.db, today, 500)) s.mls.deleteGlobal(tx, k)
            // CH-OUTCOME: an op is deleted when its outcome is decided; here both are decided
            for (op in listOf(id(5), id(6))) s.posts.deleteOp(tx, op)
        }
        // the sweep ends with the checkpoint, outside the transaction, its result checked (§8.2, F9 `Checkpoint.truncate`)
        if (checkpoint) check(Checkpoint.truncate(w.db) { }) { "the checkpoint stayed busy" }
    }

    private fun SqlExecutor.nonEmpty(): Map<String, Long> {
        val out = LinkedHashMap<String, Long>()
        for (table in ChannelSchema.tables.sorted()) {
            val n = queryLong("SELECT count(*) FROM $table") ?: 0L
            if (n > 0) out[table] = n
        }
        return out
    }

    @Test
    fun afterTheSweepTheDumpShowsOnlyWhatTheDesignDeclaresAsResidue() = StoreWorld().use { w ->
        live(w)
        // before: every one of the 27 tables has a row (the world is lived-in)
        assertEquals(ChannelSchema.tables, w.db.nonEmpty().keys)
        sweep(w)
        val residue = w.db.nonEmpty()
        assertEquals(
            "tables that still hold rows after the sweep",
            setOf(
                // the per-channel state (§9)
                "ch_channel", "ch_liveness", "ch_schedule", "ch_generation", "ch_epoch", "ch_epoch_log", "ch_candidate",
                "ch_fork_signal",
                // the OpenMLS state and the member's own keys within retention
                "mls_kv", "ch_box_key",
                // membership metadata the design declares (§8.5): sponsor, refresh days, last epochs
                "ch_sponsor", "ch_member_refresh", "ch_member_seen",
                // the wrapped channel state key (slice S4, §10.4): it lives as long as the database's channels can
                "mls_self",
            ),
            residue.keys,
        )
        // what is gone is gone for every row derived from a post (§8.5's table)
        for (gone in listOf("ch_post", "ch_reaction", "ch_pending_post", "ch_reveal", "ch_seen", "ch_outbound_op", "ch_invite_issued", "ch_invite_own", "ch_request", "ch_join", "ch_join_request", "ch_kp_seen", "mls_global_kv")) {
            assertFalse("$gone", gone in residue)
        }
        // the generations and epochs that remain are the live ones, with the rows that belong to them
        assertEquals(2L, residue["ch_generation"])
        assertEquals(2L, residue["ch_epoch"])
        assertEquals("the log is trimmed by count, not by the sweep", 2L, residue["ch_epoch_log"])
        assertEquals(2L, residue["ch_candidate"])
        assertEquals(1L, residue["ch_box_key"])
        assertEquals(1L, residue["ch_fork_signal"])
        assertEquals(11L, residue["mls_kv"])
        // no count of the member's own posts outlives the use of an epoch: finality reset the 25 that epoch 1 had
        assertEquals(1L, w.db.queryLong("SELECT count(*) FROM ch_epoch WHERE state = 'final'"))
        assertEquals(0L, w.db.queryLong("SELECT count(*) FROM ch_epoch WHERE state = 'final' AND own_seq <> 0"))
    }

    /**
     * The rows that outlive their post are not an order either (T33; the review of S3: with a hidden rowid the gaps
     * between the rowids that survive count the rows swept, of every channel — one timer-off channel and one
     * 5-minute channel posting 1 + 40 + 1 + 7 + 1 posts left the rowids 1, 42 and 50, and the gaps of 40 and 7 were the
     * other channel's expired posts). Posts of two channels, written in descending key order and half of them expired:
     * after the sweep the table has no rowid to read, and a scan of it comes back in key order, not in the order the
     * rows arrived in.
     */
    @Test
    fun theSurvivorsOfTwoChannelsShowNeitherARowidNorTheOrderTheyArrivedIn(): Unit = StoreWorld().use { w ->
        w.channel()
        w.channel(w.ch2)
        w.tx { tx ->
            for ((i, n) in (60 downTo 1).withIndex()) {
                val channel = if (i % 2 == 0) w.ch else w.ch2
                val deleteAt = if (i % 3 == 0) now - 60 else now + 3_600
                w.stores.posts.insertIncomingIfAbsent(tx, id(n), channel, key(i), 1, null, 4, 1, chBytes(60, n), now - 3_600, deleteAt, null)
            }
        }
        val expired = w.stores.posts.expiredPosts(w.db, now, 500)
        assertEquals(20, expired.size)
        w.tx { tx -> for (post in expired) w.stores.posts.deletePost(tx, post) }
        val scan = ArrayList<Int>()
        // The body is read, so no secondary index covers the query (`SELECT op_id` alone is answered from the order
        // index, in its order) and the scan is the table's own b-tree, whose order is the key's.
        w.db.query("SELECT op_id, body_env FROM ch_post") { scan += it.blob(0)[0].toInt() }
        assertEquals(40, scan.size)
        assertEquals("the scan is in key order, ascending, while the rows were written descending", scan.sorted(), scan)
        assertThrows(java.sql.SQLException::class.java) { w.db.query("SELECT rowid FROM ch_post") { } }
    }

    /**
     * A channel whose timer is off keeps a read post for ever, and keeps nothing of when it was read: no displayed
     * minute (F9's `dm_message` stores no time with the timer off, T33), no deadline, no relay expiry. An unread one
     * is swept at its relay expiry like any other (§8.2), which is the only deadline it has.
     */
    @Test
    fun aReadPostOfATimerOffChannelLivesOnWithNoTimeButItsAuthorMinute() = StoreWorld().use { w ->
        w.channel()
        w.tx { tx ->
            w.stores.posts.insertIncomingIfAbsent(tx, id(1), w.ch, key(1), 1, null, 0, 1, chBytes(60, 1), now - 7_200, null, now + 3_600)
            w.stores.posts.markDisplayed(tx, id(1), now - 3_540, null)
            w.stores.posts.insertIncomingIfAbsent(tx, id(2), w.ch, key(2), 1, null, 0, 1, chBytes(60, 2), now - 7_200, null, now - 3_600)
            w.stores.posts.insertIncomingIfAbsent(tx, id(3), w.ch, key(3), 1, null, 0, 1, chBytes(60, 3), now - 7_200, null, now + 3_600)
        }
        assertEquals(listOf(2), w.stores.posts.expiredPosts(w.db, now, 10).map { it[0].toInt() })
        w.tx { tx -> for (post in w.stores.posts.expiredPosts(w.db, now, 10)) w.stores.posts.deletePost(tx, post) }
        // the read post is still there at any later time; the unread one goes when its relay copy does
        assertEquals(listOf(1, 3), w.stores.posts.page(w.db, w.ch, now, 50).map { it.opId[0].toInt() }.sorted())
        assertEquals(listOf(3), w.stores.posts.expiredPosts(w.db, now + 3_600, 10).map { it[0].toInt() })
        assertEquals(listOf(1), w.stores.posts.page(w.db, w.ch, now + 3_600, 50).map { it.opId[0].toInt() })
        assertEquals(listOf(1), w.stores.posts.page(w.db, w.ch, now + 400 * 86_400L, 50).map { it.opId[0].toInt() })
        val read = w.stores.posts.post(w.db, id(1), now + 400 * 86_400L)!!
        assertEquals(PostState.READ, read.state)
        assertNull("no read minute", read.displayedMinute)
        assertNull("no deadline", read.deleteAtMinute)
        assertNull("no relay expiry", read.relayExpiryHour)
        assertEquals(0L, w.db.queryLong("SELECT count(*) FROM ch_post WHERE displayed_minute IS NOT NULL OR relay_expiry_hour IS NOT NULL AND state = 'read'"))
    }

    @Test
    fun theTimeColumnsThatStillHoldAValueAreAllAmongThoseSectionNineDeclares() = StoreWorld().use { w ->
        live(w)
        sweep(w)
        val declared = ChannelSchema.timeColumns
        val remaining = HashSet<String>()
        for (table in ChannelSchema.tables) {
            val columns = ArrayList<String>()
            w.db.query("PRAGMA table_info($table)") { columns += it.string(1) }
            for (column in columns) {
                if ("$table.$column" !in declared) continue
                if ((w.db.queryLong("SELECT count(*) FROM $table WHERE $column IS NOT NULL") ?: 0L) > 0) remaining += "$table.$column"
            }
        }
        // the declared activity records (§9 intro, §19.21), and nothing that is the time of a post
        assertEquals(
            setOf(
                "ch_channel.last_committer_commit_day", "ch_liveness.unopenable_first_minute",
                "ch_schedule.next_selfupdate_day", "ch_schedule.last_own_commit_day", "ch_schedule.next_pass_minute",
                "ch_generation.switch_hour", "ch_epoch.anchor_minute", "ch_epoch.final_day", "ch_epoch.keep_until_day",
                "ch_epoch_log.final_day", "ch_candidate.first_seen_minute", "ch_fork_signal.first_seen_day",
                "ch_sponsor.admitted_day", "ch_member_refresh.refresh_day",
            ),
            remaining,
        )
        assertFalse("a post's time outlived its post", remaining.any { it.startsWith("ch_post.") || it.startsWith("ch_reveal.") })
        // the anchor of a final epoch is cleared (§19.21): only the open epoch holds one
        assertEquals(1L, w.db.queryLong("SELECT count(*) FROM ch_epoch WHERE anchor_minute IS NOT NULL"))
        assertEquals(0L, w.db.queryLong("SELECT count(*) FROM ch_epoch WHERE anchor_minute IS NOT NULL AND state = 'final'"))
    }

    /** T25 on the file: the canary text of an expired post is not in the database file once the sweep has run. */
    @Test
    fun theBodyOfAnExpiredPostIsNotInTheDatabaseFileAfterTheSweep() {
        val file = File.createTempFile("ghost-channel-residue", ".db")
        try {
            StoreWorld(file.path).use { w ->
                val canary = ByteArray(48) { (0xC0 + it % 16).toByte() }
                live(w, canary)
                val before = file.readBytes()
                assertTrue("the control: the canary is in the file while the post is alive", before.indexOf(canary) >= 0)
                sweep(w)
                assertFalse("the post is gone from the table", w.stores.posts.page(w.db, w.ch, now - 100_000, 50).any { it.opId.contentEquals(id(1)) })
                val after = file.readBytes()
                assertEquals("the canary is overwritten, not only unlinked (secure_delete)", -1, after.indexOf(canary))
            }
        } finally {
            file.delete()
        }
    }

    private fun holds(file: File, wal: File, needle: ByteArray): Boolean =
        file.readBytes().indexOf(needle) >= 0 || (wal.isFile && wal.readBytes().indexOf(needle) >= 0)

    /**
     * T25 on the device's layout (the review of S3: the test above runs in rollback-journal mode and scans the
     * database file alone, while the device runs in WAL mode, where a deleted body is not only in the file — the log
     * keeps the earlier images of its page until a checkpoint truncates it). The sweep ends with the checkpoint
     * (§8.2); after it neither the file nor the `-wal` file holds the canary, and without it the log still does.
     */
    @Test
    fun inWalModeTheBodyOfAnExpiredPostIsInNeitherTheFileNorTheLogOnceTheSweepHasCheckpointed() {
        val file = File.createTempFile("ghost-channel-residue-wal", ".db")
        val wal = File(file.path + "-wal")
        try {
            StoreWorld(file.path, wal = true).use { w ->
                assertEquals("wal", w.db.queryString("PRAGMA journal_mode"))
                val canary = ByteArray(48) { (0xB0 + it % 16).toByte() }
                live(w, canary)
                assertTrue("the control: the canary is in the file or in the log while the post is alive", holds(file, wal, canary))
                sweep(w, checkpoint = false)
                assertTrue("a sweep that does not checkpoint leaves the body in the log", wal.isFile && wal.readBytes().indexOf(canary) >= 0)
                assertTrue(Checkpoint.truncate(w.db) { })
                assertEquals("the log is truncated", 0L, wal.length())
                assertFalse("neither the file nor the log holds the body", holds(file, wal, canary))
            }
        } finally {
            file.delete()
            wal.delete()
            File(file.path + "-shm").delete()
        }
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        outer@ for (i in 0..size - needle.size) {
            for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}
