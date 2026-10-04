package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every state-machine, write-once and bound trigger of migration 7 (Phase 10 design §6.11, §6.3.5 (CS-C8), §8.2,
 * §9, §19.21; slice S3): **each legal transition succeeds and each illegal one is refused**, for every pair
 * of states of every machine, and every bound is exercised at its edge and one past it **and in a second channel**
 * (a bound that counted every channel's rows would pass the first and fail the second: the review of S3 found five
 * of them that no test told from the right one).
 *
 * The tables of legal edges below are written from §6.11 again, not read from the schema, so a trigger that
 * gains or loses an edge fails here. The 36 triggers are listed in [ChannelSchema.rules]; the last test
 * of this class requires that each of them was fired (its message was seen) by a test of the class.
 */
class ChannelTriggersTest {

    private val fired = HashSet<String>()

    /** Runs an UPDATE or a DELETE and returns the rows it changed. */
    private fun ChannelFixture.upd(sql: String, vararg args: Any?): Int = db.execUpdate(sql, args.toList())

    /** Asserts that [sql] aborts with the message of [trigger], and records the trigger as exercised. */
    private fun ChannelFixture.refuses(trigger: String, message: String, sql: String, vararg args: Any?) {
        db.rejects(message, sql, *args)
        fired += trigger
    }

    private val ch = ChannelFixture.CH

    /** A second channel: the room of a bound is the channel's own, and a count over every channel's rows would refuse it. */
    private val other = chBytes(32, 0xC2)

    // ------------------------------------------------------------------ the channel

    private val channelStates = listOf(
        "joining", "active", "leaving", "left", "removed", "replaced", "resync_needed", "reinvite_needed", "join_expired",
    )

    /** §6.11, Channel (member view), and the re-entry of §6.2.2: the pairs (from, to) the machine allows. */
    private val channelEdges: Set<Pair<String, String>> = buildSet {
        for (s in channelStates) add(s to s)
        for (to in listOf("active", "join_expired")) add("joining" to to)
        for (to in listOf("leaving", "removed", "replaced", "resync_needed", "reinvite_needed")) add("active" to to)
        for (to in listOf("left", "removed")) add("leaving" to to)
        for (to in listOf("active", "reinvite_needed")) add("resync_needed" to to)
        add("reinvite_needed" to "active")
        add("replaced" to "active")
        for (from in listOf("left", "removed", "replaced", "join_expired")) add(from to "joining")
    }

    @Test
    fun theChannelStateMachineAllowsExactlyTheEdgesOfSection611() {
        assertEquals(81, channelStates.size * channelStates.size)
        var allowed = 0
        for (from in channelStates) for (to in channelStates) ChannelFixture().use { f ->
            f.put("ch_channel", "state" to from)
            val sql = "UPDATE ch_channel SET state = ? WHERE channel_id = ?"
            if (from to to in channelEdges) {
                allowed++
                assertEquals("$from -> $to", 1, f.upd(sql, to, ch))
                assertEquals(to, f.db.queryString("SELECT state FROM ch_channel"))
            } else {
                f.refuses("ch_channel_state", "illegal channel state transition", sql, to, ch)
                assertEquals("$from -> $to", from, f.db.queryString("SELECT state FROM ch_channel"))
            }
        }
        // 9 no-ops, 2 + 5 + 2 + 2 + 1 + 1 forward edges, and the 4 re-entries.
        assertEquals(9 + 13 + 4, allowed)
    }

    @Test
    fun aChannelKeepsItsIdItsSuiteAndItsPseudonymAndNothingElseIsFixed() = ChannelFixture().use { f ->
        f.put("ch_channel")
        f.refuses("ch_channel_identity", "keeps its id", "UPDATE ch_channel SET channel_id = ?", chBytes(32, 9))
        f.refuses("ch_channel_identity", "keeps its id", "UPDATE ch_channel SET my_pseudonym = ?", chBytes(32, 9))
        f.refuses("ch_channel_identity", "keeps its id", "UPDATE ch_channel SET suite = 3.0 + 0, my_pseudonym = ?", chBytes(32, 9))
        // A rejoin or a settle moves position, policy and flags; a restore of a channel adopts another generation.
        assertEquals(1, f.upd("UPDATE ch_channel SET generation = 3, epoch = 9, joined_epoch = 4, timer_code = 2, size_class = 1, pw_required = 1"))
        assertEquals(1, f.upd("UPDATE ch_channel SET split_suspected = 1, partition_suspected = 1, stale_suspected = 1"))
        assertEquals(1, f.upd("UPDATE ch_channel SET split_suspected = 0, name_env = ?, last_committer_commit_day = 20001", chBytes(40, 1)))
        // The rule is about rows, not about the order of statements: a state change in the same UPDATE is judged too.
        f.refuses("ch_channel_state", "illegal channel state transition", "UPDATE ch_channel SET state = 'joining', generation = 4")
    }

    // ------------------------------------------------------------------ generations

    private val generationStates = listOf("pending_switch", "current", "draining")
    private val generationEdges = setOf(
        "pending_switch" to "pending_switch", "current" to "current", "draining" to "draining",
        "pending_switch" to "current", "current" to "draining",
    )

    /** The columns a row in [state] must carry (the CHECKs of §9 tie the hour and the drain day to the state). */
    private fun generationRow(state: String): Array<Pair<String, Any?>> = when (state) {
        "pending_switch" -> arrayOf("state" to state, "switch_hour" to 3_600L)
        "draining" -> arrayOf("state" to state, "drain_until_day" to 20_014L)
        else -> arrayOf("state" to state)
    }

    private fun generationSet(state: String): String = when (state) {
        "pending_switch" -> "state = 'pending_switch', switch_hour = 3600, drain_until_day = NULL"
        "draining" -> "state = 'draining', switch_hour = NULL, drain_until_day = 20014"
        else -> "state = 'current', switch_hour = NULL, drain_until_day = NULL"
    }

    @Test
    fun theGenerationMachineIsPendingSwitchCurrentDrainingAndNothingElse() {
        for (from in generationStates) for (to in generationStates) ChannelFixture().use { f ->
            f.put("ch_generation", *generationRow(from))
            val sql = "UPDATE ch_generation SET ${generationSet(to)} WHERE generation = 0"
            if (from to to in generationEdges) {
                assertEquals("$from -> $to", 1, f.upd(sql))
                assertEquals(to, f.db.queryString("SELECT state FROM ch_generation"))
            } else {
                f.refuses("ch_generation_state", "illegal generation transition", sql)
                assertEquals(from, f.db.queryString("SELECT state FROM ch_generation"))
            }
        }
    }

    @Test
    fun aGenerationKeepsItsNamespaceAndItsSecrets() = ChannelFixture().use { f ->
        f.put("ch_generation")
        for ((column, value) in listOf(
            "generation" to 1L, "namespace_id" to chBytes(32, 9), "g_env" to chBytes(60, 9),
            "jk_env" to chBytes(60, 9), "r_join" to chBytes(32, 9),
        )) {
            f.refuses("ch_generation_identity", "keeps its namespace", "UPDATE ch_generation SET $column = ?", value)
        }
        assertEquals(1, f.upd("UPDATE ch_generation SET state = 'draining', drain_until_day = 20014"))
    }

    /**
     * The end of a drain is the day `G_g` and `JK_g` are deleted (§6.5): it only moves earlier, so a re-write
     * cannot keep them. The first version accepted `drain_until_day = 99999`, and its test asserted that a later
     * end is accepted (the review of S3).
     */
    @Test
    fun theEndOfADrainOnlyMovesEarlierAndIsNeverForgotten() = ChannelFixture().use { f ->
        f.put("ch_generation", "state" to "draining", "drain_until_day" to 20_014L)
        val message = "only moves earlier"
        assertEquals(1, f.upd("UPDATE ch_generation SET drain_until_day = 20014"))
        assertEquals(1, f.upd("UPDATE ch_generation SET drain_until_day = 20010"))
        f.refuses("ch_generation_drain", message, "UPDATE ch_generation SET drain_until_day = 20011")
        f.refuses("ch_generation_drain", message, "UPDATE ch_generation SET drain_until_day = 99999")
        f.refuses("ch_generation_drain", message, "UPDATE ch_generation SET drain_until_day = NULL")
        assertEquals(20_010L, f.db.queryLong("SELECT drain_until_day FROM ch_generation"))
        // The end is set once, when a current generation is demoted: NULL -> a day starts the drain.
        f.put("ch_generation", "generation" to 1L, "namespace_id" to chBytes(32, 2), "state" to "current")
        assertEquals(1, f.upd("DELETE FROM ch_generation WHERE generation = 0"))
        assertEquals(1, f.upd("UPDATE ch_generation SET state = 'draining', drain_until_day = 20020 WHERE generation = 1"))
    }

    @Test
    fun aChannelHasAtMostOneCurrentAndOneDrainingGeneration() = ChannelFixture().use { f ->
        f.put("ch_generation", "generation" to 0L, "namespace_id" to chBytes(32, 1), "state" to "current")
        // A second current one: inserted, or promoted from pending while the first is still current.
        f.refuses(
            "ch_generation_one_current_insert", "at most one current generation",
            f.sql("ch_generation", mapOf("generation" to 1L, "namespace_id" to chBytes(32, 2), "state" to "current")).first,
            *f.sql("ch_generation", mapOf("generation" to 1L, "namespace_id" to chBytes(32, 2), "state" to "current")).second.toTypedArray(),
        )
        f.put("ch_generation", "generation" to 1L, "namespace_id" to chBytes(32, 2), "state" to "pending_switch", "switch_hour" to 3_600L)
        f.refuses("ch_generation_one_current_update", "at most one current generation",
            "UPDATE ch_generation SET state = 'current', switch_hour = NULL WHERE generation = 1")
        // The order CH-SWITCH uses: the older drain ends first, the current one is demoted, the pending one promoted.
        assertEquals(1, f.upd("UPDATE ch_generation SET state = 'draining', drain_until_day = 20014 WHERE generation = 0"))
        assertEquals(1, f.upd("UPDATE ch_generation SET state = 'current', switch_hour = NULL WHERE generation = 1"))
        // A second draining one, inserted or demoted while the first drains.
        val second = f.sql("ch_generation", mapOf("generation" to 2L, "namespace_id" to chBytes(32, 3), "state" to "draining", "drain_until_day" to 20_020L))
        f.refuses("ch_generation_one_draining_insert", "at most one draining generation", second.first, *second.second.toTypedArray())
        assertEquals("the refused rows were not written", 2L, f.count("ch_generation"))
    }

    @Test
    fun aSecondDrainingGenerationIsRefusedWhenACurrentOneIsDemoted() = ChannelFixture().use { f ->
        f.put("ch_generation", "generation" to 0L, "namespace_id" to chBytes(32, 1), "state" to "draining", "drain_until_day" to 20_014L)
        f.put("ch_generation", "generation" to 1L, "namespace_id" to chBytes(32, 2), "state" to "current")
        f.refuses("ch_generation_one_draining_update", "at most one draining generation",
            "UPDATE ch_generation SET state = 'draining', drain_until_day = 20020 WHERE generation = 1")
        // The rule is per channel: another channel has its own current and draining generations.
        f.put("ch_channel", "channel_id" to chBytes(32, 0xC2))
        f.put("ch_generation", "channel_id" to chBytes(32, 0xC2), "generation" to 0L, "namespace_id" to chBytes(32, 5), "state" to "current")
        f.put("ch_generation", "channel_id" to chBytes(32, 0xC2), "generation" to 1L, "namespace_id" to chBytes(32, 6), "state" to "draining", "drain_until_day" to 20_014L)
        assertEquals(4L, f.count("ch_generation"))
    }

    // ------------------------------------------------------------------ epochs

    @Test
    fun aChannelHasAtMostSeventeenEpochRows() = ChannelFixture().use { f ->
        for (e in 0L until 17L) f.put("ch_epoch", "epoch" to e, "state" to if (e < 16) "final" else "open", "final_day" to if (e < 16) 20_000L else null)
        val over = f.sql("ch_epoch", mapOf("epoch" to 17L))
        f.refuses("ch_epoch_limit", "at most 17 epochs", over.first, *over.second.toTypedArray())
        // The bound is per channel; deleting an epoch makes room for the next.
        f.put("ch_channel", "channel_id" to chBytes(32, 0xC2))
        f.put("ch_epoch", "channel_id" to chBytes(32, 0xC2))
        assertEquals(1, f.upd("DELETE FROM ch_epoch WHERE channel_id = ? AND epoch = 0", ch))
        f.put("ch_epoch", "epoch" to 17L)
        assertEquals(18L, f.count("ch_epoch"))
    }

    @Test
    fun theAnchorOfAFinalEpochIsClearedAtInsertAndAtUpdate() = ChannelFixture().use { f ->
        val insert = f.sql("ch_epoch", mapOf("state" to "final", "final_day" to 20_000L, "anchor_minute" to 600L))
        f.parents("ch_epoch")
        f.refuses("ch_epoch_anchor_insert", "anchor of a final epoch", insert.first, *insert.second.toTypedArray())
        f.put("ch_epoch", "anchor_minute" to 600L)
        // The epoch becomes final: the anchor goes in the same statement, or the statement is refused.
        f.refuses("ch_epoch_anchor_update", "anchor of a final epoch", "UPDATE ch_epoch SET state = 'final', final_day = 20000")
        f.refuses("ch_epoch_anchor_update", "anchor of a final epoch", "UPDATE ch_epoch SET state = 'final', final_day = 20000, anchor_minute = 660")
        assertEquals(1, f.upd("UPDATE ch_epoch SET state = 'final', final_day = 20000, anchor_minute = NULL, winner_hash = ?, keep_until_day = 20002", chBytes(32, 7)))
        // A final epoch cannot get an anchor back.
        f.refuses("ch_epoch_anchor_update", "anchor of a final epoch", "UPDATE ch_epoch SET anchor_minute = 600")
        assertNull(f.db.queryLong("SELECT anchor_minute FROM ch_epoch"))
    }

    @Test
    fun anEpochKeepsItsKeysAndItsWinnerAndItsSequenceNeverGoesBack() = ChannelFixture().use { f ->
        f.put("ch_epoch")
        for ((column, value) in listOf("epoch" to 1L, "k_env" to chBytes(68, 9), "r_ep" to chBytes(32, 9))) {
            f.refuses("ch_epoch_identity", "keeps its keys", "UPDATE ch_epoch SET $column = ?", value)
        }
        f.refuses("ch_epoch_identity", "keeps its keys", "UPDATE ch_epoch SET channel_id = ?", chBytes(32, 9))
        // The sequence of own posts: up, never down (a repeated `seq` would break peer ordering, §6.3.3).
        assertEquals(1, f.upd("UPDATE ch_epoch SET own_seq = 3"))
        assertEquals(1, f.upd("UPDATE ch_epoch SET own_seq = 3"))
        assertEquals(1, f.upd("UPDATE ch_epoch SET own_seq = 9"))
        f.refuses("ch_epoch_identity", "never goes back", "UPDATE ch_epoch SET own_seq = 8")
        // The winner is set once.
        assertEquals(1, f.upd("UPDATE ch_epoch SET winner_hash = ?", chBytes(32, 7)))
        assertEquals(1, f.upd("UPDATE ch_epoch SET winner_hash = ?", chBytes(32, 7)))
        f.refuses("ch_epoch_identity", "keeps its keys", "UPDATE ch_epoch SET winner_hash = ?", chBytes(32, 8))
        f.refuses("ch_epoch_identity", "keeps its keys", "UPDATE ch_epoch SET winner_hash = NULL")
        assertEquals(9L, f.db.queryLong("SELECT own_seq FROM ch_epoch"))
    }

    /**
     * `own_seq` is the `seq` of the next own post of the open epoch. Nothing reads it afterwards, and left in place
     * it shows, for as long as the epoch's keys are kept (up to 16 epochs), how many posts the member wrote in each:
     * an activity counter that outlives the posts (the review of S3: 25 own posts left `own_seq = 25`). Finality
     * resets it, in the same statement and nowhere else.
     */
    @Test
    fun aFinalEpochKeepsNoSequenceAndOnlyFinalityResetsIt() = ChannelFixture().use { f ->
        f.put("ch_epoch")
        assertEquals(1, f.upd("UPDATE ch_epoch SET own_seq = 25"))
        // finality that keeps the count is refused by the table ...
        f.db.rejects(CHECK_FAILED, "UPDATE ch_epoch SET state = 'final', final_day = 20000, anchor_minute = NULL, keep_until_day = 20002")
        // ... the reset of an open epoch's count by the rule that it never goes back ...
        f.refuses("ch_epoch_identity", "never goes back", "UPDATE ch_epoch SET own_seq = 0")
        assertEquals(25L, f.db.queryLong("SELECT own_seq FROM ch_epoch"))
        // ... and finality with the reset is the one write that resets it
        assertEquals(1, f.upd("UPDATE ch_epoch SET state = 'final', final_day = 20000, anchor_minute = NULL, own_seq = 0, keep_until_day = 20002"))
        assertEquals(0L, f.db.queryLong("SELECT own_seq FROM ch_epoch"))
        // a final epoch changes no more (its count stays 0), and none is inserted final with a count
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET own_seq = 1")
        val insert = f.sql("ch_epoch", mapOf("epoch" to 1L, "state" to "final", "final_day" to 20_000L, "own_seq" to 3L))
        f.db.rejects(CHECK_FAILED, insert.first, *insert.second.toTypedArray())
    }

    @Test
    fun aFinalEpochIsStickyAndOnlyItsRetentionMovesAndOnlyEarlier() = ChannelFixture().use { f ->
        f.put("ch_epoch", "state" to "final", "final_day" to 20_000L, "winner_hash" to chBytes(32, 7), "keep_until_day" to 20_002L)
        // finality is never left (later commits for it are fork signals, CO-6) ...
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET state = 'open', final_day = NULL, keep_until_day = NULL")
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET final_day = 20001")
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET own_seq = 1")
        // retention: earlier, or equal; never later and never forgotten into 'no bound'
        assertEquals(1, f.upd("UPDATE ch_epoch SET keep_until_day = 20001"))
        assertEquals(1, f.upd("UPDATE ch_epoch SET keep_until_day = 20001"))
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET keep_until_day = 20003")
        f.refuses("ch_epoch_final", "sticky", "UPDATE ch_epoch SET keep_until_day = NULL")
        assertEquals(20_001L, f.db.queryLong("SELECT keep_until_day FROM ch_epoch"))
        // An open epoch becomes final once, and the retention is then set by the same or a later statement.
        f.put("ch_epoch", "epoch" to 1L)
        assertEquals(1, f.upd("UPDATE ch_epoch SET state = 'final', final_day = 20001, anchor_minute = NULL WHERE epoch = 1"))
        assertEquals(1, f.upd("UPDATE ch_epoch SET keep_until_day = 20003 WHERE epoch = 1"))
    }

    @Test
    fun theEpochLogIsAppendOnlyAndBoundedAtOneThousandAndTwentyFourRows() = ChannelFixture().use { f ->
        f.put("ch_channel")
        f.db.transaction {
            for (e in 0L until 1024L) f.put("ch_epoch_log", "epoch" to e, "winner_hash" to chBytes(32, (e % 200).toInt() + 1))
        }
        val over = f.sql("ch_epoch_log", mapOf("epoch" to 1024L))
        f.refuses("ch_epoch_log_limit", "at most 1024", over.first, *over.second.toTypedArray())
        f.refuses("ch_epoch_log_append_only", "append-only", "UPDATE ch_epoch_log SET winner_hash = ? WHERE epoch = 5", chBytes(32, 250))
        f.refuses("ch_epoch_log_append_only", "append-only", "UPDATE ch_epoch_log SET final_day = 1 WHERE epoch = 5")
        // The oldest rows go first, and that makes room.
        assertEquals(1, f.upd("DELETE FROM ch_epoch_log WHERE epoch = 0"))
        f.put("ch_epoch_log", "epoch" to 1024L)
        assertEquals(1024L, f.count("ch_epoch_log"))
        // The bound is the channel's: another channel has its own 1024 (a limit over the whole table refuses this).
        f.put("ch_channel", "channel_id" to other)
        f.put("ch_epoch_log", "channel_id" to other)
        assertEquals(1025L, f.count("ch_epoch_log"))
    }

    // ------------------------------------------------------------------ candidates and fork signals

    private fun ChannelFixture.candidate(i: Int, vararg extra: Pair<String, Any?>) =
        put("ch_candidate", "hash" to chBytes(32, 100 + i), "sender" to chBytes(32, 150 + i), *extra)

    @Test
    fun anEpochHasAtMostEightForeignCandidatesAndOneOwnCommit() = ChannelFixture().use { f ->
        for (i in 0 until 8) f.candidate(i)
        val ninth = f.sql("ch_candidate", mapOf("epoch" to 0L, "hash" to chBytes(32, 108), "sender" to chBytes(32, 158)))
        f.refuses("ch_candidate_limit", "at most 8 foreign candidates", ninth.first, *ninth.second.toTypedArray())
        // The own commit comes beside them, once.
        f.candidate(20, "own" to 1L)
        val secondOwn = f.sql("ch_candidate", mapOf("epoch" to 0L, "hash" to chBytes(32, 121), "sender" to chBytes(32, 171), "own" to 1L))
        f.refuses("ch_candidate_limit", "one own commit", secondOwn.first, *secondOwn.second.toTypedArray())
        // Another epoch has its own room, and deleting a candidate makes room in this one.
        f.candidate(30, "epoch" to 1L)
        assertEquals(1, f.upd("DELETE FROM ch_candidate WHERE epoch = 0 AND hash = ?", chBytes(32, 100)))
        f.candidate(9)
        assertEquals(10L, f.count("ch_candidate"))
        // The bounds are the channel's: another channel has its own eight foreign candidates and its own commit.
        f.put("ch_channel", "channel_id" to other)
        f.put("ch_candidate", "channel_id" to other, "hash" to chBytes(32, 200), "sender" to chBytes(32, 201))
        f.put("ch_candidate", "channel_id" to other, "hash" to chBytes(32, 202), "sender" to chBytes(32, 203), "own" to 1L)
        assertEquals(12L, f.count("ch_candidate"))
    }

    @Test
    fun aCandidateChangesOnlyByAVerifiedCopyAnEarlierStoreHourAndTheErasureOfItsWelcomes() = ChannelFixture().use { f ->
        f.candidate(1, "own" to 1L, "welcome_env" to chBytes(100, 1), "box_env" to chBytes(60, 1), "store_hour" to 7_200L)
        for ((column, value) in listOf(
            "epoch" to 1L, "hash" to chBytes(32, 9), "sender" to chBytes(32, 9), "rank" to 3L, "own" to 0L,
            "body_env" to chBytes(300, 9), "first_seen_minute" to 120L,
        )) {
            f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET $column = ?", value)
        }
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET channel_id = ?", chBytes(32, 9))
        // a verified copy stays verified
        assertEquals(1, f.upd("UPDATE ch_candidate SET verified = 1"))
        assertEquals(1, f.upd("UPDATE ch_candidate SET verified = 1"))
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET verified = 0")
        // the store hour only moves earlier; a copy seen at another relay can only lower the anchor
        assertEquals(1, f.upd("UPDATE ch_candidate SET store_hour = 3600"))
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET store_hour = 7200")
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET store_hour = NULL")
        // the Welcomes and the box key are written with the row and may be erased, never replaced or added later
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET welcome_env = ?", chBytes(100, 2))
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET box_env = ?", chBytes(60, 2))
        assertEquals(1, f.upd("UPDATE ch_candidate SET welcome_env = NULL, box_env = NULL"))
        f.refuses("ch_candidate_identity", "a candidate changes only", "UPDATE ch_candidate SET welcome_env = ?", chBytes(100, 1))
        // a foreign candidate learns its store hour once, from NULL
        f.candidate(2)
        assertEquals(1, f.upd("UPDATE ch_candidate SET store_hour = 3600 WHERE hash = ?", chBytes(32, 102)))
    }

    @Test
    fun aChannelHasAtMostSixteenForkSignalsAndTheyAreNeverRewritten() = ChannelFixture().use { f ->
        for (i in 0 until 16) f.put("ch_fork_signal", "epoch" to (i / 4).toLong(), "hash" to chBytes(32, 50 + i))
        val over = f.sql("ch_fork_signal", mapOf("hash" to chBytes(32, 99)))
        f.refuses("ch_fork_signal_limit", "at most 16", over.first, *over.second.toTypedArray())
        f.refuses("ch_fork_signal_append_only", "never rewritten", "UPDATE ch_fork_signal SET first_seen_day = 1")
        // the oldest is dropped to make room, and the signals of an epoch go with its key
        assertEquals(4, f.upd("DELETE FROM ch_fork_signal WHERE epoch = 0"))
        for (i in 0 until 4) f.put("ch_fork_signal", "epoch" to 9L, "hash" to chBytes(32, 60 + i))
        assertEquals(16L, f.count("ch_fork_signal"))
        // The bound is the channel's: another channel has its own 16.
        f.put("ch_channel", "channel_id" to other)
        f.put("ch_fork_signal", "channel_id" to other, "hash" to chBytes(32, 98))
        assertEquals(17L, f.count("ch_fork_signal"))
    }

    // ------------------------------------------------------------------ posts

    private val postStates = listOf("queued", "sent", "degraded", "failed", "indeterminate", "unread", "read")
    private val postEdges: Set<Pair<String, String>> = buildSet {
        for (s in postStates) add(s to s)
        for (to in listOf("sent", "degraded", "failed", "indeterminate")) add("queued" to to)
        add("failed" to "queued")
        add("unread" to "read")
    }

    @Test
    fun thePostMachineIsQueuedThenAnOutcomeOrUnreadThenReadAndAFailedPostCanBeRetried() {
        var allowed = 0
        for (from in postStates) for (to in postStates) ChannelFixture().use { f ->
            val outgoing = from != "unread" && from != "read"
            f.put(
                "ch_post", "direction" to if (outgoing) "out" else "in", "state" to from,
                "displayed_minute" to if (from == "read") 660L else null,
            )
            val set = if (to == "read") "state = 'read', displayed_minute = 660" else "state = '$to'"
            val sql = "UPDATE ch_post SET $set WHERE op_id = ?"
            if (from to to in postEdges) {
                allowed++
                assertEquals("$from -> $to", 1, f.upd(sql, ChannelFixture.POST))
                assertEquals(to, f.db.queryString("SELECT state FROM ch_post"))
            } else {
                f.refuses("ch_post_state", "illegal post state transition", sql, ChannelFixture.POST)
                assertEquals(from, f.db.queryString("SELECT state FROM ch_post"))
            }
        }
        assertEquals(7 + 4 + 1 + 1, allowed)
    }

    @Test
    fun aPostKeepsItsIdentityAndOnlyARetryReEncryptsIt() = ChannelFixture().use { f ->
        f.put("ch_post", "direction" to "out", "state" to "queued", "reply_to" to chBytes(16, 5))
        val identity = "only the state"
        for ((column, value) in listOf(
            "op_id" to chBytes(16, 9), "direction" to "in", "author" to chBytes(32, 9), "kind" to 2L,
            "reply_to" to chBytes(16, 9), "body_env" to chBytes(50, 9),
        )) {
            f.refuses("ch_post_identity", identity, "UPDATE ch_post SET $column = ?", value)
        }
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET channel_id = ?", chBytes(32, 9))
        // the epoch, the timer and the author minute are the encryption's: fixed while the post lives its life ...
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET epoch = 4")
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET timer_code = 2")
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET author_minute = 660")
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET state = 'sent', epoch = 4")
        assertEquals(1, f.upd("UPDATE ch_post SET state = 'failed'"))
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET epoch = 4")
        // ... and a retry (failed -> queued) re-encrypts the post under the epoch, the timer and the minute then current
        assertEquals(1, f.upd("UPDATE ch_post SET state = 'queued', epoch = 4, timer_code = 2, author_minute = 660"))
        f.refuses("ch_post_identity", identity, "UPDATE ch_post SET body_env = ?, state = 'sent'", chBytes(50, 9))
    }

    @Test
    fun aPostIsDisplayedOnceAndItsDeletionTimeOnlyMovesEarlier() = ChannelFixture().use { f ->
        f.put("ch_post", "relay_expiry_hour" to 7_200L, "delete_at_minute" to 7_200L)
        val message = "displayed once"
        // the reader's countdown starts at the first display
        assertEquals(1, f.upd("UPDATE ch_post SET state = 'read', displayed_minute = 660, delete_at_minute = 3600, relay_expiry_hour = NULL"))
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET displayed_minute = 720")
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET displayed_minute = NULL")
        assertEquals(1, f.upd("UPDATE ch_post SET displayed_minute = 660"))
        // deadlines only move earlier (the expiry clock never runs backwards, §8.2)
        assertEquals(1, f.upd("UPDATE ch_post SET delete_at_minute = 3000"))
        assertEquals(1, f.upd("UPDATE ch_post SET delete_at_minute = 3000"))
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET delete_at_minute = 3600")
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET delete_at_minute = NULL")
        assertEquals(3_000L, f.db.queryLong("SELECT delete_at_minute FROM ch_post"))
        // the relay expiry E is a live deadline of an unread post (§8.2), so it only moves earlier too ...
        val unread = chBytes(16, 0x31)
        f.put("ch_post", "op_id" to unread, "relay_expiry_hour" to 7_200L)
        assertEquals(1, f.upd("UPDATE ch_post SET relay_expiry_hour = 3600 WHERE op_id = ?", unread))
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET relay_expiry_hour = 7200 WHERE op_id = ?", unread)
        // ... and an unread post cannot lose it: NULL is not "earlier", and the comparison NEW > OLD is NULL for
        // it, which the first version let through (SET relay_expiry_hour = NULL, then NULL -> E + 30 d). The
        // review of S3 found that its test asserted the first step "once displayed" on a post that was unread.
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET relay_expiry_hour = NULL WHERE op_id = ?", unread)
        assertEquals(3_600L, f.db.queryLong("SELECT relay_expiry_hour FROM ch_post WHERE op_id = ?", listOf(unread)))
        // a display forgets it in the statement that makes the post read, and a read post cannot get one back
        assertEquals(1, f.upd("UPDATE ch_post SET state = 'read', displayed_minute = 660, relay_expiry_hour = NULL WHERE op_id = ?", unread))
        f.db.rejects(CHECK_FAILED, "UPDATE ch_post SET relay_expiry_hour = 7200 WHERE op_id = ?", unread)
        // a post that came with no relay expiry may gain one (a deadline appearing is earlier than none), once
        val none = chBytes(16, 0x33)
        f.put("ch_post", "op_id" to none)
        assertEquals(1, f.upd("UPDATE ch_post SET relay_expiry_hour = 7200 WHERE op_id = ?", none))
        f.refuses("ch_post_expiry", message, "UPDATE ch_post SET relay_expiry_hour = 10800 WHERE op_id = ?", none)
        // a deletion time is set from NULL once
        f.put("ch_post", "op_id" to chBytes(16, 0x32))
        assertEquals(1, f.upd("UPDATE ch_post SET delete_at_minute = 6000 WHERE op_id = ?", chBytes(16, 0x32)))
    }

    @Test
    fun aChannelHasAtMostTwoHundredAndFiftySixPendingPosts() = ChannelFixture().use { f ->
        f.put("ch_channel")
        f.db.transaction {
            for (i in 0 until 256) f.put("ch_pending_post", "op_id" to ByteArray(16).also { it[0] = (i / 256).toByte(); it[1] = (i % 256).toByte(); it[15] = 1 })
        }
        val over = f.sql("ch_pending_post", mapOf("op_id" to chBytes(16, 0x7F)))
        f.refuses("ch_pending_post_limit", "at most 256", over.first, *over.second.toTypedArray())
        f.put("ch_channel", "channel_id" to chBytes(32, 0xC2))
        f.put("ch_pending_post", "channel_id" to chBytes(32, 0xC2), "op_id" to chBytes(16, 0x7F))
        assertEquals(1, f.upd("DELETE FROM ch_pending_post WHERE channel_id = ? AND op_id = ?", ch, ByteArray(16).also { it[15] = 1 }))
        f.put("ch_pending_post", "op_id" to chBytes(16, 0x7E))
        assertEquals(257L, f.count("ch_pending_post"))
    }

    // ------------------------------------------------------------------ joins, invites and keys

    @Test
    fun aChannelHasAtMostSixtyFourPendingJoinRequests() = ChannelFixture().use { f ->
        f.put("ch_channel")
        for (i in 0 until 64) f.put("ch_join_request", "hash" to chBytes(32, 100 + i))
        val over = f.sql("ch_join_request", mapOf("hash" to chBytes(32, 99)))
        f.refuses("ch_join_request_limit", "at most 64", over.first, *over.second.toTypedArray())
        assertEquals(1, f.upd("DELETE FROM ch_join_request WHERE hash = ?", chBytes(32, 100)))
        f.put("ch_join_request", "hash" to chBytes(32, 99))
        assertEquals(64L, f.count("ch_join_request"))
        // The bound is the channel's: another channel has its own 64.
        f.put("ch_channel", "channel_id" to other)
        f.put("ch_join_request", "channel_id" to other, "hash" to chBytes(32, 98))
        assertEquals(65L, f.count("ch_join_request"))
    }

    @Test
    fun anIssuedInviteIsImmutableButForItsTwoOneWayFlags() = ChannelFixture().use { f ->
        f.put("ch_invite_issued", "pw_version" to 2L)
        for ((column, value) in listOf(
            "invite_id" to chBytes(16, 9), "invite_pk" to chBytes(32, 9), "sponsor" to chBytes(32, 9),
            "sponsor_sig" to chBytes(64, 9), "committers_digest" to chBytes(32, 9), "pw_version" to 3L, "expiry_day" to 20_100L,
        )) {
            f.refuses("ch_invite_issued_identity", "immutable", "UPDATE ch_invite_issued SET $column = ?", value)
        }
        f.refuses("ch_invite_issued_identity", "immutable", "UPDATE ch_invite_issued SET pw_version = NULL")
        // consumed and void are set at the settle, once
        assertEquals(1, f.upd("UPDATE ch_invite_issued SET consumed = 1"))
        assertEquals(1, f.upd("UPDATE ch_invite_issued SET consumed = 1"))
        f.refuses("ch_invite_issued_flags", "consumed once", "UPDATE ch_invite_issued SET consumed = 0")
        assertEquals(1, f.upd("UPDATE ch_invite_issued SET void = 1"))
        f.refuses("ch_invite_issued_flags", "consumed once", "UPDATE ch_invite_issued SET void = 0")
        // an open invite carries no password version, and its row is as immutable as a password one
        f.put("ch_invite_issued", "invite_id" to chBytes(16, 0x28))
        f.refuses("ch_invite_issued_identity", "immutable", "UPDATE ch_invite_issued SET pw_version = 1 WHERE invite_id = ?", chBytes(16, 0x28))
    }

    @Test
    fun aChannelHasAtMostOneThousandAndTwentyFourKeyPackageTagsButARepeatIsNotRefused() = ChannelFixture().use { f ->
        f.put("ch_channel")
        f.db.transaction {
            for (i in 0 until 1024) f.put("ch_kp_seen", "tag" to ByteArray(16).also { it[0] = (i / 256).toByte(); it[1] = (i % 256).toByte(); it[15] = 3 })
        }
        val over = f.sql("ch_kp_seen", mapOf("tag" to chBytes(16, 0x7F)))
        f.refuses("ch_kp_seen_limit", "at most 1024", over.first, *over.second.toTypedArray())
        // INSERT OR IGNORE of a tag that is there is no new row, so the bound does not apply to it
        val repeat = f.sql("ch_kp_seen", mapOf("tag" to ByteArray(16).also { it[15] = 3 }), verb = "INSERT OR IGNORE")
        assertEquals(0, f.db.execUpdate(repeat.first, repeat.second))
        assertEquals(1024L, f.count("ch_kp_seen"))
        f.put("ch_channel", "channel_id" to chBytes(32, 0xC2))
        f.put("ch_kp_seen", "channel_id" to chBytes(32, 0xC2), "tag" to chBytes(16, 0x7F))
    }

    @Test
    fun aChannelHasAtMostEighteenBoxKeysAndAKeyIsReplacedOnceInTheEpochThatReplacedIt() = ChannelFixture().use { f ->
        for (i in 0 until 18) f.put("ch_box_key", "box_pk" to chBytes(32, 100 + i))
        val over = f.sql("ch_box_key", mapOf("box_pk" to chBytes(32, 99)))
        f.refuses("ch_box_key_limit", "at most 18", over.first, *over.second.toTypedArray())
        // in the current leaf (NULL) until a new leaf replaces it, in the epoch of the replacement
        assertEquals(1, f.upd("UPDATE ch_box_key SET last_epoch = 4 WHERE box_pk = ?", chBytes(32, 100)))
        assertEquals(1, f.upd("UPDATE ch_box_key SET last_epoch = 4 WHERE box_pk = ?", chBytes(32, 100)))
        f.refuses("ch_box_key_replaced", "replaced once", "UPDATE ch_box_key SET last_epoch = 5 WHERE box_pk = ?", chBytes(32, 100))
        f.refuses("ch_box_key_replaced", "replaced once", "UPDATE ch_box_key SET last_epoch = NULL WHERE box_pk = ?", chBytes(32, 100))
        f.refuses("ch_box_key_replaced", "replaced once", "UPDATE ch_box_key SET sk_env = ? WHERE box_pk = ?", chBytes(60, 9), chBytes(32, 101))
        f.refuses("ch_box_key_replaced", "replaced once", "UPDATE ch_box_key SET box_pk = ? WHERE box_pk = ?", chBytes(32, 9), chBytes(32, 101))
        // SWEEP deletes a key when its last epoch leaves retention, which makes room for the next
        assertEquals(1, f.upd("DELETE FROM ch_box_key WHERE last_epoch = 4"))
        f.put("ch_box_key", "box_pk" to chBytes(32, 99))
        // The bound is the channel's: another channel has its own 18.
        f.put("ch_channel", "channel_id" to other)
        f.put("ch_box_key", "channel_id" to other, "box_pk" to chBytes(32, 98))
        assertEquals(19L, f.count("ch_box_key"))
    }

    // ------------------------------------------------------------------ the rows that move, and the death days

    /**
     * The bounds count at INSERT, so an UPDATE of channel_id would move rows into a channel that is full: the
     * review of S3 moved 256 pending posts and 64 requests into channels that held as many already. A bounded row
     * that nothing else keeps in place never changes its channel.
     */
    @Test
    fun aBoundedRowNeverMovesToAnotherChannel() = ChannelFixture().use { f ->
        f.put("ch_channel")
        f.put("ch_channel", "channel_id" to other)
        for ((table, trigger) in listOf(
            "ch_pending_post" to "ch_pending_post_channel",
            "ch_join_request" to "ch_join_request_channel",
            "ch_kp_seen" to "ch_kp_seen_channel",
        )) {
            f.put(table)
            f.refuses(trigger, "never moves to another channel", "UPDATE $table SET channel_id = ?", other)
            assertEquals(table, 0L, f.db.queryLong("SELECT count(*) FROM $table WHERE channel_id = ?", listOf(other)))
            // an UPDATE that leaves the channel where it is is not the move
            assertEquals(table, 1, f.upd("UPDATE $table SET channel_id = ?", ch))
        }
        // the full scenario of the review: a channel at its bound takes no row from another
        f.db.transaction {
            for (i in 0 until 64) f.put("ch_join_request", "channel_id" to other, "hash" to chBytes(32, 100 + i))
        }
        f.refuses("ch_join_request_channel", "never moves to another channel", "UPDATE ch_join_request SET channel_id = ? WHERE channel_id = ?", other, ch)
        assertEquals(64L, f.db.queryLong("SELECT count(*) FROM ch_join_request WHERE channel_id = ?", listOf(other)))
    }

    /**
     * A join keeps its KeyPackage and its invite, and its expiry - the day the KeyPackage's private keys die
     * (section 6.2.2) - only moves earlier (the review of S3: a later one was accepted).
     */
    @Test
    fun aJoinKeepsItsKeyPackageAndItsInviteAndItsExpiryOnlyMovesEarlier() = ChannelFixture().use { f ->
        f.put("ch_join")
        val message = "a join keeps its KeyPackage"
        f.put("ch_channel", "channel_id" to other)
        for ((column, value) in listOf("kp_ref" to chBytes(32, 9), "invite_id" to chBytes(16, 9), "generation" to 3L, "channel_id" to other)) {
            f.refuses("ch_join_fixed", message, "UPDATE ch_join SET $column = ?", value)
        }
        f.refuses("ch_join_fixed", message, "UPDATE ch_join SET type = 'restore'")
        assertEquals(1, f.upd("UPDATE ch_join SET expiry_day = 20007"))
        assertEquals(1, f.upd("UPDATE ch_join SET expiry_day = 20003"))
        f.refuses("ch_join_fixed", message, "UPDATE ch_join SET expiry_day = 20004")
        f.refuses("ch_join_fixed", message, "UPDATE ch_join SET expiry_day = 99999")
        assertEquals(20_003L, f.db.queryLong("SELECT expiry_day FROM ch_join"))
    }

    /**
     * The sponsor's own link (Q50 (a)): a password invite stores none, and a row that stored none never gets one
     * (a stored password link is an Argon2id-priced oracle on a seized unlocked device); the link of an open invite
     * can be erased and never replaced, and the expiry only moves earlier.
     */
    @Test
    fun anOwnInviteIsErasedNeverRewrittenAndAPasswordInviteNeverGetsALink() = ChannelFixture().use { f ->
        val open = chBytes(16, 36)
        val password = chBytes(16, 0x37)
        f.put("ch_invite_own")
        f.put("ch_invite_own", "invite_id" to password, "invite_env" to null)
        val message = "an own invite is erased"
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET invite_env = ? WHERE invite_id = ?", chBytes(363, 5), password)
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET invite_env = ? WHERE invite_id = ?", chBytes(363, 6), open)
        assertEquals(1, f.upd("UPDATE ch_invite_own SET invite_env = NULL WHERE invite_id = ?", open))
        assertEquals(1, f.upd("UPDATE ch_invite_own SET invite_env = NULL WHERE invite_id = ?", open))
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET invite_env = ? WHERE invite_id = ?", chBytes(363, 7), open)
        f.put("ch_channel", "channel_id" to other)
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET invite_id = ? WHERE invite_id = ?", chBytes(16, 9), open)
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET channel_id = ? WHERE invite_id = ?", other, open)
        assertEquals(1, f.upd("UPDATE ch_invite_own SET expiry_day = 20003 WHERE invite_id = ?", open))
        f.refuses("ch_invite_own_fixed", message, "UPDATE ch_invite_own SET expiry_day = 20004 WHERE invite_id = ?", open)
        assertEquals(null, f.db.queryBlob("SELECT invite_env FROM ch_invite_own WHERE invite_id = ?", listOf(password)))
    }

    /**
     * The rows of GhostKv that are global (a KeyPackage and its private keys) die on a day, held like every death
     * day: it only moves earlier and, once set, is never forgotten; a row with none may be given one. The key and the
     * channel of a row never change; its value is rewritten freely (the adapter's put).
     */
    @Test
    fun aGlobalRowKeepsItsKeyAndItsChannelAndItsDayOnlyMovesEarlier() = ChannelFixture().use { f ->
        val dated = chBytes(20, 14)
        val undated = chBytes(20, 55)
        f.put("mls_global_kv", "delete_after_day" to 20_007L)
        f.put("mls_global_kv", "k" to undated)
        val message = "a global row keeps its key"
        f.put("ch_channel", "channel_id" to other)
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET k = ? WHERE k = ?", chBytes(20, 99), dated)
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET channel_id = ? WHERE k = ?", other, dated)
        assertEquals(1, f.upd("UPDATE mls_global_kv SET v_env = ? WHERE k = ?", chBytes(100, 9), dated))
        assertEquals(1, f.upd("UPDATE mls_global_kv SET delete_after_day = 20007 WHERE k = ?", dated))
        assertEquals(1, f.upd("UPDATE mls_global_kv SET delete_after_day = 20003 WHERE k = ?", dated))
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET delete_after_day = 20004 WHERE k = ?", dated)
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET delete_after_day = 99999 WHERE k = ?", dated)
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET delete_after_day = NULL WHERE k = ?", dated)
        assertEquals(20_003L, f.db.queryLong("SELECT delete_after_day FROM mls_global_kv WHERE k = ?", listOf(dated)))
        // a row that was written with no day may be given one, once
        assertEquals(1, f.upd("UPDATE mls_global_kv SET delete_after_day = 20005 WHERE k = ?", undated))
        f.refuses("mls_global_kv_fixed", message, "UPDATE mls_global_kv SET delete_after_day = 20006 WHERE k = ?", undated)
    }

    // ------------------------------------------------------------------ all of them

    /**
     * Every trigger of [ChannelSchema.rules] fired in this class: a rule that exists and was never provoked
     * is a rule nobody tested. The tests above run first within the JVM only by luck of ordering, so this one
     * runs them itself (each is cheap) and then checks the set.
     */
    @Test
    fun everyRuleTriggerWasProvokedByATestOfThisClass() {
        theChannelStateMachineAllowsExactlyTheEdgesOfSection611()
        aChannelKeepsItsIdItsSuiteAndItsPseudonymAndNothingElseIsFixed()
        theGenerationMachineIsPendingSwitchCurrentDrainingAndNothingElse()
        aGenerationKeepsItsNamespaceAndItsSecrets()
        aChannelHasAtMostOneCurrentAndOneDrainingGeneration()
        aSecondDrainingGenerationIsRefusedWhenACurrentOneIsDemoted()
        aChannelHasAtMostSeventeenEpochRows()
        theAnchorOfAFinalEpochIsClearedAtInsertAndAtUpdate()
        anEpochKeepsItsKeysAndItsWinnerAndItsSequenceNeverGoesBack()
        aFinalEpochIsStickyAndOnlyItsRetentionMovesAndOnlyEarlier()
        theEpochLogIsAppendOnlyAndBoundedAtOneThousandAndTwentyFourRows()
        anEpochHasAtMostEightForeignCandidatesAndOneOwnCommit()
        aCandidateChangesOnlyByAVerifiedCopyAnEarlierStoreHourAndTheErasureOfItsWelcomes()
        aChannelHasAtMostSixteenForkSignalsAndTheyAreNeverRewritten()
        thePostMachineIsQueuedThenAnOutcomeOrUnreadThenReadAndAFailedPostCanBeRetried()
        aPostKeepsItsIdentityAndOnlyARetryReEncryptsIt()
        aPostIsDisplayedOnceAndItsDeletionTimeOnlyMovesEarlier()
        aChannelHasAtMostTwoHundredAndFiftySixPendingPosts()
        aChannelHasAtMostSixtyFourPendingJoinRequests()
        anIssuedInviteIsImmutableButForItsTwoOneWayFlags()
        aChannelHasAtMostOneThousandAndTwentyFourKeyPackageTagsButARepeatIsNotRefused()
        aChannelHasAtMostEighteenBoxKeysAndAKeyIsReplacedOnceInTheEpochThatReplacedIt()
        theEndOfADrainOnlyMovesEarlierAndIsNeverForgotten()
        aFinalEpochKeepsNoSequenceAndOnlyFinalityResetsIt()
        aBoundedRowNeverMovesToAnotherChannel()
        aJoinKeepsItsKeyPackageAndItsInviteAndItsExpiryOnlyMovesEarlier()
        anOwnInviteIsErasedNeverRewrittenAndAPasswordInviteNeverGetsALink()
        aGlobalRowKeepsItsKeyAndItsChannelAndItsDayOnlyMovesEarlier()
        assertEquals("rules never provoked", emptySet<String>(), ChannelSchema.rules - fired)
        assertEquals("a refusal recorded for a trigger that is not in the schema", emptySet<String>(), fired - ChannelSchema.rules)
        assertTrue(fired.size == 36)
    }
}
