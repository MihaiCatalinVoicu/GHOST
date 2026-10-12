package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The CHECK and foreign-key constraints of the 28 channel tables (Phase 10 design §9 and slice S4's `mls_self`,
 * slice S13c's `ch_rotation_history`), **executed**: every
 * length, closed list, range and coupling a table declares refuses the value just outside it and accepts
 * the value just inside it (slice S3). The `typeof` and grid checks of the integer columns are
 * [ChannelSchemaIntrospectionTest]'s; the triggers are [ChannelTriggersTest]'s.
 *
 * Every case runs on a fresh migrated database through [ChannelFixture], whose default rows are valid, so a
 * refusal can only be the one constraint the case names: the case writes the default row with exactly one
 * column (or one coupled pair) changed.
 */
class ChannelSchemaConstraintsTest {

    private class Case(val table: String, val set: Map<String, Any?>, val why: String, val fragment: String = CHECK_FAILED)

    private fun refused(table: String, why: String, vararg set: Pair<String, Any?>) = Case(table, mapOf(*set), why)

    private fun accepted(table: String, why: String, vararg set: Pair<String, Any?>) = Case(table, mapOf(*set), why, fragment = "")

    /** A BLOB column of exactly [size] bytes: the sizes just beside it are refused, the size itself is accepted. */
    private fun exact(table: String, column: String, size: Int, vararg with: Pair<String, Any?>): List<Case> =
        listOf(size - 1, size + 1).filter { it >= 0 }.map { refused(table, "$column of $it bytes", column to chBytes(it, 1), *with) } +
            accepted(table, "$column of $size bytes", column to chBytes(size, 1), *with)

    /** A BLOB column of [min]..[max] bytes. */
    private fun between(table: String, column: String, min: Int, max: Int, vararg with: Pair<String, Any?>): List<Case> =
        listOf(
            refused(table, "$column of ${min - 1} bytes", column to chBytes(min - 1, 1), *with),
            refused(table, "$column of ${max + 1} bytes", column to chBytes(max + 1, 1), *with),
            accepted(table, "$column of $min bytes", column to chBytes(min, 1), *with),
            accepted(table, "$column of $max bytes", column to chBytes(max, 1), *with),
        )

    /** A column with a closed list of text values: a value outside is refused, each value inside is accepted. */
    private fun oneOf(table: String, column: String, values: List<String>, vararg with: Pair<String, Any?>): List<Case> =
        listOf(refused(table, "$column = 'bogus'", column to "bogus", *with)) +
            values.map { accepted(table, "$column = '$it'", column to it, *with) }

    private val cases: List<Case> = buildList {
        // ---- ch_channel
        addAll(exact("ch_channel", "channel_id", 32))
        addAll(exact("ch_channel", "my_pseudonym", 32))
        addAll(oneOf("ch_channel", "state", listOf("joining", "active", "leaving", "left", "removed", "replaced", "resync_needed", "reinvite_needed", "join_expired")))
        for (flag in listOf("split_suspected", "partition_suspected", "stale_suspected", "pw_required")) {
            add(refused("ch_channel", "$flag = 2", flag to 2L))
            add(accepted("ch_channel", "$flag = 1", flag to 1L))
        }
        add(refused("ch_channel", "size_class = 2", "size_class" to 2L))
        add(accepted("ch_channel", "size_class = 1", "size_class" to 1L))
        add(refused("ch_channel", "suite = 4", "suite" to 4L))
        add(refused("ch_channel", "suite = 2", "suite" to 2L))
        add(accepted("ch_channel", "suite = 3", "suite" to 3L))
        add(accepted("ch_channel", "generation = 2^32 - 1", "generation" to 4_294_967_295L))
        add(accepted("ch_channel", "timer_code = 0", "timer_code" to 0L))
        add(accepted("ch_channel", "timer_code = 5", "timer_code" to 5L))
        addAll(between("ch_channel", "name_env", 29, 76))
        // Slice S4 (§19.37 F-S4-2): the committers digest of the current context, unknown until a native call returns it.
        addAll(exact("ch_channel", "committers_digest", 32))
        add(accepted("ch_channel", "no committers digest yet", "committers_digest" to null))
        // ---- ch_liveness
        addAll(between("ch_liveness", "progress_env", 28, 256))
        add(refused("ch_liveness", "a counted blob without the window's start", "unopenable_count" to 1L))
        add(refused("ch_liveness", "a window start with nothing counted", "unopenable_first_minute" to 600L))
        add(accepted("ch_liveness", "a counted blob with the window's start", "unopenable_count" to 1L, "unopenable_first_minute" to 600L))
        add(accepted("ch_liveness", "the counters at their caps", "unopenable_count" to 255L, "unopenable_first_minute" to 600L, "sessions" to 255L, "unopenable_operators" to 255L))
        // ---- ch_schedule
        add(accepted("ch_schedule", "a schedule with its three days", "last_own_commit_day" to 20_000L, "next_pass_minute" to 600L))
        // ---- ch_generation
        addAll(exact("ch_generation", "namespace_id", 32))
        addAll(exact("ch_generation", "g_env", 60))
        addAll(exact("ch_generation", "jk_env", 60))
        addAll(exact("ch_generation", "r_join", 32))
        add(refused("ch_generation", "an unknown state", "state" to "bogus"))
        add(accepted("ch_generation", "a current generation"))
        add(accepted("ch_generation", "a pending switch with its hour", "state" to "pending_switch", "switch_hour" to 3_600L))
        add(accepted("ch_generation", "a pending switch with no hour (the joiner's: next session start)", "state" to "pending_switch"))
        add(refused("ch_generation", "a current generation with a switch hour", "state" to "current", "switch_hour" to 3_600L))
        add(refused("ch_generation", "a draining generation with a switch hour", "state" to "draining", "switch_hour" to 3_600L, "drain_until_day" to 20_014L))
        add(accepted("ch_generation", "a draining generation with its drain day", "state" to "draining", "drain_until_day" to 20_014L))
        add(refused("ch_generation", "a draining generation without a drain day", "state" to "draining"))
        add(refused("ch_generation", "a current generation with a drain day", "state" to "current", "drain_until_day" to 20_014L))
        add(refused("ch_generation", "a pending generation with a drain day", "state" to "pending_switch", "drain_until_day" to 20_014L))
        // Slice S4 (§19.37 F-S4-7): every generation knows the epoch that opened it (§5.4's bootstrap).
        add(Case("ch_generation", mapOf("open_epoch" to null), "a generation without its open epoch", "NOT NULL constraint failed"))
        add(accepted("ch_generation", "a generation opened at epoch 9", "open_epoch" to 9L))
        // ---- ch_epoch
        addAll(exact("ch_epoch", "k_env", 68))
        addAll(exact("ch_epoch", "r_ep", 32))
        add(refused("ch_epoch", "a winner of 31 bytes", "winner_hash" to chBytes(31, 1)))
        add(accepted("ch_epoch", "a winner of 32 bytes", "winner_hash" to chBytes(32, 1)))
        add(refused("ch_epoch", "an unknown state", "state" to "bogus"))
        add(accepted("ch_epoch", "an open epoch"))
        add(refused("ch_epoch", "a final epoch without its day", "state" to "final"))
        add(accepted("ch_epoch", "a final epoch with its day", "state" to "final", "final_day" to 20_000L))
        add(refused("ch_epoch", "an open epoch with a final day", "state" to "open", "final_day" to 20_000L))
        add(refused("ch_epoch", "a retention bound on an open epoch", "keep_until_day" to 20_002L))
        add(accepted("ch_epoch", "a retention bound on a final epoch", "state" to "final", "final_day" to 20_000L, "keep_until_day" to 20_002L))
        // A final epoch keeps no count of the member's posts (T33): finality resets it, and none is stored with one.
        add(accepted("ch_epoch", "an open epoch with a count of own posts", "own_seq" to 25L))
        add(refused("ch_epoch", "a final epoch with a count of own posts", "state" to "final", "final_day" to 20_000L, "own_seq" to 1L))
        // ---- ch_epoch_log
        addAll(exact("ch_epoch_log", "winner_hash", 32))
        // ---- ch_candidate
        addAll(exact("ch_candidate", "hash", 32))
        addAll(exact("ch_candidate", "sender", 32))
        addAll(between("ch_candidate", "body_env", 29, 16_777_216))
        add(refused("ch_candidate", "rank 256", "rank" to 256L))
        add(accepted("ch_candidate", "rank 255", "rank" to 255L))
        add(refused("ch_candidate", "own = 2", "own" to 2L))
        add(refused("ch_candidate", "Welcomes on a foreign candidate", "welcome_env" to chBytes(100, 1)))
        add(refused("ch_candidate", "a box key on a foreign candidate", "box_env" to chBytes(60, 1)))
        add(refused("ch_candidate", "a verified copy of a foreign candidate", "verified" to 1L))
        add(accepted("ch_candidate", "an own commit with Welcomes, a box key and a verified copy", "own" to 1L, "welcome_env" to chBytes(100, 1), "box_env" to chBytes(60, 1), "verified" to 1L))
        add(refused("ch_candidate", "an own box key of 59 bytes", "own" to 1L, "box_env" to chBytes(59, 1)))
        add(refused("ch_candidate", "an own box key of 61 bytes", "own" to 1L, "box_env" to chBytes(61, 1)))
        add(refused("ch_candidate", "Welcomes of 28 bytes", "own" to 1L, "welcome_env" to chBytes(28, 1)))
        // Slice S4 (§19.35 F-1): the removal mark of CO-13, a 0/1 flag on any candidate.
        add(refused("ch_candidate", "removes = 2", "removes" to 2L))
        add(accepted("ch_candidate", "a foreign candidate that removes a pseudonym", "removes" to 1L))
        add(accepted("ch_candidate", "an own commit that removes a pseudonym", "own" to 1L, "removes" to 1L))
        // ---- ch_fork_signal
        addAll(exact("ch_fork_signal", "hash", 32))
        // ---- mls_kv and mls_global_kv: the keys are label NUL json, the values are envelopes (28 bytes of overhead)
        addAll(between("mls_kv", "k", 2, 1024))
        addAll(between("mls_kv", "v_env", 28, 4_194_304))
        addAll(between("mls_global_kv", "k", 2, 1024))
        addAll(between("mls_global_kv", "v_env", 28, 4_194_304))
        // ---- ch_post
        addAll(oneOf("ch_post", "direction", listOf("in")))
        add(accepted("ch_post", "an outgoing queued post", "direction" to "out", "state" to "queued"))
        add(refused("ch_post", "kind 3", "kind" to 3L))
        add(refused("ch_post", "kind 0", "kind" to 0L))
        add(accepted("ch_post", "kind 2", "kind" to 2L))
        addAll(exact("ch_post", "op_id", 16))
        addAll(exact("ch_post", "author", 32))
        add(refused("ch_post", "a reply_to of 15 bytes", "reply_to" to chBytes(15, 1)))
        add(accepted("ch_post", "a reply_to of 16 bytes", "reply_to" to chBytes(16, 1)))
        addAll(between("ch_post", "body_env", 29, 65_564))
        for (state in listOf("queued", "sent", "degraded", "failed", "indeterminate")) {
            add(refused("ch_post", "an incoming post in the outgoing state $state", "direction" to "in", "state" to state))
            add(accepted("ch_post", "an outgoing post in state $state", "direction" to "out", "state" to state))
        }
        for (state in listOf("unread", "read")) {
            add(refused("ch_post", "an outgoing post in the incoming state $state", "direction" to "out", "state" to state))
        }
        add(refused("ch_post", "an unknown state", "state" to "bogus"))
        add(refused("ch_post", "an outgoing post that was displayed", "direction" to "out", "state" to "queued", "displayed_minute" to 660L))
        add(refused("ch_post", "an outgoing post with a relay expiry", "direction" to "out", "state" to "queued", "relay_expiry_hour" to 3_600L))
        // The minute a post was read is kept only where a countdown needs it: a read post of a channel with a timer.
        // With the timer off nothing stores when the user opened a post (F9's dm_message stores no time either, T33).
        add(accepted("ch_post", "a read post with no displayed minute (what a timer-off channel stores)", "state" to "read", "timer_code" to 0L))
        add(accepted("ch_post", "a read post with no displayed minute", "state" to "read"))
        add(refused("ch_post", "an unread post that was displayed", "state" to "unread", "displayed_minute" to 660L))
        add(accepted("ch_post", "a read post that was displayed", "state" to "read", "displayed_minute" to 660L, "delete_at_minute" to 3_600L))
        add(refused("ch_post", "a read post of a timer-off channel with a displayed minute", "state" to "read", "timer_code" to 0L, "displayed_minute" to 660L))
        add(accepted("ch_post", "an unread post with its relay expiry", "relay_expiry_hour" to 3_600L, "delete_at_minute" to 3_600L))
        // The relay expiry is a deadline of an unread post only: a display forgets it, and a read post has none.
        add(refused("ch_post", "a read post with a relay expiry", "state" to "read", "relay_expiry_hour" to 3_600L))
        add(accepted("ch_post", "an unread post of a timer-off channel: a relay expiry and no deadline", "timer_code" to 0L, "relay_expiry_hour" to 3_600L))
        // Slice S13c (§19.54 row 6): the ratchet seq, `own_seq`'s `u32` bound, written at insert, never updated.
        add(refused("ch_post", "a negative seq", "seq" to -1L))
        add(refused("ch_post", "a seq of 2^32", "seq" to 4_294_967_296L))
        add(accepted("ch_post", "the first seq of an epoch", "seq" to 0L))
        add(accepted("ch_post", "the largest seq", "seq" to 4_294_967_295L))
        // ---- ch_rotation_history (slice S13c, §19.54 row 12): one row per rotation, keyed by the generation it opened
        add(refused("ch_rotation_history", "a rotation of generation 0 (the founding generation is no rotation)", "generation" to 0L))
        add(accepted("ch_rotation_history", "the first rotation's row"))
        add(refused("ch_rotation_history", "a removal flag of 2", "removal" to 2L))
        add(accepted("ch_rotation_history", "a removal rotation's row", "removal" to 1L))
        add(refused("ch_rotation_history", "a negative day", "rotated_day" to -1L))
        // ---- ch_reaction
        addAll(between("ch_reaction", "grapheme_env", 29, 60))
        addAll(exact("ch_reaction", "author", 32))
        add(Case("ch_reaction", mapOf("target" to chBytes(16, 0x99)), "a reaction to a post that is not there", FOREIGN_KEY_FAILED))
        // ---- ch_pending_post
        addAll(between("ch_pending_post", "content_env", 29, 65_564))
        addAll(exact("ch_pending_post", "op_id", 16))
        // ---- ch_outbound_op
        addAll(oneOf("ch_outbound_op", "purpose", listOf("post", "commit", "welcome", "join", "rejoin", "request")))
        add(refused("ch_outbound_op", "an empty reference", "ref" to chBytes(0, 1)))
        add(refused("ch_outbound_op", "a reference of 65 bytes", "ref" to chBytes(65, 1)))
        add(accepted("ch_outbound_op", "a reference of 64 bytes", "ref" to chBytes(64, 1)))
        add(accepted("ch_outbound_op", "no reference"))
        // Slice S8's three columns (§19.45; unpinned until the review, §19.46 FIX 6): the blob is a
        // floor-sized bucket of §5.6, the deadline an hour, the resend count 0 … 2.
        add(accepted("ch_outbound_op", "a blob of the 4 KiB bucket", "blob" to chBytes(4096, 1)))
        add(accepted("ch_outbound_op", "a blob of the 16 KiB bucket", "blob" to chBytes(16384, 1)))
        add(accepted("ch_outbound_op", "a blob of the 64 KiB bucket", "blob" to chBytes(65536, 1)))
        add(refused("ch_outbound_op", "a blob of 4095 bytes", "blob" to chBytes(4095, 1)))
        add(refused("ch_outbound_op", "a blob of 4097 bytes", "blob" to chBytes(4097, 1)))
        add(refused("ch_outbound_op", "a blob of 65537 bytes", "blob" to chBytes(65537, 1)))
        add(accepted("ch_outbound_op", "a deadline on the hour", "deadline_hour" to 3600L))
        add(refused("ch_outbound_op", "a deadline an hour over the grid", "deadline_hour" to 3601L))
        add(refused("ch_outbound_op", "a negative deadline", "deadline_hour" to -3600L))
        add(accepted("ch_outbound_op", "two resends", "resends" to 2L))
        add(refused("ch_outbound_op", "three resends", "resends" to 3L))
        add(refused("ch_outbound_op", "a negative resend count", "resends" to -1L))
        // ---- ch_seen, ch_kp_seen, ch_reveal
        addAll(exact("ch_seen", "tag", 16))
        // the day is a week, as dm_seen's (F9 section 7.6 D3): a seizer learns the week and not the day
        add(refused("ch_seen", "a day that is not a week", "until_day" to 19_998L))
        add(refused("ch_seen", "a day a week and a day on", "until_day" to 20_000L))
        add(accepted("ch_seen", "a week", "until_day" to 19_999L))
        add(accepted("ch_seen", "week 0", "until_day" to 0L))
        addAll(exact("ch_kp_seen", "tag", 16))
        addAll(oneOf("ch_reveal", "direction", listOf("in", "out")))
        addAll(exact("ch_reveal", "peer", 32))
        add(accepted("ch_reveal", "a reveal in a channel whose timer is off (no deadline)"))
        // ---- ch_join and ch_join_request
        addAll(exact("ch_join", "kp_ref", 32))
        addAll(oneOf("ch_join", "type", listOf("join", "restore"), "invite_id" to chBytes(16, 27)))
        // A rejoin has no invite, so none of the invite's state either (slice S4, §19.35 F-8).
        val noInviteState = arrayOf("ns" to null, "jk_env" to null, "r_join" to null, "committers_digest" to null)
        // Slice S7 (§6.7): a rejoin row alone carries its give-up day.
        add(accepted("ch_join", "a rejoin without an invite", "type" to "rejoin", "invite_id" to null, "rejoin_deadline_day" to 20_021L, *noInviteState))
        add(refused("ch_join", "a rejoin with an invite's namespace", "type" to "rejoin", "invite_id" to null, "rejoin_deadline_day" to 20_021L, "jk_env" to null, "r_join" to null, "committers_digest" to null))
        add(refused("ch_join", "a join without its invite's state", *noInviteState))
        for (column in listOf("ns", "jk_env", "r_join", "committers_digest")) {
            add(refused("ch_join", "a join whose invite state lacks $column", column to null))
        }
        addAll(exact("ch_join", "ns", 32))
        addAll(exact("ch_join", "jk_env", 60))
        addAll(exact("ch_join", "r_join", 32))
        addAll(exact("ch_join", "committers_digest", 32))
        add(refused("ch_join", "a rejoin with an invite", "type" to "rejoin"))
        add(refused("ch_join", "a join without an invite", "invite_id" to null))
        add(refused("ch_join", "a restore without an invite", "type" to "restore", "invite_id" to null))
        add(refused("ch_join", "an invite id of 15 bytes", "invite_id" to chBytes(15, 1)))
        addAll(exact("ch_join_request", "hash", 32))
        addAll(oneOf("ch_join_request", "type", listOf("join", "restore"), "invite_id" to chBytes(16, 27)))
        add(accepted("ch_join_request", "a rejoin request without an invite", "type" to "rejoin", "invite_id" to null))
        add(refused("ch_join_request", "a rejoin request with an invite", "type" to "rejoin"))
        add(refused("ch_join_request", "a join request without an invite", "invite_id" to null))
        addAll(between("ch_join_request", "body_env", 29, 4_096))
        // ---- ch_invite_issued
        addAll(exact("ch_invite_issued", "invite_id", 16))
        addAll(exact("ch_invite_issued", "invite_pk", 32))
        addAll(exact("ch_invite_issued", "sponsor", 32))
        addAll(exact("ch_invite_issued", "sponsor_sig", 64))
        addAll(exact("ch_invite_issued", "committers_digest", 32))
        add(refused("ch_invite_issued", "pw_version 0", "pw_version" to 0L))
        add(refused("ch_invite_issued", "pw_version 65536", "pw_version" to 65_536L))
        add(accepted("ch_invite_issued", "pw_version 1", "pw_version" to 1L))
        add(accepted("ch_invite_issued", "pw_version 65535", "pw_version" to 65_535L))
        add(refused("ch_invite_issued", "consumed = 2", "consumed" to 2L))
        add(refused("ch_invite_issued", "void = 2", "void" to 2L))
        add(accepted("ch_invite_issued", "consumed and void set", "consumed" to 1L, "void" to 1L))
        // ---- the committer's work and the member records
        addAll(exact("ch_member_seen", "member", 32))
        addAll(between("ch_invite_own", "invite_env", 29, 1024))
        add(accepted("ch_invite_own", "a password invite is not stored (Q50 (a))", "invite_env" to null))
        addAll(exact("ch_invite_own", "invite_id", 16))
        addAll(exact("ch_sponsor", "member", 32))
        addAll(exact("ch_sponsor", "sponsor", 32))
        addAll(exact("ch_sponsor", "invite_id", 16))
        addAll(exact("ch_member_refresh", "member", 32))
        addAll(oneOf("ch_request", "kind", listOf("leave", "remove", "policy", "class")))
        addAll(between("ch_request", "subject", 1, 32))
        addAll(between("ch_request", "payload_env", 29, 4_096))
        // ---- ch_box_key
        addAll(exact("ch_box_key", "box_pk", 32))
        addAll(exact("ch_box_key", "sk_env", 60))
        // ---- mls_self (slice S4, §10.4 "State key"): one row, a wrapped key of 40 … 256 bytes
        addAll(between("mls_self", "state_key_wrapped", 40, 256))
        add(refused("mls_self", "a second row", "id" to 2L))
        add(refused("mls_self", "row 0", "id" to 0L))
    }

    @Test
    fun everyConstraintRefusesTheValueJustOutsideAndAcceptsTheValueJustInside() {
        val tables = cases.map { it.table }.toSet()
        // Every table has cases, so a constraint added to one without a test here is at least beside tests.
        assertEquals("a channel table with no case at all", emptySet<String>(), ChannelSchema.tables - tables)
        assertTrue("the case list is long enough to mean something: ${cases.size}", cases.size >= 250)
        for (case in cases) ChannelFixture().use { f ->
            val label = "${case.table}: ${case.why}"
            f.parents(case.table)
            val (sql, args) = f.sql(case.table, case.set)
            if (case.fragment.isEmpty()) {
                f.db.exec(sql, args)
                assertEquals(label, 1L, f.count(case.table))
            } else {
                f.db.rejects(case.fragment, sql, *args.toTypedArray())
                assertEquals(label, 0L, f.count(case.table))
            }
        }
    }

    /** The defaults themselves are valid rows of every table (a baseline for every refusal above). */
    @Test
    fun theDefaultRowOfEveryTableIsValidAndEveryTableTakesItsRowsThroughTheForeignKeys() = ChannelFixture().use { f ->
        for (table in ChannelSchema.tables) f.put(table)
        for (table in ChannelSchema.tables) assertEquals(table, 1L, f.count(table))
        assertEquals(null, f.db.queryLong("PRAGMA foreign_key_check"))
        // A child of a channel that is not there is refused, for every channel-scoped table.
        for (table in ChannelSchema.tables - setOf("ch_channel", "ch_reaction", "mls_self")) ChannelFixture().use { g ->
            val (sql, args) = g.sql(table, mapOf("channel_id" to chBytes(32, 0x77)))
            g.db.rejects(FOREIGN_KEY_FAILED, sql, *args.toTypedArray())
        }
    }
}
