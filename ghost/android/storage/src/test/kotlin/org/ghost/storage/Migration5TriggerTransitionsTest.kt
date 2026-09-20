package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The **v5 trigger transition tests** of slice S5 (Phase 9 design §21.13 point 3, §13.6 step 6):
 * legal and illegal transitions on the state machines migration 5 writes in SQL.
 *
 * [Migration5Test] walks one path through each of those machines and covers the write-once and
 * REPLACE rules; what is missing there, and what this class adds, is the **matrix**: for each
 * state machine, every one of the `n × n` ordered pairs is attempted, the legal ones must be
 * accepted and every other one must be refused by name. A trigger that lost an arm passes a walk
 * through the arms it kept; it cannot pass a matrix.
 *
 * Two further rules of §13.6 step 6 that no walk reaches are covered here too: a message's
 * unread deadline (the incoming half of `dm_message_expiry`, where [Migration5Test] exercises the
 * outgoing one), and `olm_session`'s write-once `unack_since_day` and erase-only `prov_env`.
 */
class Migration5TriggerTransitionsTest {

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    // ---------------------------------------------------------------- dm_contact_trust

    private val trustStates = listOf("request", "unverified", "verified", "changed", "blocked", "revoked")

    /** §8.2, §8.3 and the trigger `dm_contact_trust`: the edges the design allows, `s -> s` aside. */
    private val legalTrustEdges = setOf(
        "request" to "unverified", "request" to "blocked", "request" to "revoked",
        "unverified" to "verified", "unverified" to "changed", "unverified" to "blocked", "unverified" to "revoked",
        // No verified -> unverified edge: a verification is cleared only through a key change.
        "verified" to "changed", "verified" to "blocked", "verified" to "revoked",
        "changed" to "unverified", "changed" to "verified", "changed" to "blocked", "changed" to "revoked",
        "blocked" to "revoked",
        // `revoked` is terminal; only deleteContact() ends it.
    )

    /**
     * A contact in [state], reached the way the design reaches it, so nothing but the transition
     * under test is ever the first write of a state.
     */
    private fun JdbcSqlExecutor.contactIn(state: String, i: Int): ByteArray {
        val id = bytes(16, i)
        val start = if (state == "request") "request" else "unverified"
        exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment, " +
                "request_until_day) VALUES (?, ?, ?, 0, ?, 'link', 'card_only', ?)",
            listOf(id, bytes(32, i), bytes(159, i), start, if (start == "request") 7L else null),
        )
        when (state) {
            "request", "unverified" -> Unit
            "verified" -> exec("UPDATE dm_contact SET trust_state = 'verified' WHERE contact_id = ?", listOf(id))
            "changed" -> {
                exec("UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ?", listOf(bytes(32, 100 + i), id))
                exec(
                    "UPDATE dm_contact SET trust_state = 'changed', pending_identity = ? WHERE contact_id = ?",
                    listOf(bytes(32, 200 + i), id),
                )
            }
            "blocked", "revoked" -> exec("UPDATE dm_contact SET trust_state = ? WHERE contact_id = ?", listOf(state, id))
        }
        assertEquals(state, queryString("SELECT trust_state FROM dm_contact WHERE contact_id = ?", listOf(id)))
        return id
    }

    /**
     * The companion columns a state needs, set in the same statement so the CHECKs of §13.6 hold
     * whichever way the transition goes and the **trigger** is the only thing that can refuse it.
     */
    private fun trustSet(to: String): String = when (to) {
        "request" -> "trust_state = 'request', pending_identity = NULL, request_until_day = 7"
        "changed" -> "trust_state = 'changed', pending_identity = ?, request_until_day = NULL"
        else -> "trust_state = '$to', pending_identity = NULL, request_until_day = NULL"
    }

    @Test
    fun theTrustMachineAcceptsEveryLegalEdgeAndRefusesEveryOther() = db().use { db ->
        var i = 0
        for (from in trustStates) {
            for (to in trustStates) {
                i += 1
                val id = db.contactIn(from, i)
                val sql = "UPDATE dm_contact SET ${trustSet(to)} WHERE contact_id = ?"
                // A contact that has to become `changed` needs a pin first; every other state
                // clears the pending identity, so the pin is untouched.
                if (to == "changed" && from != "changed") {
                    db.exec("UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ?", listOf(bytes(32, 100 + i), id))
                }
                val args: List<Any?> = if (to == "changed") listOf(bytes(32, 200 + i), id) else listOf(id)
                if (from == to || (from to to) in legalTrustEdges) {
                    assertEquals("$from -> $to must be legal", 1, db.execUpdate(sql, args))
                    assertEquals(to, db.queryString("SELECT trust_state FROM dm_contact WHERE contact_id = ?", listOf(id)))
                } else {
                    db.rejects("illegal trust transition", sql, *args.toTypedArray())
                    assertEquals(from, db.queryString("SELECT trust_state FROM dm_contact WHERE contact_id = ?", listOf(id)))
                }
            }
        }
        assertEquals("the matrix ran", trustStates.size * trustStates.size, i)
    }

    // ---------------------------------------------------------------- dm_message_state

    private val messageStates = listOf("queued", "sent", "degraded", "failed", "indeterminate", "unread", "read")

    /** §11.1's message state machine and the trigger `dm_message_state`, `s -> s` aside. */
    private val legalMessageEdges = setOf(
        "queued" to "sent", "queued" to "degraded", "queued" to "failed", "queued" to "indeterminate",
        "failed" to "queued",
        "unread" to "read",
    )

    /** An outgoing message lives in the first five states, an incoming one in the last two. */
    private fun directionOf(state: String) = if (state in listOf("unread", "read")) "in" else "out"

    /**
     * A message in [state] with `timer_code = 0` (off): the three expiry columns are then NULL by
     * CHECK whatever the direction, so the transition under test is the only variable.
     */
    private fun JdbcSqlExecutor.messageIn(state: String, i: Int): ByteArray {
        val id = bytes(16, i)
        val direction = directionOf(state)
        val start = if (direction == "out") "queued" else "unread"
        exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state) VALUES (?, ?, ?, 1, 600, 600, ?, 0, ?, ?)",
            listOf(id, bytes(16, 1), direction, i % 65536, bytes(100, i % 251), start),
        )
        if (state != start) exec("UPDATE dm_message SET state = ? WHERE message_id = ?", listOf(state, id))
        assertEquals(state, queryString("SELECT state FROM dm_message WHERE message_id = ?", listOf(id)))
        return id
    }

    @Test
    fun theMessageMachineAcceptsEveryLegalEdgeAndRefusesEveryOther() = db().use { db ->
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
        var i = 0
        for (from in messageStates) {
            for (to in messageStates) {
                i += 1
                val id = db.messageIn(from, i)
                val sql = "UPDATE dm_message SET state = ? WHERE message_id = ?"
                if (from == to || (from to to) in legalMessageEdges) {
                    assertEquals("$from -> $to must be legal", 1, db.execUpdate(sql, listOf(to, id)))
                } else {
                    // Cross-direction pairs would also break the direction CHECK, but a BEFORE
                    // UPDATE trigger runs before constraints, so the trigger is what answers.
                    db.rejects("illegal message state transition", sql, to, id)
                }
                assertEquals(
                    if (from == to || (from to to) in legalMessageEdges) to else from,
                    db.queryString("SELECT state FROM dm_message WHERE message_id = ?", listOf(id)),
                )
            }
        }
        assertEquals("the matrix ran", messageStates.size * messageStates.size, i)
    }

    // ---------------------------------------------------------------- the remaining v5 rules

    /** `dm_message_identity`: everything but the state and the three expiry columns is frozen. */
    @Test
    fun everyColumnOfAMessageButItsStateAndExpiriesIsFrozen() = db().use { db ->
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
        db.messageIn("queued", 1)
        // The conversation the move would target does not exist: the trigger is a BEFORE UPDATE
        // one, so it answers before the foreign key would, and the assertion on its message is
        // what tells the two apart.
        val frozen = mapOf(
            "message_id" to bytes(16, 9),
            "conversation_id" to bytes(16, 2),
            "direction" to "in",
            "kind" to 2,
            "author_minute" to 660L,
            "sort_minute" to 540L,
            "minute_index" to 7,
            "timer_code" to 4,
            "body_env" to bytes(100, 9),
        )
        for ((column, value) in frozen) {
            db.rejects(
                "only the state",
                "UPDATE dm_message SET $column = ? WHERE message_id = ?",
                value, bytes(16, 1),
            )
        }
        // The trigger's column list is the whole row minus four columns, so a column added to
        // `dm_message` later is either frozen here or one of the four, and this catches the gap.
        val columns = ArrayList<String>()
        db.query("PRAGMA table_info(dm_message)") { columns += it.string(1) }
        assertEquals(
            frozen.keys + setOf("state", "expire_at_minute", "unread_deadline_minute", "delete_at_minute"),
            columns.toSet(),
        )
    }

    /**
     * The incoming half of `dm_message_expiry` (§10.6, ADR-27 point 9): an unread deadline only
     * moves earlier and never becomes NULL, and `delete_at_minute` follows it by CHECK.
     */
    @Test
    fun anUnreadDeadlineOnlyMovesEarlier() = db().use { db ->
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, " +
                "timer_code, body_env, state, unread_deadline_minute, delete_at_minute) " +
                "VALUES (?, ?, 'in', 1, 600, 600, 0, 4, ?, 'unread', 3600, 3600)",
            listOf(bytes(16, 1), bytes(16, 1), bytes(100, 1)),
        )
        val where = "WHERE message_id = ?"
        db.rejects(
            "an expiry time only moves earlier",
            "UPDATE dm_message SET unread_deadline_minute = 4200, delete_at_minute = 4200 $where",
            bytes(16, 1),
        )
        db.rejects(
            "an expiry time only moves earlier",
            "UPDATE dm_message SET unread_deadline_minute = NULL, delete_at_minute = NULL $where",
            bytes(16, 1),
        )
        assertEquals(
            1,
            db.changes("UPDATE dm_message SET unread_deadline_minute = 3000, delete_at_minute = 3000 $where", bytes(16, 1)),
        )
        // On display the message is read and the expiry minute becomes the source of the delete
        // minute, which may sit later than the unread deadline it replaces (ADR-27 point 9).
        assertEquals(
            1,
            db.changes(
                "UPDATE dm_message SET state = 'read', expire_at_minute = 3300, delete_at_minute = 3300 $where",
                bytes(16, 1),
            ),
        )
        assertEquals(3300L, db.queryLong("SELECT delete_at_minute FROM dm_message"))
    }

    /** `dm_conversation_timer` (§10.5 R-T9): the timer version never decreases. */
    @Test
    fun theTimerVersionNeverDecreasesAndTheCodeFollowsIt() = db().use { db ->
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
        val where = "WHERE conversation_id = ?"
        assertEquals(4L, db.queryLong("SELECT timer_code FROM dm_conversation"))
        assertEquals(0L, db.queryLong("SELECT timer_version FROM dm_conversation"))
        assertEquals(1, db.changes("UPDATE dm_conversation SET timer_code = 1, timer_version = 5 $where", bytes(16, 1)))
        // Equal versions are allowed through (the shorter timer wins, decided above SQL).
        assertEquals(1, db.changes("UPDATE dm_conversation SET timer_code = 0, timer_version = 5 $where", bytes(16, 1)))
        db.rejects("the timer version never decreases", "UPDATE dm_conversation SET timer_version = 4 $where", bytes(16, 1))
        assertEquals(5L, db.queryLong("SELECT timer_version FROM dm_conversation"))
        // The code stays a bucket index, 0..5 (§10.5).
        db.rejects(CHECK_FAILED, "UPDATE dm_conversation SET timer_code = 6 $where", bytes(16, 1))
    }

    /**
     * `olm_session_identity`'s two rules no walk reaches: `unack_since_day` is write-once (§8.5's
     * `UNACK_MAX` counts from the first unacknowledged send, not from the latest), and `prov_env`
     * is erased, never replaced (§22.8.5).
     */
    @Test
    fun theUnackDayIsWriteOnceAndTheProvisionalEnvelopeIsOnlyErased() = db().use { db ->
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        // An unacknowledged initiator session: the only shape that carries `unack_since_day`.
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_gen_id, " +
                "unack_since_day, prov_env, prov_erase_minute) VALUES (?, 'current', ?, 'initiator', 0, ?, 7, 100, ?, 600)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(200, 1), bytes(60, 1)),
        )
        val where = "WHERE contact_id = ? AND slot = 'current'"
        db.rejects("keeps its identity", "UPDATE olm_session SET unack_since_day = 101 $where", bytes(16, 1))
        db.rejects("keeps its identity", "UPDATE olm_session SET prov_env = ? $where", bytes(60, 2), bytes(16, 1))
        // Erasing the provisional envelope and its minute together is the legal move.
        assertEquals(
            1,
            db.changes("UPDATE olm_session SET prov_env = NULL, prov_erase_minute = NULL $where", bytes(16, 1)),
        )
        // And it cannot come back.
        db.rejects("keeps its identity", "UPDATE olm_session SET prov_env = ? $where", bytes(60, 3), bytes(16, 1))
        // Acknowledgement clears the unack day; it is the one write that may.
        assertEquals(
            1,
            db.changes("UPDATE olm_session SET acknowledged = 1, unack_since_day = NULL $where", bytes(16, 1)),
        )
        assertTrue(db.queryLong("SELECT unack_since_day FROM olm_session") == null)
    }

    /** `olm_prekey_gen_fixed`: the erasure day is derived once and never moves (§5.4). */
    @Test
    fun aGenerationsDeletionDayIsWrittenOnceWithItsSupersession() = db().use { db ->
        db.exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (1, 2870, ?, ?)",
            listOf(bytes(32, 1), bytes(92, 1)),
        )
        db.rejects(
            CHECK_FAILED,
            "UPDATE olm_prekey_gen SET delete_after_day = 101 WHERE gen_id = 1",
        )
        assertEquals(
            1,
            db.changes("UPDATE olm_prekey_gen SET superseded_day = 10, delete_after_day = 101 WHERE gen_id = 1"),
        )
        db.rejects("immutable", "UPDATE olm_prekey_gen SET delete_after_day = 102 WHERE gen_id = 1")
        db.rejects("immutable", "UPDATE olm_prekey_gen SET superseded_day = NULL, delete_after_day = NULL WHERE gen_id = 1")
    }
}
