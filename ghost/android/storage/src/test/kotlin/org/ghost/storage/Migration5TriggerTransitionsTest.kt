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
 * Beside the two state machines, the same idea is applied to the **immutability** triggers, which
 * are not state machines but disjunctions of arms: `dm_self_fixed`, `dm_contact_identity`,
 * `dm_message_identity`, `dm_pair_offer_root`, `olm_session_identity` and `olm_prekey_gen_fixed`
 * each name a set of columns that may not change, and a walk that updates one of them passes even
 * after the trigger lost the arms for the others. Every one of those triggers therefore gets the
 * `PRAGMA table_info` treatment [everyColumnOfAMessageButItsStateAndExpiriesIsFrozen] gives
 * `dm_message`: the whole row is attempted column by column, the frozen ones must be refused, the
 * changeable ones must be accepted, and the two sets together must be the table's own column list —
 * so a column added later is either covered or the test fails.
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

    // ---------------------------------------------------------------- the frozen-column matrices

    /**
     * The matrix of one immutability trigger: every column of [table] is attempted on a row that
     * [where] selects, and each must land in exactly one of three declared places.
     *
     *  - [frozen]: the column with a value the trigger must refuse, by [message]. The assertion is
     *    on the trigger's own text, so a CHECK or a foreign key that would also have refused the
     *    write cannot stand in for the arm (a `BEFORE UPDATE` trigger runs before both).
     *  - [changeable]: a value the table must accept, so the trigger cannot be over-wide.
     *  - [otherwiseRuled]: a column whose rule is not this trigger's — a CHECK that ties it to
     *    another column, a state machine of its own, a key the REPLACE guard covers — with the
     *    reason and where it is tested instead.
     *
     * The three together must be the table's whole column list, read from `PRAGMA table_info`: a
     * column added to the table later is in none of them and fails here, which is what stops a
     * trigger from quietly stopping short of the row it guards.
     */
    private fun JdbcSqlExecutor.everyColumnOf(
        table: String,
        where: String,
        key: List<Any?>,
        message: String,
        frozen: Map<String, Any?>,
        changeable: Map<String, Any?>,
        otherwiseRuled: Map<String, String>,
    ) {
        for ((column, value) in frozen) {
            rejects(
                message,
                "UPDATE $table SET $column = ? WHERE $where",
                *(listOf(value) + key).toTypedArray(),
            )
        }
        for ((column, value) in changeable) {
            assertEquals(
                "$table.$column must still be writable",
                1,
                execUpdate("UPDATE $table SET $column = ? WHERE $where", listOf(value) + key),
            )
        }
        val columns = ArrayList<String>()
        query("PRAGMA table_info($table)") { columns += it.string(1) }
        assertEquals(
            "every column of $table is frozen, changeable or ruled elsewhere, and no other",
            columns.toSortedSet().toList(),
            (frozen.keys + changeable.keys + otherwiseRuled.keys).toSortedSet().toList(),
        )
    }

    private fun JdbcSqlExecutor.aContact(i: Int = 1) = exec(
        "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
            "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
        listOf(bytes(16, i), bytes(32, i), bytes(159, i)),
    )

    /** `dm_self_fixed` and `dm_self_monotonic`, arm by arm (§13.6: `id`, `seen_key`, `card_index`). */
    @Test
    fun theIdentityRowFreezesItsIdItsSeenKeyAndItsCardIndex() = db().use { db ->
        db.exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, expiry_clock_minute) " +
                "VALUES (1, 0, ?, ?, ?, 60)",
            listOf(bytes(32, 1), bytes(60, 2), bytes(60, 3)),
        )
        db.everyColumnOf(
            "dm_self", "id = ?", listOf(1L),
            "the identity row keeps its id, seen key and card index",
            frozen = mapOf(
                // `id` also carries `CHECK (id = 1)`, and the message is what tells the two apart.
                "id" to 2L,
                "seen_key" to bytes(32, 9),
                "card_index" to 1,
            ),
            changeable = mapOf(
                "content_key_wrapped" to bytes(60, 9),
                "state_key_wrapped" to bytes(60, 9),
                "expiry_clock_minute" to 120L,
                "accept_after_minute" to 600L,
                "bundle_week" to 2870L,
                "bundle_published_week" to 2870L,
            ),
            otherwiseRuled = emptyMap(),
        )
        // And the two monotonic columns still are: `dm_self_monotonic` is a separate trigger.
        db.rejects("never go backwards", "UPDATE dm_self SET bundle_week = 2869 WHERE id = 1")
        db.rejects("never go backwards", "UPDATE dm_self SET bundle_week = NULL WHERE id = 1")
        db.rejects("never go backwards", "UPDATE dm_self SET expiry_clock_minute = 60 WHERE id = 1")
    }

    /** `dm_contact_identity` (§13.6: `contact_id`, `identity_pk` immutable), arm by arm. */
    @Test
    fun aContactFreezesItsIdAndItsIdentityAndNothingElse() = db().use { db ->
        db.aContact()
        db.everyColumnOf(
            "dm_contact", "contact_id = ?", listOf(bytes(16, 1)),
            "a contact keeps its id and its Ed25519 identity",
            frozen = mapOf(
                // The `contact_id` arm is the one no walk reaches: `identity_pk` is the one
                // `Migration5Test.aContactKeepsItsIdentityAndPinsOnce` fires.
                "contact_id" to bytes(16, 9),
                "identity_pk" to bytes(32, 9),
            ),
            changeable = mapOf(
                "card_env" to bytes(159, 9),
                "card_index" to 1,
                "bundle_week_seen" to 2870L,
                "source" to "qr_in_person",
                "establishment" to "ready",
                "fetch_attempts" to 1,
                "reset_needed" to 1,
                "verified_fp" to bytes(32, 9),
                "name_env" to bytes(100, 9),
                "pq_announced_week" to 2870L,
            ),
            otherwiseRuled = mapOf(
                "trust_state" to "the state machine of [theTrustMachineAcceptsEveryLegalEdgeAndRefusesEveryOther]",
                "pinned_identity" to "dm_contact_pin (Migration5Test.aContactKeepsItsIdentityAndPinsOnce)",
                "pending_identity" to "CHECK-tied to trust_state = 'changed' (§8.3)",
                "request_until_day" to "CHECK-tied to trust_state = 'request'",
                "fetch_listen_until_minute" to "CHECK-tied to establishment = 'fetching'",
            ),
        )
    }

    /**
     * `olm_prekey_gen_fixed` (§13.6: `gen_id`, `fallback_pub`, `secrets_env`, `bundle_week`
     * immutable). `Migration5Test` fires the `secrets_env` and `bundle_week` arms; the two this
     * adds are `gen_id` and `fallback_pub`, which no walk reaches.
     */
    @Test
    fun aGenerationFreezesItsIdItsFallbackKeyItsSecretsAndItsWeek() = db().use { db ->
        db.exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (1, 2870, ?, ?)",
            listOf(bytes(32, 1), bytes(92, 1)),
        )
        db.everyColumnOf(
            "olm_prekey_gen", "gen_id = ?", listOf(1L),
            "a generation is immutable and is superseded once",
            frozen = mapOf(
                "gen_id" to 2L,
                "fallback_pub" to bytes(32, 9),
                "secrets_env" to bytes(92, 9),
                "bundle_week" to 2871L,
            ),
            changeable = emptyMap(),
            otherwiseRuled = mapOf(
                "superseded_day" to "written once together with delete_after_day " +
                    "([aGenerationsDeletionDayIsWrittenOnceWithItsSupersession])",
                "delete_after_day" to "derived by CHECK from superseded_day, written in the same statement",
            ),
        )
    }

    /**
     * `dm_pair_offer_root` (§13.6: "`root_env` **and** `offer_env` may only become NULL;
     * `acknowledged` only 0 → 1"). `Migration5Test.anOfferedRootIsErasedNeverReplaced` walks
     * `root_env` and `acknowledged`; the `offer_env` arms are the ones no walk reaches, and a
     * trigger that lost both of them passes that walk.
     */
    @Test
    fun bothEnvelopesOfAPairOfferAreErasedNeverReplaced() = db().use { db ->
        db.aContact()
        db.exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, offer_env, base_week) VALUES (?, 0, ?, ?, 2870)",
            listOf(bytes(16, 1), bytes(60, 1), bytes(70, 1)),
        )
        db.everyColumnOf(
            "dm_pair_offer", "contact_id = ? AND root_gen = 0", listOf(bytes(16, 1)),
            "an offered root is erased, never replaced, and is acknowledged once",
            frozen = mapOf("root_env" to bytes(60, 2), "offer_env" to bytes(70, 2)),
            changeable = mapOf("acknowledged" to 1, "root_env" to null, "offer_env" to null),
            otherwiseRuled = mapOf(
                "contact_id" to "the row's key; the REPLACE guard covers it (ReplaceGuardsTest)",
                "root_gen" to "the row's key; the REPLACE guard covers it (ReplaceGuardsTest)",
                "base_week" to "the week the root was derived for; no rule of §13.6 freezes it",
            ),
        )
        // Erased, and it cannot come back — which is the half a value-to-value test never reaches.
        db.rejects(
            "never replaced",
            "UPDATE dm_pair_offer SET offer_env = ? WHERE contact_id = ? AND root_gen = 0",
            bytes(70, 3), bytes(16, 1),
        )
        db.rejects(
            "acknowledged once",
            "UPDATE dm_pair_offer SET acknowledged = 0 WHERE contact_id = ? AND root_gen = 0",
            bytes(16, 1),
        )
    }

    /**
     * `olm_session_identity` arm by arm (§13.6: `session_id`, `role`, `peer_gen_id` immutable;
     * `acknowledged` only 0 → 1; `peer_bind_minute` only increases; `prov_anchor_minute`
     * write-once; `pair_sent` only 0 → 1). The `unack_since_day` and `prov_env` arms are
     * [theUnackDayIsWriteOnceAndTheProvisionalEnvelopeIsOnlyErased]'s.
     */
    @Test
    fun everyFrozenColumnOfASessionIsRefusedOnItsOwn() = db().use { db ->
        db.aContact()
        // A responder session, the one shape that carries `peer_bind_minute` and `prov_anchor_minute`.
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute, " +
                "prov_anchor_minute, pair_sent) VALUES (?, 'current', ?, 'responder', 1, ?, 600, 600, 1)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(200, 1)),
        )
        db.everyColumnOf(
            "olm_session", "contact_id = ? AND slot = 'current'", listOf(bytes(16, 1)),
            "a session keeps its identity",
            frozen = mapOf(
                "session_id" to bytes(32, 9),
                "role" to "initiator",
                "acknowledged" to 0,
                // Write-once: the anchor is already set, so any other value is refused.
                "prov_anchor_minute" to 660L,
                "pair_sent" to 0,
                // `peer_bind_minute` only increases, and NULL is "decreases" under R-T6.
                "peer_bind_minute" to null,
            ),
            changeable = mapOf("state_env" to bytes(200, 9), "peer_bind_minute" to 660L),
            otherwiseRuled = mapOf(
                "contact_id" to "the row's key; a slot change is a delete and an insert (§22.8.3)",
                "slot" to "the row's key; a slot change is a delete and an insert (§22.8.3)",
                "retire_day" to "CHECK-tied to slot = 'previous'",
                "peer_gen_id" to "CHECK-tied to role = 'initiator'; frozen below on such a session",
                "unack_since_day" to "[theUnackDayIsWriteOnceAndTheProvisionalEnvelopeIsOnlyErased]",
                "prov_env" to "[theUnackDayIsWriteOnceAndTheProvisionalEnvelopeIsOnlyErased]",
                "prov_erase_minute" to "CHECK-tied to prov_env, erased with it",
            ),
        )
        // The `peer_gen_id` arm on the one session shape that may carry it.
        db.aContact(2)
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_gen_id, " +
                "unack_since_day) VALUES (?, 'current', ?, 'initiator', 0, ?, 7, 100)",
            listOf(bytes(16, 2), bytes(32, 2), bytes(200, 2)),
        )
        db.rejects(
            "a session keeps its identity",
            "UPDATE olm_session SET peer_gen_id = 8 WHERE contact_id = ? AND slot = 'current'",
            bytes(16, 2),
        )
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
        // The other half of the same trigger, and the arm no walk reaches: an expiry minute that
        // is set never becomes NULL either. (The `delete_at_minute` CHECK would also refuse this
        // write; the trigger is a BEFORE UPDATE one, so its message is what answers.)
        db.rejects(
            "an expiry time only moves earlier",
            "UPDATE dm_message SET expire_at_minute = NULL, delete_at_minute = NULL $where",
            bytes(16, 1),
        )
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
