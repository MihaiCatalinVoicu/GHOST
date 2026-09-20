package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration 5 (Phase 9 design §13.6 steps 5–6): the `dm_*` and `olm_*` tables, their CHECKs, their
 * state and write-once triggers and their REPLACE guards.
 *
 * The upgrade paths (v1, v2, v3 → v4 → v5) and the crash-at-every-statement drill live in
 * [SchemaAndMigrationTest] with the other migrations; this class is about what v5 itself enforces.
 */
class Migration5Test {

    private fun db(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    private fun JdbcSqlExecutor.self() = exec(
        "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, expiry_clock_minute) " +
            "VALUES (1, 0, ?, ?, ?, 60)",
        listOf(bytes(32, 1), bytes(60, 2), bytes(60, 3)),
    )

    private fun JdbcSqlExecutor.contact(
        i: Int,
        trust: String = "unverified",
        pinned: ByteArray? = null,
        pending: ByteArray? = null,
        requestUntil: Long? = null,
    ) = exec(
        "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, pinned_identity, pending_identity, " +
            "trust_state, source, establishment, request_until_day) VALUES (?, ?, ?, 0, ?, ?, ?, 'link', 'card_only', ?)",
        listOf(bytes(16, i), bytes(32, i), bytes(159, i), pinned, pending, trust, requestUntil),
    )

    private fun JdbcSqlExecutor.generation(gen: Int) = exec(
        "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (?, 2870, ?, ?)",
        listOf(gen, bytes(32, gen), bytes(92, gen)),
    )

    private fun JdbcSqlExecutor.session(
        contact: Int,
        slot: String,
        session: Int,
        role: String = "responder",
        retire: Long? = if (slot == "previous") 46L else null,
    ) = exec(
        "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_gen_id, " +
            "unack_since_day, retire_day, peer_bind_minute) VALUES (?, ?, ?, ?, 1, ?, ?, NULL, ?, ?)",
        listOf(
            bytes(16, contact),
            slot,
            bytes(32, session),
            role,
            bytes(200, session),
            if (role == "initiator") 7 else null,
            retire,
            if (role == "responder") 60L else null,
        ),
    )

    @Test
    fun theSchemaReachesVersionFiveWithEveryTableAndTrigger() = db().use { db ->
        MigrationRunner(db).verifyIntegrity()
        assertEquals(Schema.CURRENT_VERSION.toLong(), db.queryLong("PRAGMA user_version"))
        val tables = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { tables += it.string(0) }
        assertTrue(tables.containsAll(Schema.expectedTables))
        val triggers = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'") { triggers += it.string(0) }
        assertEquals(Schema.expectedTriggers, Schema.expectedTriggers.intersect(triggers))
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
    }

    /** R-M4: no virtual table, hence no FTS index over DM content (§13.6). */
    @Test
    fun theSchemaCarriesNoVirtualTable() = db().use { db ->
        val virtualTables = ArrayList<String>()
        db.query("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND sql LIKE '%VIRTUAL%'") {
            virtualTables += it.string(0)
        }
        assertEquals(emptyList<String>(), virtualTables)
    }

    /**
     * R-M3 (T20, T33): migration 5 adds exactly the time columns §13.6 lists, and every one of
     * them is integer-typed by a CHECK. A column with a time-like name that is not on the list
     * fails here.
     */
    @Test
    fun theTimeColumnsAreExactlyTheOnesTheDesignLists() = db().use { db ->
        val expected = setOf(
            "dm_self.expiry_clock_minute", "dm_self.accept_after_minute",
            "dm_contact.fetch_listen_until_minute", "dm_contact.request_until_day",
            "dm_message.author_minute", "dm_message.sort_minute", "dm_message.expire_at_minute",
            "dm_message.unread_deadline_minute", "dm_message.delete_at_minute",
            "dm_outbound_item.deadline_hour", "dm_outbound_op.deadline_hour",
            "dm_pending_send.fail_after_hour", "dm_scheduled.due_minute",
            "dm_held.hold_until_minute", "dm_held.relay_expiry_hour", "dm_held.consume_minute",
            "dm_seen.until_day",
            "olm_session.prov_erase_minute", "olm_session.unack_since_day", "olm_session.retire_day",
            "olm_session.peer_bind_minute", "olm_session.prov_anchor_minute",
            "olm_prekey_gen.superseded_day", "olm_prekey_gen.delete_after_day",
        )
        val dmTables = Schema.expectedTables.filter { it.startsWith("dm_") || it.startsWith("olm_") }
        val found = HashSet<String>()
        for (table in dmTables) {
            db.query("PRAGMA table_info($table)") { row ->
                val column = row.string(1)
                if (column.endsWith("_minute") || column.endsWith("_hour") || column.endsWith("_day")) {
                    found += "$table.$column"
                }
            }
        }
        assertEquals(expected, found)
    }

    @Test
    fun theIdentityRowKeepsItsFixedColumnsAndItsClockNeverGoesBackwards() = db().use { db ->
        db.self()
        db.rejects("keeps its id", "UPDATE dm_self SET seen_key = ?", bytes(32, 9))
        db.rejects("keeps its id", "UPDATE dm_self SET card_index = 1")
        db.rejects("never go backwards", "UPDATE dm_self SET expiry_clock_minute = 0")
        assertEquals(1, db.changes("UPDATE dm_self SET expiry_clock_minute = 120"))
        assertEquals(1, db.changes("UPDATE dm_self SET bundle_week = 2870"))
        db.rejects("never go backwards", "UPDATE dm_self SET bundle_week = 2869")
        db.rejects("never go backwards", "UPDATE dm_self SET bundle_week = NULL")
        db.rejects(
            "dm_self rows are never replaced",
            "INSERT OR REPLACE INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "expiry_clock_minute) VALUES (1, 0, ?, ?, ?, 60)",
            bytes(32, 4), bytes(60, 5), bytes(60, 6),
        )
    }

    @Test
    fun aContactKeepsItsIdentityAndPinsOnce() = db().use { db ->
        db.contact(1)
        db.rejects("keeps its id", "UPDATE dm_contact SET identity_pk = ? WHERE contact_id = ?", bytes(32, 9), bytes(16, 1))
        // The pin is taken once...
        assertEquals(1, db.changes("UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ?", bytes(32, 5), bytes(16, 1)))
        // ...and does not move while the contact is not `changed`.
        db.rejects(
            "set once",
            "UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ?",
            bytes(32, 6), bytes(16, 1),
        )
        // A key change: pending is set, then KEYDEC promotes exactly that value.
        assertEquals(
            1,
            db.changes(
                "UPDATE dm_contact SET trust_state = 'changed', pending_identity = ? WHERE contact_id = ?",
                bytes(32, 7), bytes(16, 1),
            ),
        )
        db.rejects(
            "set once",
            "UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ?",
            bytes(32, 8), bytes(16, 1),
        )
        assertEquals(
            1,
            db.changes(
                "UPDATE dm_contact SET pinned_identity = ?, pending_identity = NULL, trust_state = 'unverified' " +
                    "WHERE contact_id = ?",
                bytes(32, 7), bytes(16, 1),
            ),
        )
    }

    @Test
    fun onlyTheTrustTransitionsOfSectionEightAreAllowed() = db().use { db ->
        db.contact(1, trust = "request", requestUntil = 7)
        db.rejects(
            "illegal trust transition",
            "UPDATE dm_contact SET trust_state = 'verified' WHERE contact_id = ?",
            bytes(16, 1),
        )
        assertEquals(
            1,
            db.changes(
                "UPDATE dm_contact SET trust_state = 'unverified', request_until_day = NULL WHERE contact_id = ?",
                bytes(16, 1),
            ),
        )
        assertEquals(1, db.changes("UPDATE dm_contact SET trust_state = 'verified' WHERE contact_id = ?", bytes(16, 1)))
        assertEquals(1, db.changes("UPDATE dm_contact SET trust_state = 'revoked' WHERE contact_id = ?", bytes(16, 1)))
        // `revoked` is terminal: only deleteContact() ends it.
        db.rejects(
            "illegal trust transition",
            "UPDATE dm_contact SET trust_state = 'unverified' WHERE contact_id = ?",
            bytes(16, 1),
        )
    }

    @Test
    fun aChangedContactNeedsBothAPinAndAPendingIdentity() = db().use { db ->
        db.rejects(
            CHECK_FAILED,
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'changed', 'link', 'card_only')",
            bytes(16, 2), bytes(32, 2), bytes(159, 2),
        )
        // A pending identity equal to the pinned one is not a key change.
        db.rejects(
            CHECK_FAILED,
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, pinned_identity, pending_identity, " +
                "trust_state, source, establishment) VALUES (?, ?, ?, 0, ?, ?, 'changed', 'link', 'card_only')",
            bytes(16, 3), bytes(32, 3), bytes(159, 3), bytes(32, 9), bytes(32, 9),
        )
    }

    @Test
    fun aSessionKeepsItsIdentityAndItsWriteOnceColumns() = db().use { db ->
        db.contact(1)
        db.session(1, "current", 1, role = "initiator")
        val where = "WHERE contact_id = ? AND slot = 'current'"
        db.rejects("keeps its identity", "UPDATE olm_session SET session_id = ? $where", bytes(32, 9), bytes(16, 1))
        db.rejects("keeps its identity", "UPDATE olm_session SET role = 'responder' $where", bytes(16, 1))
        db.rejects("keeps its identity", "UPDATE olm_session SET peer_gen_id = 8 $where", bytes(16, 1))
        db.rejects("keeps its identity", "UPDATE olm_session SET acknowledged = 0 $where", bytes(16, 1))
        // The state envelope is what a ratchet step replaces, and it may.
        assertEquals(1, db.changes("UPDATE olm_session SET state_env = ? $where", bytes(300, 4), bytes(16, 1)))
        // `pair_sent` only goes 0 -> 1, and `prov_anchor_minute` is write-once.
        assertEquals(1, db.changes("UPDATE olm_session SET pair_sent = 1 $where", bytes(16, 1)))
        db.rejects("keeps its identity", "UPDATE olm_session SET pair_sent = 0 $where", bytes(16, 1))
        assertEquals(1, db.changes("UPDATE olm_session SET prov_anchor_minute = 60 $where", bytes(16, 1)))
        db.rejects("keeps its identity", "UPDATE olm_session SET prov_anchor_minute = 120 $where", bytes(16, 1))
    }

    @Test
    fun aResponderSessionCarriesABindMinuteThatOnlyIncreases() = db().use { db ->
        db.contact(1)
        db.session(1, "current", 1)
        val where = "WHERE contact_id = ? AND slot = 'current'"
        assertEquals(1, db.changes("UPDATE olm_session SET peer_bind_minute = 120 $where", bytes(16, 1)))
        db.rejects("keeps its identity", "UPDATE olm_session SET peer_bind_minute = 60 $where", bytes(16, 1))
        db.rejects("keeps its identity", "UPDATE olm_session SET peer_bind_minute = NULL $where", bytes(16, 1))
    }

    /** §15.3 structural invariant: at most two rows per contact, exactly one `current`. */
    @Test
    fun atMostTwoSessionsPerContactAndOnlyOneOfEachSlot() = db().use { db ->
        db.contact(1)
        db.session(1, "current", 1)
        db.session(1, "previous", 2)
        // The REPLACE guard fires first (it is a BEFORE INSERT trigger), which is the point: a
        // second `current` row never reaches the primary key, so it can never delete the first one
        // through REPLACE conflict resolution.
        db.rejects(
            "olm_session rows are never replaced",
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 60)",
            bytes(16, 1), bytes(32, 3), bytes(200, 3),
        )
        db.rejects(
            "olm_session rows are never replaced",
            "INSERT OR REPLACE INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 60)",
            bytes(16, 1), bytes(32, 3), bytes(200, 3),
        )
        // A `previous` row without a retire day, or a `current` row with one, is refused.
        db.exec("DELETE FROM olm_session WHERE contact_id = ? AND slot = 'previous'", listOf(bytes(16, 1)))
        db.rejects(
            CHECK_FAILED,
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'previous', ?, 'responder', 1, ?, 60)",
            bytes(16, 1), bytes(32, 4), bytes(200, 4),
        )
    }

    /** §13.6: the wrapped state has the `SESSION_STATE_MAX` envelope bounds. */
    @Test
    fun theSessionStateEnvelopeIsBounded() = db().use { db ->
        db.contact(1)
        for (size in listOf(28, 65_565)) {
            db.rejects(
                CHECK_FAILED,
                "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                    "VALUES (?, 'current', ?, 'responder', 1, ?, 60)",
                bytes(16, 1), bytes(32, 1), bytes(size, 1),
            )
        }
    }

    @Test
    fun aGenerationIsImmutableAndSupersededOnce() = db().use { db ->
        db.generation(1)
        db.rejects("immutable", "UPDATE olm_prekey_gen SET secrets_env = ? WHERE gen_id = 1", bytes(92, 9))
        db.rejects("immutable", "UPDATE olm_prekey_gen SET bundle_week = 2871 WHERE gen_id = 1")
        assertEquals(
            1,
            db.changes("UPDATE olm_prekey_gen SET superseded_day = 10, delete_after_day = 101 WHERE gen_id = 1"),
        )
        db.rejects("immutable", "UPDATE olm_prekey_gen SET superseded_day = 11, delete_after_day = 102 WHERE gen_id = 1")
        // `delete_after_day` is derived: superseded + 91 (§5.4).
        db.generation(2)
        db.rejects(
            CHECK_FAILED,
            "UPDATE olm_prekey_gen SET superseded_day = 10, delete_after_day = 100 WHERE gen_id = 2",
        )
    }

    /** At most one live generation: the partial unique index of §13.6. */
    @Test
    fun onlyOneGenerationIsLiveAtATime() = db().use { db ->
        db.generation(1)
        // The REPLACE guard covers the partial unique index too, so it is what fires: a second
        // live generation never reaches the index, hence never deletes the first one through
        // REPLACE conflict resolution (which would take its `olm_prekey_used` tuples with it).
        db.rejects(
            "olm_prekey_gen rows are never replaced",
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (2, 2870, ?, ?)",
            bytes(32, 2), bytes(92, 2),
        )
        db.rejects(
            "olm_prekey_gen rows are never replaced",
            "INSERT OR REPLACE INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) " +
                "VALUES (2, 2870, ?, ?)",
            bytes(32, 2), bytes(92, 2),
        )
        assertEquals(
            1,
            db.changes("UPDATE olm_prekey_gen SET superseded_day = 10, delete_after_day = 101 WHERE gen_id = 1"),
        )
        db.generation(2)
    }

    @Test
    fun theFirstFlightReuseSetIsAppendOnlyAndCascades() = db().use { db ->
        db.generation(1)
        db.exec("INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (1, ?)", listOf(bytes(32, 5)))
        db.rejects("append-only", "UPDATE olm_prekey_used SET session_id = ? WHERE gen_id = 1", bytes(32, 6))
        db.rejects(
            "olm_prekey_used rows are never replaced",
            "INSERT OR REPLACE INTO olm_prekey_used(gen_id, session_id) VALUES (1, ?)",
            bytes(32, 5),
        )
        // The cascade of §5.4: erasing the generation erases its reuse tuples.
        db.exec("DELETE FROM olm_prekey_gen WHERE gen_id = 1")
        assertEquals(0L, db.queryLong("SELECT count(*) FROM olm_prekey_used"))
    }

    @Test
    fun heldRowsAndPeerKeysAreCapped() = db().use { db ->
        db.contact(1)
        for (i in 0 until 256) {
            db.exec(
                "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, hold_until_minute, relay_expiry_hour, " +
                    "consume_minute) VALUES (?, ?, ?, ?, 1, 600, 3600, 60)",
                listOf(heldId(i), bytes(16, 1), bytes(32, 1), bytes(100, 1)),
            )
        }
        db.rejects(
            "at most 256 held rows",
            "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, hold_until_minute, relay_expiry_hour, " +
                "consume_minute) VALUES (?, ?, ?, ?, 1, 600, 3600, 60)",
            heldId(256), bytes(16, 1), bytes(32, 1), bytes(100, 1),
        )
        db.rejects("a hold deadline only moves earlier", "UPDATE dm_held SET hold_until_minute = 660 WHERE held_id = ?", heldId(0))
        assertEquals(1, db.changes("UPDATE dm_held SET hold_until_minute = 540 WHERE held_id = ?", heldId(0)))

        for (gen in 1..3) {
            db.exec(
                "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, ?, 2870, 'bundle', ?)",
                listOf(bytes(16, 1), gen, bytes(1216, gen)),
            )
        }
        db.rejects(
            "at most 3 peer X-Wing keys",
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, 4, 2870, 'bundle', ?)",
            bytes(16, 1), bytes(1216, 4),
        )
    }

    @Test
    fun anOfferedRootIsErasedNeverReplaced() = db().use { db ->
        db.contact(1)
        db.exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, offer_env, base_week) VALUES (?, 0, ?, ?, 2870)",
            listOf(bytes(16, 1), bytes(60, 1), bytes(70, 1)),
        )
        val where = "WHERE contact_id = ? AND root_gen = 0"
        db.rejects("never replaced", "UPDATE dm_pair_offer SET root_env = ? $where", bytes(60, 2), bytes(16, 1))
        assertEquals(1, db.changes("UPDATE dm_pair_offer SET acknowledged = 1 $where", bytes(16, 1)))
        db.rejects("acknowledged once", "UPDATE dm_pair_offer SET acknowledged = 0 $where", bytes(16, 1))
        assertEquals(1, db.changes("UPDATE dm_pair_offer SET root_env = NULL $where", bytes(16, 1)))
        db.rejects("never replaced", "UPDATE dm_pair_offer SET root_env = ? $where", bytes(60, 3), bytes(16, 1))
    }

    @Test
    fun aMessageKeepsEverythingButItsStateAndExpiryColumns() = db().use { db ->
        db.contact(1)
        db.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(bytes(16, 1), bytes(16, 1)),
        )
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, " +
                "timer_code, body_env, state, expire_at_minute, delete_at_minute) " +
                "VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'queued', 604800, 604800)",
            listOf(bytes(16, 1), bytes(16, 1), bytes(100, 1)),
        )
        db.rejects("only the state", "UPDATE dm_message SET body_env = ? WHERE message_id = ?", bytes(100, 2), bytes(16, 1))
        db.rejects("only the state", "UPDATE dm_message SET author_minute = 660 WHERE message_id = ?", bytes(16, 1))
        db.rejects(
            "illegal message state transition",
            "UPDATE dm_message SET state = 'read' WHERE message_id = ?",
            bytes(16, 1),
        )
        assertEquals(1, db.changes("UPDATE dm_message SET state = 'sent' WHERE message_id = ?", bytes(16, 1)))
        db.rejects(
            "an expiry time only moves earlier",
            "UPDATE dm_message SET expire_at_minute = 605400, delete_at_minute = 605400 WHERE message_id = ?",
            bytes(16, 1),
        )
        assertEquals(
            1,
            db.changes(
                "UPDATE dm_message SET expire_at_minute = 604200, delete_at_minute = 604200 WHERE message_id = ?",
                bytes(16, 1),
            ),
        )
    }

    /** §13.6: `delete_at_minute` follows its CHECK, so it cannot drift from the two sources. */
    @Test
    fun theDeleteTimeFollowsTheExpiryColumns() = db().use { db ->
        db.contact(1)
        db.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(bytes(16, 1), bytes(16, 1)),
        )
        db.rejects(
            CHECK_FAILED,
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, " +
                "timer_code, body_env, state, expire_at_minute, delete_at_minute) " +
                "VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'queued', 604800, 600)",
            bytes(16, 2), bytes(16, 1), bytes(100, 2),
        )
        // An incoming message counts down from first display: the unread deadline is the source.
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, " +
                "timer_code, body_env, state, unread_deadline_minute, delete_at_minute) " +
                "VALUES (?, ?, 'in', 1, 600, 600, 0, 4, ?, 'unread', 3600, 3600)",
            listOf(bytes(16, 3), bytes(16, 1), bytes(100, 3)),
        )
    }

    @Test
    fun deletingAContactCascadesToEveryDmRowItOwns() = db().use { db ->
        db.contact(1)
        db.generation(1)
        db.session(1, "current", 1)
        db.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(bytes(16, 1), bytes(16, 1)),
        )
        db.exec(
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', 0, 2870, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(60, 1)),
        )
        db.exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, 1, 2870, 'bundle', ?)",
            listOf(bytes(16, 1), bytes(1216, 1)),
        )
        db.exec("DELETE FROM dm_contact WHERE contact_id = ?", listOf(bytes(16, 1)))
        for (table in listOf("olm_session", "dm_conversation", "dm_pair_key", "dm_peer_pq")) {
            assertEquals("$table did not cascade", 0L, db.queryLong("SELECT count(*) FROM $table"))
        }
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
    }

    /** Every v5 table with a guard refuses a REPLACE on every one of its keys (§19.21 point 4). */
    @Test
    fun everyGuardedTableRefusesAReplace() = db().use { db ->
        db.contact(1)
        db.rejects(
            "dm_contact rows are never replaced",
            "INSERT OR REPLACE INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, " +
                "establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            bytes(16, 1), bytes(32, 9), bytes(159, 9),
        )
        db.rejects(
            "dm_contact rows are never replaced",
            "INSERT OR REPLACE INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, " +
                "establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            bytes(16, 9), bytes(32, 1), bytes(159, 9),
        )
        // `dm_seen` has no guard on purpose: INSERT OR IGNORE deletes nothing.
        db.exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, 7)", listOf(bytes(16, 1)))
        assertEquals(0, db.changes("INSERT OR IGNORE INTO dm_seen(tag, until_day) VALUES (?, 14)", bytes(16, 1)))
        assertEquals(7L, db.queryLong("SELECT until_day FROM dm_seen"))
    }

    private fun heldId(i: Int) = ByteArray(16).also {
        it[14] = (i shr 8).toByte()
        it[15] = i.toByte()
    }
}
