package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **R-M1** (Phase 9 design §13.6, §10.6, T25, T33), slice S5: after every message of a
 * conversation has expired, a full dump of the database shows only the contact, its trust and
 * establishment state, the conversation's timer code and version, its wrapped session state, and
 * unlinked `dm_seen` tags.
 *
 * **What this test proves and what it cannot yet prove (design §22.10 item 1).** The rows are
 * seeded with SQL and the three deletions of §10.6 are issued as SQL, because the step that will
 * issue them — SWEEP — is slice S9, and the DAOs that create the rows are S6 and S7. What is
 * under test is therefore the **schema's** half of R-M1, which is the half that decides the
 * residue: which rows a message takes with it when it goes (the `ON DELETE CASCADE` closure),
 * which rows it cannot take (the per-contact state that outlives it), and what the survivors are
 * still able to say. The test issues exactly three deletes — expired messages, expired held rows,
 * expired seen tags — and everything else that disappears, disappears because the schema made it.
 * A message row that a future DAO forgot to delete is **not** covered here; that is the end-to-end
 * R-M1 of S7/S9, recorded as deferred.
 */
class DmForensicResidueTest {

    /** Minute values are Unix seconds on a minute boundary; `NOW` stands for the sweep's `now_e`. */
    private companion object {
        const val NOW = 1_800_000_000L - 1_800_000_000L % 60
        const val AUTHOR = NOW - 7 * 86_400L
        const val DAY = 20_833L
    }

    private fun world(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    /** The bodies, reactions and payloads that must not survive in any column of any table. */
    private val secrets = listOf(
        bytes(120, 0x41), bytes(120, 0x42), bytes(120, 0x43), bytes(120, 0x44), // message bodies
        bytes(40, 0x52), // a reaction grapheme
        bytes(200, 0x4c), // an L0 envelope on an outbound item
        bytes(4096, 0x42), // the retained blob of an outbound op
        bytes(300, 0x48), // a held L1 envelope
    )

    /**
     * A conversation with everything a live one can hold: four messages (two each way, all with a
     * 7-day timer), a reaction, the outbound item, op and pending send of one of them, a held
     * envelope from a key change, dedup tags, both session slots, the pair keys and offer, the
     * peer's X-Wing key, a bundle generation with a reuse tuple and a bundle candidate.
     */
    private fun JdbcSqlExecutor.seedALiveConversation() {
        exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, bundle_week, " +
                "expiry_clock_minute, bundle_published_week) VALUES (1, 0, ?, ?, ?, 2870, ?, 2870)",
            listOf(bytes(32, 1), bytes(60, 2), bytes(60, 3), NOW),
        )
        for ((role, index) in listOf("inbox" to 1, "bundle" to 2)) {
            exec(
                "INSERT INTO dm_own_namespace(namespace_id, role, card_index) VALUES (?, ?, 0)",
                listOf(bytes(32, index), role),
            )
        }
        exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, pinned_identity, bundle_week_seen, " +
                "trust_state, source, establishment, verified_fp, name_env) " +
                "VALUES (?, ?, ?, 0, ?, 2870, 'verified', 'qr_in_person', 'ready', ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1), bytes(32, 1), bytes(32, 7), bytes(100, 8)),
        )
        exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id, timer_code, timer_version) VALUES (?, ?, 4, 3)",
            listOf(bytes(16, 1), bytes(16, 1)),
        )
        // Two outgoing and two incoming messages, every one of them past its deletion minute.
        for ((i, direction) in listOf(1 to "out", 2 to "out", 3 to "in", 4 to "in")) {
            val expire = if (direction == "out") NOW - 60 else null
            val unread = if (direction == "in") NOW - 60 else null
            exec(
                "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                    "minute_index, timer_code, body_env, state, expire_at_minute, unread_deadline_minute, delete_at_minute) " +
                    "VALUES (?, ?, ?, 1, ?, ?, ?, 4, ?, ?, ?, ?, ?)",
                listOf(
                    bytes(16, i), bytes(16, 1), direction, AUTHOR, AUTHOR, i,
                    secrets[i - 1], if (direction == "out") "sent" else "unread",
                    expire, unread, NOW - 60,
                ),
            )
        }
        exec(
            "INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)",
            listOf(bytes(16, 3), secrets[4]),
        )
        exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, l0_env, deadline_hour, state) " +
                "VALUES (?, ?, ?, 1, ?, ?, 'enqueued')",
            listOf(bytes(16, 1), bytes(16, 1), bytes(16, 1), secrets[5], NOW - NOW % 3600),
        )
        exec(
            "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, blob, deadline_hour) VALUES (?, 'item', ?, ?, ?)",
            listOf(bytes(16, 1), bytes(16, 1), secrets[6], NOW - NOW % 3600),
        )
        exec(
            "INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, ?)",
            listOf(bytes(16, 1), bytes(16, 1), NOW - NOW % 3600),
        )
        exec(
            "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, hold_until_minute, relay_expiry_hour, " +
                "consume_minute) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            listOf(bytes(16, 1), bytes(16, 1), bytes(32, 9), secrets[7], NOW - 120, NOW - NOW % 3600, AUTHOR),
        )
        // Two tags: one still inside its window (the residue R-M1 names), one past it.
        exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, ?)", listOf(bytes(16, 1), (DAY + 7) / 7 * 7))
        exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, ?)", listOf(bytes(16, 2), (DAY - 14) / 7 * 7))
        // Session state, pair material and the generation: per-contact state, not per-message.
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(400, 0x53), AUTHOR),
        )
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, retire_day, " +
                "peer_bind_minute) VALUES (?, 'previous', ?, 'responder', 1, ?, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 2), bytes(400, 0x54), DAY + 46, AUTHOR),
        )
        exec(
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', 0, 2870, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 3), bytes(60, 4)),
        )
        exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, base_week, acknowledged) VALUES (?, 0, ?, 2870, 1)",
            listOf(bytes(16, 1), bytes(60, 5)),
        )
        exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, 1, 2870, 'bundle', ?)",
            listOf(bytes(16, 1), bytes(1216, 6)),
        )
        exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (1, 2870, ?, ?)",
            listOf(bytes(32, 1), bytes(92, 1)),
        )
        exec("INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (1, ?)", listOf(bytes(32, 1)))
        exec(
            "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) VALUES (?, ?, 2870, 0)",
            listOf(bytes(16, 1), bytes(1421, 7)),
        )
    }

    /**
     * The three deletions §10.6 lists that are keyed on a time, issued here because SWEEP is S9.
     * Nothing else is deleted: every other row that disappears is a cascade of the schema.
     */
    private fun JdbcSqlExecutor.sweep(): Int {
        var deleted = 0
        deleted += execUpdate("DELETE FROM dm_message WHERE delete_at_minute <= ?", listOf(NOW))
        deleted += execUpdate("DELETE FROM dm_held WHERE hold_until_minute <= ?", listOf(NOW))
        deleted += execUpdate("DELETE FROM dm_seen WHERE until_day <= ?", listOf(DAY))
        return deleted
    }

    /** Every table of the database with the number of rows it holds; empty tables included. */
    private fun JdbcSqlExecutor.rowCounts(): Map<String, Long> {
        val names = ArrayList<String>()
        query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name") {
            names += it.string(0)
        }
        return names.associateWith { queryLong("SELECT count(*) FROM $it") ?: 0L }
    }

    /** Every non-NULL column of every row of every table, as `table.column` names. */
    private fun JdbcSqlExecutor.nonNullColumns(): Set<String> {
        val out = HashSet<String>()
        for (table in rowCounts().keys) {
            val columns = ArrayList<String>()
            query("PRAGMA table_info($table)") { columns += it.string(1) }
            query("SELECT ${columns.joinToString()} FROM $table") { row ->
                columns.forEachIndexed { index, column -> if (!row.isNull(index)) out += "$table.$column" }
            }
        }
        return out
    }

    /** Every BLOB value stored anywhere, so a residue can be searched for byte by byte. */
    private fun JdbcSqlExecutor.allBlobs(): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        for (table in rowCounts().keys) {
            val columns = ArrayList<String>()
            query("PRAGMA table_info($table)") { columns += it.string(1) }
            // `getBytes` renders a TEXT or INTEGER value as its bytes rather than failing, which
            // only widens the search: no seeded secret is a number or a state name.
            query("SELECT ${columns.joinToString()} FROM $table") { row ->
                columns.indices.forEach { index -> if (!row.isNull(index)) out += row.blob(index) }
            }
        }
        return out
    }

    @Test
    fun afterEveryMessageExpiredTheDumpHoldsOnlyWhatRM1Allows() = world().use { db ->
        db.seedALiveConversation()
        val before = db.rowCounts()
        assertEquals("the world holds four messages", 4L, before["dm_message"])
        assertEquals(1L, before["dm_reaction"])
        assertEquals(1L, before["dm_outbound_item"])
        assertEquals(1L, before["dm_outbound_op"])
        assertEquals(1L, before["dm_pending_send"])
        assertEquals(1L, before["dm_held"])
        assertEquals(2L, before["dm_seen"])

        // Three deletes, six tables emptied: the reaction, the item, the op and the pending send go
        // as cascades of the message row, which is R-M1's mechanism and not the test's doing.
        assertEquals(4 + 1 + 1, db.sweep())

        val after = db.rowCounts()
        val emptied = listOf("dm_message", "dm_reaction", "dm_outbound_item", "dm_outbound_op", "dm_pending_send", "dm_held")
        for (table in emptied) assertEquals("$table still holds rows", 0L, after[table])
        // What R-M1 says is left, and nothing beside it, among the tables that hold conversation state.
        assertEquals(1L, after["dm_contact"])
        assertEquals(1L, after["dm_conversation"])
        assertEquals(2L, after["olm_session"])
        assertEquals("only the tag still inside its window survives", 1L, after["dm_seen"])
        assertEquals(bytes(16, 1).toList(), db.queryBlob("SELECT tag FROM dm_seen")!!.toList())
        // Every table that is empty stays empty, and no table grew.
        for ((table, count) in after) {
            assertTrue("$table grew during the sweep", count <= (before[table] ?: 0L))
        }
    }

    /**
     * The residue cannot say what was said, nor to which message a tag belongs. Every byte string
     * a message carried — its body, its reaction, its L0 envelope, its retained blob, the held L1 —
     * is searched for across every BLOB column of every table.
     */
    @Test
    fun noByteOfAnyMessageSurvivesTheSweep() = world().use { db ->
        db.seedALiveConversation()
        val live = db.allBlobs().map { it.toList() }.toSet()
        for (secret in secrets) assertTrue("the world did not store one of the secrets", secret.toList() in live)
        db.sweep()
        val residue = db.allBlobs().map { it.toList() }.toSet()
        val survivors = secrets.filter { it.toList() in residue }.map { "${it.size} bytes of 0x%02x".format(it[0]) }
        assertEquals(emptyList<String>(), survivors)
    }

    /**
     * §10.8 and §21.10 point 4: a `dm_seen` tag is **unlinked** — the table has no column naming a
     * conversation, a contact or a message, so the residue is a keyed 16-byte tag and a week. (A
     * seizer who already knows a candidate `message_id` can recompute the tag and confirm receipt;
     * that is the declared leak of §22.9 point 4 and mutant ME-6, whose dictionary test is S11's.)
     */
    @Test
    fun aSeenTagCarriesNothingButItsTagAndItsWeek() = world().use { db ->
        val columns = ArrayList<String>()
        db.query("PRAGMA table_info(dm_seen)") { columns += it.string(1) }
        assertEquals(listOf("tag", "until_day"), columns)
    }

    /**
     * What the survivors are still able to say, column by column: the contact's identity, card,
     * trust and establishment state, the conversation's timer code and version, the session slots'
     * wrapped state with the schedule L7-D7 declares, and the tag. Any other non-NULL column of
     * these four tables is residue R-M1 does not allow, and fails here.
     */
    @Test
    fun theSurvivingColumnsAreExactlyTheOnesRM1Names() = world().use { db ->
        db.seedALiveConversation()
        db.sweep()
        val dmTables = setOf("dm_contact", "dm_conversation", "olm_session", "dm_seen")
        val found = db.nonNullColumns().filter { it.substringBefore(".") in dmTables }.toSet()
        assertEquals(
            setOf(
                // The contact: who it is, how it was met, whether it is trusted, whether it can be reached.
                "dm_contact.contact_id", "dm_contact.identity_pk", "dm_contact.card_env", "dm_contact.card_index",
                "dm_contact.pinned_identity", "dm_contact.bundle_week_seen", "dm_contact.trust_state",
                "dm_contact.source", "dm_contact.establishment", "dm_contact.fetch_attempts",
                "dm_contact.reset_needed", "dm_contact.verified_fp", "dm_contact.name_env",
                // The conversation: a bucket code and a version, and no time at all.
                "dm_conversation.conversation_id", "dm_conversation.contact_id",
                "dm_conversation.timer_code", "dm_conversation.timer_version",
                // The sessions: opaque state under the state key, plus the retirement schedule.
                "olm_session.contact_id", "olm_session.slot", "olm_session.session_id", "olm_session.role",
                "olm_session.acknowledged", "olm_session.state_env", "olm_session.retire_day",
                "olm_session.peer_bind_minute", "olm_session.pair_sent",
                // The tag.
                "dm_seen.tag", "dm_seen.until_day",
            ),
            found,
        )
        // The conversation row holds no time column at all: there is nowhere for a last-activity
        // minute to live (mutant PM-10, T33).
        val conversation = ArrayList<String>()
        db.query("PRAGMA table_info(dm_conversation)") { conversation += it.string(1) }
        assertEquals(emptyList<String>(), conversation.filter { Regex("(minute|hour|day|_at$)").containsMatchIn(it) })
    }
}
