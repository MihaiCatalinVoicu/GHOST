package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **R-M1** (Phase 9 design §13.6, §10.6, T25, T33), slice S5: after every message of a
 * conversation has expired, a full dump of the database shows only the contact, its trust and
 * establishment state, the conversation's timer code and version, its wrapped session state, and
 * unlinked `dm_seen` tags — beside the per-device state L7-D7 declares.
 *
 * **What this test proves and what it cannot yet prove (design §22.10 item 1).** The rows are
 * seeded with SQL and the time-keyed deletions of §10.6 are issued as SQL, because the step that
 * will issue them — SWEEP — is slice S9, and the DAOs that create the rows are S6 and S7. What is
 * under test is therefore the **schema's** half of R-M1, which is the half that decides the
 * residue: which rows a message takes with it when it goes (the `ON DELETE CASCADE` closure),
 * which rows it cannot take (the per-contact state that outlives it), and what the survivors are
 * still able to say. Everything that disappears beyond the rows [sweep] names, disappears because
 * the schema made it. A message row that a future DAO forgot to delete is **not** covered here;
 * that is the end-to-end R-M1 of S7/S9, recorded as deferred. Neither is the **physical** half: the
 * dump is logical, read back through `JdbcSqlExecutor`, so a page of a freed `-wal` frame is
 * outside its reach and belongs to the raw-file scan §10.9 point 2 assigns to the T25 EP cases.
 */
class DmForensicResidueTest {

    /** Minute values are Unix seconds on a minute boundary; `NOW` stands for the sweep's `now_e`. */
    private companion object {
        const val NOW = 1_800_000_000L - 1_800_000_000L % 60
        const val AUTHOR = NOW - 7 * 86_400L
        const val DAY = 20_833L
        const val WEEK = 2870L
    }

    private fun world(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    /** The bodies, reactions and payloads that must not survive in any column of any table. */
    private val secrets = listOf(
        bytes(120, 0x41), bytes(120, 0x42), bytes(120, 0x43), bytes(120, 0x44), // message bodies
        bytes(40, 0x52), // a reaction grapheme
        bytes(200, 0x4c), // an L0 envelope on an outbound item
        bytes(4096, 0x62), // the retained blob of an outbound op
        bytes(300, 0x48), // a held L1 envelope
        bytes(400, 0x55), // the wrapped state of a session retired past its day
        bytes(60, 0x50), // a provisional envelope past its erase minute
        bytes(92, 0x47), // the secrets of a generation past its deletion day
        bytes(60, 0x4b), // the opening envelope of a pair week key past its freshness
        bytes(200, 0x63), // an L0 envelope of a request contact that timed out
    )

    /**
     * Not a secret of a message: the payload of a scheduled revocation notice, which §12 writes and
     * no deletion of §10.6 removes. It **survives**, which is why L7-D7 has to name it (§22.10
     * item 1) — and why it is asserted to be there rather than asserted to be gone.
     */
    private val scheduledPayload = bytes(102, 0x4e)

    /**
     * A conversation with everything a live one can hold: four messages (two each way, all with a
     * 7-day timer), a reaction, the outbound item, op and pending send of one of them, a held
     * envelope from a key change, a scheduled control, dedup tags, both session slots with a
     * provisional envelope past its erase minute, the pair keys and offer (one week key already
     * stale), the peer's X-Wing key, two bundle generations with their reuse tuples and a bundle
     * candidate — beside a second contact still in `request` past its deadline, and a third whose
     * `previous` session is due for retirement.
     */
    private fun JdbcSqlExecutor.seedALiveConversation() {
        exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, bundle_week, " +
                "expiry_clock_minute, bundle_published_week) VALUES (1, 0, ?, ?, ?, ?, ?, ?)",
            listOf(bytes(32, 1), bytes(60, 2), bytes(60, 3), WEEK, NOW, WEEK),
        )
        for ((role, index) in listOf("inbox" to 1, "bundle" to 2)) {
            exec(
                "INSERT INTO dm_own_namespace(namespace_id, role, card_index) VALUES (?, ?, 0)",
                listOf(bytes(32, index), role),
            )
        }
        exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, pinned_identity, bundle_week_seen, " +
                "trust_state, source, establishment, verified_fp, name_env, pq_announced_week) " +
                "VALUES (?, ?, ?, 0, ?, ?, 'verified', 'qr_in_person', 'ready', ?, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1), bytes(32, 1), WEEK, bytes(32, 7), bytes(100, 8), WEEK),
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
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, l0_env, deadline_hour, state, ttl_seconds) " +
                "VALUES (?, ?, ?, 1, ?, ?, 'enqueued', 604800)",
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
        // A scheduled revocation notice: per-contact, carrying a payload and a future minute. It is
        // a row a live conversation holds (§12), it is outside every deletion of §10.6, and it
        // survives — which is why §22.10 item 1 has to name it.
        exec(
            "INSERT INTO dm_scheduled(sched_id, contact_id, what, payload, due_minute) " +
                "VALUES (?, ?, 'revocation', ?, ?)",
            listOf(bytes(16, 1), bytes(16, 1), scheduledPayload, NOW + 3600),
        )
        // Two tags: one still inside its window (the residue R-M1 names), one past it.
        exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, ?)", listOf(bytes(16, 1), (DAY + 7) / 7 * 7))
        exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, ?)", listOf(bytes(16, 2), (DAY - 14) / 7 * 7))
        // Session state, pair material and the generations: per-contact state, not per-message. The
        // current session carries a provisional envelope whose erase minute has passed.
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, prov_env, " +
                "prov_erase_minute, prov_anchor_minute, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, ?, ?, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(400, 0x53), secrets[9], NOW - 60, AUTHOR, AUTHOR),
        )
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, retire_day, " +
                "peer_bind_minute) VALUES (?, 'previous', ?, 'responder', 1, ?, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 2), bytes(400, 0x54), DAY + 46, AUTHOR),
        )
        // Two pair week keys: the current one, and one whose week is long past its freshness bound.
        exec(
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', 0, ?, ?, ?)",
            listOf(bytes(16, 1), WEEK, bytes(32, 3), bytes(60, 4)),
        )
        exec(
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', 0, ?, ?, ?)",
            listOf(bytes(16, 1), WEEK - 4, bytes(32, 11), secrets[11]),
        )
        exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, base_week, acknowledged) VALUES (?, 0, ?, ?, 1)",
            listOf(bytes(16, 1), bytes(60, 5), WEEK),
        )
        exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, 1, ?, 'bundle', ?)",
            listOf(bytes(16, 1), WEEK, bytes(1216, 6)),
        )
        // The live generation, and one superseded long enough ago that its deletion day has passed.
        exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, delete_after_day) " +
                "VALUES (1, ?, ?, ?, ?, ?)",
            listOf(WEEK, bytes(32, 1), secrets[10], DAY - 92, DAY - 1),
        )
        exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (2, ?, ?, ?)",
            listOf(WEEK, bytes(32, 2), bytes(92, 1)),
        )
        exec("INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (1, ?)", listOf(bytes(32, 1)))
        exec("INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (2, ?)", listOf(bytes(32, 2)))
        exec(
            "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) VALUES (?, ?, ?, 0)",
            listOf(bytes(16, 1), bytes(1421, 7), WEEK),
        )
        seedARequestPastItsDeadline()
        seedAContactWithARetiredSession()
    }

    /**
     * §10.6: "requests past `request_until_day`" — and the note beside it, "a request cascades its
     * contact, session, pair keys and rows". The contact is given one of everything a contact can
     * own, so the widest cascade R-M1 depends on is walked rather than assumed.
     */
    private fun JdbcSqlExecutor.seedARequestPastItsDeadline() {
        exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, " +
                "establishment, request_until_day) VALUES (?, ?, ?, 0, 'request', 'request', 'card_only', ?)",
            listOf(bytes(16, 2), bytes(32, 2), bytes(159, 2), DAY - 1),
        )
        exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(bytes(16, 2), bytes(16, 2)),
        )
        exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
                "minute_index, timer_code, body_env, state) VALUES (?, ?, 'in', 1, ?, ?, 0, 0, ?, 'unread')",
            listOf(bytes(16, 9), bytes(16, 2), AUTHOR, AUTHOR, bytes(100, 0x21)),
        )
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, ?)",
            listOf(bytes(16, 2), bytes(32, 3), bytes(400, 0x56), AUTHOR),
        )
        exec(
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'out', 0, ?, ?, ?)",
            listOf(bytes(16, 2), WEEK, bytes(32, 12), bytes(60, 12)),
        )
        exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, base_week) VALUES (?, 0, ?, ?)",
            listOf(bytes(16, 2), bytes(60, 13), WEEK),
        )
        exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) VALUES (?, 2, ?, 'bundle', ?)",
            listOf(bytes(16, 2), WEEK, bytes(1216, 14)),
        )
        exec(
            "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, hold_until_minute, relay_expiry_hour, " +
                "consume_minute) VALUES (?, ?, ?, ?, 2, ?, ?, ?)",
            listOf(bytes(16, 2), bytes(16, 2), bytes(32, 15), bytes(300, 0x49), NOW + 86_400, NOW - NOW % 3600, AUTHOR),
        )
        exec(
            "INSERT INTO dm_scheduled(sched_id, contact_id, what, due_minute) VALUES (?, ?, 'reconnect', ?)",
            listOf(bytes(16, 2), bytes(16, 2), NOW + 3600),
        )
        exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, kind, control, l0_env, deadline_hour, state, ttl_seconds) " +
                "VALUES (?, ?, 4, 'reconnect', ?, ?, 'enqueued', 86400)",
            listOf(bytes(16, 2), bytes(16, 2), secrets[12], NOW - NOW % 3600),
        )
        exec(
            "INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, ?)",
            listOf(bytes(16, 2), bytes(16, 2), NOW - NOW % 3600),
        )
        exec(
            "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) VALUES (?, ?, ?, 1)",
            listOf(bytes(16, 2), bytes(1421, 16), WEEK),
        )
    }

    /** §10.6: "retired `previous` sessions at `retire_day`", which contact 1's is not yet due for. */
    private fun JdbcSqlExecutor.seedAContactWithARetiredSession() {
        exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'verified', 'link', 'ready')",
            listOf(bytes(16, 3), bytes(32, 3), bytes(159, 3)),
        )
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, ?)",
            listOf(bytes(16, 3), bytes(32, 4), bytes(400, 0x57), AUTHOR),
        )
        exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, retire_day, " +
                "peer_bind_minute) VALUES (?, 'previous', ?, 'responder', 1, ?, ?, ?)",
            listOf(bytes(16, 3), bytes(32, 5), secrets[8], DAY - 1, AUTHOR),
        )
    }

    /**
     * The time-keyed deletions of §10.6, issued here because SWEEP is slice S9. They are the eight
     * the section lists that a schema-level test can issue; nothing else is deleted, and every
     * other row that disappears is a cascade of the schema. (§10.6's ninth item, surplus
     * `dm_peer_pq` rows, is bounded by a count and by the `dm_peer_pq_limit` trigger, not by a
     * time, so it is not a sweep this test can issue.)
     */
    private fun JdbcSqlExecutor.sweep(): Map<String, Int> {
        val held = execUpdate("DELETE FROM dm_held WHERE hold_until_minute <= ?", listOf(NOW))
        // The generations go after the held rows: §10.6 refuses to delete a generation a live held
        // row references, and `dm_held.gen_id` is a CHECK and not a foreign key, so nothing but
        // that ordering rule protects it. [aGenerationIsNotHeldByAForeignKey] pins the fact.
        return linkedMapOf(
            "expired messages" to execUpdate("DELETE FROM dm_message WHERE delete_at_minute <= ?", listOf(NOW)),
            "held rows past their hold minute" to held,
            "seen tags past their week" to execUpdate("DELETE FROM dm_seen WHERE until_day <= ?", listOf(DAY)),
            "requests past their day" to execUpdate(
                "DELETE FROM dm_contact WHERE trust_state = 'request' AND request_until_day <= ?", listOf(DAY),
            ),
            "pair week keys past their freshness" to execUpdate("DELETE FROM dm_pair_key WHERE week < ?", listOf(WEEK)),
            "retired previous sessions" to execUpdate(
                "DELETE FROM olm_session WHERE retire_day IS NOT NULL AND retire_day <= ?", listOf(DAY),
            ),
            "provisional envelopes past their erase minute" to execUpdate(
                "UPDATE olm_session SET prov_env = NULL, prov_erase_minute = NULL WHERE prov_erase_minute <= ?",
                listOf(NOW),
            ),
            "generations past their deletion day" to execUpdate(
                "DELETE FROM olm_prekey_gen WHERE delete_after_day IS NOT NULL AND delete_after_day <= ?", listOf(DAY),
            ),
        )
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
            val columns = columnsOf(table)
            query("SELECT ${columns.joinToString()} FROM $table") { row ->
                columns.forEachIndexed { index, column -> if (!row.isNull(index)) out += "$table.$column" }
            }
        }
        return out
    }

    private fun JdbcSqlExecutor.columnsOf(table: String): List<String> {
        val out = ArrayList<String>()
        query("PRAGMA table_info($table)") { out += it.string(1) }
        return out
    }

    /** Every BLOB value stored anywhere, so a residue can be searched for byte by byte. */
    private fun JdbcSqlExecutor.allBlobs(): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        for (table in rowCounts().keys) {
            val columns = columnsOf(table)
            // `getBytes` renders a TEXT or INTEGER value as its bytes rather than failing, which
            // only widens the search: no seeded secret is a number or a state name.
            query("SELECT ${columns.joinToString()} FROM $table") { row ->
                columns.indices.forEach { index -> if (!row.isNull(index)) out += row.blob(index) }
            }
        }
        return out
    }

    /** True when [needle] appears anywhere inside [this], not only as the whole value. */
    private fun ByteArray.containsSequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        outer@ for (start in 0..size - needle.size) {
            for (i in needle.indices) if (this[start + i] != needle[i]) continue@outer
            return true
        }
        return false
    }

    private fun List<ByteArray>.holds(needle: ByteArray) = any { it.containsSequence(needle) }

    /**
     * The tables that still hold a row once the sweep has run, each with the sentence that permits
     * it. The set is asserted in **both** directions against the dump, so a row kind that starts
     * surviving — a table a later slice adds, or one this world did not know it was keeping — fails
     * here until someone writes down what it is allowed to say.
     */
    private val survivingTables: Map<String, String> = mapOf(
        "dm_contact" to "R-M1: the contact, its trust and establishment state",
        "dm_conversation" to "R-M1: the conversation's timer code and version",
        "olm_session" to "R-M1: the wrapped session state; L7-D7: <= 2 sessions per contact",
        "dm_seen" to "R-M1: unlinked dm_seen tags (<= ~2 to ~7 weeks by bucket)",
        "dm_self" to "L7-D7: the device's own identity row, its clock and its bundle week",
        "dm_own_namespace" to "L7-D7: the device's own inbox and bundle namespaces",
        "dm_pair_key" to "L7-D7: pair week keys, <= FRESH after their week",
        "dm_pair_offer" to "L7-D7: reply_seeds until their erasure bound (§22.8.5)",
        "dm_peer_pq" to "L7-D7: peers' X-Wing public keys",
        "olm_prekey_gen" to "L7-D7: <= 14 bundle generations, <= 13 weeks after supersession",
        "olm_prekey_used" to "L7-D7: the reuse tuples of those generations (§7.6)",
        // Two that S5 found beside L7-D7's list; §22.10 item 1 records them and L7-D7 now names them.
        "dm_bundle_candidate" to "L7-D7 (added in S5): one cached peer bundle envelope per contact",
        "dm_scheduled" to "L7-D7 (added in S5): a pending reconnect or revocation notice and its due minute",
        // Not DM state at all: the v1 row that records which schema version created the database.
        "schema_meta" to "the schema's own version row (migration 1), which says nothing about a conversation",
    )

    @Test
    fun afterEveryMessageExpiredTheDumpHoldsOnlyWhatRM1Allows() = world().use { db ->
        db.seedALiveConversation()
        val before = db.rowCounts()
        assertEquals("the world holds five messages", 5L, before["dm_message"])
        assertEquals(1L, before["dm_reaction"])
        assertEquals(2L, before["dm_outbound_item"])
        assertEquals(1L, before["dm_outbound_op"])
        assertEquals(2L, before["dm_pending_send"])
        assertEquals(2L, before["dm_held"])
        assertEquals(2L, before["dm_seen"])
        assertEquals(2L, before["dm_scheduled"])
        assertEquals(5L, before["olm_session"])
        assertEquals(3L, before["dm_contact"])

        // Eight deletions, and everything else that goes, goes as a cascade of the schema.
        assertEquals(
            mapOf(
                "expired messages" to 4,
                "held rows past their hold minute" to 1,
                "seen tags past their week" to 1,
                "requests past their day" to 1,
                "pair week keys past their freshness" to 1,
                "retired previous sessions" to 1,
                "provisional envelopes past their erase minute" to 1,
                "generations past their deletion day" to 1,
            ),
            db.sweep(),
        )

        val after = db.rowCounts()
        val emptied = listOf("dm_message", "dm_reaction", "dm_outbound_item", "dm_outbound_op", "dm_pending_send", "dm_held")
        for (table in emptied) assertEquals("$table still holds rows", 0L, after[table])
        // What R-M1 says is left, and nothing beside it, among the tables that hold conversation state.
        assertEquals("the request contact and its rows went with it", 2L, after["dm_contact"])
        assertEquals(1L, after["dm_conversation"])
        assertEquals("the retired session went; the two current ones and one previous stay", 3L, after["olm_session"])
        assertEquals("only the tag still inside its window survives", 1L, after["dm_seen"])
        assertEquals(bytes(16, 1).toList(), db.queryBlob("SELECT tag FROM dm_seen")!!.toList())
        assertEquals("the superseded generation went with its reuse tuple", 1L, after["olm_prekey_gen"])
        assertEquals(1L, after["olm_prekey_used"])
        assertEquals("the stale pair week key went", 1L, after["dm_pair_key"])
        assertEquals("the request contact's scheduled reconnect went with it", 1L, after["dm_scheduled"])
        // The rest of the request contact's cascade, which no other test of migration 5 walks.
        assertEquals(1L, after["dm_pair_offer"])
        assertEquals(1L, after["dm_peer_pq"])
        assertEquals(1L, after["dm_bundle_candidate"])
        // Every table that is empty stays empty, and no table grew.
        for ((table, count) in after) {
            assertTrue("$table grew during the sweep", count <= (before[table] ?: 0L))
        }
    }

    /**
     * Which tables still hold anything at all, against the declaration that permits each. R-M1's
     * own words are "a **full** dump", so the corpus is every table of the database and not a slice
     * of four: `dm_bundle_candidate` and `dm_scheduled` survive every deletion of §10.6 and were
     * named by no declaration before S5, which is exactly what an assertion over four tables could
     * not have said.
     */
    @Test
    fun everyTableThatSurvivesTheSweepIsOneADeclarationNames() = world().use { db ->
        db.seedALiveConversation()
        db.sweep()
        val survivors = db.rowCounts().filterValues { it > 0L }.keys
        assertEquals(
            "a table survives the sweep that no R-M1 or L7-D7 sentence covers",
            survivingTables.keys.sorted(),
            survivors.sorted(),
        )
    }

    /**
     * The residue cannot say what was said, nor to which message a tag belongs. Every byte string
     * a message carried — its body, its reaction, its L0 envelope, its retained blob, the held L1,
     * the retired session state, the erased provisional envelope, the deleted generation's secrets
     * and the stale pair key — is searched for **inside** every BLOB column of every table, not
     * only compared to it: a residue that embedded a body in a larger envelope would pass a
     * whole-value comparison.
     *
     * The one payload that does survive is the scheduled revocation notice's, and it is asserted
     * to survive rather than left unmentioned: no deletion of §10.6 removes a `dm_scheduled` row,
     * so the bytes are declared residue (L7-D7, §22.10 item 1) and not an escape.
     */
    @Test
    fun noByteOfAnyMessageSurvivesTheSweep() = world().use { db ->
        db.seedALiveConversation()
        val live = db.allBlobs()
        for (secret in secrets) assertTrue("the world did not store one of the secrets", live.holds(secret))
        // The containment search is not vacuous: a secret wrapped inside a larger value is found.
        val wrapped = ByteArray(7) + secrets[0] + ByteArray(7)
        assertTrue(listOf(wrapped).holds(secrets[0]))
        db.sweep()
        val residue = db.allBlobs()
        val survivors = secrets.filter { residue.holds(it) }.map { "${it.size} bytes of 0x%02x".format(it[0]) }
        assertEquals(emptyList<String>(), survivors)
        assertTrue(
            "the scheduled notice's payload is declared residue and must still be there",
            residue.holds(scheduledPayload),
        )
    }

    /**
     * §10.8 and §21.10 point 4: a `dm_seen` tag is **unlinked** — the table has no column naming a
     * conversation, a contact or a message, so the residue is a keyed 16-byte tag and a week. (A
     * seizer who already knows a candidate `message_id` can recompute the tag and confirm receipt;
     * that is the declared leak of §22.9 point 4 and mutant ME-6, whose dictionary test is S11's.)
     */
    @Test
    fun aSeenTagCarriesNothingButItsTagAndItsWeek() = world().use { db ->
        assertEquals(listOf("tag", "until_day"), db.columnsOf("dm_seen"))
    }

    /**
     * §10.6: "bundle generations past `delete_after_day` (with their reuse tuples; **not while a
     * live held row references them**)". That last rule is code, not schema — `dm_held.gen_id`
     * carries a range CHECK and no `REFERENCES` — so the ordering inside [sweep] is all that keeps
     * a held envelope's generation alive, and S9's SWEEP must keep it. The fact is pinned here so
     * a migration that added the foreign key, or removed the need for the rule, is noticed.
     */
    @Test
    fun aGenerationIsNotHeldByAForeignKey() = world().use { db ->
        val held = db.queryString("SELECT sql FROM sqlite_master WHERE name = 'dm_held'")!!.replace(Regex("\\s+"), " ")
        assertTrue("dm_held.gen_id must still be range-checked", held.contains("gen_id BETWEEN 0 AND 4294967295"))
        assertTrue(
            "dm_held.gen_id has become a foreign key; §10.6's ordering rule can be dropped",
            !Regex("gen_id[^,]*REFERENCES").containsMatchIn(held),
        )
    }

    /**
     * What the survivors are still able to say, column by column, over the **whole** dump: the
     * contacts' identities, cards, trust and establishment state, the conversation's timer code and
     * version, the session slots' wrapped state with the schedule L7-D7 declares, the device's own
     * row, the pair material, the peers' X-Wing keys, the live generation and its reuse tuple, the
     * cached bundle candidate, the scheduled notice and the tag. Any other non-NULL column
     * anywhere is residue no declaration allows, and fails here.
     */
    @Test
    fun theSurvivingColumnsAreExactlyTheOnesRM1AndL7D7Name() = world().use { db ->
        db.seedALiveConversation()
        db.sweep()
        assertEquals(
            setOf(
                // The device's own row and namespaces.
                "dm_self.id", "dm_self.card_index", "dm_self.seen_key", "dm_self.content_key_wrapped",
                "dm_self.state_key_wrapped", "dm_self.bundle_week", "dm_self.expiry_clock_minute",
                "dm_self.bundle_published_week",
                "dm_own_namespace.namespace_id", "dm_own_namespace.role", "dm_own_namespace.card_index",
                // The contacts: who they are, how they were met, whether they are trusted and reachable.
                "dm_contact.contact_id", "dm_contact.identity_pk", "dm_contact.card_env", "dm_contact.card_index",
                "dm_contact.pinned_identity", "dm_contact.bundle_week_seen", "dm_contact.trust_state",
                "dm_contact.source", "dm_contact.establishment", "dm_contact.fetch_attempts",
                "dm_contact.reset_needed", "dm_contact.verified_fp", "dm_contact.name_env",
                "dm_contact.pq_announced_week",
                // The conversation: a bucket code and a version, and no time at all.
                "dm_conversation.conversation_id", "dm_conversation.contact_id",
                "dm_conversation.timer_code", "dm_conversation.timer_version",
                // The sessions: opaque state under the state key, plus the retirement schedule and
                // the two anchors §22.8.4 and §22.8.5 declare. `prov_env` and `prov_erase_minute`
                // are gone: the sweep erased them.
                "olm_session.contact_id", "olm_session.slot", "olm_session.session_id", "olm_session.role",
                "olm_session.acknowledged", "olm_session.state_env", "olm_session.retire_day",
                "olm_session.peer_bind_minute", "olm_session.prov_anchor_minute", "olm_session.pair_sent",
                // The pair material and the peer's X-Wing key.
                "dm_pair_key.contact_id", "dm_pair_key.direction", "dm_pair_key.root_gen", "dm_pair_key.week",
                "dm_pair_key.recog_key", "dm_pair_key.open_env",
                "dm_pair_offer.contact_id", "dm_pair_offer.root_gen", "dm_pair_offer.root_env",
                "dm_pair_offer.base_week", "dm_pair_offer.acknowledged",
                "dm_peer_pq.contact_id", "dm_peer_pq.gen_id", "dm_peer_pq.bundle_week", "dm_peer_pq.source",
                "dm_peer_pq.xwing_pk",
                // The live generation and its reuse tuple.
                "olm_prekey_gen.gen_id", "olm_prekey_gen.bundle_week", "olm_prekey_gen.fallback_pub",
                "olm_prekey_gen.secrets_env",
                "olm_prekey_used.gen_id", "olm_prekey_used.session_id",
                // The cached bundle candidate and the scheduled notice, which L7-D7 did not name
                // before S5 (§22.10 item 1). `attempts` is Q27/S3b's reschedule bound (§21.8 point 4):
                // the counter's start, 0, survives like every other declared non-NULL column.
                "dm_bundle_candidate.contact_id", "dm_bundle_candidate.bundle_env",
                "dm_bundle_candidate.bundle_week", "dm_bundle_candidate.bundle_rank",
                "dm_scheduled.sched_id", "dm_scheduled.contact_id", "dm_scheduled.what",
                "dm_scheduled.payload", "dm_scheduled.due_minute", "dm_scheduled.attempts",
                // The tag.
                "dm_seen.tag", "dm_seen.until_day",
                // The schema's own version row, which no conversation writes.
                "schema_meta.key", "schema_meta.value",
            ),
            db.nonNullColumns(),
        )
        // The conversation row holds no time column at all: there is nowhere for a last-activity
        // minute to live (mutant PM-10, T33).
        assertEquals(
            emptyList<String>(),
            db.columnsOf("dm_conversation").filter { Regex("(minute|hour|day|_at$)").containsMatchIn(it) },
        )
    }

    /**
     * The column list above is a claim about the schema and not only about what this world wrote:
     * every column of every surviving table is either one the dump may show, or one the sweep must
     * have cleared. A column added to a surviving table later belongs to neither list and fails
     * here, which is the gap an assertion driven by "whatever the seed happened to set" leaves.
     */
    @Test
    fun everyColumnOfEverySurvivingTableIsEitherAllowedOrCleared() = world().use { db ->
        db.seedALiveConversation()
        db.sweep()
        val allowed = db.nonNullColumns()
        // The columns the sweep must have cleared, or that this world never writes, with the reason.
        val cleared = mapOf(
            "dm_self.accept_after_minute" to "the accept-after minute of a reset, unset here",
            "dm_contact.pending_identity" to "only a `changed` contact carries one (§8.3)",
            "dm_contact.fetch_listen_until_minute" to "only an establishment in `fetching` carries one",
            "dm_contact.request_until_day" to "only a `request` contact carries one, and it was swept",
            "olm_session.prov_env" to "erased past prov_erase_minute by the sweep (§22.8.5)",
            "olm_session.prov_erase_minute" to "erased with the envelope it dates",
            "olm_session.peer_gen_id" to "only an initiator session carries one",
            "olm_session.unack_since_day" to "only an unacknowledged initiator session carries one",
            "dm_pair_offer.offer_env" to "erased once the offer was acknowledged (§9.4)",
            "olm_prekey_gen.superseded_day" to "the surviving generation is the live one",
            "olm_prekey_gen.delete_after_day" to "derived from the supersession day, so also unset",
        )
        val everyColumn = survivingTables.keys.flatMap { table -> db.columnsOf(table).map { "$table.$it" } }.toSet()
        assertEquals(
            "a column of a surviving table is neither allowed residue nor asserted cleared",
            emptySet<String>(),
            everyColumn - allowed - cleared.keys,
        )
        assertEquals(
            "a column declared cleared no longer exists, or is not of a surviving table",
            emptySet<String>(),
            cleared.keys - everyColumn,
        )
        assertEquals("a column declared cleared is in fact non-NULL", emptySet<String>(), cleared.keys intersect allowed)
    }
}
