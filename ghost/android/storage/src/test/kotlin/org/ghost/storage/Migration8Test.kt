package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration 8 (Phase 11 design §13.6 "Schema migration M"; slice S3) on a **populated v7 database**, SCN-MF's storage
 * half: the two v1 media tables go behind their guard, the five DM tables that admit a media message are rebuilt with
 * every row, index and trigger they had, the five media tables arrive empty, and not a row of any other table moves;
 * an interruption at any statement leaves v7 as it was; an older app and a half-migrated database are refused.
 *
 * What each new object enforces by itself is tested where its family is: the shapes and the declared time columns in
 * [MediaSchemaIntrospectionTest], the CHECKs in [MediaSchemaConstraintsTest], the triggers in [MediaTriggersTest], the
 * REPLACE guards in [MediaReplaceGuardsTest] and [ReplaceGuardsTest], the version lists in [SchemaAndMigrationTest].
 * This class is about the **upgrade** (CS-M9, the G-9 test of F9 §21.13 point 9): which rows exist before and after,
 * what the rebuild changes in the schema text and what it must not, and what a crash in the middle leaves behind.
 */
class Migration8Test {
    private val upToV7 = Schema.migrations.filter { it.version <= 7 }
    private val v8 = Schema.migrations.single { it.version == 8 }

    /** Fails the [failAt]-th `exec` call (0-based); everything else is delegated. */
    private class FailAtExec(private val delegate: SqlExecutor, private val failAt: Int) : SqlExecutor by delegate {
        var calls = 0
        override fun exec(sql: String, args: List<Any?>) {
            if (calls++ == failAt) throw IllegalStateException("injected failure at statement $failAt")
            delegate.exec(sql, args)
        }
    }

    /** Fails when `user_version` is set to [version], the last step of a migration transaction. */
    private class FailOnVersionBump(private val delegate: SqlExecutor, private val version: Int) : SqlExecutor by delegate {
        override var userVersion: Int
            get() = delegate.userVersion
            set(value) {
                check(value != version) { "injected failure at the version bump" }
                delegate.userVersion = value
            }
    }

    private val mediaNs = bytes(32, 0x4D)
    private val dmOn = bytes(32, 0x42)
    private val contactA = bytes(16, 0xA1)
    private val contactB = bytes(16, 0xB1)
    private val contactC = bytes(16, 0xC1)

    /**
     * A database exactly at v7 with a row in every family v8 relies on or must leave alone: the v1 survivors, the sync
     * tables (a media namespace, a DM namespace, a pending outbox operation, a fetched blob, a registration), the
     * entitlement tables, **the five DM tables v8 rebuilds in every shape the checks admit** (text and reaction
     * messages, incoming and outgoing, with and without a timer, an unread and a read one; outbound items of kinds 1,
     * 2 and 4; item and bundle operations; pending sends; reactions from both sides), the other DM tables and a
     * channel. The two v1 media tables are empty, as they are in production.
     */
    private fun populatedV7(): JdbcSqlExecutor = JdbcSqlExecutor().also { db ->
        assertEquals((1..7).toList(), MigrationRunner(db, upToV7).migrate())
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, 'ghost:me', ?, 1, 7)",
            listOf(bytes(32, 1)),
        )
        db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 10)", listOf(bytes(16, 7)))
        db.exec("INSERT INTO revocations(identity_public_key, certificate, received_at) VALUES (?, ?, 11)", listOf(bytes(32, 8), bytes(64, 9)))
        for (id in 1..2) {
            db.exec(
                "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (?, ?, ?, 'active', 'config')",
                listOf(id, onion(id), bytes(16, id)),
            )
        }
        val insertNamespace = "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay, capability_source) VALUES (?, ?, ?, ?, ?)"
        db.exec(insertNamespace, listOf(dmOn, "dm", 1, "on", "redeem"))
        db.exec(insertNamespace, listOf(mediaNs, "media", 0, "default", "local"))
        for (ns in listOf(dmOn, mediaNs)) {
            for (relay in 1..2) db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, ?)", listOf(ns, relay))
        }
        db.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
                "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
            listOf(opId(1), mediaNs, hash(1), bytes(65536, 1)),
        )
        db.exec("INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, 1, 'pending', 0)", listOf(opId(1)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(mediaNs, hash(10)))
        db.exec(
            "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, next_attempt_minute) " +
                "VALUES (1, ?, 2870, 'deposit', ?, ?, 'pending', 600)",
            listOf(dmOn, bytes(32, 5), bytes(16, 5)),
        )
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', 726, ?)", listOf(bytes(32, 3)))
        db.exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, expiry_clock_minute) VALUES (1, 0, ?, ?, ?, 60)",
            listOf(bytes(32, 1), bytes(60, 2), bytes(60, 3)),
        )
        val insertContact = "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment%s) VALUES (?, ?, %s, 0, ?, ?, ?%s)"
        db.exec(insertContact.format("", "?", ""), listOf(contactA, bytes(32, 0x11), bytes(159, 1), "unverified", "link", "ready"))
        db.exec(insertContact.format("", "?", ""), listOf(contactB, bytes(32, 0x12), bytes(159, 2), "verified", "qr_in_person", "ready"))
        db.exec(insertContact.format(", request_until_day", "?", ", 20000"), listOf(contactC, bytes(32, 0x13), bytes(159, 3), "request", "request", "card_only"))
        for (c in listOf(contactA, contactB, contactC)) {
            db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, c[0].toInt() + 1), c))
        }
        // Messages: every kind and state the v5 checks admit. A timer (4) needs an expiry (out) or an unread deadline (in).
        val message = "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
            "body_env, state, expire_at_minute, unread_deadline_minute, delete_at_minute) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        val convA = bytes(16, contactA[0].toInt() + 1)
        val convB = bytes(16, contactB[0].toInt() + 1)
        db.exec(message, listOf(bytes(16, 0x21), convA, "out", 1, 600L, 600L, 0, 4, bytes(100, 0x31), "sent", 604800L, null, 604800L))
        db.exec(message, listOf(bytes(16, 0x22), convA, "in", 1, 660L, 600L, 1, 4, bytes(30, 0x32), "unread", null, 700800L, 700800L))
        db.exec(message, listOf(bytes(16, 0x23), convA, "in", 2, 720L, 720L, 0, 4, null, "unread", null, 700800L, 700800L))
        db.exec(message, listOf(bytes(16, 0x24), convB, "out", 1, 780L, 780L, 0, 0, bytes(61485, 0x34), "failed", null, null, null))
        db.exec(message, listOf(bytes(16, 0x25), convB, "in", 1, 840L, 840L, 0, 0, bytes(31, 0x35), "read", null, null, null))
        db.exec(message, listOf(bytes(16, 0x26), convB, "out", 2, 900L, 900L, 0, 0, null, "queued", null, null, null))
        db.exec(message, listOf(bytes(16, 0x27), convB, "in", 1, 960L, 960L, 0, 4, bytes(45, 0x37), "read", 801000L, 801000L, 801000L))
        // Outbound items: a text, a failed text waiting for a session, a reaction, a control item (no message).
        // `ttl_seconds` (Q27/S3b) is part of the row a v7 database of this branch carries; every value is a
        // valid ADR-27 bucket (the texts and the reaction under the default 7-day timer, the control at a day).
        val item = "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, control, l0_env, deadline_hour, state, ttl_seconds) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        db.exec(item, listOf(bytes(16, 0x41), contactA, bytes(16, 0x21), 1, null, bytes(65564, 0x51), 360000L, "sent", 604800L))
        db.exec(item, listOf(bytes(16, 0x42), contactB, bytes(16, 0x24), 1, null, bytes(29, 0x52), 360000L, "pending", 604800L))
        db.exec(item, listOf(bytes(16, 0x43), contactB, bytes(16, 0x26), 2, null, null, 363600L, "enqueued", 604800L))
        db.exec(item, listOf(bytes(16, 0x44), contactA, null, 4, "reconnect", null, 367200L, "failed", 86400L))
        val op = "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, bundle_week, blob, resend_count, deadline_hour) VALUES (?, ?, ?, ?, ?, ?, ?)"
        db.exec(op, listOf(bytes(16, 0x61), "item", bytes(16, 0x41), null, bytes(65536, 0x71), 1, 360000L))
        db.exec(op, listOf(bytes(16, 0x62), "item", bytes(16, 0x43), null, null, 0, 363600L))
        db.exec(op, listOf(bytes(16, 0x63), "bundle", null, 2870L, bytes(4096, 0x73), 2, 367200L))
        db.exec("INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, 360000)", listOf(bytes(16, 0x42), contactB))
        val reaction = "INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, ?, ?)"
        db.exec(reaction, listOf(bytes(16, 0x21), 1, bytes(30, 0x81)))
        db.exec(reaction, listOf(bytes(16, 0x21), 0, bytes(31, 0x82)))
        db.exec(reaction, listOf(bytes(16, 0x25), 0, bytes(60, 0x83)))
        db.exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, 7)", listOf(bytes(16, 1)))
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 600)",
            listOf(contactA, bytes(32, 5), bytes(200, 6)),
        )
        ChannelFixture(db).apply { put("ch_channel"); put("ch_post") }
        assertEquals(7, db.userVersion)
    }

    /** Every row of every table, as text (`quote` of each column), by table name: the content a migration must keep. */
    private fun SqlExecutor.dump(): Map<String, List<String>> {
        val tables = ArrayList<String>()
        query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name") { tables += it.string(0) }
        val out = LinkedHashMap<String, List<String>>()
        for (table in tables) {
            val columns = ArrayList<String>()
            query("PRAGMA table_info($table)") { columns += it.string(1) }
            val rows = ArrayList<String>()
            query("SELECT ${columns.joinToString(" || '|' || ") { "quote($it)" }} FROM $table") { rows += it.string(0) }
            out[table] = rows.sorted()
        }
        return out
    }

    private fun SqlExecutor.schemaSnapshot(): List<String> {
        val out = ArrayList<String>()
        query("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name") { out += "${it.string(0)}|${it.string(1)}|${it.string(2)}" }
        return out
    }

    private fun SqlExecutor.queryNames(type: String): Set<String> {
        val out = HashSet<String>()
        query("SELECT name FROM sqlite_master WHERE type = ?", listOf(type)) { out += it.string(0) }
        return out
    }

    /** Identifier quoting (`ALTER TABLE ... RENAME` adds it) and whitespace are not schema differences. */
    private fun normalize(sql: String): String = sql.replace("\"", "").replace(Regex("\\s+"), " ").trim()

    /** (type, name, tbl_name, normalized sql) of every object, by (type, name): the object set G-9 compares. */
    private fun SqlExecutor.objects(): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        query("SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name") {
            out["${it.string(0)} ${it.string(1)}"] = "${it.string(2)}|${normalize(it.string(3))}"
        }
        return out
    }

    private fun SqlExecutor.pragmaRows(pragma: String): List<String> {
        val out = ArrayList<String>()
        query("PRAGMA $pragma") { row ->
            val cells = ArrayList<String>()
            var i = 0
            while (true) {
                val cell = try {
                    if (row.isNull(i)) "null" else row.string(i)
                } catch (e: java.sql.SQLException) {
                    break
                }
                cells += cell
                i++
            }
            out += cells.joinToString(",")
        }
        return out
    }

    // ------------------------------------------------------------------ the upgrade

    @Test
    fun aPopulatedV7DatabaseKeepsEveryRowAndGainsTheMediaTables() = populatedV7().use { db ->
        val before = db.dump()
        assertTrue("the fixture must be populated", before.getValue("dm_message").size == 7 && before.getValue("dm_reaction").size == 3)
        assertEquals(4, before.getValue("dm_outbound_item").size)
        assertEquals(3, before.getValue("dm_outbound_op").size)
        for (table in MediaSchema.v1Tables) assertEquals("$table is empty before the migration", emptyList<String>(), before.getValue(table))
        assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
        MigrationRunner(db).verifyIntegrity()
        assertEquals(9, db.userVersion)
        val after = db.dump()
        // Every table that v7 has and v8 keeps holds exactly the rows it held, byte for byte (the five rebuilt ones included) ...
        for ((table, rows) in before) {
            if (table in MediaSchema.v1Tables) continue
            assertEquals(table, rows, after.getValue(table))
        }
        for (table in MediaSchema.rebuilt) assertTrue("$table must have rows to prove anything", before.getValue(table).isNotEmpty())
        // ... the two v1 media tables are gone with the guard, and the five media tables are there and empty
        // (v9's transport_bridge arrives in the same run: one additive table, no rows).
        assertEquals(MediaSchema.v1Tables, before.keys - after.keys)
        assertEquals(MediaSchema.tables + setOf("transport_bridge"), after.keys - before.keys)
        assertEquals(emptyList<String>(), after.getValue("transport_bridge"))
        for (table in MediaSchema.tables) assertEquals("$table starts empty", emptyList<String>(), after.getValue(table))
        for (leftover in listOf("v8_migration_guard", "v8_alter_guard", "v8_fk_guard")) assertFalse(leftover in after.keys)
        for (leftover in listOf("dm_message_v8", "dm_outbound_item_v8", "dm_outbound_op_v8", "dm_pending_send_v8", "dm_reaction_v8")) {
            assertFalse("$leftover was renamed", leftover in after.keys)
        }
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
        // No object names a dropped table any more (a trigger's message may use the word and is no reference).
        val dropped = MediaSchema.v1Tables.joinToString("|")
        val reads = Regex("\\b(FROM|JOIN|INTO|UPDATE|REFERENCES|ON)\\s+($dropped)\\b")
        val dangling = ArrayList<String>()
        db.query("SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master") { r ->
            if (r.string(2) in MediaSchema.v1Tables || reads.containsMatchIn(r.string(3))) dangling += "${r.string(0)} ${r.string(1)}"
        }
        assertEquals(emptyList<String>(), dangling)
    }

    @Test
    fun theMediaTablesWorkRightAfterTheUpgrade() = populatedV7().use { db ->
        MigrationRunner(db).migrate()
        MediaFixture(db).apply {
            // An outgoing object with its message, upload, blob, fragment and operation; an incoming one without a message.
            dmMessage(bytes(16, 0x91))
            put("media_object", "object_id" to MediaFixture.OUT, "message_id" to bytes(16, 0x91))
            put("media_upload")
            put("media_fragment")
            put("media_outbound_op")
            putIn("awaiting")
            assertEquals(mapOf("media_object" to 2L, "media_upload" to 1L, "media_blob" to 1L, "media_fragment" to 1L, "media_outbound_op" to 1L),
                MediaSchema.tables.associateWith { count(it) })
        }
        // The deletion of a message takes its media rows with it and no other family's (no cascade crosses over).
        val dmBefore = db.queryLong("SELECT count(*) FROM dm_message")!!
        db.exec("DELETE FROM dm_message WHERE message_id = ?", listOf(bytes(16, 0x91)))
        assertEquals(dmBefore - 1, db.queryLong("SELECT count(*) FROM dm_message"))
        for (table in listOf("media_upload", "media_fragment", "media_outbound_op")) {
            assertEquals("$table is gone with its object", 0L, db.queryLong("SELECT count(*) FROM $table"))
        }
        assertEquals("the incoming object has no message and stays", 1L, db.queryLong("SELECT count(*) FROM media_object"))
        assertEquals("a blob outlives the rows that named it until the store deletes it", 1L, db.queryLong("SELECT count(*) FROM media_blob"))
        assertEquals(1L, db.queryLong("SELECT count(*) FROM sync_namespace WHERE consumer = 'media'"))
    }

    // ------------------------------------------------------------------ the rebuild (G-9)

    /**
     * The negative control of the five-table rebuild (finding F-S3-1 of the design's section 22.4). Section 13.6 names two
     * tables to rebuild, `dm_message` and `dm_outbound_item`; but with foreign keys on — they are, and
     * `PRAGMA foreign_keys` is a no-op inside a transaction, so the migration cannot turn them off — `DROP TABLE` of a
     * parent performs an implicit `DELETE` of its rows first, and that fires every `ON DELETE CASCADE` into the children.
     * A rebuild that drops `dm_message` while its children are alive would silently delete every outbound item, operation,
     * pending send and reaction of the user. This runs exactly that on the populated v7 and shows the rows go; the
     * migration under test copies all five tables before it drops any (`aPopulatedV7DatabaseKeepsEveryRow...`), which is
     * why the rebuilt set is five tables and not two. (The order of the drops, children first, is not what keeps the rows: a
     * throwaway mutant of the review dropped the parents first and lost none, because the copies were already made.)
     */
    @Test
    fun droppingTheParentFirstWouldHaveCascadedAwayTheChildrenSoTheRebuildCoversTheWholeSubtree() = populatedV7().use { db ->
        val children = listOf("dm_outbound_item", "dm_outbound_op", "dm_pending_send", "dm_reaction")
        val rowsOf = { children.associateWith { db.queryLong("SELECT count(*) FROM $it")!! } }
        assertEquals(mapOf("dm_outbound_item" to 4L, "dm_outbound_op" to 3L, "dm_pending_send" to 1L, "dm_reaction" to 3L), rowsOf())
        assertEquals("foreign keys are on, as in the application", 1L, db.queryLong("PRAGMA foreign_keys"))
        db.transaction {
            db.exec("DROP TABLE dm_message")
            // the children are still tables with their rows' keys intact, and the rows that named a message are gone
            val after = rowsOf()
            assertEquals("the item that names a message went with it; the control item (no message) stayed", 1L, after.getValue("dm_outbound_item"))
            assertEquals("the operation of a lost item went with it; the bundle operation stayed", 1L, after.getValue("dm_outbound_op"))
            assertEquals(0L, after.getValue("dm_pending_send"))
            assertEquals(0L, after.getValue("dm_reaction"))
        }
    }

    /**
     * The G-9 test of F9 §21.13 point 9, for the rebuild of Phase 11: the five rebuilt tables differ from v7 in the
     * kind lists and the envelope checks of `dm_message` and `dm_outbound_item` and **in nothing else** — written again
     * here as textual substitutions on the v7 text, so that the migration's own derivation and this list cannot drift
     * together — every other column, CHECK and key is v7's, every index, trigger and guard that names one of them is
     * recreated with the same text, and every object that names none of the rebuilt, dropped and new tables is untouched —
     * with the one deliberate exception Q27/S3b adds outside the rebuild: `dm_scheduled.attempts`, the §21.8 point 4
     * reschedule bound, added by `ALTER TABLE` and asserted here as one more literal substitution.
     */
    @Test
    fun theRebuiltTablesDifferFromV7InTheKindAndEnvelopeChecksAndInNothingElse() {
        val v7 = JdbcSqlExecutor().use { db -> MigrationRunner(db, upToV7).migrate(); db.objects() to shapes(db) }
        val v8Db = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        v8Db.use { db ->
            val now = db.objects()
            val changes = mapOf(
                "table dm_message" to listOf(
                    "kind INTEGER NOT NULL CHECK (kind IN (1, 2))," to "kind INTEGER NOT NULL CHECK (kind IN (1, 2, 5)),",
                    "length(body_env) BETWEEN 30 AND 61485" to "length(body_env) BETWEEN 28 AND 61485",
                    "CHECK ((kind = 1) = (body_env IS NOT NULL))," to
                        "CHECK ((kind IN (1, 5)) = (body_env IS NOT NULL)), CHECK (kind <> 1 OR length(body_env) >= 30), " +
                        "CHECK (kind <> 5 OR length(body_env) BETWEEN 28 AND 1052),",
                ),
                "table dm_outbound_item" to listOf("CHECK (kind BETWEEN 1 AND 4)," to "CHECK (kind BETWEEN 1 AND 5),"),
            )
            val rebuiltObjects = ArrayList<String>()
            for ((key, text) in v7.first) {
                val table = text.substringBefore('|')
                if (table !in MediaSchema.rebuilt) continue
                rebuiltObjects += key
                assertTrue("$key must exist after the rebuild", key in now)
                var expected = text
                for ((old, new) in changes[key].orEmpty()) {
                    assertEquals("$key: the old text of a change occurs once", 2, expected.split(old).size)
                    expected = expected.replace(old, new)
                }
                assertEquals(key, expected, now.getValue(key))
            }
            // The objects that hang on the rebuilt tables are exactly the ones v7 had: 5 tables, 3 indexes, 3 triggers, 5 guards.
            assertEquals(5 + 3 + 3 + 5 + autoIndexes(v7.first), rebuiltObjects.size)
            assertEquals(
                rebuiltObjects.toSet(),
                now.filterValues { it.substringBefore('|') in MediaSchema.rebuilt }.keys,
            )
            // Everything else that v7 had is untouched, byte for byte (type, name, table, text) — except
            // `dm_scheduled`, whose Q27 column (`attempts`, §21.8 point 4's reschedule bound) migration 8
            // adds by `ALTER TABLE`; written again here as a literal substitution, so this list cannot
            // drift with the migration. What v8 adds is the media objects.
            val scheduledChanges = listOf(
                "due_minute INTEGER NOT NULL CHECK (typeof(due_minute) = 'integer' AND due_minute % 60 = 0)," to
                    "due_minute INTEGER NOT NULL CHECK (typeof(due_minute) = 'integer' AND due_minute % 60 = 0), " +
                    "attempts INTEGER NOT NULL DEFAULT 0 CHECK (typeof(attempts) = 'integer' AND attempts BETWEEN 0 AND 3),",
            )
            val untouched = v7.first.filterValues {
                it.substringBefore('|') !in MediaSchema.rebuilt && it.substringBefore('|') !in MediaSchema.v1Tables
            } - "table dm_scheduled"
            for ((key, text) in untouched) assertEquals(key, text, now[key])
            var expectedScheduled = v7.first.getValue("table dm_scheduled")
            for ((old, new) in scheduledChanges) {
                assertEquals("table dm_scheduled: the old text of a change occurs once", 2, expectedScheduled.split(old).size)
                expectedScheduled = expectedScheduled.replace(old, new)
            }
            assertEquals("table dm_scheduled", expectedScheduled, now["table dm_scheduled"])
            val added = now.keys - v7.first.keys
            // v9 (Phase 12 transports §6.3) lands in the same run and adds exactly the one table.
            assertEquals(
                MediaSchema.tables + MediaSchema.indexes + MediaSchema.rules + MediaSchema.guards + setOf("transport_bridge"),
                added.map { it.substringAfter(' ') }.filter { !it.startsWith("sqlite_autoindex") }.toSet(),
            )
            assertEquals(setOf("index sqlite_autoindex_media_outbound_op_2"), added.filter { it.contains("sqlite_autoindex") }.toSet())
            // The shape is v7's too: the columns (names, types, nullability, defaults, primary key), the foreign keys and the indexes.
            for (table in MediaSchema.rebuilt) {
                val (columns, foreignKeys, indexes) = v7.second.getValue(table)
                assertEquals("$table columns", columns, db.pragmaRows("table_info($table)"))
                assertEquals("$table foreign keys", foreignKeys, db.pragmaRows("foreign_key_list($table)"))
                assertEquals("$table indexes", indexes, db.pragmaRows("index_list($table)").map { it.replaceFirst(Regex("^\\d+,"), "") })
            }
        }
    }

    private fun autoIndexes(objects: Map<String, String>): Int =
        objects.keys.count { it.startsWith("index sqlite_autoindex") && objects.getValue(it).substringBefore('|') in MediaSchema.rebuilt }

    private fun shapes(db: JdbcSqlExecutor): Map<String, Triple<List<String>, List<String>, List<String>>> =
        MediaSchema.rebuilt.associateWith {
            Triple(
                db.pragmaRows("table_info($it)"),
                db.pragmaRows("foreign_key_list($it)"),
                db.pragmaRows("index_list($it)").map { row -> row.replaceFirst(Regex("^\\d+,"), "") },
            )
        }

    /** The columns the migration copies by name equal the columns v7 has: a column added to v5 and not to the copy fails here. */
    @Test
    fun theExplicitCopyListsNameEveryColumnOfTheRebuiltTables() = populatedV7().use { db ->
        val copies = v8.statements.map { it.replace(Regex("\\s+"), " ").trim() }.filter { it.startsWith("INSERT INTO dm_") && it.contains("_v8(") }
        assertEquals(5, copies.size)
        for (table in MediaSchema.rebuilt) {
            val columns = ArrayList<String>()
            db.query("PRAGMA table_info($table)") { columns += it.string(1) }
            val copy = copies.single { it.startsWith("INSERT INTO ${table}_v8(") }
            val inserted = copy.substringAfter("_v8(").substringBefore(")").split(", ")
            val selected = copy.substringAfter("SELECT ").substringBefore(" FROM ").split(", ")
            assertEquals("$table insert list", columns, inserted)
            assertEquals("$table select list", columns, selected)
            assertTrue(copy, copy.endsWith(" FROM $table"))
        }
    }

    /**
     * Q27's other column lands outside the rebuild: `dm_scheduled` is not one of the five tables, so
     * migration 8 adds `attempts` (the §21.8 point 4 reschedule bound, faza9-dm.md §22.13 item 9) by
     * `ALTER TABLE … ADD COLUMN`. The statement runs on every path — a fresh install runs migrations
     * 1…8 — so both an upgrade and a fresh install must end with the identical column, default and
     * CHECK; the backfill gives an existing row the bound counter's start, and the CHECK executes
     * (a fractional value and an out-of-range one are refused).
     */
    @Test
    fun theScheduledAttemptsColumnArrivesByAlterOnEveryPath() {
        fun shape(db: JdbcSqlExecutor): List<String> {
            val out = ArrayList<String>()
            db.query("PRAGMA table_info(dm_scheduled)") { r ->
                out += "${r.string(1)}|${r.string(2)}|${r.long(3)}|${if (r.isNull(4)) "null" else r.string(4)}"
            }
            return out
        }
        val freshShape = JdbcSqlExecutor().use { fresh -> MigrationRunner(fresh).migrate(); shape(fresh) }
        populatedV7().use { db ->
            MigrationRunner(db).migrate()
            assertEquals("the upgrade and a fresh install must end with the identical dm_scheduled", freshShape, shape(db))
            assertTrue("the ALTER added attempts with its DEFAULT", freshShape.any { it.startsWith("attempts|INTEGER|1|0") })
            db.exec(
                "INSERT INTO dm_scheduled(sched_id, contact_id, what, due_minute) VALUES (?, ?, 'reconnect', 600)",
                listOf(bytes(16, 0x51), contactA),
            )
            assertEquals("the counter's start is its DEFAULT", 0L, db.queryLong("SELECT attempts FROM dm_scheduled"))
            db.rejects(CHECK_FAILED, "UPDATE dm_scheduled SET attempts = 1.5 WHERE sched_id = ?", bytes(16, 0x51))
            db.rejects(CHECK_FAILED, "UPDATE dm_scheduled SET attempts = 4 WHERE sched_id = ?", bytes(16, 0x51))
            db.exec("UPDATE dm_scheduled SET attempts = 3 WHERE sched_id = ?", listOf(bytes(16, 0x51)))
            assertEquals(3L, db.queryLong("SELECT attempts FROM dm_scheduled"))
        }
    }

    /** The rebuilt tables still cascade where v7 cascaded, and admit kind 5 (the edges of the new checks are [MediaSchemaConstraintsTest]'s). */
    @Test
    fun theRebuiltTablesStillCascadeAndNowAdmitAMediaMessage() = populatedV7().use { db ->
        MigrationRunner(db).migrate()
        // Deleting a message takes its reactions and its outbound items, and an item takes its operations and its pending send.
        assertEquals(1, db.changes("DELETE FROM dm_message WHERE message_id = ?", bytes(16, 0x24)))
        assertEquals(0L, db.queryLong("SELECT count(*) FROM dm_outbound_item WHERE item_id = ?", listOf(bytes(16, 0x42))))
        assertEquals(0L, db.queryLong("SELECT count(*) FROM dm_pending_send"))
        assertEquals(1, db.changes("DELETE FROM dm_message WHERE message_id = ?", bytes(16, 0x21)))
        assertEquals(0L, db.queryLong("SELECT count(*) FROM dm_reaction WHERE target_id = ?", listOf(bytes(16, 0x21))))
        assertEquals(0L, db.queryLong("SELECT count(*) FROM dm_outbound_op WHERE item_id = ?", listOf(bytes(16, 0x41))))
        assertEquals("the bundle operation has no item and stays", 1L, db.queryLong("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'bundle'"))
        assertEquals("a reaction on another message stays", 1L, db.queryLong("SELECT count(*) FROM dm_reaction"))
        // A media message (kind 5, a caption of 28 bytes) and its outbound item (kind 5) are admitted now.
        MediaFixture(db).dmMessage(bytes(16, 0x95), body = bytes(28, 0x73))
        db.exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, message_ref, kind, deadline_hour, state, ttl_seconds) " +
                "VALUES (?, ?, ?, 5, 360000, 'pending', 604800)",
            listOf(bytes(16, 0x96), MediaFixture.DEST, bytes(16, 0x95)),
        )
        assertEquals(1L, db.queryLong("SELECT count(*) FROM dm_outbound_item WHERE kind = 5"))
        // The triggers and guards of the rebuilt tables came back (the references they check are the new tables').
        db.rejects("illegal message state transition", "UPDATE dm_message SET state = 'read' WHERE message_id = ?", bytes(16, 0x95))
        db.rejects("dm_message rows are never replaced", "INSERT OR REPLACE INTO dm_message(message_id) VALUES (?)", bytes(16, 0x95))
    }

    // ------------------------------------------------------------------ the guard and the crash

    private fun SqlExecutor.seedV1Media(table: String) {
        when (table) {
            "media" -> exec(
                "INSERT INTO media(media_id, owner_operation_id, manifest, wrapped_file_key, size_bytes, mime, cache_state) VALUES (?, ?, ?, ?, 10, 'image/png', 'none')",
                listOf(bytes(16, 6), bytes(16, 7), bytes(40, 1), bytes(60, 2)),
            )
            else -> {
                if (queryLong("SELECT count(*) FROM media")!! == 0L) seedV1Media("media")
                exec("INSERT INTO media_blobs(media_id, ordinal, blob_hash) VALUES (?, 0, ?)", listOf(bytes(16, 6), hash(9)))
            }
        }
    }

    /** The guard: a row in either v1 media table (or both) aborts the migration and leaves v7 exactly as it was. */
    @Test
    fun guardAbortsV8WhenAV1MediaTableHasRows() {
        for (tables in listOf(listOf("media"), listOf("media_blobs"), listOf("media", "media_blobs"))) {
            populatedV7().use { db ->
                for (t in tables) db.seedV1Media(t)
                val schema = db.schemaSnapshot()
                val rows = db.dump()
                val e = assertThrows(tables.toString(), java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
                assertTrue(e.message, e.message.orEmpty().contains("CHECK constraint failed"))
                assertEquals(7, db.userVersion)
                assertEquals(schema, db.schemaSnapshot())
                assertEquals(rows, db.dump())
                assertFalse(db.inTransaction)
                // Once the tables are emptied the same runner finishes (media_blobs first: the child).
                db.exec("DELETE FROM media_blobs")
                db.exec("DELETE FROM media")
                assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
            }
        }
    }

    /** `legacy_alter_table` on would stop the renames from rewriting the references of the new children: the migration refuses to start. */
    @Test
    fun v8RefusesToRunWithLegacyAlterTableOn() = populatedV7().use { db ->
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        db.exec("PRAGMA legacy_alter_table = ON")
        assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
        assertEquals(7, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
        db.exec("PRAGMA legacy_alter_table = OFF")
        assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
    }

    /**
     * A row of a rebuilt table that names a parent which is not there (foreign keys off at the time it was written) is
     * not copied past silently: the copy meets the constraint and the migration rolls back, leaving v7.
     */
    @Test
    fun anOrphanRowOfARebuiltTableFailsTheMigrationAndLeavesV7() = populatedV7().use { db ->
        db.exec("PRAGMA foreign_keys = OFF")
        db.exec("INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)", listOf(bytes(16, 0xEE), bytes(30, 1)))
        db.exec("PRAGMA foreign_keys = ON")
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
        assertEquals(7, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
        db.exec("DELETE FROM dm_reaction WHERE target_id = ?", listOf(bytes(16, 0xEE)))
        assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
    }

    /**
     * The last statements of the rebuild repeat migration 4's guard: `pragma_foreign_key_check` must be empty, and it counts
     * **every** dangling reference of the database, not only those the rebuild could have made. A correct rebuild cannot make
     * one (the copies meet the constraints first, `anOrphanRowOfARebuiltTableFailsTheMigrationAndLeavesV7`), so the guard is
     * the one thing that stops a run only when a row of a table the rebuild leaves alone already dangles — which is what this
     * writes, with the keys off, as an old bug or a restore could have. It is red when the guard is neutered (the review's
     * mutant `SELECT 0` passed every other test of the migration).
     */
    @Test
    fun aDanglingReferenceAnywhereInTheDatabaseIsStoppedByTheForeignKeyGuardAndLeavesV7() = populatedV7().use { db ->
        db.exec("PRAGMA foreign_keys = OFF")
        db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, 1)", listOf(bytes(32, 0xEE))) // a namespace that is not there
        db.exec("PRAGMA foreign_keys = ON")
        assertEquals("the row dangles", 1L, db.queryLong("SELECT count(*) FROM pragma_foreign_key_check"))
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        val e = assertThrows(java.sql.SQLException::class.java) { MigrationRunner(db).migrate() }
        assertTrue(e.message, e.message.orEmpty().contains("CHECK constraint failed"))
        assertEquals(7, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
        assertFalse(db.inTransaction)
        db.exec("DELETE FROM namespace_relay WHERE namespace_id = ?", listOf(bytes(32, 0xEE)))
        assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
    }

    /**
     * The migration's own failure modes (SCN-MF, CS-9 over v7 to v8): an interruption at every one of its statements,
     * and at the version bump, leaves the populated v7 database untouched — schema text, every row, version — and the
     * next run succeeds with the same result as an uninterrupted one. The statements include the guards' inserts, the
     * five table copies, the drops, the renames and every table, trigger and guard.
     */
    @Test
    fun anInterruptionAtAnyStatementLeavesThePopulatedV7Untouched() {
        val expected = populatedV7().use { db ->
            MigrationRunner(db).migrate()
            Pair(db.schemaSnapshot(), db.dump())
        }
        assertEquals(
            "guards 9, rebuild 5 tables + 5 copies + 5 drops + 5 renames + 3 indexes + 3 triggers + 5 guards + 3 foreign-key guard, " +
                "1 scheduled column, media 5 tables + 5 indexes, 14 rules + 5 guards: a change is deliberate",
            9 + (5 + 5 + 5 + 5 + 3 + 3 + 5 + 3 + 1) + (5 + 5) + (14 + 5),
            v8.statements.size,
        )
        for (i in v8.statements.indices) {
            populatedV7().use { db ->
                val schema = db.schemaSnapshot()
                val rows = db.dump()
                val faulty = FailAtExec(db, i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty).migrate() }
                assertEquals("statement $i ran", i + 1, faulty.calls)
                assertEquals("statement $i", 7, db.userVersion)
                assertEquals("statement $i", schema, db.schemaSnapshot())
                assertEquals("statement $i", rows, db.dump())
                assertFalse(db.inTransaction)
                // A half-migrated database is refused, never used; then the same runner finishes the job.
                assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                assertEquals("statement $i", listOf(8, 9), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertEquals("statement $i", expected.first, db.schemaSnapshot())
                assertEquals("statement $i", expected.second, db.dump())
            }
        }
        populatedV7().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            assertThrows(IllegalStateException::class.java) { MigrationRunner(FailOnVersionBump(db, 8)).migrate() }
            assertEquals(7, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
            assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
            assertEquals(expected.second, db.dump())
        }
    }

    /**
     * A **process death** in the middle of the transaction is the same thing for SQLite as the injected failure above,
     * which rolls back; this reopens the file the way a restart does: a database file, an exception in the middle of v8
     * (the rebuild: the new tables created and copied, the old ones perhaps dropped; nothing committed), a second
     * executor on the same file that sees v7 with every row and migrates it. The JVM stand-in for the emulator's
     * SQLCipher drill (§15.8).
     */
    @Test
    fun aRestartAfterAnInterruptedUpgradeFindsV7WithEveryRowAndMigrates() {
        val file = java.io.File.createTempFile("ghost-migration8", ".db")
        try {
            // The statement after the drops and before the renames: the worst moment for the rebuilt tables.
            val midRebuild = v8.statements.indexOfFirst { it.trim().startsWith("ALTER TABLE dm_message_v8 RENAME") }
            assertTrue(midRebuild > 0)
            val rows = JdbcSqlExecutor(file.path).use { db ->
                assertEquals((1..7).toList(), MigrationRunner(db, upToV7).migrate())
                MediaFixture(db).dmMessage(bytes(16, 0x91), kind = 1L, body = bytes(60, 0x73))
                db.exec("INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)", listOf(bytes(16, 0x91), bytes(30, 1)))
                val rows = db.dump()
                assertThrows(IllegalStateException::class.java) { MigrationRunner(FailAtExec(db, midRebuild)).migrate() }
                rows
            }
            JdbcSqlExecutor(file.path).use { db ->
                assertEquals(7, db.userVersion)
                assertEquals(rows, db.dump())
                assertFalse("dm_message_v8" in db.queryNames("table"))
                assertFalse("media_object" in db.queryNames("table"))
                assertEquals(listOf(8, 9), MigrationRunner(db).migrate())
                MigrationRunner(db).verifyIntegrity()
                assertEquals(1L, db.queryLong("SELECT count(*) FROM dm_reaction"))
            }
        } finally {
            file.delete()
        }
    }

    /** The open helper's path: every pending migration in the caller's transaction, rolled back together on a failure. */
    @Test
    fun theOpenHelperPathUpgradesInsideTheCallersTransactionAndRollsBackOnAFailure() {
        fun helperOpen(db: SqlExecutor): List<Int> = db.transaction {
            val applied = MigrationRunner(db).migrateWithinTransaction(db.userVersion)
            db.userVersion = Schema.CURRENT_VERSION
            applied
        }
        populatedV7().use { db ->
            assertEquals(listOf(8, 9), helperOpen(db))
            MigrationRunner(db).verifyIntegrity()
            assertEquals(MediaSchema.tables, db.queryNames("table").filter { it.startsWith("media_") }.toSet())
        }
        populatedV7().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            // The last statement of v8 fails: the rebuild, the tables, the triggers and the drops before it are undone together.
            val faulty = FailAtExec(db, v8.statements.size - 1)
            assertThrows(IllegalStateException::class.java) {
                faulty.transaction { MigrationRunner(faulty).migrateWithinTransaction(faulty.userVersion) }
            }
            assertEquals(7, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
        }
        // From v1, on device, v8 shares the helper's transaction with everything before it.
        JdbcSqlExecutor().use { db ->
            val upToV1 = Schema.migrations.filter { it.version <= 1 }
            MigrationRunner(db, upToV1).migrate()
            val schema = db.schemaSnapshot()
            val faulty = FailAtExec(db, Schema.migrations.filter { it.version > 1 }.sumOf { it.statements.size } - 1)
            assertThrows(IllegalStateException::class.java) {
                faulty.transaction { MigrationRunner(faulty).migrateWithinTransaction(faulty.userVersion) }
            }
            assertEquals(1, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
        }
    }

    @Test
    fun anOlderAppRefusesTheUpgradedDatabaseAndLeavesItUntouched() = populatedV7().use { db ->
        MigrationRunner(db).migrate()
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        assertThrows(MigrationRunner.DowngradeException::class.java) { MigrationRunner(db, upToV7).migrate() }
        assertThrows(MigrationRunner.DowngradeException::class.java) {
            db.transaction { MigrationRunner(db, upToV7).migrateWithinTransaction(db.userVersion) }
        }
        assertEquals(9, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
    }

    /** A fresh install and an upgrade from v7 end with the identical schema text (the migration test compares by (type, name, sql)). */
    @Test
    fun anUpgradeFromV7AndAFreshInstallEndWithTheSameSchema() {
        val fresh = JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            db.schemaSnapshot()
        }
        populatedV7().use { db ->
            MigrationRunner(db).migrate()
            assertEquals(fresh, db.schemaSnapshot())
        }
    }

    /** The statements of v8, in the order the design gives them: the guards first, then the rebuild, the tables, the rules. */
    @Test
    fun theStatementsRunInTheDesignedOrder() {
        val statements = v8.statements.map { it.replace(Regex("\\s+"), " ").trim() }
        fun at(prefix: String) = statements.indexOfFirst { it.startsWith(prefix) }
        fun exact(statement: String) = statements.indexOf(statement)
        assertTrue("the legacy_alter_table guard comes first", statements[0].startsWith("CREATE TABLE v8_alter_guard"))
        assertTrue("the guard is dropped before any table is", exact("DROP TABLE v8_migration_guard") in 1 until exact("DROP TABLE media_blobs"))
        // The child of the v1 media tables goes before the parent, so no cascade hides a counted row.
        assertTrue(exact("DROP TABLE media_blobs") < exact("DROP TABLE media") && exact("DROP TABLE media") < at("CREATE TABLE dm_message_v8"))
        for (table in MediaSchema.v1Tables) {
            assertEquals(table, 1, statements.count { it == "INSERT INTO v8_migration_guard(row_count) SELECT count(*) FROM $table" })
        }
        // The new tables are created first and copied, then the old ones dropped children first, then renamed.
        val creates = MediaSchema.rebuilt.map { at("CREATE TABLE ${it}_v8 (") }
        val copies = MediaSchema.rebuilt.map { at("INSERT INTO ${it}_v8(") }
        assertTrue(creates.all { it >= 0 } && copies.all { it >= 0 })
        assertTrue("every new table exists before the first copy", creates.max() < copies.min())
        val drops = listOf("dm_outbound_op", "dm_pending_send", "dm_reaction", "dm_outbound_item", "dm_message").map { exact("DROP TABLE $it") }
        assertEquals("children first, as migration 4 does (the copies above are what keep the rows; this is the tidy order)", drops.sorted(), drops)
        assertTrue(drops.all { it >= 0 })
        assertTrue(copies.max() < drops.min())
        val renames = MediaSchema.rebuilt.map { at("ALTER TABLE ${it}_v8 RENAME TO $it") }
        assertTrue(renames.all { it > drops.max() })
        assertTrue("the foreign-key guard runs after the rebuild is whole", at("CREATE TABLE v8_fk_guard") > at("CREATE TRIGGER dm_reaction_no_replace"))
        assertTrue("the media tables come after the rebuild (media_object references dm_message)", at("CREATE TABLE media_object") > exact("DROP TABLE v8_fk_guard"))
        assertTrue("every table precedes the first media rule", statements.indexOfLast { it.startsWith("CREATE TABLE media_") } < at("CREATE TRIGGER media_"))
    }
}
