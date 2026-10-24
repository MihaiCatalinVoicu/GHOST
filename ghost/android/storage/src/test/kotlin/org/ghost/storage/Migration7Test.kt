package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration 7 (Phase 10 design §9, "Migration 7 (channels)"; slice S3) on a **populated v6 database**:
 * the four v1 channel tables go behind their guard, the 28 channel tables arrive empty, and not a row
 * of any other table moves; an interruption at any statement leaves v6 as it was; an older app and a
 * half-migrated database are refused.
 *
 * What each new object enforces by itself is tested where its family is: the shapes and the declared
 * time columns in [ChannelSchemaIntrospectionTest], the CHECKs in [ChannelSchemaConstraintsTest], the
 * triggers in [ChannelTriggersTest], the REPLACE guards in [ReplaceGuardsTest] and [ChannelReplaceGuardsTest],
 * the version lists in [SchemaAndMigrationTest]. This class is about the **upgrade** (CS-C9, SCN-CI's
 * storage half): which rows exist before and after, and what a crash in the middle leaves behind.
 */
class Migration7Test {
    private val upToV6 = Schema.migrations.filter { it.version <= 6 }
    private val v7 = Schema.migrations.single { it.version == 7 }

    /** This class tests migration 7 on its own: v8 (Phase 11) is applied by [Migration8Test]. */
    private val upToV7 = Schema.migrations.filter { it.version <= 7 }

    /**
     * What `verifyIntegrity` asserts, for a database at v7: the runner's check is against the **current** schema (v8
     * drops the two v1 media tables and adds five), so a v7 database is verified against the objects of v1 to v7 and
     * the version it is at. Throws [IllegalStateException] like the runner.
     */
    private fun verifyAtV7(db: SqlExecutor) {
        check(db.userVersion == 7) { "schema version mismatch: ${db.userVersion}" }
        val tables = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { tables += it.string(0) }
        val triggers = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'") { triggers += it.string(0) }
        // v8 (Phase 11 §13.6) and v9 (Phase 12 transports §6.3) have not run at v7: the current
        // schema's tables from both are subtracted, exactly like v8 subtracts the media family.
        // v11 (Phase 14 §9.6) has not run at v7 either.
        val expectedTables = Schema.expectedTables - MediaSchema.tables - setOf("transport_bridge", "ui_settings", "ui_lock", "ui_crash", "upd_state", "upd_staged") + MediaSchema.v1Tables
        val expectedTriggers = Schema.expectedTriggers - MediaSchema.rules - MediaSchema.guards - UpdateSchema.rules
        check((expectedTables - tables).isEmpty()) { "schema integrity: missing tables ${expectedTables - tables}" }
        check((expectedTriggers - triggers).isEmpty()) { "schema integrity: missing triggers ${expectedTriggers - triggers}" }
        for ((pragma, expected) in Schema.expectedPragmaValues) assertEquals(pragma, expected, db.queryLong("PRAGMA $pragma"))
    }

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

    private val channelOn = bytes(32, 0x40)
    private val dmOn = bytes(32, 0x42)

    /**
     * A database exactly at v6 with a row in every family v7 relies on or must leave alone: the v1
     * survivors, the sync tables (a channel namespace and a DM namespace, a funded one, a registration
     * capability), the entitlement tables and the DM tables, the live ones among them (a message with a
     * reaction, a session, a seen tag). The four v1 channel tables are empty, as they are in production.
     */
    private fun populatedV6(): JdbcSqlExecutor = JdbcSqlExecutor().also { db ->
        assertEquals(listOf(1, 2, 3, 4, 5, 6), MigrationRunner(db, upToV6).migrate())
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, 'ghost:me', ?, 1, 7)",
            listOf(bytes(32, 1)),
        )
        db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 10)", listOf(bytes(16, 7)))
        db.exec("INSERT INTO revocations(identity_public_key, certificate, received_at) VALUES (?, ?, 11)", listOf(bytes(32, 8), bytes(64, 9)))
        for (id in 1..3) {
            db.exec(
                "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (?, ?, ?, 'active', 'config')",
                listOf(id, onion(id), bytes(16, id)),
            )
        }
        val insertNamespace = "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay, capability_source) VALUES (?, ?, ?, ?, ?)"
        db.exec(insertNamespace, listOf(dmOn, "dm", 1, "on", "redeem"))
        db.exec(insertNamespace, listOf(channelOn, "channel", 1, "default", "local"))
        for (ns in listOf(dmOn, channelOn)) {
            for (relay in 1..2) db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, ?)", listOf(ns, relay))
        }
        db.exec("INSERT INTO sync_namespace_fund(namespace_id) VALUES (?)", listOf(channelOn))
        db.exec(
            "INSERT INTO relay_register_capability(relay_id, namespace_id, token, expires_hour, state, generation) VALUES (1, ?, ?, 7200, 'usable', 2)",
            listOf(channelOn, bytes(82, 1)),
        )
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) VALUES (1, ?, 'write', ?, ?, 'usable', 3)",
            listOf(channelOn, bytes(82, 2), 3600L * 500_000),
        )
        db.exec("INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (1, ?, ?)", listOf(dmOn, bytes(8, 1)))
        db.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
                "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
            listOf(opId(1), channelOn, hash(1), bytes(1024, 1)),
        )
        db.exec("INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, 1, 'pending', 0)", listOf(opId(1)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(channelOn, hash(10)))
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
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                "body_env, state, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'sent', 604800, 604800)",
            listOf(bytes(16, 2), bytes(16, 1), bytes(100, 3)),
        )
        db.exec("INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)", listOf(bytes(16, 2), bytes(30, 4)))
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 600)",
            listOf(bytes(16, 1), bytes(32, 5), bytes(200, 6)),
        )
        db.exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, 7)", listOf(bytes(16, 1)))
        // media and media_blobs stay for Phase 11 (§9 step 0): a row in each must survive.
        db.exec(
            "INSERT INTO media(media_id, owner_operation_id, manifest, wrapped_file_key, size_bytes, mime, cache_state) VALUES (?, ?, ?, ?, 10, 'image/png', 'none')",
            listOf(bytes(16, 6), bytes(16, 7), bytes(40, 1), bytes(60, 2)),
        )
        db.exec("INSERT INTO media_blobs(media_id, ordinal, blob_hash) VALUES (?, 0, ?)", listOf(bytes(16, 6), hash(9)))
        assertEquals(6, db.userVersion)
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

    @Test
    fun aPopulatedV6DatabaseKeepsEveryRowAndGainsTheChannelTables() = populatedV6().use { db ->
        val before = db.dump()
        assertTrue("the fixture must be populated", before.getValue("dm_message").size == 1 && before.getValue("sync_namespace").size == 2)
        assertEquals(setOf("channels", "channel_pseudonyms", "mls_state", "posts"), ChannelSchema.v1Tables)
        for (table in ChannelSchema.v1Tables) assertEquals("$table is empty before the migration", emptyList<String>(), before.getValue(table))
        assertEquals(listOf(7), MigrationRunner(db, upToV7).migrate())
        verifyAtV7(db)
        assertEquals(7, db.userVersion)
        val after = db.dump()
        // Every table that v6 has and v7 keeps holds exactly the rows it held ...
        for ((table, rows) in before) {
            if (table in ChannelSchema.v1Tables) continue
            assertEquals(table, rows, after.getValue(table))
        }
        // ... the four v1 channel tables are gone with the guard, and the 26 channel tables are there and empty.
        assertEquals(ChannelSchema.v1Tables, before.keys - after.keys)
        assertEquals(ChannelSchema.tables, after.keys - before.keys)
        for (table in ChannelSchema.tables) assertEquals("$table starts empty", emptyList<String>(), after.getValue(table))
        assertFalse("v7_migration_guard" in after.keys)
        assertTrue("media stays for Phase 11", "media" in after.keys && "media_blobs" in after.keys)
        assertEquals(1, after.getValue("media").size)
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
        // The index of the dropped posts table went with it; no object names a dropped table any more.
        val dangling = ArrayList<String>()
        val dropped = ChannelSchema.v1Tables.joinToString("|")
        val reads = Regex("\\b(FROM|JOIN|INTO|UPDATE|REFERENCES|ON)\\s+($dropped)\\b")
        db.query("SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master") { r ->
            // an object on a dropped table, or one whose statement reads, writes or references it (a trigger's
            // message may use the word "posts" and is no reference)
            if (r.string(2) in ChannelSchema.v1Tables || reads.containsMatchIn(r.string(3))) dangling += "${r.string(0)} ${r.string(1)}"
        }
        assertEquals(emptyList<String>(), dangling)
    }

    @Test
    fun theChannelTablesWorkRightAfterTheUpgrade() = populatedV6().use { db ->
        MigrationRunner(db, upToV7).migrate()
        ChannelFixture(db).apply {
            for (table in ChannelSchema.tables) put(table)
            for (table in ChannelSchema.tables) assertEquals(table, 1L, count(table))
        }
        // The sync and DM rows beside them are untouched by a delete of the channel: no cascade crosses over.
        val dmRows = db.queryLong("SELECT count(*) FROM dm_message")
        db.exec("DELETE FROM ch_channel")
        // `mls_self` (slice S4) is the one table no channel owns: the state key of every channel, kept when one goes.
        for (table in ChannelSchema.tables - "mls_self") assertEquals("$table is gone with its channel", 0L, db.queryLong("SELECT count(*) FROM $table"))
        assertEquals("the channel state key is no channel's", 1L, db.queryLong("SELECT count(*) FROM mls_self"))
        assertEquals(dmRows, db.queryLong("SELECT count(*) FROM dm_message"))
        assertEquals(1L, db.queryLong("SELECT count(*) FROM sync_namespace WHERE consumer = 'channel'"))
    }

    /**
     * The migration's own failure modes (CS-9 over v6 to v7, CS-C9): an interruption at every one of its
     * statements, and at the version bump, leaves the populated v6 database untouched — schema text,
     * every row, version — and the next run succeeds with the same result as an uninterrupted one. The
     * statements include the guard's inserts, the drops and every table, trigger and guard.
     */
    @Test
    fun anInterruptionAtAnyStatementLeavesThePopulatedV6Untouched() {
        val expected = populatedV6().use { db ->
            MigrationRunner(db, upToV7).migrate()
            Pair(db.schemaSnapshot(), db.dump())
        }
        assertTrue(
            "step 0 (11), 32 tables and indexes, 38 rules, 26 guards and 4 rowid triggers are 111 statements (105 before " +
                "slice S4 added `mls_self`, its rule and its guard, §19.37; 108 before slice S13c added `ch_rotation_history`, " +
                "its rule and its guard, §19.54 row 12); a change is deliberate: ${v7.statements.size}",
            v7.statements.size == 111,
        )
        for (i in v7.statements.indices) {
            populatedV6().use { db ->
                val schema = db.schemaSnapshot()
                val rows = db.dump()
                val faulty = FailAtExec(db, i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty, upToV7).migrate() }
                assertEquals("statement $i ran", i + 1, faulty.calls)
                assertEquals("statement $i", 6, db.userVersion)
                assertEquals("statement $i", schema, db.schemaSnapshot())
                assertEquals("statement $i", rows, db.dump())
                assertFalse(db.inTransaction)
                // A half-migrated database is refused, never used; then the same runner finishes the job.
                assertThrows(IllegalStateException::class.java) { verifyAtV7(db) }
                assertEquals("statement $i", listOf(7), MigrationRunner(db, upToV7).migrate())
                verifyAtV7(db)
                assertEquals("statement $i", expected.first, db.schemaSnapshot())
                assertEquals("statement $i", expected.second, db.dump())
            }
        }
        populatedV6().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            assertThrows(IllegalStateException::class.java) { MigrationRunner(FailOnVersionBump(db, 7), upToV7).migrate() }
            assertEquals(6, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
            assertEquals(listOf(7), MigrationRunner(db, upToV7).migrate())
            assertEquals(expected.second, db.dump())
        }
    }

    /**
     * A **process death** in the middle of the transaction is the same thing for SQLite as the injected
     * failure above, which rolls back; this reopens the file the way a restart does: a database file, an
     * exception in the middle of v7 (nothing committed), a second executor on the same file that sees v6 and
     * migrates it. The JVM stand-in for the emulator's SQLCipher drill (§15.9).
     */
    @Test
    fun aRestartAfterAnInterruptedUpgradeFindsV6AndMigrates() {
        val file = java.io.File.createTempFile("ghost-migration7", ".db")
        try {
            JdbcSqlExecutor(file.path).use { db ->
                assertEquals(listOf(1, 2, 3, 4, 5, 6), MigrationRunner(db, upToV6).migrate())
                db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 10)", listOf(bytes(16, 7)))
                val faulty = FailAtExec(db, v7.statements.size / 2)
                assertThrows(IllegalStateException::class.java) { MigrationRunner(faulty, upToV7).migrate() }
            }
            JdbcSqlExecutor(file.path).use { db ->
                assertEquals(6, db.userVersion)
                assertEquals(1L, db.queryLong("SELECT count(*) FROM invite_nonces"))
                assertFalse("ch_channel" in db.queryNames("table"))
                assertEquals(listOf(7), MigrationRunner(db, upToV7).migrate())
                verifyAtV7(db)
            }
        } finally {
            file.delete()
        }
    }

    private fun SqlExecutor.queryNames(type: String): Set<String> {
        val out = HashSet<String>()
        query("SELECT name FROM sqlite_master WHERE type = ?", listOf(type)) { out += it.string(0) }
        return out
    }

    /** The open helper's path: every pending migration in the caller's transaction, rolled back together on a failure. */
    @Test
    fun theOpenHelperPathUpgradesInsideTheCallersTransactionAndRollsBackOnAFailure() {
        fun helperOpen(db: SqlExecutor): List<Int> = db.transaction {
            val applied = MigrationRunner(db, upToV7).migrateWithinTransaction(db.userVersion)
            db.userVersion = 7
            applied
        }
        populatedV6().use { db ->
            assertEquals(listOf(7), helperOpen(db))
            verifyAtV7(db)
            assertEquals(ChannelSchema.tables, db.queryNames("table").filter { it.startsWith("ch_") || it.startsWith("mls_") }.toSet())
        }
        populatedV6().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            // The last statement of v7 fails: the tables, the triggers and the drops before it are undone together.
            val faulty = FailAtExec(db, v7.statements.size - 1)
            assertThrows(IllegalStateException::class.java) {
                faulty.transaction { MigrationRunner(faulty, upToV7).migrateWithinTransaction(faulty.userVersion) }
            }
            assertEquals(6, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
        }
        // From v1, on device, v7 shares the helper's transaction with everything before it.
        JdbcSqlExecutor().use { db ->
            val upToV1 = Schema.migrations.filter { it.version <= 1 }
            MigrationRunner(db, upToV1).migrate()
            val schema = db.schemaSnapshot()
            val faulty = FailAtExec(db, upToV7.filter { it.version > 1 }.sumOf { it.statements.size } - 1)
            assertThrows(IllegalStateException::class.java) {
                faulty.transaction { MigrationRunner(faulty, upToV7).migrateWithinTransaction(faulty.userVersion) }
            }
            assertEquals(1, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
        }
    }

    @Test
    fun anOlderAppRefusesTheUpgradedDatabaseAndLeavesItUntouched() = populatedV6().use { db ->
        MigrationRunner(db, upToV7).migrate()
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        assertThrows(MigrationRunner.DowngradeException::class.java) { MigrationRunner(db, upToV6).migrate() }
        assertThrows(MigrationRunner.DowngradeException::class.java) {
            db.transaction { MigrationRunner(db, upToV6).migrateWithinTransaction(db.userVersion) }
        }
        assertEquals(7, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
    }

    /** A fresh install and an upgrade from v6 end with the identical schema text (the migration test compares by (type, name, sql)). */
    @Test
    fun anUpgradeFromV6AndAFreshInstallEndWithTheSameSchema() {
        val fresh = JdbcSqlExecutor().use { db ->
            MigrationRunner(db, upToV7).migrate()
            db.schemaSnapshot()
        }
        populatedV6().use { db ->
            MigrationRunner(db, upToV7).migrate()
            assertEquals(fresh, db.schemaSnapshot())
        }
    }

    /** The statements of v7, in the order the design gives them: step 0 first, then the tables, then the rules. */
    @Test
    fun theStatementsRunInTheDesignedOrder() {
        val statements = v7.statements.map { it.replace(Regex("\\s+"), " ").trim() }
        val firstTable = statements.indexOfFirst { it.startsWith("CREATE TABLE ch_channel") }
        val lastDrop = statements.indexOfLast { it.startsWith("DROP TABLE") }
        val firstTrigger = statements.indexOfFirst { it.startsWith("CREATE TRIGGER") }
        val lastTable = statements.indexOfLast { it.startsWith("CREATE TABLE") }
        assertTrue("step 0 comes first", statements[0].startsWith("CREATE TABLE v7_migration_guard"))
        assertTrue("the guard is dropped before any table is", statements.indexOfFirst { it == "DROP TABLE v7_migration_guard" } < statements.indexOfFirst { it.startsWith("DROP TABLE posts") })
        assertTrue("every drop precedes the first new table", lastDrop < firstTable)
        assertTrue("every table precedes the first rule", lastTable < firstTrigger)
        // The children of the v1 channels go before the parent, so no cascade hides a counted row.
        val order = listOf("posts", "mls_state", "channel_pseudonyms", "channels").map { name -> statements.indexOf("DROP TABLE $name") }
        assertEquals(order.sorted(), order)
        assertTrue(order.all { it >= 0 })
        // The guard counts each of the four tables, once.
        for (table in ChannelSchema.v1Tables) {
            assertEquals(table, 1, statements.count { it == "INSERT INTO v7_migration_guard(row_count) SELECT count(*) FROM $table" })
        }
    }
}
