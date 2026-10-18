package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Migration 6 (Phase 10 design §9, "Migration 6 (`:sync`)"; slice S1a) on a **populated v5
 * database**: the funding flag, the registration capabilities, the channel send-delay rule and the
 * guards arrive without touching a row of any table v5 has, and an interruption at any statement
 * leaves v5 as it was.
 *
 * What each new object enforces by itself is tested where its family is: the CHECKs and the cascades
 * in [SyncSchemaConstraintsTest], the REPLACE guards in [ReplaceGuardsTest], the time column in
 * [DmSchemaIntrospectionTest] and the version lists in [SchemaAndMigrationTest]. This class is about
 * the **upgrade**: which rows exist before and after, in which state, and what a crash in the middle
 * leaves behind.
 */
class Migration6Test {
    private val upToV5 = Schema.migrations.filter { it.version <= 5 }
    private val upToV6 = Schema.migrations.filter { it.version <= 6 }
    private val v6 = Schema.migrations.single { it.version == 6 }

    /**
     * What `verifyIntegrity` asserts, for a database at v6: this class tests migration 6 on its own, and
     * the runner's check is against the **current** schema (v7 has since dropped four tables and added
     * 26, v8 dropped two and added five), so a v6 database is verified against the objects of v1 to v6 and
     * the version it is at.
     */
    private fun verifyAtV6(db: SqlExecutor) {
        assertEquals(6, db.userVersion)
        val tables = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { tables += it.string(0) }
        val triggers = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'") { triggers += it.string(0) }
        // v9 (Phase 12 transports §6.3) has not run at v6: its table is part of the current schema,
        // so the v6 expectation subtracts it exactly like the v7/v8 families.
        val expectedTables = Schema.expectedTables - ChannelSchema.tables - MediaSchema.tables - setOf("transport_bridge") +
            ChannelSchema.v1Tables + MediaSchema.v1Tables
        val expectedTriggers = Schema.expectedTriggers - ChannelSchema.rules - ChannelSchema.guards - ChannelSchema.rowidChecks -
            MediaSchema.rules - MediaSchema.guards
        assertEquals(emptySet<String>(), expectedTables - tables)
        assertEquals(emptySet<String>(), expectedTriggers - triggers)
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

    private val channelOff = bytes(32, 0x40)
    private val mediaOff = bytes(32, 0x41)
    private val dmOn = bytes(32, 0x42)
    private val dmDefault = bytes(32, 0x43)
    private val bundle = bytes(32, 0x44)

    /**
     * A database exactly at v5 with a row in every family v6 relies on or must leave alone: the v1
     * survivors, the sync tables (a channel namespace and a media namespace that turned the send delay
     * off, which v5 allows for both), a registration pair and a deferred fetched blob, the entitlement
     * tables and the DM tables.
     */
    private fun populatedV5(): JdbcSqlExecutor = JdbcSqlExecutor().also { db ->
        assertEquals(listOf(1, 2, 3, 4, 5), MigrationRunner(db, upToV5).migrate())
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, 'ghost:me', ?, 1, 7)",
            listOf(bytes(32, 1)),
        )
        db.exec("INSERT INTO invite_nonces(nonce, seen_at) VALUES (?, 10)", listOf(bytes(16, 7)))
        for (id in 1..3) {
            db.exec(
                "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (?, ?, ?, 'active', 'config')",
                listOf(id, onion(id), bytes(16, id)),
            )
        }
        val insertNamespace = "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay, capability_source) VALUES (?, ?, ?, ?, ?)"
        db.exec(insertNamespace, listOf(dmOn, "dm", 1, "on", "redeem"))
        db.exec(insertNamespace, listOf(dmDefault, "dm", 1, "default", "local"))
        db.exec(insertNamespace, listOf(bundle, "prekeys", 0, "default", "redeem"))
        // Legal at v5, and the only rows migration 6 changes: a channel and a media namespace with the delay off.
        db.exec(insertNamespace, listOf(channelOff, "channel", 1, "off", "local"))
        db.exec(insertNamespace, listOf(mediaOff, "media", 1, "off", "redeem"))
        for (ns in listOf(dmOn, channelOff)) {
            for (relay in 1..2) db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, ?)", listOf(ns, relay))
        }
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, expires_hour, state, generation) VALUES (1, ?, 'write', ?, ?, 'usable', 3)",
            listOf(channelOff, bytes(82, 1), 3600L * 500_000),
        )
        db.exec(
            "INSERT INTO relay_capability(relay_id, namespace_id, kind, token, state, generation) VALUES (2, ?, 'read', ?, 'rejected', 7)",
            listOf(channelOff, bytes(82, 2)),
        )
        db.exec("INSERT INTO relay_cursor(relay_id, namespace_id, cursor) VALUES (1, ?, ?)", listOf(dmOn, bytes(8, 1)))
        db.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
                "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
            listOf(opId(1), dmOn, hash(1), bytes(1024, 1)),
        )
        db.exec("INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, 1, 'pending', 0)", listOf(opId(1)))
        // A fetched blob of the channel namespace that a consumer deferred, one listed and one consumed.
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(channelOff, hash(10)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(channelOff, hash(11)))
        db.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 1, offer_after_minute = 360000, relay_expiry_hour = 3600 " +
                "WHERE blob_hash = ?",
            listOf(bytes(1024, 11), hash(11)),
        )
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', 14)", listOf(channelOff, hash(12)))
        db.exec(
            "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, next_attempt_minute) " +
                "VALUES (1, ?, 2870, 'deposit', ?, ?, 'pending', 600)",
            listOf(dmOn, bytes(32, 5), bytes(16, 5)),
        )
        db.exec(
            "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, next_attempt_minute, valid_until_hour) " +
                "VALUES (2, ?, 2870, 'read', ?, ?, 'done', 600, 7200)",
            listOf(dmOn, bytes(32, 6), bytes(16, 6)),
        )
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', 726, ?)", listOf(bytes(32, 3)))
        db.exec("INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES ('slots', 726, ?)", listOf(bytes(32, 4)))
        db.exec(
            "INSERT INTO ent_state(id, schedule_seq, schedule_digest, payout_salt) VALUES (1, 1, ?, ?)",
            listOf(bytes(32, 4), bytes(32, 8)),
        )
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
        db.exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, 7)", listOf(bytes(16, 1)))
        assertEquals(5, db.userVersion)
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

    private fun SqlExecutor.sendDelay(ns: ByteArray): String =
        queryString("SELECT send_delay FROM sync_namespace WHERE namespace_id = ?", listOf(ns))!!

    @Test
    fun aPopulatedV5DatabaseKeepsEveryRowAndGainsTheNewObjects() = populatedV5().use { db ->
        val before = db.dump()
        assertTrue("the fixture must be populated", before.getValue("sync_namespace").size == 5 && before.getValue("inbox_blob").size == 3)
        assertEquals(listOf(6), MigrationRunner(db, upToV6).migrate())
        verifyAtV6(db)
        val after = db.dump()
        // Every table v5 has holds exactly the rows it held, except the one row of step 0 ...
        for ((table, rows) in before) {
            if (table == "sync_namespace") continue
            assertEquals(table, rows, after.getValue(table))
        }
        // ... which is the channel namespace that had the delay off; the media namespace is another consumer's and keeps it.
        assertEquals("default", db.sendDelay(channelOff))
        assertEquals("off", db.sendDelay(mediaOff))
        assertEquals("on", db.sendDelay(dmOn))
        assertEquals("default", db.sendDelay(dmDefault))
        assertEquals(
            before.getValue("sync_namespace").size,
            after.getValue("sync_namespace").size,
        )
        val unchanged = before.getValue("sync_namespace").toSet() - after.getValue("sync_namespace").toSet()
        assertEquals("exactly one namespace row changed", 1, unchanged.size)
        // The two new tables exist and are empty; nothing was funded or installed by the migration.
        assertEquals(setOf("sync_namespace_fund", "relay_register_capability"), after.keys - before.keys)
        assertEquals(emptyList<String>(), after.getValue("sync_namespace_fund"))
        assertEquals(emptyList<String>(), after.getValue("relay_register_capability"))
        assertNull(db.queryLong("PRAGMA foreign_key_check"))
        assertEquals("ok", db.queryString("PRAGMA integrity_check"))
        // The blob a consumer deferred is as it was (its re-offer is the consumer's call, not the migration's).
        assertEquals(
            360000L,
            db.queryLong("SELECT offer_after_minute FROM inbox_blob WHERE state = 'fetched'"),
        )
    }

    @Test
    fun theNewTriggersAndGuardsHoldOnTheUpgradedDatabase() = populatedV5().use { db ->
        MigrationRunner(db, upToV6).migrate()
        // The rule is about rows now: the upgraded channel namespace cannot be set back to off, and neither can a new one.
        db.rejects("Channel namespaces cannot turn the send delay off", "UPDATE sync_namespace SET send_delay = 'off' WHERE namespace_id = ?", channelOff)
        db.rejects(
            "Channel namespaces cannot turn the send delay off",
            "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay) VALUES (?, 'channel', 1, 'off')",
            bytes(32, 0x50),
        )
        // The v4 rule is untouched, and the other consumers keep the override.
        db.rejects(
            "DM namespaces cannot turn the send delay off",
            "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay) VALUES (?, 'dm', 1, 'off')",
            bytes(32, 0x51),
        )
        assertEquals(1, db.changes("UPDATE sync_namespace SET send_delay = 'on' WHERE namespace_id = ?", channelOff))
        assertEquals(1, db.changes("UPDATE sync_namespace SET send_delay = 'off' WHERE namespace_id = ?", bundle))
        // The flag and the capability of a namespace the v5 database already holds.
        db.exec("INSERT INTO sync_namespace_fund(namespace_id) VALUES (?)", listOf(channelOff))
        db.exec(
            "INSERT INTO relay_register_capability(relay_id, namespace_id, token, expires_hour, state, generation) VALUES (1, ?, ?, 7200, 'usable', 1)",
            listOf(channelOff, bytes(82, 9)),
        )
        // The write capability the namespace holds is another table's row: the new table did not read it.
        assertEquals(1L, db.queryLong("SELECT count(*) FROM relay_capability WHERE kind = 'write' AND namespace_id = ?", listOf(channelOff)))
        assertEquals(1L, db.queryLong("SELECT count(*) FROM relay_register_capability"))
    }

    /**
     * The migration's own failure modes (CS-9): an interruption at every one of its statements, and at
     * the version bump, leaves the populated v5 database untouched — schema text, every row, version —
     * and the next run succeeds with the same result as an uninterrupted one.
     */
    @Test
    fun anInterruptionAtAnyStatementLeavesThePopulatedV5Untouched() {
        val expected = populatedV5().use { db ->
            MigrationRunner(db, upToV6).migrate()
            Pair(db.schemaSnapshot(), db.dump())
        }
        for (i in v6.statements.indices) {
            populatedV5().use { db ->
                val schema = db.schemaSnapshot()
                val rows = db.dump()
                val faulty = FailAtExec(db, i)
                assertThrows("statement $i", IllegalStateException::class.java) { MigrationRunner(faulty, upToV6).migrate() }
                assertEquals("statement $i ran", i + 1, faulty.calls)
                assertEquals("statement $i", 5, db.userVersion)
                assertEquals("statement $i", schema, db.schemaSnapshot())
                assertEquals("statement $i", rows, db.dump())
                assertFalse(db.inTransaction)
                // A half-migrated database is refused, never used; then the same runner finishes the job.
                assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
                assertEquals("statement $i", listOf(6), MigrationRunner(db, upToV6).migrate())
                verifyAtV6(db)
                assertEquals("statement $i", expected.first, db.schemaSnapshot())
                assertEquals("statement $i", expected.second, db.dump())
            }
        }
        populatedV5().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            assertThrows(IllegalStateException::class.java) { MigrationRunner(FailOnVersionBump(db, 6), upToV6).migrate() }
            assertEquals(5, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
            assertEquals(listOf(6), MigrationRunner(db, upToV6).migrate())
            assertEquals(expected.second, db.dump())
        }
    }

    /** The open helper's path: every pending migration in the caller's transaction, rolled back together on a failure. */
    @Test
    fun theOpenHelperPathUpgradesInsideTheCallersTransactionAndRollsBackOnAFailure() {
        fun helperOpen(db: SqlExecutor): List<Int> = db.transaction {
            val applied = MigrationRunner(db, upToV6).migrateWithinTransaction(db.userVersion)
            db.userVersion = 6
            applied
        }
        populatedV5().use { db ->
            assertEquals(listOf(6), helperOpen(db))
            verifyAtV6(db)
            assertEquals("default", db.sendDelay(channelOff))
        }
        populatedV5().use { db ->
            val schema = db.schemaSnapshot()
            val rows = db.dump()
            // A statement of v6 that fails undoes the statements before it (step 0's UPDATE among them).
            val faulty = FailAtExec(db, v6.statements.size - 1)
            assertThrows(IllegalStateException::class.java) {
                faulty.transaction { MigrationRunner(faulty, upToV6).migrateWithinTransaction(faulty.userVersion) }
            }
            assertEquals(5, db.userVersion)
            assertEquals(schema, db.schemaSnapshot())
            assertEquals(rows, db.dump())
            assertEquals("off", db.sendDelay(channelOff))
        }
    }

    @Test
    fun anOlderAppRefusesTheUpgradedDatabaseAndLeavesItUntouched() = populatedV5().use { db ->
        MigrationRunner(db, upToV6).migrate()
        val schema = db.schemaSnapshot()
        val rows = db.dump()
        assertThrows(MigrationRunner.DowngradeException::class.java) { MigrationRunner(db, upToV5).migrate() }
        assertThrows(MigrationRunner.DowngradeException::class.java) {
            db.transaction { MigrationRunner(db, upToV5).migrateWithinTransaction(db.userVersion) }
        }
        assertEquals(6, db.userVersion)
        assertEquals(schema, db.schemaSnapshot())
        assertEquals(rows, db.dump())
    }

    /**
     * R-M1, R-M3 and R-M4 in the shape the Phase 9 introspection tests use, over the two new tables
     * (Phase 10 design §9, "Migration 6"): the columns are exactly the ones the design lists — a flag
     * and a capability, nothing that records when it was funded or used —, the keys, foreign keys and
     * cascades are the specified ones, both tables are WITHOUT ROWID, and the only object attached to
     * either is its REPLACE guard.
     */
    @Test
    fun theTwoNewTablesHaveExactlyTheShapeOfSectionNine() = JdbcSqlExecutor().use { db ->
        MigrationRunner(db).migrate()
        class Column(val name: String, val type: String, val notNull: Boolean, val pk: Int)
        fun columns(table: String): List<Column> {
            val out = ArrayList<Column>()
            db.query("PRAGMA table_info($table)") { out += Column(it.string(1), it.string(2), it.long(3) == 1L, it.long(5).toInt()) }
            return out
        }
        fun foreignKeys(table: String): List<String> {
            val out = ArrayList<String>()
            db.query("PRAGMA foreign_key_list($table)") { out += "${it.string(3)} -> ${it.string(2)}.${it.string(4)} on delete ${it.string(6)}" }
            return out.sorted()
        }
        fun objectsOn(table: String): List<String> {
            val out = ArrayList<String>()
            db.query("SELECT type, name FROM sqlite_master WHERE tbl_name = ? AND type <> 'table' ORDER BY type, name", listOf(table)) {
                out += "${it.string(0)} ${it.string(1)}"
            }
            return out
        }
        fun createSql(table: String): String =
            db.queryString("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table))!!.replace(Regex("\\s+"), " ")

        assertEquals(listOf("namespace_id:BLOB:true:1"), columns("sync_namespace_fund").map { "${it.name}:${it.type}:${it.notNull}:${it.pk}" })
        assertEquals(listOf("namespace_id -> sync_namespace.namespace_id on delete CASCADE"), foreignKeys("sync_namespace_fund"))
        assertEquals(
            listOf(
                "relay_id:INTEGER:true:1", "namespace_id:BLOB:true:2", "token:BLOB:true:0",
                "expires_hour:INTEGER:false:0", "state:TEXT:true:0", "generation:INTEGER:true:0",
            ),
            columns("relay_register_capability").map { "${it.name}:${it.type}:${it.notNull}:${it.pk}" },
        )
        assertEquals(
            listOf(
                "namespace_id -> sync_namespace.namespace_id on delete CASCADE",
                "relay_id -> relay_directory.relay_id on delete CASCADE",
            ),
            foreignKeys("relay_register_capability"),
        )
        for (table in listOf("sync_namespace_fund", "relay_register_capability")) {
            assertTrue("$table is WITHOUT ROWID", createSql(table).trimEnd().endsWith("WITHOUT ROWID"))
            assertEquals("nothing but the REPLACE guard hangs on $table", listOf("trigger ${table}_no_replace"), objectsOn(table))
        }
        // R-M4: neither is, nor names, a virtual table (the whole-schema check is DmSchemaIntrospectionTest's).
        for (table in listOf("sync_namespace_fund", "relay_register_capability")) {
            assertFalse(createSql(table).uppercase().contains("VIRTUAL"))
        }
        // The channel send-delay rule hangs on sync_namespace beside the DM rule of v4 and nothing else is new there.
        assertEquals(
            listOf(
                "trigger sync_namespace_channel_delay_insert", "trigger sync_namespace_channel_delay_update",
                "trigger sync_namespace_dm_delay", "trigger sync_namespace_dm_delay_insert",
            ),
            objectsOn("sync_namespace").filter { it.startsWith("trigger") },
        )
    }

    /** A fresh install and an upgrade from v5 end with the identical schema text (the migration test compares by (type, name, sql)). */
    @Test
    fun anUpgradeFromV5AndAFreshInstallEndWithTheSameSchema() {
        val fresh = JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            db.schemaSnapshot()
        }
        populatedV5().use { db ->
            MigrationRunner(db).migrate()
            assertEquals(fresh, db.schemaSnapshot())
        }
    }
}
