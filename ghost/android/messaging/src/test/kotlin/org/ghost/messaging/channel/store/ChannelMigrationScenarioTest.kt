package org.ghost.messaging.channel.store

import org.ghost.messaging.channel.ChannelAdmissionTest
import org.ghost.messaging.channel.ChannelWorld
import org.ghost.messaging.store.MessageStore
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.Schema
import org.ghost.storage.SqlExecutor
import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.FixedRandom
import org.ghost.sync.store.ManualClock
import org.ghost.sync.store.SyncStores
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * **SCN-CI** (Phase 10 design §12.5: "a v5 database with live DM and sync rows → v6 → v7, then SCN-CA"), as far as
 * it is a storage scenario (slice S3), and **the storage half of SCN-CA** (channel creation, §6.1) on the
 * database it leaves.
 *
 * The first test migrates a populated v5 database — live DM rows, a live DM namespace and a channel
 * namespace whose send delay v5 allowed to be off, a pending outbox operation, a fetched blob, a registration,
 * entitlement rows — through v6 and v7, with a crash in the middle of v7 and a restart, and requires that
 * every row of every table the migrations keep is exactly as it was (the one row v6 rewrites aside), that the
 * DM stores read their messages afterwards, and that the schema equals a fresh install's. The second creates a
 * channel in **one** `SyncDatabase.transaction` — the namespace, its funding flag, the channel, generation 0,
 * epoch 0, the OpenMLS rows and the box key — and proves that a failure after the sync writes undoes the
 * channel's rows and the sync's together. What SCN-CA proves beyond storage — a real group, a real MLS state —
 * is S4's, with the native library.
 */
class ChannelMigrationScenarioTest {

    private val upToV5 = Schema.migrations.filter { it.version <= 5 }

    /** SCN-CI ends at v7, the version Phase 10 slice S3 wrote it for; migration 8 (Phase 11 slice S3) is applied on top at the end. */
    private val upToV7 = Schema.migrations.filter { it.version <= 7 }
    private val channelNamespace = chBytes(32, 0x40)
    private val dmNamespace = chBytes(32, 0x42)

    private fun onion(i: Int, port: String = "443") = ('a' + i).toString().repeat(56) + ".onion:" + port

    /** A v5 database with a row in every family the later migrations must keep. */
    private fun populatedV5(): JdbcSqlExecutor = JdbcSqlExecutor().also { db ->
        assertEquals(listOf(1, 2, 3, 4, 5), MigrationRunner(db, upToV5).migrate())
        db.exec(
            "INSERT INTO identity(id, public_identity, identity_public_key, derivation_version, created_at) VALUES (1, 'ghost:me', ?, 1, 7)",
            listOf(chBytes(32, 1)),
        )
        for (id in 1..3) {
            db.exec(
                "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) VALUES (?, ?, ?, 'active', 'config')",
                listOf(id, onion(id), chBytes(16, id)),
            )
        }
        val insertNamespace = "INSERT INTO sync_namespace(namespace_id, consumer, listening, send_delay, capability_source) VALUES (?, ?, 1, ?, ?)"
        db.exec(insertNamespace, listOf(dmNamespace, "dm", "on", "redeem"))
        // Legal at v5 and the one row migration 6 rewrites: a channel namespace with the delay off.
        db.exec(insertNamespace, listOf(channelNamespace, "channel", "off", "local"))
        for (ns in listOf(dmNamespace, channelNamespace)) {
            for (relay in 1..2) db.exec("INSERT INTO namespace_relay(namespace_id, relay_id) VALUES (?, ?)", listOf(ns, relay))
        }
        db.exec(
            "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, required_operators, outcome) " +
                "VALUES (?, ?, ?, ?, 604800, 0, 2, 'pending')",
            listOf(chBytes(16, 1), dmNamespace, chBytes(32, 1), chBytes(1024, 1)),
        )
        db.exec("INSERT INTO outbox_delivery(operation_id, relay_id, state, next_attempt_minute) VALUES (?, 1, 'pending', 0)", listOf(chBytes(16, 1)))
        db.exec("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)", listOf(channelNamespace, chBytes(32, 10)))
        db.exec(
            "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, next_attempt_minute) " +
                "VALUES (1, ?, 2870, 'deposit', ?, ?, 'pending', 600)",
            listOf(dmNamespace, chBytes(32, 5), chBytes(16, 5)),
        )
        db.exec("INSERT INTO ent_key(kind, epoch, key_id) VALUES ('access', 726, ?)", listOf(chBytes(32, 3)))
        // the DM tables: a contact, its conversation, a live message with a reaction, a session and a seen tag
        db.exec(
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, expiry_clock_minute) VALUES (1, 0, ?, ?, ?, 60)",
            listOf(chBytes(32, 1), chBytes(60, 2), chBytes(60, 3)),
        )
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'verified', 'link', 'ready')",
            listOf(chBytes(16, 1), chBytes(32, 1), chBytes(159, 1)),
        )
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(chBytes(16, 1), chBytes(16, 1)))
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                "body_env, state, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'sent', 604800, 604800)",
            listOf(chBytes(16, 2), chBytes(16, 1), chBytes(100, 3)),
        )
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                "body_env, state, unread_deadline_minute, delete_at_minute) VALUES (?, ?, 'in', 1, 660, 660, 0, 4, ?, 'unread', 604800, 604800)",
            listOf(chBytes(16, 3), chBytes(16, 1), chBytes(100, 4)),
        )
        db.exec("INSERT INTO dm_reaction(target_id, from_self, grapheme_env) VALUES (?, 1, ?)", listOf(chBytes(16, 2), chBytes(30, 4)))
        db.exec(
            "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env, peer_bind_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 600)",
            listOf(chBytes(16, 1), chBytes(32, 5), chBytes(200, 6)),
        )
        db.exec("INSERT INTO dm_seen(tag, until_day) VALUES (?, 7)", listOf(chBytes(16, 1)))
        assertEquals(5, db.userVersion)
    }

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

    private class FailAtExec(private val delegate: SqlExecutor, private val failAt: Int) : SqlExecutor by delegate {
        var calls = 0
        override fun exec(sql: String, args: List<Any?>) {
            if (calls++ == failAt) throw IllegalStateException("injected failure at statement $failAt")
            delegate.exec(sql, args)
        }
    }

    @Test
    fun scnCiAV5DatabaseWithLiveDmAndSyncRowsGoesToV7WithACrashInTheMiddleAndKeepsEveryRow() {
        // v6 commits, v7 dies halfway through its statements, a restart (the same runner on the same database) finishes it.
        populatedV5().use { db ->
            val before = db.dump()
            assertEquals(2, before.getValue("dm_message").size)
            val v7Statements = Schema.migrations.single { it.version == 7 }.statements.size
            val faulty = FailAtExec(db, Schema.migrations.single { it.version == 6 }.statements.size + v7Statements / 2)
            assertThrows(IllegalStateException::class.java) { MigrationRunner(faulty).migrate() }
            // v6 committed on its own; v7 left no trace: the four v1 channel tables are still there and empty
            assertEquals(6, db.userVersion)
            assertTrue(ChannelNames.v1.all { name -> db.queryString("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(name)) == name })
            assertFalse(db.queryString("SELECT name FROM sqlite_master WHERE name = 'ch_channel'") != null)
            assertThrows(IllegalStateException::class.java) { MigrationRunner(db).verifyIntegrity() }
            // the restart
            assertEquals(listOf(7), MigrationRunner(db, upToV7).migrate())
            assertEquals(7, db.userVersion) // the runner's own integrity check is for the current version (8), asserted below
            val after = db.dump()
            for ((table, rows) in before) {
                if (table in ChannelNames.v1) continue
                if (table == "sync_namespace") continue
                assertEquals(table, rows, after.getValue(table))
            }
            assertEquals(ChannelNames.v1, before.keys - after.keys)
            assertEquals("default", db.queryString("SELECT send_delay FROM sync_namespace WHERE namespace_id = ?", listOf(channelNamespace)))
            assertEquals("on", db.queryString("SELECT send_delay FROM sync_namespace WHERE namespace_id = ?", listOf(dmNamespace)))
            assertNull(db.queryLong("PRAGMA foreign_key_check"))
            // the DM stores read what the DM engine wrote before the upgrade
            val page = MessageStore().conversationPage(db, chBytes(16, 1), 1_200, 10)
            assertEquals(listOf(3, 2), page.map { it.messageId[0].toInt() })
            assertArrayEquals(chBytes(100, 4), page[0].bodyEnv)
            assertEquals(1, MessageStore().unreadCount(db, 1_200))
            // a fresh install of v7 ends with the identical schema text
            val fresh = JdbcSqlExecutor().use { f ->
                MigrationRunner(f, upToV7).migrate()
                f.schemaText()
            }
            assertEquals(fresh, db.schemaText())
            // ... and the same database then takes migration 8 (Phase 11, slice S3): the DM tables it rebuilds keep every row
            // they hold (a message, its reaction, the session, the seen tag), the stores read them as before, and the schema
            // is again a fresh install's.
            val dmRows = { db.dump().filterKeys { it.startsWith("dm_") || it.startsWith("olm_") } }
            val dmBeforeV8 = dmRows()
            assertEquals(listOf(8, 9, 10, 11), MigrationRunner(db).migrate())
            MigrationRunner(db).verifyIntegrity()
            assertEquals(dmBeforeV8, dmRows())
            assertEquals(1L, db.queryLong("SELECT count(*) FROM dm_reaction"))
            assertEquals(listOf(3, 2), MessageStore().conversationPage(db, chBytes(16, 1), 1_200, 10).map { it.messageId[0].toInt() })
            assertNull(db.queryLong("PRAGMA foreign_key_check"))
            val freshV8 = JdbcSqlExecutor().use { f ->
                MigrationRunner(f).migrate()
                f.schemaText()
            }
            assertEquals(freshV8, db.schemaText())
        }
    }

    /**
     * **SCN-CI's group half** (slice S4, §19.37; migration 8 amended by Phase 11 S3, §22.5): the populated v5 database
     * upgraded to the current version (v8 — migration 8 rebuilds the DM tables), then SCN-CA on it — a real MLS
     * group created over the upgraded schema, a member invited, admitted and joined, a post each way — and every DM row
     * as it was before the upgrade.
     */
    @Test
    fun scnCiThenScnCaOnTheUpgradedDatabaseKeepsEveryDmRow() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
        populatedV5().use { db ->
            assertEquals(listOf(6, 7, 8, 9, 10, 11), MigrationRunner(db).migrate())
            val dmTables = setOf("dm_self", "dm_contact", "dm_conversation", "dm_message", "dm_reaction", "olm_session", "dm_seen")
            val before = db.dump().filterKeys { it in dmTables }
            assertEquals(dmTables, before.keys)
            ChannelWorld().use { w ->
                ChannelAdmissionTest.scnCa(w, w.client("owner", db), w.client("bob"))
            }
            assertEquals(before, db.dump().filterKeys { it in dmTables })
            MigrationRunner(db).verifyIntegrity()
        }
    }

    private object ChannelNames {
        val v1 = setOf("channels", "channel_pseudonyms", "mls_state", "posts")
    }

    private fun SqlExecutor.schemaText(): List<String> {
        val out = ArrayList<String>()
        query("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name") { out += "${it.string(0)}|${it.string(1)}|${it.string(2)}" }
        return out
    }

    // ---------------------------------------------------------------- the storage half of SCN-CA

    @Test
    fun scnCaStorageHalfAChannelIsCreatedInOneTransactionWithTheSyncRowsAndAFailureUndoesBoth() {
        populatedV5().use { db ->
            MigrationRunner(db).migrate()
            val sync = SyncDatabase(db)
            val syncStores = SyncStores(sync, ManualClock(1_800_000_000L), FixedRandom()) { PrivacyMode.STANDARD }
            val stores = ChannelStores()
            val channel = chBytes(32, 0xC1)
            val ns0 = NamespaceId(chBytes(32, 0x61))
            val relays = setOf(RelayId(1), RelayId(2))
            val dmRowsBefore = db.dump().filterKeys { it.startsWith("dm_") || it.startsWith("olm_") }

            fun create(failAfterTheChannelRows: Boolean) = sync.transaction { tx ->
                syncStores.namespaces.register(tx, ns0, Consumer.CHANNEL, relays, true, SendDelay.DEFAULT, CapabilitySource.LOCAL)
                syncStores.funding.set(tx, ns0, true)
                stores.channels.insert(
                    tx,
                    ChannelStore.NewChannel(
                        channelId = channel, state = ChannelState.ACTIVE, generation = 0, epoch = 0, joinedEpoch = 0, sizeClass = 0,
                        timerCode = 4, myPseudonym = chBytes(32, 0x50), nameEnv = chBytes(40, 7),
                    ),
                )
                stores.generations.insert(
                    tx, channel, 0, ns0.toByteArray(), GenerationState.CURRENT, chBytes(60, 2), chBytes(60, 3), chBytes(32, 4),
                    openEpoch = 0,
                )
                stores.epochs.insert(tx, channel, 0, chBytes(68, 5), chBytes(32, 6))
                stores.members.insertBoxKey(tx, channel, chBytes(32, 0x70), chBytes(60, 8))
                stores.channels.putSchedule(tx, channel, 20_840, null, null)
                stores.mls.apply(
                    tx, channel,
                    (0 until 11).map { i -> MlsKvStore.KvChange(MlsKvStore.Scope.GROUP, "Tree".toByteArray() + byteArrayOf(0, i.toByte()), chBytes(200, i)) },
                )
                if (failAfterTheChannelRows) error("the creation failed after its writes")
            }

            // a failure after every write: not one row of the sync side or of the channel side stays
            assertThrows(IllegalStateException::class.java) { create(failAfterTheChannelRows = true) }
            assertEquals(2L, db.queryLong("SELECT count(*) FROM sync_namespace"))
            assertEquals(0L, db.queryLong("SELECT count(*) FROM sync_namespace_fund"))
            for (table in listOf("ch_channel", "ch_generation", "ch_epoch", "ch_box_key", "ch_schedule", "mls_kv")) {
                assertEquals(table, 0L, db.queryLong("SELECT count(*) FROM $table"))
            }
            // the same creation without the failure commits all of it
            create(failAfterTheChannelRows = false)
            assertEquals(3L, db.queryLong("SELECT count(*) FROM sync_namespace"))
            assertEquals(1L, db.queryLong("SELECT count(*) FROM sync_namespace_fund"))
            assertEquals(ChannelState.ACTIVE, stores.channels.channel(db, channel)!!.state)
            assertEquals(ns0.toByteArray().toList(), stores.generations.current(db, channel, 20_833)!!.namespaceId.toList())
            assertArrayEquals(channel, stores.generations.route(db, ns0.toByteArray(), 20_833)!!.channelId)
            assertEquals(0L, stores.epochs.open(db, channel, 20_833)!!.epoch)
            assertEquals(11, stores.mls.groupRowCount(db, channel))
            assertEquals(1, stores.members.boxKeys(db, channel, 20_833).size)
            // nothing the DM engine owns was touched, and the foreign keys hold
            assertEquals(dmRowsBefore, db.dump().filterKeys { it.startsWith("dm_") || it.startsWith("olm_") })
            assertNull(db.queryLong("PRAGMA foreign_key_check"))
            // a repeat of the creation is refused by the stores (the channel exists) and the sync side with it
            assertThrows(IllegalStateException::class.java) { create(failAfterTheChannelRows = false) }
            assertEquals(3L, db.queryLong("SELECT count(*) FROM sync_namespace"))
            // deleting the channel (the wipe, §6.12) removes every channel row; the namespace is the sync engine's to remove
            sync.transaction { tx -> assertTrue(stores.channels.delete(tx, channel)) }
            assertEquals(0L, db.queryLong("SELECT count(*) FROM ch_epoch") ?: 0L)
            assertEquals(0L, db.queryLong("SELECT count(*) FROM mls_kv") ?: 0L)
        }
    }
}
