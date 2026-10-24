package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **R-M3 and R-M4 over the whole database** (Phase 9 design §13.6, T20, T33), slice S5.
 *
 * Three tests of this file already exist in narrower form, and this one does not replace them:
 * `SchemaIntrospectionTest` (`:sync`) pins the 15 sync time columns, `EntitlementSchemaIntrospectionTest`
 * the 14 entitlement ones, and [Migration5Test.theTimeColumnsAreExactlyTheOnesTheDesignLists] the
 * 24 that migration 5 adds. Each of those looks at **its own** tables, so a time column added to a
 * table none of them owns — a v1 survivor, a table a future migration adds — is invisible to all
 * three. R-M3's sentence is "a test lists every column of **every** table and fails on any other
 * time-like name", and that is what runs here: the corpus is `sqlite_master`, not a list of table
 * names, so a new table is covered the day it is created.
 *
 * Every column whose name looks like a time must therefore be in one of four declared sets:
 *
 *  - [timeColumnsOfMigration4] and [timeColumnsOfMigration5], the exact enumeration R-M3 gives;
 *  - [ChannelSchema.timeColumns], [ChannelSchema.epochColumns] and [ChannelSchema.notTimes], the 35 time
 *    columns, the nine epoch counters and the two timer codes migration 7 adds (Phase 10 design §9;
 *    [ChannelSchemaIntrospectionTest] owns what each of them enforces, and this test only requires that
 *    the whole database holds nothing else);
 *  - [timeColumnsBeforeV4], the ones v1, v2 and v3 already carried, each pinned by its own
 *    subsystem test — repeated here only so this test's corpus can be the whole database;
 *  - [periodIndices], integers naming a cell of a grid (a week, an epoch, a period) rather than a
 *    point in time, plus the rank and the random generation ids R-M3 names beside them, each of
 *    which must carry a `typeof(x) = 'integer'` CHECK;
 *  - [notTimes], counters, durations and codes whose name happens to contain one of the rule's
 *    words. Each entry is justified, and each is asserted to be **used**: an exemption that stops
 *    matching anything is removed, so it can never cover a column added later.
 *
 * Every set is asserted to be exactly the set found, in both directions: an undeclared time
 * column fails, and so does a declared one that no longer exists.
 */
class DmSchemaIntrospectionTest {

    /**
     * The Phase 7 time-name rule (`:sync` `SchemaIntrospectionTest`) widened by R-M3's own words
     * with `minute`, `hour`, `day` and `week`, so a column called `week` or `hour_of_use` matches
     * wherever it sits and not only when it ends in the suffix the schema convention uses.
     */
    private val timeLike = Regex("(minute|hour|day|week|_at$|time|date|epoch|_ms$|_seconds$|expir|_ts$|stamp|last_|since|until)")

    /** §13.6 steps 2 and 4: the four time columns migration 4 adds (the sync set grows 11 -> 15). */
    private val timeColumnsOfMigration4 = setOf(
        "inbox_blob.relay_expiry_hour",
        "relay_key_registration.lease_hour",
        "relay_key_registration.next_attempt_minute",
        "relay_key_registration.valid_until_hour",
    )

    /**
     * Phase 10 design §9, "Migration 6" (slice S1a): the one time column migration 6 adds, the floored
     * expiry of a registration capability (the sync set grows 15 -> 16). It follows the v4 and v5 rule:
     * granularity and `typeof` in one CHECK.
     */
    private val timeColumnsOfMigration6 = setOf("relay_register_capability.expires_hour")

    /**
     * Phase 12 design §6.3's one time-like column (slice S2): `transport_bridge.added_day`, the
     * day index (T33: a day index, not an epoch-aligned column, so the CHECK pins `typeof` and the
     * range, not a `% 86400` grid — the same shape as `dm_seen.until_day` and `ch_seen.until_day`,
     * which are day indices of their own families).
     */
    private val timeColumnsOfMigration9 = setOf("transport_bridge.added_day")

    /** Phase 13 UX (faza13-ux.md §10): the crash report's day index — day-granular by design,
     * no finer column exists in the UI's tables (T33's §10 half). */
    private val timeColumnsOfMigration10 = setOf("ui_crash.day")

    /**
     * The integer counter of migration 6 that is no time and no period index: the capability's
     * generation, the rejection race guard of Phase 7 §3.8. Its name matches none of the rule's words,
     * so only the executed test below finds it; it is declared so that a REAL cannot be stored in it.
     */
    private val countersOfMigration6 = setOf("relay_register_capability.generation")

    /**
     * The one integer counter of migration 8's Q27 fold (faza11-media.md §22.5 row 22): the
     * reschedule bound of faza9-dm.md §21.8 point 4, added by `ALTER TABLE` because `dm_scheduled`
     * is not one of the five rebuilt tables. Its name matches none of [timeLike]'s words — the
     * executed case below is what pins its `typeof` CHECK.
     */
    private val countersOfMigration8 = setOf("dm_scheduled.attempts")

    /** §13.6 steps 5 and 6: the 24 time columns migration 5 adds, verbatim from R-M3. */
    private val timeColumnsOfMigration5 = setOf(
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

    /**
     * What the database already carried when Phase 9 started: the 9 of the v1 tables that survive
     * migration 4, the 11 pre-v4 sync columns (`:sync` `SchemaIntrospectionTest`) and the 14
     * entitlement ones (`EntitlementSchemaIntrospectionTest`). Listed, not exempted: R-M3's claim
     * is about every column of every table, and a set that stopped at the DM tables would let the
     * next `last_activity_minute` (mutant PM-10) land one table to the left.
     */
    private val timeColumnsBeforeV4 = setOf(
        // v1 survivors (Phases 3-6). The `*_at` columns are second-granular and predate ADR-08; they
        // are declared, not endorsed, and no DM code reads them. (`channels`, `mls_state` and `posts`
        // and their columns are gone since migration 7, `channels.current_epoch` with them.)
        "identity.created_at", "devices.added_at", "devices.revoked_at",
        "invite_nonces.seen_at", "revocations.received_at",
        // v2 sync (Phase 7 §11.2 #8)
        "relay_directory.retired_day", "relay_capability.expires_hour",
        "outbox_op.not_before_minute", "outbox_op.deadline_hour",
        "outbox_delivery.next_attempt_minute", "outbox_delivery.lease_hour",
        "outbox_delivery.copy_hour", "outbox_delivery.ack_minute",
        "inbox_blob.next_fetch_minute", "inbox_blob.offer_after_minute", "inbox_blob.retain_until_day",
        // v3 entitlement (Phase 8 §11.3, §19.15, §19.29)
        "ent_state.restore_scan_until_day", "ent_state.payment_shown_minute",
        "ent_purchase.created_hour", "ent_purchase.receipt_minute", "ent_purchase.next_due_minute",
        "ent_purchase.terminal_day", "ent_token.eligible_minute",
        "ent_invite.listen_until_day", "ent_invite.refresh_minute",
        "ent_drop_target.drop_minute", "ent_drop_target.until_day",
        "ent_claim.next_due_minute", "ent_claim.terminal_day", "ent_payout_used.until_day",
    )

    /**
     * R-M3's third list: the period indices, the rank and the random generation ids. None of them
     * is a point in time — a week index names a cell of the grid of §4.1, a `gen_id` is 32 random
     * bits — and all of them are integers with a `typeof` CHECK (§21.14), which is what stops
     * SQLite's `%` from casting a REAL to INTEGER and admitting a finer value than the column's
     * granularity claims.
     *
     * This set is deliberately **wider** than the sentence R-M3 writes, and §22.10 item 4 records
     * why. Beside the columns R-M3 names it carries the three `ent_*` epochs and
     * `ent_purchase.base_week` — the v3 grid indices, under the same rule since Phase 8 (§19.17) —
     * and `dm_pair_key.root_gen` and `dm_pair_offer.root_gen`, 0..65535 pair-root generation
     * indices that migration 5 gives the same `typeof` CHECK and that R-M3's enumeration omits. A
     * set that stopped at R-M3's words would leave nothing enforcing those six CHECKs.
     */
    private val periodIndices = setOf(
        "dm_self.bundle_week", "dm_bundle_candidate.bundle_week", "dm_outbound_op.bundle_week",
        "olm_prekey_gen.bundle_week", "dm_peer_pq.bundle_week",
        "dm_contact.bundle_week_seen", "dm_self.bundle_published_week", "dm_contact.pq_announced_week",
        "dm_pair_key.week", "dm_pair_offer.base_week", "relay_key_registration.period_id",
        "dm_bundle_candidate.bundle_rank",
        "dm_held.gen_id", "olm_prekey_gen.gen_id", "olm_prekey_used.gen_id", "dm_peer_pq.gen_id",
        "olm_session.peer_gen_id",
        // The pair-root generation index, 0..65535 (§9.4); R-M3's sentence does not name it.
        "dm_pair_key.root_gen", "dm_pair_offer.root_gen",
        // v3 grid indices (Phase 8 §19.17, §19.20 point 1)
        "ent_key.epoch", "ent_schedule_fact.epoch", "ent_token.epoch", "ent_purchase.base_week",
    )

    /**
     * The four v3 grid indices above are **executed** — a REAL literal refused, a whole one stored
     * as an integer — by `EntitlementSchemaConstraintsTest.timesAndGridIndicesAreWholeIntegers`,
     * which owns the entitlement fixtures. [everyTypedColumnRefusesAFractionalValue] covers the v4
     * and v5 columns and names these as delegated rather than repeating those fixtures.
     */
    private val executedByTheEntitlementSuite = setOf(
        "ent_key.epoch", "ent_schedule_fact.epoch", "ent_token.epoch", "ent_purchase.base_week",
    )

    /**
     * `olm_prekey_used.gen_id` is the one member of [periodIndices] without a `typeof` CHECK of
     * its own, and this is the recorded reason (design §22.10 item 2). It is a foreign key to
     * `olm_prekey_gen.gen_id`, which has the CHECK; the column has INTEGER affinity, so SQLite
     * stores `'7'` and `7.0` as the integer 7 and leaves only a value with a fractional part
     * un-coerced — and such a value matches no parent row, so the foreign key refuses it. The
     * exemption is proved, not asserted: [theReuseTupleInheritsItsTypeFromItsParentGeneration]
     * inserts the fractional id and watches the foreign key reject it.
     */
    private val typeofCheckedByForeignKey = setOf("olm_prekey_used.gen_id")

    /**
     * Counters, durations and codes whose **name** contains one of the rule's words while the
     * value is not a time. Each is justified here and each must still match, or it is removed.
     */
    private val notTimes = mapOf(
        // Phase 7 §11.2 #8: a TTL bucket is a duration, not a point in time. (The `*attempts`
        // counters the `:sync` test exempts do not appear here: no word of the rule matches them.)
        "outbox_op.ttl_seconds" to "a TTL bucket in seconds, a duration",
        // Q27/S3b: the relay TTL bucket the outbound item's send committed — R-T3's larger of the
        // old and the new for a TIMER_SET — kept with the pending item; a duration, like
        // `outbox_op.ttl_seconds` and `media_upload.ttl_seconds`, not a point in time.
        "dm_outbound_item.ttl_seconds" to "the item's TTL bucket in seconds, a duration",
        // Phase 9 §7.5: the position of a message inside its author minute, not a second.
        "dm_message.minute_index" to "the index of a message within its author minute, never a finer time",
        // Phase 9 §9.1: a timer is a bucket code (0..5) and a version counter, not a time. This is
        // what R-M1 keeps after every message has expired, and it says nothing about when.
        "dm_conversation.timer_code" to "the disappearing-timer bucket code, 0..5",
        // Phase 13 UX (faza13-ux.md §10, Q5): the lock timeout CHOICE (0/60/300/1800 s), a
        // setting like the theme, not a point in time and never of activity (T33).
        "ui_settings.lock_timeout_s" to "the lock-timeout choice in seconds, a setting, not a time",
        "dm_conversation.timer_version" to "the timer's version counter, monotone, not a time",
        "dm_message.timer_code" to "the bucket code the message was written under",
    )

    private fun tables(db: JdbcSqlExecutor): List<String> {
        val out = ArrayList<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name") {
            out += it.string(0)
        }
        return out
    }

    private fun columns(db: JdbcSqlExecutor, table: String): List<String> {
        val out = ArrayList<String>()
        db.query("PRAGMA table_info($table)") { out += it.string(1) }
        return out
    }

    private fun createSql(db: JdbcSqlExecutor, table: String): String {
        var sql = ""
        db.query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", listOf(table)) { sql = it.string(0) }
        return sql.replace(Regex("\\s+"), " ")
    }

    private fun migrated(): JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }

    @Test
    fun everyTimeLikeColumnOfEveryTableIsOneTheDesignDeclares() = migrated().use { db ->
        val declared = timeColumnsOfMigration4 + timeColumnsOfMigration5 + timeColumnsOfMigration6 +
            timeColumnsOfMigration9 + timeColumnsOfMigration10 + timeColumnsBeforeV4 + ChannelSchema.timeColumns + MediaSchema.timeColumns + UpdateSchema.timeColumns
        val indices = periodIndices + ChannelSchema.epochColumns
        val exempt = notTimes + ChannelSchema.notTimes + MediaSchema.notTimes + UpdateSchema.notTimes
        val foundTimes = HashSet<String>()
        val foundIndices = HashSet<String>()
        val usedExemptions = HashSet<String>()
        val undeclared = ArrayList<String>()
        val scanned = tables(db)
        assertTrue("no tables were scanned; the corpus would be empty", scanned.size >= 40)
        for (table in scanned) {
            for (column in columns(db, table)) {
                val qualified = "$table.$column"
                if (!timeLike.containsMatchIn(column.lowercase())) continue
                when (qualified) {
                    in declared -> foundTimes += qualified
                    in indices -> foundIndices += qualified
                    in exempt -> usedExemptions += qualified
                    else -> undeclared += qualified
                }
            }
        }
        assertEquals("undeclared time-like columns (R-M3)", emptyList<String>(), undeclared.sorted())
        // In the other direction: a declared column that no longer exists is removed, so the lists
        // cannot drift into decoration. Only the period indices whose *name* trips the rule can be
        // found by this scan — `period_id`, `bundle_rank` and the `gen_id`s do not — and
        // [everyPeriodIndexRankAndRandomIdIsIntegerTyped] is where all of them are required to exist.
        val namedLikeATime = indices.filter { timeLike.containsMatchIn(it.substringAfter('.').lowercase()) }.toSet()
        assertEquals("declared time columns that no table has", declared, foundTimes)
        assertEquals("declared period indices that no table has", namedLikeATime, foundIndices)
        assertEquals("exemptions that match nothing", exempt.keys, usedExemptions)
    }

    /**
     * §13.6 and §21.14: the granularity of a time column is enforced by a CHECK, and the CHECK is
     * paired with `typeof(x) = 'integer'` wherever the migration that created it writes one —
     * `%` casts a REAL to INTEGER before taking the remainder, so `x % 60 = 0` alone would accept
     * a value finer than a minute. Migrations 4 and 5 write the pair on every column they add;
     * the v1 and v2 columns predate the rule and are checked for their granularity only.
     */
    @Test
    fun everyTimeColumnCarriesItsGranularityCheck() = migrated().use { db ->
        val v4AndV5 = timeColumnsOfMigration4 + timeColumnsOfMigration5 + timeColumnsOfMigration6
        for (qualified in v4AndV5 + timeColumnsBeforeV4) {
            val (table, column) = qualified.split(".")
            val sql = createSql(db, table)
            assertTrue("missing table $table", sql.isNotEmpty())
            when {
                column.endsWith("_minute") -> assertTrue("$qualified needs % 60 = 0", sql.contains("$column % 60 = 0"))
                column.endsWith("_hour") -> assertTrue("$qualified needs % 3600 = 0", sql.contains("$column % 3600 = 0"))
                column.endsWith("_day") ->
                    assertTrue("$qualified needs a CHECK", Regex("CHECK \\([^)]*\\b$column\\b").containsMatchIn(sql))
                // `posts.expires_at`, `identity.created_at` and the other v1 columns are
                // second-granular and predate ADR-08; they carry no CHECK and none is added here.
                else -> assertTrue("$qualified is a pre-v4 column without a granularity suffix", qualified in timeColumnsBeforeV4)
            }
            if (qualified in v4AndV5) {
                assertTrue("$qualified needs typeof($column) = 'integer'", sql.contains("typeof($column) = 'integer'"))
            }
        }
    }

    /** R-M3: every period index, the rank and every random generation id is integer-typed. */
    @Test
    fun everyPeriodIndexRankAndRandomIdIsIntegerTyped() = migrated().use { db ->
        for (qualified in periodIndices - typeofCheckedByForeignKey) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified does not exist", column in columns(db, table))
            val sql = createSql(db, table)
            assertTrue("$qualified needs typeof($column) = 'integer'", sql.contains("typeof($column) = 'integer'"))
        }
        // The one exemption is declared, and it really is a foreign key (§22.10 item 2).
        for (qualified in typeofCheckedByForeignKey) {
            val (table, column) = qualified.split(".")
            assertTrue("$qualified does not exist", column in columns(db, table))
            assertTrue(
                "$qualified is exempt because it is a foreign key, and it is not one",
                Regex("\\b$column\\b[^,]*REFERENCES").containsMatchIn(createSql(db, table)),
            )
        }
    }

    // ------------------------------------------------- the CHECKs executed, not read as text

    /**
     * One `typeof`-guarded column with a statement that writes it. `{v}` stands for the value:
     * the test writes it first as `x.5`, which the `typeof` CHECK must refuse, and then as `x.0`,
     * which INTEGER affinity coerces, so the column must end up holding an integer. `{d}` is the
     * partner value of the one column pair whose CHECK ties the two together.
     */
    private class TypedColumn(
        val qualified: String,
        val whole: Long,
        val sql: String,
        val args: List<Any?> = emptyList(),
        val derived: Long? = null,
        val prepare: (JdbcSqlExecutor) -> Unit = {},
    ) {
        /** [sql] with `{v}` (and `{d}`) written by [value], which sees the declared whole number. */
        fun render(value: (Long) -> String): String =
            sql.replace("{v}", value(whole)).replace("{d}", derived?.let(value).orEmpty())
    }

    private fun aRelayAndNamespace(db: JdbcSqlExecutor) {
        db.exec(
            "INSERT INTO relay_directory(relay_id, onion_address, operator_id, state, source) " +
                "VALUES (1, ?, ?, 'active', 'config')",
            listOf(onion(1), bytes(16, 1)),
        )
        db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'dm', 1)", listOf(bytes(32, 1)))
    }

    /** A blob that reached `fetched` the way §10.3 reaches it: listed first, then fetched. */
    private fun aFetchedBlob(db: JdbcSqlExecutor) {
        aRelayAndNamespace(db)
        db.exec(
            "INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', 112)",
            listOf(bytes(32, 1), bytes(32, 2)),
        )
        db.exec(
            "UPDATE inbox_blob SET state = 'fetched', ciphertext = ?, fetch_seq = 1",
            listOf(bytes(1024, 3)),
        )
    }

    private fun aContact(db: JdbcSqlExecutor) {
        db.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(bytes(16, 1), bytes(32, 1), bytes(159, 1)),
        )
    }

    private fun aConversation(db: JdbcSqlExecutor) {
        aContact(db)
        db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(bytes(16, 1), bytes(16, 1)))
    }

    private fun anOutboundItem(db: JdbcSqlExecutor) {
        aContact(db)
        db.exec(
            "INSERT INTO dm_outbound_item(item_id, contact_id, kind, control, deadline_hour, state, ttl_seconds) " +
                "VALUES (?, ?, 4, 'reconnect', 3600, 'pending', 86400)",
            listOf(bytes(16, 1), bytes(16, 1)),
        )
    }

    private val contactRow =
        "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment"
    private val messageRow =
        "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, " +
            "minute_index, timer_code, body_env, state"
    private val sessionRow = "INSERT INTO olm_session(contact_id, slot, session_id, role, acknowledged, state_env"
    private val registrationRow =
        "INSERT INTO relay_key_registration(relay_id, namespace_id, period_id, kind, verifier, request_id, state, " +
            "next_attempt_minute"

    private fun heldRow(gen: String, hold: String, relay: String, consume: String) =
        "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, hold_until_minute, " +
            "relay_expiry_hour, consume_minute) VALUES (?, ?, ?, ?, $gen, $hold, $relay, $consume)"

    private fun heldArgs(): List<Any?> = listOf(bytes(16, 1), bytes(16, 1), bytes(32, 1), bytes(300, 1))
    private fun sessionArgs(): List<Any?> = listOf(bytes(16, 1), bytes(32, 1), bytes(200, 1))
    private fun generationArgs(): List<Any?> = listOf(bytes(32, 1), bytes(92, 1))

    private val self32 = listOf<Any?>(bytes(32, 1), bytes(60, 2), bytes(60, 3))
    private val contactArgs = listOf<Any?>(bytes(16, 1), bytes(32, 1), bytes(159, 1))
    private val messageArgs = listOf<Any?>(bytes(16, 1), bytes(16, 1), bytes(100, 1))
    private val registrationArgs = listOf<Any?>(bytes(32, 1), bytes(32, 2), bytes(16, 1))

    /**
     * Every v4, v5 and v6 column that R-M3 declares integer-typed, with a statement that writes it.
     *
     * Two pairs cannot be separated, and are written together on purpose: `dm_message`'s
     * `expire_at_minute` and `delete_at_minute` are tied by `delete_at_minute IS (CASE WHEN
     * expire_at_minute IS NOT NULL THEN expire_at_minute ELSE unread_deadline_minute END)`, and
     * `olm_prekey_gen`'s `superseded_day` and `delete_after_day` by `delete_after_day =
     * superseded_day + 91`. Writing one of a pair as a REAL and the other as an integer would be
     * refused by the tying CHECK rather than by `typeof`, which would prove nothing; each pair is
     * therefore written fractional on both sides, and each column of it stays separately pinned by
     * the text assertion of [everyTimeColumnCarriesItsGranularityCheck].
     */
    private val typedColumns: List<TypedColumn> = listOf(
        // ---- migration 4
        TypedColumn(
            "inbox_blob.relay_expiry_hour", 3600,
            // The insert trigger refuses a relay expiry on any row; it is written on a fetched one.
            "UPDATE inbox_blob SET relay_expiry_hour = {v}", prepare = ::aFetchedBlob,
        ),
        TypedColumn(
            "relay_key_registration.lease_hour", 3600,
            "$registrationRow, lease_hour) VALUES (1, ?, 7, 'read', ?, ?, 'pending', 600, {v})",
            registrationArgs, prepare = ::aRelayAndNamespace,
        ),
        TypedColumn(
            "relay_key_registration.next_attempt_minute", 600,
            "$registrationRow) VALUES (1, ?, 7, 'read', ?, ?, 'pending', {v})",
            registrationArgs, prepare = ::aRelayAndNamespace,
        ),
        TypedColumn(
            "relay_key_registration.valid_until_hour", 3600,
            "$registrationRow, valid_until_hour) VALUES (1, ?, 7, 'read', ?, ?, 'done', 600, {v})",
            registrationArgs, prepare = ::aRelayAndNamespace,
        ),
        TypedColumn(
            "relay_key_registration.period_id", 7,
            "$registrationRow) VALUES (1, ?, {v}, 'read', ?, ?, 'pending', 600)",
            registrationArgs, prepare = ::aRelayAndNamespace,
        ),
        // ---- migration 6
        TypedColumn(
            "relay_register_capability.expires_hour", 3600,
            "INSERT INTO relay_register_capability(relay_id, namespace_id, token, expires_hour, state, generation) " +
                "VALUES (1, ?, ?, {v}, 'usable', 1)",
            listOf(bytes(32, 1), bytes(82, 1)), prepare = ::aRelayAndNamespace,
        ),
        TypedColumn(
            "relay_register_capability.generation", 7,
            "INSERT INTO relay_register_capability(relay_id, namespace_id, token, state, generation) " +
                "VALUES (1, ?, ?, 'usable', {v})",
            listOf(bytes(32, 1), bytes(82, 1)), prepare = ::aRelayAndNamespace,
        ),
        // ---- dm_self
        TypedColumn(
            "dm_self.expiry_clock_minute", 600,
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "expiry_clock_minute) VALUES (1, 0, ?, ?, ?, {v})",
            self32,
        ),
        TypedColumn(
            "dm_self.accept_after_minute", 600,
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "expiry_clock_minute, accept_after_minute) VALUES (1, 0, ?, ?, ?, 600, {v})",
            self32,
        ),
        TypedColumn(
            "dm_self.bundle_week", 2870,
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "expiry_clock_minute, bundle_week) VALUES (1, 0, ?, ?, ?, 600, {v})",
            self32,
        ),
        TypedColumn(
            "dm_self.bundle_published_week", 2870,
            "INSERT INTO dm_self(id, card_index, seen_key, content_key_wrapped, state_key_wrapped, " +
                "expiry_clock_minute, bundle_published_week) VALUES (1, 0, ?, ?, ?, 600, {v})",
            self32,
        ),
        // ---- dm_contact
        TypedColumn(
            "dm_contact.fetch_listen_until_minute", 600,
            "$contactRow, fetch_listen_until_minute) VALUES (?, ?, ?, 0, 'unverified', 'link', 'fetching', {v})",
            contactArgs,
        ),
        TypedColumn(
            "dm_contact.request_until_day", 7,
            "$contactRow, request_until_day) VALUES (?, ?, ?, 0, 'request', 'link', 'card_only', {v})",
            contactArgs,
        ),
        TypedColumn(
            "dm_contact.bundle_week_seen", 2870,
            "$contactRow, bundle_week_seen) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only', {v})",
            contactArgs,
        ),
        TypedColumn(
            "dm_contact.pq_announced_week", 2870,
            "$contactRow, pq_announced_week) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only', {v})",
            contactArgs,
        ),
        // ---- dm_message
        TypedColumn(
            "dm_message.author_minute", 660,
            "$messageRow) VALUES (?, ?, 'in', 1, {v}, 600, 0, 0, ?, 'unread')",
            messageArgs, prepare = ::aConversation,
        ),
        TypedColumn(
            "dm_message.sort_minute", 600,
            "$messageRow) VALUES (?, ?, 'in', 1, 660, {v}, 0, 0, ?, 'unread')",
            messageArgs, prepare = ::aConversation,
        ),
        TypedColumn(
            "dm_message.expire_at_minute", 604_800,
            "$messageRow, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'sent', {v}, {v})",
            messageArgs, prepare = ::aConversation,
        ),
        TypedColumn(
            "dm_message.delete_at_minute", 604_800,
            "$messageRow, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 1, 600, 600, 0, 4, ?, 'sent', {v}, {v})",
            messageArgs, prepare = ::aConversation,
        ),
        TypedColumn(
            "dm_message.unread_deadline_minute", 600,
            "$messageRow, expire_at_minute, unread_deadline_minute, delete_at_minute) " +
                "VALUES (?, ?, 'in', 1, 600, 600, 0, 4, ?, 'read', 604800, {v}, 604800)",
            messageArgs, prepare = ::aConversation,
        ),
        // ---- the outbound path
        TypedColumn(
            "dm_outbound_item.deadline_hour", 3600,
            "INSERT INTO dm_outbound_item(item_id, contact_id, kind, control, deadline_hour, state, ttl_seconds) " +
                "VALUES (?, ?, 4, 'reconnect', {v}, 'pending', 86400)",
            listOf(bytes(16, 1), bytes(16, 1)), prepare = ::aContact,
        ),
        // Q27/S3b (migration 8's fold): the reschedule bound's counter, added by `ALTER TABLE`
        // because dm_scheduled is not one of the five rebuilt tables.
        TypedColumn(
            "dm_scheduled.attempts", 1,
            "INSERT INTO dm_scheduled(sched_id, contact_id, what, due_minute, attempts) " +
                "VALUES (?, ?, 'reconnect', 600, {v})",
            listOf(bytes(16, 1), bytes(16, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_outbound_op.deadline_hour", 3600,
            "INSERT INTO dm_outbound_op(operation_id, purpose, bundle_week, deadline_hour) " +
                "VALUES (?, 'bundle', 2870, {v})",
            listOf(bytes(16, 1)),
        ),
        TypedColumn(
            "dm_outbound_op.bundle_week", 2870,
            "INSERT INTO dm_outbound_op(operation_id, purpose, bundle_week, deadline_hour) " +
                "VALUES (?, 'bundle', {v}, 3600)",
            listOf(bytes(16, 1)),
        ),
        TypedColumn(
            "dm_pending_send.fail_after_hour", 3600,
            "INSERT INTO dm_pending_send(item_id, contact_id, fail_after_hour) VALUES (?, ?, {v})",
            listOf(bytes(16, 1), bytes(16, 1)), prepare = ::anOutboundItem,
        ),
        TypedColumn(
            "dm_scheduled.due_minute", 600,
            "INSERT INTO dm_scheduled(sched_id, contact_id, what, due_minute) VALUES (?, ?, 'reconnect', {v})",
            listOf(bytes(16, 1), bytes(16, 1)), prepare = ::aContact,
        ),
        // ---- dm_held
        TypedColumn(
            "dm_held.gen_id", 1,
            heldRow("{v}", "600", "3600", "600"), heldArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_held.hold_until_minute", 600,
            heldRow("1", "{v}", "3600", "600"), heldArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_held.relay_expiry_hour", 3600,
            heldRow("1", "600", "{v}", "600"), heldArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_held.consume_minute", 600,
            heldRow("1", "600", "3600", "{v}"), heldArgs(), prepare = ::aContact,
        ),
        // ---- dm_seen
        TypedColumn("dm_seen.until_day", 14, "INSERT INTO dm_seen(tag, until_day) VALUES (?, {v})", listOf(bytes(16, 1))),
        // ---- olm_session
        TypedColumn(
            "olm_session.peer_bind_minute", 600,
            "$sessionRow, peer_bind_minute) VALUES (?, 'current', ?, 'responder', 1, ?, {v})",
            sessionArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "olm_session.prov_anchor_minute", 600,
            "$sessionRow, peer_bind_minute, prov_anchor_minute) VALUES (?, 'current', ?, 'responder', 1, ?, 600, {v})",
            sessionArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "olm_session.prov_erase_minute", 600,
            "$sessionRow, peer_bind_minute, prov_env, prov_erase_minute) " +
                "VALUES (?, 'current', ?, 'responder', 1, ?, 600, ?, {v})",
            sessionArgs() + listOf(bytes(60, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "olm_session.retire_day", 100,
            "$sessionRow, peer_bind_minute, retire_day) VALUES (?, 'previous', ?, 'responder', 1, ?, 600, {v})",
            sessionArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "olm_session.unack_since_day", 100,
            "$sessionRow, peer_gen_id, unack_since_day) VALUES (?, 'current', ?, 'initiator', 0, ?, 7, {v})",
            sessionArgs(), prepare = ::aContact,
        ),
        TypedColumn(
            "olm_session.peer_gen_id", 7,
            "$sessionRow, peer_gen_id, unack_since_day) VALUES (?, 'current', ?, 'initiator', 0, ?, {v}, 100)",
            sessionArgs(), prepare = ::aContact,
        ),
        // ---- olm_prekey_gen
        TypedColumn(
            "olm_prekey_gen.gen_id", 7,
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES ({v}, 2870, ?, ?)",
            generationArgs(),
        ),
        TypedColumn(
            "olm_prekey_gen.bundle_week", 2870,
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (7, {v}, ?, ?)",
            generationArgs(),
        ),
        TypedColumn(
            "olm_prekey_gen.superseded_day", 10,
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, " +
                "delete_after_day) VALUES (7, 2870, ?, ?, {v}, {d})",
            generationArgs(), derived = 101,
        ),
        TypedColumn(
            "olm_prekey_gen.delete_after_day", 10,
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env, superseded_day, " +
                "delete_after_day) VALUES (7, 2870, ?, ?, {v}, {d})",
            generationArgs(), derived = 101,
        ),
        // ---- the peer's X-Wing keys, the bundle candidate and the pair material
        TypedColumn(
            "dm_peer_pq.gen_id", 1,
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) " +
                "VALUES (?, {v}, 2870, 'bundle', ?)",
            listOf(bytes(16, 1), bytes(1216, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_peer_pq.bundle_week", 2870,
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) " +
                "VALUES (?, 1, {v}, 'bundle', ?)",
            listOf(bytes(16, 1), bytes(1216, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_bundle_candidate.bundle_week", 2870,
            "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) VALUES (?, ?, {v}, 0)",
            listOf(bytes(16, 1), bytes(1421, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_bundle_candidate.bundle_rank", 7,
            "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) VALUES (?, ?, 2870, {v})",
            listOf(bytes(16, 1), bytes(1421, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_pair_key.week", 2870,
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', 3, {v}, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(60, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_pair_key.root_gen", 3,
            "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                "VALUES (?, 'in', {v}, 2870, ?, ?)",
            listOf(bytes(16, 1), bytes(32, 1), bytes(60, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_pair_offer.base_week", 2870,
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, base_week) VALUES (?, 3, ?, {v})",
            listOf(bytes(16, 1), bytes(60, 1)), prepare = ::aContact,
        ),
        TypedColumn(
            "dm_pair_offer.root_gen", 3,
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, base_week) VALUES (?, {v}, ?, 2870)",
            listOf(bytes(16, 1), bytes(60, 1)), prepare = ::aContact,
        ),
    )

    /**
     * R-M3 and §21.14, **executed**: every v4 and v5 column the design declares integer-typed
     * refuses a REAL whose whole part is aligned, and stores the same value written `x.0` as an
     * integer.
     *
     * This is the half the text assertions of [everyTimeColumnCarriesItsGranularityCheck] and
     * [everyPeriodIndexRankAndRandomIdIsIntegerTyped] cannot give: those read `CREATE TABLE` for a
     * substring, so a CHECK that is present in the text and vacuous in effect — `CHECK (typeof(x)
     * = 'integer' AND x BETWEEN 0 AND 65535 OR 1)`, which parses as `(A AND B) OR 1` — satisfies
     * them while refusing nothing. It refuses nothing here.
     *
     * The granularity CHECK is executed in the same pass wherever the schema writes one: the
     * divisor is read out of the column's own `CREATE TABLE` text, and a value one unit past the
     * grid must be refused. That covers the `% 7 = 0` of `dm_seen.until_day`, which the `_day`
     * branch of [everyTimeColumnCarriesItsGranularityCheck] only looks for as "some CHECK".
     */
    @Test
    fun everyTypedColumnRefusesAFractionalValue() {
        val declared = timeColumnsOfMigration4 + timeColumnsOfMigration5 + timeColumnsOfMigration6 +
            countersOfMigration6 + countersOfMigration8 + periodIndices - typeofCheckedByForeignKey -
            executedByTheEntitlementSuite
        assertEquals(
            "a declared integer-typed column that no case of this test ever writes",
            declared.sorted(),
            typedColumns.map { it.qualified }.distinct().sorted(),
        )
        val withGranularity = ArrayList<String>()
        for (case in typedColumns) migrated().use { db ->
            case.prepare(db)
            val (table, column) = case.qualified.split(".")
            // SQLite's `%` casts a REAL to INTEGER before the remainder, and `BETWEEN` compares
            // numerically, so `x.5` satisfies every granularity and range CHECK on the column:
            // `typeof(x) = 'integer'` is the only thing that can refuse it.
            db.rejects(CHECK_FAILED, case.render { "$it.5" }, *case.args.toTypedArray())
            if (Regex("\\b$column % \\d+ = 0").containsMatchIn(createSql(db, table))) {
                withGranularity += case.qualified
                // One unit off the grid: an integer, so only the granularity CHECK can refuse it.
                db.rejects(CHECK_FAILED, case.render { "${it + 1}" }, *case.args.toTypedArray())
            }
            // Written with no fractional part, INTEGER affinity coerces it and the row is stored.
            db.exec(case.render { "$it.0" }, case.args)
            assertEquals(
                case.qualified,
                "integer",
                db.queryString("SELECT typeof($column) FROM $table WHERE $column IS NOT NULL"),
            )
        }
        // The granularity half is not vacuous either: every `_minute` and `_hour` column and the
        // weekly `dm_seen.until_day` were among the ones whose off-grid value was refused.
        assertTrue(
            "no granularity CHECK was executed: $withGranularity",
            "dm_seen.until_day" in withGranularity && withGranularity.size >= 20,
        )
    }

    /**
     * The exemption above, executed rather than argued: a reuse tuple whose `gen_id` is not an
     * integer cannot be stored. `7.0` is coerced to the integer 7 by the column's INTEGER affinity
     * and matches its generation; `7.5` keeps its type and matches no generation, so the foreign
     * key refuses it, which is the property `typeof(gen_id) = 'integer'` would have given.
     */
    @Test
    fun theReuseTupleInheritsItsTypeFromItsParentGeneration() = migrated().use { db ->
        db.exec(
            "INSERT INTO olm_prekey_gen(gen_id, bundle_week, fallback_pub, secrets_env) VALUES (7, 2870, ?, ?)",
            listOf(bytes(32, 1), bytes(92, 1)),
        )
        db.exec("INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (7.0, ?)", listOf(bytes(32, 2)))
        assertEquals("integer", db.queryString("SELECT typeof(gen_id) FROM olm_prekey_used"))
        db.rejects(
            FOREIGN_KEY_FAILED,
            "INSERT INTO olm_prekey_used(gen_id, session_id) VALUES (7.5, ?)",
            bytes(32, 3),
        )
    }

    /**
     * **R-M4** over every object of the schema, not only over the tables. `secure_delete` does not
     * scrub the shadow tables of a virtual table (§10.7), so an expired message would leave its
     * words behind; [Migration5Test.theSchemaCarriesNoVirtualTable] reads the table rows, and this
     * reads every row — an index, a trigger or a view could name one just as well. The gate
     * `dm-no-fts.sh` (G-DM6) is the other half: it reads the production sources as text, so a
     * virtual table created at runtime rather than by a migration is caught before the database is
     * opened at all.
     */
    @Test
    fun noObjectOfTheSchemaIsOrNamesAVirtualTable() = migrated().use { db ->
        val offenders = ArrayList<String>()
        db.query("SELECT type, name, ifnull(sql, '') FROM sqlite_master") { row ->
            val sql = row.string(2).lowercase()
            if (sql.contains("virtual") || Regex("(^|[^a-z0-9])fts").containsMatchIn(sql)) {
                offenders += "${row.string(0)} ${row.string(1)}"
            }
        }
        assertEquals(emptyList<String>(), offenders)
        // And no shadow table of a past FTS index survives under another name.
        val names = tables(db)
        assertEquals(emptyList<String>(), names.filter { Regex("(^|[^a-z0-9])fts").containsMatchIn(it.lowercase()) })
    }
}
