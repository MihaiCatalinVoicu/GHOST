package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The CHECK, unique-key and foreign-key constraints of the five media tables and of the two rebuilt DM tables'
 * new checks (Phase 11 design §13.6), **executed**: every length, closed list, range and coupling a table declares
 * refuses the value just outside it and accepts the value just inside it (slice S3). The `typeof` and grid checks of the
 * integer columns are [MediaSchemaIntrospectionTest]'s; the triggers are [MediaTriggersTest]'s.
 *
 * Every case runs on a fresh migrated database through [MediaFixture], whose default rows are valid, so a refusal can
 * only be the one constraint the case names: the case writes the default row with exactly one column (or one coupled
 * set) changed. The keys that are unique are exercised with a **second row** ([secondRowsMeetEveryUniqueKeyAndEveryForeignKey]):
 * Phase 10's review found bounds that held only for the first row.
 */
class MediaSchemaConstraintsTest {

    /** [fragments] empty means the row is accepted; otherwise the insert must fail with a message naming one of them. */
    private class Case(
        val table: String,
        val set: Map<String, Any?>,
        val why: String,
        val fragments: List<String>,
        /** Whether the blob a fragment names exists beforehand; null leaves it to the fixture (a bound fragment gets its blob). */
        val blob: Boolean? = null,
    )

    private fun refused(table: String, why: String, vararg set: Pair<String, Any?>) = Case(table, mapOf(*set), why, listOf(CHECK_FAILED))

    private fun refusedBy(table: String, why: String, fragment: String, vararg set: Pair<String, Any?>) =
        Case(table, mapOf(*set), why, listOf(fragment))

    private fun refusedWithBlob(table: String, why: String, fragment: String, blob: Boolean, vararg set: Pair<String, Any?>) =
        Case(table, mapOf(*set), why, listOf(fragment), blob)

    private fun accepted(table: String, why: String, vararg set: Pair<String, Any?>) = Case(table, mapOf(*set), why, emptyList())

    /** A BLOB column of exactly [size] bytes: the sizes just beside it are refused, the size itself is accepted. */
    private fun exact(table: String, column: String, size: Int, vararg with: Pair<String, Any?>): List<Case> =
        listOf(size - 1, size + 1).filter { it >= 0 }.map { refused(table, "$column of $it bytes", column to mBytes(it, 1), *with) } +
            accepted(table, "$column of $size bytes", column to mBytes(size, 1), *with)

    /** An optional BLOB column of exactly [size] bytes: NULL is accepted too. */
    private fun exactOrNull(table: String, column: String, size: Int, vararg with: Pair<String, Any?>): List<Case> =
        exact(table, column, size, *with) + accepted(table, "$column NULL", column to null, *with)

    /** The overrides of an incoming object in [state]. */
    private fun inObject(state: String, vararg more: Pair<String, Any?>): Array<Pair<String, Any?>> =
        arrayOf("object_id" to MediaFixture.IN, "role" to "in", "state" to state, "incomplete_after_hour" to 3_600_000L, *more)

    private val cases: List<Case> = buildList {
        // ---- media_object
        addAll(exact("media_object", "object_id", 16))
        addAll(exact("media_object", "dest_id", 16))
        addAll(exact("media_object", "manifest_hash", 32))
        addAll(exactOrNull("media_object", "key_env", 60))
        add(refused("media_object", "role 'bogus'", "role" to "bogus"))
        add(refused("media_object", "kind 0", "kind" to 0L))
        add(refused("media_object", "kind 3", "kind" to 3L))
        add(accepted("media_object", "kind 2 (video)", "kind" to 2L))
        add(refused("media_object", "an image above class 0", "kind" to 1L, "class_code" to 1L))
        add(accepted("media_object", "a video of class 10", "kind" to 2L, "class_code" to 10L))
        add(refused("media_object", "a video of class 11", "kind" to 2L, "class_code" to 11L))
        add(refused("media_object", "view_once = 2", "view_once" to 2L))
        add(accepted("media_object", "view_once = 1", "view_once" to 1L))
        add(refused("media_object", "an unknown state", "state" to "bogus"))
        // The role follows the state: out for the three upload states, in for the nine others (§7.6), both ways round.
        for (state in MediaSchema.outStates) {
            add(accepted("media_object", "an outgoing object $state", "state" to state))
            add(refused("media_object", "an incoming object $state", *inObject(state)))
        }
        for (state in MediaSchema.inStates) {
            val needsNoKey = state in listOf("viewing", "viewed", "corrupt", "incomplete")
            val viewOnce = state in listOf("viewing", "viewed")
            val with = listOfNotNull(
                if (needsNoKey) "key_env" to null else null,
                if (viewOnce) "view_once" to 1L else null,
            ).toTypedArray()
            add(accepted("media_object", "an incoming object $state", *inObject(state, *with)))
            add(refused("media_object", "an outgoing object $state", "state" to state, *with))
        }
        // A key is held by an object that can still be opened, never by one that cannot (T45).
        for (state in listOf("viewing", "viewed", "corrupt", "incomplete")) {
            add(refused("media_object", "$state with a key", *inObject(state, "view_once" to 1L)))
        }
        for (state in listOf("awaiting", "fetching", "complete", "verified", "undecodable")) {
            add(accepted("media_object", "$state with a key", *inObject(state)))
        }
        // View-once is the only way to `viewing` and `viewed`.
        for (state in listOf("viewing", "viewed")) {
            add(refused("media_object", "$state of an object that is not view-once", *inObject(state, "key_env" to null, "view_once" to 0L)))
        }
        add(refused("media_object", "an incoming object with no deadline", *inObject("awaiting", "incomplete_after_hour" to null)))
        add(accepted("media_object", "an outgoing object with no deadline", "incomplete_after_hour" to null))
        add(accepted("media_object", "an outgoing object with a deadline", "incomplete_after_hour" to 3_600_000L))
        add(refused("media_object", "decode_failures 3", "decode_failures" to 3L))
        add(accepted("media_object", "decode_failures 2", *inObject("verified", "decode_failures" to 2L)))
        // ---- media_upload
        for (ttl in listOf(3_600L, 86_400L, 604_800L, 2_592_000L)) add(accepted("media_upload", "a bucket of $ttl s", "ttl_seconds" to ttl))
        for (ttl in listOf(0L, 300L, 1_800L, 3_601L, 7_776_000L)) add(refused("media_upload", "a bucket of $ttl s", "ttl_seconds" to ttl))
        // (the length of `namespace_id` is `sync_namespace`'s CHECK; here it is only a foreign key, tested in [aRowWhoseParentIsNotThereIsRefused])
        add(accepted("media_upload", "retry generation 3", "retry_gen" to 3L))
        add(refused("media_upload", "retry generation 4", "retry_gen" to 4L))
        // ---- media_blob
        addAll(exact("media_blob", "blob_hash", 32))
        addAll(exact("media_blob", "file_name", 16))
        add(refused("media_blob", "origin 'bogus'", "origin" to "bogus"))
        add(accepted("media_blob", "a sealed blob with no retention"))
        add(refused("media_blob", "a sealed blob with a retention day", "retain_until_day" to 20_000L))
        add(refused("media_blob", "an ingested blob with no retention day", "origin" to "ingested"))
        add(accepted("media_blob", "an ingested blob with a retention day", "origin" to "ingested", "retain_until_day" to 20_000L))
        add(accepted("media_blob", "an ingested blob retained until day 0", "origin" to "ingested", "retain_until_day" to 0L))
        add(refused("media_blob", "an ingested blob retained until day -1", "origin" to "ingested", "retain_until_day" to -1L))
        // ---- media_fragment
        // a hash of the wrong length: the CHECK, or the trigger that wants the blob row (which cannot exist), whichever SQLite runs first
        for (size in listOf(31, 33)) {
            add(
                Case(
                    "media_fragment", mapOf("blob_hash" to mBytes(size, 1)), "blob_hash of $size bytes",
                    listOf(CHECK_FAILED, "a fragment is bound exactly when its blob row exists"), blob = false,
                ),
            )
        }
        add(accepted("media_fragment", "blob_hash of 32 bytes", "blob_hash" to mBytes(32, 1)))
        add(accepted("media_fragment", "the manifest's ordinal -1", "ordinal" to -1L))
        add(accepted("media_fragment", "the last ordinal of class 10, 803", "ordinal" to 803L))
        add(refused("media_fragment", "ordinal -2", "ordinal" to -2L))
        add(refused("media_fragment", "ordinal 804", "ordinal" to 804L))
        // (a BEFORE INSERT trigger runs before the CHECKs, so for a value both refuse the trigger's message is the one SQLite reports)
        val insertRules = listOf(CHECK_FAILED, "an outgoing fragment starts bound and unsent", "a fragment is bound exactly when its blob row exists")
        add(Case("media_fragment", mapOf("state" to "bogus"), "state 'bogus'", insertRules))
        add(Case("media_fragment", mapOf("upload_state" to "bogus"), "upload state 'bogus'", insertRules))
        add(accepted("media_fragment", "an outgoing fragment, unsent"))
        for (upload in MediaSchema.uploadStates - "unsent") {
            add(refusedBy("media_fragment", "an outgoing fragment inserted as $upload", "an outgoing fragment starts bound and unsent", "upload_state" to upload))
        }
        // Two triggers refuse this one (the order SQLite runs them in is not defined), and either is the right answer.
        add(
            Case(
                "media_fragment", mapOf("state" to "expected"), "an outgoing fragment that is only expected, the blob being there",
                listOf("an outgoing fragment starts bound and unsent", "a fragment is bound exactly when its blob row exists"), blob = true,
            ),
        )
        // With no blob row there is nothing for the bound-blob rule to say (expected and no blob is its own answer), so only the
        // starting-state rule of the role trigger refuses this one (review of slice S3: the clause was pinned by no test).
        add(refusedWithBlob("media_fragment", "an outgoing fragment that is only expected, with no blob row", "an outgoing fragment starts bound and unsent", false, "state" to "expected"))
        add(refusedBy("media_fragment", "an outgoing fragment with no upload state", "an outgoing fragment starts bound and unsent", "upload_state" to null))
        add(refusedWithBlob("media_fragment", "a bound fragment whose blob is not there", "a fragment is bound exactly when its blob row exists", false, "blob_hash" to mBytes(32, 0x96)))
        // An incoming fragment is expected (no blob yet) or bound (the blob is there), and has no upload state.
        add(accepted("media_fragment", "an incoming fragment, bound", "object_id" to MediaFixture.IN, "upload_state" to null))
        add(accepted("media_fragment", "an incoming fragment, expected", "object_id" to MediaFixture.IN, "upload_state" to null, "state" to "expected", "blob_hash" to mBytes(32, 0x94)))
        add(refusedBy("media_fragment", "an incoming fragment with an upload state", "an outgoing fragment starts bound and unsent", "object_id" to MediaFixture.IN))
        add(refusedWithBlob("media_fragment", "an incoming fragment expected for a blob that is there", "a fragment is bound exactly when its blob row exists", true, "object_id" to MediaFixture.IN, "upload_state" to null, "state" to "expected"))
        // ---- media_outbound_op
        addAll(exact("media_outbound_op", "operation_id", 16))
        add(accepted("media_outbound_op", "retry generation 3, resend 2", "retry_gen" to 3L, "resend_count" to 2L))
        add(refused("media_outbound_op", "retry generation 4", "retry_gen" to 4L))
        add(refused("media_outbound_op", "resend 3", "resend_count" to 3L))
        // ---- the rebuilt DM tables: what the new checks admit, at their edges (the old ones are v5's tests)
        for (kind in listOf(0L, 3L, 4L, 6L)) add(refused("dm_message", "kind $kind", "kind" to kind))
        add(accepted("dm_message", "a text of 30 bytes", "kind" to 1L, "body_env" to mBytes(30, 1)))
        add(refused("dm_message", "a text of 29 bytes (a text keeps its floor of 30)", "kind" to 1L, "body_env" to mBytes(29, 1)))
        add(accepted("dm_message", "a text of 61485 bytes", "kind" to 1L, "body_env" to mBytes(61_485, 1)))
        add(refused("dm_message", "a text of 61486 bytes", "kind" to 1L, "body_env" to mBytes(61_486, 1)))
        add(refused("dm_message", "a text with no body", "kind" to 1L, "body_env" to null))
        add(accepted("dm_message", "a reaction with no body", "kind" to 2L, "body_env" to null))
        add(refused("dm_message", "a reaction with a body", "kind" to 2L, "body_env" to mBytes(40, 1)))
        add(accepted("dm_message", "an empty caption (a 28-byte envelope)", "kind" to 5L, "body_env" to mBytes(28, 1)))
        add(accepted("dm_message", "a caption of 1052 bytes", "kind" to 5L, "body_env" to mBytes(1_052, 1)))
        add(refused("dm_message", "a caption of 1053 bytes", "kind" to 5L, "body_env" to mBytes(1_053, 1)))
        add(refused("dm_message", "a caption of 27 bytes", "kind" to 5L, "body_env" to mBytes(27, 1)))
        add(refused("dm_message", "a media message with no caption envelope", "kind" to 5L, "body_env" to null))
        for (kind in listOf(0L, 6L)) add(refused("dm_outbound_item", "kind $kind", "kind" to kind))
        add(accepted("dm_outbound_item", "kind 5 (a media message)", "kind" to 5L))
        add(accepted("dm_outbound_item", "kind 1", "kind" to 1L))
        // Q27/S3b's column: ADR-27's four DM buckets exactly; nothing else, and never NULL.
        add(accepted("dm_outbound_item", "the 1-hour TTL bucket", "ttl_seconds" to 3_600L))
        add(refused("dm_outbound_item", "a TTL of 7 200 seconds (no such bucket)", "ttl_seconds" to 7_200L))
    }

    /** The defaults of the two rebuilt tables, which the media defaults do not carry. */
    private fun dmDefaults(table: String): Map<String, Any?> = when (table) {
        "dm_message" -> linkedMapOf(
            "message_id" to mBytes(16, 0x90), "conversation_id" to mBytes(16, 0xC0), "direction" to "out", "kind" to 5L,
            "author_minute" to 600L, "sort_minute" to 600L, "minute_index" to 0L, "timer_code" to 0L,
            "body_env" to mBytes(60, 0x73), "state" to "queued",
        )
        else -> linkedMapOf(
            "item_id" to mBytes(16, 0x92), "contact_id" to MediaFixture.DEST, "message_ref" to mBytes(16, 0x91), "kind" to 5L,
            "deadline_hour" to 360_000L, "state" to "pending", "ttl_seconds" to 604_800L,
        )
    }

    private fun insert(f: MediaFixture, case: Case) {
        val dm = case.table.startsWith("dm_")
        val (sql, args) = if (dm) {
            val row = LinkedHashMap(dmDefaults(case.table)).also { it.putAll(case.set) }
            "INSERT INTO ${case.table}(${row.keys.joinToString(", ")}) VALUES (${row.keys.joinToString(", ") { "?" }})" to row.values.toList()
        } else {
            f.sql(case.table, case.set)
        }
        if (case.fragments.isEmpty()) {
            f.db.exec(sql, args)
        } else {
            val e = org.junit.Assert.assertThrows("${case.table}: ${case.why}", java.sql.SQLException::class.java) { f.db.exec(sql, args) }
            val message = e.message.orEmpty()
            assertTrue("${case.table}: ${case.why}: expected one of ${case.fragments}, got: $message", case.fragments.any { message.contains(it) })
        }
    }

    @Test
    fun everyConstraintRefusesTheValueJustOutsideAndAcceptsTheValueJustInside() {
        val tables = cases.map { it.table }.toSet()
        // Every table has cases, so a constraint added to one without a test here is at least beside tests.
        assertEquals("a media table with no case at all", emptySet<String>(), MediaSchema.tables - tables)
        assertEquals(setOf("dm_message", "dm_outbound_item"), tables.filter { it.startsWith("dm_") }.toSet())
        assertTrue("the case list is long enough to mean something: ${cases.size}", cases.size >= 130)
        for (case in cases) MediaFixture().use { f ->
            val label = "${case.table}: ${case.why}"
            if (case.table == "dm_outbound_item") f.dmMessage(mBytes(16, 0x91)) // the message the item names
            else if (case.table == "dm_message") f.dmConversation()
            else f.parents(case.table, case.set, case.blob)
            val before = f.count(case.table)
            insert(f, case)
            assertEquals(label, if (case.fragments.isEmpty()) before + 1 else before, f.count(case.table))
        }
    }

    /** The defaults themselves are valid rows of every table (a baseline for every refusal above). */
    @Test
    fun theDefaultRowOfEveryTableIsValidAndEveryTableTakesItsRowsThroughTheForeignKeys() = MediaFixture().use { f ->
        for (table in listOf("media_object", "media_upload", "media_blob", "media_fragment", "media_outbound_op")) f.put(table)
        for (table in MediaSchema.tables) assertEquals(table, 1L, f.count(table))
        assertEquals(null, f.db.queryLong("PRAGMA foreign_key_check"))
    }

    /**
     * A child of a parent that is not there is refused, for every foreign key of the five tables (no parent is created for
     * it). Where a trigger reads the parent's role (an upload, a fragment) it answers first, with its own message: either
     * way the row is refused.
     */
    @Test
    fun aRowWhoseParentIsNotThereIsRefused() {
        fun refusedRow(table: String, vararg set: Pair<String, Any?>) = MediaFixture().use { f ->
            val (sql, args) = f.sql(table, mapOf(*set))
            val e = org.junit.Assert.assertThrows(sql, java.sql.SQLException::class.java) { f.db.exec(sql, args) }
            val message = e.message.orEmpty()
            assertTrue(message, message.contains(FOREIGN_KEY_FAILED) || message.contains("an upload belongs to an outgoing object"))
            assertEquals(table, 0L, f.count(table))
        }
        refusedRow("media_object", "message_id" to mBytes(16, 0x99))
        refusedRow("media_upload", "object_id" to mBytes(16, 0x97))
        MediaFixture().use { f ->
            f.put("media_object")
            val (sql, args) = f.sql("media_upload", mapOf("namespace_id" to mBytes(32, 0x98)))
            f.db.rejects(FOREIGN_KEY_FAILED, sql, *args.toTypedArray())
        }
        MediaFixture().use { f ->
            f.ensureBlob(MediaFixture.BLOB)
            val (sql, args) = f.sql("media_fragment", mapOf("object_id" to mBytes(16, 0x95)))
            val e = org.junit.Assert.assertThrows(sql, java.sql.SQLException::class.java) { f.db.exec(sql, args) }
            val message = e.message.orEmpty()
            assertTrue(message, message.contains(FOREIGN_KEY_FAILED) || message.contains("an outgoing fragment starts bound and unsent"))
            assertEquals(0L, f.count("media_fragment"))
        }
        MediaFixture().use { f ->
            f.put("media_fragment")
            val (sql, args) = f.sql("media_outbound_op", mapOf("ordinal" to 7L))
            f.db.rejects(FOREIGN_KEY_FAILED, sql, *args.toTypedArray())
        }
    }

    /**
     * The unique keys and the foreign keys with a **second row**: the bound held for the first row of a table is not a
     * bound held for the table (Phase 10's review R-9). A second object may not name the first one's message, a second
     * blob may not take the first one's file, a second operation may not take the first one's (object, ordinal,
     * generation, resend) — and the same values for another message, file or ordinal are accepted, so the refusal is the
     * key and not the table.
     */
    @Test
    fun secondRowsMeetEveryUniqueKeyAndEveryForeignKey() = MediaFixture().use { f ->
        f.dmMessage(mBytes(16, 0x91))
        f.dmMessage(mBytes(16, 0x92))
        f.put("media_object", "message_id" to mBytes(16, 0x91))
        // a second object for the same message: the partial unique index and the guard that names it
        f.db.rejects("media_object rows are never replaced", f.sql("media_object", mapOf("object_id" to mBytes(16, 0xA9), "message_id" to mBytes(16, 0x91))).first,
            *f.sql("media_object", mapOf("object_id" to mBytes(16, 0xA9), "message_id" to mBytes(16, 0x91))).second.toTypedArray())
        f.put("media_object", "object_id" to mBytes(16, 0xA9), "message_id" to mBytes(16, 0x92))
        f.put("media_object", "object_id" to mBytes(16, 0xAA)) // no message: any number of them
        f.put("media_object", "object_id" to mBytes(16, 0xAB))
        assertEquals(4L, f.count("media_object"))
        // a second blob with the first one's file name
        f.put("media_blob")
        val sameFile = f.sql("media_blob", mapOf("blob_hash" to mBytes(32, 0xC2)))
        f.db.rejects("media_blob rows are never replaced", sameFile.first, *sameFile.second.toTypedArray())
        f.put("media_blob", "blob_hash" to mBytes(32, 0xC2), "file_name" to mBytes(16, 0xF2))
        // many fragments (of many objects) may name one blob (D25)
        f.put("media_fragment")
        f.put("media_fragment", "ordinal" to 1L)
        f.put("media_fragment", "object_id" to mBytes(16, 0xA9), "ordinal" to 0L)
        assertEquals(3L, f.db.queryLong("SELECT count(*) FROM media_fragment WHERE blob_hash = ?", listOf(MediaFixture.BLOB)))
        // a second operation for the same (object, ordinal, generation, resend) under another id
        f.put("media_outbound_op")
        val sameTuple = f.sql("media_outbound_op", mapOf("operation_id" to mBytes(16, 0xE2)))
        f.db.rejects("media_outbound_op rows are never replaced", sameTuple.first, *sameTuple.second.toTypedArray())
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE2), "resend_count" to 1L)
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE3), "ordinal" to 1L)
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE4), "retry_gen" to 1L)
        assertEquals(4L, f.count("media_outbound_op"))
        // a second upload for an object that has one
        f.put("media_upload")
        val second = f.sql("media_upload", emptyMap())
        f.db.rejects("media_upload rows are never replaced", second.first, *second.second.toTypedArray())
        assertEquals(null, f.db.queryLong("PRAGMA foreign_key_check"))
    }
}
