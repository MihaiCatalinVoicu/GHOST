package org.ghost.media.store

import org.ghost.storage.queryString
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MediaFixture
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin statement of each machine against the schema's (Phase 11 design §7.6, §6.4; Phase 10's
 * `ChannelStateMachinesTest` twin): [ObjectState.allows] and [UploadState.allows] are run through the triggers
 * `media_object_state` and `media_fragment_state` on **every pair**, so the two statements of one machine cannot drift. The
 * schema's own tests (`MediaTriggersTest`, in `:storage`) hold the edge tables written from the design; this one holds the
 * enums to them.
 */
class MediaStateMachinesTest {

    private val keyless = setOf(ObjectState.VIEWING, ObjectState.VIEWED, ObjectState.CORRUPT, ObjectState.INCOMPLETE)

    @Test
    fun theObjectEnumAllowsExactlyWhatTheTriggerAllows() {
        assertEquals(12, ObjectState.entries.size)
        var allowed = 0
        for (from in ObjectState.entries) for (to in ObjectState.entries) MediaFixture().use { f ->
            val incoming = from.role == MediaRole.IN
            val overrides = buildList {
                add("state" to from.code)
                add("view_once" to 1L)
                if (incoming) {
                    add("object_id" to MediaFixture.IN); add("role" to "in"); add("incomplete_after_hour" to 3_600_000L)
                }
                if (from in keyless) add("key_env" to null)
            }
            f.put("media_object", *overrides.toTypedArray())
            val id = if (incoming) MediaFixture.IN else MediaFixture.OUT
            val clear = if (to in keyless) ", key_env = NULL" else ""
            val sql = "UPDATE media_object SET state = ?$clear WHERE object_id = ?"
            val accepted = try {
                f.db.exec(sql, listOf(to.code, id))
                true
            } catch (e: java.sql.SQLException) {
                false
            }
            assertEquals("$from -> $to", from.allows(to), accepted)
            if (accepted) allowed++
        }
        assertEquals(26, allowed)
        // the role of a state is the role of the rows that can hold it
        assertEquals(setOf(ObjectState.UPLOADING, ObjectState.UPLOADED, ObjectState.FAILED), ObjectState.entries.filter { it.role == MediaRole.OUT }.toSet())
        // a state that holds no key is exactly the set the CHECK lists
        assertEquals(keyless, ObjectState.entries.filter { it.keyless }.toSet())
    }

    @Test
    fun theUploadEnumAllowsExactlyWhatTheTriggerAllowsWhenTheRetryConditionHolds() {
        assertEquals(6, UploadState.entries.size)
        var allowed = 0
        for (from in UploadState.entries) for (to in UploadState.entries) MediaFixture().use { f ->
            f.put("media_fragment")
            f.put("media_upload")
            f.put("media_outbound_op")
            for (step in when (from) {
                UploadState.UNSENT -> emptyList()
                UploadState.OPEN -> listOf("open")
                else -> listOf("open", from.code)
            }) f.db.exec("UPDATE media_fragment SET upload_state = ?", listOf(step))
            // `failed` -> `unsent` needs the object's generation to have moved past the fragment's last operation (the retry)
            if (from == UploadState.FAILED && to == UploadState.UNSENT) f.db.exec("UPDATE media_upload SET retry_gen = 1")
            val accepted = try {
                f.db.exec("UPDATE media_fragment SET upload_state = ?", listOf(to.code))
                true
            } catch (e: java.sql.SQLException) {
                false
            }
            assertEquals("$from -> $to", from.allows(to), accepted)
            if (accepted) allowed++
        }
        // 6 no-ops, unsent -> open, open -> four final states, failed -> unsent
        assertEquals(6 + 1 + 4 + 1, allowed)
        assertEquals(setOf(UploadState.SENT, UploadState.DEGRADED, UploadState.INDETERMINATE), UploadState.entries.filter { it.acknowledged }.toSet())
    }

    @Test
    fun everyEnumReadsBackWhatItWritesAndRefusesWhatItDoesNotKnow() {
        for (e in ObjectState.entries) assertEquals(e, ObjectState.of(e.code))
        for (e in UploadState.entries) assertEquals(e, UploadState.of(e.code))
        for (e in FragmentState.entries) assertEquals(e, FragmentState.of(e.code))
        for (e in BlobOrigin.entries) assertEquals(e, BlobOrigin.of(e.code))
        for (e in MediaRole.entries) assertEquals(e, MediaRole.of(e.code))
        for (e in MediaKind.entries) assertEquals(e, MediaKind.of(e.code))
        expectStoreError(MediaStoreError.BAD_VALUE) { ObjectState.of("gone") }
        expectStoreError(MediaStoreError.BAD_VALUE) { UploadState.of("bogus") }
        expectStoreError(MediaStoreError.BAD_VALUE) { FragmentState.of("bogus") }
        expectStoreError(MediaStoreError.BAD_VALUE) { BlobOrigin.of("bogus") }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaRole.of("bogus") }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaKind.of(3) }
        // `gone` is the transaction that deletes the row, not a stored state (§7.6)
        assertTrue(ObjectState.entries.none { it.code == "gone" })
    }

    /** The constants the schema's CHECKs carry are the design's: a class code is an index, the buckets are four. */
    @Test
    fun theLimitsAreTheDesignsAndTheSchemasChecksCarryThem() {
        assertEquals(listOf(16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804), MediaLimits.CLASSES.toList())
        assertEquals(17, MediaLimits.blobsOf(0))
        assertEquals(805, MediaLimits.blobsOf(10))
        assertEquals(MediaLimits.CLASSES.last() - 1, MediaLimits.MAX_ORDINAL)
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaLimits.blobsOf(11) }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaLimits.blobsOf(-1) }
        JdbcSqlExecutor().use { db ->
            org.ghost.storage.MigrationRunner(db).migrate()
            val sql = db.queryString("SELECT sql FROM sqlite_master WHERE name = 'media_upload'")!!.replace(Regex("\\s+"), " ")
            assertTrue(sql, sql.contains("ttl_seconds IN (3600, 86400, 604800, 2592000)"))
            assertEquals(setOf(3_600L, 86_400L, 604_800L, 2_592_000L), MediaLimits.TTL_BUCKETS)
            assertTrue(sql, sql.contains("retry_gen BETWEEN 0 AND ${MediaLimits.MAX_RETRIES}"))
            val fragment = db.queryString("SELECT sql FROM sqlite_master WHERE name = 'media_fragment'")!!.replace(Regex("\\s+"), " ")
            assertTrue(fragment, fragment.contains("ordinal BETWEEN ${MediaLimits.MANIFEST_ORDINAL} AND ${MediaLimits.MAX_ORDINAL}"))
            val op = db.queryString("SELECT sql FROM sqlite_master WHERE name = 'media_outbound_op'")!!.replace(Regex("\\s+"), " ")
            assertTrue(op, op.contains("resend_count BETWEEN 0 AND ${MediaLimits.MAX_RESENDS}"))
            val obj = db.queryString("SELECT sql FROM sqlite_master WHERE name = 'media_object'")!!.replace(Regex("\\s+"), " ")
            assertTrue(obj, obj.contains("decode_failures BETWEEN 0 AND ${MediaLimits.MAX_DECODE_FAILURES}"))
            assertTrue(obj, obj.contains("class_code BETWEEN 0 AND ${MediaLimits.CLASSES.size - 1}"))
        }
    }
}
