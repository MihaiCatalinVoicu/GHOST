package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every state-machine, write-once and consistency trigger of migration 8 (Phase 11 design §6.4, §7.2, §7.6, §13.6 step 5;
 * slice S3): **each legal transition succeeds and each illegal one is refused**, for every pair of states of every
 * machine — the twelve states of an object (144 pairs), the seven upload states of a fragment (49) and its two
 * states (4) —, and every write-once column is changed and refused.
 *
 * The tables of legal edges below are written from §7.6 and §6.4 again, not read from the schema, so a trigger that
 * gains or loses an edge fails here. The 14 triggers are listed in [MediaSchema.rules]; the last test of this class
 * requires that each of them was fired (its message was seen) by a test of the class. The five REPLACE guards are
 * [MediaReplaceGuardsTest]'s.
 */
class MediaTriggersTest {

    private val fired = HashSet<String>()

    private fun MediaFixture.upd(sql: String, vararg args: Any?): Int = db.execUpdate(sql, args.toList())

    /** Asserts that [sql] aborts with the message of [trigger], and records the trigger as exercised. */
    private fun MediaFixture.refuses(trigger: String, message: String, sql: String, vararg args: Any?) {
        db.rejects(message, sql, *args)
        fired += trigger
    }

    private val out = MediaFixture.OUT
    private val inn = MediaFixture.IN

    // ------------------------------------------------------------------ the object

    /** §7.6: the pairs (from, to) the object machine allows, written again from the table. */
    private val objectEdges: Set<Pair<String, String>> = buildSet {
        for (s in MediaSchema.outStates + MediaSchema.inStates) add(s to s)
        for (to in listOf("uploaded", "failed")) add("uploading" to to)
        add("failed" to "uploading")
        for (to in listOf("fetching", "corrupt", "incomplete")) add("awaiting" to to)
        for (to in listOf("complete", "incomplete")) add("fetching" to to)
        for (to in listOf("verified", "corrupt")) add("complete" to to)
        for (to in listOf("corrupt", "undecodable", "viewing")) add("verified" to to)
        add("viewing" to "viewed")
    }

    /** The states whose row holds no key (the CHECK of §13.6: a key is held only by an object that can still be opened). */
    private val keyless = setOf("viewing", "viewed", "corrupt", "incomplete")

    /** An object in [state], view-once (so that `viewing` and `viewed` are reachable from any row), with a key where it may hold one. */
    private fun MediaFixture.objectIn(state: String, id: ByteArray = if (state in MediaSchema.outStates) out else inn) {
        val base = if (state in MediaSchema.outStates) arrayOf("object_id" to id, "state" to state)
        else arrayOf("object_id" to id, "role" to "in", "state" to state, "incomplete_after_hour" to 3_600_000L)
        put("media_object", *base, "view_once" to 1L, *(if (state in keyless) arrayOf("key_env" to null) else emptyArray()))
    }

    @Test
    fun theObjectMachineAllowsExactlyTheEdgesOfSectionSevenSix() {
        val states = MediaSchema.outStates + MediaSchema.inStates
        assertEquals(144, states.size * states.size)
        var allowed = 0
        for (from in states) for (to in states) MediaFixture().use { f ->
            f.objectIn(from)
            val id = if (from in MediaSchema.outStates) out else inn
            val sql = "UPDATE media_object SET state = ?${if (to in keyless) ", key_env = NULL" else ""} WHERE object_id = ?"
            if (from to to in objectEdges) {
                allowed++
                assertEquals("$from -> $to", 1, f.upd(sql, to, id))
                assertEquals(to, f.db.queryString("SELECT state FROM media_object"))
            } else {
                f.refuses("media_object_state", "illegal media object state transition", sql, to, id)
                assertEquals("$from -> $to", from, f.db.queryString("SELECT state FROM media_object"))
            }
        }
        // 12 no-ops, the 3 edges of an upload, the 11 of a download.
        assertEquals(12 + 3 + 11, allowed)
        assertEquals(26, objectEdges.size)
    }

    @Test
    fun aKeyIsOnlyEverErased() = MediaFixture().use { f ->
        f.put("media_object")
        // A change to another key, and a key where there was none, are refused; the same key written again is no change.
        f.refuses("media_object_key", "a media key is only ever erased", "UPDATE media_object SET key_env = ?", mBytes(60, 0x11))
        assertEquals(1, f.upd("UPDATE media_object SET key_env = key_env"))
        assertEquals(1, f.upd("UPDATE media_object SET key_env = NULL"))
        assertNull(f.db.queryBlob("SELECT key_env FROM media_object"))
        f.refuses("media_object_key", "a media key is only ever erased", "UPDATE media_object SET key_env = ?", mBytes(60, 0x12))
        // Erasing twice is no change either.
        assertEquals(1, f.upd("UPDATE media_object SET key_env = NULL"))
        // An incoming object that never held a key (a descriptor in a request is stored with none, D28) cannot be given one.
        f.putIn("awaiting", "key_env" to null)
        f.refuses("media_object_key", "a media key is only ever erased", "UPDATE media_object SET key_env = ? WHERE object_id = ?", mBytes(60, 0x13), inn)
        // The key of one object is not the key of another: erasing one leaves the other.
        f.putIn("fetching", "object_id" to mBytes(16, 0xB2), "key_env" to mBytes(60, 0x14))
        assertEquals(1, f.upd("UPDATE media_object SET key_env = NULL WHERE object_id = ?", mBytes(16, 0xB2)))
        assertEquals(0L, f.db.queryLong("SELECT count(*) FROM media_object WHERE key_env IS NOT NULL"))
    }

    @Test
    fun anObjectKeepsItsIdentityRoleDestinationKindClassManifestAndMessage() = MediaFixture().use { f ->
        f.dmMessage(mBytes(16, 0x91))
        f.dmMessage(mBytes(16, 0x92))
        f.put("media_object", "kind" to 2L, "class_code" to 3L, "message_id" to mBytes(16, 0x91))
        val message = "a media object keeps its identity"
        for ((column, value) in listOf(
            "object_id" to mBytes(16, 0x01), "dest_id" to mBytes(16, 0x02), "kind" to 1L, "view_once" to 1L,
            "class_code" to 4L, "manifest_hash" to mBytes(32, 0x03), "message_id" to mBytes(16, 0x92),
        )) {
            f.refuses("media_object_fixed", message, "UPDATE media_object SET $column = ?", value)
        }
        f.refuses("media_object_fixed", message, "UPDATE media_object SET message_id = NULL")
        f.refuses("media_object_fixed", message, "UPDATE media_object SET role = 'in'")
        // The rule is about rows, not about the order of statements: a legal change in the same UPDATE is judged too.
        f.refuses("media_object_fixed", message, "UPDATE media_object SET state = 'uploaded', dest_id = ?", mBytes(16, 0x02))
        // What changes: the state, the key and the counters of a download (a second object is untouched by all of it).
        f.putIn("verified", "object_id" to mBytes(16, 0xB5), "kind" to 2L)
        assertEquals(1, f.upd("UPDATE media_object SET state = 'uploaded', key_env = NULL WHERE object_id = ?", out))
        assertEquals(1, f.upd("UPDATE media_object SET decode_failures = 1 WHERE object_id = ?", mBytes(16, 0xB5)))
        assertEquals("verified", f.db.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(mBytes(16, 0xB5))))
    }

    @Test
    fun aMessageIsSetOnceAndANullMessageStaysNull() = MediaFixture().use { f ->
        f.dmMessage(mBytes(16, 0x91))
        f.put("media_object")
        f.refuses("media_object_fixed", "a media object keeps its identity", "UPDATE media_object SET message_id = ?", mBytes(16, 0x91))
        assertNull(f.db.queryBlob("SELECT message_id FROM media_object"))
    }

    /** The count of failed decodes never falls (a poison guard that reset would offer a crashing file again); a deadline only moves earlier. */
    @Test
    fun theDecodeFailuresNeverFallAndTheIncompleteDeadlineOnlyMovesEarlier() = MediaFixture().use { f ->
        f.putIn("verified", "decode_failures" to 1L, "incomplete_after_hour" to 7_200L)
        val message = "never decreases and the incomplete deadline only moves earlier"
        f.refuses("media_object_monotonic", message, "UPDATE media_object SET decode_failures = 0")
        assertEquals(1, f.upd("UPDATE media_object SET decode_failures = 1"))
        assertEquals(1, f.upd("UPDATE media_object SET decode_failures = 2"))
        f.refuses("media_object_monotonic", message, "UPDATE media_object SET decode_failures = 1")
        f.refuses("media_object_monotonic", message, "UPDATE media_object SET incomplete_after_hour = 10800")
        f.refuses("media_object_monotonic", message, "UPDATE media_object SET incomplete_after_hour = NULL")
        assertEquals(1, f.upd("UPDATE media_object SET incomplete_after_hour = 7200"))
        assertEquals(1, f.upd("UPDATE media_object SET incomplete_after_hour = 3600"))
        assertEquals(3_600L, f.db.queryLong("SELECT incomplete_after_hour FROM media_object"))
        // An outgoing object has none, and is not given one.
        f.put("media_object")
        f.refuses("media_object_monotonic", message, "UPDATE media_object SET incomplete_after_hour = 3600 WHERE object_id = ?", out)
        // A second download is its own row: its deadline is not bounded by the first one's.
        f.putIn("awaiting", "object_id" to mBytes(16, 0xB6), "incomplete_after_hour" to 360_000L)
        assertEquals(1, f.upd("UPDATE media_object SET incomplete_after_hour = 356400 WHERE object_id = ?", mBytes(16, 0xB6)))
    }

    // ------------------------------------------------------------------ the fragment

    private val uploadStatesWithNull = listOf<String?>(null) + MediaSchema.uploadStates

    /** §6.4: `unsent` → `open` → one of four final states; `failed` → `unsent` is the retry (its own test). */
    private val uploadEdges: Set<Pair<String?, String?>> = buildSet {
        for (s in uploadStatesWithNull) add(s to s)
        add("unsent" to "open")
        for (to in listOf("sent", "degraded", "indeterminate", "failed")) add("open" to to)
    }

    /** A fragment of the outgoing object (or of the incoming one when [upload] is null) in the upload state [upload], reached by its legal path. */
    private fun MediaFixture.fragmentAt(upload: String?) {
        if (upload == null) {
            putIn("fetching")
            put("media_fragment", "object_id" to inn, "upload_state" to null)
            return
        }
        put("media_fragment")
        put("media_upload") // the retry rule reads it
        put("media_outbound_op") // ... and the operation the fragment last went out with, under generation 0
        val path = when (upload) {
            "unsent" -> emptyList()
            "open" -> listOf("open")
            else -> listOf("open", upload)
        }
        for (step in path) assertEquals(1, upd("UPDATE media_fragment SET upload_state = ? WHERE object_id = ? AND ordinal = 0", step, out))
    }

    @Test
    fun theUploadStatesOfAFragmentFollowTheirPathAndNothingElse() {
        assertEquals(49, uploadStatesWithNull.size * uploadStatesWithNull.size)
        var allowed = 0
        for (from in uploadStatesWithNull) for (to in uploadStatesWithNull) MediaFixture().use { f ->
            f.fragmentAt(from)
            val id = if (from == null) inn else out
            val sql = "UPDATE media_fragment SET upload_state = ? WHERE object_id = ? AND ordinal = 0"
            if (from to to in uploadEdges) {
                allowed++
                assertEquals("$from -> $to", 1, f.upd(sql, to, id))
                assertEquals(to, f.db.queryString("SELECT upload_state FROM media_fragment WHERE object_id = ?", listOf(id)))
            } else {
                // `failed` -> `unsent` is refused here because the operation of the fragment went out under the object's
                // current generation: the retry that allows it is the next test's.
                f.refuses("media_fragment_state", "a fragment keeps its identity", sql, to, id)
                assertEquals("$from -> $to", from, f.db.queryString("SELECT upload_state FROM media_fragment WHERE object_id = ?", listOf(id)))
            }
        }
        // 7 no-ops, unsent -> open and the four final states.
        assertEquals(7 + 1 + 4, allowed)
    }

    /**
     * "`failed → unsent` only together with a `retry_gen` increment of its object" (§13.6 step 5): the fragment may go back
     * only when its object's retry generation has moved past the generation of the fragment's last operation, so a
     * fragment is never fed twice in one generation, and an object that has no upload row (its uploads are over) cannot be
     * retried at all.
     */
    @Test
    fun aFailedFragmentGoesBackToUnsentOnlyAfterARetryOfItsObject() = MediaFixture().use { f ->
        f.fragmentAt("failed")
        val back = "UPDATE media_fragment SET upload_state = 'unsent' WHERE object_id = ? AND ordinal = 0"
        val message = "failed returns only after a retry of its object"
        // Generation 0: the fragment's operation went out under it.
        f.refuses("media_fragment_state", message, back, out)
        // The user retries: the generation moves to 1, and then (and only then) the fragment may go back.
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 1 WHERE object_id = ?", out))
        assertEquals(1, f.upd(back, out))
        // Fed again under generation 1: a new operation, the fragment fails again, the generation is still 1: refused.
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE5), "retry_gen" to 1L)
        assertEquals(1, f.upd("UPDATE media_fragment SET upload_state = 'open' WHERE object_id = ? AND ordinal = 0", out))
        assertEquals(1, f.upd("UPDATE media_fragment SET upload_state = 'failed' WHERE object_id = ? AND ordinal = 0", out))
        f.refuses("media_fragment_state", message, back, out)
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 2 WHERE object_id = ?", out))
        assertEquals(1, f.upd(back, out))
        // Another fragment of the same object is judged by its own operations: ordinal 1 failed in generation 2 only.
        f.put("media_fragment", "ordinal" to 1L)
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE6), "ordinal" to 1L, "retry_gen" to 2L)
        assertEquals(1, f.upd("UPDATE media_fragment SET upload_state = 'open' WHERE ordinal = 1"))
        assertEquals(1, f.upd("UPDATE media_fragment SET upload_state = 'failed' WHERE ordinal = 1"))
        f.refuses("media_fragment_state", message, "UPDATE media_fragment SET upload_state = 'unsent' WHERE ordinal = 1")
        // An object whose upload row is gone (its uploads are over, §5.1) cannot retry a fragment.
        MediaFixture().use { g ->
            g.fragmentAt("failed")
            assertEquals(1, g.upd("DELETE FROM media_upload WHERE object_id = ?", out))
            g.refuses("media_fragment_state", message, back, out)
        }
    }

    private val fragmentStates = listOf("expected", "bound")

    @Test
    fun aFragmentIsBoundOnceAndKeepsItsObjectItsOrdinalAndItsHash() {
        for (from in fragmentStates) for (to in fragmentStates) MediaFixture().use { f ->
            f.putIn("fetching")
            f.ensureBlob(MediaFixture.BLOB)
            f.put("media_fragment", "object_id" to inn, "upload_state" to null, "state" to from, "blob_hash" to if (from == "bound") MediaFixture.BLOB else mBytes(32, 0x94))
            if (from == "expected") f.ensureBlob(mBytes(32, 0x94)) // the blob arrives, and the row is bound in the same transaction
            val sql = "UPDATE media_fragment SET state = ? WHERE object_id = ? AND ordinal = 0"
            if (from == "bound" && to == "expected") {
                f.refuses("media_fragment_state", "a fragment keeps its identity", sql, to, inn)
            } else {
                assertEquals("$from -> $to", 1, f.upd(sql, to, inn))
            }
        }
        MediaFixture().use { f ->
            f.put("media_fragment")
            f.ensureBlob(mBytes(32, 0x95), mBytes(16, 0xF5))
            val message = "a fragment keeps its identity"
            f.refuses("media_fragment_state", message, "UPDATE media_fragment SET blob_hash = ?", mBytes(32, 0x95))
            f.refuses("media_fragment_state", message, "UPDATE media_fragment SET ordinal = 5")
            f.putIn("awaiting", "object_id" to mBytes(16, 0xB7))
            f.refuses("media_fragment_state", message, "UPDATE media_fragment SET object_id = ?", mBytes(16, 0xB7))
            assertEquals(1L, f.count("media_fragment"))
        }
    }

    @Test
    fun anExpectedFragmentIsBoundOnlyOnceItsBlobIsThere() = MediaFixture().use { f ->
        f.putIn("fetching")
        val hash = mBytes(32, 0x94)
        f.put("media_fragment", "object_id" to inn, "upload_state" to null, "state" to "expected", "blob_hash" to hash)
        val sql = "UPDATE media_fragment SET state = 'bound' WHERE object_id = ? AND ordinal = 0"
        f.refuses("media_fragment_bound_blob_update", "a fragment is bound exactly when its blob row exists", sql, inn)
        f.ensureBlob(hash, mBytes(16, 0xF4))
        assertEquals(1, f.upd(sql, inn))
        // Two objects naming one blob are both bound by one arrival (D25): a second expected row, then the blob, then both.
        f.putIn("fetching", "object_id" to mBytes(16, 0xB8))
        val other = mBytes(32, 0x93)
        f.put("media_fragment", "object_id" to inn, "ordinal" to 1L, "upload_state" to null, "state" to "expected", "blob_hash" to other)
        f.put("media_fragment", "object_id" to mBytes(16, 0xB8), "upload_state" to null, "state" to "expected", "blob_hash" to other)
        f.ensureBlob(other, mBytes(16, 0xF3))
        assertEquals(2, f.upd("UPDATE media_fragment SET state = 'bound' WHERE blob_hash = ?", other))
    }

    @Test
    fun aFragmentIsInsertedBoundExactlyWhenItsBlobIsThereAndUnsentExactlyWhenItsObjectIsOutgoing() = MediaFixture().use { f ->
        f.put("media_object")
        // bound, no blob
        val noBlob = f.sql("media_fragment", mapOf("blob_hash" to mBytes(32, 0x96)))
        f.refuses("media_fragment_bound_blob_insert", "a fragment is bound exactly when its blob row exists", noBlob.first, *noBlob.second.toTypedArray())
        f.ensureBlob(MediaFixture.BLOB)
        // expected, blob there (an incoming object, so that only this rule applies)
        f.putIn("fetching")
        val expectedThere = f.sql("media_fragment", mapOf("object_id" to inn, "upload_state" to null, "state" to "expected"))
        f.refuses("media_fragment_bound_blob_insert", "a fragment is bound exactly when its blob row exists", expectedThere.first, *expectedThere.second.toTypedArray())
        // the role rule: an outgoing fragment starts bound and unsent; an incoming one has no upload state
        for (upload in MediaSchema.uploadStates - "unsent") {
            val s = f.sql("media_fragment", mapOf("upload_state" to upload))
            f.refuses("media_fragment_role", "an outgoing fragment starts bound and unsent", s.first, *s.second.toTypedArray())
        }
        val noUpload = f.sql("media_fragment", mapOf("upload_state" to null))
        f.refuses("media_fragment_role", "an outgoing fragment starts bound and unsent", noUpload.first, *noUpload.second.toTypedArray())
        val incomingWithUpload = f.sql("media_fragment", mapOf("object_id" to inn))
        f.refuses("media_fragment_role", "an outgoing fragment starts bound and unsent", incomingWithUpload.first, *incomingWithUpload.second.toTypedArray())
        assertEquals(0L, f.count("media_fragment"))
        f.put("media_fragment")
        f.put("media_fragment", "object_id" to inn, "upload_state" to null)
        assertEquals(2L, f.count("media_fragment"))
    }

    // ------------------------------------------------------------------ the upload

    @Test
    fun anUploadBelongsToAnOutgoingObjectAndKeepsItsNamespaceBucketAndDeadline() = MediaFixture().use { f ->
        f.putIn("fetching")
        f.ensureNamespace(MediaFixture.NS)
        val onIncoming = f.sql("media_upload", mapOf("object_id" to inn))
        f.refuses("media_upload_role", "an upload belongs to an outgoing object", onIncoming.first, *onIncoming.second.toTypedArray())
        f.put("media_object")
        f.put("media_upload")
        val message = "an upload keeps its namespace, bucket and deadline"
        f.ensureNamespace(mBytes(32, 0x4E))
        f.refuses("media_upload_fixed", message, "UPDATE media_upload SET namespace_id = ?", mBytes(32, 0x4E))
        f.refuses("media_upload_fixed", message, "UPDATE media_upload SET ttl_seconds = 3600")
        f.refuses("media_upload_fixed", message, "UPDATE media_upload SET deadline_hour = 7200")
        f.refuses("media_upload_fixed", message, "UPDATE media_upload SET object_id = ?", mBytes(16, 0x01))
        // The same values written again are no change; the retry generation is the one column that moves.
        assertEquals(1, f.upd("UPDATE media_upload SET ttl_seconds = 604800, deadline_hour = 3600000"))
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 1"))
    }

    @Test
    fun theRetryGenerationNeverDecreases() = MediaFixture().use { f ->
        f.put("media_upload", "retry_gen" to 2L)
        f.refuses("media_upload_monotonic", "the retry generation never decreases", "UPDATE media_upload SET retry_gen = 1")
        f.refuses("media_upload_monotonic", "the retry generation never decreases", "UPDATE media_upload SET retry_gen = 0")
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 2"))
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 3"))
        // A second object has its own generation.
        f.put("media_object", "object_id" to mBytes(16, 0xA2))
        f.put("media_upload", "object_id" to mBytes(16, 0xA2))
        assertEquals(1, f.upd("UPDATE media_upload SET retry_gen = 1 WHERE object_id = ?", mBytes(16, 0xA2)))
    }

    @Test
    fun anOutboundOpIsNeverChanged() = MediaFixture().use { f ->
        f.put("media_outbound_op")
        val message = "a media outbound op is never changed"
        f.refuses("media_outbound_op_fixed", message, "UPDATE media_outbound_op SET resend_count = 1")
        f.refuses("media_outbound_op_fixed", message, "UPDATE media_outbound_op SET retry_gen = 1")
        f.refuses("media_outbound_op_fixed", message, "UPDATE media_outbound_op SET operation_id = ?", mBytes(16, 0x01))
        f.refuses("media_outbound_op_fixed", message, "UPDATE media_outbound_op SET resend_count = resend_count")
        // A second op, and the cascade that removes it with its fragment.
        f.put("media_outbound_op", "operation_id" to mBytes(16, 0xE2), "resend_count" to 1L)
        assertEquals(1, f.upd("DELETE FROM media_fragment WHERE object_id = ? AND ordinal = 0", out))
        assertEquals(0L, f.count("media_outbound_op"))
    }

    // ------------------------------------------------------------------ the blob

    @Test
    fun aBlobThatAFragmentNamesIsNotDeleted() = MediaFixture().use { f ->
        f.put("media_fragment")
        f.put("media_fragment", "ordinal" to 1L)
        val delete = "DELETE FROM media_blob WHERE blob_hash = ?"
        val message = "a blob that a fragment names is not deleted"
        f.refuses("media_blob_referenced", message, delete, MediaFixture.BLOB)
        // Two fragments name it (D25): the blob goes only when the last of them has gone.
        assertEquals(1, f.upd("DELETE FROM media_fragment WHERE ordinal = 0"))
        f.refuses("media_blob_referenced", message, delete, MediaFixture.BLOB)
        assertEquals(1, f.upd("DELETE FROM media_fragment WHERE ordinal = 1"))
        assertEquals(1, f.upd(delete, MediaFixture.BLOB))
        // A blob nothing names (a pooled one) goes at any time, and the rule is per blob: another one is untouched.
        f.ensureBlob(mBytes(32, 0x92), mBytes(16, 0xF2))
        f.ensureBlob(mBytes(32, 0x93), mBytes(16, 0xF3))
        f.put("media_fragment", "blob_hash" to mBytes(32, 0x93))
        assertEquals(1, f.upd(delete, mBytes(32, 0x92)))
        f.refuses("media_blob_referenced", message, delete, mBytes(32, 0x93))
        // The object's deletion removes its fragments, and then the blob may go.
        assertEquals(1, f.upd("DELETE FROM media_object WHERE object_id = ?", out))
        assertEquals(1, f.upd(delete, mBytes(32, 0x93)))
    }

    @Test
    fun aBlobKeepsItsHashFileAndOriginAndItsRetentionOnlyMovesEarlier() = MediaFixture().use { f ->
        f.put("media_blob", "origin" to "ingested", "retain_until_day" to 20_008L)
        val message = "a blob keeps its hash, file and origin and its retention only moves earlier"
        f.refuses("media_blob_fixed", message, "UPDATE media_blob SET blob_hash = ?", mBytes(32, 0x01))
        f.refuses("media_blob_fixed", message, "UPDATE media_blob SET file_name = ?", mBytes(16, 0x01))
        f.refuses("media_blob_fixed", message, "UPDATE media_blob SET origin = 'sealed', retain_until_day = NULL")
        f.refuses("media_blob_fixed", message, "UPDATE media_blob SET retain_until_day = 20009")
        f.refuses("media_blob_fixed", message, "UPDATE media_blob SET retain_until_day = NULL, origin = 'sealed'")
        assertEquals(1, f.upd("UPDATE media_blob SET retain_until_day = 20008"))
        assertEquals(1, f.upd("UPDATE media_blob SET retain_until_day = 20001"))
        assertEquals(20_001L, f.db.queryLong("SELECT retain_until_day FROM media_blob"))
        // A second blob has its own retention.
        f.put("media_blob", "blob_hash" to mBytes(32, 0xC2), "file_name" to mBytes(16, 0xF2), "origin" to "ingested", "retain_until_day" to 20_100L)
        assertEquals(1, f.upd("UPDATE media_blob SET retain_until_day = 20050 WHERE blob_hash = ?", mBytes(32, 0xC2)))
    }

    // ------------------------------------------------------------------ the cascades

    /** An object takes its upload, fragments and operations with it; a blob stays (the store deletes it); no other family's row moves. */
    @Test
    fun theCascadesRunFromTheMessageToTheObjectAndOnToItsRows() = MediaFixture().use { f ->
        f.dmMessage(mBytes(16, 0x91))
        f.put("media_object", "message_id" to mBytes(16, 0x91))
        f.put("media_upload")
        f.put("media_fragment")
        f.put("media_outbound_op")
        f.putIn("complete")
        f.put("media_fragment", "object_id" to inn, "upload_state" to null)
        val sync = f.db.queryLong("SELECT count(*) FROM sync_namespace")
        assertEquals(1, f.upd("DELETE FROM dm_message WHERE message_id = ?", mBytes(16, 0x91)))
        assertEquals(mapOf("media_object" to 1L, "media_upload" to 0L, "media_blob" to 1L, "media_fragment" to 1L, "media_outbound_op" to 0L), MediaSchema.tables.associateWith { f.count(it) })
        assertEquals(sync, f.db.queryLong("SELECT count(*) FROM sync_namespace"))
        // The namespace of an upload is not deleted under it (no action): the uploads are deleted first (§5.1).
        f.put("media_object", "object_id" to mBytes(16, 0xA3))
        f.put("media_upload", "object_id" to mBytes(16, 0xA3))
        f.db.rejects(FOREIGN_KEY_FAILED, "DELETE FROM sync_namespace WHERE namespace_id = ?", MediaFixture.NS)
        assertEquals(1, f.upd("DELETE FROM media_upload WHERE object_id = ?", mBytes(16, 0xA3)))
        assertEquals(1, f.upd("DELETE FROM sync_namespace WHERE namespace_id = ?", MediaFixture.NS))
    }

    // ------------------------------------------------------------------ the whole set

    @Test
    fun everyRuleOfTheListWasFiredByATestOfThisClass() {
        // Each test method has its own instance of the class (and its own record), so this one runs the cheapest case of
        // each rule again and requires the record to equal the list: a trigger renamed or dropped fails here by name.
        MediaFixture().use { f ->
            f.dmMessage(mBytes(16, 0x91))
            f.put("media_object", "message_id" to mBytes(16, 0x91))
            f.put("media_upload")
            f.put("media_fragment")
            f.put("media_outbound_op")
            f.refuses("media_object_fixed", "a media object keeps its identity", "UPDATE media_object SET dest_id = ?", mBytes(16, 2))
            f.refuses("media_object_key", "a media key is only ever erased", "UPDATE media_object SET key_env = ?", mBytes(60, 2))
            f.refuses("media_object_state", "illegal media object state transition", "UPDATE media_object SET state = 'verified', key_env = key_env")
            f.putIn("verified", "incomplete_after_hour" to 7_200L)
            f.refuses("media_object_monotonic", "the decode-failure count never decreases", "UPDATE media_object SET incomplete_after_hour = 10800 WHERE object_id = ?", inn)
            f.refuses("media_fragment_state", "a fragment keeps its identity", "UPDATE media_fragment SET ordinal = 9")
            val role = f.sql("media_fragment", mapOf("ordinal" to 2L, "upload_state" to "open"))
            f.refuses("media_fragment_role", "an outgoing fragment starts bound and unsent", role.first, *role.second.toTypedArray())
            val noBlob = f.sql("media_fragment", mapOf("ordinal" to 3L, "blob_hash" to mBytes(32, 0x96)))
            f.refuses("media_fragment_bound_blob_insert", "a fragment is bound exactly when its blob row exists", noBlob.first, *noBlob.second.toTypedArray())
            f.put("media_fragment", "object_id" to inn, "upload_state" to null, "state" to "expected", "blob_hash" to mBytes(32, 0x94))
            f.refuses(
                "media_fragment_bound_blob_update", "a fragment is bound exactly when its blob row exists",
                "UPDATE media_fragment SET state = 'bound' WHERE object_id = ?", inn,
            )
            val upload = f.sql("media_upload", mapOf("object_id" to inn))
            f.refuses("media_upload_role", "an upload belongs to an outgoing object", upload.first, *upload.second.toTypedArray())
            f.refuses("media_upload_fixed", "an upload keeps its namespace", "UPDATE media_upload SET ttl_seconds = 3600")
            f.upd("UPDATE media_upload SET retry_gen = 2")
            f.refuses("media_upload_monotonic", "the retry generation never decreases", "UPDATE media_upload SET retry_gen = 1")
            f.refuses("media_outbound_op_fixed", "never changed", "UPDATE media_outbound_op SET resend_count = 1")
            f.refuses("media_blob_referenced", "is not deleted", "DELETE FROM media_blob WHERE blob_hash = ?", MediaFixture.BLOB)
            f.refuses("media_blob_fixed", "keeps its hash, file and origin", "UPDATE media_blob SET file_name = ?", mBytes(16, 9))
        }
        assertEquals(MediaSchema.rules, fired)
        assertTrue(MediaSchema.rules.size == 14)
        // ... and each of the 14 is in the schema once, by name.
        MediaFixture().use { f ->
            for (rule in MediaSchema.rules) {
                assertEquals(rule, 1L, f.db.queryLong("SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?", listOf(rule)))
            }
        }
    }
}
