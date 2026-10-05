package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * What migration 8 leaves to the DAOs, **recorded and pinned** (Phase 11 design §22.4 row 29; finding 5 of the first lens of the
 * adversarial review of slice S3 and finding 3 of the second).
 *
 * The state machines of §7.6 and §6.4 are enforced by triggers **on update**. Four things are not, because enforcing them is a
 * design decision with a cost the review asked the owner's lead to weigh (the options and the price are in §22.4 row 29):
 *
 *  1. **The first state of a row.** An incoming object can be inserted as `verified`, `complete` or `viewed` (skipping
 *     `MEDIA-VERIFY`) and with `decode_failures` already 2; an outgoing one as `uploaded`.
 *  2. **The state of the parent when a child is added.** A fragment can be added to an object that is already `uploaded` or
 *     `verified`; an operation can name the fragment of an *incoming* object.
 *  3. **The retry of an object.** `failed` → `uploading` needs no increment of `retry_gen` and no deadline (the schema has no
 *     clock): five round trips at generation 3 are accepted.
 *  4. **The retry of a fragment, once it has no operation.** `failed` → `unsent` is allowed "when the upload has no operation of
 *     the ordinal in its current generation", which holds for a fragment that failed with no operation at all.
 *
 * `MediaObjects.insertOutgoing`, `onDescriptor`, `MediaFragments.insertSealed`/`insertIncoming`/`enqueue`/`insertResend` and
 * `MediaObjects.retryUpload` hardcode the legal first states and the order, so none of this is reachable through the stores.
 * This class makes the gap a fact that cannot rot: each case **succeeds today**, and the day a trigger refuses one, the test
 * fails and says to update the note and move the case to [MediaTriggersTest].
 */
class MediaSchemaDeclaredGapsTest {

    private fun MediaFixture.mustStillAccept(why: String, sql: String, vararg args: Any?) {
        try {
            db.exec(sql, args.toList())
        } catch (e: java.sql.SQLException) {
            fail("$why is refused now (${e.message}): the gap of §22.4 row 29 is closed, so update that row and move this case to MediaTriggersTest")
        }
    }

    @Test
    fun theFirstStateOfARowIsNotTheSchemasBusiness() = MediaFixture().use { f ->
        for ((n, state) in listOf("verified", "complete", "viewed").withIndex()) {
            val keyless = state == "viewed"
            f.putIn(
                state, "object_id" to mBytes(16, 0xE0 + n), "decode_failures" to 2L,
                *(if (keyless) arrayOf("key_env" to null, "view_once" to 1L) else emptyArray()),
            )
        }
        f.put("media_object", "object_id" to mBytes(16, 0xE5), "state" to "uploaded")
        assertEquals(4L, f.count("media_object"))
        assertEquals(3L, f.db.queryLong("SELECT count(*) FROM media_object WHERE role = 'in' AND decode_failures = 2"))
    }

    @Test
    fun aRowMayBeAddedToAParentInAnyStateAndAnOperationMayNameAnIncomingFragment() = MediaFixture().use { f ->
        f.put("media_object", "state" to "uploaded")
        f.put("media_fragment") // a fragment added to an object that is already uploaded
        f.putIn("verified")
        f.put("media_fragment", "object_id" to MediaFixture.IN, "upload_state" to null) // ... and to a verified download
        f.mustStillAccept(
            "an operation naming the fragment of an incoming object",
            "INSERT INTO media_outbound_op(operation_id, object_id, ordinal, retry_gen, resend_count) VALUES (?, ?, 0, 0, 0)",
            mBytes(16, 0xE9), MediaFixture.IN,
        )
        assertEquals(2L, f.count("media_fragment"))
        assertEquals(1L, f.count("media_outbound_op"))
    }

    @Test
    fun aFailedObjectGoesBackToUploadingWithNoIncrementOfItsGeneration() = MediaFixture().use { f ->
        f.put("media_object", "state" to "failed")
        f.put("media_upload", "retry_gen" to 3L) // the last generation: three retries are made already
        repeat(5) {
            f.mustStillAccept("failed -> uploading at generation 3, round $it", "UPDATE media_object SET state = 'uploading'")
            f.mustStillAccept("uploading -> failed at generation 3, round $it", "UPDATE media_object SET state = 'failed'")
        }
        assertEquals(3L, f.db.queryLong("SELECT retry_gen FROM media_upload"))
    }

    @Test
    fun aFragmentThatFailedWithNoOperationGoesBackToUnsentWithNoIncrement() = MediaFixture().use { f ->
        f.put("media_fragment")
        f.put("media_upload") // generation 0
        f.mustStillAccept("unsent -> open with no operation", "UPDATE media_fragment SET upload_state = 'open'")
        f.mustStillAccept("open -> failed", "UPDATE media_fragment SET upload_state = 'failed'")
        assertEquals(0L, f.count("media_outbound_op"))
        f.mustStillAccept("failed -> unsent in the same generation with no operation of the ordinal", "UPDATE media_fragment SET upload_state = 'unsent'")
        assertEquals(0L, f.db.queryLong("SELECT retry_gen FROM media_upload"))
    }
}
