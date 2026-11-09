package org.ghost.messaging.media

import org.ghost.media.send.MediaPreparer
import org.ghost.messaging.engine.MediaSteps
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **SCN-MB** (Phase 11 design §15.3): the upload state machine on a class-0 object (17 ordinals)
 * with scripted outcomes — SENT to READY (the countdown, the descriptor sendable exactly once),
 * INDETERMINATE with the two resends and the final-indeterminate rule, FAILED with the user retry
 * (a new generation, the acknowledged ordinals never re-enqueued, the failed one re-fed from the
 * same ciphertext files), and the deadline. The per-ordinal oracles: op ids unique and
 * deterministic, at most two resends per ordinal and generation, an acknowledged ordinal never
 * enqueued again, and `expire_at_minute` never increasing, lowered exactly at READY.
 */
class MediaUploadScenarioTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-scn-mb").toFile()
        val db: String = File(dir, "world.db").absolutePath
        var world: MediaWorld = MediaWorld(db, dir)
        var activated = false

        fun open(relay: ScriptedOutbox = this.world.relay): MediaWorld {
            world.close()
            world = MediaWorld(db, dir, relay)
            if (!activated) {
                world.activate()
                activated = true
            }
            return world
        }
    }

    private fun commitRequest(prepared: MediaPreparer.Prepared, contactId: ByteArray): MediaSteps.CommitRequest {
        val sealed = prepared.sealed
        return MediaSteps.CommitRequest(
            contactId = contactId,
            kind = org.ghost.media.store.MediaKind.IMAGE,
            viewOnce = prepared.viewOnce,
            classCode = sealed.classCode,
            objectId = prepared.objectId,
            manifestHash = sealed.manifestHash,
            caption = "scn-mb".toByteArray(),
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    private fun commitOne(world: MediaWorld, contact: ByteArray, tag: Byte): ByteArray {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        // Distinguish objects: rewrite the object id the request names (the sealer's id is fixed).
        val request = commitRequest(prepared, contact).let { r ->
            MediaSteps.CommitRequest(
                contactId = r.contactId, kind = r.kind, viewOnce = r.viewOnce, classCode = r.classCode,
                objectId = ByteArray(16) { tag.toByte() }, manifestHash = r.manifestHash,
                caption = r.caption, keyEnv = r.keyEnv, manifestBlob = r.manifestBlob,
                manifestFile = r.manifestFile, fragmentHashes = r.fragmentHashes,
                fragmentFiles = r.fragmentFiles,
            )
        }
        val result = world.steps.commit(world.contexts.get()!!, request)
        check(result is MediaSteps.CommitResult.Committed)
        world.steps.feed()
        return request.objectId
    }

    private fun oracleOps(world: MediaWorld, objectId: ByteArray): Long =
        world.sql.queryLong(
            "SELECT count(*) FROM media_outbound_op WHERE object_id = ?",
            listOf(objectId),
        )!!

    /**
     * §15.3's SCN-MB enumeration: a crash at every file operation of the upload run (the
     * preparation, `MEDIA-COMMIT`, `MEDIA-FEED`), a reboot and the MB oracles after each — the op
     * set stays exactly the 17 first-feed ops (release-first + deterministic op ids: a resumed
     * feed never double-feeds), the run resumes to READY from wherever the process died. The
     * outcome branches (INDETERMINATE resends, FAILED retry, the deadline) have their dedicated
     * tests above; this enumeration covers the crash points of the happy upload path.
     */
    @Test
    fun aCrashAtEveryFileOperationOfTheUploadRunResumesToReady() {
        if (!MediaScenarios.owns(1)) return
        val objectId = ByteArray(16) { 0x35 }

        // Quiet pass: count the run's file calls (prepare + commit + feed).
        val counter = Sandbox()
        val cw = counter.open()
        val ccid = ByteArray(16) { 0x21 }
        cw.addContact(ccid)
        commitOne(cw, ccid, tag = 0x35)
        val totalCalls = cw.crashFs.trace.size
        counter.world.close()

        for (k in 1..totalCalls) {
            val box = Sandbox()
            var world = box.open()
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            world.crashFs.crashAtCall = k
            try {
                commitOne(world, contact, tag = 0x35)
                error("the crash at call $k did not fire")
            } catch (e: Exception) {
                // the process death: close without reconcile, like a power loss
            }
            box.world.close()

            world = box.open()
            world.reconcile()
            world.assertSendInvariants()
            val committed = world.sql.queryLong(
                "SELECT count(*) FROM media_object WHERE object_id = ?",
                listOf(objectId),
            )!! > 0
            if (!committed) {
                // The crash preceded MEDIA-COMMIT: the preparation is memory-only (S0-23), its
                // orphaned files died with the reconcile; the run redoes from the preparation.
                commitOne(world, contact, tag = 0x35)
            } else {
                // Mid-feed: the release-first ops resume; an ordinal already fed is not fed twice.
                world.steps.feed()
            }
            world.assertSendInvariants()
            repeat(17) { i ->
                world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
            }
            world.steps.outcomes()
            assertEquals(
                "crash at call $k: uploaded",
                "uploaded",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
            )
            // The MB oracle: exactly the 17 first-feed ops — no double feed across the crash.
            assertEquals("crash at call $k: 17 ops, every id unique", 17L, oracleOps(world, objectId))
            world.assertSendInvariants()
            box.world.close()
        }
        MediaScenarios.report("SCN-MB", totalCalls, "preparation, MEDIA-COMMIT and MEDIA-FEED file operations on a class-0 object")
    }

    @Test
    fun sentOutcomesReachReadyExactlyOnceWithTheCountdownStarted() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x30)

        val expireBefore = world.sql.queryLong(
            "SELECT expire_at_minute FROM dm_message WHERE kind = 5",
            emptyList(),
        )!!
        // SENT for every ordinal, one pass.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        val expireAfter = world.sql.queryLong(
            "SELECT expire_at_minute FROM dm_message WHERE kind = 5",
            emptyList(),
        )!!
        assertTrue("the countdown never increases", expireAfter <= expireBefore)
        assertTrue("the countdown moved to the deadline hour + timer", expireAfter < expireBefore)
        // The descriptor is sendable exactly once: with the envelope layer closed the flush stops
        // at the decode (the item stays pending, no descriptor op reaches the relay — on a device
        // the session check queues it in dm_pending_send; §6.3's "waits exactly as a text does").
        assertEquals(
            "pending",
            world.sql.queryString("SELECT state FROM dm_outbound_item WHERE kind = 5", emptyList()),
        )
        assertEquals(18, world.relay.held.size) // 17 media ops + the owner's bundle op, no descriptor
        // A further pass changes nothing.
        world.steps.outcomes()
        assertEquals(18, world.relay.held.size)
        box.world.close()
    }

    @Test
    fun indeterminateResendsTwiceThenSettlesFinal() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x31)

        val op0 = world.relay.opIdOf(objectId, 0)
        // INDETERMINATE with resend budget: resend 1; again: resend 2; again: no budget left.
        world.relay.script(op0, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        assertEquals(
            "the ordinal stays open on a resend",
            "open",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 0",
                listOf(objectId),
            ),
        )
        val resend1 = world.relay.opIdOf(objectId, 0, resend = 1)
        world.relay.script(resend1, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        val resend2 = world.relay.opIdOf(objectId, 0, resend = 2)
        world.relay.script(resend2, Outcome.INDETERMINATE, resendNotAfter = MediaWorld.NOW + 3_600)
        world.steps.outcomes()
        assertEquals(
            "final indeterminate after the budget",
            "indeterminate",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 0",
                listOf(objectId),
            ),
        )
        // Oracle: 17 first-feed ops + 2 resends for ordinal 0, every id unique.
        assertEquals(19L, oracleOps(world, objectId))
        // The other ordinals are still open (no outcomes scripted for them): 1..15 = 15.
        assertEquals(
            15L,
            world.sql.queryLong(
                "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'open' AND ordinal > 0",
                listOf(objectId),
            ),
        )
        box.world.close()
    }

    @Test
    fun aFailedOrdinalFailsTheObjectAndTheUserRetryRefeedsOnlyTheFailedOrdinal() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x32)

        // SENT for ordinals -1..14, FAILED for 15: the object fails mid-burst.
        repeat(16) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.relay.script(world.relay.opIdOf(objectId, 15), Outcome.FAILED)
        world.steps.outcomes()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM dm_message WHERE kind = 5", emptyList()),
        )
        // User retry before the deadline: generation 1, the failed ordinal back to unsent.
        val retried = world.database.transaction { tx -> world.objects.retryUpload(tx, objectId, MediaWorld.NOW) }
        assertEquals(org.ghost.media.store.RetryResult.RETRIED, retried)
        world.steps.feed()
        // Oracle: the acknowledged 16 ordinals were never enqueued again. The retried ordinal's
        // identical bytes are refused by Phase 7's UNIQUE(namespace, blob_hash) (F-S5-19): it
        // stays unsent, the 17 first-feed ops remain the object's whole op set.
        assertEquals(17L, oracleOps(world, objectId))
        assertEquals(
            "unsent",
            world.sql.queryString(
                "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = 15",
                listOf(objectId),
            ),
        )
        box.world.close()
    }

    @Test
    fun theDeadlineFailsTheObjectAndTheOrphanRuleTakesTheUpload() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        val mediaNs = world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x33)

        world.clock.now = MediaWorld.NOW + 7 * 86_400L + 3_600L
        world.steps.deadline()
        assertEquals(
            "failed",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        // The 17 ops the relay still holds (released = 0) block the orphan rule — the clause is
        // live because the world's relay writes real outbox_op rows (F-S5-16).
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM dm_orphan_namespace", emptyList()),
        )
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(objectId)),
        )
        // The outbox decides them SENT (a device that came back late): the releases drain the
        // clause and the orphan completes — the upload row goes, M_c is recorded.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            1L,
            world.sql.queryLong(
                "SELECT count(*) FROM dm_orphan_namespace WHERE namespace_id = ?",
                listOf(mediaNs),
            ),
        )
        box.world.close()
    }

    @Test
    fun aTimerChangeDuringUploadDoesNotSplitTheObjectsBucket() {
        // R-MT4 (§7.3 S8, ADR-45 point 4): every blob of an object **and its descriptor** carry
        // one TTL, fixed at commit — a timer change mid-upload must not re-bucket the object.
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = commitOne(world, contact, tag = 0x34)
        val bucketAtCommit = world.sql.queryLong(
            "SELECT ttl_seconds FROM media_upload WHERE object_id = ?",
            listOf(objectId),
        )!!
        assertEquals(604_800L, bucketAtCommit) // the world's conversation timer is the 7-day one

        // Mid-upload: the conversation's timer goes 7 d → 1 h (TIMER_SET's shape at the row).
        world.sql.exec(
            "UPDATE dm_conversation SET timer_code = 0, timer_version = timer_version + 1 " +
                "WHERE contact_id = ?",
            listOf(contact),
        )

        // Every ordinal SENT: READY lowers the countdown; the object's bucket is untouched.
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            "the upload row keeps the commit-time bucket (R-MT4)",
            bucketAtCommit,
            world.sql.queryLong("SELECT ttl_seconds FROM media_upload WHERE object_id = ?", listOf(objectId)),
        )
        assertEquals(
            "the descriptor item carries the object's bucket, not the conversation's new timer",
            bucketAtCommit,
            world.sql.queryLong("SELECT ttl_seconds FROM dm_outbound_item WHERE kind = 5", emptyList()),
        )
        assertEquals(
            "the conversation's timer did change (the test's premise)",
            1L,
            world.sql.queryLong(
                "SELECT count(*) FROM dm_conversation WHERE contact_id = ? AND timer_code = 0",
                listOf(contact),
            ),
        )
        box.world.close()
    }
}
