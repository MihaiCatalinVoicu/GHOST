package org.ghost.messaging.media

import org.ghost.media.send.MediaPreparer
import org.ghost.messaging.engine.MediaSteps
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * §6.4/§11.2's **view-once sender cleanup** over [MediaWorld] (slice S8): once the descriptor has
 * a final outcome other than FAILED (SENT, DEGRADED, final INDETERMINATE — the INDETERMINATE
 * whose resends are spent, MC-M20's target), the sender's copy — `key_env`, the fragment rows,
 * every unshared blob — goes in the outcome's transaction, the §11.1 checkpoint and the reconcile
 * after the commit (§13.5). A FAILED descriptor keeps the copy for the user's retry until the
 * deadline; `MEDIA-DEADLINE` then runs the same cleanup. A normal (re-viewable) object keeps its
 * copy until the message expires (§11.1), and the object row itself stays with its state — only
 * the key and the bytes go.
 */
class MediaViewOnceSenderTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-vo-send").toFile()
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
            caption = "vo-sender".toByteArray(),
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    private class Sent(val objectId: ByteArray, val messageId: ByteArray, val blobHashes: List<ByteArray>)

    /** Commit one object and drive its upload to READY (every ordinal SENT), as SCN-MB does. */
    private fun sendToReady(world: MediaWorld, contact: ByteArray, viewOnce: Boolean, tag: Byte): Sent {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = viewOnce)
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
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(request.objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(request.objectId)),
        )
        prepared.releaseNames()
        val hashes = ArrayList<ByteArray>()
        world.sql.query(
            "SELECT b.blob_hash FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "WHERE f.object_id = ?",
            listOf(request.objectId),
        ) { hashes += it.blob(0).copyOf() }
        return Sent(request.objectId, result.messageId, hashes)
    }

    /**
     * Give the descriptor its F9 op shape and script its outcome. The world's envelope layer is
     * closed (MediaUploadScenarioTest's note), so the descriptor item sits `pending`; OUTCOME's
     * guarded moves expect `enqueued`, and `dm_outbound_op` is the F9 row a deposited descriptor
     * would have — the outcome then drives the real `OutcomeStep.terminal`.
     */
    private fun decideDescriptor(world: MediaWorld, sent: Sent, outcome: Outcome, resendNotAfter: Long? = null) {
        world.sql.exec("UPDATE dm_outbound_item SET state = 'enqueued' WHERE item_id = ?", listOf(sent.messageId))
        val opId = world.random.bytes(16)
        val deadline = world.sql.queryLong(
            "SELECT u.deadline_hour FROM media_upload u WHERE u.object_id = ?",
            listOf(sent.objectId),
        )!!
        world.sql.exec(
            "INSERT INTO dm_outbound_op(operation_id, purpose, item_id, bundle_week, blob, resend_count, " +
                "deadline_hour) VALUES (?, 'item', ?, NULL, NULL, 0, ?)",
            listOf(opId, sent.messageId, deadline),
        )
        world.relay.scriptDm(org.ghost.sync.api.OperationId(opId), outcome, resendNotAfter)
    }

    private fun assertCopyErased(world: MediaWorld, sent: Sent) {
        assertEquals(
            "the key is gone, the object row stays with its state",
            "1",
            world.sql.queryString(
                "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NULL AND state = 'uploaded'",
                listOf(sent.objectId),
            ),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(sent.objectId)),
        )
        for (hash in sent.blobHashes) {
            assertEquals(
                "every unshared blob of the object went",
                0L,
                world.sql.queryLong("SELECT count(*) FROM media_blob WHERE blob_hash = ?", listOf(hash)),
            )
        }
        assertEquals(
            "the op rows cascaded with the fragments",
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_outbound_op WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertTrue("the checkpoint followed the key erasure (§11.1)", world.checkpointLog.isNotEmpty())
        val named = sent.blobHashes.map { hexOf(it) }.toSet()
        assertTrue(
            "the reconcile took the files",
            world.files.list().none { it in named },
        )
    }

    @Test
    fun aFinalSentDescriptorErasesTheSendersCopyAtOnce() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val sent = sendToReady(world, contact, viewOnce = true, tag = 0x40)

        decideDescriptor(world, sent, Outcome.SENT)
        world.outcomeStep.run()
        assertEquals(
            "the descriptor is sent",
            "sent",
            world.sql.queryString(
                "SELECT state FROM dm_outbound_item WHERE item_id = ?",
                listOf(sent.messageId),
            ),
        )
        assertCopyErased(world, sent)
        // EP-M (7) at the row level: the upload half is over and the orphan clause fired — the
        // namespace row itself goes with F9's sweep of dm_orphan_namespace (SweepTest's half).
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertEquals(
            1L,
            world.sql.queryLong("SELECT count(*) FROM dm_orphan_namespace", emptyList()),
        )
        box.world.close()
    }

    @Test
    fun degradedAndFinalIndeterminateDescriptorsDoTheSame() {
        for (outcome in listOf(Outcome.DEGRADED, Outcome.INDETERMINATE)) {
            val box = Sandbox()
            val world = box.open()
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val sent = sendToReady(world, contact, viewOnce = true, tag = 0x41)

            // Final INDETERMINATE: no resend window scripted, so the terminal rule settles it —
            // this is the exact path MC-M20 ("cleanup skipped on a final INDETERMINATE") guards.
            decideDescriptor(world, sent, outcome)
            world.outcomeStep.run()
            assertEquals(
                outcome.name.lowercase(),
                world.sql.queryString(
                    "SELECT state FROM dm_outbound_item WHERE item_id = ?",
                    listOf(sent.messageId),
                ),
            )
            assertCopyErased(world, sent)
            box.world.close()
        }
    }

    @Test
    fun aFailedDescriptorKeepsTheCopyUntilTheDeadline() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        // The 30-day timer: the upload deadline is capped at 7 days (R-T4's min(bucket, 7 d)),
        // the message's countdown runs 30 days — so the deadline cleanup genuinely precedes the
        // sweep (with a ≤ 7-day timer the sweep owns the same minute and takes the rows first).
        world.sql.exec(
            "UPDATE dm_conversation SET timer_code = 5 WHERE contact_id = ?",
            listOf(contact),
        )
        val sent = sendToReady(world, contact, viewOnce = true, tag = 0x42)

        decideDescriptor(world, sent, Outcome.FAILED)
        world.outcomeStep.run()
        assertEquals(
            "failed",
            world.sql.queryString(
                "SELECT state FROM dm_outbound_item WHERE item_id = ?",
                listOf(sent.messageId),
            ),
        )
        assertEquals(
            "FAILED is not terminal: the copy stays for the user's retry",
            "1",
            world.sql.queryString(
                "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL",
                listOf(sent.objectId),
            ),
        )
        assertEquals(
            17L,
            world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(sent.objectId)),
        )

        // The retry window ends at the deadline: the same cleanup runs there (§6.4's last rule).
        world.clock.now = MediaWorld.NOW + 7 * 86_400L + 3_600L
        world.steps.deadline()
        assertCopyErased(world, sent)
        box.world.close()
    }

    @Test
    fun aNormalDescriptorKeepsTheSendersCopyUntilExpiry() {
        val box = Sandbox()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val sent = sendToReady(world, contact, viewOnce = false, tag = 0x43)

        decideDescriptor(world, sent, Outcome.SENT)
        world.outcomeStep.run()
        assertEquals(
            "a re-viewable object keeps its key and bytes until the message expires (§11.1)",
            "1",
            world.sql.queryString(
                "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL AND state = 'uploaded'",
                listOf(sent.objectId),
            ),
        )
        assertEquals(
            17L,
            world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertNotNull(
            world.sql.queryString("SELECT state FROM dm_outbound_item WHERE item_id = ?", listOf(sent.messageId)),
        )
        box.world.close()
    }
}
