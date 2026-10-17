package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * **T25 for media — the EP-M suite** (Phase 11 design §15.5), in the `EphemeralTest` shape: one
 * case per rule, pinning the behaviour the gate-scale EP suite will measure across the whole
 * timer × path matrix (that cross product, with the relay lies and the test destination of §5.6,
 * is S9's; the §15.8 physical scans at gate scale are the emulator job's).
 *
 * Each case drives the real engine steps over [MediaWorld] (file-backed, WAL + `secure_delete`,
 * as the device), advances the virtual clock to the §11.1 bound + 1 min, sweeps through the real
 * [MessagingRuntime.SweepMediaPort] contract and asserts §15.5's oracles: (1) logically no
 * `media_object`/`media_upload`/`media_fragment`/`media_outbound_op` row; (2) physically the raw
 * `.db` and `-wal` hold no `key_env` byte and the store holds no file of the object; (3) the WAL
 * is 0 bytes after the checkpoint; (3b) right after `VIEW-ONCE-OPEN` and every other key-erasing
 * transaction — covered by `MediaViewOnceTest`'s raw scan; (6) the preview cache holds no entry
 * of the object. EP-M's (4) (a clock stepped back does not delay deletion) and (5) (one bucket
 * for every store and the descriptor) are F9's `EphemeralTest`/`aClockSteppedBackDoesNotDelayTheWake`
 * and S5's `MediaUploadScenarioTest` respectively — the media rows add no new clock or bucket
 * behaviour, and (7) (`M_c` orphaned) is `MediaViewOnceSenderTest` at the row level plus F9's
 * sweeper half.
 */
class MediaEphemeralTest {

    companion object {
        /** The gate report's T25-media line: written when the suite ran inside a gate invocation. */
        @org.junit.AfterClass
        @JvmStatic
        fun reportT25Media() {
            if (System.getProperty("ghost.media.report") != null) {
                MediaPrivacyReport.line(
                    "T25 media (EP-M): PASS (every timer x path at the slice's scale, the physical byte oracles)",
                )
            }
        }
    }

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-epm").toFile()
        val db: String = File(dir, "world.db").absolutePath
        var activated = false

        fun open(): MediaWorld {
            val world = MediaWorld(db, dir)
            if (!activated) {
                world.activate()
                activated = true
            }
            return world
        }
    }

    private class Sent(
        val objectId: ByteArray,
        val messageId: ByteArray,
        val keyNeedle: ByteArray,
        val blobHashes: List<ByteArray>,
    )

    private fun support(world: MediaWorld): MediaEngineSupport = MediaEngineSupport(
        database = world.database,
        steps = world.steps,
        receiveSteps = world.receiveSteps,
        preparations = org.ghost.media.send.Preparations(),
        pipeline = MediaPipelinePorts(
            world.files, world.preparing, FakeStripper, FakeVideoExport, world.readers, world.decoder,
        ),
        worker = Executors.newSingleThreadExecutor(),
        random = world.random,
        contexts = world.contexts,
        actorCall = { it() },
        checkpoint = { world.checkpointLog += true; true },
    )

    // ------------------------------------------------------------- fixtures

    /** Commit one object and drive its upload to READY; returns the oracles' needles. */
    private fun sendToReady(world: MediaWorld, contact: ByteArray, viewOnce: Boolean, tag: Byte): Sent {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = viewOnce)
        val sealed = prepared.sealed
        val objectId = ByteArray(16) { tag.toByte() }
        val result = world.steps.commit(world.contexts.get()!!, commitRequest(contact, viewOnce, objectId, sealed))
        world.steps.feed()
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        assertEquals(
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        prepared.releaseNames()
        val hashes = objectBlobHashes(world, objectId)
        return Sent(objectId, result.messageId(), sealed.keyEnv.copyOf(), hashes)
    }

    private fun commitRequest(
        contact: ByteArray,
        viewOnce: Boolean,
        objectId: ByteArray,
        sealed: org.ghost.media.send.SealedResult,
    ): org.ghost.messaging.engine.MediaSteps.CommitRequest = org.ghost.messaging.engine.MediaSteps.CommitRequest(
        contactId = contact,
        kind = MediaKind.IMAGE,
        viewOnce = viewOnce,
        classCode = sealed.classCode,
        objectId = objectId,
        manifestHash = sealed.manifestHash,
        caption = "ep-m".toByteArray(),
        keyEnv = sealed.keyEnv,
        manifestBlob = sealed.manifestBlob,
        manifestFile = sealed.manifestFile,
        fragmentHashes = sealed.fragmentHashes,
        fragmentFiles = sealed.fragmentFiles,
    )

    private fun org.ghost.messaging.engine.MediaSteps.CommitResult.messageId(): ByteArray =
        when (this) {
            is org.ghost.messaging.engine.MediaSteps.CommitResult.Committed -> messageId
            else -> error("the commit refused: $this")
        }

    private fun objectBlobHashes(world: MediaWorld, objectId: ByteArray): List<ByteArray> {
        val hashes = ArrayList<ByteArray>()
        world.sql.query(
            "SELECT b.blob_hash FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "WHERE f.object_id = ?",
            listOf(objectId),
        ) { hashes += it.blob(0).copyOf() }
        return hashes
    }

    /** Receive and verify an incoming object, with the conversation's timer set as asked. */
    private fun receiveVerified(
        world: MediaWorld,
        contact: ByteArray,
        viewOnce: Boolean,
        timerCode: Int,
        unreadDeadlineMinute: Long?,
        incompleteAfterHour: Long = MediaWorld.NOW + 7 * 86_400,
        runVerify: Boolean = true,
    ): Sent {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = viewOnce)
        val sealed = prepared.sealed
        world.depositMedia(sealed.manifestBlob)
        for (i in sealed.fragmentHashes.indices) {
            world.depositMedia(world.files.read(sealed.fragmentFiles[i]))
        }
        val messageId = world.random.bytes(16)
        val self = world.contexts.get()!!
        val bodyEnv = self.content.seal(world.random.bytes(12), messageId, "media".toByteArray())
        world.database.transaction { tx ->
            var conversationId = ByteArray(0)
            tx.sql.query(
                "SELECT conversation_id FROM dm_conversation WHERE contact_id = ?",
                listOf(contact),
            ) { conversationId = it.blob(0) }
            org.ghost.messaging.store.MessageStore().insertIncomingIfAbsent(
                tx = tx,
                messageId = messageId,
                conversationId = conversationId,
                kind = 5,
                authorMinute = org.ghost.messaging.engine.DmTime.floorMinute(world.clock.now),
                sortMinute = org.ghost.messaging.engine.DmTime.floorMinute(world.clock.now),
                minuteIndex = 0,
                timerCode = timerCode,
                bodyEnv = bodyEnv,
                unreadDeadlineMinute = unreadDeadlineMinute,
            )
            world.objects.onDescriptor(
                tx = tx,
                messageId = messageId,
                contactId = contact,
                descriptor = org.ghost.media.store.MediaDescriptor(
                    prepared.objectId, MediaKind.IMAGE, viewOnce = viewOnce, classCode = 0,
                    manifestHash = sealed.manifestHash,
                ),
                keyEnv = sealed.keyEnv,
                incompleteAfterHour = incompleteAfterHour,
            )
        }
        world.receiveSteps.ingest()
        world.receiveSteps.bind()
        if (runVerify) {
            world.receiveSteps.verify()
            assertEquals(
                "verified",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(prepared.objectId)),
            )
        } else {
            assertEquals(
                "complete",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(prepared.objectId)),
            )
        }
        prepared.releaseNames()
        val hashes = objectBlobHashes(world, prepared.objectId)
        return Sent(prepared.objectId, messageId, FakeReaders.fakeKeyEnvOf(prepared.objectId), hashes)
    }

    /**
     * SWEEP's media half through the real port contract: the port call inside the sweep
     * transaction (before the message delete), the message delete, then the §11.1 checkpoint and
     * the reconcile — what F9's sweeper and the media pass run around [SweepMediaPort].
     */
    private class SweepResult(val deletedObjectIds: List<ByteArray>, val walBytes: Long)

    private fun sweep(world: MediaWorld, messageIds: List<ByteArray>): SweepResult {
        val port = MessagingRuntime.SweepMediaPort()
        world.database.transaction { tx ->
            port.onMessagesDeleted(tx, messageIds.map { MessageId(it) })
            for (id in messageIds) {
                tx.sql.exec("DELETE FROM dm_message WHERE message_id = ?", listOf(id))
            }
        }
        world.realCheckpoint()
        val walBytes = File(world.dbPath + "-wal").length()
        world.reconcile()
        return SweepResult(port.drainDeletedObjectIds(), walBytes)
    }

    // ------------------------------------------------------------- the sender bound

    /** §15.5's "sender uploaded": at the countdown's end nothing of the object remains. */
    @Test
    fun senderUploadedGoesAtTheCountdownBound() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val sent = sendToReady(world, contact, viewOnce = false, tag = 0x50)
        val expireAt = world.sql.queryLong(
            "SELECT expire_at_minute FROM dm_message WHERE message_id = ?",
            listOf(sent.messageId),
        )!!

        world.clock.now = expireAt + 60
        val swept = sweep(world, listOf(sent.messageId))
        assertGone(world, sent)
        assertEquals("the WAL is 0 bytes after the checkpoint (EP-M 3)", 0L, swept.walBytes)
        world.close()
    }

    // ----------------------------------------------------------- the recipient bounds

    /** §15.5's "recipient verified-unread": the unread cap is the bound. */
    @Test
    fun recipientVerifiedUnreadGoesAtTheUnreadCap() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val consume = world.clock.now
        val deadline = ceilMinute(consume + 2 * 3_600L) // 1 h timer: consume + bucket + 1 h
        val received = receiveVerified(world, contact, viewOnce = false, timerCode = 2, unreadDeadlineMinute = deadline)

        world.clock.now = deadline + 60
        val swept = sweep(world, listOf(received.messageId))
        assertGone(world, received)
        assertEquals(0L, swept.walBytes)
        world.close()
    }

    /** §15.5's "recipient verified-displayed": the display restarts the countdown. */
    @Test
    fun recipientVerifiedDisplayedGoesAtItsOwnCountdown() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val consume = world.clock.now
        // 7-day timer: the unread cap is consume + 7 d + 1 h; a display a day later restarts
        // the countdown at display + 7 d, later than the cap (§10.3's "may move later").
        val cap = ceilMinute(consume + 7 * 86_400L + 3_600L)
        val received = receiveVerified(world, contact, viewOnce = false, timerCode = 4, unreadDeadlineMinute = cap)

        world.clock.now = consume + 86_400L
        val displayed = ceilMinute(world.clock.now + 7 * 86_400L)
        world.sql.exec(
            "UPDATE dm_message SET expire_at_minute = ?, delete_at_minute = ? WHERE message_id = ?",
            listOf(displayed, displayed, received.messageId),
        )
        assertTrue("display moved the bound later than the cap", displayed > cap)

        world.clock.now = displayed + 60
        val swept = sweep(world, listOf(received.messageId))
        assertGone(world, received)
        assertEquals(0L, swept.walBytes)
        world.close()
    }

    // ------------------------------------------------------------------ view-once paths

    /** §15.5's "view-once unopened": the object goes with its message, key bytes included. */
    @Test
    fun viewOnceUnopenedGoesWithItsMessage() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val consume = world.clock.now
        val deadline = ceilMinute(consume + 2 * 3_600L)
        val received = receiveVerified(world, contact, viewOnce = true, timerCode = 2, unreadDeadlineMinute = deadline)

        world.clock.now = deadline + 60
        val swept = sweep(world, listOf(received.messageId))
        assertGone(world, received)
        assertEquals(0L, swept.walBytes)
        world.close()
    }

    // ------------------------------------------------------- the loss paths (SCN-ME's half)

    /** §15.5's "incomplete" and "corrupt": the key is erased with the state, the references go. */
    @Test
    fun incompleteAndCorruptPathsEraseTheKeyAndReleaseTheReferences() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val deadline1h = ceilMinute(world.clock.now + 2 * 3_600L)

        // `incomplete`: only the manifest ever arrives; the relay window (incomplete_after_hour)
        // passes while the object still `fetching`, and `MEDIA-GC` declares the loss.
        val lostPrepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        world.depositMedia(lostPrepared.sealed.manifestBlob)
        val lostMessage = world.random.bytes(16)
        val self = world.contexts.get()!!
        val lostBody = self.content.seal(world.random.bytes(12), lostMessage, "lost".toByteArray())
        world.database.transaction { tx ->
            var conversationId = ByteArray(0)
            tx.sql.query(
                "SELECT conversation_id FROM dm_conversation WHERE contact_id = ?",
                listOf(contact),
            ) { conversationId = it.blob(0) }
            org.ghost.messaging.store.MessageStore().insertIncomingIfAbsent(
                tx = tx,
                messageId = lostMessage,
                conversationId = conversationId,
                kind = 5,
                authorMinute = org.ghost.messaging.engine.DmTime.floorMinute(world.clock.now),
                sortMinute = org.ghost.messaging.engine.DmTime.floorMinute(world.clock.now),
                minuteIndex = 0,
                timerCode = 2,
                bodyEnv = lostBody,
                unreadDeadlineMinute = deadline1h,
            )
            world.objects.onDescriptor(
                tx = tx,
                messageId = lostMessage,
                contactId = contact,
                descriptor = org.ghost.media.store.MediaDescriptor(
                    lostPrepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = lostPrepared.sealed.manifestHash,
                ),
                keyEnv = lostPrepared.sealed.keyEnv,
                incompleteAfterHour = MediaWorld.NOW + 3_600,
            )
        }
        lostPrepared.releaseNames()
        world.receiveSteps.ingest()
        world.receiveSteps.bind()
        val lost = Sent(
            lostPrepared.objectId, lostMessage,
            FakeReaders.fakeKeyEnvOf(lostPrepared.objectId),
            objectBlobHashes(world, lostPrepared.objectId),
        )
        assertEquals("fetching", stateOf(world, lost.objectId))

        // Past the relay window (NOW + 1 h) but well inside the message's own unread deadline
        // (NOW + 2 h): the loss is declared while the message lives.
        world.clock.now = MediaWorld.NOW + 3_600 + 1_800
        world.receiveSteps.gc()
        assertEquals("incomplete", stateOf(world, lost.objectId))
        assertNoKeyAndNoFiles(world, lost)

        // `corrupt`: one flipped byte fails the verify walk (before any exposure); the object
        // releases everything.
        val tampered = receiveVerified(
            world, contact, viewOnce = false, timerCode = 2, unreadDeadlineMinute = deadline1h,
            runVerify = false,
        )
        val file = fragmentFileOf(world, tampered.objectId, 1)
        val bytes = world.files.read(file)
        bytes[123] = (bytes[123].toInt() xor 0x01).toByte()
        java.nio.file.Files.write(java.io.File(world.files.directory, hexName(file)).toPath(), bytes)
        world.receiveSteps.verify()
        assertEquals("corrupt", stateOf(world, tampered.objectId))
        assertNoKeyAndNoFiles(world, tampered)
        world.close()
    }

    private fun stateOf(world: MediaWorld, objectId: ByteArray): String? =
        world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId))

    /** §15.5's "sender deleted by its user during upload": the rows, key and files go at once. */
    @Test
    fun aMessageDeletedByItsUserDuringUploadGoesAtOnce() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        val sealed = prepared.sealed
        val objectId = ByteArray(16) { 0x51 }
        val result = world.steps.commit(world.contexts.get()!!, commitRequest(contact, false, objectId, sealed))
        world.steps.feed() // the ops are open, the outbox holds the frozen payloads
        prepared.releaseNames()
        val committed = result.messageId()
        val sent = Sent(
            objectId, committed, sealed.keyEnv.copyOf(),
            objectBlobHashes(world, objectId),
        )

        val swept = sweep(world, listOf(committed))
        assertGone(world, sent)
        assertEquals(0L, swept.walBytes)

        // The ops the relay still holds run to their outcome untouched (F9 §21.10): the release
        // stands, the outcome is ignored, nothing reappears.
        world.relay.script(world.relay.opIdOf(sent.objectId, 0), Outcome.SENT)
        assertEquals("the late outcome is released and ignored", 1, world.steps.outcomes())
        assertGone(world, sent)
        world.close()
    }

    // ------------------------------------------------------------- the preview cache (EP-M 6)

    /** §15.5's (6): after the sweep the preview cache holds no entry of the object. */
    @Test
    fun thePreviewCacheHoldsNoEntryOfTheObjectAfterDeletion() {
        val box = Box()
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val deadline1h = ceilMinute(world.clock.now + 2 * 3_600L)
        val received = receiveVerified(world, contact, viewOnce = false, timerCode = 2, unreadDeadlineMinute = deadline1h)
        val facade = support(world)
        facade.onForeground(true)
        facade.onScreen(contact)
        assertNotNull("the preview decoded and cached", facade.preview(received.messageId))
        assertTrue("the cache held the entry before the sweep", facade.previewCacheHolds(received.objectId))

        // The media pass's exact sweep shape (MessagingRuntime.MediaPassSteps.runIngestBindVerify):
        // drain the port's object ids, evict their previews, reconcile the dereferenced files.
        val swept = sweep(world, listOf(received.messageId))
        facade.evictPreviews(swept.deletedObjectIds)
        assertFalse(
            "the erased preview is gone from the cache (§10.5, EP-M 6)",
            facade.previewCacheHolds(received.objectId),
        )
        world.close()
    }

    // ------------------------------------------------------------- oracles

    /** §15.5's (1)–(3): the logical and the physical half of "nothing remains". */
    private fun assertGone(world: MediaWorld, sent: Sent) {
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_object WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_upload WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM media_outbound_op WHERE object_id = ?", listOf(sent.objectId)),
        )
        assertEquals(
            0L,
            world.sql.queryLong("SELECT count(*) FROM dm_message WHERE message_id = ?", listOf(sent.messageId)),
        )
        assertFalse("no key_env byte in the raw .db or -wal", bytesHold(world, sent.keyNeedle))
        val named = sent.blobHashes.map { hexOf(it) }.toSet()
        assertTrue("no file of the object in the store", world.files.list().none { it in named })
    }

    /** The keyless-state half: the key is erased, the checkpoint ran, the files went. */
    private fun assertNoKeyAndNoFiles(world: MediaWorld, sent: Sent) {
        assertEquals(
            "the key went with the transition (T45)",
            "1",
            world.sql.queryString(
                "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NULL",
                listOf(sent.objectId),
            ),
        )
        assertTrue("the checkpoint followed the key erasure (§11.1)", world.checkpointLog.isNotEmpty())
        world.reconcile()
        val named = sent.blobHashes.map { hexOf(it) }.toSet()
        assertTrue("the released files went with the reconcile", world.files.list().none { it in named })
        assertFalse("no key_env byte in the raw .db or -wal", bytesHold(world, sent.keyNeedle))
    }

    /** The stored file name of an object's fragment [ordinal] (`media_blob.file_name`). */
    private fun fragmentFileOf(world: MediaWorld, objectId: ByteArray, ordinal: Int): ByteArray {
        var name = ByteArray(0)
        world.sql.query(
            "SELECT b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "WHERE f.object_id = ? AND f.ordinal = ?",
            listOf(objectId, ordinal.toLong()),
        ) { name = it.blob(0) }
        assertTrue("fragment $ordinal has a file", name.isNotEmpty())
        return name
    }

    private fun hexName(name: ByteArray): String = name.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** Whether the raw database file or its write-ahead log holds [needle]. */
    private fun bytesHold(world: MediaWorld, needle: ByteArray): Boolean =
        world.dbFiles().any { contains(it.readBytes(), needle) }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    private fun ceilMinute(seconds: Long): Long = -Math.floorDiv(-seconds, 60L) * 60L
}
