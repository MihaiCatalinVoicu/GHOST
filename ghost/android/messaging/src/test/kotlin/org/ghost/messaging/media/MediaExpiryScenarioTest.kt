package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.engine.MediaSteps
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.sync.api.Outcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **SCN-ME** (Phase 11 design §15.3) at the engine boundary: SWEEP with media, reconcile,
 * `MEDIA-GC` (the pool's retention day and the `incomplete`/`corrupt` releases), the view-once
 * sender cleanup and the `M_c` orphan — one scripted device life crashed and swept to its end:
 * **no row, no `key_env` byte, no file**. The store-level crash enumeration of the same scenario
 * (every statement and file operation) is S3's `MediaStoreScenarioTest`; the per-statement engine
 * enumeration at gate scale is S9's. What this file adds is the steps-level life cycle: real
 * `MediaSteps`, `MediaReceiveSteps` and `OutcomeStep` over [MediaWorld], the real
 * [MessagingRuntime.SweepMediaPort] contract, and the physical byte scans.
 */
class MediaExpiryScenarioTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-scn-me").toFile()
        val db: String = File(dir, "world.db").absolutePath

        fun open(): MediaWorld = MediaWorld(db, dir).also { it.activate() }
    }

    private class Life(val world: MediaWorld, val needles: List<ByteArray>, val messageIds: List<ByteArray>)

    /** One sender object at READY and one verified recipient object, plus a pooled stranger blob. */
    private fun fullLife(box: Box): Life {
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val needles = ArrayList<ByteArray>()
        val messageIds = ArrayList<ByteArray>()

        // The sender: commit, feed, every ordinal SENT, READY — the countdown starts.
        val outPrepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        val outObjectId = ByteArray(16) { 0x60 }
        val outResult = world.steps.commit(
            world.contexts.get()!!,
            MediaSteps.CommitRequest(
                contactId = contact,
                kind = MediaKind.IMAGE,
                viewOnce = false,
                classCode = outPrepared.sealed.classCode,
                objectId = outObjectId,
                manifestHash = outPrepared.sealed.manifestHash,
                caption = "out".toByteArray(),
                keyEnv = outPrepared.sealed.keyEnv,
                manifestBlob = outPrepared.sealed.manifestBlob,
                manifestFile = outPrepared.sealed.manifestFile,
                fragmentHashes = outPrepared.sealed.fragmentHashes,
                fragmentFiles = outPrepared.sealed.fragmentFiles,
            ),
        )
        check(outResult is MediaSteps.CommitResult.Committed)
        world.steps.feed()
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(outObjectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        outPrepared.releaseNames()
        needles += outPrepared.sealed.keyEnv.copyOf()
        messageIds += outResult.messageId

        // The recipient: deposit, descriptor, ingest, bind, verify.
        val inPrepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        world.depositMedia(inPrepared.sealed.manifestBlob)
        for (i in inPrepared.sealed.fragmentHashes.indices) {
            world.depositMedia(world.files.read(inPrepared.sealed.fragmentFiles[i]))
        }
        val inMessageId = world.receiveDescriptor(
            contact,
            org.ghost.media.store.MediaDescriptor(
                inPrepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                manifestHash = inPrepared.sealed.manifestHash,
            ),
            keyEnv = inPrepared.sealed.keyEnv,
        )
        world.receiveSteps.ingest()
        world.receiveSteps.bind()
        world.receiveSteps.verify()
        inPrepared.releaseNames()
        needles += FakeReaders.fakeKeyEnvOf(inPrepared.objectId)
        messageIds += inMessageId

        // A pooled stranger: fetched, ingested, named by no object — its retention day is its end.
        val pooled = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x5C }
        world.depositMedia(pooled, relayExpirySeconds = MediaWorld.NOW + 2 * 86_400)
        world.receiveSteps.ingest()
        assertEquals(
            "the pooled blob has a row",
            1L,
            world.sql.queryLong("SELECT count(*) FROM media_blob WHERE blob_hash = ?", listOf(digest(pooled))),
        )
        return Life(world, needles, messageIds)
    }

    /** The end of the life: both messages past every bound, swept, GC'd, reconciled — nothing left. */
    @Test
    fun theWholeLifeEndsWithAnEmptyStoreAndAnEmptyDirectory() {
        val box = Box()
        val life = fullLife(box)
        val world = life.world

        // Past the sender's countdown and the recipient's unread cap (7-day default timer → the
        // sender's countdown is the far bound; step past both with one jump).
        val farBound = world.sql.queryLong(
            "SELECT max(coalesce(expire_at_minute, delete_at_minute)) FROM dm_message WHERE message_id IN (" +
                life.messageIds.joinToString(",") { "?" } + ")",
            life.messageIds,
        )!!
        world.clock.now = farBound + 7 * 86_400 + 3_600 // and past the pooled blob's retention day

        // SWEEP through the port contract: the port call inside the sweep transaction (before
        // the message delete), the delete, then the §11.1 checkpoint — the WAL must be empty at
        // this instant (EP-M 3) — then the time-triggered maintenance and the reconcile.
        val port = MessagingRuntime.SweepMediaPort()
        world.database.transaction { tx ->
            port.onMessagesDeleted(tx, life.messageIds.map { MessageId(it) })
            for (id in life.messageIds) {
                tx.sql.exec("DELETE FROM dm_message WHERE message_id = ?", listOf(id))
            }
        }
        world.realCheckpoint()
        assertEquals(0L, File(world.dbPath + "-wal").length())
        world.receiveSteps.gc()
        world.reconcile()

        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_object", emptyList()))
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_upload", emptyList()))
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_fragment", emptyList()))
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_outbound_op", emptyList()))
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_blob", emptyList()))
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM dm_message WHERE kind = 5", emptyList()))
        assertTrue("the store's directory is empty", world.files.list().isEmpty())
        for (needle in life.needles) {
            assertFalse("no key_env byte of any object remains", bytesHold(world, needle))
        }
        world.close()
    }

    /** SCN-ME's pool half alone: the retention day collects a blob no object names. */
    @Test
    fun aPooledBlobGoesAfterItsRetentionDay() {
        val box = Box()
        val world = box.open()
        val pooled = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x5C }
        world.depositMedia(pooled, relayExpirySeconds = MediaWorld.NOW + 2 * 86_400)
        world.receiveSteps.ingest()
        val name = world.sql.let { sql ->
            var n = ByteArray(0)
            sql.query("SELECT file_name FROM media_blob WHERE origin = 'ingested'", emptyList()) { n = it.blob(0) }
            n
        }
        assertTrue(hexOf(name) in world.files.list())

        world.clock.now = MediaWorld.NOW + 4 * 86_400 // the retention day (d0+3) has passed
        world.receiveSteps.gc() // the retention day passed: the row goes, the reconcile takes the file
        assertEquals(0L, world.sql.queryLong("SELECT count(*) FROM media_blob", emptyList()))
        assertFalse(hexOf(name) in world.files.list())
        world.close()
    }

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
}
