package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * §6.5/§11.2's `openViewOnce` over [MediaWorld] (slice S8): the one display of a view-once
 * object. The key moves into the native reader and the row half (`viewing`, `key_env = NULL`)
 * commits before the checkpoint and the handle (§11.2's order — the raw `.db`/`-wal` hold no
 * `key_env` byte when the handle returns, EP-M's assertion 3b); a second open refuses (CS-M5's
 * at-most-once at the facade level, the crash half is `MediaViewOnceScenarioTest`); closing the
 * handle — the UI, the lock — is `VIEW-ONCE-CLOSE` (`viewed`, the fragments and unshared blobs
 * go, the reconcile takes the files); and a process that died mid-view closes the row at the
 * next start (§11.2's start rule).
 */
class MediaViewOnceTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-vo").toFile()
        val db: String = File(dir, "world.db").absolutePath
        var activated = false

        fun open(relay: ScriptedOutbox = ScriptedOutbox()): MediaWorld {
            val world = MediaWorld(db, dir, relay)
            if (!activated) {
                world.activate()
                activated = true
            }
            return world
        }
    }

    private fun support(world: MediaWorld, realCheckpoint: Boolean = false): MediaEngineSupport = MediaEngineSupport(
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
        checkpoint = if (realCheckpoint) {
            { world.realCheckpoint() }
        } else {
            { world.checkpointLog += true; true }
        },
    )

    /** A verified view-once incoming object with its message, as a delivered send would leave them. */
    private class Fx(val world: MediaWorld, val contact: ByteArray, val messageId: ByteArray, val objectId: ByteArray) :
        AutoCloseable {
        override fun close() = world.close()
    }

    private fun verifiedViewOnce(box: Box): Fx {
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = true)
        world.depositMedia(prepared.sealed.manifestBlob)
        for (i in prepared.sealed.fragmentHashes.indices) {
            world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[i]))
        }
        val messageId = world.receiveDescriptor(
            contact,
            org.ghost.media.store.MediaDescriptor(
                prepared.objectId, MediaKind.IMAGE, viewOnce = true, classCode = 0,
                manifestHash = prepared.sealed.manifestHash,
            ),
            keyEnv = prepared.sealed.keyEnv,
        )
        world.receiveSteps.ingest()
        world.receiveSteps.bind()
        world.receiveSteps.verify()
        assertEquals(
            "verified",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(prepared.objectId)),
        )
        prepared.releaseNames()
        return Fx(world, contact, messageId, prepared.objectId)
    }

    @Test
    fun openingErasesTheKeyBeforeTheHandleReturnsAndClosingIsViewOnceClose() {
        val box = Box()
        verifiedViewOnce(box).use { fx ->
            val facade = support(fx.world, realCheckpoint = true)
            val keyNeedle = FakeReaders.fakeKeyEnvOf(fx.objectId)

            val handle = facade.openViewOnce(fx.messageId)
            assertNotNull("a verified view-once object opens exactly once", handle)
            val h = handle!!
            assertEquals(
                "the row half committed: viewing, key NULL",
                "1",
                fx.world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'viewing' AND key_env IS NULL",
                    listOf(fx.objectId),
                ),
            )
            assertTrue("the checkpoint ran before the handle returned (§11.2)", fx.world.checkpointLog.isNotEmpty())
            assertFalse(
                "no key_env byte in the raw .db or -wal when the handle returns (EP-M 3b)",
                bytesHold(fx.world, keyNeedle),
            )
            assertEquals(
                "the write-ahead log is empty after the checkpoint (EP-M 3)",
                0L,
                File(fx.world.dbPath + "-wal").length(),
            )

            // The display itself: the readable reader serves the object's chunks.
            assertEquals(4 * MediaLimits.FRAGMENT_BYTES, h.playable.readChunk(0).size)

            h.close()
            assertEquals(
                "VIEW-ONCE-CLOSE: viewed, the fragment rows and the unshared blobs go",
                "1",
                fx.world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'viewed' AND key_env IS NULL",
                    listOf(fx.objectId),
                ),
            )
            assertEquals(
                0L,
                fx.world.sql.queryLong(
                    "SELECT count(*) FROM media_fragment WHERE object_id = ?",
                    listOf(fx.objectId),
                ),
            )
            assertEquals(
                "the object's files went with the close's reconcile",
                0,
                objectFiles(fx.world, fx.objectId).size,
            )
            assertNull("a viewed object never opens again", facade.openViewOnce(fx.messageId))
            assertNull("and openMedia still refuses view-once (S7's gate)", facade.openMedia(fx.messageId))
        }
    }

    @Test
    fun openRefusesAnythingButAVerifiedUnopenedViewOnceObject() {
        val box = Box()
        verifiedViewOnce(box).use { fx ->
            val facade = support(fx.world)
            // No object at all.
            assertNull(facade.openViewOnce(fx.world.random.bytes(16)))

            // A verified non-view-once object opens through openMedia, never openViewOnce.
            val plainBox = Box()
            val plainWorld = plainBox.open()
            plainWorld.use { world ->
                val contact = ByteArray(16) { 0x21 }
                world.addContact(contact)
                val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
                world.depositMedia(prepared.sealed.manifestBlob)
                for (i in prepared.sealed.fragmentHashes.indices) {
                    world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[i]))
                }
                val messageId = world.receiveDescriptor(
                    contact,
                    org.ghost.media.store.MediaDescriptor(
                        prepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                        manifestHash = prepared.sealed.manifestHash,
                    ),
                    keyEnv = prepared.sealed.keyEnv,
                )
                world.receiveSteps.ingest()
                world.receiveSteps.bind()
                world.receiveSteps.verify()
                prepared.releaseNames()
                val plainFacade = support(world)
                assertNull(plainFacade.openViewOnce(messageId))
                assertNotNull(plainFacade.openMedia(messageId))
            }

            // An awaiting view-once object: nothing opens before verify.
            val awaitingBox = Box()
            val awaitingWorld = awaitingBox.open()
            awaitingWorld.use { world ->
                val contact = ByteArray(16) { 0x21 }
                world.addContact(contact)
                val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = true)
                val messageId = world.receiveDescriptor(
                    contact,
                    org.ghost.media.store.MediaDescriptor(
                        prepared.objectId, MediaKind.IMAGE, viewOnce = true, classCode = 0,
                        manifestHash = prepared.sealed.manifestHash,
                    ),
                    keyEnv = prepared.sealed.keyEnv,
                )
                prepared.releaseNames()
                assertNull(support(world).openViewOnce(messageId))
            }
        }
    }

    @Test
    fun aSecondOpenWhileViewingRefuses() {
        val box = Box()
        verifiedViewOnce(box).use { fx ->
            val facade = support(fx.world)
            val first = facade.openViewOnce(fx.messageId)
            assertNotNull(first)
            assertNull("at most one display: a second open while viewing refuses", facade.openViewOnce(fx.messageId))
            first!!.close()
        }
    }

    @Test
    fun aFailedReaderMoveLeavesNothingShownAndTheObjectOpenable() {
        val box = Box()
        verifiedViewOnce(box).use { fx ->
            val facade = support(fx.world)
            // §11.2's pre-commit crash shape: the reader could not be opened (a dead process
            // mid-move is indistinguishable at the row level) — nothing was shown, the key and
            // the verified state stand, and the one display is still ahead.
            val record = fx.world.readers.registry.remove(hexOf(fx.objectId))!!
            assertNull(facade.openViewOnce(fx.messageId))
            assertEquals(
                "the key survived the refused move",
                "1",
                fx.world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'verified' AND key_env IS NOT NULL",
                    listOf(fx.objectId),
                ),
            )
            fx.world.readers.registry[hexOf(fx.objectId)] = record
            val handle = facade.openViewOnce(fx.messageId)
            assertNotNull("the object is openable after a pre-commit crash", handle)
            handle!!.close()
        }
    }

    @Test
    fun lockClosesTheViewAsViewOnceCloseAndLaterReadsAreTyped() {
        val box = Box()
        verifiedViewOnce(box).use { fx ->
            val facade = support(fx.world)
            val handle = facade.openViewOnce(fx.messageId)!!
            assertEquals(4 * MediaLimits.FRAGMENT_BYTES, handle.playable.readChunk(0).size)

            facade.onLocked()
            assertEquals(
                "the lock ran VIEW-ONCE-CLOSE: viewed, rows gone",
                "1",
                fx.world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'viewed'",
                    listOf(fx.objectId),
                ),
            )
            assertEquals(0, objectFiles(fx.world, fx.objectId).size)
            try {
                handle.playable.readChunk(0)
                fail("a read after the lock must end typed")
            } catch (e: org.ghost.media.play.MediaPlayException.Closed) {
                // §13.7: typed, never a call on a stale context
            }
            handle.close() // idempotent after the lock closed it
        }
    }

    @Test
    fun aProcessDeathMidViewIsClosedAtTheNextStartAndNeverRedisplayed() {
        val box = Box()
        val relay = ScriptedOutbox()
        val fx = verifiedViewOnce(box)
        val keyNeedle = FakeReaders.fakeKeyEnvOf(fx.objectId)
        val facade = support(fx.world, realCheckpoint = true)
        val handle = facade.openViewOnce(fx.messageId)!!
        assertEquals(4 * MediaLimits.FRAGMENT_BYTES, handle.playable.readChunk(0).size)
        // The process dies here: the handle is never closed, the world just stops.
        fx.world.close()

        val rebooted = box.open(relay)
        rebooted.use { world ->
            val rebootedFacade = support(world)
            assertEquals(
                "the dead process left the row viewing, key still gone",
                "1",
                world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'viewing' AND key_env IS NULL",
                    listOf(fx.objectId),
                ),
            )
            rebootedFacade.closeInterruptedViews()
            assertEquals(
                "§11.2's start rule: viewed",
                "1",
                world.sql.queryString(
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND state = 'viewed'",
                    listOf(fx.objectId),
                ),
            )
            assertEquals(
                0L,
                world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(fx.objectId)),
            )
            assertEquals(0, objectFiles(world, fx.objectId).size)
            assertNull("never a second display (CS-M5)", rebootedFacade.openViewOnce(fx.messageId))
            assertFalse(
                "the pre-death checkpoint left no key byte (the start pass checkpoints too)",
                bytesHold(world, keyNeedle),
            )
        }
    }

    /** Every fragment file of [objectId] that still sits in the store. */
    private fun objectFiles(world: MediaWorld, objectId: ByteArray): List<String> {
        val names = HashSet<String>()
        world.sql.query(
            "SELECT b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "WHERE f.object_id = ?",
            listOf(objectId),
        ) { names += hexOf(it.blob(0)) }
        return world.files.list().filter { it in names }
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
