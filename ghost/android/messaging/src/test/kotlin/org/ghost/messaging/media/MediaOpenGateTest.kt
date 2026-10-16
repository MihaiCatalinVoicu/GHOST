package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.storage.queryString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * §6.5/§10.2's `openMedia` over [MediaWorld] (slice S7): a `verified` object opens a handle
 * carrying the manifest's metadata and a readable chunk cursor; an unverified, view-once or
 * absent object refuses; the sender's own `out` object in `failed` opens (§7.4's readable
 * states); one flipped byte on a fragment file after `verified` makes the read fail typed,
 * records `verified → corrupt`, erases the key and checkpoints (§7.3, §15.8 item 3's JVM
 * shape, MC-M22's oracle); and a lock closes every open handle, turning later reads into the
 * typed `Closed` (§13.7).
 */
class MediaOpenGateTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-open").toFile()
        val db: String = File(dir, "world.db").absolutePath

        fun open(): MediaWorld = MediaWorld(db, dir).also { it.activate() }
    }

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

    /** A verified incoming object with its message, as a delivered send would leave them. */
    private class Fx(val world: MediaWorld, val contact: ByteArray, val messageId: ByteArray, val objectId: ByteArray) :
        AutoCloseable {
        override fun close() = world.close()
    }

    private fun verifiedWorld(box: Box, viewOnce: Boolean = false): Fx {
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = viewOnce)
        world.depositMedia(prepared.sealed.manifestBlob)
        for (i in prepared.sealed.fragmentHashes.indices) {
            world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[i]))
        }
        val messageId = world.receiveDescriptor(
            contact,
            org.ghost.media.store.MediaDescriptor(
                prepared.objectId, MediaKind.IMAGE, viewOnce = viewOnce, classCode = 0,
                manifestHash = prepared.sealed.manifestHash,
            ),
            keyEnv = prepared.sealed.keyEnv,
        )
        world.receiveSteps.ingest()
        world.receiveSteps.bind()
        world.receiveSteps.verify()
        assertEquals("verified", world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(prepared.objectId)))
        prepared.releaseNames()
        return Fx(world, contact, messageId, prepared.objectId)
    }

    @Test
    fun aVerifiedObjectOpensWithTheManifestMetadataAndReadableChunks() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)
            val handle = facade.openMedia(fx.messageId)
            assertNotNull(handle)
            val h = handle!!
            assertEquals(MediaKind.IMAGE, h.kind)
            assertEquals(0, h.classCode)
            assertEquals(1_280, h.width)
            assertEquals(720, h.height)
            assertEquals(0, h.durationMs)

            // Chunks read through the cursor: chunk 0's plaintext is the four fragments the
            // fake sealer sealed (its reader answers the assembled bytes back).
            val chunk0 = h.playable.readChunk(0)
            val expected = ByteArray(4 * MediaLimits.FRAGMENT_BYTES)
            for (k in 0 until 4) {
                val frag = fx.world.files.read(fragmentFileOf(fx.world, fx.objectId, k))
                System.arraycopy(frag, 0, expected, k * MediaLimits.FRAGMENT_BYTES, MediaLimits.FRAGMENT_BYTES)
            }
            assertArrayEquals(expected, chunk0)
            assertEquals("the content length is the manifest's", Goldens.jpeg.size.toLong(), h.contentLength)
            chunk0.fill(0)

            // The second read of the same chunk is the random-access shape (§10.2): the fake's
            // sequential validate pass refuses it, so READ's random access is exercised by the
            // device suite — here chunk 1 follows chunk 0 forward.
            val chunk1 = h.playable.readChunk(1)
            assertEquals(4 * MediaLimits.FRAGMENT_BYTES, chunk1.size)
            chunk1.fill(0)

            h.close()
            h.close() // idempotent
        }
    }

    @Test
    fun unverifiedViewOnceAndAbsentObjectsRefuse() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)

            // A view-once object: §11.2's openViewOnce is its surface (S8), openMedia refuses.
            val viewOnceBox = Box()
            verifiedWorld(viewOnceBox, viewOnce = true).use { vfx ->
                val viewOnceFacade = support(vfx.world)
                assertNull(viewOnceFacade.openMedia(vfx.messageId))
            }

            // Awaiting (the descriptor arrived, nothing else): nothing opens before verified.
            val awaitingBox = Box()
            val awaitingWorld = awaitingBox.open()
            awaitingWorld.use { world ->
                val contact = ByteArray(16) { 0x21 }
                world.addContact(contact)
                val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
                val messageId = world.receiveDescriptor(
                    contact,
                    org.ghost.media.store.MediaDescriptor(
                        prepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                        manifestHash = prepared.sealed.manifestHash,
                    ),
                    keyEnv = prepared.sealed.keyEnv,
                )
                prepared.releaseNames()
                assertNull(support(world).openMedia(messageId))
            }

            // No object at all.
            assertNull(facade.openMedia(fx.world.random.bytes(16)))
        }
    }

    @Test
    fun theSendersOwnFailedObjectOpensReadable() {
        val box = Box()
        val world = box.open()
        world.use {
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
            val self = world.contexts.get()!!
            val messageId = world.random.bytes(16)
            val bodyEnv = self.content.seal(world.random.bytes(12), messageId, "mine".toByteArray())
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
                    authorMinute = 0,
                    sortMinute = 0,
                    minuteIndex = 0,
                    timerCode = 0,
                    bodyEnv = bodyEnv,
                    unreadDeadlineMinute = null,
                )
                // The rows MEDIA-COMMIT would write, with the object already in `failed`:
                // the object first (the role trigger asks for it), then the sealed blobs under
                // their files, then the fragments bound — the object readable (§7.4).
                tx.sql.exec(
                    "INSERT INTO media_object(object_id, role, dest_id, kind, view_once, class_code, manifest_hash, " +
                        "key_env, state, message_id) VALUES (?, 'out', ?, 1, 0, 0, ?, ?, 'failed', ?)",
                    listOf(prepared.objectId, contact, prepared.sealed.manifestHash, prepared.sealed.keyEnv, messageId),
                )
                tx.sql.exec(
                    "INSERT INTO media_blob(blob_hash, file_name, origin, retain_until_day) VALUES (?, ?, 'sealed', NULL)",
                    listOf(prepared.sealed.manifestHash, prepared.sealed.manifestFile),
                )
                tx.sql.exec(
                    "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) VALUES (?, -1, ?, 'bound', 'unsent')",
                    listOf(prepared.objectId, prepared.sealed.manifestHash),
                )
                for (i in prepared.sealed.fragmentHashes.indices) {
                    tx.sql.exec(
                        "INSERT INTO media_blob(blob_hash, file_name, origin, retain_until_day) VALUES (?, ?, 'sealed', NULL)",
                        listOf(prepared.sealed.fragmentHashes[i], prepared.sealed.fragmentFiles[i]),
                    )
                    tx.sql.exec(
                        "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) VALUES (?, ?, ?, 'bound', 'unsent')",
                        listOf(prepared.objectId, i, prepared.sealed.fragmentHashes[i]),
                    )
                }
            }
            prepared.releaseNames()

            val facade = support(world)
            val handle = facade.openMedia(messageId)
            assertNotNull("the sender's own failed object is readable (§7.4)", handle)
            val chunk0 = handle!!.playable.readChunk(0)
            assertEquals(4 * MediaLimits.FRAGMENT_BYTES, chunk0.size)
            chunk0.fill(0)
            handle.close()
        }
    }

    @Test
    fun aFlippedByteAfterVerifiedRecordsCorruptErasesTheKeyAndCheckpoints() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)
            val handle = facade.openMedia(fx.messageId)!!
            handle.close()

            // §15.8 item 3's injection: one flipped byte on disk, after `verified`.
            val file = fragmentFileOf(fx.world, fx.objectId, 1)
            val bytes = fx.world.files.read(file)
            bytes[123] = (bytes[123].toInt() xor 0x01).toByte()
            java.nio.file.Files.write(File(fx.world.files.directory, hexName(file)).toPath(), bytes)

            val checkpointsBefore = fx.world.checkpointLog.size
            val second = facade.openMedia(fx.messageId)
            assertNotNull(second)
            try {
                second!!.playable.readChunk(0)
                fail("a flipped fragment must fail the read")
            } catch (e: org.ghost.media.play.MediaPlayException.Corrupt) {
                // the typed error the player ends with — never a crash
            }
            assertEquals(
                "verified → corrupt (§7.3)",
                "corrupt",
                fx.world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(fx.objectId)),
            )
            var erased: Long = -1
            fx.world.sql.query(
                "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NULL",
                listOf(fx.objectId),
            ) { r -> erased = r.long(0) }
            assertEquals("the key is erased with the transition (T45)", 1L, erased)
            assertTrue(
                "the checkpoint follows the key erasure (§11.1)",
                fx.world.checkpointLog.size > checkpointsBefore,
            )
            assertNull("a corrupt object no longer opens", facade.openMedia(fx.messageId))
        }
    }

    @Test
    fun lockClosesOpenHandlesAndLaterReadsAreTyped() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)
            val handle = facade.openMedia(fx.messageId)!!
            assertEquals(4 * MediaLimits.FRAGMENT_BYTES, handle.playable.readChunk(0).size)

            facade.onLocked()
            try {
                handle.playable.readChunk(0)
                fail("a read after the lock must end typed")
            } catch (e: org.ghost.media.play.MediaPlayException.Closed) {
                // §13.7: the player ends with a typed error, never a call on a stale context
            }
            handle.close() // idempotent after the lock closed it
        }
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
}
