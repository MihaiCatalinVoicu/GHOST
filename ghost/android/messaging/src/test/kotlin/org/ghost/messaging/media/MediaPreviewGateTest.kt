package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.ObjectState
import org.ghost.messaging.api.MediaStateView
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * §9.3's zero-click rules and §6.5's preview facade over [MediaWorld] (slice S6, the T46 shape):
 * with the decoder spy on the sandbox seam, no decode request happens while no conversation is
 * named on screen, while the app is in the background, for a blocked contact or for a request;
 * previews decode only for the named conversation, only for a `verified` object; the RAM cache
 * answers a second call without a second decode; two sandbox failures make the object
 * `undecodable` (CS-M8) and it is never offered to the sandbox again; `mediaState` reports the
 * state and held/F progress, and `NOT_KEPT` for a kind-5 message whose descriptor arrived in a
 * request (D28); and a decode entered in the foreground but finished in the background (ON_STOP
 * mid-decode, a blocking decorator over the seam) is dropped — erased, never cached — so §9.3's
 * "nothing is decoded in the background" holds of the answer too.
 */
class MediaPreviewGateTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-preview").toFile()
        val db: String = File(dir, "world.db").absolutePath

        fun open(): MediaWorld = MediaWorld(db, dir).also { it.activate() }
    }

    /** A verified incoming object with its message, as a delivered send would leave them. */
    private class Fx(val world: MediaWorld, val contact: ByteArray, val messageId: ByteArray, val objectId: ByteArray) :
        AutoCloseable {
        override fun close() = world.close()
    }

    private fun verifiedWorld(box: Box, trust: String = "unverified"): Fx {
        val world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        if (trust != "unverified") {
            world.sql.exec("UPDATE dm_contact SET trust_state = ? WHERE contact_id = ?", listOf(trust, contact))
        }
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
        assertEquals("verified", world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(prepared.objectId)))
        prepared.releaseNames()
        return Fx(world, contact, messageId, prepared.objectId)
    }

    private fun support(
        world: MediaWorld,
        decoder: org.ghost.media.send.ImageDecoder = world.decoder,
    ): MediaEngineSupport = MediaEngineSupport(
        database = world.database,
        steps = world.steps,
        receiveSteps = world.receiveSteps,
        preparations = org.ghost.media.send.Preparations(),
        pipeline = MediaPipelinePorts(
            world.files, world.preparing, FakeStripper, FakeVideoExport, world.readers, decoder,
        ),
        worker = Executors.newSingleThreadExecutor(),
        random = world.random,
        contexts = world.contexts,
        actorCall = { it() },
        checkpoint = { world.checkpointLog += true; true },
    )

    @Test
    fun noDecodeWithoutOnScreenConversationOrInTheBackground() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)

            // Nothing named on screen, background: the default state refuses everything.
            assertNull(facade.preview(fx.messageId))
            assertTrue("no decode request with nothing named", fx.world.decoder.requests.isEmpty())

            // Named, still background: §9.3's zero-click rule — no decode in the background.
            facade.onScreen(fx.contact)
            assertNull(facade.preview(fx.messageId))
            assertTrue(fx.world.decoder.requests.isEmpty())

            // Foreground, nothing named.
            facade.onForeground(true)
            facade.onScreen(null)
            assertNull(facade.preview(fx.messageId))
            assertTrue(fx.world.decoder.requests.isEmpty())

            // Foreground, a different conversation named: previews only for the named one.
            facade.onScreen(ByteArray(16) { 0x22 })
            assertNull(facade.preview(fx.messageId))
            assertTrue(fx.world.decoder.requests.isEmpty())

            // The named conversation: the decode runs, once.
            facade.onScreen(fx.contact)
            val preview = facade.preview(fx.messageId)
            assertNotNull(preview)
            assertEquals(320, preview!!.width)
            assertEquals(1, fx.world.decoder.requests.size)
            assertEquals(
                "the decode asks for the preview's canonical bound",
                org.ghost.media.send.MediaSendLimits.PREVIEW_LONG_EDGE,
                fx.world.decoder.requests.single().second,
            )

            // The RAM cache answers the second call without a second decode (§10.5).
            assertNotNull(facade.preview(fx.messageId))
            assertEquals(1, fx.world.decoder.requests.size)

            // ON_STOP shuts the gate again, cache or no cache.
            facade.onForeground(false)
            assertNull(facade.preview(fx.messageId))
            assertEquals(1, fx.world.decoder.requests.size)
        }
    }

    @Test
    fun blockedContactsAndRequestsAreNeverDecoded() {
        val box = Box()
        verifiedWorld(box, trust = "blocked").use { fx ->
            val facade = support(fx.world)
            facade.onForeground(true)
            facade.onScreen(fx.contact)
            assertNull(facade.preview(fx.messageId))
            assertTrue(fx.world.decoder.requests.isEmpty())
        }
    }

    @Test
    fun anUnverifiedObjectIsNeverOfferedToTheSandbox() {
        val box = Box()
        val world = box.open()
        world.use {
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
            // The descriptor arrived, nothing else: `awaiting`, nothing shown before verified (§7.3).
            val messageId = world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    prepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = prepared.sealed.manifestHash,
                ),
                keyEnv = prepared.sealed.keyEnv,
            )
            prepared.releaseNames()
            val facade = support(world)
            facade.onForeground(true)
            facade.onScreen(contact)
            assertNull(facade.preview(messageId))
            assertTrue(world.decoder.requests.isEmpty())
        }
    }

    @Test
    fun twoSandboxFailuresMakeTheObjectUndecodableAndItIsNeverDecodedAgain() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)
            facade.onForeground(true)
            facade.onScreen(fx.contact)
            fx.world.decoder.failuresLeft = 2
            assertNull(facade.preview(fx.messageId))
            assertNull(facade.preview(fx.messageId))
            assertEquals(2, fx.world.decoder.requests.size)
            assertEquals(
                "two failures: undecodable, never offered to the sandbox again (CS-M8)",
                "undecodable",
                fx.world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(fx.objectId)),
            )
            assertNull(facade.preview(fx.messageId))
            assertEquals(2, fx.world.decoder.requests.size)
        }
    }

    @Test
    fun aDecodeThatCompletesInTheBackgroundIsDroppedAndNeverCached() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            // A blocking decorator over the recording fake: the decode enters, then waits for
            // the test — the ON_STOP-during-decode interleave the recording-fake oracle cannot
            // produce (T46/§9.3: nothing is decoded in the background).
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val blocking = object : org.ghost.media.send.ImageDecoder {
                override fun decode(jpeg: ByteArray, maxW: Int, maxH: Int): org.ghost.media.send.ImageDecoder.Decoded? {
                    entered.countDown()
                    if (!release.await(30, java.util.concurrent.TimeUnit.SECONDS)) {
                        throw AssertionError("the decode was never released")
                    }
                    return fx.world.decoder.decode(jpeg, maxW, maxH)
                }
            }
            val facade = support(fx.world, blocking)
            facade.onForeground(true)
            facade.onScreen(fx.contact)

            val answer = arrayOfNulls<org.ghost.messaging.api.MediaPreview>(1)
            val caller = Thread {
                answer[0] = facade.preview(fx.messageId)
            }
            caller.start()
            assertTrue("the decode entered", entered.await(30, java.util.concurrent.TimeUnit.SECONDS))
            // ON_STOP lands while the sandbox decode is blocked.
            facade.onForeground(false)
            release.countDown()
            caller.join(30_000)
            assertTrue("the preview caller finished", caller.state == Thread.State.TERMINATED)

            assertNull(
                "a decode started in the foreground but finished in the background is dropped",
                answer[0],
            )
            assertEquals(1, fx.world.decoder.requests.size)

            // Never cached: back in the foreground, the same preview decodes again.
            facade.onForeground(true)
            assertNotNull(facade.preview(fx.messageId))
            assertEquals(2, fx.world.decoder.requests.size)
        }
    }

    @Test
    fun mediaStateReportsProgressAndTheRequestRuleAnswer() {
        val box = Box()
        verifiedWorld(box).use { fx ->
            val facade = support(fx.world)
            val state = facade.mediaState(fx.messageId)!!
            assertEquals(ObjectState.VERIFIED, state.state)
            assertEquals(MediaKind.IMAGE, state.kind)
            assertEquals(0, state.classCode)
            assertEquals(MediaLimits.CLASSES[0], state.totalFragments)
            assertEquals(MediaLimits.CLASSES[0], state.heldFragments)

            // A kind-5 message whose descriptor arrived in a request (D28): stored, never openable.
            val requestMessage = fx.world.random.bytes(16)
            val self = fx.world.contexts.get()!!
            val bodyEnv = self.content.seal(fx.world.random.bytes(12), requestMessage, "kept as text".toByteArray())
            fx.world.database.transaction { tx ->
                var conversationId = ByteArray(0)
                tx.sql.query(
                    "SELECT conversation_id FROM dm_conversation WHERE contact_id = ?",
                    listOf(fx.contact),
                ) { conversationId = it.blob(0) }
                org.ghost.messaging.store.MessageStore().insertIncomingIfAbsent(
                    tx = tx,
                    messageId = requestMessage,
                    conversationId = conversationId,
                    kind = 5,
                    authorMinute = 0,
                    sortMinute = 0,
                    minuteIndex = 1,
                    timerCode = 0,
                    bodyEnv = bodyEnv,
                    unreadDeadlineMinute = null,
                )
            }
            assertEquals(MediaStateView.NOT_KEPT, facade.mediaState(requestMessage))

            // A text message has no media state at all.
            assertNull(facade.mediaState(fx.world.random.bytes(16)))
        }
    }
}
