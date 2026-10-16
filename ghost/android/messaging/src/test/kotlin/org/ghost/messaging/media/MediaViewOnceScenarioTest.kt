package org.ghost.messaging.media

import org.ghost.media.store.MediaKind
import org.ghost.messaging.engine.MediaEngineSupport
import org.ghost.messaging.engine.MediaPipelinePorts
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.Executors

/**
 * **SCN-MD** (Phase 11 design §15.3) at the engine boundary, with **CS-M5** (view-once at most
 * once per device, across crashes at any statement and file operation) as the scenario's oracle:
 * `VIEW-ONCE-OPEN`, the checkpoint, display, `VIEW-ONCE-CLOSE`, lock, restart — each phase of one
 * scripted view crashed in turn (a world reopen is the process death; the crash-injecting SQL
 * executor's per-statement enumeration is the exit gate's, S9's), rebooted, and checked:
 *
 *  - a crash before the open's commit leaves the key in the database and nothing shown — the
 *    object opens again (`MediaViewOnceTest.aFailedReaderMoveLeavesNothingShownAndTheObjectOpenable`);
 *  - a crash after the commit loses the object (the key existed only in the dead reader) — the
 *    start pass closes the row `viewed` and **no second display ever happens**, also across reboots;
 *  - a checkpoint that stays busy returns the handle anyway (L9-M10's lag, counted here) and the
 *    next checkpoint clears the surviving bytes;
 *  - a crash at every file operation of the close's reconcile leaves nothing the next reconcile
 *    does not remove.
 */
class MediaViewOnceScenarioTest {

    private class Sandbox {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-scn-md").toFile()
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

    private fun support(
        world: MediaWorld,
        checkpoint: () -> Boolean = { world.checkpointLog += true; true },
        mediaCheckpoint: org.ghost.messaging.engine.MediaCheckpointState = org.ghost.messaging.engine.MediaCheckpointState(),
    ): MediaEngineSupport =
        MediaEngineSupport(
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
            checkpoint = checkpoint,
            mediaCheckpoint = mediaCheckpoint,
        )

    /**
     * The production SWEEP over this world, wired to [debt] exactly as `MessagingRuntime`
     * wires the shared state — the re-ask under test is the real pass, not a stubbed one.
     */
    private fun sweeperOf(
        world: MediaWorld,
        debt: org.ghost.messaging.engine.MediaCheckpointState,
    ): org.ghost.messaging.engine.Sweeper = org.ghost.messaging.engine.Sweeper(
        database = world.database,
        namespaces = world.stores.namespaces,
        envelopes = world.envelopes,
        pairKeys = org.ghost.messaging.engine.PairKeySteps(world.envelopes),
        checkpoint = { world.realCheckpoint() },
        clock = world.clock,
        contexts = world.contexts,
        media = org.ghost.messaging.api.MediaPort.NONE,
        mediaOrphans = org.ghost.messaging.engine.MediaOrphanSteps(world.crypto, world.clock),
        mediaCheckpoint = debt,
    )

    private class Fx(val world: MediaWorld, val messageId: ByteArray, val objectId: ByteArray) :
        AutoCloseable {
        override fun close() = world.close()
    }

    /** A verified view-once incoming object with its message. */
    private fun verifiedViewOnce(box: Sandbox): Fx {
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
        prepared.releaseNames()
        return Fx(world, messageId, prepared.objectId)
    }

    private fun stateOf(world: MediaWorld, objectId: ByteArray): String? =
        world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId))

    private fun fragmentCount(world: MediaWorld, objectId: ByteArray): Long =
        world.sql.queryLong("SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(objectId))!!

    /** Every file of [objectId] still in the store. */
    private fun objectFiles(world: MediaWorld, objectId: ByteArray): List<String> {
        val names = HashSet<String>()
        world.sql.query(
            "SELECT b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                "WHERE f.object_id = ?",
            listOf(objectId),
        ) { names += hexOf(it.blob(0)) }
        return world.files.list().filter { it in names }
    }

    /**
     * The crash-after-commit: the one display happened, the process died with the handle open,
     * and the rebooted device must never show the object again.
     */
    @Test
    fun aCrashAfterTheOpenCommitLosesTheObjectAndNeverRedisplays() {
        val box = Sandbox()
        val fx = verifiedViewOnce(box)
        val keyNeedle = FakeReaders.fakeKeyEnvOf(fx.objectId)
        val handle = support(fx.world, checkpoint = { fx.world.realCheckpoint() }).openViewOnce(fx.messageId)
        assertNotNull("the one display", handle)
        handle!!.playable.readChunk(0)
        fx.world.close() // the process dies with the view open

        val rebooted = box.open()
        rebooted.use { world ->
            val facade = support(world, checkpoint = { world.realCheckpoint() })
            assertEquals("the dead process left the row viewing", "viewing", stateOf(world, fx.objectId))
            facade.closeInterruptedViews()
            assertEquals("§11.2's start rule closed it", "viewed", stateOf(world, fx.objectId))
            assertEquals(0L, fragmentCount(world, fx.objectId))
            assertTrue("the start pass reconciled the files", objectFiles(world, fx.objectId).isEmpty())
            assertNull("CS-M5: never a second display", facade.openViewOnce(fx.messageId))
            assertNull("and openMedia refuses too", facade.openMedia(fx.messageId))
            assertFalse("the pre-death checkpoint left no key byte", bytesHold(world, keyNeedle))
        }
    }

    /**
     * The busy-checkpoint branch of §11.2: the pragma stays busy through its retries, the handle
     * returns anyway (the key is already gone from the logical database, and refusing would lose
     * the object), the lag is recorded, and the **production** retry — SWEEP's re-ask of the
     * pragma at its next pass, although that sweep deletes nothing — clears the bytes (L9-M10,
     * the S8 review's R1; the gloss used to call a manual `realCheckpoint` "the sweep's").
     */
    @Test
    fun aBusyCheckpointStillReturnsTheHandleAndTheSweepReAskClearsTheLag() {
        val box = Sandbox()
        verifiedViewOnce(box).use { fx ->
            val keyNeedle = FakeReaders.fakeKeyEnvOf(fx.objectId)
            // The checkpoint answers false (busy) without truncating: §10.7's checkpoint_due shape.
            val debt = org.ghost.messaging.engine.MediaCheckpointState()
            val facade = support(
                fx.world,
                checkpoint = { fx.world.checkpointLog += true; false },
                mediaCheckpoint = debt,
            )
            val handle = facade.openViewOnce(fx.messageId)
            assertNotNull("a busy checkpoint must not lose the object (§11.2)", handle)
            assertEquals("the key is logically gone", "viewing", stateOf(fx.world, fx.objectId))
            handle!!.close()
            assertTrue("the busy pragma left the pre-image in the -wal", bytesHold(fx.world, keyNeedle))

            // The production retry, no manual checkpoint anywhere: the media debt stands, so an
            // otherwise idle sweep still runs the pragma — and the pre-image goes.
            val report = sweeperOf(fx.world, debt).sweep()
            assertEquals("an idle sweep: the media debt is the only reason for the pragma", 0, report.rows)
            assertTrue("the sweep ran the pragma", report.checkpointed)
            assertFalse(
                "the sweep's re-ask truncated the pre-image (L9-M10)",
                bytesHold(fx.world, keyNeedle),
            )
        }
    }

    /**
     * A crash at every file operation of `VIEW-ONCE-CLOSE`'s reconcile: the close's transaction
     * committed (viewed, rows gone), the process died mid-delete; the reboot's reconcile removes
     * the rest, and a second reconcile changes nothing.
     */
    @Test
    fun aCrashAtEveryFileOperationOfTheCloseReconcileIsRepairedByTheNextReconcile() {
        // The reconcile traces one call per delete: the manifest's file plus the 16 fragments
        // of a class-0 object (F + 1 blobs, §15.3's count).
        val points = 17
        for (point in 1..points) {
            val box = Sandbox()
            val fx = verifiedViewOnce(box)
            val facade = support(fx.world)
            val handle = facade.openViewOnce(fx.messageId)
            assertNotNull(handle)

            // The close: reader close, the close transaction, then the reconcile — which dies
            // at the armed file operation, exactly as a power loss would. The trace counts the
            // whole process's file calls: cleared so the armed index lands on this reconcile.
            fx.world.crashFs.trace.clear()
            fx.world.crashFs.crashAtCall = point
            try {
                handle!!.close()
                if (point <= points) error("the armed crash point $point did not fire")
            } catch (e: org.ghost.media.store.CiphertextFilesException) {
                // the process death
            }
            fx.world.close()

            val rebooted = box.open(fx.world.relay)
            rebooted.use { world ->
                assertEquals("the close committed before the crash", "viewed", stateOf(world, fx.objectId))
                assertEquals(0L, fragmentCount(world, fx.objectId))
                world.reconcile()
                assertTrue("point $point: the reboot's reconcile removed every file", objectFiles(world, fx.objectId).isEmpty())
                assertTrue(
                    "point $point: a second reconcile changes nothing",
                    world.reconcile().clean,
                )
            }
        }
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
