package org.ghost.messaging.media

import org.ghost.media.store.MediaDescriptor
import org.ghost.media.store.MediaKind
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
import java.util.Random

/**
 * §15.4's seeded worlds for media, at the gate's reduced but honest scope: per seed, one device
 * life — upload (prepare, COMMIT, FEED), outcomes to READY, the receive half (deposit, INGEST,
 * BIND, VERIFY), the sweep and the reconcile — with a random crash point armed per phase. After
 * every reboot: reconcile, [MediaWorld.assertSendInvariants], then the life resumes (every phase
 * is idempotent under the reboot: feed and outcomes re-apply as no-ops, the upload phase skips a
 * committed object, the receive half skips a verified one). Final oracle: the object is uploaded,
 * a received copy is verified, and after the sweep nothing of the expired messages remains — no
 * row, no file, no stored key byte (the sender's `key_env`, captured in a side file at commit so
 * the scan has a real needle across reboots). The design's fuller §15.4 roster (hash squatting,
 * relays that lie, requests, timer changes mid-upload) has its dedicated suites in the twins and
 * the scenario classes; this runner's claim is the crash-resilience half, named in the line.
 */
class MediaSeededWorldsTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-media-seeded").toFile()
        val db: String = File(dir, "world.db").absolutePath
        val needle: File = File(dir, "needle.bin")
        var activated = false

        fun open(): MediaWorld = MediaWorld(db, dir).also {
            if (!activated) {
                it.activate()
                activated = true
            }
        }
    }

    private fun runLife(box: Box, world: MediaWorld, contact: ByteArray, objectId: ByteArray) {
        // Upload: skip a committed object (the phase died mid-flight last time).
        val committed = world.sql.queryLong(
            "SELECT count(*) FROM media_object WHERE object_id = ?",
            listOf(objectId),
        )!! > 0
        if (!committed) {
            val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
            val sealed = prepared.sealed
            box.needle.writeBytes(sealed.keyEnv) // the erasure scan's needle, surviving reboots
            val result = world.steps.commit(
                world.contexts.get()!!,
                MediaSteps.CommitRequest(
                    contactId = contact, kind = MediaKind.IMAGE, viewOnce = false,
                    classCode = sealed.classCode, objectId = objectId, manifestHash = sealed.manifestHash,
                    caption = "seeded".toByteArray(), keyEnv = sealed.keyEnv,
                    manifestBlob = sealed.manifestBlob, manifestFile = sealed.manifestFile,
                    fragmentHashes = sealed.fragmentHashes, fragmentFiles = sealed.fragmentFiles,
                ),
            )
            check(result is MediaSteps.CommitResult.Committed)
            prepared.releaseNames()
        }
        world.steps.feed() // a second pass is a no-op for fed ordinals
        // Outcomes: re-application is exactly-once (release-first, §15.3's MA oracle).
        repeat(17) { i ->
            world.relay.script(world.relay.opIdOf(objectId, i - 1), Outcome.SENT)
        }
        world.steps.outcomes()
        // Receive half: skip when a verified object exists (the half completed last time).
        val verified = world.sql.queryLong(
            "SELECT count(*) FROM media_object WHERE state = 'verified'",
            emptyList(),
        )!! > 0
        if (!verified) {
            val inPrepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
            world.depositMedia(inPrepared.sealed.manifestBlob)
            for (i in inPrepared.sealed.fragmentHashes.indices) {
                world.depositMedia(world.files.read(inPrepared.sealed.fragmentFiles[i]))
            }
            world.receiveDescriptor(
                contact,
                MediaDescriptor(
                    inPrepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = inPrepared.sealed.manifestHash,
                ),
                keyEnv = inPrepared.sealed.keyEnv,
            )
            world.receiveSteps.ingest()
            world.receiveSteps.bind()
            world.receiveSteps.verify()
            inPrepared.releaseNames()
        }
    }

    private fun runSeededWorld(seed: Long) {
        val random = Random(seed)
        val box = Box()
        var world = box.open()
        val contact = ByteArray(16) { 0x21 }
        world.addContact(contact)
        val objectId = ByteArray(16) { random.nextInt(256).toByte() }

        // A crash point armed per phase: the index lands inside the phase's call window with high
        // probability; a point past the phase's calls does not fire there and is disarmed at the
        // phase's end. Either way the world reboots, reconciles, checks invariants and resumes.
        repeat(3) {
            val base = world.crashFs.trace.size
            world.crashFs.crashAtCall = base + 1 + random.nextInt(40)
            try {
                runLife(box, world, contact, objectId)
            } catch (e: Exception) {
                // the process death
            }
            world.crashFs.crashAtCall = -1
            world.close()
            world = box.open()
            world.reconcile()
            world.assertSendInvariants()
        }
        // The armed phases proved the reboot invariants; reach quiescence unarmed for the oracles.
        world.crashFs.crashAtCall = -1
        runLife(box, world, contact, objectId)
        world.reconcile()
        world.assertSendInvariants()
        // Final oracle: uploaded, a received copy verified, invariants clean.
        assertEquals(
            "seed $seed: uploaded",
            "uploaded",
            world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
        )
        assertTrue(
            "seed $seed: a received object verified",
            world.sql.queryLong("SELECT count(*) FROM media_object WHERE state = 'verified'", emptyList())!! >= 1L,
        )
        world.assertSendInvariants()
        // The sweep takes the expired world: advance past every bound, delete through the port,
        // checkpoint, reconcile — no row, no file, no stored key byte.
        val messageIds = ArrayList<ByteArray>()
        world.sql.query("SELECT message_id FROM dm_message WHERE kind = 5", emptyList()) { messageIds += it.blob(0) }
        world.clock.now += 30 * 86_400L
        val port = MessagingRuntime.SweepMediaPort()
        world.database.transaction { tx ->
            port.onMessagesDeleted(tx, messageIds.map { MessageId(it) })
            for (id in messageIds) tx.sql.exec("DELETE FROM dm_message WHERE message_id = ?", listOf(id))
        }
        world.realCheckpoint()
        world.receiveSteps.gc()
        world.reconcile()
        assertEquals("seed $seed: no object rows", 0L, world.sql.queryLong("SELECT count(*) FROM media_object", emptyList()))
        assertTrue("seed $seed: the directory is empty", world.files.list().isEmpty())
        if (box.needle.isFile) {
            val needle = box.needle.readBytes()
            world.dbFiles().forEach { dbFile ->
                assertFalse("seed $seed: no key_env byte of the object remains", contains(dbFile.readBytes(), needle))
            }
        }
        world.close()
    }

    @Test
    fun seededWorldsSurviveTheirRandomCrashPoints() {
        if (!MediaScenarios.owns(6)) return
        val seeds = (System.getProperty("ghost.media.seededWorlds") ?: "20").toInt()
        check(seeds > 0) { "an empty loop proves nothing (JC-5)" }
        for (seed in 1..seeds) {
            try {
                runSeededWorld(seed * 1_000_003L)
            } catch (e: Throwable) {
                throw AssertionError("seed $seed: ${e.message}", e)
            }
        }
        MediaPrivacyReport.line("seeded worlds: $seeds run, 0 failures")
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
