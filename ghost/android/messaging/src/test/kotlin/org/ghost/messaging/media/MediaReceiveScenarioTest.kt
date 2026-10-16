package org.ghost.messaging.media

import org.ghost.crypto.bridge.MediaCrypto
import org.ghost.media.send.MediaPreparer
import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.messaging.engine.MediaReceiveSteps
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **SCN-MC** (Phase 11 design §15.3, §15.4) at the slice's scale: `MEDIA-INGEST`, `MEDIA-BIND` and
 * `MEDIA-VERIFY` over [MediaWorld], with the scenario's oracles asserted one by one —
 *
 *  - no blob consumed without a durable file (the crash enumeration at every file operation of an
 *    ingest, rebooted and reconciled between points);
 *  - a wrong-size blob consumed and dropped, counted; a hash the store already has consumed
 *    without a second file; a write below the free-space floor consumed without a file, counted;
 *  - the retention day `min(day(E) + 1, today + 8)`;
 *  - `complete` only with every row of the class bound, `verified` only after a full pass;
 *  - a manifest that does not open makes the object `corrupt` (key erased, references released,
 *    the checkpoint the §11.1 caller owes);
 *  - **hash squatting**: an object whose manifest names another sender's fragment hashes binds the
 *    honest files, stays bound while the honest object names them, and fails in `MEDIA-VERIFY`
 *    while the honest object verifies from the same files (§7.2: ownership by authentication);
 *  - the pool cap evicts the earliest retention, never stopping the claims;
 *  - `MEDIA-GC`: past `incomplete_after_hour` declared `incomplete` (the same release), pooled
 *    blobs past their day collected, files gone with the reconcile.
 *
 * The worlds the gate scale multiplies (first-message media through `sessionInbound`, a request's
 * branches) are `DmMediaReceiveTest`'s, on the real cryptography; the timer-change-during-upload
 * world is the sender half's (R-MT4, `MediaStepsTest`).
 */
class MediaReceiveScenarioTest {

    private class Box {
        val dir: File = java.nio.file.Files.createTempDirectory("ghost-receive").toFile()
        val db: String = File(dir, "world.db").absolutePath
        var world: MediaWorld = MediaWorld(db, dir)
        var activated = false

        fun open(): MediaWorld {
            world.close()
            world = MediaWorld(db, dir, world.relay)
            if (!activated) {
                world.activate()
                activated = true
            }
            return world
        }
    }

    /** One sealed image as a scripted sender would produce it (files included, names released after). */
    private fun sealedImage(world: MediaWorld, contact: ByteArray): Pair<MediaPreparer.Prepared, ByteArray> {
        val prepared = world.preparer.prepareImage(Goldens.jpeg, contact, viewOnce = false)
        return prepared to prepared.sealed.manifestHash
    }

    /** Deposit every sealed file (manifest first, then the fragments) and return the object id. */
    private fun depositObject(world: MediaWorld, prepared: MediaPreparer.Prepared): ByteArray {
        world.depositMedia(prepared.sealed.manifestBlob)
        for (i in prepared.sealed.fragmentHashes.indices) {
            world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[i]))
        }
        return prepared.objectId
    }

    private fun stateOf(world: MediaWorld, objectId: ByteArray): String =
        world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId))!!

    private fun count(world: MediaWorld, sql: String, args: List<Any?> = emptyList()): Long =
        world.sql.queryLong(sql, args)!!

    private fun filesOnDisk(world: MediaWorld): Int = world.files.list().count { it.length == 32 }

    @Test
    fun aFullReceiveRunsIngestBindVerifyInOrder() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val (prepared) = sealedImage(world, contact)
            val objectId = prepared.objectId

            // The descriptor arrives first: the object is `awaiting`, nothing fetched yet.
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = prepared.sealed.manifestHash,
                ),
                keyEnv = prepared.sealed.keyEnv,
            )
            assertEquals("awaiting", stateOf(world, objectId))

            // Deposit everything; one pass ingests (binding rows as blobs arrive), binds the
            // manifest, completes at the sixteenth fragment and verifies.
            depositObject(world, prepared)
            world.receiveSteps.ingest()
            assertEquals(0L, count(world, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
            world.receiveSteps.bind()
            assertEquals("bind met every blob already ingested: complete at once", "complete", stateOf(world, objectId))
            world.receiveSteps.verify()
            assertEquals("verified", stateOf(world, objectId))
            assertEquals(1, world.receiveSteps.stats.verified)
            assertTrue("no key erasure: no checkpoint", world.checkpointLog.isEmpty())

            // Every row names a whole file; every file is named by a row. The disk holds the
            // sender-side sealed files too (17, their names still reserved) — 34 in total.
            world.assertSendInvariants()
            assertEquals(34, filesOnDisk(world))
            prepared.releaseNames()
        }
    }

    @Test
    fun fragmentsFirstPoolUntilTheDescriptorArrives() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val (prepared) = sealedImage(world, contact)

            // Everything pooled: no object names anything.
            depositObject(world, prepared)
            world.receiveSteps.ingest()
            assertEquals(17L, count(world, "SELECT count(*) FROM media_blob"))
            assertEquals(17L, count(world, "SELECT count(*) FROM media_blob b WHERE NOT EXISTS " +
                "(SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash)"))

            // The descriptor adopts the pool: bind finds every row already bound, the object runs
            // to `verified` in one pass.
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    prepared.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = prepared.sealed.manifestHash,
                ),
                keyEnv = prepared.sealed.keyEnv,
            )
            world.receiveSteps.bind()
            assertEquals("complete", stateOf(world, prepared.objectId))
            world.receiveSteps.verify()
            assertEquals("verified", stateOf(world, prepared.objectId))
            prepared.releaseNames()
        }
    }

    @Test
    fun wrongSizeDuplicateAndBelowFloorAreConsumedAndCounted() {
        Box().open().use { world ->
            // A blob that is not exactly 64 KiB: consumed, dropped, counted — no row, no file.
            world.depositMedia(ByteArray(MediaLimits.FRAGMENT_BYTES) { 1 }, relayExpirySeconds = world.clock.now + 86_400)
            world.sql.exec(
                "UPDATE inbox_blob SET ciphertext = randomblob(1024) WHERE state = 'fetched'",
                emptyList(),
            )
            world.receiveSteps.ingest()
            assertEquals(1, world.receiveSteps.stats.wrongSizeDrops)
            assertEquals(0L, count(world, "SELECT count(*) FROM media_blob"))

            // A hash the store already has: consumed without a second file.
            val bytes = ByteArray(MediaLimits.FRAGMENT_BYTES) { 2 }
            world.database.transaction { tx ->
                org.ghost.media.store.MediaBlobs(world.fragments).insert(
                    tx,
                    org.ghost.media.store.MediaBlob(
                        org.ghost.messaging.media.digest(bytes), world.files.newName(),
                        org.ghost.media.store.BlobOrigin.SEALED, null,
                    ),
                )
            }
            world.depositMedia(bytes)
            val filesBefore = filesOnDisk(world)
            world.receiveSteps.ingest()
            assertEquals(1, world.receiveSteps.stats.duplicateConsumes)
            assertEquals(filesBefore, filesOnDisk(world))

            // Below the free-space floor: consumed without a file, counted, no row.
            world.crashFs.freeSpaceBytes = 1
            world.depositMedia(ByteArray(MediaLimits.FRAGMENT_BYTES) { 3 })
            world.receiveSteps.ingest()
            assertEquals(1, world.receiveSteps.stats.belowFloorConsumes)
            assertEquals(
                "no ingested row: the below-floor blob wrote nothing (the sealed row from the duplicate case is the only one)",
                1L, count(world, "SELECT count(*) FROM media_blob"),
            )
            world.crashFs.freeSpaceBytes = null
        }
    }

    @Test
    fun retentionDayIsTheEarlierOfRelayExpiryPlusOneAndEightDays() {
        Box().open().use { world ->
            val early = ByteArray(MediaLimits.FRAGMENT_BYTES) { 4 }
            val late = ByteArray(MediaLimits.FRAGMENT_BYTES) { 5 }
            world.depositMedia(early, relayExpirySeconds = world.clock.now + 2 * 86_400)
            world.depositMedia(late, relayExpirySeconds = world.clock.now + 30 * 86_400)
            world.receiveSteps.ingest()
            val day = MediaLimits.day(world.clock.now)
            assertEquals(
                "min(day(E) + 1, today + 8): E is two days out, so day(E) + 1",
                day + 3,
                count(world, "SELECT retain_until_day FROM media_blob WHERE blob_hash = ?", listOf(org.ghost.messaging.media.digest(early))),
            )
            assertEquals(
                day + MediaLimits.POOL_MAX_DAYS,
                count(world, "SELECT retain_until_day FROM media_blob WHERE blob_hash = ?", listOf(org.ghost.messaging.media.digest(late))),
            )
        }
    }

    @Test
    fun completeRequiresEveryFragmentAndVerifyRejectsTampering() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val (prepared) = sealedImage(world, contact)
            val objectId = prepared.objectId
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = prepared.sealed.manifestHash,
                ),
                keyEnv = prepared.sealed.keyEnv,
            )
            // Manifest plus fifteen fragments: one `expected` row remains, no completeness.
            world.depositMedia(prepared.sealed.manifestBlob)
            for (i in 0 until 15) world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[i]))
            world.receiveSteps.ingest()
            world.receiveSteps.bind()
            assertEquals("fetching", stateOf(world, objectId))
            world.receiveSteps.verify()
            assertEquals("nothing verified before complete", 0, world.receiveSteps.stats.verified)

            // The sixteenth fragment completes the object.
            world.depositMedia(world.files.read(prepared.sealed.fragmentFiles[15]))
            world.receiveSteps.ingest()
            assertEquals("complete", stateOf(world, objectId))

            // Tamper with one fragment file — the one the fragment **row** names (ingest wrote its
            // own copy under a fresh name): the full pass fails the object, erases the key,
            // releases the references and the caller checkpoints.
            var tamperName = ByteArray(0)
            world.sql.query(
                "SELECT b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
                    "WHERE f.object_id = ? AND f.ordinal = 3",
                listOf(objectId),
            ) { tamperName = it.blob(0) }
            val tampered = world.files.read(tamperName)
            tampered[100] = (tampered[100].toInt() xor 0xFF).toByte()
            world.files.delete(tamperName)
            world.files.write(tamperName, tampered, enforceFloor = false)
            world.receiveSteps.verify()
            assertEquals("corrupt", stateOf(world, objectId))
            assertEquals(1, world.receiveSteps.stats.corrupted)
            assertEquals(
                "the key is erased",
                0L, count(world, "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL", listOf(objectId)),
            )
            assertEquals("the references are released", 0L, count(world, "SELECT count(*) FROM media_fragment WHERE object_id = ?", listOf(objectId)))
            assertEquals("the caller checkpoints after a key erasure", 1, world.checkpointLog.size)
            prepared.releaseNames()
        }
    }

    @Test
    fun aManifestThatDoesNotOpenMakesTheObjectCorrupt() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            val (prepared) = sealedImage(world, contact)
            val objectId = prepared.objectId
            // A manifest hash that names garbage: the descriptor is fine, the manifest is not.
            val garbage = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x7F }
            val garbageHash = org.ghost.messaging.media.digest(garbage)
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0, manifestHash = garbageHash,
                ),
                keyEnv = prepared.sealed.keyEnv,
            )
            world.depositMedia(garbage)
            world.receiveSteps.ingest()
            world.receiveSteps.bind()
            assertEquals("corrupt", stateOf(world, objectId))
            assertEquals(1, world.receiveSteps.stats.corrupted)
            assertEquals(1, world.checkpointLog.size)
            prepared.releaseNames()
        }
    }

    @Test
    fun hashSquattingFailsTheSquattersObjectAndNotTheHonestOne() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)

            // The honest sender's object, sealed and deposited.
            val honest = sealedImage(world, contact).first
            depositObject(world, honest)
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    honest.objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = honest.sealed.manifestHash,
                ),
                keyEnv = honest.sealed.keyEnv,
            )

            // The squatter: its own key and registry record, but a manifest naming the honest
            // object's fragment hashes. Its descriptor names that manifest. The honest files are
            // already on disk — the squatter names them and deposits nothing of its own.
            val squatterId = ByteArray(16) { 0x66 }
            val squatterKey = org.ghost.messaging.media.FakeReaders.fakeKeyEnvOf(squatterId)
            val honestHashes = honest.sealed.fragmentHashes
            val squatManifest = org.ghost.messaging.media.FakeReaders.manifestBytes(
                objectId = squatterId,
                kindCode = 1,
                viewOnce = false,
                classCode = 0,
                contentLen = honest.sealed.contentLen,
                width = honest.sealed.width,
                height = honest.sealed.height,
                durationMs = honest.sealed.durationMs,
                preview = ByteArray(0),
                hashes = honestHashes,
            )
            world.readers.register(
                org.ghost.messaging.media.FakeReaders.Recorded(
                    objectId = squatterId,
                    keyEnv = squatterKey,
                    // Different sealed bytes: the squatter's "ciphertext" is its own.
                    chunks = honest.sealed.fragmentHashes.mapIndexed { index, _ ->
                        List(4) { k ->
                            ByteArray(MediaLimits.FRAGMENT_BYTES) { ((index * 31 + k * 7 + it % 13) and 0xFF).toByte() }
                        }
                    },
                    kind = MediaCrypto.Kind.IMAGE,
                    viewOnce = false,
                    classCode = 0,
                    contentLen = honest.sealed.contentLen,
                    width = honest.sealed.width,
                    height = honest.sealed.height,
                    durationMs = honest.sealed.durationMs,
                    preview = ByteArray(0),
                ),
            )
            world.depositMedia(squatManifest)
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    squatterId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = org.ghost.messaging.media.digest(squatManifest),
                ),
                keyEnv = squatterKey,
            )

            // Both bind: the honest files back both objects' rows, and every row being bound,
            // both objects are complete.
            world.receiveSteps.ingest()
            world.receiveSteps.bind()
            assertEquals("complete", stateOf(world, honest.objectId))
            assertEquals("complete", stateOf(world, squatterId))
            assertEquals(
                "a hash named by two objects stays bound to both",
                34L, // 17 rows per object (manifest + 16 fragments); the squatter's fragment rows name the honest hashes
                count(world, "SELECT count(*) FROM media_fragment WHERE state = 'bound'"),
            )

            // Verify: the honest object verifies from the same files the squatter failed on.
            world.receiveSteps.verify()
            assertEquals("verified", stateOf(world, honest.objectId))
            assertEquals("corrupt", stateOf(world, squatterId))
            assertEquals(
                "the honest blobs survive the squatter's release (the honest object still names them); " +
                    "the squatter's own manifest returns to the pool, §7.2's RELEASE rule",
                18L, count(world, "SELECT count(*) FROM media_blob"),
            )
            assertEquals(
                "the squatter's key is gone",
                0L, count(world, "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL", listOf(squatterId)),
            )
            assertEquals(
                "the honest key is untouched",
                1L, count(world, "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL", listOf(honest.objectId)),
            )
            honest.releaseNames()
        }
    }

    @Test
    fun thePoolCapEvictsTheEarliestRetentionNeverStoppingTheClaims() {
        Box().open().use { world ->
            // A tiny cap over the same world: three blobs hold, the fourth evicts the earliest.
            val steps = MediaReceiveSteps(
                database = world.database,
                sync = world.syncPorts,
                files = world.files,
                readers = world.readers,
                preparing = { world.preparing.snapshot() },
                checkpoint = { true },
                contexts = world.contexts,
                clock = world.clock,
                poolCapBytes = 3L * MediaLimits.FRAGMENT_BYTES,
            )
            val blobs = (0 until 4).map { n ->
                ByteArray(MediaLimits.FRAGMENT_BYTES) { n.toByte() }.also { world.depositMedia(it, relayExpirySeconds = world.clock.now + (n + 1) * 86_400) }
            }
            steps.ingest()
            assertEquals("all four claimed and consumed", 0L, count(world, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
            assertEquals(1, steps.stats.evicted)
            assertEquals(
                "the earliest retention went",
                3L, count(world, "SELECT count(*) FROM media_blob"),
            )
            assertEquals(
                0L, count(world, "SELECT count(*) FROM media_blob WHERE blob_hash = ?", listOf(org.ghost.messaging.media.digest(blobs[0]))),
            )
        }
    }

    @Test
    fun gcDeclaresIncompleteObjectsAndCollectsExpiredPools() {
        Box().open().use { world ->
            val contact = ByteArray(16) { 0x21 }
            world.addContact(contact)
            // An object already past its relay expiry when the GC pass runs. No files: the
            // object's pipeline never ran, so the directory is the pooled blob's alone.
            val objectId = ByteArray(16) { 0x77 }
            world.receiveDescriptor(
                contact,
                org.ghost.media.store.MediaDescriptor(
                    objectId, MediaKind.IMAGE, viewOnce = false, classCode = 0,
                    manifestHash = digest(ByteArray(32) { 0x55 }),
                ),
                keyEnv = org.ghost.messaging.media.FakeReaders.fakeKeyEnvOf(objectId),
                relayExpiryHour = world.clock.now - 3_600 - world.clock.now % 3_600,
            )
            // A pooled blob whose day has passed.
            val pooled = ByteArray(MediaLimits.FRAGMENT_BYTES) { 9 }
            world.depositMedia(pooled, relayExpirySeconds = world.clock.now + 3_600)
            world.receiveSteps.ingest()
            world.clock.now += 2 * 86_400

            world.receiveSteps.gc()
            assertEquals("incomplete", stateOf(world, objectId))
            assertEquals(1, world.receiveSteps.stats.declaredIncomplete)
            assertEquals("the pooled blob is collected", 0L, count(world, "SELECT count(*) FROM media_blob WHERE origin = 'ingested'"))
            assertEquals("a key went: the checkpoint ran", 1, world.checkpointLog.size)
            assertEquals("the reconcile took the pooled file", 0, filesOnDisk(world))
        }
    }

    @Test
    fun aCrashAtEveryIngestFileOperationLeavesAConsistentStore() {
        // One blob, one write of five calls; a fresh world per point, a reboot and a reconcile
        // between the crash and the retry — §15.3's engine-boundary enumeration.
        for (point in 1..5) {
            val box = Box()
            box.open().use { world ->
                world.addContact(ByteArray(16) { 0x21 })
                world.depositMedia(ByteArray(MediaLimits.FRAGMENT_BYTES) { point.toByte() })
            }
            // The crash: the write dies at this call; the blob is deferred, not consumed.
            box.open().use { world ->
                world.crashFs.crashAtCall = point
                world.receiveSteps.ingest()
                world.crashFs.crashAtCall = -1
            }
            // The reboot: reconcile repairs the orphan; past the deferral the retry lands the blob.
            box.open().use { world ->
                world.reconcile()
                assertStoreConsistent(world)
                world.clock.now += 120
                world.receiveSteps.ingest()
                world.receiveSteps.bind()
                world.receiveSteps.verify()
                assertStoreConsistent(world)
                assertEquals(
                    "point $point: the row and its whole file survive",
                    1L, count(world, "SELECT count(*) FROM media_blob"),
                )
                assertEquals("point $point: the blob is consumed", 0L, count(world, "SELECT count(*) FROM inbox_blob WHERE state = 'fetched'"))
                assertEquals("point $point: one file on disk", 1, filesOnDisk(world))
            }
        }
    }

    /** The receive-side half of §15.3's invariants: every row names a whole file and vice versa. */
    private fun assertStoreConsistent(world: MediaWorld) {
        val rows = ArrayList<Pair<ByteArray, ByteArray>>()
        world.sql.query("SELECT blob_hash, file_name FROM media_blob") { r ->
            rows += r.blob(0) to r.blob(1)
        }
        for ((hash, name) in rows) {
            val bytes = world.files.read(name)
            assertEquals("a file is whole", MediaLimits.FRAGMENT_BYTES.toLong(), bytes.size.toLong())
            assertTrue("a file matches its row's hash", digest(bytes).zip(hash).all { (a, b) -> a == b })
        }
        val named = rows.map { hexOf(it.second) }.toHashSet()
        for (listed in world.files.list()) {
            assertTrue("a stray file survives: $listed", listed.startsWith(".t") || named.contains(listed))
        }
    }
}
