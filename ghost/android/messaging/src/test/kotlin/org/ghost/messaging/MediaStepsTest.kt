package org.ghost.messaging

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmContent
import org.ghost.media.send.MediaFeeder
import org.ghost.media.store.CiphertextFiles
import org.ghost.media.store.MediaBlobs
import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.MediaFragments
import org.ghost.media.store.NameSource
import org.ghost.media.store.RetryResult
import org.ghost.messaging.engine.ContactMaterial
import org.ghost.messaging.engine.DmSyncPorts
import org.ghost.messaging.engine.MediaOpIds
import org.ghost.messaging.engine.MediaOrphanSteps
import org.ghost.messaging.engine.MediaSteps
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.SendStep
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The MEDIA-* machines of Phase 11 design §13.5 over a real migrated v8 database ([OwnerWorld]):
 * `MEDIA-COMMIT`'s rows and the `M_c` registration, `MEDIA-FEED`'s deterministic ops and windows,
 * the corrupt-file rule (`NOT_RETRYABLE`), `MEDIA-DEADLINE`'s failure, and the user-retry paths.
 * The envelope layer is faked at its only seam used here (`encodeContent` — the L0's bytes are
 * the codec's subject, not this file's); everything the rows claim is asserted in the database.
 */
class MediaStepsTest {

    private val week = 604_800L
    private val day = 86_400L
    private val hour = 3_600L
    private val weekOrigin = 345_600L
    private val now = weekStart(2_870) + 2 * day

    private fun weekStart(w: Long) = weekOrigin + week * w

    /** Test-local name source ([CiphertextFiles]'s constructor takes one; the store's tests hold theirs). */
    private class Names : NameSource {
        private var n = 0
        override fun next16(): ByteArray {
            val v = n++
            return ByteArray(16) { if (it < 4) (v ushr (8 * it)).toByte() else 0 }
        }
    }

    private class Fx(
        val contactId: ByteArray,
        val mediaNs: ByteArray,
        val steps: MediaSteps,
        val fragments: MediaFragments,
        val objects: MediaObjects,
        val files: CiphertextFiles,
    )

    private fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun blob(n: Int): ByteArray = ByteArray(MediaLimits.FRAGMENT_BYTES) { ((it * 31 + n) and 0xFF).toByte() }

    /** [org.ghost.media.store]'s `queryCount` is module-internal; this test counts via [queryLong]. */
    private fun count(sql: org.ghost.storage.SqlExecutor, text: String, args: List<Any?> = emptyList()): Long =
        sql.queryLong(text, args)!!

    private fun queryBytes(sql: org.ghost.storage.SqlExecutor, text: String, args: List<Any?>): ByteArray {
        var out = ByteArray(0)
        sql.query(text, args) { out = it.blob(0) }
        return out
    }

    private fun seed(world: OwnerWorld): Fx {
        world.clock.now = now
        world.activate()
        val self = world.contexts.get()!!
        val card = world.crypto.ownCard(0)!!.card
        val contactId = ByteArray(16) { 0x21 }
        val cardEnv = self.content.seal(world.random.bytes(12), contactId, card)
        world.sql.exec(
            "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, " +
                "source, establishment) VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
            listOf(contactId, ByteArray(32) { 0x22 }, cardEnv),
        )
        world.sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(ByteArray(16) { 0x23 }, contactId),
        )
        // A pending orphan row for a DIFFERENT namespace: the commit must delete only M_c's.
        world.sql.exec(
            "INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)",
            listOf(ByteArray(32) { 0x24 }),
        )
        val derived = world.crypto.deriveCard(card, 0) as DmCards.DeriveResult.Ok
        val mediaNs = derived.values.mediaNamespace
        derived.values.clearSecrets()

        val dir = java.nio.file.Files.createTempDirectory("ghost-media-steps").toFile()
        val files = CiphertextFiles(File(dir, "m"), org.ghost.media.store.NioCiphertextFileSystem(), Names(), 0L)
            .also { it.open() }
        val fragments = MediaFragments()
        val objects = MediaObjects(fragments)
        val blobs = MediaBlobs(fragments)
        val sync = DmSyncPorts(
            world.stores.namespaces, world.stores.capabilities, world.stores.registrations,
            world.stores.outbox, world.stores.inbox,
        )
        val envelopes = object : org.ghost.messaging.port.DmEnvelopes by world.envelopes {
            override fun encodeContent(
                kind: DmContent.Kind,
                messageId: ByteArray,
                authorMinute: Long,
                minuteIndex: Int,
                timerCode: Int,
                timerVersion: Long,
                quoteRef: ByteArray?,
                body: ByteArray,
                contactId: ByteArray,
                offerRootGen: Int,
                offerEnv: ByteArray,
                revocation: ByteArray,
                sessionReset: Boolean,
                pqKey: DmContent.PqKeyCandidate?,
                pqKeyFirst: Boolean,
            ): DmContent.Encoded = DmContent.Encoded.Ok(ByteArray(64) { 0x05 }, 4_096)
        }
        val material = ContactMaterial(world.crypto, world.contexts)
        val sendStep = SendStep(
            world.database, sync, envelopes, material, RelaySetResolver(world.esSlots),
            world.clock, world.random, world.contexts,
        )
        val feeder = MediaFeeder(files, objects, fragments, blobs, sync.outbox, MediaOpIds.sha256())
        val steps = MediaSteps(
            database = world.database,
            sync = sync,
            crypto = world.crypto,
            envelopes = envelopes,
            material = material,
            relays = RelaySetResolver(world.esSlots),
            sendStep = sendStep,
            feeder = feeder,
            opIds = MediaOpIds.sha256(),
            clock = world.clock,
            random = world.random,
            contexts = world.contexts,
            mediaOrphans = MediaOrphanSteps(world.crypto, world.clock),
        )
        return Fx(contactId, mediaNs, steps, fragments, objects, files)
    }

    /**
     * Commits a class-0 image object ([corruptAt], when set, names the ordinal whose row hash is
     * computed over different bytes than its file holds — the feed's corruption shape) and
     * returns the object id.
     */
    private fun commitObject(world: OwnerWorld, fx: Fx, corruptAt: Int = -1): ByteArray {
        val objectId = ByteArray(16) { 0x30 }
        val manifest = ByteArray(MediaLimits.FRAGMENT_BYTES) { 0x4D }
        val manifestName = fx.files.newName()
        fx.files.write(manifestName, manifest, enforceFloor = false)
        val fragmentHashes = (0 until 16).map { if (it == corruptAt) hash(blob(100 + it)) else hash(blob(it)) }
        val fragmentFiles = (0 until 16).map {
            val name = fx.files.newName()
            fx.files.write(name, blob(it), enforceFloor = false)
            name
        }
        val result = fx.steps.commit(
            world.contexts.get()!!,
            MediaSteps.CommitRequest(
                contactId = fx.contactId,
                kind = MediaKind.IMAGE,
                viewOnce = false,
                classCode = 0,
                objectId = objectId,
                manifestHash = hash(manifest),
                caption = ByteArray(0),
                keyEnv = ByteArray(60) { 0x4B },
                manifestBlob = manifest,
                manifestFile = manifestName,
                fragmentHashes = fragmentHashes,
                fragmentFiles = fragmentFiles,
            ),
        )
        assertTrue(result is MediaSteps.CommitResult.Committed)
        return objectId
    }

    @Test
    fun commitRegistersMcWritesTheRowsAndClearsOnlyMcOrphan() {
        OwnerWorld().use { world ->
            val fx = seed(world)
            val objectId = commitObject(world, fx)
            assertEquals(1L, count(world.sql, "SELECT count(*) FROM dm_message WHERE kind = 5"))
            assertEquals(1L, count(world.sql, "SELECT count(*) FROM dm_outbound_item WHERE kind = 5"))
            assertEquals(
                1L,
                count(world.sql, 
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND role = 'out' AND state = 'uploading'",
                    listOf(objectId),
                ),
            )
            assertEquals(
                17L,
                count(world.sql, 
                    "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'unsent'",
                    listOf(objectId),
                ),
            )
            assertEquals(
                1L,
                count(world.sql, 
                    "SELECT count(*) FROM sync_namespace WHERE namespace_id = ? AND consumer = 'media'",
                    listOf(fx.mediaNs),
                ),
            )
            assertEquals(
                0L,
                count(world.sql, 
                    "SELECT count(*) FROM dm_orphan_namespace WHERE namespace_id = ?",
                    listOf(fx.mediaNs),
                ),
            )
            assertEquals(1L, count(world.sql, "SELECT count(*) FROM dm_orphan_namespace"))
            // The countdown did not start: the expiry is the upper bound, well beyond now
            // (the `*_minute` columns are second-aligned timestamps on a minute grid).
            val expireAt = world.sql.queryLong("SELECT expire_at_minute FROM dm_message WHERE kind = 5", emptyList())!!
            assertTrue(expireAt > now + 24 * hour)
        }
    }

    @Test
    fun feedEnqueuesDeterministicOpsLowestFirstAndStopsAtTheWindows() {
        OwnerWorld().use { world ->
            val fx = seed(world)
            val objectId = commitObject(world, fx)
            // The feed fills the windows: a class-0 object's whole 17 ordinals fit the 32 bound,
            // so one pass feeds all of them, the manifest first.
            fx.steps.feed()
            val ops = "SELECT count(*) FROM media_outbound_op WHERE object_id = ?"
            val open = "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'open'"
            val joined = "SELECT count(*) FROM outbox_op oo JOIN media_outbound_op mo " +
                "ON oo.operation_id = mo.operation_id WHERE mo.object_id = ?"
            assertEquals(17L, count(world.sql, ops, listOf(objectId)))
            assertEquals(17L, count(world.sql, open, listOf(objectId)))
            assertEquals(17L, count(world.sql, joined, listOf(objectId)))
            // Determinism: the same (object, ordinal, generation, resend) derives the same op id.
            val opId = MediaOpIds.sha256().of(objectId, -1, 0, 0)
            assertEquals(
                1L,
                count(
                    world.sql,
                    "SELECT count(*) FROM media_outbound_op WHERE object_id = ? AND ordinal = -1 AND operation_id = ?",
                    listOf(objectId, opId),
                ),
            )
            // A re-feed with everything open feeds nothing (the windows are per state, not per call).
            fx.steps.feed()
            assertEquals(17L, count(world.sql, ops, listOf(objectId)))
        }
    }

    @Test
    fun aFileThatDoesNotMatchItsHashFailsTheObjectWithNoRetry() {
        OwnerWorld().use { world ->
            val fx = seed(world)
            // Ordinal 3's row hash names different bytes than its file holds.
            val objectId = commitObject(world, fx, corruptAt = 3)
            fx.steps.feed()
            // The feed fed -1, 0, 1, 2, then failed the object at 3.
            assertEquals(
                "failed",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
            )
            assertEquals(
                4L,
                count(world.sql, 
                    "SELECT count(*) FROM media_outbound_op WHERE object_id = ?",
                    listOf(objectId),
                ),
            )
            // No failed ordinal was ever settled — the corrupt-file shape: not retryable.
            assertEquals(
                RetryResult.NOT_RETRYABLE,
                world.database.transaction { tx -> fx.objects.retryUpload(tx, objectId, now) },
            )
        }
    }

    @Test
    fun deadlineFailsTheObjectTheMessageAndStartsTheCountdown() {
        OwnerWorld().use { world ->
            val fx = seed(world)
            val objectId = commitObject(world, fx)
            // The deadline hour, read before the pass: MEDIA-DEADLINE runs the M_c orphan rule in
            // the same transaction, and a completed condition deletes the upload row (section 13.5).
            val deadlineHour = world.sql.queryLong(
                "SELECT deadline_hour FROM media_upload WHERE object_id = ?",
                listOf(objectId),
            )!!
            world.clock.now = now + 7 * day + hour
            fx.steps.deadline()
            assertEquals(
                "failed",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
            )
            assertEquals(
                "failed",
                world.sql.queryString("SELECT state FROM dm_outbound_item WHERE kind = 5", emptyList()),
            )
            assertEquals(
                "failed",
                world.sql.queryString("SELECT state FROM dm_message WHERE kind = 5", emptyList()),
            )
            val expireAt = world.sql.queryLong("SELECT expire_at_minute FROM dm_message WHERE kind = 5", emptyList())!!
            val timerCode = world.sql.queryLong("SELECT timer_code FROM dm_conversation", emptyList())!!.toInt()
            // The countdown anchors at the upload's deadline hour, not the pass's clock (D26),
            // as a second-aligned minute-grid timestamp.
            val expect = deadlineHour + org.ghost.messaging.engine.DmTimers.timerSeconds(timerCode)
            assertTrue("expireAt=$expireAt expect=$expect", expireAt in expect..expect + 60)
        }
    }

    @Test
    fun aFailedOrdinalObjectRetriesUntilTheDeadlinePasses() {
        OwnerWorld().use { world ->
            val fx = seed(world)
            val objectId = commitObject(world, fx)
            assertEquals(
                RetryResult.NOT_FAILED,
                world.database.transaction { tx -> fx.objects.retryUpload(tx, objectId, now) },
            )
            // The FAILED-outcome shape: an ordinal settled failed (along the trigger's path).
            world.database.transaction { tx ->
                tx.sql.exec(
                    "UPDATE media_fragment SET upload_state = 'open' WHERE object_id = ? AND ordinal = 0",
                    listOf(objectId),
                )
                tx.sql.exec(
                    "UPDATE media_fragment SET upload_state = 'failed' WHERE object_id = ? AND ordinal = 0",
                    listOf(objectId),
                )
                fx.objects.markFailed(tx, objectId)
            }
            assertEquals(
                RetryResult.RETRIED,
                world.database.transaction { tx -> fx.objects.retryUpload(tx, objectId, now) },
            )
            assertEquals(
                "uploading",
                world.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId)),
            )
            assertEquals(
                17L,
                count(world.sql, 
                    "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'unsent'",
                    listOf(objectId),
                ),
            )
            world.database.transaction { tx ->
                tx.sql.exec(
                    "UPDATE media_fragment SET upload_state = 'open' WHERE object_id = ? AND ordinal = 0",
                    listOf(objectId),
                )
                tx.sql.exec(
                    "UPDATE media_fragment SET upload_state = 'failed' WHERE object_id = ? AND ordinal = 0",
                    listOf(objectId),
                )
                fx.objects.markFailed(tx, objectId)
            }
            assertEquals(
                RetryResult.DEADLINE_PASSED,
                world.database.transaction { tx -> fx.objects.retryUpload(tx, objectId, now + 7 * day + hour) },
            )
        }
    }
}
