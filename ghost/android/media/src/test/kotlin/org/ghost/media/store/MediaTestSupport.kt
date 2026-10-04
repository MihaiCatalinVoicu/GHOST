package org.ghost.media.store

import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncDatabase
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import java.io.File

internal fun bytes(size: Int, fill: Int) = ByteArray(size) { fill.toByte() }

internal fun id16(n: Int) = bytes(16, n)

internal fun hash32(n: Int) = bytes(32, n)

/** A 64 KiB "ciphertext" blob whose bytes are a function of [n] (the store treats it as opaque). */
internal fun blobOf(n: Int): ByteArray = ByteArray(MediaLimits.FRAGMENT_BYTES) { ((it * 31 + n * 7 + (it ushr 8)) and 0xFF).toByte() }

/** The hash the world gives blob [n]: distinct per [n] (the store never computes one: ingest and sealing hand it in). */
internal fun hashOfBlob(n: Int): ByteArray = ByteArray(32) { if (it < 4) ((n ushr (8 * it)) and 0xFF).toByte() else 0x5A }

/**
 * No `toString` of a store type may show a byte (T3): no `[B@` array identity, no hex or Base64 run of a field, no decimal
 * list. [fields] are the byte arrays the object holds; each must be absent from [text] in every common rendering.
 */
internal fun assertRedacted(text: String, vararg fields: ByteArray) {
    assertFalse("array identity in: $text", text.contains("[B@"))
    for (field in fields) {
        if (field.isEmpty()) continue
        val hex = hex(field)
        assertFalse("hex of a field in: $text", text.lowercase().contains(hex))
        assertFalse("hex prefix of a field in: $text", hex.length >= 8 && text.lowercase().contains(hex.substring(0, 8)))
        assertFalse("decimal list in: $text", text.contains(field.joinToString(", ")) && field.size > 1)
        val base64 = java.util.Base64.getEncoder().encodeToString(field)
        assertFalse("base64 of a field in: $text", base64.length >= 8 && text.contains(base64))
    }
}

/** True when [text] holds none of the lower-case hex or decimal renderings of any of [secrets]. */
internal fun containsNone(text: String, secrets: List<ByteArray>): Boolean = secrets.none { text.lowercase().contains(hex(it)) }

/**
 * A migrated database with the production pragmas, the sync layer's transaction wrapper over it, the media stores, and a
 * temporary directory with a [CiphertextFiles] over a [CrashableFileSystem]. Closing it removes the directory.
 */
internal class MediaWorld(
    directory: File? = null,
    val freeFloorBytes: Long = 0L,
    val db: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() },
    /** Wraps the executor the transactions run on, to inject a failure at a statement (the reads of the tests use [db] itself). */
    wrap: (SqlExecutor) -> SqlExecutor = { it },
) : AutoCloseable {
    val database = SyncDatabase(wrap(db))
    val stores = MediaStores()
    val dir: File = directory ?: java.nio.file.Files.createTempDirectory("ghost-media-store").toFile()
    val disk = CrashableFileSystem(NioCiphertextFileSystem(directorySyncSupported = false))
    val names = SequentialNames()
    val files = CiphertextFiles(File(dir, "m"), disk, names, freeFloorBytes).also { it.open() }
    val reconcile = MediaReconcile(files, stores.blobs, stores.fragments)

    fun <T> tx(block: (org.ghost.sync.api.SyncTransaction) -> T): T = database.transaction(block)

    /** Writes the blob [n] under a new name and inserts its row (sealed, or ingested with a retention day) in one transaction. */
    fun putBlob(n: Int, origin: BlobOrigin = BlobOrigin.SEALED, retainUntilDay: Long? = null): ByteArray {
        val written = files.write(blobOf(n), enforceFloor = false) as WriteResult.Written
        tx { stores.blobs.insert(it, MediaBlob(hashOfBlob(n), written.fileName, origin, retainUntilDay)) }
        return written.fileName
    }

    /** The names present in the store directory. */
    fun listed(): List<String> = files.list()

    override fun close() {
        db.close()
        dir.deleteRecursively()
    }

    /** A DM message row to hang an object on, with an optional expiry (`delete_at_minute`). */
    fun dmMessage(messageId: ByteArray, deleteAtMinute: Long? = null) {
        val contact = id16(0xD1)
        if ((db.queryLong("SELECT count(*) FROM dm_contact WHERE contact_id = ?", listOf(contact)) ?: 0L) == 0L) {
            db.exec(
                "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                    "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
                listOf(contact, bytes(32, 0x71), bytes(159, 0x72)),
            )
            db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(id16(0xC0), contact))
        }
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                "body_env, state, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 5, 600, 600, 0, ?, ?, 'queued', ?, ?)",
            listOf(messageId, id16(0xC0), if (deleteAtMinute == null) 0L else 4L, bytes(60, 0x73), deleteAtMinute, deleteAtMinute),
        )
    }

    fun ensureNamespace(namespaceId: ByteArray) {
        if ((db.queryLong("SELECT count(*) FROM sync_namespace WHERE namespace_id = ?", listOf(namespaceId)) ?: 0L) == 0L) {
            db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'media', 1)", listOf(namespaceId))
        }
    }

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table") ?: 0L

    /** The blobs of an object: the manifest first, then the [MediaLimits.CLASSES] fragments of its class, hashed from a base number. */
    class Blobs(val manifest: ByteArray, val fragments: List<ByteArray>) {
        val all: List<ByteArray> get() = listOf(manifest) + fragments
        override fun toString(): String = "Blobs(${fragments.size})"
    }

    /** The blob hashes of object number [n] of class [classCode] (distinct per object: hash numbers are `n * 1000 + i`). */
    fun blobsOf(n: Int, classCode: Int = 0): Blobs =
        Blobs(hashOfBlob(n * 1000), List(MediaLimits.CLASSES[classCode]) { hashOfBlob(n * 1000 + 1 + it) })

    /** A file name derived from a hash: 16 distinct bytes, so a world with many blob rows and no files has unique names. */
    fun nameOf(hash: ByteArray): ByteArray = hash.copyOf(16).also { it[15] = 0x77 }

    /** `MEDIA-COMMIT` without files: the object, its upload, its blob rows (sealed) and its fragment rows, in one transaction. */
    fun commitOutgoing(
        n: Int,
        messageId: ByteArray? = id16(0x90 + n),
        classCode: Int = 0,
        viewOnce: Boolean = false,
        ttl: Long = 604_800L,
        deadlineHour: Long = 3_600L * 1_000_000,
        namespace: ByteArray = hash32(0x4D),
        blobs: Blobs = blobsOf(n, classCode),
        messageDeleteAtMinute: Long? = null,
        keyEnv: ByteArray = bytes(60, 0x30 + n),
    ): ByteArray {
        val objectId = id16(0xA0 + n)
        if (messageId != null) dmMessage(messageId, messageDeleteAtMinute)
        ensureNamespace(namespace)
        tx { tx ->
            for (hash in blobs.all) stores.blobs.insert(tx, MediaBlob(hash, nameOf(hash), BlobOrigin.SEALED, null))
            stores.objects.insertOutgoing(
                tx,
                NewOutgoing(
                    MediaDescriptor(objectId, MediaKind.VIDEO, viewOnce, classCode, blobs.manifest), id16(0xD1), keyEnv,
                    messageId ?: error("an outgoing object needs a message"), namespace, ttl, deadlineHour,
                ),
            )
            stores.fragments.insertSealed(tx, objectId, classCode, blobs.manifest, blobs.fragments)
        }
        return objectId
    }

    /** `RECV` + `MEDIA-BIND`: the descriptor creates the object `awaiting`; with [bind] its fragment rows are in and it is `fetching`. */
    fun receive(
        n: Int,
        messageId: ByteArray = id16(0x90 + n),
        classCode: Int = 0,
        viewOnce: Boolean = false,
        incompleteAfterHour: Long = 3_600L * 1_000_000,
        bind: Boolean = true,
        blobs: Blobs = blobsOf(n, classCode),
        messageDeleteAtMinute: Long? = null,
        keyEnv: ByteArray = bytes(60, 0x40 + n),
    ): ByteArray {
        val objectId = id16(0xB0 + n)
        dmMessage(messageId, messageDeleteAtMinute)
        tx { tx ->
            stores.objects.onDescriptor(
                tx, messageId, id16(0xD1), MediaDescriptor(objectId, MediaKind.VIDEO, viewOnce, classCode, blobs.manifest),
                keyEnv, incompleteAfterHour,
            )
            if (bind) {
                stores.fragments.insertIncoming(tx, objectId, classCode, blobs.manifest, blobs.fragments)
                stores.objects.markFetching(tx, objectId)
            }
        }
        return objectId
    }

    /** `MEDIA-INGEST`, the database half, for every hash of [hashes] in turn (no file). Returns the objects whose rows were bound. */
    fun ingest(hashes: List<ByteArray>, retainUntilDay: Long = 20_100L): Set<List<Byte>> {
        val bound = LinkedHashSet<List<Byte>>()
        for (hash in hashes) tx { tx ->
            if (!stores.blobs.exists(tx.sql, hash)) stores.blobs.ingest(tx, hash, nameOf(hash), retainUntilDay).forEach { bound += it.toList() }
        }
        return bound
    }

    fun rawState(objectId: ByteArray): String? = db.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(objectId))
}

/** Names from a counter, so that a test can predict them. */
internal class SequentialNames : NameSource {
    private var next = 1
    override fun next16(): ByteArray = ByteArray(16).also { out ->
        out[0] = 0xAB.toByte()
        out[12] = (next ushr 24).toByte()
        out[13] = (next ushr 16).toByte()
        out[14] = (next ushr 8).toByte()
        out[15] = next.toByte()
        next++
    }
}

/** The error of a store call, for `assertThrows`-style checks without catching a catch-all type. */
internal inline fun expectStoreError(error: MediaStoreError, block: () -> Unit) {
    try {
        block()
    } catch (e: MediaStoreException) {
        assertTrue("expected $error, got ${e.error} at ${e.where}", e.error == error)
        return
    }
    org.junit.Assert.fail("expected a MediaStoreException with $error")
}

internal fun SqlExecutor.longs(sql: String, vararg args: Any?): List<Long> {
    val out = ArrayList<Long>()
    query(sql, args.toList()) { out += it.long(0) }
    return out
}

/** Fails the [failAt]-th statement that writes (0-based, `exec` and `execUpdate` alike); everything else is delegated. */
internal class FailAtStatement(private val delegate: SqlExecutor, var failAt: Int = -1) : SqlExecutor by delegate {
    var calls = 0

    override fun exec(sql: String, args: List<Any?>) {
        if (calls++ == failAt) throw IllegalStateException("injected failure at statement ${calls - 1}")
        delegate.exec(sql, args)
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int {
        if (calls++ == failAt) throw IllegalStateException("injected failure at statement ${calls - 1}")
        return delegate.execUpdate(sql, args)
    }
}
