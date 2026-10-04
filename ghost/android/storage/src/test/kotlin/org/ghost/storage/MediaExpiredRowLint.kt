package org.ghost.storage

import java.io.File

/**
 * The **expired-row lint over the media tables** (Phase 11 design §13.6, §10.7 point 4 as F9 and Phase 10 state it; mutant
 * **ME-16**, "a read path ignores expiry"), built in slice S3 with the DAOs of `org.ghost.media.store`.
 *
 * The mechanism is [DmExpiredRowLint]'s and is not reimplemented: its scanner takes the set of tables to look for
 * ([DmExpiredRowLint.readQueriesOverExpiringRows]), and its two-world idea is applied here — every registered query runs against
 * a database that still holds the expired rows and against the same database after they were swept, and the two answers must be
 * **identical**, so a compliant read cannot tell whether SWEEP and the maintenance passes have run yet. What differs from the DM
 * lint is what "expired" means for a media row, which has **no deadline column for its own life**:
 *
 *  - an object, its upload, its fragments and its operations **die with their message**: they are expired when
 *    `dm_message.delete_at_minute <= :now_e` (the sweep deletes the message and the foreign keys cascade);
 *  - an incoming object still `awaiting` or `fetching` past its `incomplete_after_hour` is **declared loss** (§7.5): `MEDIA-GC`
 *    turns it `incomplete`, erases its key and deletes its fragments, so until then a reader must see exactly that;
 *  - an outgoing object still `uploading` past its `deadline_hour` is **failed** (§6.4): `MEDIA-DEADLINE` turns it `failed`;
 *  - a **pooled** blob (one no fragment names) is expired when `retain_until_day < today` and the pool's collector deletes it.
 *
 * Four kinds of query exist because four contracts do, as for the channel tables:
 *
 *  - [MediaDaoQueries] **reads** — a user, the engine or a call sees their result: identical in the two worlds, non-empty in the
 *    swept one, and exactly the rows the live fixture holds (so a filter that hides a live row, `>` for `>=` on a boundary, is
 *    caught here and not only by the store's own tests). A point lookup by key is registered twice: with a live key (judged as a
 *    read) and with an **expired** key ([Mode.HIDES]), which must answer nothing in a world that still holds the row.
 *  - [MediaBoundQueries] **bounds** — a lookup, count or ordering that must agree with what is on the disk and with the
 *    schema's triggers (`media_blob_referenced` counts every fragment, the reconcile keeps every file a row names, the feeder's
 *    open ordinals are operations in flight at Phase 7 whether or not the message has expired). They **see** the expired rows;
 *    the lint requires that they do, so a filter added to one by mistake fails here.
 *  - [MediaSweepQueries] **sweeps** — the maintenance passes' own selects, which name exactly the expired rows: something in the
 *    world that holds them, nothing after the sweep, and every expired row of the fixture.
 *
 * **The static half** is [DmExpiredRowLint]'s scan with [expiringTables]: every literal in the Android production sources that
 * reads one of the five tables must be registered (verbatim, so the string the DAO runs is the string the lint runs) and every
 * registered query must still exist. The registry's SQL is **copied** from the three DAOs into [MediaQueryTexts], and the arming
 * test proves the copy against the source in both directions. The DM lint reads `dm_message` too, and the media queries join it
 * to apply the message's filter, so [DmExpiredRowLintTest] counts the registered media queries that name `dm_message` as
 * registered.
 */
object MediaExpiredRowLint {

    /** Table -> what makes a row of it expired (see the class comment). */
    val expiringTables: Map<String, String> = mapOf(
        "media_object" to "its message's delete_at_minute; incomplete_after_hour while awaiting or fetching; the upload's deadline_hour while uploading",
        "media_upload" to "its object's message (through the object); deadline_hour",
        "media_fragment" to "its object's message (through the object); incomplete_after_hour of an unfinished download",
        "media_outbound_op" to "its object's message (through the fragment)",
        "media_blob" to "retain_until_day while pooled; the message of the objects that name it",
    )

    /** The `now_e` of the fixture world, in seconds: on a minute and on an hour boundary. */
    const val NOW: Long = 1_800_000_000L

    /** The day of the fixture world: what a `retain_until_day` filter is given (`day(NOW)`). */
    const val TODAY: Long = NOW / 86_400L

    fun id(n: Int): ByteArray = mBytes(16, n)
    fun hash(n: Int): ByteArray = mBytes(32, n)

    val NS: ByteArray = MediaFixture.NS

    /** What a query is judged by. */
    enum class Mode { READ, HIDES, BOUND, SWEEP }

    class Query(
        val name: String,
        val sql: String,
        val args: List<Any?>,
        val mode: Mode = Mode.READ,
        /** READ and SWEEP: the rows the query answers in the swept world (READ) or names in the unswept one (SWEEP). */
        val rows: Int? = null,
        /** HIDES: a statement that counts the expired row the key names, to prove the unswept world holds it. */
        val proof: Pair<String, List<Any?>>? = null,
    ) {
        override fun toString(): String = name
    }

    data class Outcome(val beforeTheSweep: List<String>, val afterTheSweep: List<String>) {
        /** The two worlds are distinguishable: an expired row changed what the query answers (ME-16). */
        val showsAnExpiredRow: Boolean get() = beforeTheSweep != afterTheSweep
        val returnsNothing: Boolean get() = afterTheSweep.isEmpty()
    }

    fun outcomeOf(sql: String, args: List<Any?>): Outcome =
        Outcome(rowsOf(sql, args, withExpired = true), rowsOf(sql, args, withExpired = false))

    fun showsAnExpiredRow(sql: String, args: List<Any?>): Boolean = outcomeOf(sql, args).showsAnExpiredRow

    private fun rowsOf(sql: String, args: List<Any?>, withExpired: Boolean): List<String> =
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seed(db, withExpired)
            val out = ArrayList<String>()
            db.query(sql, args) { out += render(it) }
            out.sorted()
        }

    /** The value of a statement that counts, in the chosen world: the proof that an expired row is there (or is not). */
    fun countIn(sql: String, args: List<Any?>, withExpired: Boolean): Long =
        JdbcSqlExecutor().use { db ->
            MigrationRunner(db).migrate()
            seed(db, withExpired)
            db.queryLong(sql, args) ?: 0L
        }

    private const val MAX_COLUMNS = 64

    private fun render(row: SqlExecutor.Row): String {
        val cells = ArrayList<String>()
        for (index in 0 until MAX_COLUMNS) {
            val cell: String
            try {
                cell = if (row.isNull(index)) "null" else row.blob(index).joinToString("") { "%02x".format(it) }
            } catch (e: Exception) {
                break
            }
            cells += cell
        }
        return cells.joinToString("|")
    }

    // ---- the fixture world: ids

    val O1 = id(0xA1) // live, uploading, deadline ahead
    val O2 = id(0xA2) // live, uploading, deadline passed (reads as failed)
    val O3 = id(0xA3) // uploaded, no message
    val O4 = id(0xA4) // DEAD: its message expired at NOW
    val O5 = id(0xA5) // DEAD: failed, its message expired
    val O6 = id(0xA6) // live, uploading, deadline exactly NOW (reads as failed)
    val I1 = id(0xB1) // live, fetching, hour ahead
    val I2 = id(0xB2) // live, awaiting, hour exactly NOW (declared incomplete)
    val I3 = id(0xB3) // live, fetching, hour passed (declared incomplete)
    val I4 = id(0xB4) // live, complete (its hour is past but it is complete)
    val I5 = id(0xB5) // live, verified
    val I6 = id(0xB6) // live, viewing (view-once)
    val I7 = id(0xB7) // DEAD: fetching, its message expired

    val M_E1 = id(0x91) // expires exactly at NOW (a read at NOW no longer shows it)
    val M_E2 = id(0x92)
    val M_E3 = id(0x93)

    fun message(n: Int): ByteArray = id(0x80 + n)

    /**
     * The fixture world. Per kind of row, rows that are expired (the boundary one, which a `>=` for `>` admits, and older ones),
     * live (the boundary a `>` for `>=` hides, a far one, one with no deadline).
     *
     * | row | unswept world | swept world (what the maintenance leaves) |
     * |---|---|---|
     * | O1, O3 live; I1, I4, I5, I6 live | as written | the same |
     * | **O4, O5, I7** (messages expired at `NOW`, `NOW − 60`, `NOW − 120`) and the blobs only they name | present | **gone** (the foreign keys cascade, the unnamed blobs are erased) |
     * | **O2** (deadline `NOW − 3 600`), **O6** (deadline exactly `NOW`), `uploading` | `uploading` | `failed` (`MEDIA-DEADLINE`) |
     * | **I2** (awaiting, hour exactly `NOW`), **I3** (fetching, hour `NOW − 3 600`), with key and fragments | `awaiting` / `fetching`, key, fragments | `incomplete`, no key, no fragments; I3's ingested blob is now pooled |
     * | pooled blobs past their day (**PX1** `TODAY − 1`, **PX2** `TODAY − 5`) | present | gone (collected) |
     * | blobs past their day that a live object names (**0x41**, **0x42**, I4's) | present | present (named, so not pooled) |
     * | pooled blobs within their day (**P1** `TODAY`, the boundary, **P2** `TODAY + 3`) | present | present |
     */
    fun seed(db: JdbcSqlExecutor, withExpired: Boolean) {
        val f = MediaFixture(db)
        f.ensureNamespace(NS)
        f.dmConversation()

        fun insertMessage(messageId: ByteArray, deleteAt: Long?) {
            db.exec(
                "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                    "body_env, state, expire_at_minute, delete_at_minute) VALUES (?, ?, 'out', 5, 600, 600, 0, ?, ?, 'queued', ?, ?)",
                listOf(messageId, mBytes(16, 0xC0), if (deleteAt == null) 0L else 4L, mBytes(60, 0x73), deleteAt, deleteAt),
            )
        }

        fun blob(n: Int, origin: String, retain: Long?) {
            db.exec(
                "INSERT INTO media_blob(blob_hash, file_name, origin, retain_until_day) VALUES (?, ?, ?, ?)",
                listOf(hash(n), mBytes(16, n), origin, retain),
            )
        }

        fun obj(
            objectId: ByteArray,
            role: String,
            state: String,
            message: ByteArray?,
            hour: Long? = null,
            key: Boolean = true,
            viewOnce: Boolean = false,
        ) {
            db.exec(
                "INSERT INTO media_object(object_id, role, dest_id, kind, view_once, class_code, manifest_hash, key_env, state, message_id, " +
                    "decode_failures, incomplete_after_hour) VALUES (?, ?, ?, 2, ?, 0, ?, ?, ?, ?, 0, ?)",
                listOf(objectId, role, MediaFixture.DEST, if (viewOnce) 1L else 0L, hash(objectId[0].toInt() and 0xFF), if (key) mBytes(60, objectId[0].toInt()) else null, state, message, hour),
            )
        }

        fun upload(objectId: ByteArray, deadline: Long, ttl: Long = 604_800L) {
            db.exec("INSERT INTO media_upload(object_id, namespace_id, ttl_seconds, deadline_hour, retry_gen) VALUES (?, ?, ?, ?, 0)", listOf(objectId, NS, ttl, deadline))
        }

        /** An outgoing fragment, walked along the legal path to [upload] (an insert starts bound and unsent). */
        fun outFragment(objectId: ByteArray, ordinal: Int, blobN: Int, upload: String) {
            db.exec(
                "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) VALUES (?, ?, ?, 'bound', 'unsent')",
                listOf(objectId, ordinal.toLong(), hash(blobN)),
            )
            for (step in when (upload) { "unsent" -> emptyList(); "open" -> listOf("open"); else -> listOf("open", upload) }) {
                db.exec("UPDATE media_fragment SET upload_state = ? WHERE object_id = ? AND ordinal = ?", listOf(step, objectId, ordinal.toLong()))
            }
        }

        fun inFragment(objectId: ByteArray, ordinal: Int, blobN: Int, state: String) {
            db.exec(
                "INSERT INTO media_fragment(object_id, ordinal, blob_hash, state, upload_state) VALUES (?, ?, ?, ?, NULL)",
                listOf(objectId, ordinal.toLong(), hash(blobN), state),
            )
        }

        fun op(opN: Int, objectId: ByteArray, ordinal: Int) {
            db.exec(
                "INSERT INTO media_outbound_op(operation_id, object_id, ordinal, retry_gen, resend_count) VALUES (?, ?, ?, 0, 0)",
                listOf(id(opN), objectId, ordinal.toLong()),
            )
        }

        // ---- messages: live ones, and the expired ones (boundary, a minute, two minutes)
        insertMessage(message(1), NOW + 60) // O1
        insertMessage(message(2), null) // O2
        insertMessage(message(6), null) // O6
        insertMessage(message(3), NOW + 120) // I1
        insertMessage(message(4), null) // I2
        insertMessage(message(5), NOW + 180) // I3
        insertMessage(message(7), null) // I4
        insertMessage(message(8), null) // I5
        insertMessage(message(9), null) // I6
        if (withExpired) {
            insertMessage(M_E1, NOW)
            insertMessage(M_E2, NOW - 60)
            insertMessage(M_E3, NOW - 120)
        }

        // ---- blobs
        for (n in 1..6) blob(n, "sealed", null) // O1 (1..3), O2 (4), O6 (5), O3 (6)
        for (n in listOf(0x21, 0x22, 0x51, 0x61)) blob(n, "ingested", TODAY + 3) // named by live downloads
        // named by the live, complete I4 although its last day has passed: a pooled blob past its day is collected, a named one is not
        for (n in listOf(0x41, 0x42)) blob(n, "ingested", TODAY - 3)
        blob(0x31, "ingested", TODAY + 2) // I3's: named while unswept, pooled once I3 is declared incomplete
        blob(0x91, "ingested", TODAY) // pooled, on its last day
        blob(0x92, "ingested", TODAY + 3) // pooled
        if (withExpired) {
            for (n in 0x11..0x14) blob(n, "sealed", null) // named only by the dead O4 and O5
            blob(0x93, "ingested", TODAY - 1) // pooled, past its day
            blob(0x94, "ingested", TODAY - 5)
        }

        // ---- outgoing, live
        obj(O1, "out", "uploading", message(1))
        upload(O1, NOW + 3_600L)
        outFragment(O1, -1, 1, "open")
        outFragment(O1, 0, 2, "sent")
        outFragment(O1, 1, 3, "unsent")
        op(0x21, O1, -1)
        op(0x22, O1, 0)
        obj(O2, "out", if (withExpired) "uploading" else "failed", message(2))
        upload(O2, NOW - 3_600L)
        outFragment(O2, 0, 4, "unsent")
        obj(O6, "out", if (withExpired) "uploading" else "failed", message(6))
        upload(O6, NOW)
        outFragment(O6, 0, 5, "unsent")
        obj(O3, "out", "uploaded", null)
        upload(O3, NOW + 7_200L, ttl = 86_400L)
        outFragment(O3, 0, 6, "sent")

        // ---- incoming, live
        obj(I1, "in", "fetching", message(3), hour = NOW + 7_200L)
        inFragment(I1, -1, 0x21, "bound")
        inFragment(I1, 0, 0x22, "bound")
        inFragment(I1, 1, 0x23, "expected")
        if (withExpired) {
            obj(I2, "in", "awaiting", message(4), hour = NOW)
            obj(I3, "in", "fetching", message(5), hour = NOW - 3_600L)
            inFragment(I3, -1, 0x31, "bound")
            inFragment(I3, 0, 0x32, "expected")
        } else {
            obj(I2, "in", "incomplete", message(4), hour = NOW, key = false)
            obj(I3, "in", "incomplete", message(5), hour = NOW - 3_600L, key = false)
        }
        obj(I4, "in", "complete", message(7), hour = NOW - 7_200L)
        inFragment(I4, -1, 0x41, "bound")
        inFragment(I4, 0, 0x42, "bound")
        obj(I5, "in", "verified", message(8), hour = NOW + 3_600L)
        inFragment(I5, -1, 0x51, "bound")
        obj(I6, "in", "viewing", message(9), hour = NOW + 3_600L, key = false, viewOnce = true)
        inFragment(I6, -1, 0x61, "bound")

        // ---- the dead: their rows go with their messages, the unnamed blobs with them
        if (withExpired) {
            obj(O4, "out", "uploading", M_E1)
            upload(O4, NOW + 7_200L)
            outFragment(O4, -1, 0x11, "open")
            outFragment(O4, 0, 0x12, "unsent")
            op(0x31, O4, -1)
            obj(O5, "out", "failed", M_E2)
            upload(O5, NOW + 3_600L, ttl = 3_600L)
            outFragment(O5, 0, 0x13, "sent")
            outFragment(O5, 1, 0x14, "failed")
            obj(I7, "in", "fetching", M_E3, hour = NOW + 3_600L)
            inFragment(I7, -1, 0x71, "expected")
            inFragment(I7, 0, 0x21, "bound") // names a blob a live object names too (D25): it stays when I7 goes
        }
    }

    // ------------------------------------------------------------------ the static half

    data class Found(val file: File, val line: Int, val sql: String) {
        override fun toString(): String {
            val path = file.invariantSeparatorsPath
            val marker = path.indexOf("/src/main/")
            val shown = if (marker < 0) path else path.substring(path.lastIndexOf('/', marker - 1) + 1)
            return "$shown:$line: ${sql.take(160)}"
        }
    }

    /** Every read of one of the five tables in [sources]: [DmExpiredRowLint]'s scan with the media set. */
    fun readQueriesOverExpiringRows(sources: List<File>): List<Found> =
        DmExpiredRowLint.readQueriesOverExpiringRows(sources, expiringTables.keys).map { Found(it.file, it.line, it.sql) }

    /** Every registered query of the three registries. */
    fun allRegistered(): List<Query> = MediaDaoQueries.registered + MediaBoundQueries.registered + MediaSweepQueries.registered
}

/**
 * The SQL of the media DAOs, **copied verbatim** from `MediaObjects`, `MediaFragments` and `MediaBlobs` (the constants of their
 * companion objects, with the DAO's name as a prefix). `MediaExpiredRowLintTest.everyProductionReadOfAnExpiringMediaTableIsRegistered`
 * proves the copy against the sources in both directions: a DAO query that is edited, added or removed without its entry here
 * fails that test with the file and line.
 */
internal object MediaQueryTexts {
    const val OBJECTS_BY_ID =
        "SELECT o.object_id, o.role, o.dest_id, o.kind, o.view_once, o.class_code, o.manifest_hash, " +
        "CASE WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN NULL ELSE o.key_env END, " +
        "CASE WHEN o.state = 'uploading' AND u.deadline_hour <= ? THEN 'failed' " +
        "WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN 'incomplete' ELSE o.state END, " +
        "o.message_id, o.decode_failures, o.incomplete_after_hour " +
        "FROM media_object o LEFT JOIN media_upload u ON u.object_id = o.object_id " +
        "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

    const val OBJECTS_BY_MESSAGE =
        "SELECT o.object_id, o.role, o.dest_id, o.kind, o.view_once, o.class_code, o.manifest_hash, " +
        "CASE WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN NULL ELSE o.key_env END, " +
        "CASE WHEN o.state = 'uploading' AND u.deadline_hour <= ? THEN 'failed' " +
        "WHEN o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? THEN 'incomplete' ELSE o.state END, " +
        "o.message_id, o.decode_failures, o.incomplete_after_hour " +
        "FROM media_object o LEFT JOIN media_upload u ON u.object_id = o.object_id " +
        "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.message_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

    const val OBJECTS_UPLOAD_OF =
        "SELECT u.object_id, u.namespace_id, u.ttl_seconds, u.deadline_hour, u.retry_gen FROM media_upload u " +
        "JOIN media_object o ON o.object_id = u.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE u.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

    const val OBJECTS_ACTIVE_UPLOADS =
        "SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id " +
        "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state = 'uploading' AND u.deadline_hour > ? " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY u.deadline_hour, o.object_id LIMIT ?"

    const val OBJECTS_PENDING_DOWNLOADS =
        "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour > ? " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY o.incomplete_after_hour, o.object_id LIMIT ?"

    const val OBJECTS_TO_VERIFY =
        "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state = 'complete' AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY o.object_id LIMIT ?"

    const val OBJECTS_VIEWING =
        "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state = 'viewing' AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY o.object_id LIMIT ?"

    const val OBJECTS_EXISTS =
        "SELECT count(*) FROM media_object WHERE object_id = ?"

    const val OBJECTS_EXISTS_FOR_MESSAGE =
        "SELECT count(*) FROM media_object WHERE message_id = ?"

    const val OBJECTS_OBJECTS_OF_MESSAGE =
        "SELECT object_id FROM media_object WHERE message_id = ? ORDER BY object_id"

    const val OBJECTS_RAW_STATE =
        "SELECT state FROM media_object WHERE object_id = ?"

    const val OBJECTS_DECODE_FAILURES_OF =
        "SELECT decode_failures FROM media_object WHERE object_id = ?"

    const val OBJECTS_INCOMPLETE_DUE =
        "SELECT o.object_id FROM media_object o LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ? " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY o.incomplete_after_hour, o.object_id LIMIT ?"

    const val OBJECTS_PAST_DEADLINE =
        "SELECT o.object_id FROM media_object o JOIN media_upload u ON u.object_id = o.object_id " +
        "LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE o.state = 'uploading' AND u.deadline_hour <= ? " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "ORDER BY u.deadline_hour, o.object_id LIMIT ?"

    const val FRAGMENTS_FRAGMENTS_OF =
        "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
        "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE f.object_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?) ORDER BY f.ordinal"

    const val FRAGMENTS_FRAGMENT =
        "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
        "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE f.object_id = ? AND f.ordinal = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?)"

    const val FRAGMENTS_UNSENT =
        "SELECT f.ordinal, f.blob_hash, f.state, f.upload_state FROM media_fragment f " +
        "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE f.object_id = ? AND f.upload_state = 'unsent' " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) ORDER BY f.ordinal LIMIT ?"

    const val FRAGMENTS_OP_BY_ID =
        "SELECT p.object_id, p.ordinal, p.retry_gen, p.resend_count FROM media_outbound_op p " +
        "JOIN media_object o ON o.object_id = p.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE p.operation_id = ? AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?)"

    const val FRAGMENTS_OPEN_OF_OBJECT =
        "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state = 'open'"

    const val FRAGMENTS_OPEN_OF_DEVICE =
        "SELECT count(*) FROM media_fragment WHERE upload_state = 'open'"

    const val FRAGMENTS_EXPECTED_OF_OBJECT =
        "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'expected'"

    const val FRAGMENTS_BOUND_OF_OBJECT =
        "SELECT count(*) FROM media_fragment WHERE object_id = ? AND state = 'bound'"

    const val FRAGMENTS_OBJECTS_NAMING =
        "SELECT DISTINCT object_id FROM media_fragment WHERE blob_hash = ? ORDER BY object_id"

    const val FRAGMENTS_OBJECTS_EXPECTING =
        "SELECT DISTINCT object_id FROM media_fragment WHERE blob_hash = ? AND state = 'expected' ORDER BY object_id"

    const val FRAGMENTS_UPLOAD_STATE_OF =
        "SELECT upload_state FROM media_fragment WHERE object_id = ? AND ordinal = ?"

    const val FRAGMENTS_ROWS_OF_OBJECT =
        "SELECT count(*) FROM media_fragment WHERE object_id = ?"

    const val FRAGMENTS_HASHES_OF_OBJECT =
        "SELECT DISTINCT blob_hash FROM media_fragment WHERE object_id = ?"

    const val FRAGMENTS_ACKNOWLEDGED_OF_OBJECT =
        "SELECT count(*) FROM media_fragment WHERE object_id = ? AND upload_state IN ('sent', 'degraded', 'indeterminate')"

    const val BLOBS_BY_HASH =
        "SELECT blob_hash, file_name, origin, retain_until_day FROM media_blob WHERE blob_hash = ?"

    const val BLOBS_EXISTS =
        "SELECT count(*) FROM media_blob WHERE blob_hash = ?"

    const val BLOBS_FILE_NAMES =
        "SELECT blob_hash, file_name FROM media_blob ORDER BY blob_hash"

    const val BLOBS_IS_NAMED =
        "SELECT count(*) FROM media_fragment WHERE blob_hash = ?"

    const val BLOBS_POOLED_COUNT =
        "SELECT count(*) FROM media_blob b WHERE b.origin = 'ingested' " +
        "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash)"

    const val BLOBS_EVICTION_ORDER =
        "SELECT b.blob_hash, b.file_name, b.origin, b.retain_until_day FROM media_blob b WHERE b.origin = 'ingested' " +
        "AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash) " +
        "ORDER BY b.retain_until_day, b.blob_hash LIMIT ?"

    const val BLOBS_EXPIRED_POOLED =
        "SELECT b.blob_hash, b.file_name, b.origin, b.retain_until_day FROM media_blob b WHERE b.origin = 'ingested' " +
        "AND b.retain_until_day < ? AND NOT EXISTS (SELECT 1 FROM media_fragment f WHERE f.blob_hash = b.blob_hash) " +
        "ORDER BY b.retain_until_day, b.blob_hash LIMIT ?"

    const val BLOBS_FILES_OF =
        "SELECT f.ordinal, b.file_name FROM media_fragment f JOIN media_blob b ON b.blob_hash = f.blob_hash " +
        "JOIN media_object o ON o.object_id = f.object_id LEFT JOIN dm_message m ON m.message_id = o.message_id " +
        "WHERE f.object_id = ? AND f.state = 'bound' " +
        "AND (m.message_id IS NULL OR m.delete_at_minute IS NULL OR m.delete_at_minute > ?) " +
        "AND NOT (o.state IN ('awaiting', 'fetching') AND o.incomplete_after_hour <= ?) ORDER BY f.ordinal"
}

/**
 * Every read of an expiring media table by a DAO, with the arguments the lint binds. Each entry is the query **verbatim**; the
 * arguments are chosen so that the query answers the live rows of the fixture world and, wherever the fixture allows it, so that
 * the unswept world differs if the filter were missing.
 */
object MediaDaoQueries {
    private val L = MediaExpiredRowLint
    private const val NOW = MediaExpiredRowLint.NOW
    private const val LIMIT = 50L

    private fun read(name: String, sql: String, args: List<Any?>, rows: Int) = MediaExpiredRowLint.Query(name, sql, args, rows = rows)

    private fun hides(name: String, sql: String, args: List<Any?>, table: String, where: String, proofArgs: List<Any?>) =
        MediaExpiredRowLint.Query(
            name, sql, args, MediaExpiredRowLint.Mode.HIDES,
            proof = "SELECT count(*) FROM $table WHERE $where" to proofArgs,
        )

    private fun byId(id: ByteArray) = listOf<Any?>(NOW, NOW, NOW, id, NOW)

    val registered: List<MediaExpiredRowLint.Query> = listOf(
        // ---- MediaObjects: one object
        read("aLiveUploadById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O1), rows = 1),
        read("aLiveFetchingDownloadById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I1), rows = 1),
        read("aCompleteDownloadById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I4), rows = 1),
        read("aVerifiedDownloadById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I5), rows = 1),
        read("aViewingObjectById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I6), rows = 1),
        read("anUploadedObjectWithNoMessageById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O3), rows = 1),
        // the two deadlines of the object itself: read as the maintenance that has not run yet would leave them
        read("anUploadPastItsDeadlineReadsAsFailed", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O2), rows = 1),
        read("anUploadOnTheHourOfItsDeadlineReadsAsFailed", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O6), rows = 1),
        read("aDownloadOnTheHourOfItsDeadlineReadsAsIncomplete", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I2), rows = 1),
        read("aDownloadPastItsDeadlineReadsAsIncompleteWithNoKey", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I3), rows = 1),
        hides("anObjectOfAnExpiredMessageById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O4), "media_object", "object_id = ?", listOf(L.O4)),
        hides("anObjectWhoseMessageExpiredAMinuteAgoById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.O5), "media_object", "object_id = ?", listOf(L.O5)),
        hides("aDownloadOfAnExpiredMessageById", MediaQueryTexts.OBJECTS_BY_ID, byId(L.I7), "media_object", "object_id = ?", listOf(L.I7)),
        // ---- by message
        read("theObjectOfALiveMessage", MediaQueryTexts.OBJECTS_BY_MESSAGE, listOf(NOW, NOW, NOW, L.message(3), NOW), rows = 1),
        read("theObjectOfAMessageWithNoTimer", MediaQueryTexts.OBJECTS_BY_MESSAGE, listOf(NOW, NOW, NOW, L.message(2), NOW), rows = 1),
        hides("theObjectOfAMessageThatExpiresNow", MediaQueryTexts.OBJECTS_BY_MESSAGE, listOf(NOW, NOW, NOW, L.M_E1, NOW), "media_object", "message_id = ?", listOf(L.M_E1)),
        hides("theObjectOfAMessageThatExpiredLongAgo", MediaQueryTexts.OBJECTS_BY_MESSAGE, listOf(NOW, NOW, NOW, L.M_E3, NOW), "media_object", "message_id = ?", listOf(L.M_E3)),
        // ---- the upload row
        read("theUploadOfALiveObject", MediaQueryTexts.OBJECTS_UPLOAD_OF, listOf(L.O1, NOW), rows = 1),
        read("theUploadOfAnObjectWithNoMessage", MediaQueryTexts.OBJECTS_UPLOAD_OF, listOf(L.O3, NOW), rows = 1),
        hides("theUploadOfAnExpiredObject", MediaQueryTexts.OBJECTS_UPLOAD_OF, listOf(L.O4, NOW), "media_upload", "object_id = ?", listOf(L.O4)),
        // ---- the worklists
        read("theActiveUploads", MediaQueryTexts.OBJECTS_ACTIVE_UPLOADS, listOf(NOW, NOW, LIMIT), rows = 1),
        read("thePendingDownloads", MediaQueryTexts.OBJECTS_PENDING_DOWNLOADS, listOf(NOW, NOW, LIMIT), rows = 1),
        read("theDownloadsToVerify", MediaQueryTexts.OBJECTS_TO_VERIFY, listOf(NOW, LIMIT), rows = 1),
        read("theViewOnceObjectsLeftViewing", MediaQueryTexts.OBJECTS_VIEWING, listOf(NOW, LIMIT), rows = 1),
        // ---- MediaFragments
        read("theFragmentsOfALiveUpload", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.O1, NOW, NOW), rows = 3),
        read("theFragmentsOfALiveDownload", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.I1, NOW, NOW), rows = 3),
        read("theFragmentsOfAnUploadWithNoMessage", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.O3, NOW, NOW), rows = 1),
        hides("theFragmentsOfAnExpiredObject", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.O4, NOW, NOW), "media_fragment", "object_id = ?", listOf(L.O4)),
        hides("theFragmentsOfADownloadDeclaredIncomplete", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.I3, NOW, NOW), "media_fragment", "object_id = ?", listOf(L.I3)),
        hides("theFragmentsOfADownloadOfAnExpiredMessage", MediaQueryTexts.FRAGMENTS_FRAGMENTS_OF, listOf(L.I7, NOW, NOW), "media_fragment", "object_id = ?", listOf(L.I7)),
        read("oneFragmentOfALiveObject", MediaQueryTexts.FRAGMENTS_FRAGMENT, listOf(L.O1, 0L, NOW, NOW), rows = 1),
        hides("oneFragmentOfAnExpiredObject", MediaQueryTexts.FRAGMENTS_FRAGMENT, listOf(L.O4, -1L, NOW, NOW), "media_fragment", "object_id = ? AND ordinal = -1", listOf(L.O4)),
        hides("oneFragmentOfADeclaredIncompleteDownload", MediaQueryTexts.FRAGMENTS_FRAGMENT, listOf(L.I3, -1L, NOW, NOW), "media_fragment", "object_id = ? AND ordinal = -1", listOf(L.I3)),
        read("theUnsentFragmentsOfALiveUpload", MediaQueryTexts.FRAGMENTS_UNSENT, listOf(L.O1, NOW, LIMIT), rows = 1),
        hides("theUnsentFragmentsOfAnExpiredUpload", MediaQueryTexts.FRAGMENTS_UNSENT, listOf(L.O4, NOW, LIMIT), "media_fragment", "object_id = ? AND upload_state = 'unsent'", listOf(L.O4)),
        read("theOperationOfALiveUpload", MediaQueryTexts.FRAGMENTS_OP_BY_ID, listOf(L.id(0x21), NOW), rows = 1),
        hides("theOperationOfAnExpiredUpload", MediaQueryTexts.FRAGMENTS_OP_BY_ID, listOf(L.id(0x31), NOW), "media_outbound_op", "operation_id = ?", listOf(L.id(0x31))),
        // ---- MediaBlobs: the files of a live object
        read("theFilesOfALiveUpload", MediaQueryTexts.BLOBS_FILES_OF, listOf(L.O1, NOW, NOW), rows = 3),
        read("theBoundFilesOfALiveDownload", MediaQueryTexts.BLOBS_FILES_OF, listOf(L.I1, NOW, NOW), rows = 2),
        hides("theFilesOfAnExpiredUpload", MediaQueryTexts.BLOBS_FILES_OF, listOf(L.O4, NOW, NOW), "media_fragment", "object_id = ?", listOf(L.O4)),
        hides("theFilesOfADeclaredIncompleteDownload", MediaQueryTexts.BLOBS_FILES_OF, listOf(L.I3, NOW, NOW), "media_fragment", "object_id = ? AND state = 'bound'", listOf(L.I3)),
    )
}

/**
 * The lookups, counts and orderings that must **see the expired rows**: the trigger `media_blob_referenced` and the reconcile
 * count every row, the feeder's open ordinals are operations in flight whether or not the message has expired, and a descriptor's
 * duplicate check must find the object whatever its age. Judged by the opposite contract of a read: the unswept world must answer
 * differently from the swept one.
 */
object MediaBoundQueries {
    private val L = MediaExpiredRowLint

    private fun bound(name: String, sql: String, args: List<Any?>) = MediaExpiredRowLint.Query(name, sql, args, MediaExpiredRowLint.Mode.BOUND)

    val registered: List<MediaExpiredRowLint.Query> = listOf(
        bound("theBlobRowOfAPooledBlobPastItsDay", MediaQueryTexts.BLOBS_BY_HASH, listOf(L.hash(0x93))),
        bound("whetherAPooledBlobPastItsDayExists", MediaQueryTexts.BLOBS_EXISTS, listOf(L.hash(0x94))),
        bound("everyFileNameARowNames", MediaQueryTexts.BLOBS_FILE_NAMES, emptyList()),
        bound("whetherABlobOnlyADeadObjectNamesIsNamed", MediaQueryTexts.BLOBS_IS_NAMED, listOf(L.hash(0x11))),
        bound("thePooledBlobCount", MediaQueryTexts.BLOBS_POOLED_COUNT, emptyList()),
        bound("thePooledBlobsInEvictionOrder", MediaQueryTexts.BLOBS_EVICTION_ORDER, listOf(50L)),
        bound("theOpenOrdinalsOfAnObjectWhoseMessageExpired", MediaQueryTexts.FRAGMENTS_OPEN_OF_OBJECT, listOf(L.O4)),
        bound("theOpenOrdinalsOfTheDevice", MediaQueryTexts.FRAGMENTS_OPEN_OF_DEVICE, emptyList()),
        bound("theExpectedFragmentsOfADeadDownload", MediaQueryTexts.FRAGMENTS_EXPECTED_OF_OBJECT, listOf(L.I7)),
        bound("theBoundFragmentsOfADeclaredIncompleteDownload", MediaQueryTexts.FRAGMENTS_BOUND_OF_OBJECT, listOf(L.I3)),
        bound("theObjectsNamingABlobOnlyADeadObjectNames", MediaQueryTexts.FRAGMENTS_OBJECTS_NAMING, listOf(L.hash(0x11))),
        bound("theObjectsExpectingABlobOnlyADeadObjectExpects", MediaQueryTexts.FRAGMENTS_OBJECTS_EXPECTING, listOf(L.hash(0x71))),
        bound("theUploadStateOfAnOrdinalOfADeadUpload", MediaQueryTexts.FRAGMENTS_UPLOAD_STATE_OF, listOf(L.O4, -1L)),
        bound("theRowsOfADeadObject", MediaQueryTexts.FRAGMENTS_ROWS_OF_OBJECT, listOf(L.O4)),
        bound("theHashesOfADeadObject", MediaQueryTexts.FRAGMENTS_HASHES_OF_OBJECT, listOf(L.O4)),
        bound("theAcknowledgedOrdinalsOfADeadUpload", MediaQueryTexts.FRAGMENTS_ACKNOWLEDGED_OF_OBJECT, listOf(L.O5)),
        bound("whetherADeadObjectExists", MediaQueryTexts.OBJECTS_EXISTS, listOf(L.O4)),
        bound("whetherAnObjectOfADeadMessageExists", MediaQueryTexts.OBJECTS_EXISTS_FOR_MESSAGE, listOf(L.M_E1)),
        bound("theObjectsOfADeadMessage", MediaQueryTexts.OBJECTS_OBJECTS_OF_MESSAGE, listOf(L.M_E1)),
        bound("theStoredStateOfAnUploadPastItsDeadline", MediaQueryTexts.OBJECTS_RAW_STATE, listOf(L.O2)),
        bound("theDecodeFailuresOfADeadDownload", MediaQueryTexts.OBJECTS_DECODE_FAILURES_OF, listOf(L.I7)),
    )
}

/**
 * The selects the maintenance passes run to find what they act on: they name **exactly the expired rows**. Judged by the
 * mirror of the read contract: something in the world that still holds them, nothing after the sweep, and — by [Query.rows] —
 * every expired row of the fixture.
 */
object MediaSweepQueries {
    private const val NOW = MediaExpiredRowLint.NOW
    private const val TODAY = MediaExpiredRowLint.TODAY
    private const val LIMIT = 50L

    private fun sweep(name: String, sql: String, args: List<Any?>, rows: Int) =
        MediaExpiredRowLint.Query(name, sql, args, MediaExpiredRowLint.Mode.SWEEP, rows = rows)

    val registered: List<MediaExpiredRowLint.Query> = listOf(
        // I2 (the hour is exactly now) and I3 (an hour ago); I7 is dead with its message and is not MEDIA-GC's to declare
        sweep("theDownloadsMediaGcDeclaresIncomplete", MediaQueryTexts.OBJECTS_INCOMPLETE_DUE, listOf(NOW, NOW, LIMIT), rows = 2),
        // O2 (an hour past) and O6 (exactly now); O4 is dead with its message
        sweep("theUploadsMediaDeadlineFails", MediaQueryTexts.OBJECTS_PAST_DEADLINE, listOf(NOW, NOW, LIMIT), rows = 2),
        // PX1 (a day past) and PX2 (five days past); P1 is on its last day and stays
        sweep("thePooledBlobsMediaGcCollects", MediaQueryTexts.BLOBS_EXPIRED_POOLED, listOf(TODAY, LIMIT), rows = 2),
    )
}
