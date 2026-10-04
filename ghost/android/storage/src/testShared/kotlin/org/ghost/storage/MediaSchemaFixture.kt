package org.ghost.storage

/**
 * The names and the row builders of the media schema (Phase 11 design §13.6 "Schema migration M"; slice S3), shared by
 * the test source sets of every module that opens a migrated database (`src/testShared`).
 *
 * **The lists are a second source of truth on purpose**, as [ChannelSchema]'s are: [Schema.expectedTables] and
 * [Schema.expectedTriggers] are what the production code asserts; the sets below are written out again from the
 * design, so a table, a trigger, an index or a time column that migration 8 gains or loses without the design saying
 * so fails a test instead of passing because both sides moved together.
 */
internal object MediaSchema {

    /** The two v1 tables migration 8 drops behind its guard (§13.6 step 1). */
    val v1Tables: Set<String> = setOf("media", "media_blobs")

    /** The five tables of §13.6 step 4. */
    val tables: Set<String> = setOf("media_object", "media_upload", "media_blob", "media_fragment", "media_outbound_op")

    /**
     * The five DM tables migration 8 rebuilds: the two of §13.6 steps 2 and 3, and the three that cascade from them,
     * which cannot be left to the `DROP TABLE` of their parent (finding of §22.4).
     */
    val rebuilt: Set<String> = setOf("dm_message", "dm_outbound_item", "dm_outbound_op", "dm_pending_send", "dm_reaction")

    /** The 14 state-machine, write-once and consistency triggers (`media_fragment_bound_blob` is a pair). */
    val rules: Set<String> = setOf(
        "media_object_fixed", "media_object_key", "media_object_state", "media_object_monotonic",
        "media_fragment_state", "media_fragment_role", "media_fragment_bound_blob_insert", "media_fragment_bound_blob_update",
        "media_upload_role", "media_upload_fixed", "media_upload_monotonic", "media_outbound_op_fixed",
        "media_blob_referenced", "media_blob_fixed",
    )

    /** The five REPLACE guards: every table. */
    val guards: Set<String> = setOf(
        "media_object_no_replace", "media_upload_no_replace", "media_blob_no_replace", "media_fragment_no_replace",
        "media_outbound_op_no_replace",
    )

    /** The indexes of §13.6 step 4, by name (the automatic index of the `UNIQUE` of `media_outbound_op` aside). */
    val indexes: Set<String> = setOf(
        "idx_media_object_message", "idx_media_blob_file", "idx_media_blob_retention", "idx_media_fragment_hash",
        "idx_media_fragment_open",
    )

    /**
     * The tables that keep a hidden rowid, which records the order their rows arrived in (T33: "random WITHOUT ROWID
     * keys"): **none**. No table of this migration needs an insertion order (an object is named by 16 random bytes, a
     * blob by its hash, a fragment by (object, ordinal), an operation by its random id), so unlike v7 there is no
     * exception to declare, and no rowid guard, positivity or fixity trigger.
     */
    val rowidTables: Set<String> = emptySet()

    /** The tables that are `WITHOUT ROWID`: all five. */
    val withoutRowidTables: Set<String> = tables - rowidTables

    /**
     * Every time column of §13.6, as `table.column`: three, and the only ones: an hour, an hour and a day. The
     * introspection tests require the database to hold exactly these (a column that matches the time-like rule and is
     * not here fails, and so does one here that no table has), each with the granularity its suffix names.
     */
    val timeColumns: Set<String> = setOf(
        "media_object.incomplete_after_hour", "media_upload.deadline_hour", "media_blob.retain_until_day",
    )

    /** Names that contain a word of the time-like rule while the value is no time. */
    val notTimes: Map<String, String> = mapOf(
        "media_upload.ttl_seconds" to "the TTL bucket of the object in seconds, a duration (R-MT1)",
    )

    /**
     * Integer columns that are neither a time nor a bucket and carry `typeof` beside a range: the size class, the
     * decode-failure count, the retry generation, the resend count and the fragment ordinal. (`media_outbound_op.ordinal`
     * has none of its own: the foreign key to the fragment it names settles it.)
     */
    val counterColumns: Set<String> = setOf(
        "media_object.class_code", "media_object.decode_failures", "media_upload.retry_gen",
        "media_fragment.ordinal", "media_outbound_op.retry_gen", "media_outbound_op.resend_count",
    )

    /** The 0/1 flags: `CHECK (x IN (0, 1))`, which admits no fraction either. */
    val flagColumns: Set<String> = setOf("media_object.view_once")

    /** The integer columns that are a closed list of values: the kind (image, video) and the TTL buckets. */
    val enumColumns: Set<String> = setOf("media_object.kind", "media_upload.ttl_seconds")

    /**
     * What each table's columns are, in order, as `name` (NOT NULL) or `name?` (nullable): §13.6's table, and nothing
     * else. A column added to a media table — a `created_at`, a counter — fails the introspection test until it is
     * written here beside the rule that allows it.
     */
    val columns: Map<String, String> = mapOf(
        "media_object" to "object_id role dest_id kind view_once class_code manifest_hash key_env? state message_id? " +
            "decode_failures incomplete_after_hour?",
        "media_upload" to "object_id namespace_id ttl_seconds deadline_hour retry_gen",
        "media_blob" to "blob_hash file_name origin retain_until_day?",
        "media_fragment" to "object_id ordinal blob_hash state upload_state?",
        "media_outbound_op" to "operation_id object_id ordinal retry_gen resend_count",
    )

    /** The twelve object states of §7.6, by role. */
    val outStates: List<String> = listOf("uploading", "uploaded", "failed")
    val inStates: List<String> = listOf(
        "awaiting", "fetching", "complete", "verified", "corrupt", "incomplete", "undecodable", "viewing", "viewed",
    )

    /** The six upload states of a fragment of an outgoing object (§6.4). */
    val uploadStates: List<String> = listOf("unsent", "open", "sent", "degraded", "indeterminate", "failed")
}

internal fun mBytes(size: Int, fill: Int) = ByteArray(size) { fill.toByte() }

/**
 * A migrated database with row builders for the five media tables: [put] inserts a valid row built from the table's
 * defaults and the overrides, after the parent rows it needs. [sql] returns the statement, so a test can embed a
 * literal (`3.5`) in place of a bound value. The default object is an **outgoing** one (`uploading`, with a key and an
 * upload); [putIn] makes an incoming one.
 */
internal class MediaFixture(
    val db: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() },
) : AutoCloseable {

    companion object {
        /** The outgoing object every default row belongs to, and an incoming one. */
        val OUT: ByteArray = mBytes(16, 0xA1)
        val IN: ByteArray = mBytes(16, 0xB1)

        /** The namespace of the default upload (a media namespace `M_c`). */
        val NS: ByteArray = mBytes(32, 0x4D)

        /** The blob every default fragment names. */
        val BLOB: ByteArray = mBytes(32, 0xC1)
        val FILE: ByteArray = mBytes(16, 0xF1)

        /** The contact an object is for. */
        val DEST: ByteArray = mBytes(16, 0xD1)

        fun hash(n: Int): ByteArray = mBytes(32, n)
        fun id(n: Int): ByteArray = mBytes(16, n)

        private val defaults: Map<String, Map<String, Any?>> = mapOf(
            "media_object" to linkedMapOf(
                "object_id" to OUT, "role" to "out", "dest_id" to DEST, "kind" to 1L, "view_once" to 0L,
                "class_code" to 0L, "manifest_hash" to mBytes(32, 0xA2), "key_env" to mBytes(60, 0xA3), "state" to "uploading",
            ),
            "media_upload" to linkedMapOf(
                "object_id" to OUT, "namespace_id" to NS, "ttl_seconds" to 604_800L, "deadline_hour" to 3_600_000L,
            ),
            "media_blob" to linkedMapOf(
                "blob_hash" to BLOB, "file_name" to FILE, "origin" to "sealed",
            ),
            "media_fragment" to linkedMapOf(
                "object_id" to OUT, "ordinal" to 0L, "blob_hash" to BLOB, "state" to "bound", "upload_state" to "unsent",
            ),
            "media_outbound_op" to linkedMapOf(
                "operation_id" to mBytes(16, 0xE1), "object_id" to OUT, "ordinal" to 0L, "retry_gen" to 0L, "resend_count" to 0L,
            ),
        )

        init {
            check(defaults.keys == MediaSchema.tables) { "a table without defaults: ${MediaSchema.tables - defaults.keys}" }
        }

        /** The default row of [table] (a copy), with its columns in the order of the insert. */
        fun defaultsOf(table: String): LinkedHashMap<String, Any?> = LinkedHashMap(defaults.getValue(table))

        /** The overrides that turn the default object into an incoming one in state [state]. */
        fun incoming(state: String = "awaiting", hour: Long = 3_600_000L): Array<Pair<String, Any?>> = arrayOf(
            "object_id" to IN, "role" to "in", "state" to state, "incomplete_after_hour" to hour,
        )
    }

    /**
     * The statement and the arguments that insert the default row of [table] with [overrides] applied. A column in
     * [literals] is written as that SQL text instead of a bound value, which is how a REAL reaches an INTEGER column,
     * since the executor binds no REAL.
     */
    fun sql(
        table: String,
        overrides: Map<String, Any?> = emptyMap(),
        literals: Map<String, String> = emptyMap(),
        verb: String = "INSERT",
    ): Pair<String, List<Any?>> {
        val row = defaultsOf(table)
        for ((k, v) in overrides) row[k] = v
        for (k in literals.keys) row.putIfAbsent(k, null)
        val columns = row.keys.toList()
        val args = ArrayList<Any?>()
        val marks = columns.map { c ->
            val literal = literals[c]
            if (literal != null) literal else { args += row[c]; "?" }
        }
        return "$verb INTO $table(${columns.joinToString(", ")}) VALUES (${marks.joinToString(", ")})" to args
    }

    /** Inserts a valid row of [table], after the parents it needs. */
    fun put(table: String, vararg overrides: Pair<String, Any?>) {
        val map = mapOf(*overrides)
        parents(table, map)
        val (sql, args) = sql(table, map)
        db.exec(sql, args)
    }

    /** Inserts an incoming object in [state] (and any override on top). */
    fun putIn(state: String = "awaiting", vararg overrides: Pair<String, Any?>) {
        put("media_object", *incoming(state), *overrides)
    }

    /** The parent rows of [table]: the namespace of an upload, the object and the blob of a fragment, the fragment of an op. */
    fun parents(table: String, row: Map<String, Any?> = emptyMap()) {
        val objectId = row["object_id"] ?: defaultsOf(table)["object_id"]
        when (table) {
            "media_upload" -> {
                ensureObject(objectId as ByteArray)
                ensureNamespace((row["namespace_id"] ?: NS) as ByteArray)
            }
            "media_fragment" -> {
                ensureObject(objectId as ByteArray)
                val hash = (row["blob_hash"] ?: BLOB) as ByteArray
                if ((row["state"] ?: "bound") == "bound") ensureBlob(hash)
            }
            "media_outbound_op" -> {
                ensureObject(objectId as ByteArray)
                val ordinal = (row["ordinal"] ?: 0L) as Long
                if (count("media_fragment", "object_id = ? AND ordinal = ?", objectId, ordinal) == 0L) {
                    ensureBlob(BLOB)
                    val (sql, args) = sql("media_fragment", mapOf("object_id" to objectId, "ordinal" to ordinal))
                    db.exec(sql, args)
                }
            }
        }
    }

    private fun ensureObject(objectId: ByteArray) {
        if (count("media_object", "object_id = ?", objectId) == 0L) {
            val overrides = if (objectId.contentEquals(IN)) incoming().toMap() else mapOf("object_id" to objectId)
            val (sql, args) = sql("media_object", overrides)
            db.exec(sql, args)
        }
    }

    fun ensureBlob(hash: ByteArray, file: ByteArray = FILE) {
        if (count("media_blob", "blob_hash = ?", hash) == 0L) {
            val name = if (hash.contentEquals(BLOB)) file else mBytes(16, hash[0].toInt() xor 0x5A)
            val (sql, args) = sql("media_blob", mapOf("blob_hash" to hash, "file_name" to name))
            db.exec(sql, args)
        }
    }

    fun ensureNamespace(namespaceId: ByteArray) {
        if (count("sync_namespace", "namespace_id = ?", namespaceId) == 0L) {
            db.exec("INSERT INTO sync_namespace(namespace_id, consumer, listening) VALUES (?, 'media', 1)", listOf(namespaceId))
        }
    }

    /** A DM contact, conversation and message (a media message, kind 5, with a caption) for the foreign key of `media_object.message_id`. */
    fun dmMessage(messageId: ByteArray, kind: Long = 5L, direction: String = "out", state: String = "queued", bodyEnvSize: Int = 60) {
        if (count("dm_contact", "contact_id = ?", DEST) == 0L) {
            db.exec(
                "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, trust_state, source, establishment) " +
                    "VALUES (?, ?, ?, 0, 'unverified', 'link', 'card_only')",
                listOf(DEST, mBytes(32, 0x71), mBytes(159, 0x72)),
            )
            db.exec("INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)", listOf(mBytes(16, 0xC0), DEST))
        }
        db.exec(
            "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, " +
                "body_env, state) VALUES (?, ?, ?, ?, 600, 600, 0, 0, ?, ?)",
            listOf(messageId, mBytes(16, 0xC0), direction, kind, mBytes(bodyEnvSize, 0x73), state),
        )
    }

    private fun count(table: String, where: String, vararg args: Any?): Long =
        db.queryLong("SELECT count(*) FROM $table WHERE $where", args.toList()) ?: 0L

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table")!!

    override fun close() = db.close()
}
