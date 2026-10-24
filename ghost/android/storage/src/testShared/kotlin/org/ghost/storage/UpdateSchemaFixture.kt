package org.ghost.storage

/**
 * The names and the row builders of the update schema (Phase 14 design §9.6 "Schema migration U"),
 * shared by the test source sets (`src/testShared`). A second source of truth on purpose, as
 * [ChannelSchema]'s and [MediaSchema]'s are: [Schema.expectedTables] and [Schema.expectedTriggers]
 * are what the production code asserts; the sets below are written out again from §9.6, so a
 * table, a trigger or a column that migration 11 gains or loses without the design saying so
 * fails a test instead of passing because both sides moved together.
 */
internal object UpdateSchema {

    /** The two tables of §9.6. */
    val tables: Set<String> = setOf("upd_state", "upd_staged")

    /** The four triggers of §9.6's note (write-once, epoch, append-only, no-DELETE, one staged row). */
    val rules: Set<String> = setOf(
        "upd_state_write_once", "upd_state_monotonic", "upd_state_no_delete", "upd_staged_one_row",
    )

    /** `upd_staged` is WITHOUT ROWID (named by the APK's SHA-256); the singleton `upd_state`
     * keeps its rowid on purpose — one row, CHECK `id = 1`, and its key is not random. */
    val withoutRowidTables: Set<String> = setOf("upd_staged")
    val rowidTables: Set<String> = setOf("upd_state")

    /**
     * The time columns of §9.6: **none** (T33's rule: no time column of activity; `NO_CHANNEL`
     * counts update runs in `failed_runs`, a counter, and the only day the channel exposes is
     * the stored manifest's own `issued_day`, inside the manifest document).
     */
    val timeColumns: Set<String> = emptySet()

    /** The columns the time-like scan must not mistake for times: the epoch is a hash, and the
     * version code names an installed APK. */
    val notTimes: Map<String, String> = mapOf(
        "upd_state.epoch" to "the trust-epoch id, a SHA-256 hash, not a time",
        "upd_state.epoch_version_code" to "the installed versionCode the epoch belongs to, not a time",
    )
}

/**
 * A migrated database with the base `upd_state` row of §9.6 (the first start: the embedded
 * chain as the first epoch, pair 0, floor 0, no manifest). Every test updates from here.
 */
internal class UpdateFixture(
    val db: JdbcSqlExecutor = JdbcSqlExecutor().also { MigrationRunner(it).migrate() },
) : AutoCloseable {

    companion object {
        val EPOCH: ByteArray = uBytes(32, 0xE1)
        val CHAIN: ByteArray = uBytes(128, 0xC1)
        val ROLLOUT: ByteArray = uBytes(32, 0x31)

        fun uBytes(n: Int, tag: Int): ByteArray = ByteArray(n) { tag.toByte() }
        fun sha(tag: Int): ByteArray = uBytes(32, tag)
    }

    /** Inserts the base row; every column the triggers read is set to a legal value. */
    fun insertBase(
        network: Long = 2L,
        epoch: ByteArray = EPOCH,
        epochVersionCode: Long = 1L,
        rootVersion: Long = 1L,
        manifestSeq: Long = 0L,
        manifestRoot: Long = 0L,
        manifestSha256: ByteArray? = null,
        manifestFile: ByteArray? = null,
        proofFile: ByteArray? = null,
        floorVersionCode: Long = 0L,
        floorRoot: Long = 0L,
        conflictRoot: Long? = null,
        rootConflict: Long = 0L,
        failedRuns: Long = 0L,
        rolloutKey: ByteArray = ROLLOUT,
    ) {
        db.execUpdate(
            "INSERT INTO upd_state (id, network, epoch, epoch_version_code, root_version, root_chain, " +
                "manifest_seq, manifest_root, manifest_sha256, manifest_file, proof_file, " +
                "floor_version_code, floor_root, conflict_root, root_conflict, failed_runs, rollout_key) " +
                "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            listOf(
                network, epoch, epochVersionCode, rootVersion, CHAIN,
                manifestSeq, manifestRoot, manifestSha256, manifestFile, proofFile,
                floorVersionCode, floorRoot, conflictRoot, rootConflict, failedRuns, rolloutKey,
            ),
        )
    }

    override fun close() = db.close()
}
