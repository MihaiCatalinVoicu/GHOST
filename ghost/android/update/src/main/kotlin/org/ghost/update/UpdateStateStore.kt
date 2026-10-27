package org.ghost.update

import org.ghost.storage.SqlExecutor
import org.ghost.storage.queryLong

/**
 * `upd_state` and `upd_staged` (Phase 14 design §9.6, §9.6.1): the SQL bridge between the JNI
 * codec blob and the columns, and the transactions the crash rules name. The relay-directory
 * half of ACCEPT arrives as a hook — the caller (:sync's wiring) applies the `relay_directory`
 * changes of §7.8 in the same transaction through its own store, since that table is :sync's.
 *
 * Every mutating entry point documents its crash rule; each is idempotent where §9.6.1 says so.
 */
class UpdateStateStore(private val db: SqlExecutor) {

    /** One loaded state: the blob for `UpdateNative` plus the column-only facts around it. */
    class Loaded(
        val network: Int,
        val conflictRoot: Int?,
        val failedRuns: Int,
        val rolloutKey: ByteArray,
        val facts: UpdateCodec.Facts,
    ) {
        /** The exact bytes `UpdateNative.nativeAccept`/`nativeOffer` take. */
        val blob: ByteArray get() = UpdateCodec.encode(facts)
    }

    /** No row yet: the first start of a fresh install. */
    fun isEmpty(): Boolean = db.queryLong("SELECT count(*) FROM upd_state") == 0L

    /**
     * START (§9.6.1): inserts the one row of a fresh install — the embedded chain as the first
     * epoch, pair 0, floor 0. The rollout key is drawn by the caller from `SecureRandom` (never
     * SQLite's `randomblob`) and never leaves the database. All or nothing; a crash leaves no
     * row and the next start repeats it.
     */
    fun insertFirst(facts: UpdateCodec.Facts, rolloutKey: ByteArray) {
        require(rolloutKey.size == 32) { "rollout key is 32 bytes" }
        require(facts.manifestSeq == 0L && facts.manifestFile == null) { "a fresh install holds no manifest" }
        db.execUpdate(
            "INSERT INTO upd_state (id, network, epoch, epoch_version_code, root_version, root_chain, " +
                "manifest_seq, manifest_root, manifest_sha256, manifest_file, proof_file, " +
                "floor_version_code, floor_root, conflict_root, root_conflict, failed_runs, rollout_key) " +
                "VALUES (1, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, NULL, ?, ?, NULL, ?, 0, ?)",
            listOf(
                facts.network, facts.epoch, facts.epochVersionCode, facts.rootVersion, facts.chain,
                facts.floorVersionCode, facts.floorRoot,
                if (facts.rootConflict) 1L else 0L, rolloutKey,
            ),
        )
    }

    /** Loads the row as the JNI blob plus the column-only facts. Empty database: null. */
    fun load(): Loaded? {
        var loaded: Loaded? = null
        db.query(
            "SELECT network, epoch, epoch_version_code, root_version, root_chain, manifest_seq, " +
                "manifest_root, manifest_sha256, manifest_file, proof_file, floor_version_code, " +
                "floor_root, conflict_root, root_conflict, failed_runs, rollout_key FROM upd_state WHERE id = 1",
        ) { r ->
            val network = r.long(0).toInt()
            val conflict = if (r.isNull(12)) null else r.long(12).toInt()
            loaded = Loaded(
                network = network,
                conflictRoot = conflict,
                failedRuns = r.long(14).toInt(),
                rolloutKey = r.blob(15),
                facts = UpdateCodec.Facts(
                    network = network,
                    epoch = r.blob(1),
                    epochVersionCode = r.long(2).toInt(),
                    chain = r.blob(4),
                    rootVersion = r.long(3).toInt(),
                    manifestRoot = r.long(6).toInt(),
                    manifestSeq = r.long(5),
                    manifestSha256 = if (r.isNull(7)) null else r.blob(7),
                    manifestFile = if (r.isNull(8)) null else r.blob(8),
                    proofFile = if (r.isNull(9)) null else r.blob(9),
                    floorVersionCode = r.long(10).toInt(),
                    floorRoot = r.long(11).toInt(),
                    conflict = conflict != null,
                    rootConflict = r.long(13) == 1L,
                ),
            )
        }
        return loaded
    }

    /**
     * ACCEPT (§9.6.1): one transaction — the new facts (chain, root version, pair, hash,
     * manifest, proof, floor, flags) and, for a fresh current manifest only, the directory
     * hook. A crash leaves the previous facts, and the next update run fetches again.
     */
    fun accept(facts: UpdateCodec.Facts, directory: (SqlExecutor, ByteArray?) -> Unit = { _, _ -> }) {
        db.execUpdate("BEGIN IMMEDIATE")
        try {
            directory(db, facts.manifestFile)
            db.execUpdate(
                "UPDATE upd_state SET epoch = ?, epoch_version_code = ?, root_version = ?, root_chain = ?, " +
                    "manifest_seq = ?, manifest_root = ?, manifest_sha256 = ?, manifest_file = ?, proof_file = ?, " +
                    "floor_version_code = ?, floor_root = ?, conflict_root = ?, root_conflict = ? WHERE id = 1",
                listOf(
                    facts.epoch, facts.epochVersionCode, facts.rootVersion, facts.chain,
                    facts.manifestSeq, facts.manifestRoot,
                    facts.manifestSha256, facts.manifestFile, facts.proofFile,
                    facts.floorVersionCode, facts.floorRoot,
                    if (facts.conflict) facts.manifestRoot else null,
                    if (facts.rootConflict) 1L else 0L,
                ),
            )
            db.execUpdate("COMMIT")
        } catch (e: Throwable) {
            db.execUpdate("ROLLBACK")
            throw e
        }
    }

    /**
     * CONFLICT (T49): an equal pair with other bytes sets the conflict flag for that root
     * version and changes nothing else — no manifest, pair, floor or directory adoption. The
     * flag is kept while the root version is unchanged and cleared by the next ACCEPT under a
     * newer root; an existing scope is never overwritten (a stored flag of another root version
     * means the state was inconsistent, and ACCEPT is the only writer that may clear it).
     */
    fun markConflict(rootVersion: Int) {
        db.execUpdate(
            "UPDATE upd_state SET conflict_root = ? WHERE id = 1 AND conflict_root IS NULL",
            listOf(rootVersion.toLong()),
        )
    }

    /** RUN-END (§9.6.1): `failed_runs` counts unanswered runs; a crash loses at most one count. */
    fun runEnd(anyMirrorAnswered: Boolean) {
        db.execUpdate(
            "UPDATE upd_state SET failed_runs = CASE WHEN ? THEN 0 ELSE failed_runs + 1 END WHERE id = 1",
            listOf(if (anyMirrorAnswered) 1L else 0L),
        )
    }

    // ---------------------------------------------------------- the staged row (§7.7, §9.6.1)

    class Staged(val sha256: ByteArray, val versionCode: Int, val apkLength: Long, val received: Long, val state: String)

    fun staged(sha: ByteArray): Staged? {
        var out: Staged? = null
        db.query(
            "SELECT apk_sha256, version_code, apk_length, received, state FROM upd_staged WHERE apk_sha256 = ?",
            listOf(sha),
        ) { r ->
            out = Staged(r.blob(0), r.long(1).toInt(), r.long(2), r.long(3), r.string(4))
        }
        return out
    }

    /** The single staged row (§9.6's at-most-one invariant), whatever its state. */
    fun staged(): Staged? {
        var out: Staged? = null
        db.query("SELECT apk_sha256, version_code, apk_length, received, state FROM upd_staged") { r ->
            out = Staged(r.blob(0), r.long(1).toInt(), r.long(2), r.long(3), r.string(4))
        }
        return out
    }

    /** STAGE-CHUNK's row half: the engine writes the range and fsyncs the file first; this
     *  advances the counter in the same transaction, so `received` never exceeds what is on disk. */
    fun stageBegin(sha: ByteArray, versionCode: Int, apkLength: Long) {
        db.execUpdate(
            "INSERT INTO upd_staged (apk_sha256, version_code, apk_length, received, state) VALUES (?, ?, ?, 0, 'partial')",
            listOf(sha, versionCode.toLong(), apkLength),
        )
    }

    fun stageAdvance(sha: ByteArray, received: Long) {
        db.execUpdate("UPDATE upd_staged SET received = ? WHERE apk_sha256 = ?", listOf(received, sha))
    }

    /** STAGE-VERIFY: the full check passed and the engine renamed the file (row to `verified`). */
    fun stageVerified(sha: ByteArray) {
        db.execUpdate(
            "UPDATE upd_staged SET state = 'verified', received = apk_length WHERE apk_sha256 = ?",
            listOf(sha),
        )
    }

    /** INSTALL-COMMIT: the platform session is committed after the native check returned OK. */
    fun stageCommitted(sha: ByteArray) {
        db.execUpdate("UPDATE upd_staged SET state = 'committed' WHERE apk_sha256 = ?", listOf(sha))
    }

    /** The failure and sweep rules: the row and the engine's file go together. */
    fun stageClear(sha: ByteArray) {
        db.execUpdate("DELETE FROM upd_staged WHERE apk_sha256 = ?", listOf(sha))
    }
}
