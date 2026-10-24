package org.ghost.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every write-once, epoch and append-only trigger of migration 11 (Phase 14 design §9.6's note;
 * slice S2): **each legal update succeeds and each illegal one is refused**, for every rule the
 * note names — network and rollout_key write-once, the epoch that changes only together with
 * `epoch_version_code`, the append-only root version, pair, floor and conflict, the
 * `root_conflict` flag that never returns to 0, the no-DELETE rule, and the one-row rule of
 * `upd_staged` with its bounds.
 *
 * The rules are written from §9.6's note again, not read from the schema, so a trigger that
 * gains or loses a rule fails here. The four triggers are listed in [UpdateSchema.rules]; the
 * last test requires that each fired (its message was seen) in a test of this class.
 */
class UpdateTriggersTest {

    private val fired = HashSet<String>()

    private fun UpdateFixture.refuses(trigger: String, message: String, sql: String, vararg args: Any?) {
        db.rejects(message, sql, *args)
        fired += trigger
    }

    /** The full UPDATE the tests build on: one named column changes, the rest stay. */
    private fun UpdateFixture.set(
        network: Long = 2L,
        epoch: ByteArray = UpdateFixture.EPOCH,
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
        rolloutKey: ByteArray = UpdateFixture.ROLLOUT,
    ): Int = db.execUpdate(
        "UPDATE upd_state SET network=?, epoch=?, epoch_version_code=?, root_version=?, root_chain=?, " +
            "manifest_seq=?, manifest_root=?, manifest_sha256=?, manifest_file=?, proof_file=?, " +
            "floor_version_code=?, floor_root=?, conflict_root=?, root_conflict=?, failed_runs=?, rollout_key=? " +
            "WHERE id = 1",
        listOf(
            network, epoch, epochVersionCode, rootVersion, UpdateFixture.CHAIN,
            manifestSeq, manifestRoot, manifestSha256, manifestFile, proofFile,
            floorVersionCode, floorRoot, conflictRoot, rootConflict, failedRuns, rolloutKey,
        ),
    )

    // ---------------------------------------------------------- write-once columns

    @Test
    fun networkAndRolloutKeyAreWriteOnce() = UpdateFixture().use { f ->
        f.insertBase()
        f.refuses(
            "upd_state_write_once", "upd_state.network is write-once",
            "UPDATE upd_state SET network = 1 WHERE id = 1",
        )
        f.refuses(
            "upd_state_write_once", "upd_state.rollout_key is write-once",
            "UPDATE upd_state SET rollout_key = ? WHERE id = 1", UpdateFixture.sha(0x55),
        )
        // The counter of failed runs is free (RUN-END writes it).
        assertEquals(1, f.set(failedRuns = 3))
    }

    // ---------------------------------------------------------- the epoch rule

    @Test
    fun theEpochChangesOnlyWithANewInstalledVersion() = UpdateFixture().use { f ->
        f.insertBase()
        f.refuses(
            "upd_state_write_once", "an epoch change comes only with a new installed version",
            "UPDATE upd_state SET epoch = ? WHERE id = 1", UpdateFixture.sha(0xE2),
        )
        // A new epoch together with a new version may reset everything §9.6 names.
        assertEquals(
            1,
            f.set(
                epoch = UpdateFixture.sha(0xE2), epochVersionCode = 2L,
                rootVersion = 1L, manifestSeq = 0L, manifestRoot = 0L,
                floorVersionCode = 0L, floorRoot = 0L, conflictRoot = null, rootConflict = 0L,
            ),
        )
    }

    // ---------------------------------------------------------- append-only facts

    @Test
    fun theRootVersionNeverDecreasesWithinAnEpoch() = UpdateFixture().use { f ->
        f.insertBase(rootVersion = 2L)
        f.refuses(
            "upd_state_monotonic", "root_version never decreases",
            "UPDATE upd_state SET root_version = 1 WHERE id = 1",
        )
        assertEquals(1, f.set(rootVersion = 3L))
        // After an epoch change the counter restarts.
        assertEquals(1, f.set(epoch = UpdateFixture.sha(0xE3), epochVersionCode = 2L, rootVersion = 1L))
    }

    @Test
    fun thePairNeverDecreasesAndAnEqualPairKeepsItsHash() = UpdateFixture().use { f ->
        val sha = UpdateFixture.sha(0xA1)
        f.insertBase(manifestSeq = 2L, manifestRoot = 1L, manifestSha256 = sha, manifestFile = byteArrayOf(1), proofFile = byteArrayOf(2))
        f.refuses(
            "upd_state_monotonic", "the pair never decreases",
            "UPDATE upd_state SET manifest_root = 0 WHERE id = 1",
        )
        f.refuses(
            "upd_state_monotonic", "the pair never decreases",
            "UPDATE upd_state SET manifest_seq = 1 WHERE id = 1",
        )
        f.refuses(
            "upd_state_monotonic", "an equal pair keeps its manifest_sha256",
            "UPDATE upd_state SET manifest_sha256 = ? WHERE id = 1", UpdateFixture.sha(0xA2),
        )
        assertEquals(1, f.set(manifestSeq = 3L, manifestRoot = 1L, manifestSha256 = sha, manifestFile = byteArrayOf(1), proofFile = byteArrayOf(2)))
    }

    @Test
    fun theFloorIsAppendOnlyWithinItsRoot() = UpdateFixture().use { f ->
        f.insertBase(floorVersionCode = 5L, floorRoot = 2L)
        f.refuses(
            "upd_state_monotonic", "floor_root never decreases",
            "UPDATE upd_state SET floor_root = 1 WHERE id = 1",
        )
        f.refuses(
            "upd_state_monotonic", "the floor never decreases within its root",
            "UPDATE upd_state SET floor_version_code = 4 WHERE id = 1",
        )
        assertEquals(1, f.set(floorVersionCode = 6L, floorRoot = 2L))
        // A newer root starts a new floor scope, which may be lower (RK4 undoes a fast-forwarded floor).
        assertEquals(1, f.set(floorRoot = 3L, floorVersionCode = 1L))
    }

    @Test
    fun conflictRootIsSetOrRaisedAndClearsOnlyWhenTheRootRises() = UpdateFixture().use { f ->
        f.insertBase()
        assertEquals(1, f.set(conflictRoot = 2L))
        f.refuses(
            "upd_state_monotonic", "conflict_root is set or raised",
            "UPDATE upd_state SET conflict_root = 1 WHERE id = 1",
        )
        assertEquals(1, f.set(conflictRoot = 3L))
        f.refuses(
            "upd_state_monotonic", "conflict_root clears only when the root version rises",
            "UPDATE upd_state SET conflict_root = NULL WHERE id = 1",
        )
        assertEquals(1, f.set(rootVersion = 2L, conflictRoot = null))
    }

    @Test
    fun rootConflictNeverReturnsToZero() = UpdateFixture().use { f ->
        f.insertBase(rootConflict = 1L)
        f.refuses(
            "upd_state_monotonic", "root_conflict never returns to 0",
            "UPDATE upd_state SET root_conflict = 0 WHERE id = 1",
        )
    }

    @Test
    fun theRowIsNeverDeleted() = UpdateFixture().use { f ->
        f.insertBase()
        f.refuses(
            "upd_state_no_delete", "upd_state rows are never deleted",
            "DELETE FROM upd_state WHERE id = 1",
        )
    }

    // ---------------------------------------------------------- the staged row

    @Test
    fun atMostOneStagedUpdateAndItsBounds() = UpdateFixture().use { f ->
        f.insertBase()
        f.db.execUpdate(
            "INSERT INTO upd_staged (apk_sha256, version_code, apk_length, received, state) VALUES (?, 2, 1000, 0, 'partial')",
            listOf(UpdateFixture.sha(0x51)),
        )
        f.refuses(
            "upd_staged_one_row", "at most one staged update",
            "INSERT INTO upd_staged (apk_sha256, version_code, apk_length, received, state) VALUES (?, 3, 1000, 0, 'partial')",
            UpdateFixture.sha(0x52),
        )
        // The bounds of the row, at the edge and one past it.
        f.db.rejects(
            "CHECK constraint failed",
            "UPDATE upd_staged SET received = 1001 WHERE apk_sha256 = ?", UpdateFixture.sha(0x51),
        )
        assertEquals(1, f.db.execUpdate("UPDATE upd_staged SET received = 1000, state = 'verified' WHERE apk_sha256 = ?", listOf(UpdateFixture.sha(0x51))))
        f.db.rejects(
            "CHECK constraint failed",
            "UPDATE upd_staged SET state = 'weird' WHERE apk_sha256 = ?", UpdateFixture.sha(0x51),
        )
        // A lifecycle failure deletes the row and its file (§9.6.1): deletion itself is legal.
        assertEquals(1, f.db.execUpdate("DELETE FROM upd_staged WHERE apk_sha256 = ?", listOf(UpdateFixture.sha(0x51))))
    }

    // ---------------------------------------------------------- the consistency CHECKs

    @Test
    fun thePairAndTheManifestDocumentsStayConsistent() = UpdateFixture().use { f ->
        f.insertBase()
        // seq = 0 exactly when no manifest is held.
        f.db.rejects(
            "CHECK constraint failed",
            "UPDATE upd_state SET manifest_seq = 1 WHERE id = 1",
        )
        val sha = UpdateFixture.sha(0xB1)
        assertEquals(1, f.set(manifestSeq = 1L, manifestRoot = 1L, manifestSha256 = sha, manifestFile = byteArrayOf(1), proofFile = byteArrayOf(2)))
        f.db.rejects(
            "CHECK constraint failed",
            "UPDATE upd_state SET manifest_file = NULL WHERE id = 1",
        )
    }

    @Test
    fun everyRuleOfTheSchemaWasExercised() {
        // JUnit4 gives each method a fresh instance, so this test runs the methods itself (each
        // is cheap) and then checks the set, as ChannelTriggersTest's coverage test does.
        networkAndRolloutKeyAreWriteOnce()
        theEpochChangesOnlyWithANewInstalledVersion()
        theRootVersionNeverDecreasesWithinAnEpoch()
        thePairNeverDecreasesAndAnEqualPairKeepsItsHash()
        theFloorIsAppendOnlyWithinItsRoot()
        conflictRootIsSetOrRaisedAndClearsOnlyWhenTheRootRises()
        rootConflictNeverReturnsToZero()
        theRowIsNeverDeleted()
        atMostOneStagedUpdateAndItsBounds()
        thePairAndTheManifestDocumentsStayConsistent()
        assertEquals("a rule no test fired would pass unproven", UpdateSchema.rules, fired)
    }
}
