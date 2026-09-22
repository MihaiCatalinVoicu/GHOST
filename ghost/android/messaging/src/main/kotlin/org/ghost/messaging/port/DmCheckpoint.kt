package org.ghost.messaging.port

/**
 * `PRAGMA wal_checkpoint(TRUNCATE)` with its result checked, as SWEEP needs it (Phase 9 design
 * §10.7, §7.2's "After commit: `checkpointTruncate()`").
 *
 * > After a SWEEP that deleted rows: `PRAGMA wal_checkpoint(TRUNCATE)` read through `query`,
 * > **require `busy = 0`**, retry 3 times 100 ms apart, else keep `checkpoint_due` in memory and
 * > retry at the next sweep.
 *
 * **Why a port and not a direct call.** The pragma is `:storage`'s `Checkpoint.truncate(sql)`, and
 * it needs the `SqlExecutor` **outside** a transaction — which `:messaging` has no way to reach:
 * `SyncDatabase.sql` is internal to `:sync`, and deliberately so, since every DM write goes through
 * a `SyncTransaction`. `:app` (and each test world) owns the executor and wires it here.
 *
 * The implementation is exactly one line, `Checkpoint.truncate(executor)`, and the whole point of
 * this port is that it is that line and not a no-op: mutant **ME-11** ("no checkpoint") and mutant
 * **ME-10** ("checkpoint result ignored") both live on the other side of it, and the T25 physical
 * assertion — the `-wal` file is 0 bytes after a sweep — is what measures them.
 */
fun interface DmCheckpoint {
    /**
     * Truncates the write-ahead log. Returns false when a reader held it through all the retries,
     * in which case the caller keeps the need and asks again at its next sweep (§10.7).
     *
     * Must not be called inside a transaction; `Checkpoint.truncate` refuses one outright.
     */
    fun truncate(): Boolean
}
