package org.ghost.messaging.harness

import org.ghost.messaging.DmDevice
import org.ghost.messaging.MovableClock
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.storage.Checkpoint
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import java.io.File

/**
 * One rebootable device of a crash world: a database **file**, a fault-injecting executor over it,
 * and a [DmDevice] that is thrown away and built again at every reboot (§15.3).
 *
 * > reboot (drop the uncommitted connection, reopen the same file, migrate, `verifyIntegrity`,
 * > R-K1, build a new client: engine, actor, DM context)
 *
 * [boot] performs exactly those five steps, in that order, and [reboot] is [kill] then [boot].
 *
 * **Why the database has to be a file.** An in-memory SQLite database lives in its connection, so
 * "drop the uncommitted connection and reopen the same file" would drop everything the run had
 * committed and every crash run would trivially pass. Every other DM world of S6–S9 is in memory
 * because nothing in them reboots; every world here is on disk.
 *
 * **What a crash does to the open transaction.** The injected [SimulatedDmCrash] unwinds out of
 * `JdbcSqlExecutor.transaction`, whose `catch` rolls the connection back, and [kill] then closes
 * it. That is the same committed state a process death would leave — SQLite's own recovery of an
 * unfinished transaction is a rollback — and it is what the Phase 7 harness models too. What it
 * does **not** model is a torn write inside a committed frame; `synchronous = FULL` plus SQLite's
 * durability is the premise §15.8 declares, not something a JVM harness can test.
 */
internal class DmNode(
    val name: String,
    val branch: Int,
    private val directory: File,
    private val bus: DmEventBus,
    startSeconds: Long,
    private val slotCount: Int = 4,
    private val operators: Int = 2,
    /** The `ghost1` seed branch: [DmDevice]'s own default of `branch + 1` unless a world needs it. */
    private val identityBranch: Int = branch + 1,
) : AutoCloseable {

    /** The clock survives a reboot: a device that restarts does not go back in time. */
    val clock = MovableClock(startSeconds)

    val path: String = File(directory, "dm-$name-$branch.db").absolutePath

    /** How many times this node has booted; 0 until the first [boot]. */
    var boots: Int = 0
        private set

    /** Wraps the envelope port of every boot (native-crash injection and the ME mutants). */
    var decorate: ((DmEnvelopes) -> DmEnvelopes)? = null

    /**
     * Statement rewriting for this node, re-installed at every boot (the MC and ME mutants of
     * §15.7, which "live only in `src/test`").
     *
     * It is a property of the node and not of the executor, because a mutant has to survive the
     * reboot a crash run performs: a mutation that healed itself at the first process death would
     * be detected by nothing but the reboot.
     */
    var rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null

    /**
     * The transaction-split seam of [FaultyDmSqlExecutor.defer], re-installed at every boot for the
     * same reason [rewrite] is: a mutation that healed itself at the first process death would be
     * detected by the reboot and by nothing else.
     */
    var defer: ((String) -> Boolean)? = null

    private var jdbc: JdbcSqlExecutor? = null
    private var faulty: FaultyDmSqlExecutor? = null
    private var current: DmDevice? = null

    /** The live device. Valid between a [boot] and the next [kill]. */
    val device: DmDevice get() = requireNotNull(current) { "$name is not booted" }

    val sql: FaultyDmSqlExecutor get() = requireNotNull(faulty) { "$name is not booted" }

    /** The raw connection, **outside** the event bus: the model relay and the setup use it. */
    val raw: JdbcSqlExecutor get() = requireNotNull(jdbc) { "$name is not booted" }

    /** True once the log was truncated at the last open (R-K1). */
    var lastOpenTruncated: Boolean = false
        private set

    /**
     * How many bytes the write-ahead log held **immediately after R-K1**, before the new client was
     * built.
     *
     * The distinction matters and cost a debugging round: building the client writes (the relay
     * directory, the slot table), so the log is no longer empty by the time [boot] returns, and an
     * assertion taken then would be measuring the new client's first transaction rather than the
     * checkpoint. §15.3's "the WAL is 0 bytes" is a statement about the moment after the
     * checkpoint, and this is that moment.
     */
    var walBytesAfterOpen: Long = -1
        private set

    /**
     * The five steps of §15.3's reboot, in order.
     *
     * Migration and `verifyIntegrity` run on the **raw** connection, unarmed, because they are the
     * open path and not the scenario: a crash injected into `MigrationRunner` would test migration
     * atomicity, which is SCN-L's job and `Migration5Test`'s, not every scenario's.
     */
    fun boot() {
        check(current == null) { "$name is already booted" }
        val connection = JdbcSqlExecutor(path)
        // WAL first, so the migration and R-K1 below see the journal mode the device runs in and
        // `-wal` exists to be truncated at all (§10.9 point 3).
        connection.query("PRAGMA journal_mode = WAL") { }
        val runner = MigrationRunner(connection)
        runner.migrate()
        // R-K1 (§10.7): "a checkpoint runs at every database open, after migration and before the
        // first read". Its other end is the in-memory `checkpoint_due` of SWEEP, which dies with
        // the process — so without this a device that swept and was then killed would keep freed
        // plaintext pages in the `-wal` for the life of the next process (the T25 physical bound).
        lastOpenTruncated = Checkpoint.truncate(connection) { }
        walBytesAfterOpen = walFile.let { if (it.exists()) it.length() else 0L }
        runner.verifyIntegrity()
        val wrapper = FaultyDmSqlExecutor(connection, bus, name)
        wrapper.rewrite = rewrite
        wrapper.defer = defer
        jdbc = connection
        faulty = wrapper
        current = DmDevice(
            branch = branch,
            slotCount = slotCount,
            operators = operators,
            startSeconds = clock.now,
            identityBranch = identityBranch,
            path = path,
            harness = DmDevice.HarnessOverride(wrapper, clock, boots, decorate),
        )
        boots++
    }

    /**
     * Process death: the DM context goes, the actor goes, the connection goes. Nothing is flushed
     * and nothing is checkpointed — a device that is killed does not get to tidy up.
     */
    fun kill() {
        current?.close()
        current = null
        // `DmDevice.close` no longer owns this connection, so the node closes it: the rollback of
        // the interrupted transaction already happened on the way out of `transaction`.
        runCatching { jdbc?.close() }
        jdbc = null
        faulty = null
    }

    fun reboot() {
        kill()
        boot()
    }

    /** The `-wal` file, for the T25 bound of §15.3 ("the WAL is 0 bytes" after SWEEP and R-K1). */
    val walFile: File get() = File("$path-wal")

    override fun close() {
        kill()
    }

    override fun toString(): String = "DmNode($name, boots=$boots)"
}
