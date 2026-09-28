package org.ghost.messaging.harness

import org.ghost.crypto.bridge.DmEquivalence
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
    /**
     * Added to the boot index the device's Kotlin random stream is named by (S10b).
     *
     * Zero for every ordinary node, which keeps every stream of S10 byte for byte. A **restored**
     * node (SCN-I) is the same MESSAGING branch and the same `ghost1` seed on a new file, so without
     * an offset its first boot would draw the lost device's first-boot stream again — the same
     * `message_id`s and the same `sched_id`s the lost device already spent, and the recipient's D3
     * tag would drop the restored device's messages as duplicates of the lost one's. That is the
     * `SequentialRandom` fixture artefact §22.14's closing note already caught once, and a device
     * that restores draws fresh entropy.
     */
    private val streamOffset: Int = 0,
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

    /** [FaultyDmSqlExecutor.deferUpdate], re-installed at every boot like [defer]. */
    var deferUpdate: ((String) -> Int?)? = null

    /** RECV's freshness policy (mutant MC-9, §22.38), handed to every device this node boots. */
    var freshness: org.ghost.messaging.engine.ContentFreshness? = null

    /**
     * MC-20's omitted binding field and KC5b's perturbed one (`DmEquivalence.bindingHooks`,
     * §22.37). They live on the native DM context, which dies with the process, so [boot]
     * re-installs them like [defer]; a step that changes one calls [installBindingHooks].
     */
    var bindingOmit: Int = DmEquivalence.BINDING_NONE
    var bindingPerturb: Int = DmEquivalence.BINDING_NONE

    /**
     * §10.9 item 3, "sweep, then assert … the WAL is 0 bytes" (§22.38), measured at the one
     * instant it is defined: right after a checkpoint the device reported done
     * ([FaultyDmSqlExecutor.afterCheckpoint]), before the pass writes again. One entry per
     * checkpoint that left bytes in the `-wal` file; [DmStructuralInvariants.check] reports them.
     * Kept across reboots: a process that died owes nothing, but what it did before is the run's.
     */
    val logAfterCheckpoint = ArrayList<String>()

    /** How many checkpoints [logAfterCheckpoint] measured, across reboots. */
    var checkpointsMeasured: Int = 0
        private set

    private fun measureTheLog() {
        checkpointsMeasured++
        val bytes = walFile.let { if (it.exists()) it.length() else 0L }
        if (bytes != 0L) {
            logAfterCheckpoint += "the log held $bytes bytes right after a checkpoint that reported it truncated " +
                "(§10.9 item 3, T25)"
        }
    }

    /**
     * Where [boot] runs the migrations (SCN-L-v3, design §22.38). False for every node but
     * SCN-L-v3's bob and EP-store-after-expiry's alice: on the raw connection, unarmed, as always.
     * True: through the fault-injecting executor, so every statement of every migration the file
     * still needs is an **event** when the world is armed — a crash point — and in every case a
     * statement a mutant's [rewrite] can change (MC-17, ME-9; ME-20 on a file migrated in a setup,
     * where nothing is an event) — and an integrity refusal at open is a **finding** of the run
     * ([DmInvariantViolation]) rather than a harness error. Test-only: the device's own open path
     * is not in `:messaging` at all.
     */
    var migrateOnTheBus: Boolean = false

    /**
     * Run at every [boot], on the raw connection, right after the migrations — before R-K1, before
     * `verifyIntegrity`, before the client is built (SCN-L-v3's CS-9 check). Nothing it reads is an
     * event.
     */
    var afterMigrations: ((JdbcSqlExecutor) -> Unit)? = null

    /**
     * ME-24's hook (`DmEquivalence.stateWrapHook`, §22.38): the context stores its Olm session
     * states unwrapped. It lives on the native DM context, which dies with the process, so [boot]
     * re-installs it, before any call that could read a state the last process stored.
     */
    var stateUnwrapped: Boolean = false

    /**
     * MC-30's second hook (`DmEquivalence.sidecarLogHook`, §22.38): the context keeps its sessions'
     * first-seen sidecars as insert-only logs. Re-installed at every boot like [stateUnwrapped].
     */
    var sidecarLog: Boolean = false

    /** Whether the running context carries hooks, so a node that never had any never calls in. */
    private var bindingHooksOn = false

    /** Sets [bindingOmit] and [bindingPerturb] on the running context. */
    fun installBindingHooks() {
        val none = bindingOmit == DmEquivalence.BINDING_NONE && bindingPerturb == DmEquivalence.BINDING_NONE
        if (none && !bindingHooksOn) return
        val handle = requireNotNull(device.nativeHandle) { "$name has no DM context to hook" }
        check(DmEquivalence.bindingHooks(handle, bindingOmit, bindingPerturb)) {
            "$name: the host library refused binding hooks ($bindingOmit, $bindingPerturb)"
        }
        bindingHooksOn = !none
    }

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
     * atomicity, which is SCN-L's job and `Migration5Test`'s, not every scenario's. SCN-L-v3's node
     * is the exception whose job it is, and EP-store-after-expiry's alice the one that needs a
     * mutant's rewrite to reach its schema ([migrateOnTheBus]).
     */
    fun boot() {
        check(current == null) { "$name is already booted" }
        val connection = JdbcSqlExecutor(path)
        // WAL first, so the migration and R-K1 below see the journal mode the device runs in and
        // `-wal` exists to be truncated at all (§10.9 point 3).
        connection.query("PRAGMA journal_mode = WAL") { }
        val wrapper = FaultyDmSqlExecutor(connection, bus, name)
        wrapper.rewrite = rewrite
        wrapper.defer = defer
        wrapper.deferUpdate = deferUpdate
        wrapper.afterCheckpoint = ::measureTheLog
        // Held before the migrations, so a crash inside one on the bus leaves a node [kill] closes.
        jdbc = connection
        faulty = wrapper
        MigrationRunner(if (migrateOnTheBus) wrapper else connection).migrate()
        afterMigrations?.invoke(connection)
        // R-K1 (§10.7): "a checkpoint runs at every database open, after migration and before the
        // first read". Its other end is the in-memory `checkpoint_due` of SWEEP, which dies with
        // the process — so without this a device that swept and was then killed would keep freed
        // plaintext pages in the `-wal` for the life of the next process (the T25 physical bound).
        lastOpenTruncated = Checkpoint.truncate(connection) { }
        walBytesAfterOpen = walFile.let { if (it.exists()) it.length() else 0L }
        val runner = MigrationRunner(connection)
        if (migrateOnTheBus) {
            // CS-9's "and the trigger set": a file the open path refuses is what the migration left,
            // so it is the run's finding.
            runCatching { runner.verifyIntegrity() }.onFailure {
                dmViolation("$name's database was refused at open: ${it.message} (MigrationRunner.verifyIntegrity, CS-9)")
            }
        } else {
            runner.verifyIntegrity()
        }
        current = DmDevice(
            branch = branch,
            slotCount = slotCount,
            operators = operators,
            startSeconds = clock.now,
            identityBranch = identityBranch,
            path = path,
            harness = DmDevice.HarnessOverride(wrapper, clock, streamOffset + boots, decorate, freshness = freshness),
        )
        bindingHooksOn = false
        installBindingHooks()
        if (stateUnwrapped) {
            val handle = requireNotNull(device.nativeHandle) { "$name has no DM context to hook" }
            check(DmEquivalence.stateWrapHook(handle, true)) { "$name: the host library refused the state-wrap hook" }
        }
        if (sidecarLog) {
            val handle = requireNotNull(device.nativeHandle) { "$name has no DM context to hook" }
            check(DmEquivalence.sidecarLogHook(handle, true)) { "$name: the host library refused the sidecar-log hook" }
        }
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
