package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ContactId
import java.io.File
import java.nio.file.Files

/**
 * A crash world: file-backed [DmNode]s, one [ModelDmRelay] over them, one [DmEventBus] for all of
 * it, and one virtual clock they share (Phase 9 design §15.1, §15.3).
 *
 * Everything a scenario does goes through here, so that a step written once runs identically in
 * the recording run and in every crash run — and so that a step keeps working after the node it
 * touches has been rebooted and its `DmDevice` replaced.
 */
internal class DmCrashWorld(
    val name: String,
    /** The world's virtual start: a Tuesday deep inside the Phase 8 grid, as every DM world uses. */
    val startSeconds: Long = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY,
) : AutoCloseable {

    val bus = DmEventBus()
    val relay = ModelDmRelay(bus)

    /** Names of the nodes [retire] took out of the world. */
    private val retired = HashSet<String>()

    /** One temporary directory per world: a reboot must find the same bytes it left. */
    val directory: File = Files.createTempDirectory("ghost-dm-s10-").toFile()

    private val order = ArrayList<DmNode>()
    private val byName = HashMap<String, DmNode>()

    /** Contact ids a scenario named, so a later step can find them after a reboot. */
    val contacts = HashMap<String, ContactId>()

    /** Free-form notes a scenario leaves for its own final checks. */
    val notes = HashMap<String, Any>()

    /**
     * A mutation installed on every node of this world as it is created (§15.7).
     *
     * On the world rather than on a node, because a mutant is a change to *the implementation*, and
     * an implementation that was wrong on one device and right on another would be detected for the
     * wrong reason. `DmMutantDetectionTest` sets it before the scenario builds its nodes.
     */
    var mutation: DmMutants.Mutation? = null

    fun node(
        name: String,
        branch: Int,
        identityBranch: Int = branch + 1,
        streamOffset: Int = 0,
    ): DmNode {
        check(name !in byName && name !in retired) { "duplicate node $name" }
        val node = DmNode(
            name = name,
            branch = branch,
            directory = directory,
            bus = bus,
            // The world's time, not its start: a node added later (SCN-I's restored device) joins
            // a world whose clocks have moved, and a device's wall clock is the world's. Every node
            // of S10 is built before the first advance, where the two are the same number.
            startSeconds = order.maxOfOrNull { it.clock.now } ?: startSeconds,
            identityBranch = identityBranch,
            streamOffset = streamOffset,
        )
        mutation?.let {
            node.rewrite = it.rewrite
            node.decorate = it.decorate
            node.defer = it.defer
        }
        node.boot()
        order += node
        byName[name] = node
        return node
    }

    fun nodes(): List<DmNode> = order

    operator fun get(name: String): DmNode = requireNotNull(byName[name]) { "no node $name" }

    /**
     * Every inbound text a **retired** node had rendered at the moment it left the world, over
     * every one of its conversations.
     *
     * The no-loss oracle of [DmCrashRunner] reads it beside the live nodes' own: a message the
     * sender calls `SENT` that the lost device rendered before it was lost was not lost by the
     * engine, and without this the oracle would charge SCN-I's restore with every message the old
     * device ever read.
     */
    val retiredRendered = HashSet<String>()

    /**
     * Takes [name] out of the world for good: a device that is **lost** (SCN-I's "B restores from
     * seed" — the old phone is gone, not rebooted).
     *
     * Its rendered texts are recorded first ([retiredRendered]), then its process dies the way
     * [DmNode.kill] models a death — nothing flushed, nothing checkpointed — and it is removed from
     * every round, so no later pump serves it a blob and no later pass runs on it. The relay keeps
     * whatever it had stored for it, which is the point: those blobs are what the restored device
     * finds in its inbox. Only a setup may call it: a retirement is not a scenario step a crash
     * can interrupt, and a node that vanished mid-step would leave a runner that cannot reboot it.
     */
    fun retire(name: String) {
        check(!bus.armed) { "a node is retired in the setup, never in the armed phase" }
        val node = this[name]
        retiredRendered += DmScripts.everyInboundText(node)
        node.close()
        order.remove(node)
        byName.remove(name)
        retired += name
    }

    /** Moves every node's clock forward by the same amount; time never goes back here. */
    fun advanceBy(seconds: Long) {
        require(seconds >= 0) { "the world clock never moves back" }
        for (node in order) {
            node.clock.now += seconds
            node.clock.monotonic += seconds * 1_000
        }
    }

    /**
     * Steps **one** node's wall clock backwards, which the EP suite and SCN-F need and which the
     * world clock must never do: §10.7's "a wall clock stepped back" is a property of one device,
     * not of time.
     */
    fun stepClockBack(node: String, seconds: Long) {
        this[node].clock.now -= seconds
        this[node].clock.monotonic += 1_000
    }

    /** One relay round. */
    fun pump(): Int = relay.pump(order)

    /**
     * Exceptions a pass threw and the device's own actor thread would have swallowed.
     *
     * `DmActor.wake` submits `runPass` to a single-thread executor and never reads the future, so
     * on a device an exception out of a pass ends that pass and nothing else: the process lives and
     * the work is owed again at the next trigger. A harness that let the exception out would be
     * testing a device that does not exist — and one that swallowed it silently would hide every
     * bug a pass has. So they are recorded here, and [DmCrashRunner] asserts what may be in the
     * list: nothing at all in a fault-free run, and only `SQLITE_FULL` in a run that injected one.
     *
     * Only `Exception` is caught. The injected deaths are `Error`s precisely so that nothing —
     * neither the engine nor this line — can absorb them.
     */
    val swallowed = ArrayList<Throwable>()

    private fun drive(body: () -> Unit) {
        try {
            body()
        } catch (e: Exception) {
            swallowed += e
        }
    }

    /** A time-triggered actor pass on every node (§21.9 rule 1). */
    fun passes() {
        for (node in order) drive { node.device.timeTriggeredPass() }
    }

    /**
     * A time-triggered pass on **one** node (S10c), through the same swallow the actor thread
     * performs. For a stretch of a scenario in which only that node has anything to do: SCN-C's
     * first part is hours of one device's attempt windows while the other two sit idle, and their
     * passes would only add crash points in SWEEP and KEEPER on devices doing nothing.
     */
    fun pass(name: String) {
        drive { this[name].device.timeTriggeredPass() }
    }

    /** A hint-triggered pass on every node: outcomes, bundles and the inbox. */
    fun hints() {
        for (node in order) drive { node.device.hintPass() }
    }

    /** A hint-triggered pass on one node, through the same swallow the actor thread performs. */
    fun hint(name: String) {
        drive { this[name].device.hintPass() }
    }

    /**
     * Runs to quiescence: rounds of pump + pass until nothing changes, or [maxRounds] is reached.
     *
     * "Nothing changes" is measured on the structural digest of every node together with the
     * relay's blob count, so a round that only moved a blob the recipient dropped still counts as
     * progress once and then stops. A world that never settles is a finding, not a timeout: an
     * engine that keeps producing work at quiescence is the "no reflex" property broken.
     */
    fun quiesce(maxRounds: Int = 24, stepSeconds: Long = 5 * DmWorld.MINUTE) {
        var previous = ""
        var jumps = 0
        for (round in 0 until maxRounds) {
            pump()
            passes()
            advanceBy(stepSeconds)
            val state = order.joinToString("|") { DmStructuralInvariants.digest(it) } +
                "/" + relay.blobCount
            if (state == previous) {
                // Nothing moved — but "nothing moved" and "nothing is owed" are different
                // statements, and only the second is quiescence. A retry backoff, a fetch attempt
                // or a poison re-offer due in an hour looks exactly like an idle world at a
                // five-minute step, so every timer-gated recovery went unexercised in every crash
                // run. So: jump the clock to the next moment something is due and keep going.
                if (jumps++ >= MAX_JUMPS || !jumpToTheNextDueMinute()) return
                previous = ""
                continue
            }
            previous = state
        }
        // Not a violation by itself: some scenarios legitimately still owe work at their bound
        // (a waiting establishment, a deadline in the future). The runner's own checks decide.
    }

    /**
     * Moves every clock to the earliest minute at which some node has work due, and answers whether
     * it moved at all.
     *
     * The jump is refused when it would cross an **expiry** deadline: an ephemeral message deleted
     * by the harness's own clock jump would be a scenario broken by quiescence rather than by the
     * engine, and §10.7's deadlines are the subject of SCN-F and of the EP case, not their
     * machinery. So a world whose next due moment is on the far side of a `delete_at_minute` simply
     * stops here, which is the state it was already in before this existed.
     */
    private fun jumpToTheNextDueMinute(): Boolean {
        val now = order.minOfOrNull { it.clock.now } ?: return false
        val due = order.mapNotNull { DmStructuralInvariants.nextDueMinute(it, now) }.minOrNull()
            ?: return false
        val expiry = order.mapNotNull { DmStructuralInvariants.nextExpiryMinute(it, now) }.minOrNull()
        if (expiry != null && expiry <= due) return false
        if (due - now > MAX_JUMP_SECONDS) return false
        advanceBy(due - now + DmWorld.MINUTE)
        return true
    }

    private companion object {
        /** At most this many clock jumps per quiescence, so a world that re-arms cannot loop. */
        const val MAX_JUMPS: Int = 4

        /** The furthest a jump reaches: a day. Anything beyond is an offline window, not a retry. */
        const val MAX_JUMP_SECONDS: Long = DmWorld.DAY
    }

    /** Structural invariants over every node. */
    fun checkAll(where: String, heavy: Boolean = true) {
        for (node in order) DmStructuralInvariants.check(node, where, heavy)
    }

    override fun close() {
        for (node in order) runCatching { node.close() }
        directory.deleteRecursively()
    }

    override fun toString(): String = "DmCrashWorld($name)"
}
