package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The harness testing itself, before any scenario trusts it (Phase 9 design §15.3; the "control"
 * discipline §15.9 item 7 states for the equivalence comparator: *a check that cannot fail is not
 * a check*).
 *
 * Every one of these is a control for a way the crash mechanism could be silently vacuous:
 *  1. the bus really counts events and the count is stable run to run;
 *  2. an injected crash really unwinds, and it is the one that was injected;
 *  3. a reboot really reopens the same file and finds the committed rows;
 *  4. a reboot really loses the uncommitted ones;
 *  5. the structural-invariant checker really fails on a broken database;
 *  6. `SQLITE_FULL` really arrives as a `StorageFullException` and not as a death;
 *  7. R-K1 really truncates the log at every open.
 *
 * Without 5 in particular the whole enumeration could pass on an engine that writes nothing.
 */
class DmHarnessSelfTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    /** 1: the counter runs, and the same scenario produces the same K twice. */
    @Test
    fun theEventCounterIsStableAcrossRuns() {
        requireNative()
        val runner = DmCrashRunner(DmScenarios.scnA())
        val first = runner.record()
        val second = runner.record()
        assertTrue("a recording run produced no events", first.events > 0)
        assertEquals("the same scenario produced a different K", first.events, second.events)
        assertEquals(0, first.crashes)
        assertEquals(0, first.reboots)
    }

    /** 2: a planned crash unwinds to the top level, and the runner reboots exactly once. */
    @Test
    fun aPlannedCrashUnwindsAndIsFollowedByExactlyOneReboot() {
        requireNative()
        val scenario = DmScenarios.scnA()
        val runner = DmCrashRunner(scenario)
        val events = runner.record().events
        val result = runner.run(DmRunSpec(crashAt = events / 2))
        assertEquals("the crash did not reach the top level", 1, result.crashes)
        assertEquals("the crash did not cause a reboot", 1, result.reboots)
    }

    /** 3 and 4: a reboot keeps what committed and loses what did not. */
    @Test
    fun aRebootKeepsCommittedRowsAndLosesUncommittedOnes() {
        requireNative()
        DmCrashWorld("self-test").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            val cardBefore = node.device.card().joinToString("") { "%02x".format(it) }
            val selfRows = DmScripts.count(world, "alice", "SELECT count(*) FROM dm_self")
            assertEquals("ACTIVATE wrote the identity row", 1L, selfRows)

            // Uncommitted work: a transaction that throws on the way out.
            runCatching {
                node.sql.transaction {
                    node.sql.exec(
                        "INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)",
                        listOf(ByteArray(32) { 7 }),
                    )
                    throw IllegalStateException("rolled back")
                }
            }
            node.reboot()

            assertEquals(2, node.boots)
            assertEquals(
                "the reboot lost a committed identity row",
                1L,
                DmScripts.count(world, "alice", "SELECT count(*) FROM dm_self"),
            )
            assertEquals(
                "the reboot kept a rolled-back row",
                0L,
                DmScripts.count(world, "alice", "SELECT count(*) FROM dm_orphan_namespace"),
            )
            // The same derived identity comes back: a reboot is the same device, not a new one.
            assertEquals(cardBefore, node.device.card().joinToString("") { "%02x".format(it) })
            // And the second boot draws from its own random stream (§15.3's "build a new client").
            assertNotEquals(
                "the second boot repeated the first boot's random draw",
                node.device.random.bytes(16).joinToString(""),
                DmCrashWorld("stream-control").use { other ->
                    other.node("alice", 0x41).device.random.bytes(16).joinToString("")
                },
            )
        }
    }

    /** 5: the invariant checker is not vacuous — a hand-broken database fails it. */
    @Test
    fun theStructuralInvariantCheckerFailsOnABrokenDatabase() {
        requireNative()
        DmCrashWorld("self-test-invariants").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            DmStructuralInvariants.check(node, "control")

            // A held row on a contact that is not `changed` — one of the §15.3 clauses.
            node.raw.exec(
                "INSERT INTO dm_contact(contact_id, identity_pk, card_env, card_index, " +
                    "trust_state, source, establishment) VALUES (?, ?, ?, 0, 'verified', " +
                    "'qr_in_person', 'card_only')",
                listOf(ByteArray(16) { 3 }, ByteArray(32) { 4 }, ByteArray(159) { 5 }),
            )
            node.raw.exec(
                "INSERT INTO dm_held(held_id, contact_id, identity, l1_env, gen_id, " +
                    "hold_until_minute, relay_expiry_hour, consume_minute) " +
                    "VALUES (?, ?, ?, ?, 1, 0, 0, 0)",
                listOf(ByteArray(16) { 6 }, ByteArray(16) { 3 }, ByteArray(32) { 4 }, ByteArray(64) { 7 }),
            )
            val failure = runCatching { DmStructuralInvariants.check(node, "broken") }.exceptionOrNull()
            assertTrue(
                "the checker accepted a held row on a 'verified' contact: $failure",
                failure is DmInvariantViolation,
            )
            assertTrue(
                "the failure does not name the clause it broke: ${failure?.message}",
                failure?.message?.contains("held row") == true,
            )
        }
    }

    /** 6: an injected `SQLITE_FULL` is a typed failure, not a death. */
    @Test
    fun anInjectedStorageFullArrivesAsAStorageFullException() {
        requireNative()
        DmCrashWorld("self-test-full").use { world ->
            val node = world.node("alice", 0x41)
            world.bus.plan = DmFaultPlan { e -> if (e.kind.sql) DmFault.StorageFull else null }
            world.bus.armed = true
            val failure = runCatching { node.device.engine.onActivated() }.exceptionOrNull()
            world.bus.armed = false
            assertTrue(
                "a full disk reached the caller as $failure",
                generateSequence(failure) { it.cause }
                    .any { it is org.ghost.storage.StorageFullException },
            )
            assertTrue("the bus did not count the injection", world.bus.storageFulls > 0)
            assertTrue("a full disk was counted as a death", world.bus.injected.isEmpty())
        }
    }

    /** 7: R-K1 runs at every open, and the log is empty after it. */
    @Test
    fun everyOpenRunsTheCheckpointOfRK1() {
        requireNative()
        DmCrashWorld("self-test-rk1").use { world ->
            val node = world.node("alice", 0x41)
            node.device.engine.onActivated()
            world.advanceBy(DmWorld.HOUR)
            node.device.timeTriggeredPass()
            assertTrue(
                "the sweep pass left no write-ahead log to truncate: the control is vacuous",
                node.walFile.exists() && node.walFile.length() > 0L,
            )
            node.reboot()
            assertTrue("R-K1 did not truncate the log at the open", node.lastOpenTruncated)
            assertEquals(
                "the log held ${node.walBytesAfterOpen} bytes after R-K1",
                0L,
                node.walBytesAfterOpen,
            )
        }
    }
}
