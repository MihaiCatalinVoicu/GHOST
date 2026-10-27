package org.ghost.update.harness

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Crash enumeration at every SQL statement of the §9.6.1 transactions (the F7 §8.3 method,
 * the sync harness's discipline): for each statement index k of one full benign flow — START
 * (the first epoch), one update run (the mirror set, the fetches, ACCEPT's BEGIN/UPDATE/
 * COMMIT, the staging steps, RUN-END) and the install commit — the world injects process death
 * before that statement, reboots the client (the connection closes, SQLite rolls the open
 * transaction back, the file survives), re-checks the structural invariants on the durable
 * state, continues the flow, and asserts the outcome equals the no-crash control. File
 * operations are covered by their own crash rules through the resume paths (a torn `.part`
 * re-downloads its range; a `.apk` with a `partial` row is re-checked) — the engine's write-
 * then-advance order is what makes `received` never exceed what is on disk.
 */
class CrashEnumerationTest {

    private fun assumeHostLibrary() = assumeTrue(
        "ghost-client-net host library not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    /** The full flow under test. */
    private class Trace {
        var statements: Long = 0
    }

    /** Process death at one SQL statement: the counter fires once and is then inert, and it
     *  survives [org.ghost.update.harness.Client.reopen]'s re-wrap (the state is shared). */
    private class Crash(val at: Long) : RuntimeException("process death at SQL statement $at")

    private fun scenario(world: World, client: Client) {
        val a = world.mirror()
        val b = world.mirror()
        client.firstStart()
        client.updateRun(a, b)
        client.updates.install().commit()
    }

    /** The structural invariants on the durable state, at every reboot (§9.6.1's crash rules). */
    private fun checkInvariants(world: World, client: Client) {
        val loaded = client.store.load()
        if (loaded != null) {
            // The stored facts decode and their columns agree with the blob (the ACCEPT
            // transaction is all-or-nothing: a crash mid-transaction leaves the previous facts).
            assertNotNull(loaded.blob)
            assertTrue(loaded.facts.manifestSeq >= 0)
            assertEquals((loaded.facts.manifestSeq == 0L), loaded.facts.manifestFile == null)
            assertEquals((loaded.facts.manifestFile == null), loaded.facts.manifestSha256 == null)
        }
        val staged = client.store.staged()
        if (staged != null) {
            assertTrue("received never exceeds the length", staged.received in 0..staged.apkLength)
            assertTrue(
                "received advances in whole ranges",
                staged.received % ModelMirror.CHUNK == 0L || staged.received == staged.apkLength,
            )
            val hex = staged.sha256.toHex()
            when (staged.state) {
                // STAGE-CHUNK's rule: `received` never exceeds what is on disk — and the row
                // may precede the file (a crash between stageBegin and the first write leaves
                // a partial row with no `.part`; the resume creates it and re-downloads from
                // `received`), so absence here is a legal mid-step state, not a tear.
                "partial" -> Unit
                // STAGE-VERIFY's rule: the `.apk` exists at the row's length.
                "verified", "committed" -> {
                    val apk = java.io.File(client.files, "$hex.apk")
                    assertTrue(apk.isFile)
                    assertEquals(staged.apkLength, apk.length())
                }
                else -> throw AssertionError("unknown staged state ${staged.state}")
            }
        }
    }

    /** The outcome-truth: the flow's end state must equal the no-crash control's. */
    private fun checkOutcome(world: World, client: Client) {
        val loaded = client.store.load()!!
        assertArrayEquals(world.fixtures.manifestSha256, loaded.facts.manifestSha256)
        assertArrayEquals(world.fixtures.doc("manifest-1.ghrm"), loaded.facts.manifestFile)
        assertEquals("verified", client.store.staged(world.fixtures.apkSha256)!!.state)
        // A crash point may split the install across the two phases (once at most: the
        // continuation commits what the crashed pass began), so 1–2 sessions, all exact bytes.
        assertTrue(client.installer.sessions.size in 1..2)
        client.installer.assertAllEqual(world.fixtures.apk)
    }

    @Test
    fun everySqlStatementCrashLeavesStateConsistentAndTheOutcomeEqualsTheControl() {
        assumeHostLibrary()
        // The control: one uneventful pass, counting the statements the flow makes.
        val trace = Trace()
        val statements = World("crash-control", seed = 41).use { world ->
            val counting = { raw: org.ghost.storage.SqlExecutor ->
                object : org.ghost.storage.SqlExecutor by raw {
                    override fun exec(sql: String, args: List<Any?>) { trace.statements++; raw.exec(sql, args) }
                    override fun execUpdate(sql: String, args: List<Any?>): Int { trace.statements++; return raw.execUpdate(sql, args) }
                    override fun query(sql: String, args: List<Any?>, onRow: (org.ghost.storage.SqlExecutor.Row) -> Unit) {
                        trace.statements++; raw.query(sql, args, onRow)
                    }
                }
            }
            val control = world.client(installed = 1, sdk = 29, wrap = counting)
            scenario(world, control)
            val scenarioStatements = trace.statements // before checkOutcome's own queries join the count
            checkOutcome(world, control)
            scenarioStatements
        }

        // The enumeration: process death before statement k, reboot, continue, compare.
        var enumerated = 0
        for (k in 0 until statements) {
            World("crash-$k", seed = 42).use { world ->
                // [0] counts the statements, [1] is the crash point; the wrapper is rebuilt on
                // reopen over the same state, and the counter never fires twice.
                val state = longArrayOf(0, k.toLong())
                val injector = { raw: org.ghost.storage.SqlExecutor ->
                    object : org.ghost.storage.SqlExecutor by raw {
                        private fun event() {
                            val n = state[0]++
                            if (n == state[1]) throw Crash(n)
                        }
                        override fun exec(sql: String, args: List<Any?>) { event(); raw.exec(sql, args) }
                        override fun execUpdate(sql: String, args: List<Any?>): Int { event(); return raw.execUpdate(sql, args) }
                        override fun query(sql: String, args: List<Any?>, onRow: (org.ghost.storage.SqlExecutor.Row) -> Unit) {
                            event(); raw.query(sql, args, onRow)
                        }
                    }
                }
                val client = world.client(installed = 1, sdk = 29, wrap = injector)
                try {
                    scenario(world, client)
                } catch (e: Crash) {
                    assertEquals(k.toLong(), e.at)
                }
                enumerated++
                try {
                    // The reboot: the previous connection is gone (its open transaction rolled
                    // back); the durable state must already satisfy the invariants.
                    client.reopen()
                    checkInvariants(world, client)
                    // The continuation: the flow is idempotent where it already completed (an
                    // accepted manifest answers UNCHANGED; a staged download resumes; the install
                    // commit re-checks the verified row before streaming). A crash that
                    // interrupted START leaves no row: §9.6.1's rule — the next start repeats
                    // it (the world's firstStart, with the fixture chain).
                    if (client.store.isEmpty()) client.firstStart()
                    val a = world.mirror()
                    val b = world.mirror()
                    client.updateRun(a, b)
                    client.updates.install().commit()
                    checkInvariants(world, client)
                    checkOutcome(world, client)
                } catch (t: Throwable) {
                    throw AssertionError("crash point k=$k of $statements", t)
                }
            }
        }
        assertEquals(statements, enumerated.toLong())
    }

    private fun ByteArray.toHex(): String {
        val alphabet = "0123456789abcdef"
        return joinToString("") { b -> "${alphabet[(b.toInt() shr 4) and 15]}${alphabet[b.toInt() and 15]}" }
    }
}
