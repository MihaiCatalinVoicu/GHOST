package org.ghost.messaging.harness

import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.DmWorld
import org.ghost.messaging.port.DmEnvelopes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * SCN-J's native half (Phase 9 design §15.1, §15.3):
 *
 * > `SimulatedNativeCrash` during RECV: re-offered alone, consumed as poison at the fourth offer
 * > (a declared loss)
 *
 * A `SimulatedNativeCrash` is the process-death model of a SIGSEGV or an uncaught native abort —
 * not a caught Rust panic, which comes back through the closed JNI surface as the `INTERNAL`
 * result code and is an ordinary typed failure. Nothing on the JVM side of that surface can catch
 * it, so the only thing that keeps one blob from killing every process that ever reaches it is the
 * **write-ahead** offer counter: the inbox raises `offers` and commits *before* the blob is handed
 * to RECV, so a process that dies inside RECV still leaves the count raised. At the fourth offer
 * the blob is consumed unprocessed and counted as poisoned, which is the declared loss.
 *
 * This is also the kill test for mutant MC-12 ("offers ignored"), whose whole content is that the
 * counter does not advance.
 */
class DmPoisonTest {

    private fun requireNative() = assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())

    /**
     * A `DmEnvelopes` that dies the way the native library would, on every attempt to decrypt.
     *
     * Kotlin's interface delegation keeps it to the one method that matters: every other call goes
     * to the real port, so the world is the real world right up to the moment RECV reaches the
     * ratchet.
     */
    private class DyingEnvelopes(
        private val real: DmEnvelopes,
        private val node: String,
        val deaths: java.util.concurrent.atomic.AtomicInteger,
    ) : DmEnvelopes by real {
        override fun decrypt(
            contactId: ByteArray,
            current: DmSessions.StoredSlot?,
            previous: DmSessions.StoredSlot?,
            l1: ByteArray,
            isPreKey: Boolean,
            today: Int,
        ): DmSessions.Decrypted = throw SimulatedNativeCrash(deaths.incrementAndGet().toLong(), node)
    }

    @Test
    fun aBlobThatKillsRecvIsConsumedAsPoisonAtTheFourthOffer() {
        requireNative()
        val deaths = poisonRun(mutation = null)
        assertTrue("the native port never died: the case is vacuous", deaths > 0)
    }

    /** MC-12: without the write-ahead counter the fourth offer never comes. */
    @Test
    fun mc12OffersIgnoredIsDetected() {
        val failure = runCatching { poisonRun(DmMutants.MC12) }.exceptionOrNull()
        assumeTrue(DmHarness.SKIP_MESSAGE, DmHarness.nativeAvailable())
        assertTrue(
            "MC-12 was not detected: a blob that kills RECV was still consumed as poison",
            failure is AssertionError,
        )
    }

    /**
     * Establishes A → B, kills B's port on every decrypt, and offers the blob until the guard
     * consumes it. Returns how many times the port died.
     *
     * Every death is a process death, so every one is followed by a real reboot: drop the
     * connection, reopen the file, migrate, R-K1, `verifyIntegrity`, build a new client. That is
     * the point — the counter has to survive exactly that.
     */
    private fun poisonRun(mutation: DmMutants.Mutation?): Int {
        val deaths = java.util.concurrent.atomic.AtomicInteger()
        DmCrashWorld("poison").use { world ->
            world.mutation = mutation
            world.node("alice", 0x41)
            val bob = world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")

            // From here on, every decrypt on B kills the process.
            bob.decorate = { real -> DyingEnvelopes(real, bob.name, deaths) }
            bob.reboot()

            world["alice"].device.engine.send(DmScripts.contact(world, "alice", "bob"), "poison", null)
            world.pump()

            // §7.6's poison guard consumes at the fourth offer, so five rounds is one more than it
            // needs and the extra round is what proves the blob is gone rather than merely quiet.
            var poisoned = 0
            for (round in 1..5) {
                try {
                    bob.device.timeTriggeredPass()
                } catch (death: SimulatedNativeCrash) {
                    bob.reboot()
                    DmStructuralInvariants.check(bob, "poison reboot $round")
                }
                poisoned = bob.device.engine.status().poisoned
                if (poisoned > 0) break
                world.advanceBy(DmWorld.HOUR)
            }
            assertEquals(
                "the blob was not consumed as poison after five offers " +
                    "(offers = ${offers(bob)}, deaths = ${deaths.get()})",
                1,
                poisoned,
            )
            // A declared loss, in both halves. The blob is a `done` tombstone — the schema resets
            // `offers` to 0 for a `done` row, so the counter itself is no longer the evidence —
            // and nothing was rendered from it.
            var tombstones = 0L
            bob.raw.query(
                "SELECT count(*) FROM inbox_blob WHERE state = 'done'",
            ) { tombstones = it.long(0) }
            assertTrue("the poisoned blob left no tombstone", tombstones > 0)
            assertTrue(
                "the poisoned message was rendered after all",
                DmScripts.inboundTexts(world, "bob").none { it == "poison" },
            )
        }
        return deaths.get()
    }

    private fun offers(node: DmNode): Long {
        var out = 0L
        node.raw.query("SELECT max(offers) FROM inbox_blob") { if (!it.isNull(0)) out = it.long(0) }
        return out
    }
}
