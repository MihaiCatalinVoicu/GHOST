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
        // The name of this test is "at the fourth offer" and for a while it asserted only "within
        // five rounds": a guard that consumed the blob at the **first** offer — an immediate,
        // undeclared loss of a message that may simply have arrived during a bad minute — would
        // have passed it, and so would one that consumed it at the tenth.
        //
        // The number the port sees is one less than the threshold, and that is exactly right.
        // `ReceiveStep.POISON_OFFERS` is 4 and the guard is `blob.offers >= 4` over the count
        // **committed before the hand-off**, so the blob reaches the ratchet at offers 1, 2 and 3
        // and the fourth offer consumes it unprocessed. Three deaths is "consumed as poison at the
        // fourth offer".
        assertEquals(
            "the blob reached the ratchet $deaths times; §7.6 offers it " +
                "${POISON_THRESHOLD - 1} times and consumes it at the ${POISON_THRESHOLD}th",
            POISON_THRESHOLD - 1,
            deaths,
        )
    }

    /**
     * SCN-J's third fault, and the one three doc comments claimed and nothing produced: a **caught
     * Rust panic**.
     *
     * It comes back through the closed JNI surface as the `INTERNAL` result code, which
     * `crypto-bridge` raises as an `IllegalStateException` — an ordinary typed failure, not a
     * death. §15.3's sentence is that it "rolls back and crashes like any `IllegalStateException`",
     * and this is what that turns out to mean, measured rather than assumed:
     *
     *  - the **process lives**. Nothing reboots; the actor swallows the exception and the pass is
     *    owed again at the next trigger, which is what distinguishes it from a `SimulatedNativeCrash`;
     *  - the transaction **rolls back**, so nothing half-applied survives and the invariants hold;
     *  - and it **does** spend the blob's offer budget, exactly as a death does. The counter is
     *    write-ahead — raised and committed *before* the blob is handed over — so it cannot tell
     *    which way the hand-off failed, and that is the point of it: a blob that fails the same way
     *    every time is a stalled inbox whether the failure is a SIGSEGV or a panic. The declared
     *    loss of §7.6 is therefore the answer to both. What must *not* reach the threshold is a
     *    rolled-back **SQL** failure, which never reaches the ratchet at all, and SCN-J's
     *    `alwaysChecks` is what asserts that.
     *
     * Three doc comments asserted this case existed — `FaultyDmSqlExecutor`'s, `DmCrashCore`'s and
     * this file's — and `INTERNAL` appeared nowhere else in the harness. Now it does.
     */
    @Test
    fun aCaughtRustPanicRollsBackAndNeverReachesThePoisonThreshold() {
        requireNative()
        val panics = java.util.concurrent.atomic.AtomicInteger()
        DmCrashWorld("internal").use { world ->
            world.node("alice", 0x41)
            val bob = world.node("bob", 0x51)
            DmScripts.activate(world)
            DmScripts.establishBothWays(world, "alice", "bob")
            bob.decorate = { real -> PanickingEnvelopes(real, panics) }
            bob.reboot()
            DmStructuralInvariants.check(bob, "internal setup reboot")
            val bootsBefore = bob.boots

            world["alice"].device.engine.send(
                DmScripts.contact(world, "alice", "bob"), "internal", null,
            )
            world.pump()
            for (round in 1..6) {
                world.passes()
                world.advanceBy(DmWorld.HOUR)
                world.pump()
            }
            assertTrue("the port never raised INTERNAL: the case is vacuous", panics.get() > 0)
            assertEquals(
                "a caught INTERNAL killed the process: $bob rebooted",
                bootsBefore,
                bob.boots,
            )
            assertTrue(
                "a caught INTERNAL was not caught: nothing reached the actor's swallow",
                world.swallowed.any { it.message?.contains("INTERNAL") == true },
            )
            DmStructuralInvariants.check(bob, "after the caught panics")
            assertEquals(
                "a caught INTERNAL that recurs for ever did not become the declared loss of §7.6",
                1,
                bob.device.engine.status().poisoned,
            )
            assertEquals(
                "the blob reached the ratchet ${panics.get()} times under a caught panic",
                POISON_THRESHOLD - 1,
                panics.get(),
            )
            assertTrue(
                "a caught INTERNAL rendered a message it could not decrypt",
                DmScripts.inboundTexts(world, "bob").none { it == "internal" },
            )
        }
    }

    /** MC-12: without the write-ahead counter the fourth offer never comes. */
    @Test
    fun mc12OffersIgnoredIsDetected() {
        // The skip guard runs **first**, as it does in every other test here. Running the world and
        // then deciding whether the run counted meant that, without the library, the mutated world
        // was built anyway, `runCatching` swallowed whatever it threw, and the assumption hid it.
        requireNative()
        // And the control: the same run without the mutation passes, so "the mutated run failed"
        // is a statement about the mutation and not about the case.
        poisonRun(mutation = null)
        val failure = runCatching { poisonRun(DmMutants.MC12) }.exceptionOrNull()
        assertTrue(
            "MC-12 was not detected: a blob that kills RECV was still consumed as poison",
            failure is AssertionError,
        )
        val message = generateSequence(failure) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" | ")
        assertTrue(
            "MC-12 failed, but not for the reason its entry names.\n" +
                "  expected to contain: ${DmMutants.MC12.expect}\n  actual: $message",
            message.contains(DmMutants.MC12.expect),
        )
        DmKills.record(DmMutants.MC12.id, message)
    }

    /**
     * A `DmEnvelopes` that raises the closed surface's `INTERNAL` — a **caught** Rust panic — on
     * every decrypt. An ordinary exception, deliberately: nothing about it is a process death.
     */
    private class PanickingEnvelopes(
        private val real: DmEnvelopes,
        val panics: java.util.concurrent.atomic.AtomicInteger,
    ) : DmEnvelopes by real {
        override fun decrypt(
            contactId: ByteArray,
            current: DmSessions.StoredSlot?,
            previous: DmSessions.StoredSlot?,
            l1: ByteArray,
            isPreKey: Boolean,
            today: Int,
        ): DmSessions.Decrypted =
            throw IllegalStateException("INTERNAL: ${panics.incrementAndGet()}")
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
            // §15.3 has no exception for a reboot the setup performs: a reboot with no invariant
            // check is a reboot that proves nothing about the state it came back to.
            DmStructuralInvariants.check(bob, "poison setup reboot")
            DmStructuralInvariants.checkpointEmptiedTheLog(bob, "poison setup reboot")

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

    private companion object {
        /** §7.6: the blob is consumed unprocessed at the fourth offer. */
        const val POISON_THRESHOLD: Int = 4
    }

    private fun offers(node: DmNode): Long {
        var out = 0L
        node.raw.query("SELECT max(offers) FROM inbox_blob") { if (!it.isNull(0)) out = it.long(0) }
        return out
    }
}
