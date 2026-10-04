package org.ghost.messaging

import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.Establishment
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.engine.EstablishmentSteps
import org.ghost.messaging.port.ExpiryWake
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SyncChange
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The review of the privacy worlds on production's triggers (design §22.36, item 12): the actor's
 * trigger bindings as a world runs them — alice built with a [DmDevice.Wiring], so every trigger goes
 * through `DmTriggers`, the bindings `MessagingRuntime` itself is built with — on the real engine and
 * the real native library.
 *
 * The first review of the MD-2 fix (§22.34 item 6) drove `runPass` with a flag of its own choosing,
 * so nothing checked what the production entry points pass: a consumer tail, an in-process timer
 * wake, an alarm or a database open that opened a later bundle-fetch attempt passed every test and
 * every world (the review's mutants A, C and D), and so did a schedule without the `EST-READY` term
 * in the bindings the runtime used (B1). Each test here fails under one of those mutants.
 */
class TriggerBindingsTest {

    private fun requireNative() {
        assumeTrue("set -Dghost.dm.native", DmWorld.nativeAvailable())
    }

    /** The actor timer's scheduler under the wiring: the one pending wake, fired by the test. */
    private class ManualTimer {
        var delay: Long? = null
            private set
        private var task: (() -> Unit)? = null

        fun schedule(delay: Long, task: () -> Unit): () -> Unit {
            this.delay = delay
            this.task = task
            return {
                if (this.task === task) {
                    this.task = null
                    this.delay = null
                }
            }
        }

        /** The pending wake fires, as `ExpiryTimer`'s scheduler thread would at its time. */
        fun fire() {
            val pending = requireNotNull(task) { "no timer wake is pending" }
            task = null
            delay = null
            pending()
        }
    }

    private fun wiring(timer: ManualTimer): DmDevice.Wiring = DmDevice.Wiring(
        timer = timer::schedule,
        alarm = ExpiryWake { },
        failed = { throw AssertionError("a DM actor turn threw", it) },
    )

    /**
     * §21.7 point 5, phase review MD-2: "at the first relay session start at least 6 h later". With a
     * later attempt due, every production trigger that is **no** relay session start — the consumer
     * tail of a quiet run and of a background session, the alarm, a database open, the in-process
     * timer's wake and each listener hint — leaves the attempt count where it is; the relay session
     * start opens it. Under the review's mutant A (the tail as a session start) the tail opens it,
     * under C (the timer's wake as one) the timer does, under D (every time trigger a session start
     * unless it says otherwise) the alarm does.
     */
    @Test
    fun aLaterFetchAttemptOpensAtARelaySessionStartOnly() {
        requireNative()
        val timer = ManualTimer()
        DmWorld(aliceWiring = wiring(timer)).use { world ->
            val alice = world.alice
            alice.engine.onActivated()
            // Bob never publishes a bundle: every attempt window of alice's establishment runs out.
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            assertEquals("the send opened attempt 1", 1, attempts(alice))
            assertTrue("attempt 1's window is open", bundleListening(alice))

            // The window closes at its end: the alarm's pass runs EST-END.
            world.advanceTo(alice.clock.now + 16 * DmWorld.MINUTE)
            alice.alarmFired()
            assertFalse("EST-END closed the window", bundleListening(alice))
            assertEquals(1, attempts(alice))

            // Six hours on, attempt 2 is due.
            world.advanceTo(alice.clock.now + 6 * DmWorld.HOUR + DmWorld.MINUTE)
            val deadline = alice.clock.monotonicMillis() + 60_000
            val triggers = listOf<Pair<String, () -> Unit>>(
                "the consumer tail of a quiet run" to { alice.consumerTail.run(SessionKind.QUIET, deadline) },
                "the consumer tail of a background session" to { alice.consumerTail.run(SessionKind.BACKGROUND, deadline) },
                "the alarm" to { alice.alarmFired() },
                "a database open" to { alice.databaseOpen() },
                "the in-process timer's wake" to { timer.fire() },
                "the listener's hints" to {
                    alice.deliver(setOf(SyncChange.INBOX, SyncChange.OUTCOMES, SyncChange.CAPABILITIES, SyncChange.TOPOLOGY))
                },
            )
            for ((name, trigger) in triggers) {
                trigger()
                assertEquals("$name opened no attempt", 1, attempts(alice))
                assertFalse("$name opened no window", bundleListening(alice))
                assertEquals(Establishment.FETCHING, alice.engine.contacts().single().establishment)
            }

            // The relay session start opens it.
            alice.relaySessionStart()
            assertEquals("the relay session start opened attempt 2", 2, attempts(alice))
            assertTrue("attempt 2's window is open", bundleListening(alice))
        }
    }

    /**
     * Phase review MD-3 (§21.7 point 4, §21.9 rule 1's "next EST timer") on the bindings the runtime
     * uses: once a bundle candidate is stored, the actor timer is armed for its `EST-READY` two minutes
     * on, and that timer's own wake establishes. The same check in `PhaseReviewRegressionTest` reads a
     * device that drives its passes itself; under the review's mutant B1 (the schedule's `EST-READY`
     * term dropped in the runtime's bindings) this one fails and that one does not.
     */
    @Test
    fun theWiredTimerWakesForEstReady() {
        requireNative()
        val timer = ManualTimer()
        DmWorld(aliceWiring = wiring(timer)).use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            world.advanceTo(alice.clock.now + 30)
            world.deliver()
            // The fetch's commit hints the listener: a hint pass claims the bundle.
            alice.deliver(setOf(SyncChange.INBOX))
            assertEquals(1, count(alice, "SELECT count(*) FROM dm_bundle_candidate"))
            val delay = requireNotNull(timer.delay) { "the timer is not armed" }
            assertTrue(
                "the timer asks for EST-READY (${EstablishmentSteps.READY_DELAY_SECONDS} s after the candidate), got $delay",
                delay <= EstablishmentSteps.READY_DELAY_SECONDS,
            )
            world.advanceTo(alice.clock.now + delay)
            timer.fire()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
        }
    }

    /**
     * MD-3's wake survives a hint at its own second (design §22.39). The gate-scale nightlies of the
     * privacy world failed on JD5 from 2026-09-28 because of this: a listener hint handed to the actor
     * at the second a candidate's `EST-READY` fell due — a fetch or a store outcome of the relay round
     * that came first — ran a pass that may not run `EST-READY` (§21.9 rule 1), and that pass's
     * schedule left the due term out and re-armed the timer for the fetch window's end, cancelling the
     * wake that was due. Here the timer is still due at once after the hint pass, and its wake
     * establishes.
     */
    @Test
    fun aHintAtTheDueSecondKeepsTheEstReadyWake() {
        requireNative()
        val timer = ManualTimer()
        DmWorld(aliceWiring = wiring(timer)).use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            world.advanceTo(alice.clock.now + 30)
            world.deliver()
            alice.deliver(setOf(SyncChange.INBOX))
            assertEquals(1, count(alice, "SELECT count(*) FROM dm_bundle_candidate"))
            val delay = requireNotNull(timer.delay) { "the timer is not armed" }
            assertTrue("the timer asks for EST-READY, got $delay", delay in 1..EstablishmentSteps.READY_DELAY_SECONDS)

            // EST-READY falls due, and a hint reaches the actor before the timer's own wake.
            world.advanceTo(alice.clock.now + delay)
            alice.deliver(setOf(SyncChange.OUTCOMES))
            assertEquals(
                "a hint pass runs no EST-READY (§21.9 rule 1)",
                Establishment.FETCHING, alice.engine.contacts().single().establishment,
            )
            assertEquals("the due EST-READY keeps its wake, at once", 0L, timer.delay)
            timer.fire()
            assertEquals(Establishment.READY, alice.engine.contacts().single().establishment)
            assertEquals("the pending text went out with EST-READY", 0, count(alice, "SELECT count(*) FROM dm_pending_send"))
        }
    }

    /**
     * The other half of the wake [aHintAtTheDueSecondKeepsTheEstReadyWake] keeps: once a time-triggered
     * pass has run at or after the due second, a candidate it could not use wakes the actor no more.
     * Alice blocks bob while his candidate waits, so no pass ever establishes with it; the timer may
     * owe one wake at the due second, and after that wake no wake at once is armed again — a wake
     * loop is what keeping every due term would make of it.
     */
    @Test
    fun aDueEstReadyThatCannotRunIsNoWakeLoop() {
        requireNative()
        val timer = ManualTimer()
        DmWorld(aliceWiring = wiring(timer)).use { world ->
            val alice = world.alice
            val bob = world.bob
            alice.engine.onActivated()
            bob.engine.onActivated()
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
            world.advanceTo(alice.clock.now + 30)
            world.deliver()
            alice.deliver(setOf(SyncChange.INBOX))
            assertEquals(1, count(alice, "SELECT count(*) FROM dm_bundle_candidate"))
            val delay = requireNotNull(timer.delay) { "the timer is not armed" }
            assertTrue(alice.engine.block(contactB))

            world.advanceTo(alice.clock.now + delay)
            alice.deliver(setOf(SyncChange.OUTCOMES))
            if (timer.delay == 0L) timer.fire()
            assertTrue("a wake at once armed again after the time-triggered pass ran: a wake loop", timer.delay != 0L)
            alice.deliver(setOf(SyncChange.INBOX))
            assertTrue("a later hint pass armed a wake at once again", timer.delay != 0L)
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun count(device: DmDevice, sql: String): Int {
        var n = 0
        device.sql.query(sql) { if (!it.isNull(0)) n = it.long(0).toInt() }
        return n
    }

    private fun attempts(device: DmDevice): Int = count(device, "SELECT fetch_attempts FROM dm_contact")

    /** A contact's bundle namespace is listened to: an attempt window is open (the own one is write-only). */
    private fun bundleListening(device: DmDevice): Boolean =
        count(device, "SELECT count(*) FROM sync_namespace WHERE consumer = 'prekeys' AND listening = 1") > 0
}
