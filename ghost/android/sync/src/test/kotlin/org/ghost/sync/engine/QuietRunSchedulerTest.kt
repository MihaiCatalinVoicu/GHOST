package org.ghost.sync.engine

import org.ghost.sync.api.IssuerAccess
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.engine.EngineWorld.Companion.MINUTE
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.port.TransportLease
import org.ghost.sync.store.FixedRandom
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier
import org.ghost.sync.api.SessionKind as ParticipantKind

/**
 * The participant's schedule and gating (Phase 8 design §11.6, §12.2, §19.11, §19.14): one run in
 * eight is quiet, as a pure function of the process key and the run index; the decision takes no
 * other input (mutant M20 has nothing to read); the payment hold is U[20 min, 60 min]; each kind of
 * session grants only its access; an issuer access makes one call on a fresh, ended flow; calls are
 * cut to the session's time, refused inside a transaction and after the lease closed.
 */
class QuietRunSchedulerTest {

    private val clock = VirtualClock(EngineWorld.T0)

    private fun keyed(seed: Int) = KeyedRandomSources(ByteArray(32) { (it * 7 + seed).toByte() })

    private fun session(
        kind: ParticipantKind,
        lease: TransportLease,
        deadline: Long = Long.MAX_VALUE,
        c: SyncClock = clock,
        inTransaction: () -> Boolean = { false },
    ): ParticipantSession = QuietRunScheduler(keyed(1), c).session(kind, lease, deadline, { true }, inTransaction)

    private val issuerCalls: List<(IssuerAccess) -> Unit> = listOf(
        { it.requestInvoice(ByteArray(32), emptyList(), 2960) },
        { it.blindSign(ByteArray(16), ByteArray(32), ByteArray(32), 1, 2960, ByteArray(32), 16) },
        { it.invoiceStatus(ByteArray(16), ByteArray(32)) },
        { it.redeemInvite(ByteArray(354), ByteArray(32), 2960, ByteArray(32), 16) },
        { it.claimPayout(ByteArray(16), listOf(ByteArray(354)), "5") },
        { it.refreshCredit(ByteArray(354), ByteArray(32), ByteArray(32)) },
    )

    private fun redeem(s: ParticipantSession, deadlineMillis: Int = 60_000) =
        checkNotNull(s.relayRedeem).redeem(TestBytes.onion(1), TestBytes.namespace(1), ByteArray(354), ByteArray(16), deadlineMillis)

    @Test
    fun oneRunInEightIsQuiet() {
        val s = QuietRunScheduler(keyed(1), clock)
        val quiet = (0L until 80_000L).count { s.quiet(it) }
        // Binomial(80 000, 1/8): mean 10 000, standard deviation ≈ 93.5; the bound is ±6 of them.
        assertTrue("quiet runs: $quiet", quiet in 9_440..10_560)
    }

    @Test
    fun theDecisionIsAPureFunctionOfTheKeyAndTheRunIndex() {
        val a = keyed(1)
        val s = QuietRunScheduler(a, clock)
        val first = (0L until 4_000L).map { s.quiet(it) }
        // Draws on every other stream in between (backoff jitter, HIGH send delays, holds) change nothing,
        repeat(500) {
            a.selection()
            a.sendDelay()
            a.paymentHold(it.toLong())
        }
        assertEquals(first, (0L until 4_000L).map { s.quiet(it) })
        // nor the order of asking, nor another instance with the same key and another clock,
        val twin = QuietRunScheduler(keyed(1), VirtualClock(0))
        assertEquals(first, (3_999L downTo 0L).map { twin.quiet(it) }.reversed())
        // while another key gives another pattern.
        assertNotEquals(first, (0L until 4_000L).map { QuietRunScheduler(keyed(2), clock).quiet(it) })
        assertThrows(IllegalArgumentException::class.java) { s.quiet(-1) }
    }

    @Test
    fun theDecisionTakesTheRunIndexAndNothingElse() {
        // Mutant M20 (quiet when work is due) needs an input to read: the decision has none but the index.
        val quiet = QuietRunScheduler::class.java.methods.filter { it.name == "quiet" }
        assertEquals(1, quiet.size)
        assertEquals(listOf<Class<*>>(java.lang.Long.TYPE), quiet.single().parameterTypes.toList())
        assertEquals(
            listOf(listOf<Class<*>>(RandomSources::class.java, SyncClock::class.java)),
            QuietRunScheduler::class.java.constructors.map { it.parameterTypes.toList() },
        )
        val fields = QuietRunScheduler::class.java.declaredFields.filter { !Modifier.isStatic(it.modifiers) }.map { it.type }
        assertEquals(setOf<Class<*>>(RandomSources::class.java, SyncClock::class.java), fields.toSet())
        assertEquals(2, fields.size)
    }

    @Test
    fun thePaymentHoldIsDrawnBetweenTwentyAndSixtyMinutes() {
        val s = QuietRunScheduler(keyed(3), clock)
        val holds = (0L until 10_000L).map { s.paymentHoldMillis(it) }
        assertTrue(holds.all { it >= 20 * MINUTE && it < 60 * MINUTE })
        assertTrue(holds.min() < 21 * MINUTE && holds.max() > 59 * MINUTE)
        assertEquals(40 * MINUTE, QuietRunScheduler(FixedRandom(), clock).paymentHoldMillis(0))
        val edges = object : RandomSources by FixedRandom() {
            override fun paymentHold(index: Long): Double = if (index == 0L) 0.0 else Math.nextDown(1.0)
        }
        assertEquals(20 * MINUTE, QuietRunScheduler(edges, clock).paymentHoldMillis(0))
        assertTrue(QuietRunScheduler(edges, clock).paymentHoldMillis(1) < 60 * MINUTE)
    }

    @Test
    fun eachKindOfSessionGrantsOnlyItsAccess() {
        for (kind in ParticipantKind.entries) {
            val s = session(kind, RecordingLease())
            val relay = kind == ParticipantKind.FOREGROUND || kind == ParticipantKind.BACKGROUND
            assertEquals(kind, s.kind)
            assertEquals("$kind redemption", relay, s.relayRedeem != null)
            assertEquals("$kind issuer", !relay, s.issuer != null)
            assertFalse(s.closed)
            assertTrue(s.clockTrusted())
        }
    }

    @Test
    fun anIssuerAccessMakesOneCallOnAFreshFlowAndEndsIt() {
        val lease = RecordingLease()
        for (first in issuerCalls) {
            val s = session(ParticipantKind.QUIET, lease)
            first(checkNotNull(s.issuer))
            for (other in issuerCalls) assertEquals("closed", category { other(checkNotNull(s.issuer)) })
        }
        val calls = lease.calls.calls
        assertEquals(listOf("requestInvoice", "blindSign", "invoiceStatus", "redeemInvite", "claimPayout", "refreshCredit"), calls.map { it.name })
        val flows = calls.map { checkNotNull(it.flow).toList() }
        assertEquals("a fresh flow for every call", 6, flows.toSet().size)
        assertEquals("every flow ended after its call", flows, lease.calls.ended.map { it.toList() })
        // A user issuer call is capped the same way.
        val user = session(ParticipantKind.USER_ISSUER_CALL, lease)
        checkNotNull(user.issuer).invoiceStatus(ByteArray(16), ByteArray(32))
        assertEquals("closed", category { checkNotNull(user.issuer).invoiceStatus(ByteArray(16), ByteArray(32)) })
    }

    @Test
    fun aFailedCallStillUsesTheAccessUpAndEndsItsFlow() {
        val lease = RecordingLease()
        lease.calls.failure = { "timeout" }
        val s = session(ParticipantKind.QUIET, lease)
        assertEquals("timeout", category { checkNotNull(s.issuer).requestInvoice(ByteArray(32), emptyList(), 2960) })
        assertEquals("closed", category { checkNotNull(s.issuer).requestInvoice(ByteArray(32), emptyList(), 2960) })
        assertEquals(1, lease.calls.calls.size)
        assertEquals(listOf(checkNotNull(lease.calls.calls.single().flow).toList()), lease.calls.ended.map { it.toList() })
    }

    @Test
    fun callsAreCutToTheTimeLeftAndNoneStartsAtTheEnd() {
        val c = VirtualClock(EngineWorld.T0).apply { millis = 100_000 }
        val lease = RecordingLease()
        val s = session(ParticipantKind.BACKGROUND, lease, deadline = 110_000, c = c)
        redeem(s, 60_000)
        redeem(s, 4_000)
        assertEquals(listOf(10_000, 4_000), lease.calls.calls.map { it.deadlineMillis })
        c.millis = 109_500
        assertEquals("closed", category { redeem(s) })
        assertFalse(s.closed)
        c.millis = 110_000
        assertTrue(s.closed)
        assertFalse(s.clockTrusted())
        assertEquals(2, lease.calls.calls.size)
    }

    @Test
    fun aClosedLeaseFailsEveryCallAndTrustsNoClock() {
        val lease = RecordingLease()
        val relay = session(ParticipantKind.FOREGROUND, lease)
        val quiet = session(ParticipantKind.QUIET, lease)
        lease.close()
        assertTrue(relay.closed && quiet.closed)
        assertFalse(relay.clockTrusted())
        assertEquals("closed", category { redeem(relay) })
        for (call in issuerCalls) assertEquals("closed", category { call(checkNotNull(session(ParticipantKind.QUIET, lease).issuer)) })
        assertEquals(0, lease.calls.calls.size)
    }

    @Test
    fun aCallFromInsideASyncTransactionIsRefused(): Unit = EngineWorld().use { w ->
        val lease = RecordingLease()
        val relay = session(ParticipantKind.FOREGROUND, lease) { w.db.inTransaction }
        val quiet = session(ParticipantKind.QUIET, lease) { w.db.inTransaction }
        w.tx {
            assertThrows(IllegalStateException::class.java) { redeem(relay) }
            assertThrows(IllegalStateException::class.java) { checkNotNull(quiet.issuer).invoiceStatus(ByteArray(16), ByteArray(32)) }
        }
        assertEquals(0, lease.calls.calls.size)
        redeem(relay)
        assertEquals(1, lease.calls.calls.size)
    }

    @Test
    fun stringsNeverShowSecrets() {
        val lease = RecordingLease()
        val s = session(ParticipantKind.QUIET, lease)
        assertEquals("ParticipantSession(QUIET)", s.toString())
        assertEquals("IssuerAccess", s.issuer.toString())
        assertEquals("RelayRedeemAccess", session(ParticipantKind.BACKGROUND, lease).relayRedeem.toString())
        assertEquals("QuietRunScheduler", QuietRunScheduler(keyed(1), clock).toString())
    }
}
