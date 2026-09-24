package org.ghost.messaging.entworld

import org.ghost.messaging.api.Establishment
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.World.Companion.MINUTE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JD8's comparator held to known answers over hand-built twins (no world, no native library): a
 * pair that agrees passes, and each way a trace can depend on DM activity — an extra call in either
 * twin, a call on a namespace the client does not own — fails for its own reason, as does each way
 * the comparison could be vacuous: twins that did not reach their variable, a trace that does not
 * cover the week, a planner that met no LOCAL need, a client who holds no token making calls — and
 * each way a call's time can move: a registration at another minute fails, a redemption in another
 * relay session fails, a redemption at another minute of the same session is counted and does not
 * decide (`Jd8`'s note: the harness cannot test a redemption's minute). The kills of
 * `DmPrivacyMutantTest` and the timing leaks of `DmJd8Test` show the same checks failing on real
 * worlds; this shows the arithmetic under them.
 */
class Jd8SelfTest {

    private val w0 = EntDmScenario.WEEK0

    /**
     * A trace that covers the week: two redemptions (weeks w0, w0 + 1) and a registration of each
     * period, each in the session that started at the quarter hour before it.
     */
    private fun trace(client: String, ns: String, exposedAt: Int = -1): List<Jd8.Call> {
        val calls = ArrayList<Jd8.Call>()
        fun at(m: Long) = m * MINUTE + 1_234
        calls += call(client, CallKind.REDEEM, ns, w0, null, at(2))
        calls += call(client, CallKind.REDEEM, ns, w0 + 1, null, at(2_806))
        for ((i, p) in listOf(w0, w0 + 1, w0 + 2).withIndex()) calls += call(client, CallKind.REGISTER, ns, p, "deposit", at(30L + 3_000 * i))
        return calls.mapIndexed { i, c -> if (i == exposedAt) moved(c, 0, exposed = true) else c }
    }

    private fun call(client: String, kind: CallKind, ns: String, period: Long, keyKind: String?, atMillis: Long): Jd8.Call =
        Jd8.Call(client, kind, "S0", ns, period, keyKind, atMillis, session = atMillis / (15 * MINUTE) * (15 * MINUTE))

    /** [c] [by] ms later, in [session] (its own by default), exposed or not. */
    private fun moved(c: Jd8.Call, by: Long, session: Long? = c.session, exposed: Boolean = c.exposed): Jd8.Call =
        Jd8.Call(c.client, c.kind, c.relay, c.namespaceHex, c.period, c.keyKind, c.atMillis + by, exposed, session)

    private fun ns(client: String): String = client.padEnd(64, '0').map { if (it in '0'..'9' || it in 'a'..'f') it else 'e' }.joinToString("")

    private fun twin(
        active: Boolean,
        calls: Map<String, List<Jd8.Call>>,
        contacts: Int = if (active) 4 else 0,
        foreign: Int = if (active) 7 else 0,
        undelivered: List<String> = emptyList(),
        failure: String? = null,
        unresolved: Int = 0,
    ): Jd8.Twin {
        val names = Jd8.COMPARED + "dave"
        return Jd8.Twin(
            active = active,
            calls = names.associateWith { calls[it].orEmpty() },
            own = names.associateWith { setOf(ns(it)) },
            foreignDmCalls = names.associateWith { if (it == "dave") 0 else foreign },
            contacts = names.associateWith { if (it == "alice") contacts else if (active && it != "dave") 1 else 0 },
            undelivered = undelivered,
            delivered = if (active) 94 else 0,
            daveEstablishment = if (active) Establishment.UNREACHABLE else null,
            localSkipped = if (active) 12 else 0,
            unresolved = unresolved,
            failure = failure,
            millis = 0,
        )
    }

    private fun idleCalls(): Map<String, List<Jd8.Call>> = Jd8.COMPARED.associateWith { trace(it, ns(it)) }

    private fun activeCalls(): Map<String, List<Jd8.Call>> =
        Jd8.COMPARED.associateWith { trace(it, ns(it), exposedAt = if (it == "alice") 1 else -1) }

    private fun result(idle: Map<String, List<Jd8.Call>> = idleCalls(), active: Map<String, List<Jd8.Call>> = activeCalls()): Jd8.Result =
        Jd8.Result(twin(false, idle), twin(true, active))

    @Test
    fun twinsThatAgreePass() {
        val r = result()
        assertTrue(r.line(), r.passed)
        assertTrue(r.line(), r.line().startsWith("dm JD8: PASS twins of 0 vs 4 contacts"))
        assertTrue(r.line(), r.line().contains("over 20 calls (alice 2+3, bob 2+3, carol 2+3, erin 2+3 redeem+register), every one on an own namespace; each covers"))
        assertTrue(
            r.line(),
            r.line().endsWith(
                "; T27's time compared: registrations to the minute (12 of 12 pairs in the same minute), redemptions to their " +
                    "relay session (8 of 8 pairs in the same session; the harness cannot test their minute, §22.26: 8 of 8 in the " +
                    "same minute); 20 of 20 pairs at the same millisecond, 1 after a message in their relay session (1 redemptions, " +
                    "0 registrations)",
            ),
        )
    }

    @Test
    fun anExtraRedemptionInTheActiveTwinFails() {
        val active = activeCalls().toMutableMap()
        active["alice"] = active.getValue("alice") + Jd8.Call("alice", CallKind.REDEEM, "S1", ns("bob"), w0, null, 400 * MINUTE)
        val r = result(active = active)
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("alice: 1 calls only in the active twin ({REDEEM=1}"))
        assertTrue(r.line(), r.line().contains("none only in the idle twin"))
        // A FAIL line does not carry a PASS line's claims.
        assertTrue(r.line(), r.line().startsWith("dm JD8: FAIL") && r.line().contains(" compared as ") && !r.line().contains(" equal as "))
        assertFalse(r.line(), r.line().contains("every one on an own namespace"))
        // The own-namespace half sees it too.
        assertTrue(r.line(), r.line().contains("names a namespace it does not own: active alice REDEEM S1"))
    }

    @Test
    fun aRegistrationMissingFromTheActiveTwinFailsOnTheIdleSide() {
        val active = activeCalls().toMutableMap()
        active["bob"] = active.getValue("bob").filterNot { it.kind == CallKind.REGISTER && it.period == w0 + 2 }
        val r = result(active = active)
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("bob: none only in the active twin, 1 calls only in the idle twin ({REGISTER=1}"))
        assertFalse("an idle-side difference must not read as an active-side one", r.line().contains("calls only in the active twin"))
        assertTrue(r.line(), r.line().contains("active bob registered no period [${w0 + 2}]"))
    }

    @Test
    fun aRegistrationAtAnotherMinuteFails() {
        val active = activeCalls().toMutableMap()
        val carol = active.getValue("carol")
        active["carol"] = carol.mapIndexed { i, c -> if (i == 2) moved(c, 40_000) else c }
        val sameMinute = result(active = active)
        assertTrue("40 s later, in the same minute: ${sameMinute.line()}", sameMinute.passed)
        assertEquals(20, sameMinute.timing.sameMinute)
        assertEquals(19, sameMinute.timing.sameMillis)
        active["carol"] = carol.mapIndexed { i, c -> if (i == 2) moved(c, MINUTE) else c }
        val later = result(active = active)
        assertFalse("a registration a minute later: ${later.line()}", later.passed)
        assertTrue(later.line(), later.line().contains("registrations to the minute (11 of 12 pairs in the same minute)"))
        assertTrue(
            later.line(),
            later.line().contains("; 1 registrations at another minute in the active twin (first: carol REGISTER S0 ${ns("carol").take(16)} p$w0 deposit at minute 30 idle, 31 active)"),
        )
        // Only the timing clause: nothing else differs, so this is not a count difference.
        assertTrue(later.line(), later.differences.isEmpty() && later.unreached.isEmpty() && later.coverage.isEmpty())
        // A registration a minute earlier fails as well.
        active["carol"] = carol.mapIndexed { i, c -> if (i == 2) moved(c, -MINUTE) else c }
        assertFalse(result(active = active).passed)
    }

    @Test
    fun aRedemptionIsComparedByItsRelaySession() {
        val active = activeCalls().toMutableMap()
        val bob = active.getValue("bob")
        // Two minutes later in the same session: its minute is counted, not compared.
        active["bob"] = bob.mapIndexed { i, c -> if (i == 1) moved(c, 2 * MINUTE) else c }
        val sameSession = result(active = active)
        assertTrue("a redemption at another minute of its session: ${sameSession.line()}", sameSession.passed)
        assertTrue(
            sameSession.line(),
            sameSession.line().contains("(8 of 8 pairs in the same session; the harness cannot test their minute, §22.26: 7 of 8 in the same minute)"),
        )
        assertEquals(listOf("bob REDEEM S0 ${ns("bob").take(16)} p${w0 + 1} at minute 2806 idle, 2808 active"), sameSession.timing.moved)
        // In the next session: a failure.
        active["bob"] = bob.mapIndexed { i, c -> if (i == 1) moved(c, 15 * MINUTE, session = c.session!! + 15 * MINUTE) else c }
        val nextSession = result(active = active)
        assertFalse(nextSession.line(), nextSession.passed)
        assertTrue(nextSession.line(), nextSession.line().contains("(7 of 8 pairs in the same session;"))
        assertTrue(
            nextSession.line(),
            nextSession.line().contains(
                "; 1 redemptions in another relay session in the active twin (first: bob REDEEM S0 ${ns("bob").take(16)} p${w0 + 1} at minute 2806 " +
                    "in the session of minute 2805 idle, 2821 in the session of minute 2820 active)",
            ),
        )
        assertTrue(nextSession.line(), nextSession.differences.isEmpty() && nextSession.unreached.isEmpty() && nextSession.coverage.isEmpty())
        // At the same millisecond but outside any session in both twins: not "the same session".
        val idle = idleCalls().toMutableMap()
        idle["bob"] = idle.getValue("bob").mapIndexed { i, c -> if (i == 1) moved(c, 0, session = null) else c }
        active["bob"] = bob.mapIndexed { i, c -> if (i == 1) moved(c, 0, session = null) else c }
        val none = result(idle, active)
        assertFalse(none.line(), none.passed)
        assertTrue(none.line(), none.line().contains("in the session of minute none idle"))
        // And no message before any call: reported, not a failure.
        val unexposed = result(active = idleCalls())
        assertTrue(unexposed.line(), unexposed.passed)
        assertTrue(unexposed.line(), unexposed.line().contains(", 0 after a message in their relay session (0 redemptions, 0 registrations)"))
    }

    @Test
    fun aCallOnANamespaceTheClientDoesNotOwnFailsEvenInBothTwins() {
        val extra = Jd8.Call("erin", CallKind.REGISTER, "S2", ns("carol"), w0, "read", 900 * MINUTE)
        val idle = idleCalls().toMutableMap().also { it["erin"] = it.getValue("erin") + extra }
        val active = activeCalls().toMutableMap().also { it["erin"] = it.getValue("erin") + extra }
        val r = result(idle, active)
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("names a namespace it does not own: idle erin REGISTER S2"))
    }

    @Test
    fun aTraceThatDoesNotCoverTheWeekFails() {
        val cut = { m: Map<String, List<Jd8.Call>> -> m.mapValues { (_, calls) -> calls.filterNot { it.kind == CallKind.REDEEM && it.period == w0 + 1 } } }
        val r = result(cut(idleCalls()), cut(activeCalls()))
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("coverage: idle alice redeemed no token of week(s) [${w0 + 1}]"))
        val empty = result(emptyMap(), emptyMap())
        assertFalse(empty.line(), empty.passed)
        assertTrue(empty.line(), empty.line().contains("no paired call: compared nothing"))
    }

    @Test
    fun anActiveTwinWhosePlannerMetNoLocalNeedFails() {
        val active = twin(true, activeCalls())
        val none = Jd8.Twin(
            active.active, active.calls, active.own, active.foreignDmCalls, active.contacts, active.undelivered, active.delivered,
            active.daveEstablishment, localSkipped = 0, unresolved = 0, failure = null, millis = 0,
        )
        val r = Jd8.Result(twin(false, idleCalls()), none)
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("alice's planner skipped no LOCAL need in the active twin"))
        // Coverage, not reach: PM-1b's own world skips none, and its kill must still count.
        assertFalse(r.line(), r.line().contains("did not reach their variable"))
    }

    @Test
    fun aClientWithoutTokensThatCallsFails() {
        val active = activeCalls().toMutableMap()
        active["dave"] = listOf(Jd8.Call("dave", CallKind.REDEEM, "S0", ns("dave"), w0, null, 10 * MINUTE))
        val r = result(active = active)
        assertFalse(r.line(), r.passed)
        assertTrue(r.line(), r.line().contains("active dave, who holds no token, made 1 calls"))
    }

    @Test
    fun twinsThatDidNotReachTheirVariableFail() {
        val cases = mapOf(
            "idle with a contact" to Jd8.Result(twin(false, idleCalls(), contacts = 1), twin(true, activeCalls())),
            "idle with DM traffic" to Jd8.Result(twin(false, idleCalls(), foreign = 3), twin(true, activeCalls())),
            "active without contacts" to Jd8.Result(twin(false, idleCalls()), twin(true, activeCalls(), contacts = 0)),
            "active without DM traffic" to Jd8.Result(twin(false, idleCalls()), twin(true, activeCalls(), foreign = 0)),
            "a text never delivered" to Jd8.Result(twin(false, idleCalls()), twin(true, activeCalls(), undelivered = listOf("alice->bob 'x'"))),
            "a world that stopped" to Jd8.Result(twin(false, idleCalls()), twin(true, activeCalls(), failure = "InvariantViolation: x")),
            "a RegisterKey unread" to Jd8.Result(twin(false, idleCalls(), unresolved = 1), twin(true, activeCalls())),
            "one twin twice" to Jd8.Result(twin(true, activeCalls()), twin(true, activeCalls())),
        )
        for ((what, r) in cases) {
            assertFalse("$what: ${r.line()}", r.passed)
            assertTrue("$what: ${r.line()}", r.line().contains("the twins did not reach their variable"))
        }
    }
}
