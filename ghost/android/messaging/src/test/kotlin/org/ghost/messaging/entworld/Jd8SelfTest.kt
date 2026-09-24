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
 * cover the week, a planner that met no LOCAL need, a client who holds no token making calls. T27's
 * minute is reported and not compared (`Jd8`'s note), and a case shows that it is counted and does
 * not decide. The kills of `DmPrivacyMutantTest` show the same checks failing on real worlds; this
 * shows the arithmetic under them.
 */
class Jd8SelfTest {

    private val w0 = EntDmScenario.WEEK0

    /** A trace that covers the week: two redemptions (weeks w0, w0 + 1) and a registration of each period. */
    private fun trace(client: String, ns: String, offsetMinutes: Long = 0, exposedAt: Int = -1): List<Jd8.Call> {
        val calls = ArrayList<Jd8.Call>()
        fun at(m: Long) = (m + offsetMinutes) * MINUTE + 1_234
        calls += Jd8.Call(client, CallKind.REDEEM, "S0", ns, w0, null, at(2))
        calls += Jd8.Call(client, CallKind.REDEEM, "S0", ns, w0 + 1, null, at(2_800))
        for ((i, p) in listOf(w0, w0 + 1, w0 + 2).withIndex()) calls += Jd8.Call(client, CallKind.REGISTER, "S0", ns, p, "deposit", at(30L + 3_000 * i))
        return calls.mapIndexed { i, c -> if (i == exposedAt) Jd8.Call(c.client, c.kind, c.relay, c.namespaceHex, c.period, c.keyKind, c.atMillis, exposed = true) else c }
    }

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
                "; T27's minute measured, not compared (DM work moves the redeem lane's steps, §22.24): 20 of 20 pairs in the same " +
                    "minute, 20 at the same millisecond, 1 after a message in their relay session (1 redemptions, 0 registrations)",
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
    fun theMinuteIsCountedAndDoesNotDecide() {
        val active = activeCalls().toMutableMap()
        val carol = active.getValue("carol")
        active["carol"] = carol.mapIndexed { i, c -> if (i == 2) Jd8.Call(c.client, c.kind, c.relay, c.namespaceHex, c.period, c.keyKind, c.atMillis + 40_000) else c }
        val sameMinute = result(active = active)
        assertTrue(sameMinute.line(), sameMinute.passed)
        assertEquals(20, sameMinute.timing.sameMinute)
        assertEquals(19, sameMinute.timing.sameMillis)
        active["carol"] = carol.mapIndexed { i, c -> if (i == 2) Jd8.Call(c.client, c.kind, c.relay, c.namespaceHex, c.period, c.keyKind, c.atMillis + MINUTE) else c }
        val moved = result(active = active)
        assertTrue("a call a minute later is measured, not a failure: ${moved.line()}", moved.passed)
        assertTrue(moved.line(), moved.line().contains(": 19 of 20 pairs in the same minute, 19 at the same millisecond,"))
        assertEquals(listOf("carol REGISTER S0 ${ns("carol").take(16)} p$w0 deposit at minute 30 idle, 31 active"), moved.timing.moved)
        // And no message before any call: reported, not a failure either.
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
