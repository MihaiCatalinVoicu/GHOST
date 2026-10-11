package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.ghost.messaging.entworld.Jd8
import org.ghost.messaging.entworld.Jd8TimingLeaks
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * JD8 (Phase 9 design §15.6, §14.1 T27) over the twin worlds of the entitlement world (`entworld/
 * EntDmJd8.kt`): a client's redemptions and registrations, as relays saw them, are the same — in
 * count, relay, namespace and week — with 0 and with 4 contacts and 95 texts; every one is on a
 * namespace the client owns; each registration falls in the same minute in both twins and each
 * redemption in the same relay session (its minute is measured and reported: the harness cannot
 * test it, `Jd8`'s note, §22.26). The lines go to the privacy report, which
 * `dm-report-check.sh privacy-suite` and `privacy-pr` require.
 *
 * Scale-independent, like the twins of `DmPrivacyWorldTest`: twin pairs of the first pinned seed.
 * Three things run here, each once per JVM (`Jd8.run` caches by seed, label and check):
 *  - the report's run, with the entitlement world's every-commit check on;
 *  - the **control** every mutated pair is held against — the same twins with that check off, the
 *    configuration of `DmPrivacyMutantTest`'s JD8 kills and of the timing leaks — which must see
 *    every relay call of the report's run at the same millisecond;
 *  - the two **timing leaks** of [Jd8TimingLeaks], each of which JD8 must fail by its timing clause
 *    alone, every count equal.
 */
class DmJd8Test {

    private fun requireNative() {
        assumeTrue(SKIP, DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
    }

    @Test
    fun jd8RedemptionsAndRegistrationsDependOnlyOnOwnNamespacesAndTheWeek() {
        requireNative()
        val result = Jd8.run(SEED, CONTROL, null, everyCommit = true)
        PrivacyReport.line(result.line())
        println("JD8 twins: idle ${result.idle.millis} ms, active ${result.active.millis} ms")
        println("JD8 relay calls seen: idle ${result.idle.seenCount}, active ${result.active.seenCount}; dave's: idle ${result.idle.daveSeen}, active ${result.active.daveSeen}")
        for (d in Jd8.timingDetail(result)) println("JD8 timing: $d")
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun theControlWithoutTheEveryCommitCheckSeesTheSameRelayCalls() {
        requireNative()
        val checked = Jd8.run(SEED, CONTROL, null, everyCommit = true)
        val unchecked = Jd8.run(SEED, CONTROL, null, everyCommit = false)
        val problems = sameRun(checked, unchecked)
        val ok = problems.isEmpty() && checked.passed && unchecked.passed
        val line = "dm JD8 control: ${if (ok) "PASS" else "FAIL"} the twins with the every-commit check off, the configuration every " +
            "JD8 kill and timing leak runs in, saw the same ${checked.idle.seenCount} and ${checked.active.seenCount} relay calls " +
            "(idle, active) at the same milliseconds as the report's run, and JD8 ${if (unchecked.passed) "passed" else "failed"} on them" +
            (if (problems.isEmpty()) "" else "; " + problems.joinToString("; "))
        PrivacyReport.line(line)
        println("JD8 control without the every-commit check: ${unchecked.line()}")
        assertTrue(line, ok)
    }

    @Test
    fun timingLeaksAreDetectedByTheTimingClauseAlone() {
        requireNative()
        val control = Jd8.run(SEED, CONTROL, null, everyCommit = false)
        assertTrue("the control fails: ${control.line()}", control.passed)
        val renewal = Jd8.run(SEED, "timing leak: renewal", Jd8TimingLeaks.RENEWAL_WAITS_FOR_TRAFFIC, everyCommit = false)
        val registration = Jd8.run(SEED, "timing leak: registration", Jd8TimingLeaks.REGISTRATION_WAITS_FOR_TRAFFIC, everyCommit = false)
        println("JD8 timing leak, renewal: ${renewal.line()}")
        println("JD8 timing leak, registration: ${registration.line()}")
        val renewalCaught = timingAlone(renewal) && renewal.timing.redemptionsOtherSession.isNotEmpty()
        val registrationCaught = timingAlone(registration) && registration.timing.registrationsMoved.isNotEmpty()
        val detected = listOf(renewalCaught, registrationCaught).count { it }
        val line = "dm JD8 timing leaks: ${if (detected == 2) "PASS" else "FAIL"} $detected of 2 detected by the timing clause alone, " +
            "every count equal in both twins: a renewal that waits for inbound traffic (${renewal.timing.redemptionsOtherSession.size} " +
            "redemptions in another relay session, ${renewal.timing.registrationsMoved.size} registrations at another minute, " +
            "of ${renewal.timing.pairs} pairs), later-week registrations that wait for inbound traffic or the week's last 10 h " +
            "(${registration.timing.registrationsMoved.size} registrations at another minute, " +
            "${registration.timing.redemptionsOtherSession.size} redemptions in another relay session, of ${registration.timing.pairs} pairs)"
        PrivacyReport.line(line)
        assertTrue("$line\n  renewal: ${renewal.line()}\n  registration: ${registration.line()}", detected == 2)
    }

    /**
     * S11's moved exit (§14's S11 row, §19.10's debt): a DM world with **HIGH mode and the
     * redeem lane** green. The world is JD8's entitlement world — the real entitlement engine,
     * the real redeem lane against the model redeem relays, the real work lane with the
     * pair-event gating — with every client's `:sync` stores in HIGH: each store waits its
     * `not_before_minute` and is stored only at the pair's next event.
     *
     * What is asserted: the world runs green to its horizon (the idle twin — activations,
     * renewals, jobs — completes; HIGH mode's send delays honoured throughout) and the redeem
     * lane redeems and registers for every token holder's own namespaces. What is reported, not
     * asserted: JD8's exact twin equality — the active twin's contact establishment rides the
     * STANDARD choreography, and HIGH mode's establishment timing is the F9-narrowed shape
     * (§22.16 item 13: the DM world's own HIGH halves were deferred there; "a fetch is the
     * pair's next read event like any read", the attempts run out inside the scenario's fixed
     * window). When the twins do reach their variable the equality is asserted whole; when the
     * unreached reason is that narrowing, the line names it (§15 item 10a: each line names what
     * it compared). Recorded as F-S11-6, §19.51.
     */
    @Test
    fun aDmWorldWithHighModeAndTheRedeemLaneIsGreen() {
        requireNative()
        val result = Jd8.run(SEED, "high mode", null, everyCommit = true, mode = org.ghost.sync.api.PrivacyMode.HIGH)
        for (d in Jd8.timingDetail(result)) println("JD8 HIGH: $d")
        val idle = result.idle
        val holders = listOf("alice", "bob", "carol", "erin")
        val problems = ArrayList<String>()
        if (idle.failure != null) problems += "the idle twin's world failed: ${idle.failure}"
        for (h in holders) {
            val calls = idle.calls[h].orEmpty()
            val redeems = calls.count { it.kind == org.ghost.sync.harness.CallKind.REDEEM }
            val registers = calls.count { it.kind == org.ghost.sync.harness.CallKind.REGISTER }
            if (redeems < 1) problems += "$h: the redeem lane redeemed nothing in HIGH mode"
            if (registers < 1) problems += "$h: the renewal registered nothing in HIGH mode"
        }
        // The exact twin equality, whole when the twins reached their variable.
        val equalityHolds = result.passed
        val unreached = result.unreached
        if (unreached.isEmpty() && !equalityHolds) problems += "the twins reached their variable and differed: ${result.differences}"
        val line = "dm JD8 HIGH mode: ${if (problems.isEmpty()) "PASS" else "FAIL"} the entitlement world with HIGH mode's send " +
            "delays green: the world runs to its horizon, the redeem lane redeemed and registered for every token holder " +
            "(idle twin ${idle.seenCount} relay calls, ${idle.calls.values.flatten().count { it.kind == org.ghost.sync.harness.CallKind.REDEEM }} redemptions, " +
            "${idle.calls.values.flatten().count { it.kind == org.ghost.sync.harness.CallKind.REGISTER }} registrations); " +
            (if (unreached.isEmpty())
                "the twins' traces identical: ${if (equalityHolds) "yes" else "no — " + result.differences}"
            else
                "the twins' exact-equality clause names its unreached reason (the F9-narrowed HIGH-establishment shape, F-S11-6): ${unreached.joinToString("; ")}") +
            (if (problems.isEmpty()) "" else "; " + problems.joinToString("; "))
        PrivacyReport.line(line)
        assertTrue(line, problems.isEmpty())
    }

    /** JD8 failed, and only its timing clause did: the twins reached their variable and every count agrees. */
    private fun timingAlone(r: Jd8.Result): Boolean =
        !r.passed && r.unreached.isEmpty() && r.differences.isEmpty() && r.foreign.isEmpty() && r.coverage.isEmpty() && r.timing.pairs > 0

    /** What differs between two runs of the same twins that must be the same run. */
    private fun sameRun(a: Jd8.Result, b: Jd8.Result): List<String> = buildList {
        for ((label, x, y) in listOf(Triple("idle", a.idle, b.idle), Triple("active", a.active, b.active))) {
            if (x.seenCount != y.seenCount || x.seenDigest != y.seenDigest) {
                add("the $label twin saw ${y.seenCount} relay calls (digest ${y.seenDigest.take(12)}) where the report's run saw ${x.seenCount} (${x.seenDigest.take(12)})")
            }
            val xs = x.calls.mapValues { (_, cs) -> cs.map { "$it ${it.atMillis} ${it.session}" } }
            val ys = y.calls.mapValues { (_, cs) -> cs.map { "$it ${it.atMillis} ${it.session}" } }
            if (xs != ys) add("the $label twin's redemptions and registrations differ from the report's run")
            if (x.delivered != y.delivered || x.foreignDmCalls != y.foreignDmCalls) add("the $label twin's DM activity differs from the report's run")
        }
    }

    internal companion object {
        const val CONTROL = "control"
        val SEED: Long = PrivacySeeds.ALL[0]
        const val SKIP = "set -Dghost.dm.native to the ghost-dm-host library: every privacy world runs the real stack"
    }
}
