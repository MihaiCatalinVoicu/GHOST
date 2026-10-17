package org.ghost.messaging.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The media privacy world (Phase 11 design §15.6; slice S9): at the PR scale (N = 60, 14 days,
 * one seed, the §15.1 media rate) in the `android` job, at the gate scale (N = 300, 28 days,
 * `-Dghost.media.privacy=gate`) in `media-exit-gate`'s world step — the JM1–JM7 joins over the
 * effective relay view, the NI-M1–NI-M7 twins, and the seizure check, each line written to the
 * media report. The floors are asserted in-suite (the JC-5 lesson): a join over an empty world
 * or a seizure control that opened nothing fails here, not vacuously.
 */
class MediaPrivacyWorldTest {

    private fun pinnedSeed(): Long = 0x5eed_0001L

    @Test
    fun theMediaPrivacyWorldIsGreenWithItsJoinsAtZero() {
        val scale = MediaPrivacyScale.selected()
        lateinit var results: List<MediaJoins.Result>
        lateinit var seizure: MediaSeizure.Result
        var objectCount = 0
        var storeCount = 0
        var getCount = 0
        MediaPrivacyWorld(scale, pinnedSeed()).use { world ->
            val joins = world.run()
            // Floors: the world must have run at scale (a join over nothing proves nothing).
            objectCount = world.truth.objects.size
            storeCount = world.relay.events.count { it.op == MediaViewOp.STORE }
            getCount = world.relay.events.count { it.op == MediaViewOp.GET }
            assertTrue("objects: $objectCount", objectCount >= scale.clients * scale.days / 4)
            assertTrue("stores: $storeCount", storeCount >= objectCount)
            assertTrue("gets: $getCount", getCount > 0)
            // The S9 review's finding 2: the two scripted off-timer anchors (one FAILED, one
            // deadline) are the only exemptions a green stochastic run executes — they must
            // appear in JM1's breakdown, and both drove the production paths finding 1 fixed
            // (the FAILED-outcome arm and MEDIA-DEADLINE at TIMER_OFF).
            val breakdown = world.truth.exemptionBreakdown()
            assertTrue(
                "the scripted off-timer exemptions ran: $breakdown",
                breakdown.contains("1 FAILED") && breakdown.contains("1 deadline"),
            )
            results = joins.all()
            for (r in results) {
                assertEquals("${r.name} over the privacy world: ${r.detail}", 0, r.violations)
            }
            seizure = MediaSeizure(world).run()
        }
        assertSeizure(seizure)

        MediaPrivacyReport.line(
            "media privacy world: N = ${scale.clients}, ${scale.days} days, 1 seed, STANDARD",
        )
        for (r in results) {
            MediaPrivacyReport.line("${r.name}: PASS 0 ${r.detail}")
        }
        MediaPrivacyReport.line(
            "seizure: ${seizure.opened} opened (${seizure.storedKeys} key_env values tried on " +
                "${seizure.archivedBlobs} archived blobs); control: ${seizure.controlOpened} live objects open",
        )
    }

    private fun assertSeizure(s: MediaSeizure.Result) {
        assertEquals("no stored key_env opens an archived blob", 0, s.opened)
        assertTrue("the control opened a live object (the oracle is not vacuous): $s", s.controlOpened >= 1)
        assertTrue("archived blobs: ${s.archivedBlobs}", s.archivedBlobs > 0)
        assertTrue("stored keys: ${s.storedKeys}", s.storedKeys > 0)
    }

    @Test
    fun theNiMTwinsHold() {
        val twins = MediaPrivacyTwins.all()
        for (t in twins) {
            assertTrue("${t.name}: ${t.detail}", t.equal)
            MediaPrivacyReport.line(
                when (t.name) {
                    "NI-M3" -> "${t.name}: equal up to the sender pair (session co-occurrence, L7-D2/L7-D5; LM declares) — ${t.detail}"
                    "NI-M5" -> "${t.name}: equal first-page list schedule (${t.detail})"
                    "NI-M7" -> "${t.name}: equal up to the TTL scalar (${t.detail})"
                    else -> "${t.name}: equal (${t.detail})"
                },
            )
        }
    }
}
