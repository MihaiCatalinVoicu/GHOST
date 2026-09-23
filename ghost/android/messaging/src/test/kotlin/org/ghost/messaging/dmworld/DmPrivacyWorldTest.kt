package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * T32 over the privacy world (Phase 9 design §14.1 T32, §15.6): the exact joins this slice builds,
 * S-DM3, and the world's own shape, at the scale `-Dghost.dm.privacy` selects (PR: N = 120 over 14
 * days; gate: N = 600 over 42 days) for every pinned seed `-Dghost.dm.privacy.seeds` selects.
 *
 * Every line it writes to the privacy report carries its denominator, and every check fails on an
 * empty sample: a join over no stores, or a statistic under its floor, is a failure here and in
 * `dm-report-check.sh`, never a pass.
 */
class DmPrivacyWorldTest {

    private fun requireNative() {
        assumeTrue(SKIP, DmWorld.nativeAvailable())
        assumeTrue("-Dghost.dm.privacy=off: the privacy worlds are skipped", PrivacyScale.enabled)
    }

    @Test
    fun t32JoinsAndSdm3HoldOverThePrivacyWorld() {
        requireNative()
        val scale = PrivacyScale.selected()
        val failures = ArrayList<String>()
        for (seed in PrivacySeeds.selected()) {
            val started = System.nanoTime()
            PrivacyWorld(PrivacyWorldConfig.of(scale, seed)).use { world ->
                world.run()
                val seconds = (System.nanoTime() - started) / 1e9
                val tag = "[seed ${java.lang.Long.toHexString(seed)}]"
                val byOp = world.relay.events.groupingBy { it.op }.eachCount()
                val sends = world.counters["sends"] ?: 0
                PrivacyReport.line(
                    "dm privacy world: N=${world.config.clients}, ${world.config.days} days, " +
                        "${world.acceptedEdges.size} edges accepted of ${world.plan.edges.size} planned, " +
                        "$sends user sends, ${byOp[ViewOp.STORE] ?: 0} stores, ${byOp[ViewOp.LIST] ?: 0} lists, " +
                        "${byOp[ViewOp.GET] ?: 0} gets, ${byOp[ViewOp.REGISTER] ?: 0} registrations, " +
                        "seals ${world.truth.seals.toSortedMap()}, ${"%.0f".format(seconds)} s $tag",
                )
                if (world.acceptedEdges.isEmpty() || sends == 0) failures += "$tag: the world did nothing"
                val joins = Joins(world)
                for (result in listOf(joins.jd1(), joins.jd2(), joins.jd3(), joins.jd4(), joins.jd5(), joins.jd6(), joins.jd7(), joins.jd9())) {
                    PrivacyReport.line(result.line() + " $tag")
                    if (!result.passed) failures += "$tag ${result.failureMessage()}"
                    if (result.scanned == 0L) failures += "$tag ${result.id} scanned nothing"
                }
                val sdm3 = Sdm3.run(world, seed)
                PrivacyReport.line(sdm3.line() + " $tag")
                if (!sdm3.passed) failures += "$tag ${sdm3.failureMessage()}"
                // A plain host build writes NOT RUN, which only the report check refuses (a local
                // run without the provenance build still passes here); a provenance build's FAIL fails.
                val t35 = T35.run(world)
                PrivacyReport.line(t35.line + " $tag")
                if (t35.ran && !t35.passed) failures += "$tag ${t35.line}"
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun niDm1InboundContentLeavesTheRecipientsViewUnchanged() {
        requireNative()
        val result = NiDm1.run(PrivacySeeds.ALL[0])
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun niDm2TypeAndSessionStateLeaveTheSizesUnchanged() {
        requireNative()
        val result = NiDm2.run(PrivacySeeds.ALL[0])
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    /**
     * JD7's WITHHOLD_ALL_BUNDLES variant (§21.7 point 6): scale-independent like the twins, so it
     * runs once, on a SMALL world whose relays show no reader a bundle it does not own.
     */
    @Test
    fun jd7UnderWithholdAllBundlesTheAttemptsStayBounded() {
        requireNative()
        PrivacyWorld(PrivacyWorldConfig.of(PrivacyScale.SMALL, PrivacySeeds.ALL[0], withholdAllBundles = true)).use { world ->
            world.run()
            val result = Joins(world).jd7Withheld()
            PrivacyReport.line(result.line() + " (N=${world.config.clients}, ${world.config.days} days)")
            assertTrue(result.failureMessage(), result.passed)
        }
    }

    @Test
    fun niDm3IdleContactsLeaveTheOwnersViewUnchanged() {
        requireNative()
        val result = NiDm3.run(PrivacySeeds.ALL[0])
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun t34TheSeizureOpensNothingOfAnExpiredWeek() {
        requireNative()
        val result = Seizure.seize(Seizure.config(PrivacySeeds.ALL[0]))
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun t34OneReplyBothSidesEraseTheirProvisionalKey() {
        requireNative()
        val result = Seizure.oneReply(PrivacySeeds.ALL[0])
        PrivacyReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    private companion object {
        const val SKIP = "set -Dghost.dm.native to the ghost-dm-host library: every privacy world runs the real stack"
    }
}
