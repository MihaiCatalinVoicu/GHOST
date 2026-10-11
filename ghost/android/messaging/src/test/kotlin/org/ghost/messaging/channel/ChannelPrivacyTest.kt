package org.ghost.messaging.channel

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The channel privacy world, S11's suite** (Phase 10 design §12.7, the exit gate's item 5):
 * the 60-client, 28-day world over the pinned seeds with the exact searches JC-1 … JC-7 over the
 * effective relay view, the NI-CH1 world twin (the full-world twin of §12.7's header), the
 * NI-CH2 … NI-CH5 twins at the harness scale ([ChannelPrivacyTwins]), and a HIGH-mode world run
 * (JC-6's send-delay rule). Every run writes its design-doc line ([ChannelReport]); each line
 * names what it compared (§15 item 10a).
 *
 * **Seeds.** The choreography is seeded ([ChannelPrivacyWorld.Config.seed]); [SEEDS] pins the
 * set at S11's exit from the measured per-seed time (§12.7: one seed at PR scale; the gate scale
 * is 56 days, pinned the same way). `-Dghost.channel.privacy.seed=<index>` runs one,
 * `-Dghost.channel.privacy.seeds=all|N` the first ones.
 */
class ChannelPrivacyTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** JC-1 … JC-7 over the world at PR scale, one seed (the pinned set by default at the gate). */
    @Test
    fun thePrivacyWorldsSearchesFindNothing() {
        val failures = ArrayList<String>()
        for (seed in selectedSeeds().take(1)) {
            ChannelPrivacyWorld(ChannelPrivacyWorld.Config(seed = seed)).use { privacy ->
                val built = privacy.build()
                val material = ChannelPrivacyChecks.gather(built)
                val results = listOf(
                    ChannelPrivacyChecks.jc1(built, material),
                    ChannelPrivacyChecks.jc2(built, material),
                    ChannelPrivacyChecks.jc3(built, material),
                    ChannelPrivacyChecks.jc4(built),
                    ChannelPrivacyChecks.jc5(built),
                    ChannelPrivacyChecks.jc6(built),
                    ChannelPrivacyChecks.jc7(built),
                )
                for (r in results) {
                    ChannelReport.line(r.line())
                    if (!r.passed) failures += r.line()
                }
                ChannelReport.line(worldLine(built, "STANDARD"))
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    /** JC-6's send-delay rule in a HIGH-mode world: every store waits its not_before. */
    @Test
    fun thePrivacyWorldInHighModeHonoursTheSendDelays() {
        ChannelPrivacyWorld(ChannelPrivacyWorld.Config(seed = SEEDS[0], highMode = true)).use { privacy ->
            val built = privacy.build()
            val r6 = ChannelPrivacyChecks.jc6(built)
            ChannelReport.line(r6.line() + " (the world in HIGH mode: ${built.world.relay.delayedStores} distinct delayed ops)")
            ChannelReport.line(worldLine(built, "HIGH"))
            assertTrue(r6.line(), r6.passed)
            assertTrue("HIGH mode's send delays were exercised", built.world.relay.delayedStores > 0)
        }
    }

    /** NI-CH1 at the world scale: the 28-day world twin, the fork-junk injection in twin B. */
    @Test
    fun niCh1AtWorldScaleLeavesEveryViewUnchanged() {
        val result = ChannelPrivacyTwins.niCh1WorldScale(SEEDS[0])
        ChannelReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    /** NI-CH2 … NI-CH5 at the harness scale. */
    @Test
    fun niCh2ACommitAndAPostOfEqualLengthAreIndistinguishable() {
        val result = ChannelPrivacyTwins.niCh2(SEEDS[0])
        ChannelReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun niCh3TheFundedNamespaceCountIsTheOnlyDifference() {
        val result = ChannelPrivacyTwins.niCh3(SEEDS[0])
        ChannelReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun niCh4TheRotationIsTheDeclaredDifference() {
        val result = ChannelPrivacyTwins.niCh4(SEEDS[0])
        ChannelReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    @Test
    fun niCh5BothTwinsHoldTwoGenerationsUnderTheExpiredInvite() {
        val result = ChannelPrivacyTwins.niCh5(SEEDS[0], "coajă mulțime vânzare pahar străin".toCharArray())
        ChannelReport.line(result.line())
        assertTrue(result.line(), result.passed)
    }

    private fun worldLine(built: ChannelPrivacyWorld.Built, mode: String): String {
        val r = built.report
        return "channel privacy world: PASS seed 0x${"%08x".format(r.seed)} $mode: ${built.clients.size} clients, " +
            "${r.channels} channels, ${r.days} days, ${r.postsStored} posts, ${r.commitsStored} commits, " +
            "${r.generations} generations, ${r.removals} removals, ${r.admissionJoiners} admissions, " +
            "${r.subjects.size} seizure subjects; wall ${"%.1f".format(r.wallSeconds)} s"
    }

    companion object {
        /** The pinned seeds (S11's exit; measured per-seed time in §19.51). */
        val SEEDS: List<Long> = listOf(0x5eed_b101L, 0x5eed_b102L, 0x5eed_b103L)

        fun selectedSeeds(): List<Long> {
            System.getProperty("ghost.channel.privacy.seed")?.let { return listOf(SEEDS[it.toInt()]) }
            return when (val v = System.getProperty("ghost.channel.privacy.seeds")) {
                null -> SEEDS
                "all" -> SEEDS
                else -> SEEDS.take(v.toInt().coerceIn(1, SEEDS.size))
            }
        }
    }
}
