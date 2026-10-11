package org.ghost.messaging.channel

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **The JC exact searches at the smoke scale** (Phase 10 design §12.7's checks over a small world —
 * four clients, two channels, three virtual days): the same [ChannelPrivacyChecks] JC-1 … JC-4 and
 * JC-6 … JC-7 the 60-client world runs, over a world's relay view built by [ChannelScenes]. This is
 * the PR-scale smoke of the privacy checks (fast enough for every push) and the small-scale control
 * the privacy mutants' scratch kills run against (PC-1, PC-3, PC-7, PC-8, PC-13, PC-16's named
 * killers; §12.9's registry names the rest's suites). JC-5 rides the world's removal subjects — the
 * 60-client world's own line — and is not repeated here.
 */
class ChannelPrivacySmokeTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    private class Built(
        val world: ChannelWorld,
        val channels: List<ChannelPrivacyWorld.ChannelInfo>,
        val clients: List<ChannelClient>,
    )

    /** The smoke world: two channels (7-day and 30-day), four clients, three days of traffic. */
    private fun built(): Built {
        val world = ChannelWorld()
        val owner = world.client("owner")
        val bob = world.client("bob")
        val carol = world.client("carol")
        val dave = world.client("dave")
        val a = ChannelScenes.channelOf(world, owner, bob, carol)
        val b = ChannelScenes.channelOf(world, owner, bob, dave)
        world.advance(2 * org.ghost.messaging.DmWorld.DAY)
        for (d in 0 until 3) {
            ChannelScenes.post(owner, a, "fum $d")
            ChannelScenes.post(bob, b, "gum $d")
            ChannelScenes.post(carol, a, "hum $d")
            world.quiesce()
            world.advance(org.ghost.messaging.DmWorld.DAY)
        }
        world.pastSettleWindow()
        world.quiesce()
        return Built(
            world,
            listOf(
                ChannelPrivacyWorld.ChannelInfo(a, "fum", 4, owner, listOf(owner, bob, carol)),
                ChannelPrivacyWorld.ChannelInfo(b, "gum", 5, owner, listOf(owner, bob, dave)),
            ),
            listOf(owner, bob, carol, dave),
        )
    }

    @Test
    fun theExactSearchesFindNothingAtTheSmokeScale() {
        val built = built()
        built.world.use {
            val asBuilt = ChannelPrivacyWorld.Built(built.world, ChannelPrivacyWorld.Report(0, false, days = 3), built.channels, built.clients)
            val material = ChannelPrivacyChecks.gather(asBuilt)
            val results = listOf(
                ChannelPrivacyChecks.jc1(asBuilt, material),
                ChannelPrivacyChecks.jc2(asBuilt, material),
                ChannelPrivacyChecks.jc3(asBuilt, material),
                ChannelPrivacyChecks.jc4(asBuilt),
                ChannelPrivacyChecks.jc6(asBuilt),
                ChannelPrivacyChecks.jc7(asBuilt),
            )
            val failures = results.filter { !it.passed }.map { it.line() }
            for (r in results) ChannelReport.line(r.line())
            assertTrue(failures.joinToString("\n"), failures.isEmpty())
        }
    }
}
