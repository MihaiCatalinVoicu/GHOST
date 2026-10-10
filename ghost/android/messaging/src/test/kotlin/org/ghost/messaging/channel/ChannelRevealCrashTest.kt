package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * **The S9 transaction paths' crash singles** (Phase 10 design §12.4, CS-C1/CS-C2; the F7 §8.3
 * method; the shape of [ChannelRejoinCrashTest]): a process death at every event of `CH-REVEAL`'s
 * build ([ChannelRevealStep.reveal] — the op and the sender's `ch_reveal` row are one transaction)
 * and of the receive batch that opens a reveal (the recipient's `ch_reveal` row and its op-id seen
 * tag are one transaction; the card offer runs only after the commit) — then a reboot (a new
 * client over the same database), the invariants, the atomicity of what the crash left, and the
 * retried path to liveness (the reveal delivered, the offer made, exactly once).
 */
class ChannelRevealCrashTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    private class Frozen(val owner: java.io.File, val dave: java.io.File, val relay: ModelChannelRelay, val now: Long, val channel: ChannelId, val daveSeenAtFreeze: Long = -1)

    private class Thawed(val world: ChannelWorld, var owner: ChannelClient, var dave: ChannelClient, val crash: CrashingSqlExecutor, val crasherIsDave: Boolean) {
        fun reboot(boot: Int): ChannelClient {
            if (crasherIsDave) {
                dave.die()
                crash.armAt = null
                dave = world.client("dave", crash, boot)
                return dave
            }
            owner.die()
            crash.armAt = null
            owner = world.client("owner", crash, boot)
            return owner
        }
    }

    private fun thaw(frozen: Frozen, boot: Int, crasherIsDave: Boolean): Thawed {
        val world = ChannelWorld(startSeconds = frozen.now, relay = frozen.relay.copy())
        val crash = CrashingSqlExecutor(ChannelWorld.restore(if (crasherIsDave) frozen.dave else frozen.owner))
        val owner = world.client("owner", if (crasherIsDave) ChannelWorld.restore(frozen.owner) else crash, boot)
        val dave = world.client("dave", if (crasherIsDave) crash else ChannelWorld.restore(frozen.dave), boot)
        return Thawed(world, owner, dave, crash, crasherIsDave)
    }

    private fun close(t: Thawed) {
        t.world.close()
    }

    /** A file-based owner + dave at epoch 1. */
    private class Built(val world: ChannelWorld, val owner: ChannelClient, val dave: ChannelClient, val id: ChannelId, val ownerFile: java.io.File, val daveFile: java.io.File)

    private fun build(): Built {
        val w = ChannelWorld()
        val ownerFile = folder.newFile("owner-rv.db").also { it.delete() }
        val daveFile = folder.newFile("dave-rv.db").also { it.delete() }
        val owner = w.client("owner", path = ownerFile.absolutePath)
        val dave = w.client("dave", path = daveFile.absolutePath)
        val id = ChannelScenes.channelOf(w, owner, dave)
        return Built(w, owner, dave, id, ownerFile, daveFile)
    }

    private fun freeze(b: Built): Frozen {
        val relay = b.world.relay.copy()
        val now = b.world.now
        val seen = b.dave.count("ch_seen")
        b.world.close()
        return Frozen(b.ownerFile, b.daveFile, relay, now, b.id, seen)
    }

    /** The world before the reveal user action: `CH-REVEAL`'s build is the action. */
    private fun beforeReveal(): Frozen = freeze(build())

    /** The world with the reveal at the relay, before dave's pass opens it. */
    private fun beforeReceive(): Frozen {
        val b = build()
        assertEquals(org.ghost.messaging.channel.engine.ChannelRevealStep.RevealResult.REVEALED, b.owner.engine.reveal(b.id, b.dave.channel(b.id)!!.myPseudonym))
        b.world.pump()
        return freeze(b)
    }

    /**
     * The F7 §8.3 single: crash at every event of [action], reboot, assert the invariants and
     * [afterCrash]'s atomicity, then [finish] to the same fixed point.
     */
    private fun runSingle(
        name: String,
        frozen: Frozen,
        crasherIsDave: Boolean = true,
        action: (Thawed) -> Unit,
        afterCrash: (Thawed, Int) -> Unit,
        finish: (Thawed) -> Unit,
    ) {
        val events = thaw(frozen, 1, crasherIsDave).let { t ->
            try {
                t.crash.reset()
                action(t)
                t.crash.count
            } finally {
                close(t)
            }
        }
        assertTrue("$name raised $events events", events >= 4)
        println("S9 crash singles: $name raises $events events")
        var crashed = 0
        for (k in 1..events) {
            val t = thaw(frozen, 1, crasherIsDave)
            try {
                t.crash.reset()
                t.crash.armAt = k
                try {
                    action(t)
                    fail("no crash at event $k of $events ($name)")
                } catch (e: SimulatedCrash) {
                    crashed++
                }
                t.reboot(2)
                val broken = if (crasherIsDave) t.dave.integrity() else t.owner.integrity()
                assertEquals("after a crash at $k of $name: $broken", emptyList<String>(), broken)
                afterCrash(t, k)
                finish(t)
            } finally {
                close(t)
            }
        }
        assertEquals(events, crashed)
    }

    /** `CH-REVEAL`'s build: nothing, or the op and the sender's row together (one transaction). */
    @Test
    fun aCrashAtEveryEventOfTheRevealBuildLeavesNothingOrAWholeReveal() {
        val frozen = beforeReveal()
        runSingle(
            "CH-REVEAL",
            frozen,
            crasherIsDave = false,
            action = { t ->
                t.owner.engine.reveal(frozen.channel, t.dave.channel(frozen.channel)!!.myPseudonym)
            },
            afterCrash = { t, k ->
                val rows = t.owner.count("ch_reveal", "direction = 'out'")
                val ops = t.owner.count("ch_outbound_op", "purpose = 'request'")
                val pending = t.owner.count("ch_pending_post")
                if (rows == 0L) {
                    assertEquals("crash at $k: an op without the reveal's row", 0L, ops)
                } else {
                    assertEquals("crash at $k", 1L, rows)
                    assertEquals("crash at $k: the reveal's op, in the same transaction", 1L, ops)
                    assertEquals("crash at $k: the channel was current — nothing pending", 0L, pending)
                }
            },
            finish = { t ->
                if (t.owner.count("ch_reveal", "direction = 'out'") == 0L) {
                    // the crash took the half-built reveal: the user's tap again
                    assertEquals(
                        org.ghost.messaging.channel.engine.ChannelRevealStep.RevealResult.REVEALED,
                        t.owner.engine.reveal(frozen.channel, t.dave.channel(frozen.channel)!!.myPseudonym),
                    )
                }
                t.world.quiesce()
                assertEquals(1, t.dave.offeredCards.size)
                assertEquals(1L, t.owner.count("ch_reveal", "direction = 'out'"))
                assertEquals(1L, t.dave.count("ch_reveal", "direction = 'in'"))
            },
        )
    }

    /**
     * The receive batch that opens the reveal: no row and no seen tag, or both — and the card
     * offer only after the batch commits (the offer is not transactional state: it is the batch's
     * post-commit effect, so a crash never offers a card the row does not record).
     */
    @Test
    fun aCrashAtEveryEventOfTheRevealReceiveLeavesNoRowOrAWholeOpen() {
        val frozen = beforeReceive()
        runSingle(
            "the reveal receive",
            frozen,
            action = { t -> t.dave.hintPass() },
            afterCrash = { t, k ->
                val rows = t.dave.count("ch_reveal", "direction = 'in'")
                val seen = t.dave.count("ch_seen")
                if (rows == 0L) {
                    assertEquals("crash at $k: a seen tag without the reveal's row", frozen.daveSeenAtFreeze, seen)
                } else {
                    assertEquals("crash at $k", 1L, rows)
                    assertEquals("crash at $k: exactly the reveal's seen tag", frozen.daveSeenAtFreeze + 1, seen)
                }
                assertEquals("crash at $k: no uncommitted offer", 0, t.dave.offeredCards.size)
            },
            finish = { t ->
                if (t.dave.count("ch_reveal", "direction = 'in'") == 0L) {
                    // the batch died: the blob is re-offered (the poison guard's first offer stood)
                    t.world.quiesce()
                    assertEquals("the retried pass opens the reveal and offers the card", 1, t.dave.offeredCards.size)
                    assertArrayEquals(t.owner.ownCard(), t.dave.offeredCards[0].first)
                } else {
                    // the batch committed and the offer fired before a later event's crash: the
                    // offer is post-commit (in the runtime, addContact's own committed
                    // transaction) — a reboot after it does not repeat it, and must not (the op
                    // id is seen; a copy drops as a DUPLICATE).
                    assertEquals(0, t.dave.offeredCards.size)
                }
                assertEquals(1L, t.dave.count("ch_reveal", "direction = 'in'"))
                assertEquals(0, t.dave.counters[org.ghost.messaging.channel.engine.ChannelCounters.Reason.REVEAL_FORGED])
            },
        )
    }

}
