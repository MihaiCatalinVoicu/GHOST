package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.Timer
import org.ghost.messaging.api.TrustState
import java.util.SplittableRandom

/**
 * A seeded random DM world (Phase 9 design §15.4, G-13), built the way the Phase 7 harness builds
 * `SeededWorld`: everything derives from the seed and a failure names it, so a red run is
 * reproducible from the one number in its message.
 *
 * > Each world draws: 2–6 clients, 2–4 relays over 2–3 operators, both modes; 0–40 messages per
 * > pair with a timer mix; displays at random times; offline windows from 1 minute to 40 days;
 * > week boundaries crossed by every world; one ES slot-table change in a quarter of the worlds;
 * > clock steps backwards up to 1 h and forwards up to 2 d while READY, large jumps while not
 * > READY; key changes (1 %), restores with reconnect (1 %), blocks and requests; one hostile relay
 * > per set; a crash probability per event and a `SQLITE_FULL` probability.
 *
 * **What this generator draws, and what it does not.** Clients (2–6, §15.4's own range), the contact
 * topology, the message counts, the timer mix, displays, offline windows, week boundaries, clock
 * steps, blocks, requests, the hostile relay mode — **one in every set**, as §15.4 says — the crash
 * probability and the `SQLITE_FULL` probability are all here. Two ranges are narrower than §15.4's
 * and §22.15 item 9 declares both: the message count is **0–12 per world** where §15.4 says 0–40
 * per *pair*, and the relay set is fixed at four slots over two operators where §15.4 draws 2–4
 * over 2–3 (the relay set is the Phase 7 engine's; see [ModelDmRelay]). Four draws of §15.4 are
 * **not** here at all, and each is deferred for a reason recorded in §22.15: the
 * privacy mode (`DmDevice` fixes it at construction), the ES slot-table change (the world owns one
 * slot table per node and `EsSlots` is read at construction), key changes and restores (both need a
 * second device per affected client, which the generator would have to plan before it knows which
 * clients it draws). What is generated is a world that crosses week boundaries, goes offline for up
 * to 40 days, steps its clocks, blocks and requests, and crashes at a random event — which is the
 * part that exercises the crash mechanism at a scale no hand-written scenario reaches.
 */
internal class DmSeededWorld(val seed: Long) {

    private val rnd = SplittableRandom(seed)

    /** The world's own description, printed with the seed when a run fails. */
    val description = StringBuilder("seed $seed: ")

    fun scenario(): DmScenario {
        // §15.4's own ranges for the two draws the first version narrowed without declaring it:
        // "2–6 clients" and a message mix. The message count is still per **world** and not §15.4's
        // "0–40 per pair" — a DM world runs the real ratchet and forty messages per pair over six
        // clients is a gate of its own — and §22.15 item 9 says so rather than leaving the range to
        // be re-derived from this line.
        val clients = 2 + rnd.nextInt(5)
        val messages = rnd.nextInt(13)
        val timerMix = List(messages.coerceAtLeast(1)) { drawTimer() }
        val hostile = drawHostile()
        val offlineSeconds = drawOffline()
        val stepBack = if (rnd.nextInt(4) == 0) (1 + rnd.nextInt(60)) * DmWorld.MINUTE else 0L
        val blocks = rnd.nextInt(8) == 0
        val request = rnd.nextInt(3) == 0
        description.append(
            "$clients clients, $messages messages, hostile=$hostile, " +
                "offline=${offlineSeconds / DmWorld.DAY}d, stepBack=${stepBack / 60}min, " +
                "block=$blocks, request=$request",
        )

        return DmScenario(
            name = "seed-$seed",
            tailRounds = 32,
            setup = { world ->
                for (i in 0 until clients) world.node(names[i], branches[i])
                DmScripts.activate(world)
                // A chain: each client after the first establishes with the one before it, so the
                // topology is a path rather than a clique and the world has both an initiator and
                // a responder role at every seed.
                for (i in 1 until clients) {
                    DmScripts.establishBothWays(world, names[i - 1], names[i])
                }
                // The relay turns hostile **after** the establishment, not before. §15.4 puts one
                // hostile relay in every set, but a relay that withholds the bundle of a device
                // that has no session yet is testing the establishment's retry budget (SCN-C's
                // WITHHOLD_NEWEST_BUNDLE, which slice S10c added and drives in SCN-C alone), not the
                // traffic — and it makes every seed's setup fail for the same uninteresting reason.
                world.relay.modes = hostile
            },
            steps = buildList {
                add(
                    step("traffic") { w ->
                        for (m in 0 until messages) {
                            val i = 1 + rnd.nextInt(clients - 1)
                            val from = if (rnd.nextBoolean()) names[i - 1] else names[i]
                            val to = if (from == names[i]) names[i - 1] else names[i]
                            val contact = w.contacts["$from->$to"] ?: continue
                            if (rnd.nextInt(6) == 0) {
                                w[from].device.engine.setTimer(contact, timerMix[m])
                            } else {
                                w[from].device.engine.send(contact, "s$seed-$m", null)
                            }
                            w.advanceBy(DmWorld.MINUTE)
                            if (rnd.nextBoolean()) {
                                w.pump()
                                w.passes()
                            }
                        }
                    },
                )
                if (request) {
                    add(
                        step("an unknown card holder writes") { w ->
                            // The last client scans the first one's card without being known to it:
                            // §12.3's request path, which is where CB's cases live.
                            val stranger = names[clients - 1]
                            val target = names[0]
                            if (w.contacts["$stranger->$target"] == null) {
                                w[stranger].device.engine.addContact(
                                    w[target].device.card(), CardSource.LINK,
                                )
                                val id = w[stranger].device.engine.contacts()
                                    .firstOrNull { it.trust == TrustState.VERIFIED }?.id
                                if (id != null) {
                                    w[stranger].device.engine.send(id, "hello stranger", null)
                                }
                            }
                            w.pump()
                            w.passes()
                        },
                    )
                }
                add(
                    step("displays") { w ->
                        for (node in w.nodes()) {
                            if (rnd.nextInt(3) == 0) continue
                            val contact = node.device.engine.contacts().firstOrNull() ?: continue
                            val ids = node.device.engine.conversation(contact.id, 50, null)
                                .map { it.id }
                            node.device.engine.markDisplayed(ids)
                        }
                    },
                )
                if (blocks) {
                    add(
                        step("a block") { w ->
                            val node = w[names[rnd.nextInt(clients)]]
                            node.device.engine.contacts().firstOrNull()?.let {
                                node.device.engine.block(it.id)
                            }
                        },
                    )
                }
                if (stepBack > 0) {
                    add(step("a clock step back") { w -> w.stepClockBack(names[0], stepBack) })
                }
                add(
                    step("an offline window across a week boundary") { w ->
                        // Every world crosses a week boundary (§15.4), because the bundle
                        // generation, the pair week key and the credential slot all turn there and
                        // a world that never crosses one tests none of them.
                        w.advanceBy(offlineSeconds + DmWorld.WEEK)
                        w.pump()
                        w.passes()
                    },
                )
                add(step("settle") { w -> w.pump(); w.passes() })
            },
            alwaysChecks = { world ->
                // What every seeded world must satisfy, faulted or not: nothing rendered twice at
                // one position (CS-2, checked by the runner), nothing past its deadline once the
                // world has settled, and the rendering order equal to the author order.
                for (node in world.nodes()) {
                    DmStructuralInvariants.afterSweep(node, node.clock.now, "seed $seed")
                }
                orderIsAuthorOrder(world)
            },
        )
    }

    /**
     * CS-4 over a seeded world: the order the **read path** returns is the order §7.7's columns
     * decide, and no two inbound messages share a position.
     *
     * A seeded world cannot name the texts it expects — it drew them — so what it can check is the
     * shape. The first half is the one that was missing: the old version compared
     * `(sort_minute, minute_index)` pairs read *in that order* with themselves, which is a
     * tautology, and its KDoc pointed at a `DmStructuralInvariants.renderOrder` that did not exist.
     * It now reads the conversation through `MessagingEngine.conversation` — the path a user sees,
     * and the one mutant MC-10 changes — and requires it to agree with the columns.
     */
    private fun orderIsAuthorOrder(world: DmCrashWorld) {
        for (node in world.nodes()) {
            val byColumns = DmStructuralInvariants.renderOrder(node)
            if (byColumns.size != byColumns.toSet().size) {
                dmViolation("$description: ${node.name} renders two messages at one position")
            }
            val device = node.device
            for (contact in device.engine.contacts()) {
                val page = device.engine.conversation(contact.id, 200, null)
                    .filter { !it.outgoing }
                    .map { it.cursor.sortMinute to it.cursor.minuteIndex }
                // The page is newest first (§7.7), so the read path's order reversed has to be
                // ascending in the pair the columns hold.
                val ascending = page.reversed()
                if (ascending != ascending.sortedWith(compareBy({ it.first }, { it.second }))) {
                    dmViolation(
                        "$description: ${node.name} renders $ascending, which is not " +
                            "(sort_minute, minute_index) order (CS-4)",
                    )
                }
            }
        }
    }

    private fun drawTimer(): Timer = when (rnd.nextInt(20)) {
        0 -> Timer.MIN_5
        1, 2 -> Timer.HOUR_1
        3, 4 -> Timer.DAY_1
        in 5..16 -> Timer.DAYS_7
        18 -> Timer.DAYS_30
        else -> Timer.OFF
    }

    /**
     * **One hostile relay per set**, in every set — which is what §15.4 says, and what this did not
     * do: two of its six branches returned an honest set, so a third of the seeds drew no hostile
     * relay at all and the draw's whole purpose was optional.
     */
    private fun drawHostile(): Set<ModelDmRelay.Mode> = when (rnd.nextInt(6)) {
        0, 4 -> setOf(ModelDmRelay.Mode.SHUFFLE)
        1 -> setOf(ModelDmRelay.Mode.REPEATS)
        2, 5 -> setOf(ModelDmRelay.Mode.WITHHOLD)
        else -> setOf(ModelDmRelay.Mode.SHUFFLE, ModelDmRelay.Mode.REPEATS)
    }

    /** Offline windows from 1 minute to 40 days (§15.4). */
    private fun drawOffline(): Long = when (rnd.nextInt(10)) {
        0 -> DmWorld.MINUTE
        1, 2, 3 -> (1 + rnd.nextInt(24)) * DmWorld.HOUR
        4, 5, 6, 7 -> (1 + rnd.nextInt(9)) * DmWorld.DAY
        else -> (10 + rnd.nextInt(31)) * DmWorld.DAY
    }

    /**
     * A crash and a `SQLITE_FULL` probability per event (§15.4), as a plan over the whole world.
     *
     * The plan is drawn from the **same** seed as the world, so a seed names one run and not a
     * family of them: the description and the plan together are the whole of what a failure has to
     * reproduce.
     */
    fun faultPlan(): DmFaultPlan {
        val planRandom = SplittableRandom(seed xor 0x5deece66dL)
        val crashAt = if (planRandom.nextInt(3) == 0) 1 + planRandom.nextInt(900).toLong() else -1L
        val fullAt = if (planRandom.nextInt(3) == 0) 1 + planRandom.nextInt(900).toLong() else -1L
        description.append(", crashAt=$crashAt, fullAt=$fullAt")
        // **Once.** `DmCrashRunner` restarts the event counter after the first crash, so a plan
        // that only compares an index crashes again at the same index of the recovery phase: a seed
        // whose description said one crash actually took two, and the description a red seed is
        // reproduced from was wrong about the run it named. The hand-written specs are phase-gated
        // for the same reason; this one was not.
        var crashed = false
        return DmFaultPlan { e ->
            when {
                e.index == crashAt && !crashed -> {
                    crashed = true
                    DmFault.Crash
                }

                e.index == fullAt && e.kind.canBeFull -> DmFault.StorageFull
                else -> null
            }
        }
    }

    private companion object {
        val names = listOf("alice", "bob", "carol", "dave", "erin", "frank")
        val branches = listOf(0x41, 0x51, 0x61, 0x71, 0x81, 0x91)
    }
}
