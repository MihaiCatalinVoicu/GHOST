package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.engine.ChannelRejoinStep
import org.ghost.messaging.channel.engine.MlsRows
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import java.io.File
import kotlin.random.Random
import kotlin.system.measureTimeMillis

/**
 * **SCN-M20, the exit scenario** (Phase 10 design §12.5): 20 clients in one channel, every flow the
 * design names, run end-to-end over the real OpenMLS — create, the 19 admissions in waves bounded by
 * the commit floor, ≈ 200 posts with reactions and replies, the four removal kinds (a moderator
 * removal, a leave, an idle eviction at 63 virtual days, a device swap whose restore rotates the
 * generation and whose old stack is a seizure subject), two members offline across ≥ 5 epochs and
 * the rotations that catch up from the relays, one member offline past EXPIRE_LOG that reaches
 * `stale_suspected` and rejoins, ranks 0 and 1 committing concurrently on one epoch (CO-3), and a
 * removed client re-invited (returning with the same pseudonym, D12). The variants the design names
 * ride the same choreography: the owner restore (rank 0 keeps rank 0, MM-33) and the relay-induced
 * FORK ([buildFork]).
 *
 * **Seeds.** The choreography is scripted by a Kotlin [Random] over fixed client names (fixed keys,
 * name-derived pseudonym seeds, virtual time — §12.1's method); the native draws stay unseeded (the
 * world's rule since S4: assertions are about states, counts and oracles, never native-drawn bytes).
 * [SEEDS] pins three seeds at S10's exit (§12.5's scale row: one seed per PR, the pinned set in the
 * exit gate); a failing seed is investigated, never re-seeded.
 *
 * **What a run proves** is stated in the report lines ([ChannelReport]) and §12.12: the measurable
 * pieces of the exit gate's first rows, STANDARD mode only (HIGH mode, the redeem lane and circuit
 * timing are S11's, §19.33 — each line names what it compared, §15 item 10a).
 */
internal object ChannelM20 {

    /** The pinned seeds (S10's exit; §12.5's scale row). `-Dghost.channel.seed=<index>` runs one (a PR), `all` or a count the first ones. */
    val SEEDS: List<Long> = listOf(0x5eed_c101L, 0x5eed_c102L, 0x5eed_c103L)

    fun selectedSeeds(): List<Long> {
        System.getProperty("ghost.channel.seed")?.let { return listOf(SEEDS[it.toInt()]) }
        return when (val v = System.getProperty("ghost.channel.seeds")) {
            null -> SEEDS.take(1)
            "all" -> SEEDS
            else -> SEEDS.take(v.toInt().coerceIn(1, SEEDS.size))
        }
    }

    enum class Variant { BASE, OWNER_RESTORE }

    /** Early stop for the crash singles' freeze points (§12.4's scale row: crash singles at the named critical events). */
    enum class StopAt { NONE, WAVE_ADMISSION, RESTORE_ADMISSION, REJOIN_ADMISSION }

    class Config(
        val seed: Long,
        val variant: Variant = Variant.BASE,
        /** Non-null: every client on a file under it (the crash singles' snapshots); null: memory DBs. */
        val dbDir: File? = null,
        val stopAt: StopAt = StopAt.NONE,
    )

    /** A T38 seizure subject: a copy of its database at the removal moment and the cutoffs. */
    class Subject(
        val name: String,
        val kind: String,
        /** The removing/rotating commit's epoch: no mode-0x11 blob of a later epoch may open. */
        val removedAtEpoch: Long,
        /** The last generation the subject held: no blob of a later generation may open (§19.16). */
        val heldGeneration: Long,
        val dump: File,
    )

    /** A T39 subject: (name, join epoch). */
    class Joiner(val name: String, val joinEpoch: Long)

    class Report(
        val seed: Long,
        val variant: Variant,
        var clients: Int = 0,
        var postsStored: Int = 0,
        var reactionsStored: Int = 0,
        var epochs: Int = 0,
        var generations: Int = 0,
        var wallSeconds: Double = 0.0,
        var t41Checks: Int = 0,
        val subjects: MutableList<Subject> = ArrayList(),
        val joiners: MutableList<Joiner> = ArrayList(),
        var forkSidesSplitSuspected: Int = 0,
        var forkMembersRejoined: Int = 0,
    ) {
        /** The design-doc report line (the format the other suites' lines use). */
        fun line(): String =
            "channel SCN-M20: PASS seed ${"0x%08x".format(seed)} ${variant.name.lowercase()}: " +
                "$clients clients, $postsStored posts ($reactionsStored reactions), $epochs epochs, " +
                "${generations} generations; ${subjects.size} seizure subjects, ${joiners.size} joiners; " +
                "t41 checks $t41Checks; wall ${"%.1f".format(wallSeconds)} s"
    }

    class Built(
        val world: ChannelWorld,
        val report: Report,
        val id: ChannelId,
        val anchor: ChannelClient,
        val members: List<ChannelClient>,
    )

    // ------------------------------------------------------------------------------------------------ cast

    const val OWNER: String = "c1"
    const val MODERATOR: String = "c2"
    val OFFLINE_CATCH_UP: Set<String> = setOf("c8", "c9")
    const val PAST_TTL: String = "c13"
    const val MODERATOR_REMOVED: String = "c10"
    const val LEAVER: String = "c11"
    const val EVICTEE: String = "c12"
    val ALL: List<String> = (1..20).map { "c$it" }

    fun swapSubject(variant: Variant): String = if (variant == Variant.OWNER_RESTORE) OWNER else "c7"

    // ------------------------------------------------------------------------------------------------ run

    fun build(config: Config): Built {
        val report = Report(config.seed, config.variant)
        val world = ChannelWorld()
        lateinit var id: ChannelId
        val elapsed = measureTimeMillis {
            id = run(world, config, Random(config.seed), report)
        }
        report.wallSeconds = elapsed / 1000.0
        return Built(world, report, id, world.clients.first { it.name == anchorName(config) }, world.clients.toList())
    }

    private fun anchorName(config: Config): String =
        if (config.variant == Variant.OWNER_RESTORE) MODERATOR else OWNER

    private fun run(w: ChannelWorld, config: Config, rnd: Random, report: Report): ChannelId {
        // Every client is file-backed: the seizure dumps, the restore stack's copy and the crash
        // singles' snapshots all read a client's database file through a fresh connection.
        val workDir = config.dbDir ?: java.nio.file.Files.createTempDirectory("ghost-m20").toFile()
        fun mk(name: String, boot: Int = 0, seedName: String? = null): ChannelClient =
            w.client(name, boot = boot, seedName = seedName, path = File(workDir, "$name.db").absolutePath)

        val owner = mk(OWNER)
        val clients = ALL.map { if (it == OWNER) owner else mk(it) }
        fun byName(name: String): ChannelClient = clients.first { it.name == name }
        fun lead(): ChannelClient = byName(anchorName(config))
        report.clients = clients.size

        // Day 0: the channel (timer 7 d, §12.5's setup).
        val id = ChannelAdmissionTest.create(owner)

        // The 19 admissions in five waves of at most four (one commit's floor fits four KeyPackages),
        // the invites spread over the first days as the script names.
        val joiners = clients.filter { it.name != OWNER }
        val waves = joiners.chunked(4)
        for ((index, wave) in waves.withIndex()) {
            for (j in wave) {
                assertEquals(AcceptResult.PENDING, j.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
            }
            w.quiesce()
            if (config.stopAt == StopAt.WAVE_ADMISSION && index == 3) return id
            // At 17 members a wave's four Adds no longer fit one commit's floor: the pass defers
            // the excess (MM-42's deferral machinery) and the next pass admits it. The retry
            // clears the 6 h spacing arm a committed pass leaves (the duePass pattern).
            var guard = 0
            while (wave.any { it.channel(id)?.state != ChannelState.ACTIVE } && guard++ < 4) {
                if (guard > 1) clearArm(owner, id)
                w.admissionPass(owner)
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
            }
            for (j in wave) {
                assertEquals("${j.name} of wave $index joined", ChannelState.ACTIVE, j.channel(id)!!.state)
                report.joiners += Joiner(j.name, j.channel(id)!!.epoch)
            }
            converged(w, ::byName, id, report)
            if (index < waves.lastIndex) w.advance(DmWorld.DAY)
        }
        // The T25 half of the design's channel cases (the 1 h timer variant) is EP-C's (S8, green);
        // this scenario asserts the 7-day timer's display half at its end.

        // Ranks and funders: rank 0 = client 1, rank 1 = client 2, funders = clients 1 and 2 (§12.5).
        makeCommitter(w, ::byName, id)
        assertEquals(2, ChannelAdversary.policy(owner, id).committers.size)
        assertEquals(2, ChannelAdversary.policy(owner, id).funders.size)

        // ≈ 200 posts with reactions and replies, in seeded bursts between commits.
        fun activePosters(): List<ChannelClient> = joiners.filter { it.channel(id)?.state == ChannelState.ACTIVE }
        var composed = 0
        fun burst(count: Int) {
            repeat(count) {
                val posters = activePosters()
                if (posters.isEmpty()) return@repeat
                val author = posters[rnd.nextInt(posters.size)]
                val text = "m${composed++}-${author.name}-${rnd.nextInt(1_000_000)}"
                ChannelScenes.post(author, id, text)
                if (rnd.nextInt(3) == 0) {
                    // A reaction to a post the reactor holds (the newest it displayed).
                    val reactor = posters[rnd.nextInt(posters.size)]
                    val page = reactor.displayed(id)
                    if (page.isNotEmpty()) {
                        val target = ChannelScenes.opIdOf(reactor, id, page.first())
                        assertEquals(PostResult.QUEUED, reactor.engine.react(id, PostId(target), "👍".toByteArray()))
                        report.reactionsStored++
                    }
                }
            }
            w.quiesce()
        }
        // A forced committer commit (the PCS cadence aged); convergence is asserted by the caller —
        // the dark members of the offline windows legitimately lag.
        fun pcs(member: ChannelClient) {
            agePcsClock(member, id, 8)
            duePass(w, member)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
        }

        burst(40)
        pcs(byName(if (rnd.nextBoolean()) OWNER else MODERATOR))
        burst(40)
        pcs(byName(if (rnd.nextBoolean()) OWNER else MODERATOR))

        // Two members go dark across the removals that follow — ≥ 5 epochs and three rotations.
        val dark = OFFLINE_CATCH_UP.map { byName(it) }
        for (d in dark) quietClocks(d, id)
        w.relay.modes = setOf(ModelChannelRelay.Mode.SILENT_ORPHAN)
        w.relay.silentOrphan = { name, _ -> name in OFFLINE_CATCH_UP }
        val darkEpoch = owner.channel(id)!!.epoch

        // Removal kind 1 — a moderator removal (c2 removes c10; a user-action Remove, committed at
        // once). While the removing candidate is held, other members post: the removal hold (CO-13)
        // keeps those posts out of the removing epoch — they land in the rotated generation.
        val c10Pseudonym = pseudonymOf(byName(MODERATOR_REMOVED), id)
        assertEquals(
            org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED,
            byName(MODERATOR).engine.remove(id, c10Pseudonym),
        )
        duePass(w, byName(MODERATOR))
        w.quiesce()
        assertEquals(1L, byName(MODERATOR).count("ch_candidate", "own = 1 AND removes = 1"))
        val heldPool = activePosters().filter { p ->
            p.name != MODERATOR_REMOVED && p.name != MODERATOR && p.name !in OFFLINE_CATCH_UP
        }
        val heldAuthors = (0..3).map { heldPool[rnd.nextInt(heldPool.size)] }.distinct().take(3)
        val heldTexts = heldAuthors.mapIndexed { i, a ->
            val text = "held-$i-${a.name}"
            ChannelScenes.post(a, id, text)
            assertEquals("the removing candidate holds the post (CO-13)", 1L, a.count("ch_pending_post"))
            text
        }
        val c10RemovalEpoch = owner.channel(id)!!.epoch
        w.pastSettleWindow()
        w.quiesce()
        assertEquals(ChannelState.REMOVED, byName(MODERATOR_REMOVED).channel(id)!!.state)
        report.subjects += Subject(MODERATOR_REMOVED, "moderator-removal", c10RemovalEpoch, 0, seize(byName(MODERATOR_REMOVED), workDir, "c10-removed"))
        switch(w, ::byName, id)
        assertEquals("the removal moved the channel to generation 1", 1L, owner.channel(id)!!.generation)
        // The held posts flush into the new generation and display at every member — not at the removed one.
        w.quiesce()
        for (t in heldTexts) {
            assertTrue("the held post $t reached the anchor", lead().displayed(id).contains(t))
            assertTrue("the removed member does not see the held post", byName(MODERATOR_REMOVED).displayed(id).none { it == t })
        }

        // Removal kind 2 — a leave: c11 leaves, the owner's pass removes the leaver.
        assertEquals(
            org.ghost.messaging.channel.engine.ChannelPostStep.LeaveResult.LEFT,
            byName(LEAVER).engine.leave(id),
        )
        w.pump()
        owner.hintPass()
        assertEquals(1L, owner.count("ch_request", "kind = 'leave'"))
        w.advance(6 * DmWorld.HOUR)
        val leaveEpoch = owner.channel(id)!!.epoch
        var leaveGuard = 0
        while (byName(LEAVER).channel(id)!!.state == ChannelState.LEAVING && leaveGuard++ < 6) {
            clearArm(owner, id)
            duePass(w, owner)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
        }
        assertEquals(ChannelState.REMOVED, byName(LEAVER).channel(id)!!.state)
        report.subjects += Subject(LEAVER, "leave", leaveEpoch, 1, seize(byName(LEAVER), workDir, "c11-removed"))
        switch(w, ::byName, id)
        assertEquals("the leave moved the channel to generation 2", 2L, owner.channel(id)!!.generation)

        // Removal kind 3 — an idle eviction: c12 silent 63 virtual days, evicted by the owner's pass.
        backdateRefresh(owner, id, 70, pseudonymOf(byName(EVICTEE), id))
        w.advance(2 * DmWorld.DAY)
        val evictEpoch = owner.channel(id)!!.epoch
        var evictGuard = 0
        while (byName(EVICTEE).channel(id)!!.state != ChannelState.REMOVED && evictGuard++ < 6) {
            clearArm(owner, id)
            duePass(w, owner)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
        }
        assertEquals(ChannelState.REMOVED, byName(EVICTEE).channel(id)!!.state)
        report.subjects += Subject(EVICTEE, "idle-eviction", evictEpoch, 2, seize(byName(EVICTEE), workDir, "c12-removed"))
        switch(w, ::byName, id)
        assertEquals("the eviction moved the channel to generation 3", 3L, owner.channel(id)!!.generation)

        // The dark members missed ≥ 5 commits spanning the rotations; the channel lives on.
        pcs(owner)
        pcs(byName(MODERATOR))
        converged(w, ::byName, id, report, exclude = OFFLINE_CATCH_UP)
        val liveEpoch = owner.channel(id)!!.epoch
        for (d in dark) assertTrue("${d.name} is behind", d.channel(id)!!.epoch < liveEpoch)
        assertTrue(
            "at least five epochs passed over the dark members",
            liveEpoch - darkEpoch >= 5,
        )

        // They come back: the missed commits are still on the relays (their TTL is the 7-day
        // bucket, the window was shorter) — catch-up in order, then T41 everywhere.
        w.relay.modes = emptySet()
        w.relay.silentOrphan = { _, _ -> false }
        for (d in dark) {
            w.pump()
            d.hintPass()
            var guard = 0
            while (d.channel(id)!!.epoch < liveEpoch && guard++ < 60) {
                w.pastSettleWindow()
                w.quiesce()
            }
            assertEquals("${d.name} caught up", liveEpoch, d.channel(id)!!.epoch)
            assertEquals("${d.name} switched to the live generation", owner.channel(id)!!.generation, d.channel(id)!!.generation)
        }
        converged(w, ::byName, id, report)

        // Ranks 0 and 1 commit concurrently on one epoch (CO-3): one winner merges everywhere,
        // the loser re-passes.
        concurrentRace(w, ::byName, id, report)

        burst(40)

        // Removal kind 4 — the device swap: the swap subject goes dark; its missed commits die at
        // the relays past their TTL (EXPIRE_LOG); nine quiet days raise `stale_suspected`; the
        // resync's rejoin is never answered (the sweep gives up at 14 days → `reinvite_needed`);
        // a new invite returns the member through a **restore** by a new stack holding the same seed
        // — which rotates the generation (§19.16). The old stack keeps its state: it is a seizure
        // subject (its dump against every later epoch and generation must open 0).
        val swap = byName(swapSubject(config.variant))
        val swapRankBefore = rankOf(::byName, id, swap)
        val swapName = swap.name
        val swapPseudonym = pseudonymOf(swap, id)
        quietClocks(swap, id)
        val currentNs = generationNs(owner, id, owner.channel(id)!!.generation)
        w.relay.modes = setOf(ModelChannelRelay.Mode.EXPIRE_LOG)
        w.relay.expireLog = { it.namespace.contentEquals(currentNs) }
        w.advance(10 * DmWorld.DAY)
        burst(40)
        // Two forced commits while the subject is dark: its missed commits die at the relays past
        // their TTL (EXPIRE_LOG), so the subject is genuinely past its epoch when it returns.
        // Two epochs must open over the dark subject (its missed commits die past their TTL);
        // a pass is skipped while a candidate of the epoch is held (CO-7), so retry as needed.
        val swapWindowEpoch = owner.channel(id)!!.epoch
        var swapPcsGuard = 0
        while (owner.channel(id)!!.epoch < swapWindowEpoch + 2 && swapPcsGuard++ < 6) {
            pcs(lead())
            pcs(byName(MODERATOR))
        }
        settleToAnchor(w, ::byName, id, exclude = setOf(swapName))
        val swapDarkEpoch = swap.channel(id)!!.epoch
        repeat(3) {
            w.advance(4 * DmWorld.DAY)
            swap.sessionStart()
        }
        assertTrue("stale_suspected after nine quiet days", swap.channel(id)!!.staleSuspected)
        // §6.7's stale clock: a resync inside the committers' 14-day drain of the member's namespace
        // sends the rejoin request (unanswered here — EXPIRE_LOG keeps it from the committers — and
        // the sweep's give-up lands at `reinvite_needed` 14 days from the attempt); past the bound
        // the resync itself is the honest `reinvite_needed` — the design's device-swap path either
        // way (§12.5: the return is a new invite admitted as a restore).
        val swapResync = swap.engine.resync(id)
        if (swapResync == ChannelRejoinStep.ResyncResult.REQUESTED) {
            w.advance(15 * DmWorld.DAY)
            swap.timePass()
        }
        assertEquals(
            "the swap subject is at reinvite_needed (the unanswered rejoin gave up, or the stale clock said so)",
            ChannelState.REINVITE_NEEDED, swap.channel(id)!!.state,
        )
        val swapLiveEpoch = owner.channel(id)!!.epoch
        assertTrue("the missed commits are past the subject's epoch", swapLiveEpoch - swapDarkEpoch >= 2)

        // The return: a fresh invite, accepted by the restored stack — a copy of the dark device's
        // database (the row-holding restore of F-S7-2) under a new name with the same seed.
        w.relay.modes = emptySet()
        w.relay.expireLog = { false }
        w.pump()
        val link = ChannelAdmissionTest.invite(if (config.variant == Variant.OWNER_RESTORE) byName(MODERATOR) else owner, id)
        // The restore stack starts from a whole copy of the dark device's database.
        val swapDump = File(workDir, "$swapName-swap.db")
        snapshotOpenDb(swap, swapDump)
        val newDb = File(workDir, "$swapName-new.db")
        swapDump.copyTo(newDb, overwrite = true)
        val restored = w.client("$swapName-new", boot = 1, seedName = swapName, path = newDb.absolutePath)
        assertEquals(AcceptResult.PENDING, restored.engine.accept(link, null))
        assertEquals("the return is a restore", 1L, restored.count("ch_join", "type = 'restore'"))
        w.quiesce()
        if (config.stopAt == StopAt.RESTORE_ADMISSION) return id
        duePass(w, if (config.variant == Variant.OWNER_RESTORE) byName(MODERATOR) else owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        val restoreEpoch = owner.channel(id)!!.epoch
        assertEquals("the restored member is active", ChannelState.ACTIVE, restored.channel(id)!!.state)
        assertEquals(lead().channel(id)!!.epoch, restored.channel(id)!!.epoch)
        assertArrayEquals(
            "the restored member's authenticator",
            epochAuthenticator(lead(), id), epochAuthenticator(restored, id),
        )
        assertEquals("the restored member kept its rank", swapRankBefore, rankOf(::byName, id, restored))
        assertArrayEquals("the same pseudonym returns (D12)", swapPseudonym, pseudonymOf(restored, id))
        report.subjects += Subject(
            "$swapName-old", "device-swap (restore)", restoreEpoch, owner.channel(id)!!.generation - 1, swapDump,
        )
        // The long dark window made every member's PCS cadence due at once: settle the restore
        // commit everywhere before the switch arms the committers again, then settle the cadence
        // wave it triggers — T41 is asserted only once every member holds the same epoch.
        settleToAnchor(w, ::byName, id, exclude = setOf(swapName))
        switch(w, ::byName, id)
        assertEquals("the restore moved the channel to generation 4", 4L, owner.channel(id)!!.generation)
        settleToAnchor(w, ::byName, id, exclude = setOf(swapName))
        converged(w, ::byName, id, report, exclude = setOf(swapName))

        // The past-TTL member: c13 goes dark, its missed commits die past TTL, it rejoins (the
        // rejoin does not rotate). The freeze point for the crash singles sits on the admitting pass.
        val lost = byName(PAST_TTL)
        quietClocks(lost, id)
        val nsNow = generationNs(owner, id, owner.channel(id)!!.generation)
        w.relay.modes = setOf(ModelChannelRelay.Mode.EXPIRE_LOG)
        w.relay.expireLog = { it.namespace.contentEquals(nsNow) }
        // The window stays inside the stale clock's 14-day drain bound: this member **rejoins**
        // (§12.5), it does not need the return invite the swap subject's path ends in.
        w.advance(10 * DmWorld.DAY)
        burst(20)
        repeat(2) {
            w.advance(DmWorld.DAY)
            lost.sessionStart()
        }
        assertTrue(lost.channel(id)!!.staleSuspected)
        w.relay.modes = emptySet()
        w.relay.expireLog = { false }
        assertEquals(ChannelRejoinStep.ResyncResult.REQUESTED, lost.engine.resync(id))
        w.pump()
        if (config.stopAt == StopAt.REJOIN_ADMISSION) return id
        duePass(w, lead())
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("the past-TTL member rejoined", ChannelState.ACTIVE, lost.channel(id)!!.state)
        assertEquals(lead().channel(id)!!.epoch, lost.channel(id)!!.epoch)
        assertEquals("a rejoin does not rotate", 4L, owner.channel(id)!!.generation)
        // Catch-up: one pass, no wall-clock wait (SCN-CE's latency claim).
        ChannelScenes.post(lead(), id, "after-the-rejoin-${config.seed}")
        w.pump()
        lost.hintPass()
        assertTrue(lost.displayed(id).any { it.startsWith("after-the-rejoin-") })
        converged(w, ::byName, id, report, exclude = setOf(swapName))

        // The re-add: the moderator-removed client is re-invited and returns with the same pseudonym.
        val readdLink = ChannelAdmissionTest.invite(lead(), id)
        assertEquals(AcceptResult.PENDING, byName(MODERATOR_REMOVED).engine.accept(readdLink, null))
        w.quiesce()
        duePass(w, lead())
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        val readded = byName(MODERATOR_REMOVED)
        assertEquals("the removed client re-joined", ChannelState.ACTIVE, readded.channel(id)!!.state)
        assertArrayEquals("the re-added member returns with the same pseudonym (D12)", c10Pseudonym, pseudonymOf(readded, id))
        report.joiners += Joiner(MODERATOR_REMOVED, readded.channel(id)!!.epoch)

        burst(20)
        converged(w, ::byName, id, report, exclude = setOf(swapName))

        // The display half of the channel's T25 cases at M20 scale: no member displays a post past
        // its timer (the physical scans are EP-C's, S8).
        for (c in clients) {
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            val rows = c.database.transaction { tx ->
                c.channelStores.posts.page(tx.sql, id.toByteArray(), Long.MAX_VALUE, 10_000)
            }
            for (row in rows) {
                assertTrue("an expired post is not displayed (T25)", row.deleteAtMinute == null || row.deleteAtMinute > c.clock.now)
            }
        }

        report.postsStored = w.relay.stored.count { it.purpose == "post" && !it.injected }
        report.epochs = lead().channel(id)!!.epoch.toInt()
        report.generations = owner.channel(id)!!.generation.toInt() + 1
        for (c in clients) {
            if (c.channel(id)?.state == ChannelState.ACTIVE) assertTrue("${c.name}: ${c.integrity()}", c.integrity().isEmpty())
        }
        assertTrue("the restored stack: ${restored.integrity()}", restored.integrity().isEmpty())
        return id
    }

    // --------------------------------------------------------------------------------------- the FORK variant

    /**
     * The FORK variant (§12.5): at a 20-client channel the relay serves three same-epoch commits to
     * disjoint subsets — the rank-0 PCS commit to the owner side, the rank-1 PCS commit to a
     * several-member side, a rank-255 self-update to one member alone — and keeps the partition
     * through the settle window. The opening also delivers a worse-ranked candidate to every
     * member minutes before the better one: the settle window is what makes every member settle
     * the same winner (the no-settle-window mutant MM-3 breaks exactly here).
     *
     * What the subsets see afterwards, honestly (F-S10-1): cross-branch traffic of a later epoch is
     * sealed under the other branch's epoch key — its hint matches no key a member holds, which is
     * the declared shape of *future-epoch traffic* (ChannelLivenessStep: such a blob never counts
     * toward CO-11). The several-member side therefore receives the fork junk of §12.1's model —
     * blobs sealed under its own epoch key id that do not open, what a hostile fork's traffic looks
     * to the wrong branch (the S7 scenario's modelling) — and, with its own branch progressing,
     * matures its window into `split_suspected` (CO-12, the adopted D-3). The one-member side sees
     * nothing openable and no committer commit of its own: the honest dead branch reaches its user
     * through `stale_suspected` (CO-12's 9-day clock) and the scripted `resync`. Both sides then
     * rejoin the owner's branch, whose fingerprint the comparison names as the live one, and the
     * authenticators converge (T41).
     */
    fun buildFork(seed: Long, dbDir: File? = null): Built {
        val world = ChannelWorld()
        val report = Report(seed, Variant.BASE)
        val rnd = Random(seed)
        lateinit var id: ChannelId
        val elapsed = measureTimeMillis {
            // (the fork world is file-backed like the base run)
            val workDir = dbDir ?: java.nio.file.Files.createTempDirectory("ghost-m20-fork").toFile()
            fun mk(name: String): ChannelClient =
                world.client(name, path = File(workDir, "$name.db").absolutePath)
            val owner = mk(OWNER)
            val clients = ALL.map { if (it == OWNER) owner else mk(it) }
            fun byName(name: String): ChannelClient = clients.first { it.name == name }
            report.clients = clients.size
            id = ChannelAdmissionTest.create(owner)
            val joiners = clients.filter { it.name != OWNER }
            for (wave in joiners.chunked(4)) {
                for (j in wave) {
                    assertEquals(AcceptResult.PENDING, j.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
                }
                world.quiesce()
                var guard = 0
                while (wave.any { it.channel(id)?.state != ChannelState.ACTIVE } && guard++ < 4) {
                    if (guard > 1) {
                        val cid = world.clients.first { it.name == OWNER }.let { org.ghost.messaging.api.ChannelId(it.database.transaction { tx -> var b: ByteArray? = null; tx.sql.query("SELECT channel_id FROM ch_channel") { b = it.blob(0) }; b!! }) }
                        clearArm(world.clients.first { it.name == OWNER }, cid)
                    }
                    world.admissionPass(owner)
                    world.quiesce()
                    world.pastSettleWindow()
                    world.quiesce()
                }
            }
            makeCommitter(world, ::byName, id)
            val sideBNames = listOf("c3", "c4", "c5", "c6")
            val sideB = sideBNames.map { byName(it) }
            val alone = byName("c20")
            val moderate = byName(MODERATOR)

            // Traffic before the fork.
            repeat(30) {
                val author = joiners[rnd.nextInt(joiners.size)]
                ChannelScenes.post(author, id, "pre-fork-$it-${author.name}")
            }
            world.quiesce()

            // The settle-window half (MM-3's shape): every member first receives a worse-ranked
            // candidate — c14's rank-255 self-update — and only minutes later the rank-0 PCS commit.
            val selfUp = byName("c14")
            bringSlotTo(selfUp, id)
            duePass(world, selfUp)
            world.quiesce()
            agePcsClock(owner, id, 8)
            clearArm(owner, id)
            owner.sessionStart()
            world.advance(6 * DmWorld.MINUTE)
            owner.timePass()
            assertEquals(1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
            val raceEpoch = owner.channel(id)!!.epoch
            // Round 1: only the rank-255 commit is served; every member passes while holding it.
            world.relay.holdAt = { name, s -> s.purpose == "commit" && s.from == selfUp.name && name != selfUp.name }
            world.pump()
            for (c in clients) c.hintPass()
            // No one settles: the window has not run since the first sighting (CO-4).
            for (c in clients) {
                assertEquals("no early settle (the window holds)", raceEpoch, c.channel(id)!!.epoch)
            }
            // Round 2: the rank-0 commit arrives; after the window every member settles it — the
            // same winner everywhere (T41). A zeroed window settled the rank-255 commit in round 1
            // at half the members (their next pass) and CO-6 never lets them move: the
            // authenticators diverge, which is MM-3's detection.
            world.relay.holdAt = { _, _ -> false }
            world.pump()
            for (c in clients) c.hintPass()
            world.advance(21 * DmWorld.MINUTE)
            world.pump()
            for (c in clients) c.timePass()
            world.quiesce()
            for (c in clients) {
                assertEquals("everyone settled the better candidate", raceEpoch + 1, c.channel(id)!!.epoch)
            }
            converged(world, ::byName, id, report)

            // The fork proper: two same-epoch commits served to disjoint subsets through the
            // settle window; c20 alone settles its own rank-255 self-update (a branch born dead —
            // no other member holds it).
            world.relay.modes = setOf(ModelChannelRelay.Mode.FORK)
            world.relay.forkServing = { s ->
                when {
                    s.purpose == "commit" && s.from == OWNER ->
                        (setOf(OWNER) + ALL.filter { it !in sideBNames && it != "c20" })
                    s.purpose == "commit" && s.from == MODERATOR -> sideBNames.toSet()
                    else -> null
                }
            }
            agePcsClock(owner, id, 8)
            agePcsClock(moderate, id, 8)
            clearArm(owner, id)
            clearArm(moderate, id)
            owner.sessionStart()
            moderate.sessionStart()
            world.advance(6 * DmWorld.MINUTE)
            owner.timePass()
            moderate.timePass()
            bringSlotTo(alone, id)
            duePass(world, alone)
            world.pump()
            world.advance(21 * DmWorld.MINUTE)
            world.pump()
            for (c in clients) c.timePass()
            world.quiesce()
            val ownerAuth = epochAuthenticator(owner, id)
            for (b in sideB) {
                assertNotEquals("side B settled its own winner", ownerAuth, epochAuthenticator(b, id))
            }
            assertNotEquals("the alone member settled its own winner", ownerAuth, epochAuthenticator(alone, id))

            // The partition heals; both branches keep progressing independently (each side's
            // later-epoch traffic is unopenable to the other — the honest fork shape, F-S10-1).
            world.relay.modes = emptySet()
            world.relay.forkServing = { null }
            world.pump()
            repeat(8) {
                val author = sideB[rnd.nextInt(sideB.size)]
                ChannelScenes.post(author, id, "side-b-$it-${author.name}")
            }
            world.pump()
            for (b in sideB) b.hintPass()
            agePcsClock(moderate, id, 8)
            duePass(world, moderate)
            world.pump()
            for (c in clients) c.hintPass()
            world.pastSettleWindow()
            world.quiesce()
            repeat(5) {
                ChannelScenes.post(owner, id, "side-a-$it")
                world.pump()
                for (c in clients) c.hintPass()
            }
            // The fork junk of §12.1's model: blobs of the current namespace sealed under side B's
            // epoch key id that do not open — with side B's own progress in the window, the mature
            // window raises `split_suspected` (and never `resync_needed`).
            repeat(3) {
                val junk = ByteArray(700) { ((it * 31 + it * 13) % 251).toByte() }
                world.relay.inject(
                    ChannelAdversary.namespace(sideB.first(), id),
                    ChannelAdversary.sealJunk(sideB.first(), id, junk),
                    world.now, "fork-junk-$it",
                )
            }
            world.pump()
            for (b in sideB) b.hintPass()
            var guard = 0
            while (sideB.count { it.channel(id)!!.splitSuspected } < sideBNames.size && guard++ < 12) {
                world.advance(DmWorld.DAY)
                world.pump()
                for (b in sideB) {
                    ChannelScenes.post(b, id, "side-b-ziua-$guard-${b.name}")
                }
                world.pump()
                for (b in sideB) b.hintPass()
                for (c in clients) c.timePass()
            }
            assertEquals(
                "the several-member side raised split_suspected (CO-12, D-3)",
                sideBNames.size, sideB.count { it.channel(id)!!.splitSuspected },
            )
            assertTrue(
                "progress kept the side out of resync_needed",
                sideB.all { it.channel(id)!!.state == ChannelState.ACTIVE },
            )
            report.forkSidesSplitSuspected = sideB.count { it.channel(id)!!.splitSuspected }

            // The scripted recovery: the fingerprint comparison (out of band, §12.5) — side B's
            // differs from the owner's — then `resync`; the owner's passes admit every rejoin (the
            // claimed epochs' winners differ on the two branches, §6.7's fork case) and the side
            // converges back.
            assertNotEquals(epochAuthenticator(sideB.first(), id), ownerAuth)
            for (b in sideB) assertEquals(ChannelRejoinStep.ResyncResult.REQUESTED, b.engine.resync(id))
            world.pump()
            admitUntil(world, ::byName, id, owner, sideBNames)
            for (b in sideB) {
                assertEquals("${b.name} rejoined the owner's branch", ChannelState.ACTIVE, b.channel(id)!!.state)
                assertArrayEquals("the authenticators agree again (T41)", ownerAuth, epochAuthenticator(b, id))
                report.forkMembersRejoined++
            }
            // The alone member: nothing of its branch ever arrived; nine quiet days raise
            // `stale_suspected` and the user resyncs (the honest dead branch, F-S10-1).
            world.pump()
            alone.hintPass()
            var aloneGuard = 0
            while (alone.channel(id)!!.state != ChannelState.RESYNC_NEEDED && aloneGuard++ < 14) {
                world.advance(DmWorld.DAY)
                world.pump()
                alone.sessionStart()
                alone.timePass()
            }
            // The honest flow flags stale_suspected, not resync_needed; either ends in the user's
            // resync — assert the flag or the state, then resync.
            assertTrue(
                "the one-member side found its branch dead",
                alone.channel(id)!!.state == ChannelState.RESYNC_NEEDED || alone.channel(id)!!.staleSuspected,
            )
            assertEquals(ChannelRejoinStep.ResyncResult.REQUESTED, alone.engine.resync(id))
            world.pump()
            admitUntil(world, ::byName, id, owner, listOf("c20"))
            assertEquals("the alone member rejoined", ChannelState.ACTIVE, alone.channel(id)!!.state)
            assertArrayEquals(ownerAuth, epochAuthenticator(alone, id))
            report.forkMembersRejoined++

            converged(world, ::byName, id, report)
            report.postsStored = world.relay.stored.count { it.purpose == "post" && !it.injected }
            report.epochs = owner.channel(id)!!.epoch.toInt()
            report.generations = owner.count("ch_generation").toInt()
        }
        report.wallSeconds = elapsed / 1000.0
        return Built(world, report, id, world.clients.first { it.name == OWNER }, world.clients.toList())
    }

    // ----------------------------------------------------------------------------------------------- helpers

    /**
     * T41 at M20 scale: every active member named in [ALL] (minus [exclude]) holds the anchor's
     * epoch, the same `epoch_authenticator` and the same per-epoch winner hashes (the anchor is the
     * owner's side's live member — c2 while the owner is dark in the owner-restore variant).
     */
    private fun converged(
        w: ChannelWorld,
        byName: (String) -> ChannelClient,
        id: ChannelId,
        report: Report,
        exclude: Set<String> = emptySet(),
    ) {
        val anchor = byName(if (exclude.contains(OWNER)) MODERATOR else OWNER)
        val anchorEpoch = anchor.channel(id)!!.epoch
        val anchorAuth = epochAuthenticator(anchor, id)
        val anchorLog = epochLog(anchor, id)
        for (name in ALL) {
            if (name in exclude) continue
            val c = byName(name)
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            assertEquals("T41: $name at the anchor's epoch", anchorEpoch, c.channel(id)!!.epoch)
            assertArrayEquals("T41: $name's epoch_authenticator", anchorAuth, epochAuthenticator(c, id))
            // The epoch log is what the member settled itself: a joiner's log starts at its join
            // epoch, so it must equal the anchor's rows from its first logged epoch on (empty at a
            // member that has not settled an epoch yet: nothing to compare).
            val memberLog = epochLog(c, id)
            if (memberLog.isNotEmpty()) {
                assertEquals(
                    "T41: $name's epoch log",
                    anchorLog.filter { it.first >= memberLog.first().first },
                    memberLog,
                )
            }
        }
        report.t41Checks++
    }

    /** Ranks 0 and 1 commit on one epoch; one winner everywhere (SCN-CD's race at M20 scale). */
    private fun concurrentRace(
        w: ChannelWorld,
        byName: (String) -> ChannelClient,
        id: ChannelId,
        report: Report,
    ) {
        val owner = byName(OWNER)
        val moderate = byName(MODERATOR)
        val epoch = owner.channel(id)!!.epoch
        agePcsClock(owner, id, 8)
        agePcsClock(moderate, id, 8)
        clearArm(owner, id)
        clearArm(moderate, id)
        owner.sessionStart()
        moderate.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        owner.timePass()
        moderate.timePass()
        assertEquals(1L, owner.count("ch_candidate", "own = 1 AND rank = 0"))
        assertEquals(1L, moderate.count("ch_candidate", "own = 1 AND rank = 1"))
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("one epoch advanced (CO-3, one winner)", epoch + 1, owner.channel(id)!!.epoch)
        assertNull("the loser cleared its pending commit", ownRow(moderate, id, epoch))
        w.advance(6 * DmWorld.HOUR)
        duePass(w, moderate)
        assertEquals(0L, moderate.count("ch_candidate", "own = 1"))
        converged(w, byName, id, report)
    }

    /** The committer's passes until every named member is active at the anchor's epoch (fork rejoins). */
    private fun admitUntil(
        w: ChannelWorld,
        byName: (String) -> ChannelClient,
        id: ChannelId,
        committer: ChannelClient,
        names: List<String>,
    ) {
        var guard = 0
        while (guard++ < 8) {
            val done = names.all { byName(it).channel(id)?.state == ChannelState.ACTIVE && byName(it).channel(id)!!.epoch == committer.channel(id)!!.epoch }
            if (done) return
            duePass(w, committer)
            w.quiesce()
            w.pastSettleWindow()
            w.quiesce()
        }
        fail("the rejoins of $names did not complete")
    }

    /**
     * `CH-SWITCH` at every active member: the pending generation (a rotation's) becomes current.
     * The production op GC (which the model relay does not run) collects the released ops first:
     * a namespace's removal — the older drain's end at a second rotation — is refused while any
     * op of it is open, and the switch would defer for ever (the S6 suites' `collectOps` stand-in).
     */
    /** Settle rounds until every active member (minus [exclude]) holds the anchor's epoch. */
    private fun settleToAnchor(w: ChannelWorld, byName: (String) -> ChannelClient, id: ChannelId, exclude: Set<String> = emptySet()) {
        val anchor = byName(if (exclude.contains(OWNER)) MODERATOR else OWNER)
        val target = anchor.channel(id)!!.epoch
        var guard = 0
        while (guard++ < 80) {
            val behind = ALL.any { name ->
                name !in exclude && byName(name).channel(id)?.state == ChannelState.ACTIVE &&
                    byName(name).channel(id)!!.epoch < target
            }
            if (!behind) return
            w.pastSettleWindow()
            w.quiesce()
        }
        error(
            "the members did not settle to the anchor's epoch $target: " +
                ALL.joinToString(" ") { n ->
                    val ch = byName(n).channel(id)
                    "$n=${ch?.state}@${ch?.epoch}"
                },
        )
    }


    private fun switch(w: ChannelWorld, byName: (String) -> ChannelClient, id: ChannelId) {
        for (name in ALL) {
            val c = byName(name)
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            c.database.transaction { tx ->
                tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
                tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
            }
        }
        w.advance(2 * DmWorld.HOUR + 60)
        for (name in ALL) {
            val c = byName(name)
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            c.sessionStart()
        }
        w.advance(6 * DmWorld.MINUTE)
        for (name in ALL) {
            val c = byName(name)
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            c.timePass()
        }
        w.quiesce()
        // A member's pass can defer once (an unconsumed fetched row of the old namespace refuses
        // the removal; the row is consumed in the same pass and the next one switches).
        w.pump()
        for (name in ALL) {
            val c = byName(name)
            if (c.channel(id)?.state != ChannelState.ACTIVE) continue
            c.hintPass()
        }
        // The session starts armed every member whose PCS cadence is due (§6.8): their rank-255
        // self-updates are honest candidates of the current epoch — settle them before the next
        // step (CO-7 refuses a pass over any held candidate).
        w.pastSettleWindow()
        w.quiesce()
    }

    /** The member's rank in the current context (255 when it is not a committer). */
    private fun rankOf(byName: (String) -> ChannelClient, id: ChannelId, member: ChannelClient): Int {
        val policy = ChannelAdversary.policy(byName(OWNER), id)
        val p = pseudonymOf(member, id)
        val at = policy.committers.indexOfFirst { it.contentEquals(p) }
        return if (at < 0) 255 else at
    }

    /** A rank-0 context change: c2 joins the committers and the funders (§12.5's ranks and funders). */
    private fun makeCommitter(w: ChannelWorld, byName: (String) -> ChannelClient, id: ChannelId) {
        val owner = byName(OWNER)
        val bob = byName(MODERATOR)
        val before = ChannelAdversary.policy(owner, id)
        val after = org.ghost.crypto.bridge.ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)),
            listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)),
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == OWNER }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (name in ALL) {
            val c = byName(name)
            if (c.channel(id)?.state == ChannelState.ACTIVE) c.timePass()
        }
        w.quiesce()
    }

    /**
     * A consistent copy of [client]'s database (SQLite's `VACUUM INTO` reads through the WAL).
     * The vacuum runs on a **fresh connection** to the client's file: the live executor caches
     * prepared statements, and SQLite refuses a vacuum with statements in progress. The world is
     * quiesced and single-threaded at every call site, so a second connection reads a stable state.
     */
    fun snapshotOpenDb(client: ChannelClient, dest: File) {
        val source = client.dbPath ?: error("a snapshot needs a file-backed client")
        if (dest.exists()) dest.delete()
        val target = dest.absolutePath.replace("'", "''")
        java.sql.DriverManager.getConnection("jdbc:sqlite:$source").use { conn ->
            conn.createStatement().use { it.execute("VACUUM INTO '$target'") }
        }
    }

    /** The epoch's authenticator through the client's own context: the crash singles' T41 half. */
    fun epochAuthenticatorOf(client: ChannelClient, id: ChannelId): ByteArray = epochAuthenticator(client, id)

    /** The seizure dump of [client]: a consistent copy of its database file at this moment. */
    private fun seize(client: ChannelClient, dir: File, tag: String): File {
        val dest = File(dir, "$tag.db")
        snapshotOpenDb(client, dest)
        return dest
    }

    private fun epochAuthenticator(client: ChannelClient, id: ChannelId): ByteArray =
        client.database.transaction { tx ->
            val rows = MlsRows.of(client.channelStores.mls.rows(tx.sql, id.toByteArray(), DmTime.day(client.clock.now)))
            client.contexts.open(id.toByteArray())!!.crypto
                .roster(id.toByteArray(), rows, DmTime.day(client.clock.now).toInt()).valueOrNull()!!.epochAuthenticator
        }

    private fun epochLog(client: ChannelClient, id: ChannelId): List<Pair<Long, String>> =
        client.database.transaction { tx ->
            val out = ArrayList<Pair<Long, String>>()
            tx.sql.query(
                "SELECT epoch, winner_hash FROM ch_epoch_log WHERE channel_id = ? ORDER BY epoch",
                listOf(id.toByteArray()),
            ) { out += it.long(0) to ChannelWorld.hex(it.blob(1)) }
            out
        }

    private fun ownRow(client: ChannelClient, id: ChannelId, epoch: Long): org.ghost.messaging.channel.store.CandidateStore.CandidateRow? =
        client.database.transaction { tx ->
            client.channelStores.candidates.own(tx.sql, id.toByteArray(), epoch)
        }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    private fun generationNs(client: ChannelClient, id: ChannelId, generation: Long): ByteArray =
        client.database.transaction { tx ->
            var ns: ByteArray? = null
            tx.sql.query(
                "SELECT namespace_id FROM ch_generation WHERE channel_id = ? AND generation = ?",
                listOf(id.toByteArray(), generation),
            ) { ns = it.blob(0) }
            ns!!
        }

    private fun quietClocks(client: ChannelClient, id: ChannelId) {
        val day = DmTime.day(client.clock.now)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), day + 365, day, row?.nextPassMinute)
        }
    }

    private fun bringSlotTo(client: ChannelClient, id: ChannelId) {
        val day = DmTime.day(client.clock.now)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), day, row?.lastOwnCommitDay ?: day, row?.nextPassMinute)
        }
    }

    private fun agePcsClock(client: ChannelClient, id: ChannelId, days: Long) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row?.nextSelfupdateDay ?: day, day, row?.nextPassMinute)
        }
    }

    private fun duePass(w: ChannelWorld, client: ChannelClient) {
        val id = currentChannelId(client)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
        client.sessionStart()
        w.advance(6 * DmWorld.MINUTE)
        client.timePass()
    }

    private fun currentChannelId(client: ChannelClient): ChannelId =
        client.database.transaction { tx ->
            var cid: ByteArray? = null
            tx.sql.query("SELECT channel_id FROM ch_channel") { cid = it.blob(0) }
            ChannelId(cid!!)
        }

    private fun clearArm(client: ChannelClient, id: ChannelId) {
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
    }

    /** The member's refresh row aged [days] back (the idle-eviction clock, §6.6). */
    private fun backdateRefresh(client: ChannelClient, id: ChannelId, days: Long, only: ByteArray) {
        val day = DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            client.channelStores.members.putRefresh(tx, id.toByteArray(), only, day)
        }
    }
}

/**
 * The channel exit scenario's report lines (Phase 10 design §12.5, §13.1 `ch-report-check`'s channel
 * file; the DM suites' `PrivacyReport` pattern). Each line names what the run compared (§15 item
 * 10a): STANDARD only — HIGH mode, the redeem lane and circuit timing are S11's (§19.33).
 */
internal object ChannelReport {
    private val lock = Any()

    @Volatile
    private var started = false

    val path: String
        get() = System.getProperty("ghost.channel.report") ?: "build/reports/channel/report.txt"

    fun line(text: String) {
        synchronized(lock) {
            val file = File(path).also { it.parentFile?.mkdirs() }
            if (!started) {
                file.writeText(
                    "GHOST channel exit scenario (Phase 10 design §12.5, SCN-M20; slice S10)\n" +
                        "mode: STANDARD (HIGH mode, the redeem lane and circuit timing are S11's, §19.33; " +
                        "each line names what it compared, §15 item 10a)\n",
                )
                started = true
            }
            file.appendText(text.trimEnd() + "\n")
        }
    }
}
