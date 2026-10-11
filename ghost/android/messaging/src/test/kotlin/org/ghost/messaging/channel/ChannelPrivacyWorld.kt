package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.sync.api.PrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.io.File
import kotlin.random.Random
import kotlin.system.measureTimeMillis

/**
 * **The channel privacy world** (Phase 10 design §12.7): 60 clients, 12 channels (5 … 20 members,
 * at most 9 channels per client — here at most 3, well under), invites, admissions, removals with
 * rotations, an offline window across a rotation, day-grain traffic over 28 virtual days (PR
 * scale; the gate scale is 56 days, seeds pinned from the measured per-seed time, S0-18), over
 * the real OpenMLS through `ghost-dm-host`. The world's relay ([ModelChannelRelay]) records the
 * effective view of §2.1 — stores, lists and gets with their credentials and circuits, register
 * calls — on which the exact searches JC-1 … JC-7 run ([ChannelPrivacyChecks]).
 *
 * **The choreography** is seeded ([Config.seed], a Kotlin [Random] over fixed client and channel
 * names — §12.1's method); the native draws stay unseeded (the S4 rule: assertions are about
 * states, counts, shapes and oracles, never native-drawn bytes). Days advance in grain steps; the
 * world's traffic per day is small (about one post per channel per day, the PCS cadence of quiet
 * channels, the scheduled removals) — the runtime budget is measured per seed ([Built.report],
 * §12.7's scale notes) and the seed count is pinned at S11's exit.
 *
 * **What is in the world** (§12.7's list): invites and admissions (every channel admitted by its
 * creator's passes, in waves bounded by the commit floor), removals of every kind the M20
 * scenario names at the scale of one channel each (a moderator removal, a leave, an idle
 * eviction — each rotates its channel, §6.5), an offline window across a rotation with an
 * in-order catch-up, funders and the renewal step (the week's registrations, §7.5 item 7), and
 * timer variety across channels (7-day, 30-day and off — JC-4's three classes). Timer *changes*
 * inside a channel are not choreographed: the policy actions' user entry points are Phase 13's
 * (§19.39 row 12), so a namespace carries one timer version and JC-4's stale-invite exception is
 * counted and reported as 0 (declared in the line, §15 item 10a). DMs are not carried by this
 * world: a combined DM+channel client does not exist in the harness, and the DM halves of the
 * privacy argument are the DM privacy world's and the entitlement world's (dm-privacy-gate); the
 * channel world proves the channel halves. Recorded as F-S11-1 in §19.51.
 *
 * **Modes.** [Config.highMode] runs every client's `:sync` stores in HIGH: each store waits its
 * `not_before_minute` and is collected by a later round (the relay's delay counter), which is
 * what JC-6's send-delay rule reads. STANDARD is the default; the twins run STANDARD (their
 * comparison is structural — minutes are compared only through the declared LC differences).
 */
internal class ChannelPrivacyWorld(val config: Config) : AutoCloseable {

    class Config(
        val seed: Long,
        val clients: Int = 60,
        val days: Int = 28,
        /** Non-null: every client file-backed under it (the seizure dumps); null: a temp dir. */
        val dbDir: File? = null,
        val highMode: Boolean = false,
        /** A twin's day-14 hook (NI-CH1 at world scale); null runs the plain choreography. */
        val midRun: ((ChannelPrivacyWorld) -> Unit)? = null,
    )

    /** One channel of the world and its cast. */
    class ChannelInfo(
        val id: ChannelId,
        val name: String,
        val timerCode: Int,
        val owner: ChannelClient,
        /** Every client admitted at any time (removed ones included), in admission order. */
        val cast: List<ChannelClient>,
    )

    class Report(
        val seed: Long,
        val highMode: Boolean,
        var days: Int = 0,
        var wallSeconds: Double = 0.0,
        var channels: Int = 0,
        var postsStored: Int = 0,
        var commitsStored: Int = 0,
        var generations: Int = 0,
        var removals: Int = 0,
        var admissionJoiners: Int = 0,
        /** T38 subjects: (name, kind, dump, removedAtEpoch, heldGeneration, channel). */
        val subjects: MutableList<Subject> = ArrayList(),
    )

    /** A T38 seizure subject of the world (a removal dump and its cutoffs). */
    class Subject(
        val name: String,
        val kind: String,
        val dump: File,
        val removedAtEpoch: Long,
        val heldGeneration: Long,
        val channel: ChannelInfo,
    )

    class Built(
        val world: ChannelWorld,
        val report: Report,
        val channels: List<ChannelInfo>,
        val clients: List<ChannelClient>,
        /** Every generation namespace the world saw → (channel, generation); JC-5's map. */
        val namespaces: Map<String, Pair<ChannelId, Long>> = emptyMap(),
    )

    val world = ChannelWorld()
    lateinit var clients: List<ChannelClient>
    lateinit var channels: List<ChannelInfo>

    /**
     * Every generation namespace the world ever saw → (its channel, its generation), recorded
     * because a live member's `ch_generation` rows lose the finished drains to the sweep (§6.5) —
     * JC-5's blob set and namespace map must reach a removed subject's own era, which only the
     * union of the live clients' rows and the subjects' seizure dumps still names.
     */
    val namespaceGeneration = LinkedHashMap<String, Pair<ChannelId, Long>>()

    private fun recordGenerations(client: ChannelClient, channels: List<ChannelInfo>) {
        for (info in channels) {
            client.sql.query(
                "SELECT namespace_id, generation FROM ch_generation WHERE channel_id = ?",
                listOf(info.id.toByteArray()),
            ) {
                namespaceGeneration[ModelChannelRelay.hex(it.blob(0))] = info.id to it.long(1)
            }
        }
    }

    /** The day's ordinal at the world's clock (0-based from the start). */
    fun day(): Long = (world.now - world.startSeconds) / DmWorld.DAY

    private fun mk(name: String): ChannelClient =
        world.client(
            name,
            privacyMode = if (config.highMode) PrivacyMode.HIGH else PrivacyMode.STANDARD,
            path = File(workDir, "$name.db").absolutePath,
        )

    private val workDir: File by lazy { config.dbDir ?: java.nio.file.Files.createTempDirectory("ghost-privacy").toFile() }

    override fun close() = world.close()

    // --------------------------------------------------------------------------------------------- building

    fun build(): Built {
        val report = Report(config.seed, config.highMode, days = config.days)
        val elapsed = measureTimeMillis { run(report) }
        report.wallSeconds = elapsed / 1000.0
        return Built(world, report, channels, clients, namespaceGeneration.toMap())
    }

    private fun run(report: Report) {
        val rnd = Random(config.seed)
        clients = (0 until config.clients).map { mk("p$it") }

        // The channel plan: twelve channels, 5 … 20 members, timers 7 d / 30 d / off. Membership
        // is a seeded shuffle: every client joins one to three channels (the design's bound is 9).
        val plan = listOf(
            Triple("salon", 12, 4),
            Triple("camin", 8, 4),
            Triple("echipa", 8, 4),
            Triple("vecini", 8, 4),
            Triple("proiect", 8, 4),
            Triple("clasa", 8, 4),
            Triple("drumetie", 8, 4),
            Triple("arhiva", 6, 5),
            Triple("anunt", 5, 0),
            Triple("club", 6, 4),
            Triple("tura", 5, 4),
            Triple("garaj", 6, 4),
        )
        val membership = Array(plan.size) { ArrayList<ChannelClient>() }
        val perClient = HashMap<String, Int>()
        val shuffled = clients.shuffled(rnd)
        var cursor = 0
        for ((index, entry) in plan.withIndex().sortedByDescending { it.value.second }) {
            val want = entry.second
            val picked = LinkedHashSet<ChannelClient>()
            while (picked.size < want) {
                val c = shuffled[cursor % shuffled.size]
                cursor++
                if (perClient.getOrDefault(c.name, 0) >= 3) continue
                if (!picked.add(c)) continue
                perClient.merge(c.name, 1, Int::plus)
            }
            membership[index] += picked
        }

        // Day 0 … 2: creates and admissions. Every channel's members join by the owner's invite,
        // admitted in waves of at most four (one commit's floor), the requests aged where a
        // rank-1 committer's work-age rule needs it (only the big channel names a moderator).
        channels = plan.mapIndexed { index, (name, _, timer) ->
            val owner = membership[index].first()
            val id = ChannelAdmissionTest.create(owner)
            ChannelInfo(id, name, timer, owner, membership[index].toList()).also { report.channels++ }
        }
        for ((index, info) in channels.withIndex()) {
            admitChannel(info, rnd, moderator = if (index == 0) info.cast.getOrNull(1) else null)
            report.admissionJoiners += info.cast.size - 1
        }
        world.advance(2 * DmWorld.DAY)

        // Funders: the owner and the second member of the big channel (§12.5's shape at world
        // scale), named through a rank-0 context change like SCN-M20's.
        makeCommitter(channels[0])

        // The traffic days. Per day: about one post per channel by a seeded active member; the
        // scheduled removals; the offline window; the PCS cadence falls out of the pass ageing.
        val removalPlan = sortedMapOf<Long, () -> Unit>(
            6L to { removeKind(channels[0], "moderator", channels[0].cast[1], rnd, report) },
            12L to { leaveKind(channels[0], rnd, report) },
            18L to { evictKind(channels[0], rnd, report) },
            10L to { removeKind(channels[1], "owner", channels[1].owner, rnd, report) },
            15L to { leaveKind(channels[3], rnd, report) },
        )
        // The offline window of the big channel: cast[2] goes dark days 8 … 13, across the day-12
        // removal's rotation, and catches up in order (LC-4's draining-namespace catch-up).
        val dark = channels[0].cast[2]
        var darkUntil = -1L
        for (d in 0 until config.days) {
            if (d == 8) {
                quietClocks(dark, channels[0].id)
                world.relay.modes = setOf(ModelChannelRelay.Mode.SILENT_ORPHAN)
                world.relay.silentOrphan = { name, _ -> name == dark.name }
            }
            if (d == 13) {
                world.relay.modes = emptySet()
                world.relay.silentOrphan = { _, _ -> false }
                darkUntil = d.toLong()
            }
            removalPlan[d.toLong()]?.invoke()
            for (info in channels) {
                val posters = activePosters(info)
                if (posters.isEmpty()) continue
                // About one post per channel per day, seeded; the big channel carries two.
                val count = if (info === channels[0]) 2 else 1
                repeat(count) {
                    val author = posters[rnd.nextInt(posters.size)]
                    ChannelScenes.post(author, info.id, "z$d-${info.name}-${author.name}-${rnd.nextInt(1_000_000)}")
                }
            }
            world.quiesce()
            if (d.toLong() == darkUntil) catchUp(dark, channels[0])
            world.advance(DmWorld.DAY)
            if (config.midRun != null && d == 13) config.midRun!!.invoke(this)
        }

        // The tail: settle every channel, run the switches the last rotations armed, and drain.
        for (info in channels) {
            world.quiesce()
            world.pastSettleWindow()
            world.quiesce()
        }
        world.advance(DmWorld.DAY)
        for (info in channels) {
            world.quiesce()
            world.pastSettleWindow()
            world.quiesce()
        }

        report.postsStored = world.relay.stored.count { it.purpose == "post" && !it.injected }
        report.commitsStored = world.relay.stored.count { it.purpose == "commit" && !it.injected }
        report.generations = channels.sumOf { info ->
            clients.maxOf { it.count("ch_generation", "channel_id = ?", info.id.toByteArray()) }.toInt()
        }
        // JC-5's namespace map: the union of every live client's generation rows and every
        // subject dump's — a finished drain's row survives in at least one of them.
        for (c in clients) recordGenerations(c, channels)
        for (s in report.subjects) {
            org.ghost.storage.JdbcSqlExecutor(s.dump.absolutePath).use { ex ->
                for (info in channels) {
                    ex.query(
                        "SELECT namespace_id, generation FROM ch_generation WHERE channel_id = ?",
                        listOf(info.id.toByteArray()),
                    ) {
                        namespaceGeneration[ModelChannelRelay.hex(it.blob(0))] = info.id to it.long(1)
                    }
                }
            }
        }
        for (c in clients) assertTrue("${c.name}: ${c.integrity()}", c.integrity().isEmpty())
    }

    // --------------------------------------------------------------------------------------------- scenes

    /** Admits every member of [info] by the owner's passes, in waves of four. */
    private fun admitChannel(info: ChannelInfo, rnd: Random, moderator: ChannelClient?) {
        val owner = info.owner
        val joiners = info.cast.filter { it !== owner }
        val waves = joiners.chunked(4)
        for ((waveIndex, wave) in waves.withIndex()) {
            for (j in wave) {
                assertEquals(AcceptResult.PENDING, j.engine.accept(ChannelAdmissionTest.invite(owner, info.id), null))
                world.recordKeyPackage(j, info.id)
            }
            world.quiesce()
            var guard = 0
            while (wave.any { it.channel(info.id)?.state != ChannelState.ACTIVE } && guard++ < 4) {
                if (guard > 1) clearArm(owner, info.id)
                world.admissionPass(owner)
                world.quiesce()
                world.pastSettleWindow()
                world.quiesce()
            }
            for (j in wave) assertEquals("${j.name} joined ${info.name}", ChannelState.ACTIVE, j.channel(info.id)!!.state)
            if (waveIndex < waves.lastIndex) world.advance(DmWorld.DAY / 2)
        }
        world.quiesce()
        world.pastSettleWindow()
        world.quiesce()
        // The namespace map: record while every row is live (the sweep removes finished drains).
        for (c in info.cast) recordGenerations(c, listOf(info))
    }

    /** A rank-0 context change naming the owner and [moderator] committers and funders (§12.5's shape). */
    private fun makeCommitter(info: ChannelInfo) {
        val owner = info.owner
        val moderator = info.cast[1]
        val before = ChannelAdversary.policy(owner, info.id)
        val after = org.ghost.crypto.bridge.ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            listOf(pseudonymOf(owner, info.id), pseudonymOf(moderator, info.id)),
            listOf(pseudonymOf(owner, info.id), pseudonymOf(moderator, info.id)),
        )
        val change = ChannelAdversary.commit(owner, info.id, after)
        world.relay.holdAt = { name, s -> s.purpose == "committers" && name == owner.name }
        ChannelAdversary.stageOwn(owner, info.id, change, rank = 0)
        ChannelAdversary.inject(world, owner, info.id, change, "committers")
        world.relay.holdAt = { _, _ -> false }
        world.quiesce()
        world.advance(21 * DmWorld.MINUTE)
        world.pump()
        for (c in info.cast) if (c.channel(info.id)?.state == ChannelState.ACTIVE) c.timePass()
        world.quiesce()
    }

    /** A user-action removal of an active non-owner member by [remover] (a committer): rotates. */
    private fun removeKind(info: ChannelInfo, kind: String, remover: ChannelClient, rnd: Random, report: Report) {
        val victims = info.cast.filter { it.channel(info.id)?.state == ChannelState.ACTIVE && it !== remover && it !== info.owner }
        if (victims.isEmpty()) return
        val victim = victims[rnd.nextInt(victims.size)]
        val victimPseudonym = pseudonymOf(victim, info.id)
        val epoch = info.owner.channel(info.id)!!.epoch
        val generation = info.owner.channel(info.id)!!.generation
        assertEquals(
            org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED,
            remover.engine.remove(info.id, victimPseudonym),
        )
        duePass(remover, info.id)
        world.quiesce()
        world.pastSettleWindow()
        world.quiesce()
        assertEquals(ChannelState.REMOVED, victim.channel(info.id)!!.state)
        report.subjects += Subject(victim.name, "$kind-removal", seize(victim, "${info.name}-${victim.name}"), epoch, generation, info)
        report.removals++
        switch(info)
    }

    /** A leave: [info]'s third active member leaves, the owner's pass removes it: rotates. */
    private fun leaveKind(info: ChannelInfo, rnd: Random, report: Report) {
        val leavers = info.cast.filter { it.channel(info.id)?.state == ChannelState.ACTIVE && it !== info.owner }
        if (leavers.isEmpty()) return
        val leaver = leavers[rnd.nextInt(leavers.size)]
        val epoch = info.owner.channel(info.id)!!.epoch
        val generation = info.owner.channel(info.id)!!.generation
        assertEquals(org.ghost.messaging.channel.engine.ChannelPostStep.LeaveResult.LEFT, leaver.engine.leave(info.id))
        world.pump()
        info.owner.hintPass()
        world.advance(6 * DmWorld.HOUR)
        var guard = 0
        while (leaver.channel(info.id)!!.state != ChannelState.REMOVED && guard++ < 6) {
            clearArm(info.owner, info.id)
            duePass(info.owner, info.id)
            world.quiesce()
            world.pastSettleWindow()
            world.quiesce()
        }
        assertEquals(ChannelState.REMOVED, leaver.channel(info.id)!!.state)
        report.subjects += Subject(leaver.name, "leave", seize(leaver, "${info.name}-${leaver.name}"), epoch, generation, info)
        report.removals++
        switch(info)
    }

    /** An idle eviction: [info]'s third active member aged past the policy, removed by the owner's pass. */
    private fun evictKind(info: ChannelInfo, rnd: Random, report: Report) {
        val candidates = info.cast.filter { it.channel(info.id)?.state == ChannelState.ACTIVE && it !== info.owner }
        if (candidates.isEmpty()) return
        val victim = candidates[rnd.nextInt(candidates.size)]
        val epoch = info.owner.channel(info.id)!!.epoch
        val generation = info.owner.channel(info.id)!!.generation
        backdateRefresh(info.owner, info.id, 70, pseudonymOf(victim, info.id))
        world.advance(2 * DmWorld.DAY)
        var guard = 0
        while (victim.channel(info.id)!!.state != ChannelState.REMOVED && guard++ < 6) {
            clearArm(info.owner, info.id)
            duePass(info.owner, info.id)
            world.quiesce()
            world.pastSettleWindow()
            world.quiesce()
        }
        assertEquals(ChannelState.REMOVED, victim.channel(info.id)!!.state)
        report.subjects += Subject(victim.name, "idle-eviction", seize(victim, "${info.name}-${victim.name}"), epoch, generation, info)
        report.removals++
        switch(info)
    }

    /** CH-SWITCH at every active member of [info] (the M20 scenario's helper, one channel). */
    private fun switch(info: ChannelInfo) {
        for (c in info.cast) {
            if (c.channel(info.id)?.state != ChannelState.ACTIVE) continue
            c.database.transaction { tx ->
                tx.sql.exec("UPDATE outbox_op SET released = 1 WHERE released = 0 AND outcome <> 'pending'")
                tx.sql.exec("DELETE FROM outbox_op WHERE released = 1 AND ciphertext IS NULL")
            }
        }
        world.advance(2 * DmWorld.HOUR + 60)
        for (c in info.cast) if (c.channel(info.id)?.state == ChannelState.ACTIVE) c.sessionStart()
        world.advance(6 * DmWorld.MINUTE)
        for (c in info.cast) if (c.channel(info.id)?.state == ChannelState.ACTIVE) c.timePass()
        world.quiesce()
        world.pump()
        for (c in info.cast) if (c.channel(info.id)?.state == ChannelState.ACTIVE) c.hintPass()
        world.pastSettleWindow()
        world.quiesce()
        // The pending generation became current (or drained further): record while the rows live.
        for (c in info.cast) recordGenerations(c, listOf(info))
    }

    /** [member] catches up in order across the epochs it missed while dark. */
    private fun catchUp(member: ChannelClient, info: ChannelInfo) {
        val target = info.owner.channel(info.id)!!.epoch
        var guard = 0
        while (member.channel(info.id)!!.epoch < target && guard++ < 60) {
            world.pastSettleWindow()
            world.quiesce()
        }
        assertEquals("${member.name} caught up in ${info.name}", target, member.channel(info.id)!!.epoch)
        assertEquals(
            "${member.name} switched to ${info.name}'s live generation",
            info.owner.channel(info.id)!!.generation, member.channel(info.id)!!.generation,
        )
    }

    private fun activePosters(info: ChannelInfo): List<ChannelClient> =
        info.cast.filter { it.channel(info.id)?.state == ChannelState.ACTIVE }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym

    /** The seizure dump of [client]: a consistent copy of its database file at this moment. */
    private fun seize(client: ChannelClient, tag: String): File {
        val dest = File(workDir, "$tag.db")
        ChannelM20.snapshotOpenDb(client, dest)
        return dest
    }

    private fun quietClocks(client: ChannelClient, id: ChannelId) {
        val day = org.ghost.messaging.engine.DmTime.day(client.clock.now)
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray())
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), day + 365, day, row?.nextPassMinute)
        }
    }

    private fun backdateRefresh(client: ChannelClient, id: ChannelId, days: Long, only: ByteArray) {
        val day = org.ghost.messaging.engine.DmTime.day(client.clock.now) - days
        client.database.transaction { tx ->
            client.channelStores.members.putRefresh(tx, id.toByteArray(), only, day)
        }
    }

    private fun duePass(client: ChannelClient, id: ChannelId) {
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
        client.sessionStart()
        world.advance(6 * DmWorld.MINUTE)
        client.timePass()
    }

    private fun clearArm(client: ChannelClient, id: ChannelId) {
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, row.lastOwnCommitDay, null)
        }
    }
}
