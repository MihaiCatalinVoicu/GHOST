package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelTime
import org.ghost.messaging.channel.engine.MlsRows
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * **SCN-M20, the exit scenario's suite** (Phase 10 design §12.5, the exit gate's first rows): the
 * base scenario over the pinned seeds ([ChannelM20.SEEDS], one per PR by default), the owner-restore
 * variant (MM-33's named killer), the FORK variant (MM-3's named killer and CS-C4's recovery), the
 * T38 removed-member seizure oracle over every removal subject of the choreography (the
 * moderator-removed member — also between its removal and its re-add —, the leaver, the evictee and
 * the device swap's old stack, later epochs and later generations), the T39 joiner oracle over the
 * wave joiners, and the commit/Welcomes size bounds of §12.5's assertions (S0-5's floors, MM-38's
 * scenario-scale killer). Every run writes the design-doc report line ([ChannelReport]).
 */
class ChannelM20Test {

    @get:Rule
    val folder = TemporaryFolder()

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** The base scenario over the pinned seeds: §12.5's script, its assertions inside the runner. */
    @Test
    fun theExitScenarioRunsGreenOverThePinnedSeeds() {
        // Measurement knob (test infra): `-Dghost.channel.report.lenient=1` records this seed's
        // commit/Welcome counts as an extra report line instead of leaving them unmeasured when
        // a strict pin is being re-measured across the seed sweep (§19.51). The strict size
        // floors live in [everyCommitIsWithinItsFloorAndEveryWelcomeUnderTheCap] and are untouched.
        val recordSizes = System.getProperty("ghost.channel.report.lenient") == "1"
        for (seed in ChannelM20.selectedSeeds()) {
            val built = ChannelM20.build(ChannelM20.Config(seed = seed))
            built.world.use { w ->
                ChannelReport.line(built.report.line())
                if (recordSizes) {
                    var commits = 0
                    var welcomes = 0
                    for (blob in w.relay.stored) {
                        if (blob.injected) continue
                        when (blob.purpose) {
                            "commit" -> commits++
                            "welcome" -> welcomes++
                        }
                    }
                    ChannelReport.line(
                        "channel SCN-M20 sizes (record-only): seed ${"0x%08x".format(seed)}: " +
                            "$commits commits, $welcomes Welcomes",
                    )
                }
            }
        }
    }

    /** The owner-restore variant: client 1 restores through a rank-1 committer's swap and keeps rank 0. */
    @Test
    fun theOwnerRestoreVariantKeepsRankZero() {
        val dir = folder.newFolder("m20-owner-restore")
        val built = ChannelM20.build(ChannelM20.Config(seed = ChannelM20.SEEDS[0], variant = ChannelM20.Variant.OWNER_RESTORE, dbDir = dir))
        built.world.use { ChannelReport.line(built.report.line()) }
    }

    /** The FORK variant: the settle window holds at every member; both sides recover by rejoin. */
    @Test
    fun theForkVariantRejoinsBothSides() {
        val built = ChannelM20.buildFork(ChannelM20.SEEDS[0])
        built.world.use {
            assertTrue("the several-member side raised split_suspected", built.report.forkSidesSplitSuspected > 0)
            assertTrue("both sides rejoined", built.report.forkMembersRejoined >= 5)
            ChannelReport.line(
                "channel SCN-M20 fork: PASS seed ${"0x%08x".format(built.report.seed)}: " +
                    "${built.report.forkSidesSplitSuspected} members split_suspected, " +
                    "${built.report.forkMembersRejoined} rejoined, t41 checks ${built.report.t41Checks}; " +
                    "wall ${"%.1f".format(built.report.wallSeconds)} s",
            )
        }
    }

    /**
     * T38's channel case over the scenario's removal subjects: every secret each held — retained
     * past-epoch secrets, generation secrets, every stored value of the dump — against every blob
     * of every later epoch and every later generation. 0 opens (P-C4(a)/(b), the exit gate's
     * "membru scos nu decriptează epoch-uri noi", FR-3.8, LIMITE:39).
     */
    @Test
    fun theRemovedMemberOracleOpensNothingLater() {
        val dir = folder.newFolder("m20-oracle")
        val built = ChannelM20.build(ChannelM20.Config(seed = ChannelM20.SEEDS[0], dbDir = dir))
        built.world.use { w ->
            val subjects = built.report.subjects
            assertTrue("the scenario names its seizure subjects", subjects.isNotEmpty())
            val maps = blobMaps(w, built)
            val reports = subjects.map { subject ->
                val seedName = subject.name.removeSuffix("-old")
                val seized = w.client(
                    "seized-${subject.name}", sql = ChannelWorld.restore(subject.dump),
                    boot = 9, seedName = seedName,
                )
                RemovedMemberOracle.run(
                    seized, subject.name, subject.kind, built.id, w.relay.stored,
                    subject.removedAtEpoch, subject.heldGeneration, maps.first, maps.second,
                )
            }
            for (r in reports) {
                if (!r.passed) {
                    System.err.println("ORACLE DIAG " + r.subject + ": " + r.openViolations.take(5).joinToString(" | "))
                    System.err.println(
                        "ORACLE GENS " + r.subject + ": " + org.ghost.storage.JdbcSqlExecutor(
                            java.io.File(built.report.subjects.first { it.name == r.subject }.dump!!.absolutePath).absolutePath,
                        ).let { ex ->
                            val sb = StringBuilder()
                            ex.query("SELECT generation, state FROM ch_generation ORDER BY generation") { sb.append("[g=${it.long(0)} ${it.string(1)}]") }
                            ex.close()
                            sb.toString()
                        },
                    )
                }
                assertTrue(r.line(), r.passed)
                ChannelReport.line(r.line())
            }
        }
    }

    /**
     * F-1's regression probe: a later epoch's `K_ep` leaked into the dump **without** its
     * `ch_epoch` row (the envelopes copied into `mls_kv` — any 28…4 MiB blob — and the rows,
     * the held posts and the recognition keys of those epochs deleted) must be caught by the
     * oracle's envelope sweep: the leaked keys open later epochs' blobs while recognition
     * matched nothing — the leak is invisible to the hint pre-filter, so the recognition-driven
     * sweep of the un-widened oracle (32/60-byte values only) never tried it and reported 0
     * opens. The leak is built from the anchor's own retained envelopes at the end (its
     * retention holds the epochs past c10's removal): same context, so its `k_env` values
     * open — the shape a real leak of a member's wrapped epoch keys would have.
     */
    @Test
    fun theRemovedMemberOracleCatchesALeakedLaterEpochKeyWithoutItsRow() {
        val dir = folder.newFolder("m20-oracle-leak")
        val built = ChannelM20.build(ChannelM20.Config(seed = ChannelM20.SEEDS[0], dbDir = dir))
        built.world.use { w ->
            val c = built.id.toByteArray()
            val anchor = built.anchor
            // The probe's cutoff: c10's removing epoch. The anchor held every generation, so
            // what must be zero is opens of epochs after the cutoff (P-C4(a)'s shape).
            val cutoff = built.report.subjects.first { it.kind == "moderator-removal" }.removedAtEpoch
            val heldGeneration = anchor.channel(built.id)!!.generation
            val tampered = File(dir, "leaked.db")
            ChannelM20.snapshotOpenDb(anchor, tampered)
            org.ghost.storage.JdbcSqlExecutor(tampered.absolutePath).use { ex ->
                // The leak: the cutoff's later epochs' k_env envelopes in mls_kv, with no
                // ch_epoch row...
                ex.exec(
                    "INSERT INTO mls_kv(channel_id, k, v_env) " +
                        "SELECT channel_id, CAST('leak-' || epoch AS BLOB), k_env FROM ch_epoch " +
                        "WHERE channel_id = ? AND epoch > ?",
                    listOf(c, cutoff),
                )
                // ...and no held posts, so the only way the dump opens later blobs is the
                // envelope sweep itself.
                ex.exec("DELETE FROM ch_epoch WHERE channel_id = ? AND epoch > ?", listOf(c, cutoff))
                ex.exec("DELETE FROM ch_post WHERE channel_id = ? AND epoch > ?", listOf(c, cutoff))
            }
            val seized = w.client("seized-leak", sql = ChannelWorld.restore(tampered), boot = 9, seedName = anchor.name)
            val maps = blobMaps(w, built)
            val r = RemovedMemberOracle.run(
                seized, anchor.name, "leaked-epoch-keys (probe)", built.id, w.relay.stored,
                cutoff, heldGeneration, maps.first, maps.second,
            )
            assertTrue("the leaked keys open later epochs' blobs: " + r.line(), r.openedLaterEpoch > 0)
            assertTrue("the leak is invisible to recognition: " + r.line(), r.recognisedLater == 0)
            assertTrue("the report must fail: " + r.line(), !r.passed)
        }
    }

    /** T39 over the wave joiners: nothing of the epochs before a join opens at the joiner. */
    @Test
    fun theJoinerOracleOpensNothingBeforeTheJoins() {
        val built = ChannelM20.build(ChannelM20.Config(seed = ChannelM20.SEEDS[0]))
        built.world.use { w ->
            var withHistory = 0
            var opened = 0
            var blobs = 0
            var joinTraffic = 0
            for (j in built.report.joiners) {
                if (j.joinEpoch <= 1) continue // no epoch before the join exists: vacuous
                if (j.name == ChannelM20.MODERATOR_REMOVED) continue // a re-add: T38's lens, not T39's
                withHistory++
                val client = w.clients.first { it.name == j.name }
                val r = JoinerOracle.run(w, client, built.id, j.joinEpoch)
                blobs += r.blobs
                opened += r.openedBeforeJoin
                joinTraffic += r.joinTraffic
                assertEquals("$j", 0, r.openedBeforeJoin)
                assertEquals("$j", 0L, r.postsBeforeJoin)
            }
            assertTrue(withHistory >= 3)
            ChannelReport.line(
                "channel T39 joiner: PASS $withHistory joiners with history: " +
                    "$blobs blobs, 0 opened before the join, $joinTraffic join traffic (the declared exception)",
            )
        }
    }

    /** §12.5's size assertions (S0-5): every commit within its floor, every Welcome under the cap. */
    @Test
    fun everyCommitIsWithinItsFloorAndEveryWelcomeUnderTheCap() {
        val built = ChannelM20.build(ChannelM20.Config(seed = ChannelM20.SEEDS[0]))
        built.world.use { w ->
            var commits = 0
            var welcomes = 0
            for (blob in w.relay.stored) {
                if (blob.injected) continue
                // The sealed blob: salt(16) || hint(16) || ChaCha20-Poly1305 body (+16 of tag).
                val inner = blob.ciphertext.size - ChannelRecognitionOverhead
                when (blob.purpose) {
                    "commit" -> {
                        commits++
                        assertTrue("a commit of ${blob.from} is within the small floor (S0-5)", inner <= ChannelTime.SMALL_FLOOR)
                    }
                    "welcome" -> {
                        welcomes++
                        assertTrue("a Welcome of ${blob.from} is under the class cap", inner <= 65_536)
                    }
                }
            }
            // The tip-pinned floors (review finding F-6): the commit count varies by one across
            // JVM runs of one seed (52, 53, 52 measured at the tip, §19.50 — the choreography is
            // seeded, one cadence commit's timing is a native-draw side), so the gate is a floor,
            // not an exact pin; the Welcomes are exact.
            assertTrue("at least the tip-pinned commit count (§19.50), got $commits", commits >= TipPinnedCommits)
            assertTrue("at least the tip-pinned Welcome count (§19.50), got $welcomes", welcomes >= TipPinnedWelcomes)
            ChannelReport.line("channel sizes: PASS $commits commits within the floor, $welcomes Welcomes under the cap")
        }
    }

    private companion object {
        /** The tip-pinned size floors: the commit count varies with host load and with the seed
         *  (the swap window's guard-bounded rounds, the seeded poster/PCS draws) — re-measured
         *  across the full 64-seed gate-scale sweep at the `p11-s2` tip (2026-10-13, the lenient
         *  record-only knob `-Dghost.channel.report.lenient=1`, one Gradle invocation per seed,
         *  `gatescale-m20-lenient.log`): commits 54 … 57, Welcomes 21 … 22 — so the gate is a
         *  floor at the minimum observed, not an exact pin (review finding F-6, §19.50; the
         *  64-seed re-measurement §19.51). Measured per seed (index: commits/Welcomes):
         *  0:55/21  1:55/21  2:56/21  3:54/21  4:55/22  5:55/21  6:55/21  7:55/21  8:56/22
         *  9:55/21 10:56/22 11:55/21 12:56/21 13:55/21 14:55/21 15:55/21 16:55/21 17:55/21
         * 18:56/22 19:55/21 20:55/21 21:55/21 22:55/21 23:56/22 24:56/22 25:55/21 26:54/21
         * 27:55/21 28:54/21 29:54/21 30:57/22 31:56/22 32:55/21 33:56/22 34:56/22 35:55/21
         * 36:56/21 37:55/21 38:54/21 39:54/21 40:57/22 41:55/21 42:56/22 43:56/21 44:55/21
         * 45:55/21 46:54/21 47:55/21 48:56/21 49:55/21 50:55/21 51:56/22 52:56/22 53:55/21
         * 54:55/21 55:55/21 56:54/21 57:54/21 58:55/21 59:55/21 60:55/21 61:57/22 62:56/22
         * 63:55/22. Minima: 54 commits (seeds 3, 26, 28, 29, 38, 39, 46, 56, 57), 21 Welcomes. */
        const val TipPinnedCommits: Int = 54
        const val TipPinnedWelcomes: Int = 21

        /** The seal's overhead over the sealed body: salt + hint + the AEAD tag. */
        const val ChannelRecognitionOverhead: Int = 16 + 16 + 16

        /**
         * The world's view of every blob: its namespace's generation (from the anchor's generation
         * rows) and its epoch. The epoch map is built by opening every distinct blob with the
         * retained epoch keys of the anchor **and of the swap subject's frozen dump** — the
         * anchor's retention window (16 epochs, S0-6) alone does not reach the scenario's first
         * epochs, and the frozen dump reaches exactly those.
         */
        fun blobMaps(
            w: ChannelWorld,
            built: ChannelM20.Built,
        ): Pair<(ByteArray) -> Long?, (ByteArray) -> Long?> {
            val c = built.id.toByteArray()
            val generationOf = HashMap<String, Long>()
            built.anchor.database.transaction { tx ->
                tx.sql.query(
                    "SELECT namespace_id, generation FROM ch_generation WHERE channel_id = ?",
                    listOf(c),
                ) { generationOf[ModelChannelRelay.hex(it.blob(0))] = it.long(1) }
            }
            val keyHolders = ArrayList<ChannelClient>()
            keyHolders += built.anchor
            val swapDump = built.report.subjects.lastOrNull { it.kind.startsWith("device-swap") }?.dump
            if (swapDump != null) {
                keyHolders += w.client(
                    "epoch-map-swap", sql = ChannelWorld.restore(swapDump), boot = 8,
                    seedName = swapDump.nameWithoutExtension.removeSuffix("-swap"),
                )
            }
            val epochs = keyHolders.flatMap { holder ->
                holder.database.transaction { tx ->
                    holder.channelStores.epochs.retained(tx.sql, c, DmTime.day(holder.clock.now))
                }
            }.distinctBy { it.epoch }
            val epochOf = HashMap<String, Long>()
            val crypto = built.anchor.contexts.open(c)!!.crypto
            for (blob in w.relay.stored) {
                val hashKey = ModelChannelRelay.hex(blob.hash)
                if (epochOf.containsKey(hashKey)) continue
                if (generationOf[ModelChannelRelay.hex(blob.namespace)] == null) continue
                for (e in epochs) {
                    val o = crypto.open(c, e.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, blob.namespace, ChannelCrypto.MODE_EPOCH, blob.ciphertext)
                    if (o is MlsOutcome.Ok && (o.value.headerEpoch ?: o.value.order.epoch) == e.epoch) {
                        epochOf[hashKey] = e.epoch
                        break
                    }
                }
            }
            return Pair(
                { ns -> generationOf[ModelChannelRelay.hex(ns)] },
                { hash -> epochOf[ModelChannelRelay.hex(hash)] },
            )
        }
    }
}
