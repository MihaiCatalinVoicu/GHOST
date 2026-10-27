package org.ghost.update.harness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The twin worlds NI-U1 … NI-U4 (Phase 14 design §11.2's table, T51): each pair differs in
 * exactly the table's axis and must give identical mirror views — every mirror request's time,
 * mirror, kind and range over 60 virtual days, as recorded in [World.mirrorTranscript] — unless
 * the column says otherwise. NI-U5 (the wire-neutral release, G-D11's byte transcript) is
 * deferred with the wire-transcript suite.
 *
 * Each side runs the same seed, so per-client draws, clock offsets and schedules align; the
 * sides are compared per client (each client is a device; the mirrors see the union, and equal
 * per-device views imply an equal union). The scheduler-held PM rows are killed inside the
 * twins they name (PM-D1 in NI-U1, PM-D2/PM-D6 in every twin, PM-D8/PM-D11 in NI-U3, PM-D12
 * in NI-U2).
 */
class NiUTwinsTest {

    private fun assumeHostLibrary() = assumeTrue(
        "the ghost-dm-host library is not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    /** One side of a twin: a client, its job driver, the mirrors it spoke to. */
    private class Side(
        val world: World,
        val client: Client,
        val driver: JobDriver,
    ) {
        val transcript: List<String> get() = world.mirrorTranscript
        val updateRuns: List<JobDriver.JobRecord> get() =
            driver.jobs.filter { it.fate == JobFateModel.UPDATE_RUN }
    }

    /** Runs one side: a world, a client, 60 days under the spec. */
    private fun side(
        name: String,
        seed: Long,
        spec: JobSpec,
        installed: Int = 2,
        days: Int = 60,
        pickFor: ((World, ByteArray) -> Pair<ModelMirror, ModelMirror>)? = null,
        prepare: (World, Client) -> Unit = { _, _ -> },
    ): Side {
        val world = World(name, seed)
        val client = world.client(installed = installed, sdk = 29)
        client.firstStart()
        world.mirror()
        world.mirror()
        prepare(world, client)
        val driver = JobDriver(world, client, spec, pickFor = pickFor)
        driver.runDays(days)
        return Side(world, client, driver)
    }

    /** The mirror view must contain only update-run traffic (PM-D2, PM-D6, T51). */
    private fun assertOnlyUpdateRuns(side: Side) {
        val windows = side.updateRuns.filter { it.ran }
            .map { it.fireMillis..(it.fireMillis + it.durationMillis) }
        for (entry in side.transcript) {
            val at = entry.substringBefore('|').toLong()
            assertTrue(
                "a mirror request outside every update run (PM-D6): $entry",
                windows.any { at in it },
            )
        }
    }

    /** Every update run lasts the fixed D_U (PM-D11; §7.3). */
    private fun assertFixedRunLength(side: Side) {
        for (run in side.updateRuns.filter { it.ran }) {
            assertEquals("an update run must last D_U (PM-D11)", JobDriver.D_U_MILLIS, run.durationMillis)
        }
    }

    private fun pmD1NoCheckAtActivity(side: Side, appOpens: List<Long>) {
        // PM-D1: nothing at app start — no mirror request within a window of an app open.
        for (open in appOpens) {
            for (entry in side.transcript) {
                val at = entry.substringBefore('|').toLong()
                assertTrue("a mirror request at an app open (PM-D1): $entry", at !in open..(open + 15 * 60_000L))
            }
        }
    }

    private fun jobSchedule(side: Side): List<String> =
        side.driver.jobs.map { "${it.index}:${it.fate}:${it.ran}" }

    // ------------------------------------------------------------------ NI-U1

    @Test
    fun niU1ActivityAxisLeavesDrawsAndMirrorViewsIdentical() {
        assumeHostLibrary()
        val appOpens = (0 until 60).map { it * 86_400_000L + 8 * 3_600_000L }

        // (a) Whatever the activity, the draws over the same job sequence are identical. The
        // activity runs (it moves nothing but visibility); it never reaches the draws.
        val quietSpec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false })
        val busySpec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false }, activityAt = { 40 })
        val sideA = side("ni-u1a", seed = 101, spec = quietSpec, installed = 2)
        val sideB = side("ni-u1b", seed = 101, spec = busySpec, installed = 2)
        assertEquals("the update draws are activity-independent (NI-U1 a)", sideA.driver.updateDraws, sideB.driver.updateDraws)

        // (b) The same visibility intervals on both sides; the activity differs only inside
        // them. The mirror views and the job schedule are identical (T19).
        val visibleSpec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { it in (8 * 3_600_000L)..(9 * 3_600_000L) })
        val sideV1 = side("ni-u1v1", seed = 102, spec = visibleSpec, installed = 2)
        val sideV2 = side("ni-u1v2", seed = 102, spec = JobSpec(
            StandbyBucket.WORKING_SET,
            visibleAt = visibleSpec.visibleAt,
            activityAt = { 40 },
        ), installed = 2)
        assertEquals("the visible-job schedule is activity-independent", jobSchedule(sideV1), jobSchedule(sideV2))
        assertEquals("the mirror view is activity-independent (T19)", sideV1.transcript, sideV2.transcript)

        for (s in listOf(sideA, sideB, sideV1, sideV2)) {
            assertOnlyUpdateRuns(s)
            assertFixedRunLength(s)
        }
        pmD1NoCheckAtActivity(sideV1, appOpens)
        pmD1NoCheckAtActivity(sideV2, appOpens)
        report("NI-U1: equal")
    }

    // ------------------------------------------------------------------ NI-U2

    @Test
    fun niU2EntitlementAxisAndThePaymentHoldLeaveMirrorViewsIdentical() {
        assumeHostLibrary()
        // The hold is placed over a job that drew an update run (deterministic: the model's
        // draw is a pure function of the seed and the index) — the payment screen shows and
        // holds relay sessions off for the modelled U[20, 60] min after it (Phase 8 §19.11).
        val worldStart = (WorldFixtures.load().issuedDay + 1L) * VirtualClock.DAY_MILLIS
        val holdWindows = findUpdateRunFires(seed = 103, clientName = "client-0", startAt = worldStart, count = 2)
            .map { it..(it + 40 * 60_000L) }
        val plain = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false })
        val held = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false }, paymentHolds = holdWindows)

        // Side B: purchases, a trial, an expired subscription (their quiet-run issuer calls
        // are the same quiet runs — the axis changes no draw) and the payment hold.
        val sideA = side("ni-u2a", seed = 103, spec = plain, installed = 2)
        val sideB = side("ni-u2b", seed = 103, spec = held, installed = 2)

        assertEquals("T2 untouched: the mirror view is entitlement-independent",
            sideA.transcript, sideB.transcript)
        assertEquals("the job schedule is entitlement-independent", jobSchedule(sideA), jobSchedule(sideB))

        // PM-D12: update runs are not held by the payment hold — the update runs inside the
        // holds still ran.
        val heldRuns = sideB.updateRuns.filter { run -> holdWindows.any { run.fireMillis in it } }
        assertTrue("the fixture places update runs inside the holds", heldRuns.isNotEmpty())
        for (run in heldRuns) {
            assertTrue("an update run was held (PM-D12): job ${run.index}", run.ran)
        }
        for (s in listOf(sideA, sideB)) {
            assertOnlyUpdateRuns(s)
            assertFixedRunLength(s)
        }
        report("NI-U2: equal")
    }

    /** The fire times of the first [count] update-run draws (the model's draw, replicated). */
    private fun findUpdateRunFires(seed: Long, clientName: String, startAt: Long, count: Int): List<Long> {
        val fires = ArrayList<Long>()
        var index = 0
        while (fires.size < count) {
            val d = sha256Bytes("$seed|$clientName|job|update|$index")
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xff)
            val draw = (v ushr 11) * (1.0 / (1L shl 53))
            if (draw < JobDriver.UPDATE_PROBABILITY) {
                fires += startAt + index * JobDriver.JOB_PERIOD_MILLIS + flex(seed, clientName, index)
            }
            index++
        }
        return fires
    }

    private fun flex(seed: Long, clientName: String, index: Int): Long {
        val d = sha256Bytes("$seed|$clientName|job|flex|$index")
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xff)
        return (((v ushr 11) * (1.0 / (1L shl 53))) * JobDriver.FLEX_MILLIS).toLong()
    }

    // ------------------------------------------------------------------ NI-U3

    @Test
    fun niU3OfferAxisLeavesBundlesTimingAndRunLengthsIdentical() {
        assumeHostLibrary()
        val spec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false })
        // Side A: installed one behind; the prepare run accepts the (multi-chunk) release and
        // drops its mid-range: a pending download the window's first run resumes.
        val sideA = side("ni-u3a", seed = 104, spec = spec, installed = 1) { w, c ->
            val big = w.fixtures.doc("app-v2-big.apk")
            val bundleBig = w.fixtures.doc("bundle-big.ghrb")
            for (m in listOf(w.mirrors[0], w.mirrors[1])) {
                m.apkOverride = big
                m.bundleOverride = bundleBig
            }
            val dropper = w.mirror(MirrorMode.DROP_MID_RANGE)
            dropper.droppedChunks = setOf(1)
            dropper.apkOverride = big
            dropper.bundleOverride = bundleBig
            val honest = w.mirror()
            honest.apkOverride = big
            honest.bundleOverride = bundleBig
            try {
                c.updateRun(honest, dropper)
            } catch (e: org.ghost.network.NetworkException) {
                // the dropped mid-range leaves a partial row
            }
            assertEquals("partial", c.store.staged()!!.state)
            w.mirrorTranscript.clear()
        }
        // Side B: installed at the release, holding a stale manifest — no offer, no download.
        val sideB = side("ni-u3b", seed = 104, spec = spec, installed = 2) { w, c ->
            c.updateRun(w.mirror(MirrorMode.STALE), w.mirror(MirrorMode.STALE))
            w.mirrorTranscript.clear()
        }

        // Bundle requests identical (times, mirrors, paths by kind).
        assertEquals(sideA.transcript.filter { "|bundle|" in it }, sideB.transcript.filter { "|bundle|" in it })
        // The timing of every later job is equal under the quota model.
        assertEquals(jobSchedule(sideA), jobSchedule(sideB))
        // Every update run's length is equal (PM-D11).
        assertFixedRunLength(sideA)
        assertFixedRunLength(sideB)
        // APK requests exist only where an offer exists…
        assertTrue("side A resumes its pending download", sideA.transcript.any { "|chunk|" in it })
        assertTrue("side B has no APK requests", sideB.transcript.none { "|chunk|" in it })
        // …in fixed 4 MiB steps (PM-D8: the range is the fixed step, never a resume offset).
        for (entry in sideA.transcript.filter { "|chunk|" in it }) {
            val index = entry.substringAfter("index=").toLong()
            assertEquals("a chunk at a fixed 4 MiB step (PM-D8)", 0L, index * ModelMirror.CHUNK % ModelMirror.CHUNK)
        }
        report("NI-U3: equal")
    }

    // ------------------------------------------------------------------ NI-U4

    @Test
    fun niU4StoredRootVersionLeavesBundleViewsIdentical() {
        assumeHostLibrary()
        val spec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false })
        // Side A: stored at the current root (the four-root chain adopted at once).
        val sideA = side("ni-u4a", seed = 105, spec = spec, installed = 2) { w, c ->
            serveBundle(w, c, w.fixtures.doc("bundle-4.ghrb"))
            w.mirrorTranscript.clear()
        }
        // Side B: three roots behind — the older bundles are served first, then the same one.
        val sideB = side("ni-u4b", seed = 105, spec = spec, installed = 2) { w, c ->
            serveBundle(w, c, w.fixtures.bundle)
            serveBundle(w, c, w.fixtures.doc("bundle-2.ghrb"))
            serveBundle(w, c, w.fixtures.doc("bundle-4.ghrb"))
            w.mirrorTranscript.clear()
        }
        assertEquals(4, sideA.client.store.load()!!.facts.rootVersion)
        assertEquals(4, sideB.client.store.load()!!.facts.rootVersion)
        // Same anchors in all four roots: the mirror views are identical.
        assertEquals("the stored root version moved no bundle byte",
            sideA.transcript, sideB.transcript)
        for (s in listOf(sideA, sideB)) {
            assertOnlyUpdateRuns(s)
            assertFixedRunLength(s)
        }
        report("NI-U4: equal")
    }

    @Test
    fun niU4ChangedAnchorsDivergeExactlyByTheMirrorChoice() {
        assumeHostLibrary()
        // L10-D22: a root whose anchor order changed legitimately moves the mirror choice —
        // the divergence is exactly which model mirror each slot speaks to, nothing else.
        // The world's mirrors model the anchors: mirrors[0] models anchor A, mirrors[1]
        // anchor B, in both worlds. The pick is the §7.8 draw replica over the stored root's
        // anchors (the shipped rule on both sides — no mutation is being killed here).
        val spec = JobSpec(StandbyBucket.WORKING_SET, visibleAt = { false })
        // The world's mirrors model the anchors: mirrors[0] models anchor A, mirrors[1]
        // anchor B, in both worlds; the pick maps the drawn onion to its model mirror.
        val same = side("ni-u4s", seed = 106, spec = spec, installed = 2,
            pickFor = anchorPick { w -> w.fixtures.anchors.map { it.first } }) { w, c ->
            serveBundle(w, c, w.fixtures.doc("bundle-4.ghrb"))
            w.mirrorTranscript.clear()
        }
        val swapped = side("ni-u4x", seed = 106, spec = spec, installed = 2,
            pickFor = anchorPick { w -> w.fixtures.anchors.map { it.first }.reversed() }) { w, c ->
            serveBundle(w, c, w.fixtures.doc("bundle-4x.ghrb"))
            w.mirrorTranscript.clear()
        }
        assertEquals(4, same.client.store.load()!!.facts.rootVersion)
        assertEquals(4, swapped.client.store.load()!!.facts.rootVersion)
        // The divergence is exactly the mirror identity per slot: same times, kinds, counts.
        assertEquals(same.transcript.size, swapped.transcript.size)
        assertEquals(
            same.transcript.map { it.substringBefore("|m") },
            swapped.transcript.map { it.substringBefore("|m") },
        )
        assertNotEquals(
            "the anchor change moved the mirror choice (L10-D22)",
            same.transcript.map { it.substringAfter("|m").substringBefore("|") },
            swapped.transcript.map { it.substringAfter("|m").substringBefore("|") },
        )
        report("NI-U4-anchor-change: mirror choice differs by design (L10-D22), nothing else")
    }

    /** The §7.8 draw: first from the anchors, second from the anchors without the first —
     *  the shipped rule over known inputs (both sides; no mutation is being killed here). */
    private fun anchorPick(
        anchorsOf: (World) -> List<String>,
    ): (World, ByteArray) -> Pair<ModelMirror, ModelMirror> = { w, draw ->
        val anchors = anchorsOf(w)
        val r0 = be64(draw, 0)
        val r1 = be64(draw, 8)
        val first = anchors[(r0 % anchors.size).toInt()]
        val candidates = anchors.filter { it != first }
        val second = candidates[(r1 % candidates.size).toInt()]
        fun mirrorOf(onion: String) =
            if (onion == w.fixtures.anchors[0].first) w.mirrors[0] else w.mirrors[1]
        mirrorOf(first) to mirrorOf(second)
    }

    private fun be64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[at + i].toLong() and 0xff)
        return v
    }

    /** One accepted bundle through a fresh pair of mirrors. */
    private fun serveBundle(w: World, c: Client, bundle: ByteArray) {
        val a = w.mirror(MirrorMode.EQUIVOCATE)
        val b = w.mirror(MirrorMode.EQUIVOCATE)
        a.equivocateBundle = bundle
        b.equivocateBundle = bundle
        c.updateRun(a, b)
    }

    /** Writes the measured twin line to the report fragment (G-D7's shape), idempotently. */
    private fun report(line: String) {
        val dir = java.io.File("build/update-mutants").apply { mkdirs() }
        val file = java.io.File(dir, "report.txt")
        val lines = if (file.isFile) file.readLines() else emptyList()
        if (line !in lines) file.appendText(line + "\n")
    }
}
