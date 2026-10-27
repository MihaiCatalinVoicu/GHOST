package org.ghost.update.harness

/**
 * The job model (Phase 14 design §7.3, §11.2; Phase 7 design §5.4): the periodic-job scheduler
 * a device runs under the OS's limits, driving the world's client through 60 virtual days.
 *
 * The decisions are the production's: [org.ghost.sync.engine.JobFate]'s precedence (return when
 * the app is visible, then quiet run, then update run, then background relay session) and the
 * production draw probabilities ([QuietRunScheduler]: quiet 1/8, update 1/24 among the rest).
 * The draws are keyed per client and job index — nothing else is an input (NI-U1 (a)).
 *
 * App Standby quotas (§7.3, developer.android.com "Power management restrictions"): Active
 * 20 min per rolling 60 (Android 16+), Working set 10 min per 4 h, Frequent 10 min per 12 h,
 * Rare 10 min per 24 h, Restricted once a day (10 min, modelled as 10 min per 24 h). A job
 * whose duration does not fit the bucket's remaining quota is deferred — it does not run.
 *
 * The payment hold (Phase 8 §19.11) holds relay sessions off for a window after the payment
 * screen; a background session due inside a hold ends at once. Update runs are not held
 * (PM-D12): the hold checks relay sessions, and an update run has none.
 *
 * Job durations are model constants: an update run lasts the fixed `D_U` = 120 s from READY
 * whatever the client holds (§7.3, Q15) — the exact property PM-D11 and NI-U3 pin. A quiet run
 * models one issuer call; a background session models a relay session. Only the update run
 * touches the mirrors (T51: nothing else ever fetches from a mirror).
 */
internal class JobDriver(
    private val world: World,
    private val client: Client,
    private val spec: JobSpec,
    /** The slot-to-mirror mapping of the run's actual draw (the §7.8 replica, for the worlds
     *  that observe which anchor a slot speaks to); null maps by position, the default. */
    private val pickFor: ((world: World, draw: ByteArray) -> Pair<ModelMirror, ModelMirror>)? = null,
) {
    /** One executed (or deferred) job. */
    class JobRecord(
        val index: Int,
        val fireMillis: Long,
        val fate: JobFateModel,
        /** The run's length: [D_U] for update runs, the model constant otherwise, 0 if deferred. */
        val durationMillis: Long,
        /** False when the quota deferred it or a hold ended it at once. */
        val ran: Boolean,
    )

    val jobs = ArrayList<JobRecord>()

    /** Which job indexes drew an update run (NI-U1 (a)'s sequence). */
    val updateDraws: List<Boolean> get() = draws

    private val draws = ArrayList<Boolean>()
    private val quota = QuotaTracker(spec.bucket)

    fun runDays(days: Int = 60) {
        val startAt = world.clock.trueMillis
        val endAt = startAt + days * VirtualClock.DAY_MILLIS
        var index = 0
        var fire = startAt + flex(index)
        while (fire < endAt) {
            step(index, fire)
            index++
            fire = startAt + index * JOB_PERIOD_MILLIS + flex(index)
        }
    }

    private fun step(index: Int, fire: Long) {
        val quiet = draw(index, "quiet") < QUIET_PROBABILITY
        val update = draw(index, "update") < UPDATE_PROBABILITY
        draws += update
        spec.activityAt(fire) // the activity runs; it moves nothing but visibility (L10-D8)
        val visible = spec.visibleAt(fire)
        val fate = when {
            visible -> JobFateModel.RETURN
            quiet -> JobFateModel.QUIET_RUN
            update -> JobFateModel.UPDATE_RUN
            else -> JobFateModel.BACKGROUND_SESSION
        }
        world.clock.advance(fire - world.clock.trueMillis)
        val duration = when (fate) {
            JobFateModel.RETURN -> 0L
            JobFateModel.QUIET_RUN -> QUIET_DURATION_MILLIS
            JobFateModel.UPDATE_RUN -> D_U_MILLIS
            JobFateModel.BACKGROUND_SESSION -> SESSION_DURATION_MILLIS
        }
        val held = fate == JobFateModel.BACKGROUND_SESSION &&
            spec.paymentHolds.any { fire in it }
        val ran = duration > 0 && !held && quota.tryConsume(fire, duration)
        if (ran) {
            if (fate == JobFateModel.UPDATE_RUN) {
                val runDraw = sha256Bytes("${'$'}{world.seed}|${'$'}{client.name}|draw|update-run|${'$'}index")
                val pick = pickFor?.invoke(world, runDraw)
                client.updateRun(world.mirrors[0], world.mirrors[1], draw = runDraw, pick = pick)
            }
            // The job occupies its quota time whatever the engine did inside it (PM-D11: an
            // update run holds its lease until D_U even when it has nothing to do).
            world.clock.advance(duration)
        }
        jobs += JobRecord(index, fire, fate, if (ran) duration else 0L, ran && !held)
    }

    /** The keyed draw the production's RandomSources pattern names: key ‖ domain ‖ index. */
    private fun draw(index: Int, domain: String): Double =
        keyedDraw(world.seed, client.name, index, domain)

    private fun flex(index: Int): Long =
        (draw(index, "flex") * FLEX_MILLIS).toLong()

    companion object {
        /** The deterministic draw, shared with the gate-scale driver (the same function a
         *  per-client [JobDriver] uses, so a world and its gate shard decide identically). */
        internal fun keyedDraw(seed: Long, clientName: String, index: Int, domain: String): Double {
            val d = sha256Bytes("${seed}|${clientName}|job|$domain|$index")
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xff)
            return (v ushr 11) * (1.0 / (1L shl 53))
        }

        /** The fire time of the [index]-th job (the [JobDriver.step] rule, for the gate driver). */
        internal fun fireAt(startAt: Long, index: Int, seed: Long, clientName: String): Long =
            startAt + index * JOB_PERIOD_MILLIS +
                (keyedDraw(seed, clientName, index, "flex") * FLEX_MILLIS).toLong()
        /** Phase 7 design: one periodic job, 15 min period with 5 min flex. */
        const val JOB_PERIOD_MILLIS: Long = 15 * 60_000L
        const val FLEX_MILLIS: Long = 5 * 60_000L

        /** §7.3: the update run's fixed duration from READY (Q15's default). */
        const val D_U_MILLIS: Long = 120_000L

        /** Model constants for the non-update fates (quota accounting only). */
        const val QUIET_DURATION_MILLIS: Long = 30_000L
        const val SESSION_DURATION_MILLIS: Long = 5 * 60_000L

        /** [QuietRunScheduler]: one run in 8 is quiet; the update draw is 1/24 of the rest. */
        const val QUIET_PROBABILITY: Double = 0.125
        const val UPDATE_PROBABILITY: Double = 1.0 / 24.0
    }
}

/** The job's fate — the model's vocabulary mirrors [org.ghost.sync.engine.JobFate]. */
internal enum class JobFateModel { RETURN, QUIET_RUN, UPDATE_RUN, BACKGROUND_SESSION }

/** What differs between the two sides of a twin world — exactly the table's axis, nothing else. */
internal class JobSpec(
    /** The App Standby bucket's quota (§7.3). */
    val bucket: StandbyBucket,
    /** Whether the app is visible when the job fires (a visible job returns, L10-D8). */
    val visibleAt: (fireMillis: Long) -> Boolean,
    /** The payment-hold windows: relay sessions held off inside them (Phase 8 §19.11). */
    val paymentHolds: List<LongRange> = emptyList(),
    /** The user activity at a fire (app opens, DM sends, channel reads — NI-U1's axis). The
     *  model consumes it and moves nothing but [visibleAt]; the draws never see it. */
    val activityAt: (fireMillis: Long) -> Int = { 0 },
)

/** App Standby execution quotas (§7.3): [quotaMillis] of execution per rolling [windowMillis]. */
internal enum class StandbyBucket(val windowMillis: Long, val quotaMillis: Long) {
    ACTIVE(60 * 60_000L, 20 * 60_000L),
    WORKING_SET(4 * 3_600_000L, 10 * 60_000L),
    FREQUENT(12 * 3_600_000L, 10 * 60_000L),
    RARE(24 * 3_600_000L, 10 * 60_000L),

    /** Restricted: once a day for 10 minutes — modelled as 10 min per rolling 24 h. */
    RESTRICTED(24 * 3_600_000L, 10 * 60_000L),
}

/** The rolling quota window: executions older than the window free their budget. */
internal class QuotaTracker(private val bucket: StandbyBucket) {
    private val consumed = ArrayList<Pair<Long, Long>>() // (start, duration)

    fun tryConsume(start: Long, duration: Long): Boolean {
        val floor = start - bucket.windowMillis
        consumed.removeAll { it.first + it.second <= floor }
        val used = consumed.filter { it.first + it.second > floor }.sumOf { it.second }
        if (used + duration > bucket.quotaMillis) return false
        consumed += start to duration
        return true
    }
}
