package org.ghost.update.harness

import kotlin.math.abs

/**
 * The update world's clock (Phase 14 design §11.2): stepped virtual time — nothing advances
 * unless the world steps it — with a per-device offset the world sets within ±σ (T50's "time
 * bounds at σ + 1 day" premise; σ is a world constant, not a protocol one). The device time is
 * what the client's engine reads through its `dayNow`; [trusted] is the sync clock's trust
 * (§7.4: an untrusted clock is a value, not a missing check), a world flips it for the
 * clock-hostile worlds.
 */
internal class VirtualClock(private val seed: Long) {

    /** True device time (the world's own clock), milliseconds since the epoch. */
    var trueMillis: Long = 0
        private set

    /** Device minus true time; the world sets it inside ±[SIGMA_MILLIS]. */
    var offsetMillis: Long = 0
        private set

    /** The sync clock's trust (a READY in the process, no step since). */
    var trusted: Boolean = true

    /** Places the world at [millis] (the fixture validity window, from the committed meta). */
    fun startAt(millis: Long) {
        trueMillis = millis
    }

    /** Steps true time (a world's scripted action); never negative. */
    fun advance(millis: Long) {
        require(millis >= 0) { "the world only advances" }
        trueMillis += millis
    }

    /** Gives this device its offset within ±σ (deterministic from the seed and [label]). */
    fun skewDevice(label: String) {
        val span = 2 * SIGMA_MILLIS + 1
        val draw = (sha256Long("$seed|skew|$label") and Long.MAX_VALUE) % span
        offsetMillis = draw - SIGMA_MILLIS
        check(abs(offsetMillis) <= SIGMA_MILLIS) { "offset within ±σ" }
    }

    fun setOffset(offsetMillis: Long) {
        require(abs(offsetMillis) <= SIGMA_MILLIS) { "offset $offsetMillis outside ±σ" }
        this.offsetMillis = offsetMillis
    }

    /** What the device believes now. */
    val nowMillis: Long get() = trueMillis + offsetMillis

    /** Epoch days, device time (the `day` of §7.4's Time::Trusted). */
    fun day(): Int = Math.floorDiv(nowMillis, DAY_MILLIS).toInt()

    /** Unix seconds, device time (the `now` of the acceptance's freshness checks). */
    fun nowSeconds(): Long = nowMillis / 1_000

    companion object {
        /** σ, the per-device bound (6 h; a world constant, T50's freshness margin is σ + 1 day). */
        const val SIGMA_MILLIS: Long = 6 * 60 * 60_000L
        const val DAY_MILLIS: Long = 86_400_000L
    }
}
