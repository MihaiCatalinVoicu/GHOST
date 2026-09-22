package org.ghost.app

import android.os.SystemClock
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmRandom
import java.security.SecureRandom

/**
 * The DM layer's two clocks on a device (Phase 9 design §13.3 item 6, `DmClock`): the wall clock
 * floored to the second for everything the DM tables store, and elapsed realtime — which counts
 * deep sleep and which no wall-clock step moves — for the consumer tail's deadline. Elapsed
 * realtime is the same source the sync runtime's clock reads, so the tail's deadline and the job's
 * are on one clock, as `DmClock.monotonicMillis` requires.
 */
internal object AndroidDmClock : DmClock {
    override fun nowEpochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)

    override fun monotonicMillis(): Long = SystemClock.elapsedRealtime()

    override fun toString(): String = "AndroidDmClock"
}

/**
 * The DM layer's CSPRNG on a device: generation ids, operation ids, `session_state_key`, the content
 * key and `seen_key` (§3.1 "Random, never derived"). The platform `SecureRandom`, as the identity's
 * root entropy uses (FR-1.1).
 */
internal class SecureDmRandom(private val random: SecureRandom = SecureRandom()) : DmRandom {
    override fun bytes(count: Int): ByteArray = ByteArray(count).also(random::nextBytes)

    override fun toString(): String = "SecureDmRandom"
}
