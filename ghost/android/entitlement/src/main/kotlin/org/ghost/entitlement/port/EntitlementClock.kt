package org.ghost.entitlement.port

/**
 * The engine's clocks. [epochSeconds] is the device wall clock: issuer-facing decisions use it only
 * under the session's `clockTrusted()` (design §19.4); relay-facing decisions correct it with relay
 * answers (`engine.ClockEstimate`, §12.5). [monotonicMillis] paces the redeem lane.
 */
interface EntitlementClock {
    fun epochSeconds(): Long

    fun monotonicMillis(): Long

    /** Waits [millis] ms; false when the waiting thread was interrupted (the caller then returns). */
    fun sleep(millis: Long): Boolean
}
