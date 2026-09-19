package org.ghost.sync.api

/**
 * Local work a consumer owes at the end of a background run (Phase 9 design §13.3 item 6; G-8,
 * SC-7). The sync runtime calls it on the job thread
 *  - after a background session's lanes have ended, its redeem hold has ended and the transport is
 *    closed, and
 *  - after a quiet run's issuer call has returned and its transport is closed,
 *
 * never in a foreground session, where the consumer is driven by the inbox listener and the facade.
 * Because it runs after the close, relay session close times and issuer-call times cannot depend on
 * how much the consumer had to do (NI-DM1).
 *
 * The tail has no transport access and does local work only; it must return by
 * `deadlineMonotonicMillis` (the sync clock, elapsed realtime). The job's end never waits past that
 * deadline, so a tail that overruns delays nothing.
 */
fun interface ConsumerTail {
    fun run(kind: SessionKind, deadlineMonotonicMillis: Long)
}
