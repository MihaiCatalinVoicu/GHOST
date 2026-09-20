package org.ghost.sync.api

/**
 * What a bearer credential v3 of a registered secret may do at a relay (Phase 9 design §4.2, §4.3
 * and §22.8.7): READ lists, gets and checks the owner's inbox; DEPOSIT stores into it; FETCH lists
 * and gets the owner's bundle namespace, with week-coarse times. The codes are the `KeyKind` values
 * of `relay.proto` (2 is Write in capability headers and is never a key kind).
 */
enum class KeyKind(val code: Int, internal val dbCode: String) {
    READ(1, "read"), DEPOSIT(3, "deposit"), FETCH(4, "fetch");

    companion object {
        internal fun ofCode(code: String): KeyKind =
            entries.firstOrNull { it.dbCode == code } ?: throw IllegalStateException("unknown key kind")
    }
}

/**
 * The bearer-key registrations the owner keeps at the relays of its own namespaces (Phase 9 design
 * §4.8, §13.3 item 5). The consumer (the DM layer's `REGROWS` step) says which rows must exist; the
 * `:sync` work lane runs them with a usable write capability, never on the read lane (T19).
 *
 * A row is due when it is pending, not in flight, its next attempt time has come, and a usable,
 * unexpired write capability of week c exists for its pair with `period_id` in `{c, c + 1}`, which
 * is the rule the relay judges the request by (§4.4 point 3). Results: OK marks the row done with
 * the relay's validity; WRONG_PERIOD and `unauthorized` leave it pending for the next capability
 * generation; transient failures take the Phase 7 backoff and breakers; a crash inside the call
 * leaves a lease that session start normalizes.
 */
interface Registrations {
    /**
     * Records that (relay, namespace, period, kind) must be registered with [verifier], inside the
     * caller's transaction. Idempotent on the four key columns; a different verifier for a row that
     * already exists throws, because the verifier of a row is fixed at insert (§4.8).
     *
     * Returns true only when this call inserted the row (Phase 9 design §7.2: REGROWS "inserts
     * only missing rows", and has to be able to say that it inserted none).
     */
    fun request(
        tx: SyncTransaction,
        relay: RelayId,
        namespace: NamespaceId,
        periodId: Long,
        kind: KeyKind,
        verifier: ByteArray,
    ): Boolean

    /**
     * The healing rule of §4.8: rows of (relay, namespace) with `period >= fromPeriod` that are
     * done return to pending with new request ids, so the owner registers them again (its records
     * at the relay were lost, or its read credential was refused). Returns the number of rows moved.
     */
    fun rearm(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, fromPeriod: Long): Int

    /** Drops the rows of (relay, namespace) whose period is before [beforePeriod]. Returns the count. */
    fun forget(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, beforePeriod: Long): Int

    /** Registrations still to be made (counts only, T3). */
    fun pendingCount(): Int
}
