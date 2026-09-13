package org.ghost.entitlement.api

/** Flags of [EntitlementStatus] (design §11.2). */
enum class EntitlementFlag {
    /** A capability need found no eligible token; surfaced at a client-random time within U[0, 12 h] (§19.13). */
    ENTITLEMENT_NEEDED,

    /** The built-in schedule ends within 5 weeks: no purchase can start. */
    UPDATE_REQUIRED,

    /** A schedule changed an accepted key, slot set or price, rolled back, or dropped a revocation (persistent). */
    SCHEDULE_CONFLICT,

    /** The issuer answered what no honest issuer answers (persistent). */
    ISSUER_MISMATCH,

    /** A relay refused a token or its drop relays are unusable (persistent). */
    REFUSED_BY_RELAY,

    /** Payment instructions wait; surfaced at least U[1 h, 6 h] after the invoice arrived (§19.11). */
    PAYMENT_READY,
    PAYMENT_EXPIRED,
    PAYMENT_LOST,

    /** Reserved (§19.4 point 4): Arti 0.46 does not expose the consensus lifetime, so it is never set (§19.22 point 3). */
    CLOCK_UNTRUSTED,
}

/**
 * Counts and enums only (design §11.2): the last week with an access token, fresh access tokens per
 * week, fresh credits and invite tokens, and the flags. `toString()` shows the flags only.
 */
class EntitlementStatus(
    val coverageEndWeek: Long?,
    freshTokensPerWeek: Map<Long, Int>,
    val credits: Int,
    val invites: Int,
    flags: Set<EntitlementFlag>,
) {
    val freshTokensPerWeek: Map<Long, Int> = freshTokensPerWeek.toSortedMap()
    val flags: Set<EntitlementFlag> = flags.toSet()

    override fun toString(): String = "EntitlementStatus(flags=$flags)"

    companion object {
        val EMPTY = EntitlementStatus(null, emptyMap(), 0, 0, emptySet())
    }
}
