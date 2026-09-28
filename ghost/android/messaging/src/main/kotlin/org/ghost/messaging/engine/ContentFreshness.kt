package org.ghost.messaging.engine

/**
 * Whether decrypted content may be applied, measured from when its ciphertext arrived (§7.6,
 * §21.10 points 3 and 5):
 * - **R9, the age bound:** the author time is at most `FRESH(bucket)` before the arrival and at most
 *   `2σ` after it;
 * - **`accept_after_minute`** (§8.6): nothing authored before it, on a device that restored;
 * - **binding B1** (§7.6): in pair mode the author's own week is the pair key's week, so an old L0
 *   cannot be re-sealed under a later week key.
 *
 * A policy object rather than three inline comparisons **only** so the crash worlds can install
 * mutant MC-9 ("no freshness check", §15.7; design §22.38): [RULE] is the three comparisons
 * `ReceiveStep` wrote inline, verbatim and in their order, and the one production caller
 * (`MessagingRuntime`) never names a policy, so it runs [RULE]. [acceptAfter] is a supplier so the
 * self row is read exactly when the inline code read it — once the age bound has passed — and the
 * device issues the same statements as before.
 */
internal fun interface ContentFreshness {
    fun admits(
        authorSeconds: Long,
        arrivalSeconds: Long,
        freshSeconds: Long,
        pairWeek: Long?,
        acceptAfter: () -> Long?,
    ): Boolean

    companion object {
        /** §7.6 and §21.10, as `ReceiveStep` wrote them inline before §22.38. */
        val RULE = ContentFreshness { authorSeconds, arrivalSeconds, freshSeconds, pairWeek, acceptAfter ->
            if (authorSeconds < arrivalSeconds - freshSeconds ||
                authorSeconds > arrivalSeconds + 2 * DmTimers.SIGMA_SECONDS
            ) {
                false
            } else {
                val after = acceptAfter()
                if (after != null && authorSeconds < after) {
                    false
                } else {
                    pairWeek == null || DmTime.week(authorSeconds) == pairWeek
                }
            }
        }
    }
}
