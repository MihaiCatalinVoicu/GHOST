package org.ghost.messaging.dmworld

/**
 * The recorded baselines of S-DM2 and S-DM4 (Phase 9 design §15.6: "the report check fails on a
 * regression above the recorded baseline + 0.02"; §16.1: "S-DM2/S-DM4 within baseline + 0.02";
 * §22.30, re-recorded by §22.36).
 *
 * **What they are a baseline of, exactly:** the privacy world at the PR scale (N = 120 over 14
 * days), seed 5eed0001, STANDARD, **on the production triggers** of §22.36 — a relay session start
 * only where Phase 7 opens a relay session, the actor timer, the alarm, the consumer tail and the
 * listener's hints as `MessagingWiring` and `MessagingRuntime` give them — measured on the owner's
 * workstation on 2026-09-27. Nothing else has been measured: the gate scale (N = 600 over 42 days)
 * has no baseline, and the other nine pinned seeds have not been run with these statistics, so every
 * other (scale, seed) has **no** baseline and its lines say so. The LD view carries no ciphertext
 * byte, so the LD attacker's numbers are a function of the seeded behaviour alone and repeat run to
 * run (the full view's bytes do not, but they enter only S-DM1). `dm-report-check.sh` holds the same
 * numbers and compares a report against **its own** copy, not against what the report prints.
 *
 * **The first recording** (2026-09-24, §22.30) was of the same world when every foreground minute
 * started a relay session — the design's cadence, not the wiring's (phase review MD-2 and MD-3,
 * §22.34 item 6): S-DM2 0.5611 and 7 d 0.5615, S-DM4 0.8769 and 0.0029 bits. On the production
 * triggers S-DM2 measures 0.5621 and 7 d 0.5624, and S-DM4 is unchanged to the digit.
 */
internal object EdgeBaselines {

    private const val WHAT = "PR scale, seed 5eed0001, production triggers, recorded 2026-09-27"

    /**
     * S-DM2: the strongest LD attacker's AUC over the six-hour windows (the co-occurrence attacker,
     * 0.5621, in the recorded run), and the same for the one TTL class that held at least 100
     * conversations there (7 d: 220 conversations; 1 h held 56, 1 d 32 and 30 d 52, reported only).
     */
    private const val SDM2_PR_SEED1: Double = 0.5621
    private const val SDM2_7D_PR_SEED1: Double = 0.5624

    /** S-DM4: the within-inbox and the cross-inbox mutual information, in bits (each held to + 0.02). */
    private const val SDM4_WITHIN_PR_SEED1: Double = 0.8769
    private const val SDM4_PAIRING_PR_SEED1: Double = 0.0029

    private fun recorded(scale: PrivacyScale, seed: Long): Boolean = scale == PrivacyScale.PR && seed == PrivacySeeds.ALL[0]

    fun sdm2(scale: PrivacyScale, seed: Long): EdgeStatistics.Baseline? =
        if (recorded(scale, seed)) EdgeStatistics.Baseline(SDM2_PR_SEED1, WHAT, mapOf("7 d" to SDM2_7D_PR_SEED1)) else null

    fun sdm4(scale: PrivacyScale, seed: Long): Pair<Pair<Double, Double>, String>? =
        if (recorded(scale, seed)) (SDM4_WITHIN_PR_SEED1 to SDM4_PAIRING_PR_SEED1) to WHAT else null
}
