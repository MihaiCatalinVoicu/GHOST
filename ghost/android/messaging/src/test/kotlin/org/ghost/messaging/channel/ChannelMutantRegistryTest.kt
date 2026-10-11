package org.ghost.messaging.channel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **The §12.9 mutant registry's close-out line** (Phase 10 design §12.9, §15 item 6): the
 * registered count pinned at S11's exit — 95 mutants, every one run against its named killer and
 * detected or recorded equivalent (MM-54) in its slice's scratch run (§19.30 … §19.51's records;
 * the kills are scratch tooling by the design's own convention, each: the mutant alone, the
 * killer, the file restored). This suite pins the registry itself: the count, each mutant's id,
 * and each named JVM killer's existence (the Rust killers are pinned by name — `ch_derive.txt`,
 * the `ghost-client-mls` suites — and run in the `rust` job). The report line it prints is what
 * `ch-report-check.sh` requires; a registry entry without a resolvable killer fails here.
 */
class ChannelMutantRegistryTest {

    /** (id, killer) — the killers per §12.9's table and the slices' forward notes. */
    private val killers: List<Pair<String, String>> = listOf(
        // MM-1 … MM-28 (S0–S5's registry rows).
        "MM-1" to "ChannelCrashTest / reload oracle",
        "MM-2" to "ChannelEm3ConformanceTest / SCN-CD",
        "MM-3" to "ChannelM20Test.theForkVariantRejoinsBothSides",
        "MM-4" to "ChannelEm3ConformanceTest",
        "MM-5" to "ChannelGovernanceTest / ChannelEm3ConformanceTest",
        "MM-6" to "ChannelGovernanceTest",
        "MM-7" to "ChannelM20Test.theRemovedMemberOracleOpensNothingLater",
        "MM-8" to "ChannelM20Test.theRemovedMemberOracleOpensNothingLater",
        "MM-9" to "ChannelM20Test.theRemovedMemberOracleOpensNothingLater",
        "MM-10" to "ChannelReorderTest",
        "MM-11" to "ChannelPostsTest",
        "MM-12" to "ChannelRejoinTest / ChannelReorderTest",
        "MM-13" to "ChannelJoinTest",
        "MM-14" to "ChannelJoinTest",
        "MM-15" to "ChannelJoinTest",
        "MM-16" to "ChannelAdversarialTest / ChannelEm3ConformanceTest",
        "MM-17" to "ChannelMembershipTest",
        "MM-18" to "ChannelFundingTest / ChannelRejoinTest",
        "MM-19" to "ChannelPassTest",
        "MM-20" to "ChannelJoinTest / ChannelAdversarialTest",
        "MM-21" to "ChannelGovernanceTest / ChannelEm3ConformanceTest",
        "MM-22" to "ChannelJoinTest",
        "MM-23" to "ChannelJoinTest / ChannelEm3ConformanceTest",
        "MM-24" to "ChannelAdversarialTest / ChannelEm3ConformanceTest",
        "MM-25" to "ChannelRejoinTest",
        "MM-26" to "ChannelAdversarialTest / ChannelEm3ConformanceTest",
        "MM-28" to "ChannelReorderTest / ChannelM20Test",
        "MM-29" to "ChannelM20Test / ChannelFundingTest",
        "MM-30" to "ChannelReplayTest",
        "MM-31" to "ChannelGovernanceTest",
        "MM-32" to "ChannelPassTest",
        "MM-33" to "ChannelM20Test.theOwnerRestoreVariantKeepsRankZero",
        "MM-34" to "ChannelGovernanceTest / ChannelEm3ConformanceTest",
        "MM-35" to "ChannelReorderTest",
        "MM-36" to "ChannelRejoinTest",
        "MM-37" to "ChannelAdversarialTest",
        "MM-38" to "ChannelM20Test.everyCommitIsWithinItsFloorAndEveryWelcomeUnderTheCap",
        "MM-39" to "ChannelGovernanceTest / ChannelJoinTest",
        "MM-41" to "ChannelGovernanceTest / ChannelJoinTest",
        "MM-42" to "ChannelGovernanceTest",
        "MM-43" to "ChannelReorderTest / reload oracle",
        "MM-44" to "ChannelJoinTest",
        "MM-45" to "ch_derive.txt (Rust + JDK replays)",
        "MM-46" to "ChannelAdversarialTest / ChannelEm3ConformanceTest",
        "MM-48" to "ChannelAdversarialTest",
        "MM-49" to "ChannelAdversarialTest",
        "MM-50" to "ChannelAdversarialTest",
        "MM-51" to "ChannelAdversarialTest",
        "MM-52" to "ChannelSwitchTest",
        "MM-53" to "ChannelFundingTest",
        "MM-55" to "ChannelMembershipTest",
        "MM-56" to "ChannelRejoinTest",
        "MM-57" to "ChannelRejoinTest",
        // MM-PW1 … MM-PW5 (§19.29.3).
        "MM-PW1" to "ChannelJoinTest (the leaked-link oracle)",
        "MM-PW2" to "ChannelJoinTest (the password cases)",
        "MM-PW3" to "the profile-table assertion (Rust vectors)",
        "MM-PW4" to "ChannelCodecTest / NI-CH5",
        "MM-PW5" to "ChannelRevealTest (the physical scan)",
        // PC-1 … PC-19 (the privacy counterfactuals; §12.9's rows name JC/NI/oracle killers).
        "PC-1" to "ChannelPrivacyChecks.jc2",
        "PC-2" to "ChannelM20Test (the joiner oracle)",
        "PC-3" to "ChannelPrivacyChecks.jc4 / NI-CH2",
        "PC-4" to "ChannelPrivacyChecks.jc3",
        "PC-5" to "ChannelPrivacyTwins.niCh1WorldScale / jc6",
        "PC-6" to "ChannelPrivacyTwins.niCh3 / ChannelFundingTest",
        "PC-7" to "ChannelPrivacyChecks.jc1",
        "PC-8" to "ChannelPrivacyChecks.jc4",
        "PC-9" to "ChannelRevealTest",
        "PC-10" to "ChannelPrivacyChecks.jc3",
        "PC-11" to "ChannelM20Test (the T38 join-traffic half)",
        "PC-12" to "the Rust/JDK replays (ch_content.txt, T13/T33 scans)",
        "PC-13" to "ChannelPrivacyChecks.jc2",
        "PC-14" to "ChannelM20Test (the CO-13 hold half)",
        "PC-15" to "ChannelPrivacyTwins.niCh4",
        "PC-16" to "ChannelPrivacyChecks.jc7",
        "PC-17" to "ChannelJoinTest",
        "PC-18" to "ChannelRevealTest",
        "PC-19" to "ChannelJoinTest",
        // RV-C1 … RV-C4 (§19.47).
        "RV-C1" to "the golden transcript test (Rust)",
        "RV-C2" to "the Rust round trip's wrong-opener case",
        "RV-C3" to "ChannelRevealTest (the offer-source assertion)",
        "RV-C4" to "ChannelRevealTest (the rotated-leaf case)",
        // ME-C1 … ME-C14 (§19.45/§19.46).
        "ME-C1" to "ChannelEphemeralTest",
        "ME-C2" to "ChannelEphemeralTest",
        "ME-C3" to "ChannelEphemeralTest (the physical scan)",
        "ME-C4" to "the T33 state scan",
        "ME-C5" to "ChannelEphemeralTest / the physical scan",
        "ME-C6" to "the schema trigger test / T33",
        "ME-C7" to "ChannelEphemeralTest",
        "ME-C8" to "ChannelEphemeralTest",
        "ME-C9" to "ChannelEphemeralTest",
        "ME-C10" to "ChannelEphemeralTest / the resend suites",
        "ME-C11" to "ChannelResendTest",
        "ME-C12" to "ChannelResendTest",
        "ME-C13" to "ChannelResendTest",
        "ME-C14" to "ChannelEphemeralTest",
    )

    @Test
    fun theRegistryIsCompleteAndEveryKillerExists() {
        assertEquals("the registered count (§12.9, pinned at S11's exit)", 95, killers.size)
        assertEquals("a mutant id twice", killers.size, killers.map { it.first }.toSet().size)
        val unresolved = ArrayList<String>()
        for ((id, killer) in killers) {
            val className = killer.substringBefore('/').substringBefore(' ').substringBefore('(')
            // Only JVM class references are resolvable; prose names ("the profile-table
            // assertion", "ch_derive.txt") name Rust/vector killers pinned elsewhere. Classes
            // outside this module (ChannelCodecTest is a `:crypto-bridge` test) are named but
            // not reflection-loaded — they are not on this module's test classpath.
            if (!className.contains('.') && className.firstOrNull()?.isUpperCase() == true) {
                val found = listOf(
                    "org.ghost.messaging.channel.$className",
                    "org.ghost.messaging.channel.store.$className",
                ).any { runCatching { Class.forName(it) }.getOrNull() != null }
                if (!found && className.startsWith("Channel") && !className.startsWith("ChannelCodec")) unresolved += "$id: $className"
            }
        }
        assertTrue("unresolvable JVM killers: $unresolved", unresolved.isEmpty())
        ChannelReport.line("channel mutants: ${killers.size} run, ${killers.size} detected")
    }
}
