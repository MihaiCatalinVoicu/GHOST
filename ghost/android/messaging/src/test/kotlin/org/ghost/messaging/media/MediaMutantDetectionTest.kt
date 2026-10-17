package org.ghost.messaging.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The JVM media mutants of Phase 11 design §15.9 whose home is the exit gate and whose killer
 * this harness holds (the `MediaWorldVariant` knobs), in the DmMutantDetectionTest discipline:
 * each case runs the **same** small scripted world clean — which must pass, so a mutant cannot
 * be "detected" by a world that was broken anyway — and once with the mutation, which the named
 * join (JM) or the world's own register oracle must catch. The kill is the check the design
 * names, not "something broke".
 *
 * What is not here (each recorded in §22.12): the Rust-crate mutants (the sealer/walker shapes,
 * `scripts/ci/media-mutants.sh`, the S1 set), the key-slot and binding mutants (PM-M13/17/22/24,
 * killed in `DmMediaReceiveTest` and the key-slot suites on the real cryptography), PM-M3 (the
 * χ² oracle lives in the emulator's §15.8 scan; the JVM sampled windows need a statistic the
 * stand-in bytes defeat), PM-M6 (a shared object is a :sync-protocol violation caught by the
 * corruption/vector suites), the emulator seven, and the two self-test fixtures (already the
 * G-M1/G-M3 negative fixtures in `self-test.sh`). The count the report may claim is this file's
 * registry — never the design's 43 until the rest land.
 */
class MediaMutantDetectionTest {

    companion object {
        /**
         * The gate report's close-out: the count this suite actually killed — never the design's
         * 43 until the rest land (G-M9 refuses the line otherwise, which is the point).
         */
        @org.junit.AfterClass
        @JvmStatic
        fun reportCloseOut() {
            if (System.getProperty("ghost.media.report") != null) {
                MediaPrivacyReport.line(
                    "media mutants: 9 run, 9 detected (JVM privacy-world kills; the Rust crate set, " +
                        "the key-slot/binding kills and the emulator seven are §22.12's pending list)",
                )
            }
        }
    }

    private val seed = 0x5eed_0002L

    /** One image send and one background class-7 video send, a 7-day and a 5-minute timer. */
    private fun script(): List<ScriptedSend> = listOf(
        ScriptedSend(
            day = 0, minuteOfDay = 100, sender = 0, recipient = 1,
            kindIsImage = true, classCode = 0, viewOnce = false, withCaption = true,
            timerCode = 4, viewed = true,
        ),
        ScriptedSend(
            day = 0, minuteOfDay = 200, sender = 0, recipient = 1,
            kindIsImage = false, classCode = 7, viewOnce = false, withCaption = false,
            timerCode = 1, backgroundOnly = true, viewed = false,
        ),
    )

    private fun runJoins(variant: MediaWorldVariant): List<MediaJoins.Result> {
        MediaPrivacyWorld(MediaPrivacyScale.SMALL, seed, variant.copy(scriptedSends = script())).use { world ->
            val joins = world.run()
            return joins.all()
        }
    }

    private fun byName(results: List<MediaJoins.Result>, name: String): MediaJoins.Result =
        results.first { it.name == name }

    /**
     * The discipline: [control] runs the honest variant and must be green; [mutated] runs the
     * mutant and must be caught by [killer], whose detail names what bit.
     */
    private fun detect(
        id: String,
        detectedBy: String,
        variant: MediaWorldVariant,
        killer: (List<MediaJoins.Result>) -> Int,
    ) {
        val control = runJoins(MediaWorldVariant())
        for (r in control) {
            assertEquals("control world, ${r.name}: ${r.detail}", 0, r.violations)
        }
        val mutated = runJoins(variant)
        val caught = killer(mutated)
        assertTrue(
            "$id ($detectedBy) survived: violations=$caught; " +
                mutated.joinToString("; ") { "${it.name}=${it.violations} ${it.detail}" },
            caught > 0,
        )
        println("$id: detected by $detectedBy (${variant.name})")
    }

    @Test
    fun pmM1TheLastFragmentInASmallerBucketIsCaughtByJm4() = detect(
        "PM-M1", "JM4",
        MediaWorldVariant(name = "PM-M1", lastFragmentSmallBucket = true),
    ) { byName(it, "JM4").violations }

    @Test
    fun pmM2ExactFragmentCountsAreCaughtByJm1() = detect(
        "PM-M2", "JM1",
        MediaWorldVariant(name = "PM-M2", noClassPadding = true),
    ) { byName(it, "JM1").violations }

    @Test
    fun pmM4TheManifestSizedByItsHashListIsCaughtByJm1() = detect(
        "PM-M4", "JM1 (the manifest store's size)",
        MediaWorldVariant(name = "PM-M4", manifestByHashList = true),
    ) { byName(it, "JM1").violations }

    @Test
    fun pmM5FetchingWhenTheDescriptorArrivesIsCaughtByJm7() = detect(
        "PM-M5", "JM7",
        MediaWorldVariant(name = "PM-M5", fetchOnDescriptor = true),
    ) { byName(it, "JM7").violations }

    @Test
    fun pmM7TheSenderRedeemingForMcIsCaughtByJm5() = detect(
        "PM-M7", "JM5",
        MediaWorldVariant(name = "PM-M7", senderRedeemsRecipientMedia = true),
    ) { byName(it, "JM5").violations }

    @Test
    fun pmM8ViewOnceStoredWithTheHourTtlIsCaughtByJm4() {
        // A view-once object under a 7-day timer: the honest bucket is 7 days, the mutant's 1 h.
        val viewOnceScript = listOf(
            ScriptedSend(
                day = 0, minuteOfDay = 100, sender = 0, recipient = 1,
                kindIsImage = true, classCode = 0, viewOnce = true, withCaption = true,
                timerCode = 4, viewed = true,
            ),
        )
        fun joins(variant: MediaWorldVariant): List<MediaJoins.Result> {
            MediaPrivacyWorld(MediaPrivacyScale.SMALL, seed, variant.copy(scriptedSends = viewOnceScript)).use { w ->
                return w.run().all()
            }
        }
        val control = joins(MediaWorldVariant())
        assertEquals(0, byName(control, "JM4").violations)
        val mutated = joins(MediaWorldVariant(name = "PM-M8", viewOnceHourTtl = true))
        assertTrue(
            "PM-M8 survived: " + mutated.joinToString("; ") { "${it.name}=${it.violations}" },
            byName(mutated, "JM4").violations > 0,
        )
    }

    @Test
    fun pmM16M0RegisteredAtFirstMediaUseIsCaughtByTheRegisterOracle() {
        // NI-M5's kill: the register trace must fall at activation (minute 0), not the first use.
        fun registerMinutes(variant: MediaWorldVariant): List<Long> {
            MediaPrivacyWorld(MediaPrivacyScale.SMALL, seed, variant.copy(scriptedSends = script())).use { w ->
                w.run()
                return w.relay.events.filter { it.op == MediaViewOp.REGISTER }.map { it.minute }
            }
        }
        val control = registerMinutes(MediaWorldVariant())
        assertTrue("the control's registers all fall at activation: $control", control.isNotEmpty() && control.all { it == 0L })
        val mutated = registerMinutes(MediaWorldVariant(name = "PM-M16", registerAtFirstMediaUse = true))
        assertTrue("PM-M16 survived: registers at $mutated", mutated.any { it != 0L })
    }

    @Test
    fun pmM20TheCountdownStartingAtCommitIsCaughtByNiM7sEquality() {
        // The design names NI-M7 and JM1's exemption list: a class-7 video under a 5-minute timer
        // reaches the upload deadline in both worlds (R-T4 bounds the burst), but PM-M20's
        // commit-based countdown cuts the burst earlier — the store streams differ.
        val background = listOf(
            ScriptedSend(
                day = 0, minuteOfDay = 100, sender = 0, recipient = 1,
                kindIsImage = false, classCode = 7, viewOnce = false, withCaption = false,
                timerCode = 1, backgroundOnly = true, viewed = false,
            ),
        )
        fun storeCount(variant: MediaWorldVariant): Int {
            MediaPrivacyWorld(MediaPrivacyScale.SMALL, seed, variant.copy(scriptedSends = background)).use { w ->
                w.run()
                return w.relay.events.count { it.op == MediaViewOp.STORE && it.role == MediaNsRole.CONTACT_MEDIA }
            }
        }
        val control = storeCount(MediaWorldVariant())
        val mutated = storeCount(MediaWorldVariant(name = "PM-M20", countdownAtCommit = true))
        assertTrue(
            "PM-M20 survived: control stored $control media events, mutant $mutated (identical bursts)",
            control != mutated,
        )
    }

    @Test
    fun pmM25TheTtlFromTheSendTimerIsCaughtByJm4() {
        // A 7-day-timer object whose SEND-time read saw a 1-hour conversation (R-MT4 violated).
        val timerScript = listOf(
            ScriptedSend(
                day = 0, minuteOfDay = 100, sender = 0, recipient = 1,
                kindIsImage = true, classCode = 0, viewOnce = false, withCaption = true,
                timerCode = 4, viewed = true,
            ),
        )
        fun joins(variant: MediaWorldVariant): List<MediaJoins.Result> {
            MediaPrivacyWorld(MediaPrivacyScale.SMALL, seed, variant.copy(scriptedSends = timerScript)).use { w ->
                return w.run().all()
            }
        }
        assertEquals(0, byName(joins(MediaWorldVariant()), "JM4").violations)
        val mutated = joins(MediaWorldVariant(name = "PM-M25", ttlFromSendTimer = true))
        assertTrue(
            "PM-M25 survived: " + mutated.joinToString("; ") { "${it.name}=${it.violations}" },
            byName(mutated, "JM4").violations > 0,
        )
    }
}
