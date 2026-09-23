package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmNative
import java.io.File

/**
 * T35 over the DM world (Phase 9 design §14.1 T35: "provenance-tagged key objects in
 * `ghost-client-dm` test builds across the DM world (PQ2)"), as far as the tags reach.
 *
 * **How it is enforced.** `ghost-dm-host` built with `--features provenance` compiles
 * `provenance::assert_seal` into every seal: a key whose provenance §9.3 does not allow for the mode
 * panics inside Rust, the JNI guard returns `INTERNAL`, and the engine call that sealed throws. The
 * recorder counts every seal call, every sealed result and every throw ([GroundTruth.sealCall]), so
 * the line's numbers are measured; a throw also ends the world run, which is why a finished world
 * reports 0 of them. The Rust tests `pm_32_an_intro_inner_layer_without_the_kem_trips_t35` and
 * `a_kem_key_may_not_seal_a_bundle` show the assertion is wired into the seal path.
 *
 * **How the build is recognised.** The assertion's message format, `"T35: "` and `" sealed with "`,
 * is linked into the library only when the assertion is (the unused `provenance::check` of a plain
 * build is dropped by the linker; measured on the MSVC build, S11). A run against a plain build writes
 * `NOT RUN` instead of a PASS it did not earn, and `dm-report-check.sh` refuses that line.
 *
 * **What the line measures, and what it cannot (§22.16).** The tags are **static**: every pair and
 * provisional key is tagged `Kem.transported_under()` at the JNI boundary whatever path its root
 * took, and every contact card's keys are tagged `Card(Link)` whatever the card's source (Kotlin's
 * `CardSource` never crosses JNI). So a world run shows that no seal call site handed a key of the
 * wrong **kind** to a mode — nothing a JVM-side mutation can reach makes this line fail, and no
 * privacy mutant of this slice is killed by it. The X-Wing-keyed intro inner layer is not a
 * `SealKey` at all (`k_in` is derived inside `seal_intro_with`), so no tag describes it and PM-32 is
 * not expressible to the mechanism. §22.8.7 rule 6's **PQ-R8 listing** is written from the world's
 * own record of how each card arrived ([GroundTruth.introSealsBySource]), not from the tag, which
 * would list every card-keyed seal as LINK.
 */
internal object T35 {

    /** True when the loaded host library carries the provenance assertions. */
    fun provenanceBuild(): Boolean {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY) ?: return false
        val bytes = runCatching { File(path).readBytes() }.getOrNull() ?: return false
        return contains(bytes, "T35: ".toByteArray()) && contains(bytes, " sealed with ".toByteArray())
    }

    class Result(val line: String, val passed: Boolean, val ran: Boolean)

    fun run(world: PrivacyWorld): Result {
        if (!provenanceBuild()) {
            return Result("dm T35: NOT RUN the loaded ghost-dm-host was built without --features provenance", false, false)
        }
        val truth = world.truth
        val calls = truth.seals.values.sum()
        val sealed = truth.sealedOk
        val total = sealed.values.sum()
        fun of(mode: String) = sealed[mode] ?: 0
        val complete = of("INTRO") > 0 && of("PAIR") > 0 && of("PROVISIONAL") > 0 && of(RecordingCrypto.BUNDLE) > 0
        val passed = complete && truth.sealsThrown == 0
        val link = truth.introSealsBySource["link"] ?: 0
        val sources = truth.introSealsBySource.entries.joinToString(", ") { "${it.value} ${it.key}" }
        val line = "dm T35: ${if (passed) "PASS" else "FAIL"} provenance build; $total seals under the assertion " +
            "of $calls seal calls (intro outer ${of("INTRO")}, pair ${of("PAIR")}, provisional ${of("PROVISIONAL")}, " +
            "bundle ${of(RecordingCrypto.BUNDLE)}), ${truth.sealsThrown} threw; PQ-R8 exception (LINK-sourced " +
            "intro seals, by the world's record of each card): $link of ${of("INTRO")} ($sources); the tags are " +
            "static and the X-Wing inner layer carries none (§22.16)" +
            (if (complete) "" else "; a seal mode was never exercised")
        return Result(line, passed, true)
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
