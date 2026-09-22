package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmNative
import java.io.File

/**
 * T35 over the DM world (Phase 9 design §14.1 T35: "provenance-tagged key objects in
 * `ghost-client-dm` test builds across the DM world (PQ2)"), as far as the tags reach.
 *
 * **How it is enforced.** `ghost-dm-host` built with `--features provenance` compiles
 * `provenance::assert_seal` into every seal: a key whose provenance §9.3 does not allow for the mode
 * panics inside Rust, the JNI guard returns `INTERNAL`, and the engine call that sealed throws — so a
 * privacy world that finishes under that build sealed every blob it stored with an allowed key. The
 * Rust tests `pm_32_an_intro_inner_layer_without_the_kem_trips_t35` and
 * `a_kem_key_may_not_seal_a_bundle` show the assertion is wired into the seal path.
 *
 * **How the build is recognised.** The assertion's message format, `"T35: "` and `" sealed with "`,
 * is linked into the library only when the assertion is (the unused `provenance::check` of a plain
 * build is dropped by the linker; measured on the MSVC build, S11). A run against a plain build writes
 * `NOT RUN` instead of a PASS it did not earn, and `dm-report-check.sh` refuses that line.
 *
 * **What it does not cover (§22.16, a structural finding).** The X-Wing-keyed intro inner layer is
 * not a `SealKey` at all — `k_in` is derived and used inside `seal_intro_with` — so no tag describes
 * it, and §15.7's PM-32 ("the intro inner layer sealed without the X-Wing KEM") is not expressible to
 * this mechanism; the Rust test named after PM-32 seals a *pair* envelope under a card key, which is
 * PM-33's shape.
 */
internal object T35 {

    /** True when the loaded host library carries the provenance assertions. */
    fun provenanceBuild(): Boolean {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY) ?: return false
        val bytes = runCatching { File(path).readBytes() }.getOrNull() ?: return false
        return contains(bytes, "T35: ".toByteArray()) && contains(bytes, " sealed with ".toByteArray())
    }

    fun line(world: PrivacyWorld): String {
        if (!provenanceBuild()) {
            return "dm T35: NOT RUN the loaded ghost-dm-host was built without --features provenance"
        }
        val seals = world.truth.seals
        val bundles = world.truth.bundleBlobs.size
        val total = seals.values.sum() + bundles
        val complete = (seals["INTRO"] ?: 0) > 0 && (seals["PAIR"] ?: 0) > 0 &&
            (seals["PROVISIONAL"] ?: 0) > 0 && bundles > 0
        return "dm T35: ${if (complete) "PASS" else "FAIL"} provenance build; $total seals asserted " +
            "(intro outer ${seals["INTRO"] ?: 0}, pair ${seals["PAIR"] ?: 0}, provisional ${seals["PROVISIONAL"] ?: 0}, " +
            "bundle $bundles), 0 refused; the X-Wing inner layer carries no tag" +
            (if (complete) "" else "; a seal mode was never exercised")
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
