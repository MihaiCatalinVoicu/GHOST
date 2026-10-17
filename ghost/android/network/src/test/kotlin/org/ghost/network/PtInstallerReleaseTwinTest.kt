package org.ghost.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * G-T5's code half (design `faza12-transports.md` §13): the runtime hash check has no
 * release/debug twin — no switch, flag, system property, or `BuildConfig`-style conditional
 * can skip the SHA-256 verification before the binary lands on disk (G-DM5's rule applied to
 * the PT extractor). PT-U9 pins the behavioural half (a mismatched asset is refused); this
 * test pins the structural half by reading the production source, the same discipline the
 * `:storage` lint suites use.
 */
class PtInstallerReleaseTwinTest {

    private fun installerSource(): String {
        val dir = System.getProperty("ghost.network.sourcedir")
            ?: error("ghost.network.sourcedir not set (network/build.gradle.kts forwards it)")
        val file = File(dir, "org/ghost/network/PtInstaller.kt")
        assertTrue("PtInstaller.kt not found under $dir", file.isFile)
        return file.readText()
    }

    /** Code lines only: the rules read source, so comment text never satisfies or violates one. */
    private fun codeLines(src: String): List<String> =
        src.lineSequence()
            .map { it.substringBefore("//") }
            .filter { it.isNotBlank() }
            .toList()

    @Test
    fun theHashVerificationHasNoBypass() {
        val code = codeLines(installerSource())
        // The verification is there: SHA-256 over the asset bytes, compared against the sums.
        assertTrue(
            "PtInstaller no longer computes SHA-256 (the gate's pin is stale or the check was removed)",
            code.any { it.contains("MessageDigest") && it.contains("SHA-256") },
        )
        // No bypass surface at all: nothing conditional on a debug flag, a build config, a
        // system property or an environment variable anywhere in the extractor.
        val banned = listOf(
            "BuildConfig" to "a BuildConfig conditional",
            "DEBUG" to "a debug flag",
            "System.getProperty" to "a system-property switch",
            "System.getenv" to "an environment switch",
            "getBoolean" to "a boolean flag read",
        )
        for ((token, what) in banned) {
            assertFalse(
                "PtInstaller gained $what ('$token'): the release twin rule (G-DM5) forbids it",
                code.any { it.contains(token) },
            )
        }
        // The refusal is unconditional: the hash-mismatch category is thrown exactly when the
        // digests differ — no flag can reach around it.
        assertTrue(
            "PtInstaller no longer throws the hash-mismatch refusal (stale pin or removed check)",
            code.any { it.contains("PT_HASH_MISMATCH") },
        )
        assertTrue(
            "the digest comparison must guard the refusal",
            code.any { it.contains("actual") && it.contains("expected") && it.contains("equals") },
        )
    }
}
