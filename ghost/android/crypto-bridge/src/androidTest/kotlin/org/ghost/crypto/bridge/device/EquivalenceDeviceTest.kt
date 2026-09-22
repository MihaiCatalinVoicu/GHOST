package org.ghost.crypto.bridge.device

import org.ghost.crypto.bridge.DmEquivalence
import org.ghost.device.DeviceRunner
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **The emulator half of the host/Android equivalence test** (Phase 9 design §15.9 item 7, RG-2,
 * V-16; slice S12): the case file replayed on the emulator's x86_64 **test library** —
 * `libghost_dm_host.so`, the same source, pins and toolchain as `libghost_client_net.so` plus the
 * `test-vectors` feature, packaged only in this `androidTest` APK (§22.8.10 point 6) — and compared
 * byte for byte with the host fixture the `android` job's JVM test recorded on `ghost-dm-host`.
 *
 * Both files are this APK's assets (`dm_equivalence.txt`, `dm_equivalence_host.txt`); the commit
 * is the `commit` instrumentation argument, and a fixture of another commit is refused. The report
 * line `dm-equivalence: N cases, N identical, control detected` is what `dm-emulator.yml` requires.
 */
class EquivalenceDeviceTest {

    @Test
    fun theEmulatorTestLibraryProducesTheHostBytes() {
        System.loadLibrary(TEST_LIBRARY)
        val assets = DeviceRunner.current.context.assets
        val cases = DmEquivalence.parseCases(assets.open(CASES).bufferedReader().use { it.readText() })
        val host = DmEquivalence.HostFixture.parse(assets.open(HOST_FIXTURE).bufferedReader().use { it.readText() })
        val commit = DeviceRunner.args.getString("commit") ?: "unrecorded"
        val report = DmEquivalence.compare(cases, host, commit, DmEquivalence::run)
        DeviceRunner.report(report.line)
        assertTrue(report.line, report.passed)
    }

    private companion object {
        /** `ghost-dm-host` cross-compiled for `x86_64-linux-android` (§22.8.10 point 6). */
        const val TEST_LIBRARY = "ghost_dm_host"
        const val CASES = "dm_equivalence.txt"
        const val HOST_FIXTURE = "dm_equivalence_host.txt"
    }
}

/** The `:crypto-bridge` device suite: the equivalence test (§15.9 item 7). */
class CryptoBridgeDeviceRunner : DeviceRunner(listOf(EquivalenceDeviceTest::class.java))
