package org.ghost.network

import android.content.Context
import android.os.Build
import android.system.Os
import org.ghost.device.DeviceRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * PT-1 on a device (Phase 12 design `faza12-transports.md` §5.4.4, §5.4.5 (rev 3), §12.1:
 * V-T6 re-run as a suite, in-app — the S0-deferred filesDir half, S0-T7): the `:network`
 * extraction installs the APK-asset lyrebird into the app-private `filesDir/pt/<abi>/`, the
 * stamp makes a repeat install a no-op, and the mode is exactly 700.
 *
 * **The exec verdict (C-3's fired half, OA-4 resolved in rev 3).** On the gate emulators
 * (API 29+, targetSdk ≥ 29), a direct `execve` of the filesDir binary is **denied by
 * SELinux** — `avc: denied { execute_no_trans } … scontext=u:r:untrusted_app
 * tcontext=u:object_r:app_data_file` — the Android 10 W^X rule the design's §5.4 point 5
 * predated. Plain `execute` (mmap-exec) **is granted**, so the adopted exec model (rev 3,
 * §5.4.5) is the *system dynamic linker as the exec target* with the binary's absolute path
 * as its first argument — ptmgr config `path` + `arguments`, no arti patch; the product path
 * resolves the linker from the compiled ABI at config-build time and fails closed
 * (`bridge_config`, `PtLinkerMissing` class) when it does not exist.
 *
 * This probe pins the facts: the direct exec **must** be refused; the own-ABI linker exec
 * **must** answer (`lyrebird 0.9.0`); the arm64 binary through the linker **must** answer
 * on an arm64 device (the OA-2 on-device half) — on a non-arm64 host without ARM translation
 * the arm64 half is recorded with its reason and not asserted (a JUnit skip would count as
 * a failure under this runner, §15.9).
 */
class PtInstallDeviceTest {

    @Test
    fun installsVerifiesChmodsAndProbesFilesDirExec() {
        val context = DeviceRunner.current.targetContext
        val installer = PtInstaller.forApp(context)
        val dir = installer.install()
        val binary = File(dir, PtInstaller.BINARY_NAME)

        // The install hash-verified the binary against the sums compiled into the test APK.
        assertTrue(installer.installed())
        assertTrue(binary.isFile)

        // chmod 700 exactly: owner rwx, nothing for group/other (700 octal = 448, 777 octal =
        // 511; Kotlin has no octal literals). st_mode carries the file-type bits, masked off.
        assertEquals(448, Os.stat(binary.absolutePath).st_mode and 511)

        // Idempotent: the versioned stamp turns the second install into a no-op.
        installer.install()
        assertTrue(installer.installed())

        // The filesDir exec verdict: direct execve is SELinux-denied (W^X, targetSdk 29+).
        val direct = try {
            ProcessBuilder(binary.absolutePath, "-version").redirectErrorStream(true).start()
                .let { it.inputStream.readBytes().toString(Charsets.UTF_8).trim() + "|exit=" + it.waitFor() }
        } catch (e: java.io.IOException) {
            "denied: " + (e.message ?: e.javaClass.simpleName)
        }
        DeviceRunner.report("pt-device: direct exec: $direct")
        assertTrue("direct exec must be refused by SELinux (W^X), got: $direct", direct.startsWith("denied"))

        // The adopted exec model (rev 3, §5.4.5): the system linker is the exec target; the
        // binary's absolute path is its argument. Both shipped ABIs are 64-bit, so the 64-bit
        // linker is the product path on every shipped ABI (verified on the x86_64 gate
        // images, where /system/bin/linker does not even exist).
        val ownAbi = Build.SUPPORTED_ABIS.firstOrNull { it in PtInstaller.SHIPPED_ABIS }
        val linker = File("/system/bin/linker64")
        assertTrue("no 64-bit linker on this device", linker.isFile)
        val own = linker.exec(binary, "-version")
        DeviceRunner.report("pt-device: own-abi ($ownAbi) linker64 exec: exit=${own.first} ${own.second.trim { it <= ' ' }}")
        assertEquals("lyrebird through the system linker must exit 0 on this ABI ($ownAbi)", 0, own.first)
        assertTrue("lyrebird -version answered: ${own.second}", own.second.contains("lyrebird"))

        // The arm64 static binary through bionic's linker64: asserted on an arm64 device (it
        // is the product path there — the OA-2 on-device half); recorded, not asserted, on a
        // non-arm64 host. A translation host (abilist containing arm64-v8a) asserts too — a
        // translated run is still the first real arm64-through-linker answer this probe can
        // give; a host without translation records exactly what happened.
        val arm64 = linker.exec(extractProbe(context, "arm64-v8a"), "-version")
        DeviceRunner.report("pt-device: arm64-through-linker64: exit=${arm64.first} ${arm64.second.trim { it <= ' ' }}")
        if (ownAbi == "arm64-v8a" || Build.SUPPORTED_ABIS.contains("arm64-v8a")) {
            assertEquals("arm64 lyrebird through linker64 must exit 0 on an arm64(-capable) device", 0, arm64.first)
            assertTrue("arm64 lyrebird -version answered: ${arm64.second}", arm64.second.contains("lyrebird"))
        } else {
            DeviceRunner.report(
                "pt-device: arm64 exec not asserted on this host: abi=$ownAbi, abilist=" +
                    Build.SUPPORTED_ABIS.joinToString() + " — no ARM translation here; the arm64 exec stays owner-device-timed (OA-2)",
            )
        }
    }

    /** Extracts an ABI's lyrebird asset into a probe dir (chmod 700, the same discipline). */
    private fun extractProbe(context: Context, abi: String): File {
        val dir = File(context.filesDir, "pt-probe/$abi").apply { mkdirs() }
        val binary = File(dir, PtInstaller.BINARY_NAME)
        context.assets.open("pt/$abi/${PtInstaller.BINARY_NAME}").use { input ->
            binary.outputStream().use { out -> input.copyTo(out) }
        }
        binary.setExecutable(true, /* ownerOnly = */ true)
        return binary
    }

    /** Runs `linker binary arg…`, merging stderr into stdout. */
    private fun File.exec(binary: File, vararg args: String): Pair<Int, String> {
        val cmd = ArrayList<String>(2 + args.size).apply {
            add(absolutePath)
            add(binary.absolutePath)
            addAll(args)
        }
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
        return p.waitFor() to out
    }
}
