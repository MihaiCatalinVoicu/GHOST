package org.ghost.uitest

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 13 design Appendix B.2, T20's emulator half: the sandbox inventory after a launch, against
 * the fresh-install baseline the invariant declares - the app writes nothing outside SQLCipher,
 * the declared Arti state directory, and empty directories. (The wipe half and the
 * jobscheduler/alarm/notification dumps complete T20 on the device checklist; the file floor is
 * what this suite pins.)
 */
@RunWith(AndroidJUnit4::class)
class InventorySuite {
    /** A file the app is allowed to keep, by path relative to the app home. */
    private val allowed = listOf(
        Regex("""^tor(/.*)?$"""),            // Arti's own state directory (T20's declared exception)
        Regex("""^app_ghost\.db(-\w+)?$"""), // the SQLCipher database, its WAL and SHM
    )

    private fun home(c: android.content.Context): File = c.dataDir

    private fun relativeFiles(root: File, c: android.content.Context): List<String> {
        val home = home(c)
        val out = ArrayList<String>()
        fun walk(f: File) {
            val rel = f.relativeTo(home).path.replace('\\', '/')
            if (f.isFile) out.add(rel)
            f.listFiles()?.forEach { walk(it) }
        }
        root.listFiles()?.forEach { walk(it) }
        return out
    }

    @Test
    fun theSandboxHoldsOnlyTheDeclaredFilesAfterALaunch() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        // Run the app once: MainActivity's lifecycle is the most a fresh install sees without an
        // unlock (§3.5: no foreground session starts at the lock).
        ActivityScenario.launch(org.ghost.app.MainActivity::class.java).use { scenario ->
            scenario.onActivity { }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        }

        val files = relativeFiles(target.dataDir, target)
        val offenders = files.filter { f -> allowed.none { it.matches(f) } }
        assertTrue(
            "unexpected files in the sandbox: $offenders (declared: $files)",
            offenders.isEmpty(),
        )

        // No SharedPreferences, ever (T54's register names the store).
        val prefs = File(target.dataDir, "shared_prefs")
        assertTrue(
            "shared_prefs must not exist or be empty: ${prefs.list()?.toList()}",
            !prefs.exists() || prefs.list().isNullOrEmpty(),
        )
    }
}
