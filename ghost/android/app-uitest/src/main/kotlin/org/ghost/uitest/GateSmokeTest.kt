package org.ghost.uitest

import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 13 design §12.1, §14.1 S1b: the smoke test the emulator suites hang on. It proves the
 * gate variant installs and its process answers: the package under test is the one the
 * instrumentation targeted, and a launcher intent resolves to the single activity (G-U11's
 * manifest contract in the installed APK, read from outside the app).
 */
@RunWith(AndroidJUnit4::class)
class GateSmokeTest {
    @Test
    fun theTargetPackageIsInstalledAndItsLauncherResolves() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val target = instrumentation.targetContext
        val pm = target.packageManager

        // The instrumentation's target is the app we meant to test (the gate variant).
        assertEquals(
            "the test must run in :app's gate process",
            "org.ghost.app.gate",
            target.packageName,
        )

        val launch = pm.getLaunchIntentForPackage(target.packageName)
        assertTrue("the single activity must resolve from a launcher intent", launch != null)
        launch!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        target.startActivity(launch)
        instrumentation.waitForIdleSync()
    }

    @Test
    fun theDeviceReportsItsLevelForTheReport() {
        // Every ui-emulator report names the level it ran on (ui-emulator-check.sh refuses
        // another level); this value lands in the suite's device header.
        val sdk = android.os.Build.VERSION.SDK_INT
        assertTrue("an API level, at least minSdk", sdk >= 29)
        ApplicationProvider.getApplicationContext<android.app.Application>()
    }
}
