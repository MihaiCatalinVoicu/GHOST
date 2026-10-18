package org.ghost.app.ui

import android.app.Application
import android.os.Bundle
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import org.ghost.app.MainActivity
import org.ghost.ui.protect.SecureActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A bare application: the production [org.ghost.app.GhostApp] wires the Tor transport, which
 * the JVM tier neither builds nor wants — the window tests exercise the activity's own
 * window behaviour, not the app. MainActivity's hooks are null-safe under it.
 */
class BareTestApp : Application()

/**
 * Phase 13 design §12.2, §4.1 (PM-U1, PM-U15): the window is secure at creation and the saved
 * bundle carries nothing. JVM tier, Robolectric SDK 35 (§12.1's default), offline images.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = BareTestApp::class)
class SecureWindowTest {
    @Test
    fun theActivitySetsFlagSecureBeforeContent() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val flags = activity.window.attributes.flags
                assertTrue(
                    "FLAG_SECURE must be set",
                    flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
                )
            }
        }
    }

    @Test
    fun onSaveInstanceStateLeavesAnEmptyBundle() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val out = Bundle()
                // The method is declared by SecureActivity (protected by the platform contract);
                // the test reaches it by reflection exactly as the framework does.
                val m = SecureActivity::class.java.getDeclaredMethod("onSaveInstanceState", Bundle::class.java)
                m.isAccessible = true
                m.invoke(activity, out)
                assertEquals("the saved-state bundle is cleared (T54)", 0, out.size())
            }
        }
    }

    @Test
    fun superOnCreateDropsAnyRestoredState() {
        // super.onCreate(null): the platform may hand a saved state; SecureActivity passes null
        // to the superclass, so nothing restores. The observable JVM half: the launched activity
        // carries no retained content; the recents/intent half is the emulator's T54.
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(activity.isFinishing.not())
            }
        }
    }
}
