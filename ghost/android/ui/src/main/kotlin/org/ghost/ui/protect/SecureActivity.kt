package org.ghost.ui.protect

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity

/**
 * Phase 13 design §4.1 (ADR-54): the one activity base of the app. Every `Activity` of the
 * production source sets extends this class (G-U1); `MainActivity` in :app is the only activity
 * and the only exported component (G-U11).
 *
 * What it does, in order:
 *  - `FLAG_SECURE` before any content call, so the window is never unprotected for a frame;
 *  - `setRecentsScreenshotEnabled(false)` on API 33+ (the recents thumbnail is a second capture
 *    surface besides the live screenshot block);
 *  - `super.onCreate(null)` — UI state never restores (T54): a new process starts at the lock
 *    screen or at home, never mid-screen with decrypted state;
 *  - autofill excluded on the decor view (§4.5: secrets never use a system field);
 *  - `ACCESSIBILITY_DATA_SENSITIVE_YES` on the decor on API 34+ (§4.3: non-tool accessibility
 *    services see no GHOST node at all);
 *  - the saved-state bundle is cleared after `super` (T54): nothing sensitive leaves the process
 *    to `system_server`.
 *
 * What it deliberately is not: no `onProvideAssist*` overrides are banned here but never written
 * (G-U1), no `setShowWhenLocked`, no picture-in-picture.
 */
abstract class SecureActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false)
        }
        super.onCreate(null)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= 34) {
            window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.clear()
    }
}
