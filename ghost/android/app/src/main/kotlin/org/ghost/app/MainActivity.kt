package org.ghost.app

import android.os.Bundle
import androidx.activity.compose.setContent
import org.ghost.ui.shell.DemoScreen
import org.ghost.ui.shell.GhostRoot
import org.ghost.ui.protect.SecureActivity

/**
 * Phase 13 design §3.1, §3.4, §4.1: the single activity of the app. `MainActivity` is the only
 * activity and the only exported component (G-U11): `singleTask` and `persistableMode=
 * "persistNever"` keep a launching link out of the persisted task record (D7), and the `ghost`
 * scheme filters accept only the `invite`, `contact` and `channel` hosts (§3.4). The window
 * protection (FLAG_SECURE, recents thumbnail off, autofill excluded, accessibility-data
 * sensitive, no saved state) lives in [SecureActivity].
 *
 * Link intake (§3.4) and the lock wiring (§3.5) land with S1's shell; until then the demo
 * screen shows only build-stage copy (CP-10).
 */
class MainActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            GhostRoot(clipboardOwner = null) {
                DemoScreen()
            }
        }
    }
}
