package org.ghost.app

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.compose.setContent
import org.ghost.app.ui.ContentLock
import org.ghost.app.ui.LinkIntake
import org.ghost.ui.shell.DemoScreen
import org.ghost.ui.shell.GhostRoot
import org.ghost.ui.protect.SecureActivity

/**
 * Phase 13 design §3.1, §3.4, §3.5, §4.1: the single activity of the app. `singleTask` and
 * `persistableMode="persistNever"` keep a launching link out of the persisted task record (D7),
 * and the `ghost` scheme filters accept only the `invite`, `contact` and `channel` hosts (§3.4).
 * The window protection (FLAG_SECURE, recents thumbnail off, autofill excluded,
 * accessibility-data sensitive, no saved state) lives in [SecureActivity].
 *
 * Lifecycle (§3.5): ON_START reports the window and runs the lock check (a hide longer than the
 * timeout locks before the next frame); onResume/onPause drive INTERACTIVE together with the
 * lock state, so the foreground session starts only at unlock, never under the lock screen
 * (D33, X-U14). Every non-configuration onStop runs the hide duties of §3.3 ([ContentLock]) —
 * screen models drop their state, media handles close, the payment screen hides — whether or
 * not the timeout will lock at the return. Link intake (§3.4) reads a `ghost://` link once here
 * and holds it in memory until the post-unlock confirmation screen acts on it (S2).
 */
class MainActivity : SecureActivity() {
    private var hiddenAtMs: Long = 0

    /** The app; null only under a test application that wires nothing. */
    private val app: GhostApp? get() = application as? GhostApp

    /**
     * The Q5 lock-timeout setting, read from the `ui_settings` row. The read is a single indexed
     * SQLite lookup; §3.5 wants the lock decision before the next frame, so it happens here on the
     * main thread rather than through the `ghost-ui-io` dispatcher (the adapters keep that path
     * for the settings screen). While no database exists the store answers the migration default
     * (60 s), matching the previous hardcoded behaviour.
     */
    private val settingsStore: org.ghost.app.ui.SettingsStore? by lazy {
        app?.let { org.ghost.app.ui.SettingsStore { it.openDatabaseDirectly() } }
    }

    @androidx.media3.common.util.UnstableApi
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        LinkIntake.take(this)
        setContent {
            val app = this.app ?: return@setContent
            val configuration = androidx.compose.ui.platform.LocalConfiguration.current
            val windowSizeClass = androidx.window.core.layout.WindowSizeClass.compute(
                configuration.screenWidthDp.toFloat(),
                configuration.screenHeightDp.toFloat(),
            )
            org.ghost.ui.shell.GhostRoot(
                clipboardOwner = androidx.compose.runtime.remember { app.clipboardOwner },
            ) {
                org.ghost.app.ui.AppNav(app, windowSizeClass)
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        LinkIntake.take(this)
    }

    override fun onStart() {
        super.onStart()
        val app = this.app ?: return
        app.presence.onWindowShown()
        // §3.5: a hide at least as long as the timeout locks before the next frame (a Compose
        // state change made here is applied before the frame that follows). Q5's choice applies
        // (0 locks at onStop, as before the S2 wiring); the store answers 60 s until the database
        // exists, matching the pre-wiring behaviour.
        val timeoutMs = (settingsStore?.lockTimeoutSeconds() ?: 60L) * 1_000L
        if (hiddenAtMs != 0L && SystemClock.elapsedRealtime() - hiddenAtMs >= timeoutMs) {
            app.onLock()
        }
    }

    override fun onResume() {
        super.onResume()
        app?.clipboardOwner?.clearAtFocus()
        app?.presence?.onResumed()
    }

    override fun onPause() {
        app?.presence?.onPaused()
        super.onPause()
    }

    override fun onStop() {
        // §3.3's hide duties run at every hide that is not a configuration change: content state
        // drops now, not when the timeout decides to lock.
        ContentLock.lockContent()
        app?.presence?.onWindowHidden()
        hiddenAtMs = SystemClock.elapsedRealtime()
        super.onStop()
    }
}
