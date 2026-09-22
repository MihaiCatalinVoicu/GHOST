package org.ghost.messaging.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * The receiver of the one inexact alarm (Phase 9 design §10.7 item 5, §13.1 `…messaging.android`,
 * §21.10 point 7).
 *
 * > on an explicit, **non-exported** `ExpiryAlarmReceiver` through `FLAG_IMMUTABLE`, one fixed
 * > request code, no extras, no new permission; cancelled when nothing is pending and at wipe; the
 * > receiver calls `goAsync()`, posts a sweep to the actor and finishes.
 *
 * **`android:exported="false"` is the manifest's**, and the manifest entry belongs to `:app`
 * (slice S12, §13.7 "Wiring"): a library manifest cannot declare a receiver without declaring an
 * `<application>`, and T15's `manifest-lint.sh` requires an `<application>` in any manifest that
 * has one to carry `allowBackup`, `dataExtractionRules`, `fullBackupContent` and
 * `networkSecurityConfig` — which are the *app's* facts and not a library's. What guards the gap
 * until then is that nothing can reach this class: the intent is explicit and immutable, the
 * pending intent is the app's own, and T15 refuses a second exported component outright (the app
 * has exactly one, the launcher).
 *
 * **It does no work itself.** `onReceive` runs on the main thread with a ~10-second budget, and a
 * SWEEP is a transaction over a SQLCipher database; more importantly, §7.9's value-state rule says
 * the DM actor is the only thread that may hold a DM transaction. So the receiver takes
 * `goAsync()`, hands the wake to [onAlarm] — which posts to the actor **without waiting** — and
 * finishes immediately. A pass that is still running when the process is frozen resumes at the
 * next trigger; SWEEP deletes by time and is idempotent against re-execution (§7.2).
 *
 * **The action is checked** although the intent is explicit. It costs nothing, and it is what
 * makes the receiver's behaviour independent of the manifest being right: a broadcast that is not
 * the alarm does nothing at all.
 */
class ExpiryAlarmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ExpiryAlarmSpec.ACTION) return
        val pending = goAsync()
        try {
            onAlarm?.invoke()
        } finally {
            pending.finish()
        }
    }

    companion object {
        /**
         * The hand-off to the DM actor, set once by `MessagingWiring` (slice S12) and cleared at
         * wipe.
         *
         * It is a static slot rather than a constructor argument because the system instantiates a
         * `BroadcastReceiver` with its no-argument constructor; the same shape `:sync`'s
         * `SyncJobService` reaches its runtime through. The lambda must **post** and return, never
         * block: see the class note.
         */
        @Volatile
        @JvmStatic
        var onAlarm: (() -> Unit)? = null
    }
}
