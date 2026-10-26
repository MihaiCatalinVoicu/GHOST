package org.ghost.app

/**
 * T15m / X-D8 (Faza 14 design §7.7): the one installer-status receiver. Not exported and
 * without an intent filter: only the app's own explicit PendingIntent (created in GhostApp's
 * install session) reaches it. The platform's own UI carries the install progress and
 * confirmation; the app keeps no state here and logs nothing (G-D1) — the update facts reset
 * on the next run of the new version, whose embedded root takes over (§7.4 step 0).
 */
class UpdateInstallReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: android.content.Context, intent: android.content.Intent) = Unit
}
