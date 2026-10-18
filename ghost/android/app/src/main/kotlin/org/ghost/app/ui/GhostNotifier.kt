package org.ghost.app.ui

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import org.ghost.messaging.api.NotificationPort

/**
 * Phase 13 design §4.6 (T11, Q7): the one constant notification. `onUnreadChanged(count)` posts
 * or cancels from a single-thread executor, never on the actor thread; nothing is posted while
 * the app is INTERACTIVE (the UI's presence tells us), and an unlock cancels.
 *
 * The shape §4.6 fixes, and this file never leaves: one channel (`ghost_messages_v1`, DEFAULT
 * importance, `setShowBadge(false)`, lock-screen SECRET set before creation); title and text
 * only from the allowlisted resource ids (`notif_title`, `notif_new`, `notif_new_count` — G-U10
 * pins exactly these); `VISIBILITY_SECRET` by default (with `VISIBILITY_PRIVATE` + the same
 * constant public version when the user opts into lock-screen display); `setLocalOnly(true)`,
 * `setOnlyAlertOnce(true)`, `setAutoCancel(true)`; the tap is an immutable PendingIntent without
 * extras. Never: MessagingStyle, BigTextStyle, InboxStyle, BigPictureStyle, RemoteInput,
 * actions, `setNumber`, Person, large icons, shortcuts, bubbles, conversation categories,
 * `VISIBILITY_PUBLIC`. A pending key change is never a notification (X-U17's in-app banner).
 */
class GhostNotifier(
    private val context: Context,
    private val interactive: () -> Boolean,
    private val lockScreenAllowed: () -> Boolean,
) : NotificationPort {
    private val executor = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "ghost-notify") }
    private val manager: NotificationManager get() = context.getSystemService(NotificationManager::class.java)

    init {
        // The channel record is created once per process start; visibility is set BEFORE creation
        // (V-U15 measures the per-level effect).
        val channel = NotificationChannel(CHANNEL_ID, context.getString(org.ghost.app.R.string.notif_title), NotificationManager.IMPORTANCE_DEFAULT)
        channel.setShowBadge(false)
        channel.lockscreenVisibility = Notification.VISIBILITY_SECRET
        manager.createNotificationChannel(channel)
    }

    override fun onUnreadChanged(count: Int) {
        executor.execute { postOrCancel(count) }
    }

    /** An unlock cancels whatever the background left (§4.6). */
    fun onUnlock() {
        executor.execute { manager.cancel(NOTIFICATION_ID) }
    }

    private fun postOrCancel(count: Int) {
        if (count <= 0 || interactive()) {
            manager.cancel(NOTIFICATION_ID)
            return
        }
        val builder = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(context.getString(org.ghost.app.R.string.notif_title))
            .setContentText(if (withCount()) context.resources.getQuantityString(org.ghost.app.R.plurals.notif_new_count, count, count) else context.getString(org.ghost.app.R.string.notif_new))
            .setVisibility(
                if (lockScreenAllowed()) Notification.VISIBILITY_PRIVATE else Notification.VISIBILITY_SECRET,
            )
            .setPublicVersion(Notification.Builder(context, CHANNEL_ID).setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(context.getString(org.ghost.app.R.string.notif_title)).setContentText(context.getString(org.ghost.app.R.string.notif_new)).build())
            .setLocalOnly(true)
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    context,
                    0,
                    Intent(context, org.ghost.app.MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                ),
            )
        manager.notify(NOTIFICATION_ID, builder.build())
    }

    /** The count option of Q7 (default off): the plural line, still nothing else. */
    private fun withCount(): Boolean = org.ghost.app.ui.GhostNotifier.countOption

    companion object {
        const val CHANNEL_ID = "ghost_messages_v1"
        const val NOTIFICATION_ID = 1

        /** Q7's option, read from Settings by the wiring; false is the shipped default. */
        @Volatile
        var countOption: Boolean = false
    }
}
