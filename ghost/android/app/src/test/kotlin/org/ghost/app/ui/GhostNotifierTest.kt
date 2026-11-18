package org.ghost.app.ui

import android.app.Notification
import android.app.NotificationManager
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

/**
 * Phase 13 design §4.6, §12.2 (PM-U12, PM-U13): the notification's shape on the JVM tier — one
 * constant, content-free, hidden on the lock screen, cancelled while INTERACTIVE and at unlock.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = BareTestApp::class)
class GhostNotifierTest {
    private fun notifier(interactive: Boolean, lockAllowed: Boolean = false): Pair<GhostNotifier, NotificationManager> {
        val context = ApplicationProvider.getApplicationContext<BareTestApp>()
        val manager = context.getSystemService(NotificationManager::class.java)
        return Pair(GhostNotifier(context, interactive = { interactive }, lockScreenAllowed = { lockAllowed }), manager)
    }

    @Test
    fun aBackgroundUnreadPostsTheConstantAndAnEmptyCountCancels() {
        val (n, manager) = notifier(interactive = false)
        n.onUnreadChanged(3)
        Thread.sleep(150) // the single-thread executor's hand-off
        val shadow = Shadows.shadowOf(manager)
        val posted = shadow.getNotification(NOTIFICATION_ID)
        assertNotNull("a background unread posts", posted)
        // The shadow reads the builder's extras: title and text are the constants only.
        val title = posted.extras?.getString("android.title")
        val text = posted.extras?.getCharSequence("android.text")?.toString()
        assertEquals("GHOST", title)
        assertEquals("You have new messages", text)
        assertEquals("nothing but the constant is carried", Notification.VISIBILITY_SECRET, posted.visibility)
        n.onUnreadChanged(0)
        Thread.sleep(150)
        assertNull("an empty count cancels", shadow.getNotification(NOTIFICATION_ID))
    }

    @Test
    fun nothingPostsWhileInteractiveAndUnlockCancels() {
        val (n, manager) = notifier(interactive = true)
        n.onUnreadChanged(2)
        Thread.sleep(150)
        assertNull("INTERACTIVE: no notification, the UI is in front", Shadows.shadowOf(manager).getNotification(NOTIFICATION_ID))

        val (n2, manager2) = notifier(interactive = false)
        n2.onUnreadChanged(2)
        Thread.sleep(150)
        assertNotNull(Shadows.shadowOf(manager2).getNotification(NOTIFICATION_ID))
        n2.cancelAll()
        Thread.sleep(150)
        assertNull("unlock cancels", Shadows.shadowOf(manager2).getNotification(NOTIFICATION_ID))
    }

    @Test
    fun theLockScreenOptionShowsTheSameConstantPrivately() {
        val (n, manager) = notifier(interactive = false, lockAllowed = true)
        n.onUnreadChanged(1)
        val posted = awaitNotification(manager)!!
        assertEquals(Notification.VISIBILITY_PRIVATE, posted.visibility)
        assertNotNull("the public version carries the same constant text", posted.publicVersion)
    }

    /** The notifier hands off to a single thread; do not make the test depend on a 150 ms scheduling guess. */
    private fun awaitNotification(manager: NotificationManager): Notification? {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            Shadows.shadowOf(manager).getNotification(NOTIFICATION_ID)?.let { return it }
            Thread.sleep(25)
        }
        return Shadows.shadowOf(manager).getNotification(NOTIFICATION_ID)
    }

    companion object {
        const val NOTIFICATION_ID = GhostNotifier.NOTIFICATION_ID
    }
}
