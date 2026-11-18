package org.ghost.app.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import org.ghost.ui.protect.SensitiveClipboard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.TimeUnit

/** Real Android clipboard objects and the main-looper timer, under Robolectric's SDK 35. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], application = BareTestApp::class)
class SensitiveClipboardTest {
    private class Labels : SensitiveClipboard.LabelStore {
        var value: String? = null
        override fun readLabel(): String? = value
        override fun writeLabel(label: String) { value = label }
        override fun clearLabel() { value = null }
    }

    private fun clipboard(): Pair<SensitiveClipboard, Labels> {
        val labels = Labels()
        return SensitiveClipboard(ApplicationProvider.getApplicationContext(), labels) to labels
    }

    private fun manager(): ClipboardManager =
        ApplicationProvider.getApplicationContext<android.app.Application>().getSystemService(ClipboardManager::class.java)

    @Test
    fun aSensitiveChannelLinkExpiresAfterThirtySeconds() {
        val (clipboard, labels) = clipboard()
        clipboard.copySensitive(SensitiveClipboard.CopyKind.CHANNEL_INVITE_LINK, "ghost://channel/test")
        val manager = manager()
        assertEquals("ghost://channel/test", manager.primaryClip?.getItemAt(0)?.text?.toString())
        assertTrue(requireNotNull(manager.primaryClipDescription).extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE))
        assertNotNull(labels.value)

        shadowOf(Looper.getMainLooper()).idleFor(29, TimeUnit.SECONDS)
        assertNotNull(manager.primaryClip)
        shadowOf(Looper.getMainLooper()).idleFor(1, TimeUnit.SECONDS)
        assertNull(manager.primaryClip)
        assertNull(labels.value)
    }

    @Test
    fun aFrozenTimerLeavesTheLabelForTheNextFocus() {
        val (clipboard, labels) = clipboard()
        clipboard.copySensitive(SensitiveClipboard.CopyKind.CHANNEL_INVITE_LINK, "ghost://channel/test")
        assertFalse(clipboard.clearIfLate(0, SensitiveClipboard.LATE_MS + 1, hasFocus = false))
        assertNotNull(manager().primaryClip)
        assertNotNull(labels.value)
        clipboard.clearIfOurs(hasFocus = true)
        assertNull(manager().primaryClip)
        assertNull(labels.value)
    }

    @Test
    fun aClearedOwnershipRecordCannotEraseAForeignUnlabelledClip() {
        val (clipboard, _) = clipboard()
        clipboard.copySensitive(SensitiveClipboard.CopyKind.CHANNEL_INVITE_LINK, "ghost://channel/test")
        clipboard.clearAtLockOrWipe()
        manager().setPrimaryClip(ClipData.newPlainText("another-app", "foreign"))
        clipboard.clearIfOurs(hasFocus = true)
        assertEquals("foreign", manager().primaryClip?.getItemAt(0)?.text?.toString())
    }
}
