package org.ghost.uitest

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.ghost.app.MainActivity
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Cold restart of the already activated peer: PIN unlock and real home navigation. */
@RunWith(AndroidJUnit4::class)
class PeerResumeSuite {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun activatedPeerUnlocksAndOpensChannels() {
        for (digit in "24681357") click(digit.toString())
        click("Confirm")
        click("Channels")
        compose.onAllNodesWithText("Channels").assertCountEquals(2)
        captureLiveChannels()
    }

    private fun click(text: String) {
        compose.waitUntil(timeoutMillis = 15_000L) {
            runCatching { compose.onNodeWithText(text).assertExists() }.isSuccess
        }
        compose.onNodeWithText(text).performClick()
        compose.waitForIdle()
    }

    private fun captureLiveChannels() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            val view = compose.activity.window.decorView
            val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
            view.draw(Canvas(bitmap))
            val directory = File(instrumentation.targetContext.cacheDir, "visual").apply { mkdirs() }
            File(directory, "peer-live-channels.png").outputStream().use {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
            }
        }
    }
}
