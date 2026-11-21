package org.ghost.uitest

import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.ghost.ui.R
import org.ghost.ui.design.HoldToConfirm
import org.ghost.ui.feature.channel.ChannelListScreen
import org.ghost.ui.feature.channel.ChannelModel
import org.ghost.ui.feature.channel.ChannelScreen
import org.ghost.ui.feature.settings.SettingsScreen
import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelMemberView
import org.ghost.ui.gateway.ChannelPostView
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.protect.SensitiveText
import org.ghost.ui.shell.GhostTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Locale

/**
 * Local visual snapshots drawn from the real Compose view tree. FLAG_SECURE stays intact: this is
 * not a screen capture and runs only in the test APK. Files go to the test app's external cache.
 */
@RunWith(AndroidJUnit4::class)
class VisualSnapshotSuite {
    @get:Rule
    val compose = createComposeRule()

    private class FakeChannels : ChannelGateway {
        override suspend fun channels() = emptyList<ChannelView>()
        override suspend fun posts(channelId: String) = emptyList<ChannelPostView>()
        override suspend fun members(channelId: String) = emptyList<ChannelMemberView>()
        override suspend fun fingerprint(channelId: String) = null
        override suspend fun removeMember(channelId: String, memberId: String) = true
        override suspend fun reveal(channelId: String, memberId: String) = true
        override suspend fun create(name: String, passwordIndices: IntArray?) = "CREATED"
        override suspend fun createInvite(channelId: String, passwordIndices: IntArray?) = SensitiveText("link")
        override suspend fun inspectInvite(link: String) = null
        override suspend fun acceptInvite(link: String, passwordIndices: IntArray?) = "PENDING"
        override suspend fun post(channelId: String, body: SensitiveText) = Unit
        override suspend fun leave(channelId: String) = Unit
        override suspend fun rejoin(channelId: String) = Unit
    }

    @Test
    fun captureChannelList() {
        val rows = listOf(
            ChannelView("01".repeat(16), "Design review", 2, false),
            ChannelView("02".repeat(16), "Private research", 0, true),
        )
        compose.setContent { GhostTheme { ChannelListScreen(rows, onOpen = {}, onCreate = {}, onJoin = {}) } }
        capture("channels-after")
    }

    @Test
    fun captureChannelDetail() {
        val channel = ChannelView("01".repeat(16), "Design review", 2, false)
        val posts = listOf(
            ChannelPostView("01", SensitiveText("The latest build is ready for review."), false, 1, "sent", 1),
            ChannelPostView("02", SensitiveText("Looks good. Checking media next."), true, 2, "sent", 1),
        )
        compose.setContent {
            GhostTheme {
                ChannelScreen(
                    model = ChannelModel(FakeChannels(), channel.id),
                    channel = channel,
                    posts = posts,
                    onInvite = {},
                    onMembers = {},
                    onLeft = {},
                )
            }
        }
        capture("channel-after")
    }

    @Test
    fun captureEmptyChannels() {
        compose.setContent {
            GhostTheme { ChannelListScreen(emptyList(), onOpen = {}, onCreate = {}, onJoin = {}) }
        }
        capture("channels-empty")
    }

    @Test
    fun captureLongPost() {
        val channel = ChannelView("01".repeat(16), "Research notes", 0, false)
        val body = "A deliberately long post used to verify wrapping and spacing. ".repeat(8)
        val posts = listOf(ChannelPostView("03", SensitiveText(body), false, 3, "sent", 1))
        compose.setContent {
            GhostTheme {
                ChannelScreen(
                    model = ChannelModel(FakeChannels(), channel.id), channel = channel, posts = posts,
                    onInvite = {}, onMembers = {}, onLeft = {},
                )
            }
        }
        capture("channel-long")
    }

    @Test
    fun captureSettings() {
        compose.setContent {
            GhostTheme {
                Column {
                    SettingsScreen(
                        onAccess = {}, onPrivacy = {}, onSecurity = {}, onAbout = {},
                        onUpdate = {}, onHelp = {}, onWipe = {},
                    )
                }
            }
        }
        capture("settings-after")
    }

    @Test
    fun englishIsForcedBelowARomanianContext() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val romanian = Configuration(context.resources.configuration).apply { setLocale(Locale("ro")) }
        val romanianContext = context.createConfigurationContext(romanian)
        compose.setContent {
            CompositionLocalProvider(
                LocalConfiguration provides romanian,
                LocalContext provides romanianContext,
            ) {
                GhostTheme { ChannelListScreen(emptyList(), onOpen = {}, onCreate = {}) }
            }
        }
        compose.onNodeWithText("Channels").assertExists()
        compose.onNodeWithText("Canale").assertDoesNotExist()
    }

    @Test
    fun holdAndAlternativeDoNotOverlap() {
        compose.setContent {
            GhostTheme {
                HoldToConfirm(
                    onConfirmed = {},
                    holdLabelId = R.string.ch_detail_leave_hold,
                    alternativeLabelId = R.string.confirm_alternative,
                )
            }
        }
        val hold = compose.onNodeWithText("Hold to leave the channel").fetchSemanticsNode().boundsInRoot
        val alternative = compose.onNodeWithText("Another way to confirm").fetchSemanticsNode().boundsInRoot
        assertTrue("confirmation labels overlap", hold.bottom <= alternative.top)
    }

    @Test
    fun joiningChannelHasVisibleState() {
        val joining = ChannelView("04".repeat(16), "", 0, false)
        compose.setContent {
            GhostTheme { ChannelListScreen(listOf(joining), onOpen = {}, onCreate = {}) }
        }
        compose.onNodeWithText("Joining channel…").assertExists()
    }

    private fun capture(name: String) {
        compose.waitForIdle()
        @Suppress("UNCHECKED_CAST")
        val activity = (compose as AndroidComposeTestRule<*, ComponentActivity>).activity
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            val view = activity.window.decorView
            val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
            view.draw(Canvas(bitmap))
            val directory = File(instrumentation.targetContext.cacheDir, "visual").apply { mkdirs() }
            val output = File(directory, "$name.png")
            output.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            assertTrue("the rendered snapshot is not empty", output.length() > 1_000L)
        }
    }
}
