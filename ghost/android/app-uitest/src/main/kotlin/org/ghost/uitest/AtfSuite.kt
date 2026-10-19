package org.ghost.uitest

import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.android.apps.common.testing.accessibility.framework.AccessibilityCheckResult
import com.google.android.apps.common.testing.accessibility.framework.AccessibilityCheckResultUtils
import com.google.android.apps.common.testing.accessibility.framework.integrations.espresso.AccessibilityValidator
import org.ghost.ui.feature.channel.ChannelListScreen
import org.ghost.ui.feature.channel.ChannelModel
import org.ghost.ui.feature.channel.ChannelScreen
import org.ghost.ui.gateway.ChannelGateway
import org.ghost.ui.gateway.ChannelView
import org.ghost.ui.protect.SensitiveText
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 13 design §9.2 (slice S9): Accessibility Test Framework (ADR-57 item 7) over the channel
 * journey's live semantics tree - the same node tree TalkBack walks, so this is also the
 * walkthrough's floor. Zero ATF errors is the requirement; warnings are printed, not failed
 * (contrast on unrendered pixels is a warning-grade signal; the WCAG arithmetic lives in
 * DesignTokensTest).
 */
@RunWith(AndroidJUnit4::class)
class AtfSuite {
    @get:Rule
    val compose = createComposeRule()

    private class FakeChannelGateway(private val rows: List<ChannelView>) : ChannelGateway {
        override suspend fun channels() = rows
        override suspend fun create(name: String, passwordIndices: IntArray?) = Unit
        override suspend fun createInvite(channelId: String) = SensitiveText("link")
        override suspend fun inspectInvite(link: String) = null
        override suspend fun acceptInvite(link: String, passwordIndices: IntArray?) = Unit
        override suspend fun post(channelId: String, body: SensitiveText) = Unit
        override suspend fun leave(channelId: String) = Unit
        override suspend fun rejoin(channelId: String) = Unit
    }

    @Test
    fun atfFindsNoErrorsInTheChannelJourney() {
        val channels = listOf(
            ChannelView(id = "01".repeat(16), name = "forum", unread = 2, passwordProtected = true),
        )
        compose.setContent {
            Column {
                ChannelListScreen(items = channels, onOpen = {}, onCreate = {})
                ChannelScreen(
                    model = ChannelModel(FakeChannelGateway(channels), "01".repeat(16)),
                    channel = channels[0],
                    onLeft = {},
                )
            }
        }
        compose.waitForIdle()

        // ATF 4.1's validator checks a view hierarchy; the composed screens hang under the
        // activity's decor view, whose accessibility node tree is what TalkBack walks.
        val activity = (compose as androidx.compose.ui.test.junit4.AndroidComposeTestRule<*, androidx.activity.ComponentActivity>).activity
        // ATF builds accessibility node infos, which for Compose touch the view hierarchy -
        // that is main-thread work.
        val results = java.util.ArrayList<com.google.android.apps.common.testing.accessibility.framework.AccessibilityViewCheckResult>()
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
            results.addAll(AccessibilityValidator().checkAndReturnResults(activity.window.decorView))
        }

        val errors = AccessibilityCheckResultUtils.getResultsForType(
            results,
            AccessibilityCheckResult.AccessibilityCheckResultType.ERROR,
        )
        val warnings = AccessibilityCheckResultUtils.getResultsForType(
            results,
            AccessibilityCheckResult.AccessibilityCheckResultType.WARNING,
        )
        for (w in warnings) {
            android.util.Log.i("AtfSuite", "warning: " + w.sourceCheckClass.simpleName)
        }
        assertTrue(
            "ATF errors: " + errors.joinToString { it.sourceCheckClass.simpleName + " - " + it.message },
            errors.isEmpty(),
        )
    }
}
