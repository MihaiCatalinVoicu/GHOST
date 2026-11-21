package org.ghost.uitest

import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.ghost.app.GhostApp
import org.ghost.app.MainActivity
import org.ghost.entitlement.api.ActivationState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real UI onboarding against staging, with the invite passed only through instrumentation args. */
@RunWith(AndroidJUnit4::class)
class PeerOnboardingSuite {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun inviteReachesActiveThroughTheRealFlow() {
        val invite = InstrumentationRegistry.getArguments().getString("invite")
            ?: throw IllegalArgumentException("missing invite")
        click("I have an invite")
        click("Continue")
        repeat(2) {
            for (digit in "24681357") click(digit.toString())
            click("Confirm")
        }
        click("Standard")
        compose.waitUntil(timeoutMillis = 10_000L) {
            runCatching { compose.onNode(hasSetTextAction()).assertExists() }.isSuccess
        }
        compose.onNode(hasSetTextAction()).performTextInput(invite)
        click("Check invitation")
        click("Activate")
        compose.waitUntil(timeoutMillis = 15_000L) {
            runCatching { compose.onNodeWithText("Your 24 words").assertExists() }.isSuccess
        }
        val app = compose.activity.application as GhostApp
        val deadline = System.currentTimeMillis() + 120_000L
        var state = app.entitlement.activationState()
        while (state == ActivationState.PENDING && System.currentTimeMillis() < deadline) {
            Thread.sleep(1_000L)
            state = app.entitlement.activationState()
        }
        assertEquals(ActivationState.ACTIVE, state)
    }

    private fun click(text: String) {
        compose.waitUntil(timeoutMillis = 10_000L) {
            runCatching { compose.onNodeWithText(text).assertExists() }.isSuccess
        }
        compose.onNodeWithText(text).performClick()
        compose.waitForIdle()
    }
}
