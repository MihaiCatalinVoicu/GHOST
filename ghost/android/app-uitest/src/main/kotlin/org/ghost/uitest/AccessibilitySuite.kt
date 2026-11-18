package org.ghost.uitest

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.Locale
import org.ghost.ui.feature.channel.ChannelListScreen
import org.ghost.ui.feature.channel.ChannelScreen
import org.ghost.ui.feature.settings.SettingsScreen
import org.ghost.ui.feature.settings.WhoSeesWhatModel
import org.ghost.ui.feature.settings.WhoSeesWhatScreen
import org.ghost.ui.gateway.ChannelView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 13 design §9.2, §9.3, §9.4 (slice S9): the emulator accessibility floor.
 *
 *  - **Font scale 2.0:** the run block puts the device itself at `font_scale 2.0` before the
 *    suite (the yardstick §9.2 fixes is a device condition, not a composition trick), so these
 *    compositions and assertions run in the real large-text environment; the block restores
 *    the scale afterwards.
 *  - **Labels in both languages (Q9, G-U12's runtime half):** the Romanian and English resource
 *    twins exist at runtime, differ where they should, and the composed screens expose their
 *    headings as text TalkBack can reach.
 */
@RunWith(AndroidJUnit4::class)
class AccessibilitySuite {
    @get:Rule
    val compose = createComposeRule()

    private val sampleChannels = listOf(
        ChannelView(id = "01".repeat(16), name = "forum", unread = 2, passwordProtected = true),
    )

    private class FakeChannelGateway(private val rows: List<ChannelView>) : org.ghost.ui.gateway.ChannelGateway {
        override suspend fun channels() = rows
        override suspend fun posts(channelId: String) = emptyList<org.ghost.ui.gateway.ChannelPostView>()
        override suspend fun members(channelId: String) = emptyList<org.ghost.ui.gateway.ChannelMemberView>()
        override suspend fun fingerprint(channelId: String): org.ghost.ui.gateway.ChannelFingerprintView? = null
        override suspend fun removeMember(channelId: String, memberId: String) = true
        override suspend fun reveal(channelId: String, memberId: String) = true
        override suspend fun create(name: String, passwordIndices: IntArray?) = "CREATED"
        override suspend fun createInvite(channelId: String, passwordIndices: IntArray?) = org.ghost.ui.protect.SensitiveText("link")
        override suspend fun inspectInvite(link: String) = null
        override suspend fun acceptInvite(link: String, passwordIndices: IntArray?) = "PENDING"
        override suspend fun post(channelId: String, body: org.ghost.ui.protect.SensitiveText) = Unit
        override suspend fun leave(channelId: String) = Unit
        override suspend fun rejoin(channelId: String) = Unit
    }

    @Test
    fun theScreensComposeAtFontScale2() {
        compose.setContent {
            // The run block has set the device to font scale 2.0 (§9.2's yardstick). One
            // composition hosts both screens - the rule allows a single setContent per test.
            androidx.compose.foundation.layout.Column {
                ChannelListScreen(items = sampleChannels, onOpen = {}, onCreate = {})
                ChannelScreen(
                    model = org.ghost.ui.feature.channel.ChannelModel(
                        FakeChannelGateway(sampleChannels),
                        "01".repeat(16),
                    ),
                    channel = sampleChannels[0],
                    onLeft = {},
                )
            }
        }
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        compose.onNodeWithText(context.getString(org.ghost.ui.R.string.ch_list_title)).assertIsDisplayed()
        // The channel name appears twice - the list row and the detail's heading: both visible.
        compose.onAllNodesWithText("forum").assertCountEquals(2)
        compose.onNodeWithText(context.getString(org.ghost.ui.R.string.ch_detail_posts_empty)).assertExists()
    }

    @Test
    fun romanianAndEnglishTwinsExistAtRuntimeAndHeadingsSpeak() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
            .targetContext
        fun stringIn(locale: Locale, id: Int): String =
            context.createConfigurationContext(
                android.content.res.Configuration(context.resources.configuration).apply { setLocale(locale) },
            ).getString(id)

        // The two twins of a sample of constants exist, are non-empty, and differ (G-U12's runtime
        // half; the static twin check is the gate's).
        val samples = listOf(
            org.ghost.ui.R.string.ch_list_title,
            org.ghost.ui.R.string.settings_title,
            org.ghost.ui.R.string.who_title,
            org.ghost.ui.R.string.privacy_mode_high_body,
        )
        for (id in samples) {
            val en = stringIn(Locale.ENGLISH, id)
            val ro = stringIn(Locale("ro"), id)
            assertTrue("en text is not blank for $id", en.isNotBlank())
            assertTrue("ro text is not blank for $id", ro.isNotBlank())
            assertNotEquals("ro and en differ for $id", en, ro)
        }

        // The "Cine vede ce" table composes in the device locale and its title is reachable text.
        compose.setContent { WhoSeesWhatScreen(model = WhoSeesWhatModel()) }
        compose.onNodeWithText(stringIn(context.resources.configuration.locales.get(0), org.ghost.ui.R.string.who_title))
            .assertExists()

        // The reference table carries every actor of plan §4 plus the design's additions.
        assertEquals(13, WhoSeesWhatModel().rows.size)
    }
}
