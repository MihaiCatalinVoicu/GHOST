package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.ui.feature.onboarding.OnboardingModel
import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.InvitePreview
import org.ghost.ui.gateway.PrivacyMode
import org.ghost.ui.gateway.RestoreResult
import org.ghost.ui.gateway.SettingsGateway
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 design §6.2, D36 (MC-U6, MC-U12, MC-U13; PM-U16/PM-U17's order half): the onboarding
 * order over recording gateways — the mode before the trial and the words (D36), the words never
 * before a lock exists (MC-U13), the backup check not skippable (MC-U6), every illegal jump an
 * exception, and zero traffic-causing calls outside the `on…` intents (§12.2's recording rule).
 */
class OnboardingModelTest {
    private open class RecordingIdentity : IdentityGateway {
        val calls = ArrayList<String>()
        override suspend fun createDatabaseKey() {
            calls.add("createDatabaseKey")
        }
        override suspend fun inspectInvite(text: String): InvitePreview {
            calls.add("inspectInvite")
            return InvitePreview(version = 1, expiryDay = null, refusedReason = null)
        }

        override suspend fun activationState(): ActivationState = ActivationState.NONE
        override suspend fun activateInvite(text: String): ActivateResult {
            calls.add("activateInvite")
            return ActivateResult.ACTIVATED
        }

        override suspend fun activateGenesis(acknowledged: Boolean): ActivateResult {
            calls.add("activateGenesis")
            return ActivateResult.ACTIVATED
        }

        override suspend fun restore(words: List<String>): RestoreResult {
            calls.add("restore")
            return RestoreResult.RESTORED
        }

        override suspend fun mnemonicIndices(): IntArray = IntArray(24)
        override suspend fun wordList(): List<String> = emptyList()
        override suspend fun backupChallenge(count: Int, carried: List<Int>): List<Int> = emptyList()
        override suspend fun verifyBackup(indices: IntArray, positions: List<Int>, answers: List<String>): Boolean = true
        override suspend fun newPassphraseIndices(count: Int): IntArray = IntArray(count)
    }

    private class RecordingSettings : SettingsGateway {
        val calls = ArrayList<String>()
        var mode: PrivacyMode = PrivacyMode.STANDARD
        override suspend fun privacyMode(): PrivacyMode = mode
        override suspend fun setPrivacyMode(mode: PrivacyMode) {
            calls.add("setPrivacyMode:$mode")
            this.mode = mode
        }

        override suspend fun notificationsEnabled(): Boolean = true
        override suspend fun setNotificationsEnabled(enabled: Boolean) {
            calls.add("setNotif")
        }
        override suspend fun hideFromAllServices(): Boolean = false
        override suspend fun setHideFromAllServices(enabled: Boolean) {
            calls.add("setHide")
        }
    }

    private fun model(): Pair<OnboardingModel, RecordingIdentity> {
        val identity = RecordingIdentity()
        return Pair(OnboardingModel(identity, RecordingSettings()), identity)
    }

    @Test
    fun theHappyPathRunsInD36sOrder(): Unit = runBlocking {
        val (m, identity) = model()
        assertEquals(OnboardingModel.Step.WELCOME, m.step)
        m.onWelcomeInvite()
        assertEquals(OnboardingModel.Step.PREPARE, m.step)
        m.onPrepared()
        m.onLockSet()
        m.onChooseMode(PrivacyMode.HIGH)
        // MC-U12: the mode is persisted BEFORE the invite is activated.
        m.onInviteConfirmed("ghost://invite/x")
        assertEquals(OnboardingModel.Step.WORDS, m.step)
        m.onWordsShown()
        m.onBackupVerified()
        m.onNotificationsAnswered()
        m.onDisclosuresRead()
        assertEquals(OnboardingModel.Step.DONE, m.step)
        assertEquals(listOf("activateInvite"), identity.calls)
    }

    @Test
    fun theModeIsChosenBeforeTheTrialAndCannotMoveOnWithoutIt(): Unit = runBlocking {
        val (m, identity) = model()
        m.onWelcomeInvite()
        m.onPrepared()
        m.onLockSet()
        // INVITE is unreachable until the mode is chosen (D36's amendment).
        assertThrows(IllegalStateException::class.java) {
            runBlocking { m.onInviteConfirmed("ghost://invite/x") }
        }
        assertEquals("no ACTIVATE before the mode", emptyList<String>(), identity.calls)
        m.onChooseMode(PrivacyMode.STANDARD)
        m.onInviteConfirmed("ghost://invite/x")
        assertEquals(OnboardingModel.Step.WORDS, m.step)
    }

    @Test
    fun theWordsNeverShowBeforeALockExists(): Unit = runBlocking {
        val (m, _) = model()
        assertFalse(m.wordsAllowed())
        assertThrows(IllegalStateException::class.java) { m.onWordsShown() }
        m.onWelcomeInvite()
        m.onPrepared()
        assertThrows(IllegalStateException::class.java) { m.onWordsShown() }
    }

    @Test
    fun theBackupCheckIsNotSkippable(): Unit = runBlocking {
        val (m, _) = model()
        m.onWelcomeInvite()
        m.onPrepared()
        m.onLockSet()
        m.onChooseMode(PrivacyMode.STANDARD)
        m.onInviteConfirmed("ghost://invite/x")
        m.onWordsShown()
        // MC-U6: notifications and disclosures stay closed until the check passes.
        assertThrows(IllegalStateException::class.java) { m.onNotificationsAnswered() }
        m.onBackupVerified()
        m.onNotificationsAnswered()
        m.onDisclosuresRead()
        assertEquals(OnboardingModel.Step.DONE, m.step)
    }

    @Test
    fun aRefusedInviteReturnsToTheInviteStep() = runBlocking {
        val (m, _) = model()
        m.onWelcomeInvite()
        m.onPrepared()
        m.onLockSet()
        m.onChooseMode(PrivacyMode.STANDARD)
        val identity = object : RecordingIdentity() {
            override suspend fun activateInvite(text: String): ActivateResult = ActivateResult.REFUSED
        }
        val m2 = OnboardingModel(identity, RecordingSettings())
        m2.onWelcomeInvite()
        m2.onPrepared()
        m2.onLockSet()
        m2.onChooseMode(PrivacyMode.STANDARD)
        assertEquals(ActivateResult.REFUSED, m2.onInviteConfirmed("ghost://invite/bad"))
        assertEquals(OnboardingModel.Step.INVITE, m2.step)
    }

    @Test
    fun inspectionIsLocalAndCausesNoTraffic() = runBlocking {
        val (m, identity) = model()
        m.onWelcomeInvite()
        m.onPrepared()
        m.onLockSet()
        m.onChooseMode(PrivacyMode.STANDARD)
        val preview = m.onInviteInspect("ghost://invite/x")
        assertEquals(1, preview.version)
        assertEquals(listOf("inspectInvite"), identity.calls)
        assertTrue("inspect is local; ACTIVATE has not run", "activateInvite" !in identity.calls)
    }
}
