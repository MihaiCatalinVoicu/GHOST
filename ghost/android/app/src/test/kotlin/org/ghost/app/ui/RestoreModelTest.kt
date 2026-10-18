package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.ui.feature.restore.RestoreModel
import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.InvitePreview
import org.ghost.ui.gateway.PrivacyMode
import org.ghost.ui.gateway.RestoreResult
import org.ghost.ui.gateway.SettingsGateway
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §5.7, D36 (MC-U9's restore half; the NFR-10 clock): the restore journey's order and
 * its recorded duration — the words only after a lock and a mode, the clock from the first PIN
 * key to the home screen.
 */
class RestoreModelTest {
    private class FakeIdentity : IdentityGateway {
        var restoreResult: RestoreResult = RestoreResult.RESTORED
        val calls = ArrayList<String>()
        override suspend fun createDatabaseKey() {
            calls.add("createKey")
        }
        override suspend fun inspectInvite(text: String): InvitePreview = error("not used")
        override suspend fun activationState(): ActivationState = ActivationState.NONE
        override suspend fun activateInvite(text: String) = error("not used")
        override suspend fun activateGenesis(acknowledged: Boolean) = error("not used")
        override suspend fun restore(words: List<String>): RestoreResult {
            calls.add("restore")
            return restoreResult
        }

        override suspend fun mnemonicIndices(): IntArray = error("not used")
        override suspend fun wordList(): List<String> = error("not used")
        override suspend fun backupChallenge(count: Int, carried: List<Int>): List<Int> = error("not used")
        override suspend fun verifyBackup(indices: IntArray, positions: List<Int>, answers: List<String>): Boolean = error("not used")
        override suspend fun newPassphraseIndices(count: Int): IntArray = error("not used")
    }

    private class FakeSettings : SettingsGateway {
        var mode: PrivacyMode? = null
        override suspend fun privacyMode(): PrivacyMode = mode ?: PrivacyMode.STANDARD
        override suspend fun setPrivacyMode(mode: PrivacyMode) {
            this.mode = mode
        }

        override suspend fun notificationsEnabled(): Boolean = true
        override suspend fun setNotificationsEnabled(enabled: Boolean) {
            // no-op
        }
        override suspend fun hideFromAllServices(): Boolean = false
        override suspend fun setHideFromAllServices(enabled: Boolean) = Unit
    }

    @Test
    fun theJourneyRunsInD36sOrderAndRecordsTheClock(): Unit = runBlocking {
        var now = 1_000L
        val identity = FakeIdentity()
        val settings = FakeSettings()
        val m = RestoreModel(identity, settings) { now }
        assertEquals(RestoreModel.Step.INTRO, m.step)
        assertEquals(-1L, m.recordedDurationMs)
        m.onIntroRead()
        // The words are unreachable before the lock and the mode (D36 on the restore path too).
        assertThrows(IllegalStateException::class.java) {
            runBlocking { m.onWordsConfirmed(listOf("x")) }
        }
        m.onLockConfigured()
        now = 61_000L // the user typed the PIN twice and chose the mode
        m.onChooseMode(PrivacyMode.HIGH)
        assertEquals(PrivacyMode.HIGH, settings.mode)
        now = 145_000L // the 24 words typed and validated
        assertEquals(RestoreResult.RESTORED, m.onWordsConfirmed(List(24) { "word" }))
        assertEquals(RestoreModel.Step.NEXT_STEPS, m.step)
        now = 152_000L // "next steps" read, home reached
        m.onNextStepsRead()
        assertEquals(RestoreModel.Step.DONE, m.step)
        assertEquals(151_000L, m.recordedDurationMs)
        assertEquals(listOf("restore"), identity.calls)
    }

    @Test
    fun aRefusedMnemonicReturnsToTheWords(): Unit = runBlocking {
        val identity = FakeIdentity()
        identity.restoreResult = RestoreResult.REFUSED_MNEMONIC
        val m = RestoreModel(identity, FakeSettings())
        m.onIntroRead()
        m.onLockConfigured()
        m.onChooseMode(PrivacyMode.STANDARD)
        assertEquals(RestoreResult.REFUSED_MNEMONIC, m.onWordsConfirmed(listOf("bad")))
        assertEquals(RestoreModel.Step.WORDS, m.step)
        assertTrue("nothing recorded on a refusal beyond the attempt", identity.calls == listOf("restore"))
    }

    @Test
    fun theClockStartsAtTheFirstPinKeyNotBefore(): Unit = runBlocking {
        var now = 500L
        val m = RestoreModel(FakeIdentity(), FakeSettings()) { now }
        m.onIntroRead()
        now = 9_999L
        m.onLockConfigured() // the clock starts here
        now = 20_000L
        m.onChooseMode(PrivacyMode.STANDARD)
        m.onWordsConfirmed(List(24) { "w" })
        m.onNextStepsRead()
        assertEquals(20_000L - 9_999L, m.recordedDurationMs)
    }
}
