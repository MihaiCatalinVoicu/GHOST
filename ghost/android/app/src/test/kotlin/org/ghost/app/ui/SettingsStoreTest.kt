package org.ghost.app.ui

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.ui.gateway.PrivacyMode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 design §10: the typed settings row — the §10 defaults, every setter round trip, the
 * CHECK domains refusing what the design forbids, and the §4.4 clip label's exact shape.
 */
class SettingsStoreTest {
    private fun store(): Pair<SettingsStore, JdbcSqlExecutor> {
        val db = JdbcSqlExecutor()
        MigrationRunner(db).migrate()
        return Pair(SettingsStore({ db }), db)
    }

    @Test
    fun theDefaultsAreTheMigrationRow() {
        val (s, _) = store()
        assertEquals(PrivacyMode.STANDARD, s.privacyMode())
        assertEquals(60L, s.lockTimeoutSeconds())
        assertFalse(s.biometricEnabled())
        assertEquals(1, s.notificationMode())
        assertFalse(s.notificationLockScreen())
        assertFalse(s.hideFromAllServices())
        assertEquals(0, s.onboardingStep())
        assertFalse(s.backupVerified())
        assertFalse(s.imeWarned())
        assertEquals(0, s.disclosuresVersion())
        assertNull(s.clipLabel())
    }

    @Test
    fun settersRoundTripThroughTheRow() {
        val (s, _) = store()
        s.setPrivacyMode(PrivacyMode.HIGH)
        s.setLockTimeoutSeconds(300)
        s.setBiometricEnabled(true)
        s.setNotificationMode(0)
        s.setNotificationLockScreen(true)
        s.setHideFromAllServices(true)
        s.setOnboardingStep(7)
        s.setBackupVerified(true)
        s.setImeWarned(true)
        s.setDisclosuresVersion(3)
        assertEquals(PrivacyMode.HIGH, s.privacyMode())
        assertEquals(300L, s.lockTimeoutSeconds())
        assertTrue(s.biometricEnabled())
        assertEquals(0, s.notificationMode())
        assertTrue(s.notificationLockScreen())
        assertTrue(s.hideFromAllServices())
        assertEquals(7, s.onboardingStep())
        assertTrue(s.backupVerified())
        assertTrue(s.imeWarned())
        assertEquals(3, s.disclosuresVersion())
    }

    @Test
    fun theCheckDomainsRefuseWhatTheDesignForbids() {
        val (s, _) = store()
        assertThrows(Exception::class.java) { s.setLockTimeoutSeconds(90) }
        assertThrows(Exception::class.java) { s.setNotificationMode(3) }
        assertThrows(Exception::class.java) { s.setOnboardingStep(12) }
        assertThrows(Exception::class.java) { s.setDisclosuresVersion(-1) }
        // The refused writes left the row untouched.
        assertEquals(60L, s.lockTimeoutSeconds())
        assertEquals(1, s.notificationMode())
    }

    @Test
    fun theClipLabelIsExactlyEightBytesAndClears() {
        val (s, _) = store()
        assertThrows(IllegalArgumentException::class.java) { s.setClipLabel(ByteArray(4)) }
        val token = ByteArray(8) { it.toByte() }
        s.setClipLabel(token)
        assertArrayEquals(token, s.clipLabel())
        s.clearClipLabel()
        assertNull(s.clipLabel())
    }

    @Test
    fun withoutADatabaseEveryReadAnswersTheDefault() {
        val s = SettingsStore({ null })
        assertEquals(PrivacyMode.STANDARD, s.privacyMode())
        assertEquals(60L, s.lockTimeoutSeconds())
        assertNull(s.clipLabel())
    }
}
