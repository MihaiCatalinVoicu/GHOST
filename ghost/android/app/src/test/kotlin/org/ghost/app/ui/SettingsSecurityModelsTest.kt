package org.ghost.app.ui

import kotlinx.coroutines.runBlocking
import org.ghost.ui.feature.settings.SecurityModel
import org.ghost.ui.feature.settings.SettingsModel
import org.ghost.ui.gateway.LockGateway
import org.ghost.ui.gateway.PinSubmitResult
import org.ghost.ui.gateway.PrivacyMode
import org.ghost.ui.gateway.SettingsGateway
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §6.8: the settings models over recording gateways — the three privacy choices and the
 * lock block (timeout, biometric, PIN) load and forward exactly one traffic call per change, and
 * the mirrors track the gateway's state.
 */
class SettingsSecurityModelsTest {
    private class RecordingSettings : SettingsGateway {
        val log = ArrayList<String>()
        var mode = PrivacyMode.STANDARD
        var notifications = true
        var hidden = false
        override suspend fun privacyMode(): PrivacyMode = mode
        override suspend fun setPrivacyMode(mode: PrivacyMode) {
            log.add("mode:$mode")
            this.mode = mode
        }
        override suspend fun notificationsEnabled(): Boolean = notifications
        override suspend fun setNotificationsEnabled(enabled: Boolean) {
            log.add("notif:$enabled")
            notifications = enabled
        }
        override suspend fun hideFromAllServices(): Boolean = hidden
        override suspend fun setHideFromAllServices(enabled: Boolean) {
            log.add("hide:$enabled")
            hidden = enabled
        }
    }

    private class RecordingLock : LockGateway {
        val log = ArrayList<String>()
        var timeout = 60L
        var biometric = false
        var pin: CharArray? = null
        override suspend fun isConfigured(): Boolean = true
        override suspend fun setPin(digits: CharArray) {
            log.add("pin")
            pin = digits
        }
        override suspend fun submitPin(digits: CharArray): PinSubmitResult = error("not used")
        override suspend fun setBiometricEnabled(enabled: Boolean) {
            log.add("bio:$enabled")
            biometric = enabled
        }
        override suspend fun biometricEnabled(): Boolean = biometric
        override suspend fun timeoutSeconds(): Long = timeout
        override suspend fun setTimeoutSeconds(seconds: Long) {
            log.add("timeout:$seconds")
            timeout = seconds
        }
    }

    @Test
    fun thePrivacyChoicesLoadAndForward(): Unit = runBlocking {
        val settings = RecordingSettings()
        val m = SettingsModel(settings)
        m.load()
        assertEquals(PrivacyMode.STANDARD, m.privacyMode)
        assertTrue(m.notificationsEnabled)
        assertTrue(!m.hideFromAllServices)

        m.onSetPrivacyMode(PrivacyMode.HIGH)
        m.onSetNotificationsEnabled(false)
        m.onSetHideFromAllServices(true)
        assertEquals(PrivacyMode.HIGH, m.privacyMode)
        assertTrue(!m.notificationsEnabled)
        assertTrue(m.hideFromAllServices)
        assertEquals(
            listOf("mode:HIGH", "notif:false", "hide:true"),
            settings.log,
        )
    }

    @Test
    fun theLockBlockLoadsAndForwards(): Unit = runBlocking {
        val lock = RecordingLock()
        val m = SecurityModel(lock)
        m.load()
        assertEquals(60L, m.timeoutSeconds)
        assertTrue(!m.biometricEnabled)

        m.onSetTimeoutSeconds(0)
        m.onSetBiometricEnabled(true)
        m.onSetPin(charArrayOf('1', '2', '3', '4'))
        assertEquals(0L, m.timeoutSeconds)
        assertTrue(m.biometricEnabled)
        assertEquals("1234", String(lock.pin!!))
        assertEquals(listOf("timeout:0", "bio:true", "pin"), lock.log)
    }
}
