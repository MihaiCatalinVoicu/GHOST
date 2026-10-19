package org.ghost.ui.feature.settings

import org.ghost.ui.gateway.LockGateway

/**
 * Phase 13 design §6.8 (Securitate): the app-lock choices over [LockGateway] — the timeout of
 * §5.1 (0/60/300/1 800 seconds, Q5), the biometric convenience, and the PIN change. The "who can
 * read the screen" and keyboard rows of the same settings page are §4.3/§4.5 surfaces of their
 * own slices; this model is the lock block.
 */
class SecurityModel(private val lock: LockGateway) {
    /** The timeout in seconds: 0 locks at once, then 60 / 300 / 1 800 (Q5's four values). */
    var timeoutSeconds: Long = 60
        private set

    /** The biometric convenience's state. */
    var biometricEnabled: Boolean = false
        private set

    /** Reads the lock choices (a read, not a user action). */
    suspend fun load() {
        timeoutSeconds = lock.timeoutSeconds()
        biometricEnabled = lock.biometricEnabled()
    }

    /** Sets the lock timeout; one of 0, 60, 300 or 1 800 (Q5). */
    suspend fun onSetTimeoutSeconds(seconds: Long) {
        lock.setTimeoutSeconds(seconds)
        timeoutSeconds = seconds
    }

    /** Enables or disables the biometric convenience (§5.1: the PIN stays the one strength). */
    suspend fun onSetBiometricEnabled(enabled: Boolean) {
        lock.setBiometricEnabled(enabled)
        biometricEnabled = enabled
    }

    /** Sets a new PIN (typed twice by the user on the PinPad; §5.2's salt and tag). */
    suspend fun onSetPin(digits: CharArray) {
        lock.setPin(digits)
    }
}
