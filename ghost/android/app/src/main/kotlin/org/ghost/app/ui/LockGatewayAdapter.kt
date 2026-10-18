package org.ghost.app.ui

import java.security.SecureRandom
import kotlinx.coroutines.withContext
import org.ghost.ui.gateway.LockGateway
import org.ghost.ui.gateway.PinSubmitResult

/**
 * Phase 13 design §3.2, §5.1, §5.2: the production [LockGateway] — the [LockController] state
 * machine over the [LockStore] record and the [KeystorePinMac] verifier, with the biometric
 * convenience and the timeout in [SettingsStore]. All facade-touching calls run on
 * `ghost-ui-io` (CS-U6 asserts the thread); the controller itself is main-memory state.
 *
 * Adapters never cache a facade across a database reopen; this adapter holds only the
 * process-lifetime controller, whose record seam reads through [executor] each time.
 */
class LockGatewayAdapter(
    private val controller: LockController,
    private val settings: SettingsStore,
    private val clock: () -> Long,
) : LockGateway {
    constructor(
        executor: () -> org.ghost.storage.SqlExecutor?,
        strongBox: Boolean,
        settings: SettingsStore,
    ) : this(
        controller = LockController(
            store = LockStore(executor),
            mac = KeystorePinMac(strongBox),
            random = SecureRandom(),
            clock = LockController.ElapsedClockMs { android.os.SystemClock.elapsedRealtime() },
        ),
        settings = settings,
        clock = { android.os.SystemClock.elapsedRealtime() },
    )

    override suspend fun isConfigured(): Boolean = onIo { controller.state != LockController.State.UNCONFIGURED }

    override suspend fun setPin(digits: CharArray): Unit = onIo {
        controller.setPin(digits)
    }

    override suspend fun submitPin(digits: CharArray): PinSubmitResult = onIo {
        when (val outcome = controller.submit(digits)) {
            is LockController.SubmitOutcome.Unlocked -> PinSubmitResult.Unlocked
            is LockController.SubmitOutcome.Wrong -> PinSubmitResult.Locked(
                failures = outcome.failures,
                waitSeconds = 0,
            )
            is LockController.SubmitOutcome.BackedOff -> PinSubmitResult.Locked(
                failures = -1,
                waitSeconds = outcome.waitSeconds,
            )
        }
    }

    override suspend fun setBiometricEnabled(enabled: Boolean): Unit = onIo {
        settings.setBiometricEnabled(enabled)
    }

    override suspend fun biometricEnabled(): Boolean = onIo { settings.biometricEnabled() }

    override suspend fun timeoutSeconds(): Long = onIo { settings.lockTimeoutSeconds() }

    override suspend fun setTimeoutSeconds(seconds: Long): Unit = onIo {
        settings.setLockTimeoutSeconds(seconds)
    }

    /** The remaining back-off for the lock screen's countdown; 0 outside BACKOFF. */
    fun backoffRemainingSeconds(): Long = controller.backoffRemainingSeconds()

    fun state(): LockController.State = controller.state

    /** Locks now ("Blochează acum", §5.1); the activity then shows the curtain. */
    fun lockNow() = controller.lock()

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
