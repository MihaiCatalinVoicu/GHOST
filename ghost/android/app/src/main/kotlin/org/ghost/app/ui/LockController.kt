package org.ghost.app.ui

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Phase 13 design §5.1, §5.2 (ADR-55): the app lock's state machine and the PIN verifier.
 *
 * States: UNCONFIGURED (onboarding before a PIN) → UNLOCKED (PIN set, §6.2 step 3);
 * UNLOCKED → LOCKED (timeout at onStart, timeout 0 at onStop, "lock now", process start with a
 * lock configured); LOCKED → CHECKING (a PIN submitted) → UNLOCKED (match, counter reset) or
 * LOCKED, and from the fifth consecutive failure BACKOFF until `elapsedRealtime` passes the wait.
 * The session (§3.3) exists exactly in UNLOCKED and UNCONFIGURED.
 *
 * The verifier, byte level (§5.2): `tag = HMAC-SHA256(K_pin, "ghost/v1/app-pin" ‖ 0x00 ‖ salt ‖
 * digits)`, stored with the salt and the failure counter — no time column (T33). Submit commits
 * `failures + 1` BEFORE the check: a kill now keeps it (CR-6, MC-U14). The back-off is armed on
 * elapsedRealtime at each failure and in full at every process start with failures ≥ 5: a kill
 * or a reboot restarts the wait; moving the system clock changes nothing (MC-U15). The digit
 * array is zeroed after the call.
 *
 * Everything behind a small seam ([Store], [Mac]) so the JVM suite drives every transition,
 * including the illegal ones (CS-U2), with an in-memory store and a software MAC.
 */
class LockController(
    private val store: Store,
    private val mac: Mac,
    private val random: SecureRandom,
    private val clock: ElapsedClockMs,
) {
    /** The persisted record: salt and tag of the PIN, and the failure counter. */
    data class PinRecord(val salt: ByteArray, val tag: ByteArray, val failures: Int)

    /** The storage seam: ui_lock(salt, tag, failures) in production (§10). */
    interface Store {
        fun read(): PinRecord?
        fun write(record: PinRecord)
    }

    /** The MAC seam: HMAC-SHA256 over the labelled input with the Keystore key (§5.2). */
    interface Mac {
        fun tag(salt: ByteArray, digits: CharArray): ByteArray
    }

    /** The elapsed-realtime seam (SystemClock.elapsedRealtime in production). */
    fun interface ElapsedClockMs {
        fun nowMs(): Long
    }

    enum class State { UNCONFIGURED, UNLOCKED, LOCKED, CHECKING, BACKOFF }

    var state: State = State.UNCONFIGURED
        private set

    private var backoffUntilMs = 0L

    init {
        // The back-off is armed in full at every process start with failures ≥ 5 (§5.2).
        val failures = store.read()?.failures ?: 0
        if (failures >= BACKOFF_THRESHOLD) {
            state = State.BACKOFF
            backoffUntilMs = clock.nowMs() + waitSeconds(failures) * 1000L
        }
    }

    /** UNCONFIGURED → UNLOCKED: the first PIN is set (§6.2 step 3). */
    fun setPin(digits: CharArray) {
        check(state == State.UNCONFIGURED) { "setPin only from UNCONFIGURED, was $state" }
        val salt = ByteArray(16).also(random::nextBytes)
        val tag = mac.tag(salt, digits)
        store.write(PinRecord(salt, tag, failures = 0))
        clear(digits)
        state = State.UNLOCKED
    }

    /** UNLOCKED → LOCKED (timeout at onStart, "lock now", or a process start — §3.5). */
    fun lock() {
        check(state == State.UNLOCKED) { "lock only from UNLOCKED, was $state" }
        state = State.LOCKED
    }

    /** LOCKED/BACKOFF → CHECKING: a PIN submitted. */
    fun submit(digits: CharArray): SubmitOutcome {
        check(state == State.LOCKED || state == State.BACKOFF) { "submit only from LOCKED/BACKOFF, was $state" }
        if (state == State.BACKOFF) {
            check(clock.nowMs() >= backoffUntilMs) { "back-off still running" }
            state = State.LOCKED
        }
        state = State.CHECKING
        val record = store.read() ?: error("no PIN record in CHECKING")
        // (1) the failure is committed BEFORE the check: a kill now keeps it (MC-U14).
        store.write(record.copy(failures = record.failures + 1))
        // (2) the check, constant-time; the digit array is zeroed after the call.
        val ok = MessageDigest.isEqual(mac.tag(record.salt, digits), record.tag)
        clear(digits)
        return if (ok) {
            // (3) a match resets the counter and unlocks; a biometric success also resets it.
            store.write(store.read()!!.copy(failures = 0))
            state = State.UNLOCKED
            SubmitOutcome.Unlocked
        } else {
            val failures = store.read()!!.failures
            if (failures >= BACKOFF_THRESHOLD) {
                backoffUntilMs = clock.nowMs() + waitSeconds(failures) * 1000L
                state = State.BACKOFF
                SubmitOutcome.BackedOff(waitSeconds(failures))
            } else {
                state = State.LOCKED
                SubmitOutcome.Wrong(failures)
            }
        }
    }

    /** A biometric success (the convenience of §5.1) also resets the counter. */
    fun biometricSuccess() {
        check(state == State.LOCKED || state == State.BACKOFF) { "biometric only from LOCKED/BACKOFF, was $state" }
        store.read()?.let { store.write(it.copy(failures = 0)) }
        state = State.UNLOCKED
    }

    /** The remaining back-off in seconds; 0 outside BACKOFF. */
    fun backoffRemainingSeconds(): Long =
        if (state == State.BACKOFF) ((backoffUntilMs - clock.nowMs()) + 999) / 1000 else 0

    sealed interface SubmitOutcome {
        data object Unlocked : SubmitOutcome
        data class Wrong(val failures: Int) : SubmitOutcome
        data class BackedOff(val waitSeconds: Long) : SubmitOutcome
    }

    companion object {
        /** The failure count at which the back-off starts (§5.2: from the fifth failure). */
        const val BACKOFF_THRESHOLD: Int = 5

        /** wait(f) = 0 for f < 5; min(30 s · 2^(f−5), 3 600 s) for f ≥ 5 (§5.2). */
        fun waitSeconds(failures: Int): Long {
            if (failures < BACKOFF_THRESHOLD) return 0
            val shift = (failures - BACKOFF_THRESHOLD).coerceAtMost(20)
            return minOf(30L shl shift, 3600L)
        }
    }
}

private fun clear(digits: CharArray) {
    digits.fill('0')
}
