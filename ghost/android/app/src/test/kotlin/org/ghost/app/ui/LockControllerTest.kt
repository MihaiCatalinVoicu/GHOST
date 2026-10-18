package org.ghost.app.ui

import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Phase 13 design §5.1, §5.2 (CS-U2, MC-U1, MC-U2, MC-U14, MC-U15): every legal and illegal
 * transition of the lock state machine, the back-off's exact waits, the kill-point ordering
 * (the failure commits before the check) and the elapsed-realtime clock (a system-clock change
 * changes nothing — the seam is never the wall clock).
 */
class LockControllerTest {
    private class MemoryStore : LockController.Store {
        var record: LockController.PinRecord? = null
        override fun read() = record
        override fun write(record: LockController.PinRecord) {
            this.record = record
        }
    }

    private class SoftwareMac : LockController.Mac {
        override fun tag(salt: ByteArray, digits: CharArray): ByteArray {
            // A deterministic stand-in: the real MAC is HMAC-SHA256 with the Keystore key (§5.2);
            // the machine's properties under test are ordering, back-off and zeroisation, which a
            // deterministic tag preserves. Equality and inequality of pins are what matter.
            val out = ByteArray(32)
            for (i in digits.indices) {
                out[i % 32] = (out[i % 32] + digits[i].code + salt[i % salt.size]).toByte()
            }
            for (i in salt.indices) out[(i + 7) % 32] = (out[(i + 7) % 32].toInt() xor salt[i].toInt()).toByte()
            return out
        }
    }

    private class FakeClock(var now: Long = 1_000_000L) : LockController.ElapsedClockMs {
        override fun nowMs() = now
    }

    private fun newController(): Triple<LockController, MemoryStore, FakeClock> {
        val store = MemoryStore()
        val clock = FakeClock()
        return Triple(LockController(store, SoftwareMac(), SecureRandom(), clock), store, clock)
    }

    @Test
    fun unconfiguredToUnlockedOnSetPin() {
        val (c, store, _) = newController()
        assertEquals(LockController.State.UNCONFIGURED, c.state)
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(LockController.State.UNLOCKED, c.state)
        assertEquals(0, store.record!!.failures)
    }

    @Test
    fun lockNowAndUnlockWithThePin() {
        val (c, _, _) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        assertEquals(LockController.State.LOCKED, c.state)
        val outcome = c.submit(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(LockController.SubmitOutcome.Unlocked, outcome)
        assertEquals(LockController.State.UNLOCKED, c.state)
    }

    @Test
    fun illegalTransitionsThrow() {
        val (c, _, _) = newController()
        // setPin from UNLOCKED.
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertThrowsIllegal { c.setPin(charArrayOf('9')) }
        // lock from LOCKED.
        c.lock()
        assertThrowsIllegal { c.lock() }
        // submit from UNLOCKED.
        c.submit(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertThrowsIllegal { c.submit(charArrayOf('1')) }
        // biometric from UNLOCKED.
        assertThrowsIllegal { c.biometricSuccess() }
    }

    @Test
    fun wrongPinCountsFailuresBeforeTheCheck() {
        val (c, store, _) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        val outcome = c.submit(charArrayOf('9', '9', '9', '9', '9', '9')) as LockController.SubmitOutcome.Wrong
        assertEquals(1, outcome.failures)
        // MC-U14: the failure is committed before the check — even though the check ran, the
        // store holds 1, and a kill at this point would still have kept it.
        assertEquals(1, store.record!!.failures)
        assertEquals(LockController.State.LOCKED, c.state)
    }

    @Test
    fun backoffFromTheFifthFailureDoublingToOneHour() {
        val (c, _, clock) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        // Failures 1..4: LOCKED again, no wait.
        for (expected in 1..4) {
            val o = c.submit(charArrayOf('9', '9', '9', '9', '9', '9'))
            assertEquals(expected, (o as LockController.SubmitOutcome.Wrong).failures)
            assertEquals(LockController.State.LOCKED, c.state)
        }
        // Failure 5: BACKOFF 30 s.
        val fifth = c.submit(charArrayOf('9', '9', '9', '9', '9', '9')) as LockController.SubmitOutcome.BackedOff
        assertEquals(30L, fifth.waitSeconds)
        assertEquals(LockController.State.BACKOFF, c.state)
        // MC-U15: the wait is on elapsedRealtime; moving the wall clock does not matter (the seam
        // IS elapsedRealtime here — advancing it 29 s is not enough).
        clock.now += 29_000
        assertTrue(c.backoffRemainingSeconds() > 0)
        assertThrowsIllegal { c.submit(charArrayOf('1', '2', '3', '4', '5', '6')) }
        clock.now += 2_000
        val o = c.submit(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(LockController.SubmitOutcome.Unlocked, o)
        assertEquals(0, c.backoffRemainingSeconds())
    }

    @Test
    fun backoffDoublingTable() {
        assertEquals(0L, LockController.waitSeconds(4))
        assertEquals(30L, LockController.waitSeconds(5))
        assertEquals(60L, LockController.waitSeconds(6))
        assertEquals(120L, LockController.waitSeconds(7))
        assertEquals(3600L, LockController.waitSeconds(12))
        assertEquals(3600L, LockController.waitSeconds(40))
    }

    @Test
    fun aProcessStartWithALockConfiguredStartsLocked() {
        val store = MemoryStore()
        val clock = FakeClock()
        val first = LockController(store, SoftwareMac(), SecureRandom(), clock)
        first.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(LockController.State.UNLOCKED, first.state)
        // A "kill and restart" with the PIN set: the new process starts LOCKED (§5.1), and a
        // submission is legal at once (MC-U20's restart half).
        val second = LockController(store, SoftwareMac(), SecureRandom(), clock)
        assertEquals(LockController.State.LOCKED, second.state)
        val outcome = second.submit(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(LockController.SubmitOutcome.Unlocked, outcome)
    }

    @Test
    fun processStartWithFailuresReArmsTheBackoffInFull() {
        val store = MemoryStore()
        val clock = FakeClock()
        val first = LockController(store, SoftwareMac(), SecureRandom(), clock)
        first.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        first.lock()
        repeat(5) { first.submit(charArrayOf('9', '9', '9', '9', '9', '9')) }
        assertEquals(LockController.State.BACKOFF, first.state)
        // A "kill and restart" mid-wait: the new instance re-arms the FULL wait (§5.2), even
        // though 29 s of the old wait had passed.
        clock.now += 29_000
        val second = LockController(store, SoftwareMac(), SecureRandom(), clock)
        assertEquals(LockController.State.BACKOFF, second.state)
        assertTrue(second.backoffRemainingSeconds() >= 29)
        assertThrowsIllegal { second.submit(charArrayOf('1', '2', '3', '4', '5', '6')) }
    }

    @Test
    fun aMatchResetsTheCounter() {
        val (c, store, _) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        repeat(3) { c.submit(charArrayOf('9', '9', '9', '9', '9', '9')) }
        assertEquals(3, store.record!!.failures)
        c.submit(charArrayOf('1', '2', '3', '4', '5', '6'))
        assertEquals(0, store.record!!.failures)
    }

    @Test
    fun biometricSuccessUnlocksAndResets() {
        val (c, store, _) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        c.submit(charArrayOf('9', '9', '9', '9', '9', '9'))
        c.biometricSuccess()
        assertEquals(LockController.State.UNLOCKED, c.state)
        assertEquals(0, store.record!!.failures)
    }

    @Test
    fun digitsArrayIsZeroedAfterSubmit() {
        val (c, _, _) = newController()
        c.setPin(charArrayOf('1', '2', '3', '4', '5', '6'))
        c.lock()
        val digits = charArrayOf('1', '2', '3', '4', '5', '6')
        c.submit(digits)
        assertTrue(digits.all { it == '0' })
    }

    private fun assertThrowsIllegal(block: () -> Unit) {
        try {
            block()
            fail("expected IllegalStateException")
        } catch (e: IllegalStateException) {
            // the expected illegal transition
        }
    }
}
