package org.ghost.messaging.android

import android.app.AlarmManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

/**
 * **The alarm contract** of Phase 9 design §10.7 item 5 and §21.10 point 7, which §15.5's EP suite
 * names as "the alarm contract (non-exported receiver, no extras, one request code, cancel at
 * wipe)".
 *
 * > `setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + (next − now),
 * > pendingIntent)`; a unit test checks the computed trigger time.
 *
 * Every clause that can be checked without a device is checked here, because on the JVM
 * `AlarmManager` is a stub that throws and an emulator run is S12's (`dm-emulator.yml`). What is
 * **not** here, and is recorded rather than implied: `android:exported="false"` lives in the
 * manifest, and the manifest entry is `:app`'s (§13.7 "Wiring"), so the merged-manifest gate
 * T15m is what will check it — a library manifest cannot declare a receiver without declaring an
 * `<application>`, and `manifest-lint.sh` requires an `<application>` that has one to carry the
 * app's backup and network-security facts.
 */
class ExpiryAlarmSpecTest {

    private val minute = 60L

    /** The wall-clock minute a row becomes due, and the two clocks it is converted between. */
    private val nextMinute = 1_800_003_600L
    private val now = 1_800_000_000L
    private val elapsed = 12_345_678L

    @Test
    fun theComputedTriggerTimeIsTheDelayOnTheElapsedRealtimeClock() {
        val spec = ExpiryAlarmSpec.wanted(nextMinute, now, elapsed)
        assertEquals(
            "SystemClock.elapsedRealtime() + (next - now), in milliseconds",
            elapsed + 3_600_000L,
            spec.triggerElapsedMillis,
        )
        assertEquals(
            "a wall clock cannot move it: the alarm is on the monotonic clock",
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            spec.clockType,
        )
    }

    /**
     * A deadline already past clamps to "now" rather than going negative: an alarm in the past is
     * refused or fired at once depending on the API level, and "at once" is what is wanted — the
     * sweep that follows is idempotent and deletes by time.
     */
    @Test
    fun aDeadlineAlreadyPastIsAWakeAsSoonAsPossible() {
        val spec = ExpiryAlarmSpec.wanted(now - 10 * minute, now, elapsed)
        assertEquals(elapsed, spec.triggerElapsedMillis)
    }

    /**
     * The four constants §10.7 fixes, each of which is a leak if it moves.
     *
     * A request code derived from the minute, or from a contact, would turn the system's alarm
     * table into a list of this device's conversations; an extra would put the expiry's subject
     * there beside its time; a mutable pending intent would let the system be asked to fill
     * something in; and an implicit intent would let another component be resolved into it.
     */
    @Test
    fun oneRequestCodeNoExtrasImmutableAndExplicit() {
        val spec = ExpiryAlarmSpec.wanted(nextMinute, now, elapsed)
        assertEquals(ExpiryAlarmSpec.REQUEST_CODE, spec.requestCode)
        assertEquals("GDM1", String(byteArrayOf(0x47, 0x44, 0x4d, 0x31), Charsets.US_ASCII))
        assertEquals(0x47444d31, ExpiryAlarmSpec.REQUEST_CODE)
        assertEquals("no extras (L7-D7: the table holds the minute and nothing else)", 0, spec.extras)
        assertTrue("FLAG_IMMUTABLE", spec.immutable)
        assertTrue("setAndAllowWhileIdle, which needs no permission", spec.allowWhileIdle)
        assertEquals(
            "explicit, by class name",
            "org.ghost.messaging.android.ExpiryAlarmReceiver",
            spec.explicitComponent,
        )
        assertEquals(
            "the component names the receiver this module ships",
            ExpiryAlarmReceiver::class.java.name,
            spec.explicitComponent,
        )
    }

    /**
     * Two wakes for the same minute are the same alarm, and two for different minutes differ in
     * the trigger time alone — which is what makes "reschedule" and "schedule" one operation
     * against one request code.
     */
    @Test
    fun theSpecDiffersOnlyInTheTriggerTime() {
        val a = ExpiryAlarmSpec.wanted(nextMinute, now, elapsed)
        val b = ExpiryAlarmSpec.wanted(nextMinute, now, elapsed)
        val later = ExpiryAlarmSpec.wanted(nextMinute + minute, now, elapsed)
        assertEquals(a, b)
        assertFalse(a == later)
        assertEquals(a, later.copy(triggerElapsedMillis = a.triggerElapsedMillis))
        // One field per clause of §10.7 item 5: a field added later must be asserted above.
        assertEquals(
            7,
            ExpiryAlarmSpec::class.java.declaredFields.count { !Modifier.isStatic(it.modifiers) },
        )
    }

    /**
     * The receiver drops anything that is not the alarm, although the pending intent is explicit
     * and immutable and the manifest entry is not exported. It costs nothing and makes the
     * receiver's behaviour independent of the manifest being right.
     */
    @Test
    fun theReceiverIsDrivenByOneActionAndNothingElse() {
        assertEquals("org.ghost.messaging.EXPIRY_SWEEP", ExpiryAlarmSpec.ACTION)
        // The hand-off is a static slot the wiring sets and the wipe clears; nothing else of the
        // receiver is public surface.
        val members = ExpiryAlarmReceiver::class.java.declaredMethods
            .filter { !it.isSynthetic && Modifier.isPublic(it.modifiers) }
            .map { it.name }
            .toSet()
        assertEquals(setOf("onReceive", "getOnAlarm", "setOnAlarm"), members)
    }
}
