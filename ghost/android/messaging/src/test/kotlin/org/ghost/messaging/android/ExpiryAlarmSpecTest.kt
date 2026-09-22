package org.ghost.messaging.android

import android.app.AlarmManager
import android.app.PendingIntent
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

    /** The delay the engine measured against `now_e`, and the monotonic clock it is set on. */
    private val delay = 3_600L
    private val elapsed = 12_345_678L

    @Test
    fun theComputedTriggerTimeIsTheDelayOnTheElapsedRealtimeClock() {
        val spec = ExpiryAlarmSpec.wanted(delay, elapsed)
        assertEquals(
            "SystemClock.elapsedRealtime() + (next - now_e), in milliseconds",
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
        val spec = ExpiryAlarmSpec.wanted(-10 * minute, elapsed)
        assertEquals(elapsed, spec.triggerElapsedMillis)
    }

    /**
     * The four constants §10.7 fixes, each of which is a leak if it moves.
     *
     * A request code derived from the minute, or from a contact, would turn the system's alarm
     * table into a list of this device's conversations; an extra would put the expiry's subject
     * there beside its time; a mutable pending intent would let the system be asked to fill
     * something in; and an implicit intent would let another component be resolved into it.
     *
     * **These assertions bind to the real call** since the S9 review: `ExpiryAlarm.pendingIntent`
     * builds its `Intent` and its `PendingIntent` out of this spec and out of nothing else, and
     * `wakeIn` chooses `setAndAllowWhileIdle` from [ExpiryAlarmSpec.allowWhileIdle], so a change
     * at the call site has to come through a change here. Before that they were a data class
     * asserted against itself: swapping `FLAG_IMMUTABLE` for `FLAG_MUTABLE`, adding a `putExtra`
     * or passing the minute as the request code each left the whole suite green.
     */
    @Test
    fun oneRequestCodeNoExtrasImmutableAndExplicit() {
        val spec = ExpiryAlarmSpec.wanted(delay, elapsed)
        assertEquals(ExpiryAlarmSpec.REQUEST_CODE, spec.requestCode)
        assertEquals("GDM1", String(byteArrayOf(0x47, 0x44, 0x4d, 0x31), Charsets.US_ASCII))
        assertEquals(0x47444d31, ExpiryAlarmSpec.REQUEST_CODE)
        assertEquals(
            "no extras (L7-D7: the table holds the minute and nothing else)",
            emptyMap<String, String>(),
            spec.extras,
        )
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
     * `FLAG_IMMUTABLE` is what [ExpiryAlarmSpec.pendingIntentFlags] adds, and it is the flag the
     * pending intent is really built with — `PendingIntent.getBroadcast` is the one call and it
     * takes this value. The base flag (`FLAG_UPDATE_CURRENT` to schedule, `FLAG_NO_CREATE` to
     * cancel) is kept, so the two uses stay distinguishable.
     */
    @Test
    fun theImmutableFlagIsTheOneThePendingIntentIsBuiltWith() {
        val spec = ExpiryAlarmSpec.wanted(delay, elapsed)
        assertEquals(
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            spec.pendingIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT),
        )
        assertEquals(
            PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE,
            spec.pendingIntentFlags(PendingIntent.FLAG_NO_CREATE),
        )
        assertEquals(
            "a spec that stopped being immutable would ask for FLAG_MUTABLE, which §10.7 forbids",
            PendingIntent.FLAG_MUTABLE,
            spec.copy(immutable = false).pendingIntentFlags(0),
        )
    }

    /**
     * Two wakes for the same minute are the same alarm, and two for different minutes differ in
     * the trigger time alone — which is what makes "reschedule" and "schedule" one operation
     * against one request code.
     */
    @Test
    fun theSpecDiffersOnlyInTheTriggerTime() {
        val a = ExpiryAlarmSpec.wanted(delay, elapsed)
        val b = ExpiryAlarmSpec.wanted(delay, elapsed)
        val later = ExpiryAlarmSpec.wanted(delay + minute, elapsed)
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
