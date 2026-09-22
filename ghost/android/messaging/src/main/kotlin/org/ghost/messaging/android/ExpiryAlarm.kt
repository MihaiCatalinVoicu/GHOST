package org.ghost.messaging.android

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import org.ghost.messaging.port.ExpiryWake

/**
 * The **pure half** of [ExpiryAlarm]: everything §10.7 item 5 and §21.10 point 7 fix about the one
 * alarm the messaging layer is allowed to hold, computed without an `AlarmManager`.
 *
 * > **one inexact alarm**: `AlarmManager.setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP,
 * > SystemClock.elapsedRealtime() + (next − now), pendingIntent)` on an explicit, **non-exported**
 * > `ExpiryAlarmReceiver` through `FLAG_IMMUTABLE`, one fixed request code, no extras, no new
 * > permission; cancelled when nothing is pending and at wipe.
 *
 * Every clause of that sentence is a field here, and `ExpiryAlarmSpecTest` asserts each one —
 * which is the only way the contract can be checked at all on the JVM, where `AlarmManager` is a
 * stub that throws. The EP suite's "alarm contract (non-exported receiver, no extras, one request
 * code, cancel at wipe)" is this class plus the manifest entry `:app` declares (slice S12).
 *
 * **The spec is what the implementation reads**, not a description beside it (S9 review). Until
 * that review, [ExpiryAlarm.wakeIn] used two of these fields and built its `PendingIntent` from
 * the companion constants directly, so a test asserting `immutable`, `extras`, `requestCode`,
 * `explicitComponent` or `allowWhileIdle` was asserting a data class against itself: switching the
 * real call to `FLAG_MUTABLE`, adding a `putExtra`, or deriving the request code from the minute
 * — each of them the leak §10.7 and L7-D7 forbid — left the whole suite green. Every field is now
 * read by the code that talks to `AlarmManager`.
 *
 * **Why `ELAPSED_REALTIME_WAKEUP` and not `RTC_WAKEUP`.** The wake has to survive a wall-clock
 * step: R-T7 already makes a backwards step unable to delay a deletion *once a sweep runs*, and an
 * `RTC` alarm set for a minute the user has just moved past would either fire immediately or never.
 * The delay this class is given is already measured against `now_e` (R-T7) by the engine, so the
 * only conversion left here is to elapsed realtime — no wall clock is read at all.
 *
 * **Why inexact.** `setAndAllowWhileIdle` needs no permission (`SCHEDULE_EXACT_ALARM` would, and
 * T15's allowlist has none), and Doze limits it to about once per nine minutes per app — which is
 * the declared lag bound of L7-D14 and not a defect: the rows stay under SQLCipher and are never
 * shown, because every read carries the filter of §10.7 point 4.
 */
internal data class ExpiryAlarmSpec(
    /** The one fixed request code, so a second schedule replaces the first rather than adding one. */
    val requestCode: Int,
    /** The alarm clock: elapsed realtime, which no wall-clock step moves. */
    val clockType: Int,
    /** `SystemClock.elapsedRealtime() + (next − now_e)`, clamped at the current instant. */
    val triggerElapsedMillis: Long,
    /** `setAndAllowWhileIdle`: fires in Doze, about once per nine minutes (L7-D14). */
    val allowWhileIdle: Boolean,
    /** `FLAG_IMMUTABLE`: the system cannot be asked to fill anything into the intent. */
    val immutable: Boolean,
    /** The receiver is named explicitly, so no other component can be resolved into it. */
    val explicitComponent: String,
    /**
     * The extras of the broadcast intent, which are **none**: the alarm table holds the minute and
     * nothing about what expires (L7-D7).
     *
     * It is a map rather than a count so that the field is *built from* rather than *described
     * beside* the intent — [ExpiryAlarm.pendingIntent] puts exactly these entries and has no other
     * `putExtra`, so an extra can only be added by adding it here, where the test sees it.
     */
    val extras: Map<String, String>,
) {
    /** The `PendingIntent` flags this spec asks for, `FLAG_MUTABLE` being the leak it forbids. */
    fun pendingIntentFlags(base: Int): Int =
        base or if (immutable) PendingIntent.FLAG_IMMUTABLE else PendingIntent.FLAG_MUTABLE

    companion object {
        /**
         * "GDM1": the one DM alarm of the app. It is fixed because §10.7 says one alarm — a
         * request code derived from the minute, or from a contact, would make the system's alarm
         * table a list of this device's conversations.
         */
        const val REQUEST_CODE: Int = 0x47444d31

        /** The explicit action, so a broadcast that is not this one is dropped by the receiver. */
        const val ACTION: String = "org.ghost.messaging.EXPIRY_SWEEP"

        /** The receiver's class name, as the manifest of `:app` declares it (non-exported). */
        const val RECEIVER: String = "org.ghost.messaging.android.ExpiryAlarmReceiver"

        /**
         * §21.10 point 7's computed trigger time.
         *
         * [delaySeconds] is `next − now_e`, already measured by the engine against the expiry
         * clock of R-T7 (see [org.ghost.messaging.port.ExpiryWake]); [elapsedRealtimeMillis] is
         * the monotonic clock the alarm is set on. A delay already past clamps to "now", because
         * an alarm in the past is either refused or fired at once depending on the API level, and
         * "at once" is what is wanted.
         */
        fun wanted(
            delaySeconds: Long,
            elapsedRealtimeMillis: Long,
        ): ExpiryAlarmSpec = ExpiryAlarmSpec(
            requestCode = REQUEST_CODE,
            clockType = AlarmManager.ELAPSED_REALTIME_WAKEUP,
            triggerElapsedMillis = elapsedRealtimeMillis + maxOf(0L, delaySeconds) * 1_000L,
            allowWhileIdle = true,
            immutable = true,
            explicitComponent = RECEIVER,
            extras = emptyMap(),
        )

        /**
         * The alarm **as it is identified**, with no trigger time: the request code, the component
         * and the flags, which is all a cancel needs. It is the same identity a schedule uses, and
         * that is the point — a cancel that named a different request code or a different
         * component would leave the standing alarm in the system's table (L7-D7).
         */
        fun standing(): ExpiryAlarmSpec = wanted(delaySeconds = 0L, elapsedRealtimeMillis = 0L)
    }
}

/**
 * [ExpiryWake] over the platform `AlarmManager` (Phase 9 design §10.7 item 5, §13.1
 * `…messaging.android`).
 *
 * One alarm, one request code, no extras, no permission, and a cancel whenever nothing is pending
 * — which is [ExpiryWake]'s null. The manifest entry for [ExpiryAlarmReceiver] is `:app`'s
 * (slice S12, §13.7 "Wiring"); this class is what schedules against it.
 *
 * `T20` is amended for exactly this one alarm (§10.7): "One periodic job without extras" is
 * unchanged, and the messaging layer may hold this one inexact alarm with no extras. A rooted
 * examiner can read the next expiry minute out of it, which is declared in L7-D7.
 */
internal class ExpiryAlarm(context: Context) : ExpiryWake {
    private val app: Context = context.applicationContext

    private fun manager(): AlarmManager? = app.getSystemService(AlarmManager::class.java)

    override fun wakeIn(delaySeconds: Long?) {
        val alarms = manager() ?: return
        if (delaySeconds == null) {
            // "cancelled when nothing is pending and at wipe" (§10.7). `FLAG_NO_CREATE` answers
            // null when there is no alarm to cancel, rather than creating a pending intent purely
            // in order to cancel it. The pending intent is cancelled too, so nothing of it is left
            // in the system's table.
            val standing = pendingIntent(ExpiryAlarmSpec.standing(), PendingIntent.FLAG_NO_CREATE)
                ?: return
            alarms.cancel(standing)
            standing.cancel()
            return
        }
        val spec = ExpiryAlarmSpec.wanted(
            delaySeconds = delaySeconds,
            elapsedRealtimeMillis = SystemClock.elapsedRealtime(),
        )
        val intent = pendingIntent(spec, PendingIntent.FLAG_UPDATE_CURRENT) ?: return
        if (spec.allowWhileIdle) {
            alarms.setAndAllowWhileIdle(spec.clockType, spec.triggerElapsedMillis, intent)
        } else {
            alarms.set(spec.clockType, spec.triggerElapsedMillis, intent)
        }
    }

    /**
     * The one pending intent, **built from [spec] and from nothing else**: explicit (a
     * [ComponentName], never an implicit action resolved at delivery), immutable, carrying exactly
     * the spec's extras — which are none — and the fixed request code that makes a second schedule
     * replace the first.
     *
     * Every value comes out of the spec so that `ExpiryAlarmSpecTest`'s assertions about the spec
     * are assertions about this call (S9 review): while these were companion constants read
     * directly, the test proved only that a data class held the values it had been given.
     */
    private fun pendingIntent(spec: ExpiryAlarmSpec, flags: Int): PendingIntent? {
        val intent = Intent(ExpiryAlarmSpec.ACTION).setComponent(
            ComponentName(app.packageName, spec.explicitComponent),
        )
        for ((name, value) in spec.extras) intent.putExtra(name, value)
        return PendingIntent.getBroadcast(
            app,
            spec.requestCode,
            intent,
            spec.pendingIntentFlags(flags),
        )
    }

    override fun toString(): String = "ExpiryAlarm"
}
