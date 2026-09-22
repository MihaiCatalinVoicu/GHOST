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
 * **Why `ELAPSED_REALTIME_WAKEUP` and not `RTC_WAKEUP`.** The wake has to survive a wall-clock
 * step: R-T7 already makes a backwards step unable to delay a deletion *once a sweep runs*, and an
 * `RTC` alarm set for a minute the user has just moved past would either fire immediately or never.
 * The conversion from the row's wall-clock minute to elapsed realtime happens here, once, and the
 * delay is clamped at zero so a minute already past is a wake as soon as the system allows.
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
    /** `SystemClock.elapsedRealtime() + (next − now)`, clamped at the current instant. */
    val triggerElapsedMillis: Long,
    /** `setAndAllowWhileIdle`: fires in Doze, about once per nine minutes (L7-D14). */
    val allowWhileIdle: Boolean,
    /** `FLAG_IMMUTABLE`: the system cannot be asked to fill anything into the intent. */
    val immutable: Boolean,
    /** The receiver is named explicitly, so no other component can be resolved into it. */
    val explicitComponent: String,
    /** No extras. The alarm table holds the minute and nothing about what expires (L7-D7). */
    val extras: Int,
) {
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
         * [wallMinute] is the row's deadline in unix seconds on the minute grid; [nowSeconds] is
         * the wall clock the engine read it against; [elapsedRealtimeMillis] is the monotonic
         * clock the alarm is set on. A deadline already past clamps to "now", because an alarm in
         * the past is either refused or fired at once depending on the API level, and "at once" is
         * what is wanted.
         */
        fun wanted(
            wallMinute: Long,
            nowSeconds: Long,
            elapsedRealtimeMillis: Long,
        ): ExpiryAlarmSpec = ExpiryAlarmSpec(
            requestCode = REQUEST_CODE,
            clockType = AlarmManager.ELAPSED_REALTIME_WAKEUP,
            triggerElapsedMillis = elapsedRealtimeMillis + maxOf(0L, wallMinute - nowSeconds) * 1_000L,
            allowWhileIdle = true,
            immutable = true,
            explicitComponent = RECEIVER,
            extras = 0,
        )
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
internal class ExpiryAlarm(context: Context, private val clock: () -> Long) : ExpiryWake {
    private val app: Context = context.applicationContext

    private fun manager(): AlarmManager? = app.getSystemService(AlarmManager::class.java)

    override fun wakeAt(wallMinute: Long?) {
        val alarms = manager() ?: return
        val intent = pendingIntent()
        if (wallMinute == null) {
            // "cancelled when nothing is pending and at wipe" (§10.7). The pending intent is
            // cancelled too, so nothing of it is left in the system's table.
            alarms.cancel(intent)
            intent.cancel()
            return
        }
        val spec = ExpiryAlarmSpec.wanted(
            wallMinute = wallMinute,
            nowSeconds = clock(),
            elapsedRealtimeMillis = SystemClock.elapsedRealtime(),
        )
        alarms.setAndAllowWhileIdle(spec.clockType, spec.triggerElapsedMillis, intent)
    }

    /**
     * The one pending intent: explicit (a [ComponentName], never an implicit action resolved at
     * delivery), immutable, no extras, and the fixed request code that makes a second schedule
     * replace the first.
     */
    private fun pendingIntent(): PendingIntent {
        val intent = Intent(ExpiryAlarmSpec.ACTION).setComponent(
            ComponentName(app.packageName, ExpiryAlarmSpec.RECEIVER),
        )
        return PendingIntent.getBroadcast(
            app,
            ExpiryAlarmSpec.REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    override fun toString(): String = "ExpiryAlarm"
}
