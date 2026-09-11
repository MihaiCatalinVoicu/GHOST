package org.ghost.sync.android

import android.annotation.SuppressLint
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import org.ghost.sync.port.WakeScheduler

/**
 * The explicit [JobInfo] fields [JobSchedulerWake.ensurePeriodic] compares (design §5.4, §11.3). A
 * pending job whose fields all equal [wanted] is left alone: scheduling it again would reset the
 * period timer. Any difference, or no pending job, schedules it.
 */
internal data class PeriodicJobSpec(
    val jobId: Int,
    val service: String,
    val periodic: Boolean,
    val intervalMillis: Long,
    val flexMillis: Long,
    val persisted: Boolean,
    val networkType: Int,
    val requiresCharging: Boolean,
    val requiresDeviceIdle: Boolean,
    val requiresBatteryNotLow: Boolean,
    val requiresStorageNotLow: Boolean,
    val prefetch: Boolean,
    val extrasEmpty: Boolean,
    val transientExtrasEmpty: Boolean,
    val triggerContentUris: Int,
) {
    companion object {
        /** "GSY1": the one sync job of the app. */
        const val JOB_ID: Int = 0x47535931

        /** The platform minimum period and flex (design §5.1). */
        const val INTERVAL_MILLIS: Long = 15 * 60_000L
        const val FLEX_MILLIS: Long = 5 * 60_000L

        const val NETWORK_TYPE_ANY: Int = JobInfo.NETWORK_TYPE_ANY

        /**
         * Periodic 15 min with 5 min flex, persisted across reboots, any network, no other
         * constraint, no extras: the scheduler holds nothing about sync but this constant entry
         * (T20).
         */
        fun wanted(service: String): PeriodicJobSpec = PeriodicJobSpec(
            jobId = JOB_ID,
            service = service,
            periodic = true,
            intervalMillis = INTERVAL_MILLIS,
            flexMillis = FLEX_MILLIS,
            persisted = true,
            networkType = NETWORK_TYPE_ANY,
            requiresCharging = false,
            requiresDeviceIdle = false,
            requiresBatteryNotLow = false,
            requiresStorageNotLow = false,
            prefetch = false,
            extrasEmpty = true,
            transientExtrasEmpty = true,
            triggerContentUris = 0,
        )

        /** True when [pending] is missing or differs from [wanted] in any compared field. */
        fun needsSchedule(pending: PeriodicJobSpec?, wanted: PeriodicJobSpec): Boolean = pending != wanted
    }
}

/**
 * [WakeScheduler] over the platform JobScheduler (design §5.4, ADR-20): one periodic job for
 * [SyncJobService], no WorkManager. [ensurePeriodic] is called at process start when the database
 * key envelope exists and right after the key is first created, never because of user activity or
 * data arrival; [cancel] runs on wipe (design §11.2 #17).
 */
internal class JobSchedulerWake(context: Context) : WakeScheduler {
    private val app: Context = context.applicationContext

    private fun scheduler(): JobScheduler = checkNotNull(app.getSystemService(JobScheduler::class.java)) { "no job scheduler" }

    override fun ensurePeriodic() {
        val scheduler = scheduler()
        val pending = scheduler.getPendingJob(PeriodicJobSpec.JOB_ID)?.let(::specOf)
        if (PeriodicJobSpec.needsSchedule(pending, PeriodicJobSpec.wanted(SyncJobService::class.java.name))) {
            scheduler.schedule(jobInfo())
        }
    }

    override fun cancel() = scheduler().cancel(PeriodicJobSpec.JOB_ID)

    // setPersisted needs RECEIVE_BOOT_COMPLETED, which the app manifest declares (ADR-20, design
    // §5.5). Library lint cannot see the app manifest; merged-manifest-lint.sh (T15m) requires the
    // permission in the manifest that ships.
    @SuppressLint("MissingPermission")
    private fun jobInfo(): JobInfo = JobInfo.Builder(PeriodicJobSpec.JOB_ID, ComponentName(app, SyncJobService::class.java))
        .setPeriodic(PeriodicJobSpec.INTERVAL_MILLIS, PeriodicJobSpec.FLEX_MILLIS)
        .setPersisted(true)
        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
        .build()

    override fun toString(): String = "JobSchedulerWake"

    private companion object {
        /** The network type getter is deprecated for the NetworkRequest form, which carries the same choice. */
        @Suppress("DEPRECATION")
        fun specOf(info: JobInfo): PeriodicJobSpec = PeriodicJobSpec(
            jobId = info.id,
            service = info.service.className,
            periodic = info.isPeriodic,
            intervalMillis = info.intervalMillis,
            flexMillis = info.flexMillis,
            persisted = info.isPersisted,
            networkType = info.networkType,
            requiresCharging = info.isRequireCharging,
            requiresDeviceIdle = info.isRequireDeviceIdle,
            requiresBatteryNotLow = info.isRequireBatteryNotLow,
            requiresStorageNotLow = info.isRequireStorageNotLow,
            prefetch = info.isPrefetch,
            extrasEmpty = info.extras.isEmpty,
            transientExtrasEmpty = info.transientExtras.isEmpty,
            triggerContentUris = info.triggerContentUris?.size ?: 0,
        )
    }
}
