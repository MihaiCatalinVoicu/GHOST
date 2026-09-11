package org.ghost.sync.android

import android.app.job.JobInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

/**
 * The pure half of [JobSchedulerWake] (design §5.4, §11.3): the wanted job carries the design's
 * fields, and `ensurePeriodic` schedules only when the pending job is missing or differs in an
 * explicitly compared field, so the period timer is not reset by every process start.
 */
class PeriodicJobSpecTest {
    private val service = SyncJobService::class.java.name
    private val wanted = PeriodicJobSpec.wanted(service)

    @Test
    fun theWantedJobCarriesTheDesignFields() {
        assertEquals(0x47535931, wanted.jobId)
        assertEquals("org.ghost.sync.android.SyncJobService", wanted.service)
        assertTrue(wanted.periodic)
        assertEquals(15 * 60_000L, wanted.intervalMillis)
        assertEquals(5 * 60_000L, wanted.flexMillis)
        assertTrue(wanted.persisted)
        assertEquals(JobInfo.NETWORK_TYPE_ANY, wanted.networkType)
        assertFalse(wanted.requiresCharging || wanted.requiresDeviceIdle || wanted.requiresBatteryNotLow || wanted.requiresStorageNotLow)
        assertFalse(wanted.prefetch)
        assertTrue("no extras: the scheduler holds nothing about sync (T20)", wanted.extrasEmpty && wanted.transientExtrasEmpty)
        assertEquals(0, wanted.triggerContentUris)
    }

    @Test
    fun aMissingJobIsScheduledAndAnIdenticalOneIsLeftAlone() {
        assertTrue(PeriodicJobSpec.needsSchedule(null, wanted))
        assertFalse(PeriodicJobSpec.needsSchedule(PeriodicJobSpec.wanted(service), wanted))
    }

    @Test
    fun anyComparedFieldThatDiffersSchedulesAgain() {
        val variants = listOf(
            wanted.copy(jobId = 1),
            wanted.copy(service = "org.ghost.other.Service"),
            wanted.copy(periodic = false),
            wanted.copy(intervalMillis = 30 * 60_000L),
            wanted.copy(flexMillis = 10 * 60_000L),
            wanted.copy(persisted = false),
            wanted.copy(networkType = JobInfo.NETWORK_TYPE_UNMETERED),
            wanted.copy(requiresCharging = true),
            wanted.copy(requiresDeviceIdle = true),
            wanted.copy(requiresBatteryNotLow = true),
            wanted.copy(requiresStorageNotLow = true),
            wanted.copy(prefetch = true),
            wanted.copy(extrasEmpty = false),
            wanted.copy(transientExtrasEmpty = false),
            wanted.copy(triggerContentUris = 1),
        )
        for (v in variants) assertTrue(v.toString(), PeriodicJobSpec.needsSchedule(v, wanted))
        // One variant per compared field: a field added later must get its own variant here.
        val fields = PeriodicJobSpec::class.java.declaredFields.count { !Modifier.isStatic(it.modifiers) }
        assertEquals(fields, variants.size)
    }
}
