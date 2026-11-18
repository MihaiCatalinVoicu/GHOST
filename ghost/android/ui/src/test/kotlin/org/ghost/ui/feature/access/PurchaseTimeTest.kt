package org.ghost.ui.feature.access

import org.junit.Assert.assertEquals
import org.junit.Test

class PurchaseTimeTest {
    @Test
    fun syncTimestampIsEpochSecondsNotMinutes() {
        assertEquals(
            "1970-01-01 00:01",
            formatSyncTime(60, java.time.ZoneOffset.UTC),
        )
    }
}
