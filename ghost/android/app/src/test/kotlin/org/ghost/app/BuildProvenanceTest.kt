package org.ghost.app

import org.ghost.app.ui.sourceSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The APK carries the exact source commit and an explicit modified-source bit, never host metadata. */
class BuildProvenanceTest {
    @Test
    fun sourceCommitAndDirtyBitArePresentAndWellFormed() {
        assertTrue(
            "commit is a full SHA-1 or explicitly unknown",
            BuildConfig.SOURCE_COMMIT == "unknown" || BuildConfig.SOURCE_COMMIT.matches(Regex("[0-9a-f]{40}")),
        )
        assertEquals("v\nsource=abc (modified)", sourceSummary("v", "abc", dirty = true))
        assertEquals("v\nsource=abc", sourceSummary("v", "abc", dirty = false))
    }
}
