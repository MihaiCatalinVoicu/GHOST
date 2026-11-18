package org.ghost.app.ui

import org.ghost.update.UpdateStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class UpdateGatewayAdapterTest {
    @Test
    fun everyUpdateStateBecomesATypedUiValue() {
        assertEquals("UP_TO_DATE", updateStatusView(UpdateStatus.UpToDate).state)
        assertEquals("AVAILABLE", updateStatusView(UpdateStatus.Available("2.0", 20)).state)
        assertEquals("2.0", updateStatusView(UpdateStatus.Available("2.0", 20)).version)
        assertEquals("12/64", updateStatusView(UpdateStatus.Downloading(12, 64)).version)
        assertEquals("READY", updateStatusView(UpdateStatus.Ready("2.0", 20)).state)
        assertEquals("INSTALLING", updateStatusView(UpdateStatus.Installing).state)
        assertEquals("INSTALLED", updateStatusView(UpdateStatus.Installed(20)).state)
        assertEquals("STALE", updateStatusView(UpdateStatus.Stale(100)).state)
        assertEquals("UNSUPPORTED", updateStatusView(UpdateStatus.Unsupported(10)).state)
        assertEquals("SDK_UNSUPPORTED", updateStatusView(UpdateStatus.SdkUnsupported).state)
        assertEquals("NO_MANIFEST", updateStatusView(UpdateStatus.NoManifest).state)
        assertEquals("CONFLICT", updateStatusView(UpdateStatus.Conflict).state)
        assertEquals("ROOT_CONFLICT", updateStatusView(UpdateStatus.RootConflict).state)
        assertEquals("NO_CHANNEL", updateStatusView(UpdateStatus.NoChannel).state)
        assertEquals("FAILED", updateStatusView(UpdateStatus.Failed(9)).state)
    }
}
