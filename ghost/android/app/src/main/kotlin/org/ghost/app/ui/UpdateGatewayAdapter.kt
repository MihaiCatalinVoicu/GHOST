package org.ghost.app.ui

import kotlinx.coroutines.withContext
import org.ghost.ui.gateway.UpdateGateway
import org.ghost.ui.gateway.UpdateStatusView

/** Phase 14 facade to Phase 13's small, local update read model. */
class UpdateGatewayAdapter(
    private val updates: () -> org.ghost.update.Updates?,
) : UpdateGateway {
    override suspend fun status(): UpdateStatusView = onIo {
        val facade = updates() ?: return@onIo UpdateStatusView("NO_UPDATER", null)
        updateStatusView(facade.status)
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun requestCheck() = onIo {
        updates()?.requestCheck()
        Unit
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun requestDownload() = onIo {
        updates()?.requestDownload()
        Unit
    }

    @org.ghost.ui.gateway.UserAction
    override suspend fun install() = onIo {
        val facade = updates() ?: return@onIo
        facade.install().commit()
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}

internal fun updateStatusView(status: org.ghost.update.UpdateStatus): UpdateStatusView = when (status) {
    org.ghost.update.UpdateStatus.UpToDate -> UpdateStatusView("UP_TO_DATE", null)
    is org.ghost.update.UpdateStatus.Available -> UpdateStatusView("AVAILABLE", status.name)
    is org.ghost.update.UpdateStatus.Downloading -> UpdateStatusView("DOWNLOADING", "${status.received}/${status.total}")
    is org.ghost.update.UpdateStatus.Ready -> UpdateStatusView("READY", status.name)
    org.ghost.update.UpdateStatus.Installing -> UpdateStatusView("INSTALLING", null)
    is org.ghost.update.UpdateStatus.Installed -> UpdateStatusView("INSTALLED", status.versionCode.toString())
    is org.ghost.update.UpdateStatus.Stale -> UpdateStatusView("STALE", status.day.toString())
    is org.ghost.update.UpdateStatus.Unsupported -> UpdateStatusView("UNSUPPORTED", status.floor.toString())
    org.ghost.update.UpdateStatus.SdkUnsupported -> UpdateStatusView("SDK_UNSUPPORTED", null)
    org.ghost.update.UpdateStatus.NoManifest -> UpdateStatusView("NO_MANIFEST", null)
    org.ghost.update.UpdateStatus.Conflict -> UpdateStatusView("CONFLICT", null)
    org.ghost.update.UpdateStatus.RootConflict -> UpdateStatusView("ROOT_CONFLICT", null)
    org.ghost.update.UpdateStatus.NoChannel -> UpdateStatusView("NO_CHANNEL", null)
    is org.ghost.update.UpdateStatus.Failed -> UpdateStatusView("FAILED", status.code.toString())
}
