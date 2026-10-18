package org.ghost.app.ui

import kotlinx.coroutines.withContext
import org.ghost.ui.gateway.PrivacyMode
import org.ghost.ui.gateway.SettingsGateway

/**
 * Phase 13 design §3.2: the [SettingsGateway] over [SettingsStore] — privacy mode (Q38),
 * notifications (Q7) and the accessibility opt-in (Q8). Calls run on `ghost-ui-io` (CS-U6).
 */
class SettingsGatewayAdapter(private val store: SettingsStore) : SettingsGateway {
    override suspend fun privacyMode(): PrivacyMode = onIo { store.privacyMode() }

    override suspend fun setPrivacyMode(mode: PrivacyMode): Unit = onIo { store.setPrivacyMode(mode) }

    override suspend fun notificationsEnabled(): Boolean = onIo { store.notificationMode() != 0 }

    override suspend fun setNotificationsEnabled(enabled: Boolean): Unit = onIo {
        store.setNotificationMode(if (enabled) 1 else 0)
    }

    override suspend fun hideFromAllServices(): Boolean = onIo { store.hideFromAllServices() }

    override suspend fun setHideFromAllServices(enabled: Boolean): Unit = onIo {
        store.setHideFromAllServices(enabled)
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
