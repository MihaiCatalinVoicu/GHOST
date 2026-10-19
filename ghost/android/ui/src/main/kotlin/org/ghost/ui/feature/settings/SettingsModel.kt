package org.ghost.ui.feature.settings

import org.ghost.ui.gateway.PrivacyMode
import org.ghost.ui.gateway.SettingsGateway

/**
 * Phase 13 design §6.8 (Confidențialitate): the privacy-mode, notification and service-visibility
 * choices over [SettingsGateway]. §7.1's table is the only place the modes' behavior is described;
 * the UI copy is the approved DC-22 sentence, shown beside the HIGH choice. The count and
 * lock-screen display choices of the notification row are not on the gateway yet — they land
 * with their own slice, declared here.
 */
class SettingsModel(private val settings: SettingsGateway) {
    /** The active mode; STANDARD until [load] reads the store. */
    var privacyMode: PrivacyMode = PrivacyMode.STANDARD
        private set

    /** The notification switch's state. */
    var notificationsEnabled: Boolean = true
        private set

    /** The hide-from-other-services switch's state (the accessibility services list, §4.3). */
    var hideFromAllServices: Boolean = false
        private set

    /** Reads the three choices (a read, not a user action). */
    suspend fun load() {
        privacyMode = settings.privacyMode()
        notificationsEnabled = settings.notificationsEnabled()
        hideFromAllServices = settings.hideFromAllServices()
    }

    /** Sets the privacy mode; §7.1: a change applies to later operations, not retroactively. */
    suspend fun onSetPrivacyMode(mode: PrivacyMode) {
        settings.setPrivacyMode(mode)
        privacyMode = mode
    }

    /** Turns the constant, content-free notification on or off. */
    suspend fun onSetNotificationsEnabled(enabled: Boolean) {
        settings.setNotificationsEnabled(enabled)
        notificationsEnabled = enabled
    }

    /** Hides GHOST from other services' pickers where the platform allows it. */
    suspend fun onSetHideFromAllServices(enabled: Boolean) {
        settings.setHideFromAllServices(enabled)
        hideFromAllServices = enabled
    }
}
