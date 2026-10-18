package org.ghost.app.ui

import org.ghost.storage.SqlExecutor
import org.ghost.storage.queryLong
import org.ghost.ui.gateway.PrivacyMode

/**
 * Phase 13 design §10: the typed access to the single `ui_settings` row (id = 1). Every value
 * is one of the migration-10 CHECK domains; a write that violates a CHECK fails here like it
 * fails in SQL. No time column of activity exists in this table (T33): the clip label is the
 * 8-byte ownership token of §4.4 (never content, never a time), and everything else is a mode,
 * a flag or a day-granular counter.
 *
 * The store is synchronous: gateway adapters call it on `ghost-ui-io` (§3.2). It is created
 * once the database exists; [executor] returns null while it does not, and every read then
 * answers the default (the migration's INSERT row) without opening anything.
 */
class SettingsStore(private val executor: () -> SqlExecutor?) {

    fun privacyMode(): PrivacyMode =
        if (int("privacy_mode") == 1) PrivacyMode.HIGH else PrivacyMode.STANDARD

    fun setPrivacyMode(mode: PrivacyMode) = set("privacy_mode", if (mode == PrivacyMode.HIGH) 1 else 0)

    /** The lock timeout choice in seconds: 0, 60, 300 or 1 800 (Q5). */
    fun lockTimeoutSeconds(): Long = int("lock_timeout_s").toLong()

    fun setLockTimeoutSeconds(seconds: Long) {
        require(seconds in setOf(0L, 60L, 300L, 1800L)) { "not a Q5 choice: $seconds" }
        set("lock_timeout_s", seconds.toInt())
    }

    fun biometricEnabled(): Boolean = int("biometric") == 1

    fun setBiometricEnabled(enabled: Boolean) = set("biometric", if (enabled) 1 else 0)

    /** §4.6's notification mode: 0 off, 1 constant, 2 constant with count (Q7). */
    fun notificationMode(): Int = int("notif_mode")

    fun setNotificationMode(mode: Int) {
        require(mode in 0..2) { "not a Q7 mode: $mode" }
        set("notif_mode", mode)
    }

    fun notificationLockScreen(): Boolean = int("notif_lockscreen") == 1

    fun setNotificationLockScreen(show: Boolean) = set("notif_lockscreen", if (show) 1 else 0)

    /** Q8's opt-in: hide content and key labels from every accessibility service. */
    fun hideFromAllServices(): Boolean = int("a11y_hide") == 1

    fun setHideFromAllServices(enabled: Boolean) = set("a11y_hide", if (enabled) 1 else 0)

    /** §6.2's onboarding step (D36's order), 0..11; 0 also means "not started". */
    fun onboardingStep(): Int = int("onboarding_step")

    fun setOnboardingStep(step: Int) {
        require(step in 0..11) { "not a §6.2 step: $step" }
        set("onboarding_step", step)
    }

    /** §5.6: the backup verification is complete (onboarding stays incomplete until it is 1). */
    fun backupVerified(): Boolean = int("backup_verified") == 1

    fun setBackupVerified(verified: Boolean) = set("backup_verified", if (verified) 1 else 0)

    /** Q30: the one-time keyboard warning has been shown. */
    fun imeWarned(): Boolean = int("ime_warned") == 1

    fun setImeWarned(warned: Boolean) = set("ime_warned", if (warned) 1 else 0)

    fun disclosuresVersion(): Int = int("disclosures_v")

    fun setDisclosuresVersion(version: Int) {
        require(version >= 0) { "negative disclosures version" }
        set("disclosures_v", version)
    }

    /** §4.4: the persisted ownership token of the last sensitive copy; null when none. */
    fun clipLabel(): ByteArray? = executor()?.let { db ->
        var out: ByteArray? = null
        db.query("SELECT clip_label FROM ui_settings WHERE id = 1") { row ->
            out = if (row.isNull(0)) null else row.blob(0)
        }
        out
    }

    fun setClipLabel(label: ByteArray) {
        require(label.size == 8) { "the ownership token is 8 bytes" }
        executor()?.execUpdate("UPDATE ui_settings SET clip_label = ? WHERE id = 1", listOf(label))
    }

    fun clearClipLabel() {
        executor()?.exec("UPDATE ui_settings SET clip_label = NULL WHERE id = 1")
    }

    private fun int(column: String): Int {
        val db = executor() ?: return DEFAULTS.getValue(column)
        return db.queryLong("SELECT $column FROM ui_settings WHERE id = 1")?.toInt()
            ?: DEFAULTS.getValue(column)
    }

    private fun set(column: String, value: Int) {
        executor()?.execUpdate("UPDATE ui_settings SET $column = ? WHERE id = 1", listOf(value.toLong()))
    }

    private companion object {
        /** The migration-10 INSERT row, mirrored for the no-database answer. */
        val DEFAULTS: Map<String, Int> = mapOf(
            "privacy_mode" to 0,
            "lock_timeout_s" to 60,
            "biometric" to 0,
            "notif_mode" to 1,
            "notif_lockscreen" to 0,
            "theme" to 0,
            "dynamic_color" to 1,
            "a11y_hide" to 0,
            "onboarding_step" to 0,
            "backup_verified" to 0,
            "ime_warned" to 0,
            "disclosures_v" to 0,
        )
    }
}
