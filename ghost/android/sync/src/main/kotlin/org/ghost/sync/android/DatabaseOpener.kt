package org.ghost.sync.android

import org.ghost.storage.SqlExecutor

/**
 * Supplied by the app: access to the encrypted database, so :sync owns no key policy (design §5.4).
 * [SyncRuntime] calls [open] on its runtime thread before a session.
 */
interface DatabaseOpener {
    /** True when the database key envelope exists (`DatabaseKeyProvider.exists()`). */
    fun keyExists(): Boolean

    /**
     * The open, migrated and verified database, or null when a session of [purpose] must not use it
     * now: no key envelope yet, or, for [Purpose.BACKGROUND], a key bound to user authentication,
     * which a background job cannot unlock (design §5.1, §11.1 Q6); the background session then
     * ends with no network I/O. Returns the same executor while the database stays open. Expected
     * conditions give null, not an exception. Must never create the key.
     */
    fun open(purpose: Purpose): SqlExecutor?

    enum class Purpose { FOREGROUND, BACKGROUND }
}

/** Implemented by the app's `Application`: the process's one sync controller, reached by [SyncJobService]. */
interface SyncHost {
    val syncController: AndroidSyncController
}
