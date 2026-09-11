package org.ghost.app

import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import org.ghost.storage.DatabaseKeyProvider
import org.ghost.storage.GhostDatabase
import org.ghost.storage.SqlExecutor
import org.ghost.sync.android.DatabaseOpener

/** Which sync sessions may open the database (design §5.1, §11.1 Q6). */
internal object DatabaseAccess {
    /**
     * Whether the database key is bound to user authentication. Phase 7 keeps the Phase 4 default
     * (`AndroidKeystoreWrapper(requireUserAuthentication = false)`); FR-1.7 makes it a setting later.
     */
    const val AUTH_BOUND: Boolean = false

    /**
     * No key envelope: nothing to open (the opener never creates the key). An auth-bound key cannot
     * be unlocked by a background job, so background sessions do nothing (Q6).
     */
    fun mayOpen(purpose: DatabaseOpener.Purpose, keyExists: Boolean, authBound: Boolean): Boolean =
        keyExists && !(authBound && purpose == DatabaseOpener.Purpose.BACKGROUND)
}

/**
 * The app's [DatabaseOpener]: the SQLCipher database (Phase 4), opened on the sync runtime thread
 * the first time a session may use it, then kept open for the process.
 */
internal class AppDatabase(
    private val context: Context,
    private val keys: DatabaseKeyProvider,
    private val authBound: Boolean,
) : DatabaseOpener {
    @Volatile
    private var database: GhostDatabase? = null

    override fun keyExists(): Boolean = keys.exists()

    override fun open(purpose: DatabaseOpener.Purpose): SqlExecutor? {
        if (!DatabaseAccess.mayOpen(purpose, keys.exists(), authBound)) return null
        database?.let { return it.executor }
        val opened = try {
            GhostDatabase.open(context, keys)
        } catch (e: UserNotAuthenticatedException) {
            // An auth-bound key outside its unlock window: no session until the user unlocks.
            return null
        }
        database = opened
        return opened.executor
    }

    override fun toString(): String = "AppDatabase"
}
