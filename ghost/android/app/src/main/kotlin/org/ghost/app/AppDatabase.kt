package org.ghost.app

import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import java.security.GeneralSecurityException
import java.util.concurrent.CopyOnWriteArrayList
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
 *
 * Phase 13 §5.4: a Keystore failure that is NOT the auth-window case (`KeyPermanentlyInvalidated-
 * Exception`, `UnrecoverableKeyException`, an `InvalidKeyException` after a Keystore reset or an
 * OEM fault) is recorded as [KEYSTORE_LOST] and the open returns null — nothing is written and
 * the sync runtime's thread is not ended by an uncaught exception. The UI shows §5.4's full
 * screen; MC-U18 keeps the mapping.
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
        } catch (e: GeneralSecurityException) {
            // Phase 13 §5.4: any other Keystore failure maps to KEYSTORE_LOST; the open refuses
            // and nothing is written (the old behavior ended the runtime's thread).
            notifyKeystoreLost()
            return null
        }
        database = opened
        return opened.executor
    }

    override fun toString(): String = "AppDatabase"

    companion object {
        private val lostListeners = CopyOnWriteArrayList<() -> Unit>()

        /** Set by the UI wiring (S2); fired at most meaningfully, coalesced by the screen. */
        fun onKeystoreLost(listener: () -> Unit) {
            lostListeners.add(listener)
        }

        internal fun notifyKeystoreLost() {
            for (l in lostListeners) l()
        }
    }
}
