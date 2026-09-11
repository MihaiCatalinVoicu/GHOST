package org.ghost.app

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.ghost.identity.AndroidKeystoreWrapper
import org.ghost.identity.NoBackupFileSecretStore
import org.ghost.storage.DatabaseKeyProvider
import org.ghost.sync.android.AndroidSyncController
import org.ghost.sync.android.SyncHost

/**
 * The application process (design §5.4, ADR-20): creates the one sync controller and wires it.
 * Sync does nothing until a database key envelope exists; onboarding (Phase 13) creates the key and
 * then calls [onDatabaseKeyCreated]. The decisions themselves live in [SyncWiring].
 */
class GhostApp : Application(), SyncHost {
    private val keys: DatabaseKeyProvider by lazy { DatabaseKeyProvider(AndroidKeystoreWrapper(), NoBackupFileSecretStore(this)) }

    private val database: AppDatabase by lazy { AppDatabase(this, keys, DatabaseAccess.AUTH_BOUND) }

    override val syncController: AndroidSyncController by lazy { AndroidSyncController.create(this, database) }

    private val wiring: SyncWiring by lazy {
        SyncWiring(
            keyExists = { keys.exists() },
            controller = syncController,
            ensurePeriodic = { syncController.ensurePeriodic() },
            databaseAvailable = { syncController.onDatabaseAvailable() },
        )
    }

    override fun onCreate() {
        super.onCreate()
        wiring.onProcessStart()
        // ON_START when the first activity starts, ON_STOP shortly after the last one stops. A
        // process started for the background job has no activity and never sees ON_START.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = wiring.onVisible()

            override fun onStop(owner: LifecycleOwner) = wiring.onHidden()
        })
    }

    /** Onboarding calls this right after the database key is first created (design §11.2 #17). */
    fun onDatabaseKeyCreated() = wiring.onKeyCreated()
}
