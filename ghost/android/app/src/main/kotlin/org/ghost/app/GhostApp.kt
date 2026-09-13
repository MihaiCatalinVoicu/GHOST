package org.ghost.app

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.ghost.entitlement.android.EntitlementWiring
import org.ghost.entitlement.api.Entitlement
import org.ghost.identity.AndroidKeystoreWrapper
import org.ghost.identity.IdentityManager
import org.ghost.identity.NoBackupFileSecretStore
import org.ghost.storage.DatabaseKeyProvider
import org.ghost.sync.android.AndroidSyncController
import org.ghost.sync.android.DatabaseOpener
import org.ghost.sync.android.SyncHost

/**
 * The application process (design §5.4, ADR-20; Phase 8 design §11.1, §11.6): creates the one sync
 * controller and the entitlement engine, installs the engine as the controller's one session
 * participant and wires both to the process lifecycle. Sync does nothing until a database key
 * envelope exists; onboarding (Phase 13) creates the key and then calls [onDatabaseKeyCreated]. The
 * decisions themselves live in [SyncWiring].
 */
class GhostApp : Application(), SyncHost {
    private val keys: DatabaseKeyProvider by lazy { DatabaseKeyProvider(AndroidKeystoreWrapper(), NoBackupFileSecretStore(this)) }

    private val database: AppDatabase by lazy { AppDatabase(this, keys, DatabaseAccess.AUTH_BOUND) }

    override val syncController: AndroidSyncController by lazy { AndroidSyncController.create(this, database) }

    private val identity: IdentityManager by lazy { IdentityManager(AndroidKeystoreWrapper(), NoBackupFileSecretStore(this)) }

    private val entitlementWiring: EntitlementWiring by lazy {
        EntitlementWiring(syncController, { syncController.stores }, identity, privacyMode = { syncController.privacyMode })
    }

    /** The entitlement facade for Phase 13 (design §11.2). */
    val entitlement: Entitlement get() = entitlementWiring.entitlement

    private val wiring: SyncWiring by lazy {
        SyncWiring(
            keyExists = { keys.exists() },
            controller = syncController,
            ensurePeriodic = { syncController.ensurePeriodic() },
            databaseAvailable = { syncController.onDatabaseAvailable() },
            participant = entitlementWiring.participant,
            // Read before any session can start (§19.11): the database opened here is the one the
            // runtime keeps using for the process.
            paymentShownAt = { database.open(DatabaseOpener.Purpose.FOREGROUND)?.let(EntitlementWiring::paymentShownEpochSeconds) },
            visible = { entitlementWiring.onVisible() },
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
