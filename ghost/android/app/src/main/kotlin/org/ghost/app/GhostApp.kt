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
import org.ghost.identity.RootEntropy
import org.ghost.messaging.android.ExpiryAlarm
import org.ghost.messaging.android.ExpiryAlarmReceiver
import org.ghost.messaging.android.KeystoreContentKeyWrapper
import org.ghost.messaging.android.KeystoreStateKeyWrapper
import org.ghost.messaging.api.Messaging
import org.ghost.app.media.MediaWiring
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.storage.Checkpoint
import org.ghost.storage.DatabaseKeyProvider
import org.ghost.sync.android.AndroidSyncController
import org.ghost.sync.android.DatabaseOpener
import org.ghost.sync.android.SyncHost
import org.ghost.sync.store.SyncStores
import java.security.GeneralSecurityException

/**
 * The application process (design §5.4, ADR-20; Phase 8 design §11.1, §11.6; Phase 9 design §13.7):
 * creates the one sync controller and the entitlement engine, installs the engine as the
 * controller's one session participant, wires the DM layer beside them and ties all three to the
 * process lifecycle. Sync does nothing until a database key envelope exists; onboarding (Phase 13)
 * creates the key and then calls [onDatabaseKeyCreated]. The decisions themselves live in
 * [SyncWiring] and [MessagingWiring].
 */
class GhostApp : Application(), SyncHost {
    private val keys: DatabaseKeyProvider by lazy { DatabaseKeyProvider(AndroidKeystoreWrapper(), NoBackupFileSecretStore(this)) }

    private val database: AppDatabase by lazy { AppDatabase(this, keys, DatabaseAccess.AUTH_BOUND) }

    override val syncController: AndroidSyncController by lazy { AndroidSyncController.create(this, database) }

    private val identity: IdentityManager by lazy { IdentityManager(AndroidKeystoreWrapper(), NoBackupFileSecretStore(this)) }

    private val entitlementWiring: EntitlementWiring by lazy {
        EntitlementWiring(
            syncController, { syncController.stores }, identity, privacyMode = { syncController.privacyMode },
            whenStoresOpen = syncController::runWhenStoresOpen,
        )
    }

    /** The entitlement facade for Phase 13 (design §11.2). */
    val entitlement: Entitlement get() = entitlementWiring.entitlement

    /**
     * The DM layer (Phase 9 design §13.7 "Wiring"; slice S12). Every Android port of the DM stack
     * is chosen here and nowhere else: the Keystore wrappers of the two device keys with the
     * database key's authentication policy (§13.8), the one inexact alarm (§10.7), the checkpoint
     * over the database's own connection, the accepted Entitlement Schedule's slot table (§5.2), and
     * the platform clock and CSPRNG.
     */
    internal val messagingWiring: MessagingWiring by lazy {
        MessagingWiring(
            controller = syncController,
            stores = { syncController.stores },
            whenStoresOpen = syncController::runWhenStoresOpen,
            stackFor = ::dmStack,
            identity = ::storedIdentity,
            primeSchedule = { entitlementWiring.acceptedSchedule() },
            setAlarmHandler = { handler -> ExpiryAlarmReceiver.onAlarm = handler },
            cancelAlarm = { ExpiryAlarm(this).wakeIn(null) },
        )
    }

    /** The DM facade of §13.2 for Phase 13; null before the first database open. */
    val messaging: Messaging? get() = messagingWiring.messaging

    private fun dmStack(stores: SyncStores): DmStack {
        // The database's own connection, read outside any transaction: the checkpoint must run
        // outside one (§10.7), on the connection the sync runtime opened.
        val executor = stores.database.transaction { tx -> tx.sql }
        val random = SecureDmRandom()
        return RuntimeStack(
            MessagingRuntime(
                stores = stores,
                // Phase 11 §13.7's sender pipeline, wired where every Android port lives
                // (slice S5): the sandbox, the transcoder, the ciphertext store under
                // `noBackupFilesDir/m`. Null where the pieces cannot load — the facade then
                // answers CRYPTO_UNAVAILABLE.
                mediaPipeline = MediaWiring.pipelinePorts(this, noBackupFilesDir),
                keys = DmKeys(
                    stateKeys = KeystoreStateKeyWrapper(DatabaseAccess.AUTH_BOUND),
                    random = random,
                    // `DmBranch` is defined per build type: the plain derivation in `src/release`
                    // and `src/debug`, the debug key-change hook in `src/gate` only (§21.13 point 7,
                    // gate G-DM5). An argument fixed at build time, not a member a subclass could
                    // override: the release carries no such seam (S12 review).
                    messagingBranch = DmBranch.forApp(this),
                ),
                contentKeys = KeystoreContentKeyWrapper(DatabaseAccess.AUTH_BOUND),
                esSlots = DirectoryEsSlots(stores.database) { entitlementWiring.acceptedScheduleIfKnown()?.slots },
                clock = AndroidDmClock,
                random = random,
                alarm = ExpiryAlarm(this),
                checkpoint = DmCheckpoint { Checkpoint.truncate(executor) },
            ),
        )
    }

    /**
     * The stored identity, unwrapped for the DM context; null when there is none or when the
     * Keystore cannot open it now (an authentication-bound key outside its window, a device reset):
     * the DM layer then answers `CRYPTO_UNAVAILABLE` and tries again at the next unlock.
     */
    private fun storedIdentity(): RootEntropy? {
        if (!identity.hasIdentity()) return null
        return try {
            identity.unlock()
        } catch (e: GeneralSecurityException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } catch (e: IllegalStateException) {
            // Wiped between the check and the unlock.
            null
        }
    }

    private val wiring: SyncWiring by lazy {
        SyncWiring(
            keyExists = { keys.exists() },
            controller = syncController,
            ensurePeriodic = { syncController.ensurePeriodic() },
            databaseAvailable = { syncController.onDatabaseAvailable() },
            // The entitlement engine stays the one participant (Phase 8 design §11.6); the DM layer
            // adds its relay-session-start time trigger in front of it (Phase 9 design §21.9 rule 1).
            participant = messagingWiring.sessionHooks(entitlementWiring.participant),
            // Read on the sync runtime thread before any session can start (§19.11): the database
            // opened there is the one the runtime keeps using for the process.
            paymentShownAt = { database.open(DatabaseOpener.Purpose.FOREGROUND)?.let(EntitlementWiring::paymentShownEpochSeconds) },
            restorePaymentHold = syncController::restorePaymentHoldFrom,
            visible = {
                entitlementWiring.onVisible()
                messagingWiring.onVisible()
            },
            hidden = { entitlementWiring.onHidden() },
        )
    }

    override fun onCreate() {
        super.onCreate()
        // Phase 11 design §9.2 (V-M19): Android instantiates the Application in every process,
        // including the isolated `:mdec` decoding service's. `wiring.onProcessStart()` and
        // `messagingWiring.onProcessStart` open no-backup files, the Keystore and system
        // services an isolated process may not touch, so a bind would die before connecting
        // (measured in S0: no onServiceConnected within 15 s). Nothing of GHOST runs here:
        // `MediaDecodeService` uses only platform decoder APIs. Mutant MC-M23 removes this.
        if (android.os.Process.isIsolated()) return
        // The K20 hook (Phase 9 design §13.4) before anything can activate an identity.
        entitlementWiring.activationHook = messagingWiring.activationHook
        wiring.onProcessStart()
        messagingWiring.onProcessStart(keyExists = keys.exists())
        // ON_START when the first activity starts, ON_STOP shortly after the last one stops. A
        // process started for the background job has no activity and never sees ON_START.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = wiring.onVisible()

            override fun onStop(owner: LifecycleOwner) = wiring.onHidden()
        })
    }

    /** Onboarding calls this right after the database key is first created (design §11.2 #17). */
    fun onDatabaseKeyCreated() {
        wiring.onKeyCreated()
        messagingWiring.onKeyCreated()
    }

    /**
     * The app locked (Phase 13's lock screen, FR-1.7): the DM context closes and its keys are
     * zeroised (Phase 9 design §2.5, §13.7).
     */
    fun onLock() = messagingWiring.onLock()

    /** The app unlocked: the DM context is reopened from the stored identity. */
    fun onUnlock() = messagingWiring.onUnlock()

    /**
     * Local data is being wiped (design §11.2 #17; Phase 13's wipe flow): the DM layer first —
     * context closed, keys zeroised, timer and alarm cancelled (Phase 9 design §13.7, §10.7) — then
     * the sync controller, which cancels the periodic job and drops the stores. The DM half waits
     * for the pass in flight, so the wipe flow calls this off the main thread.
     *
     * [onLock], [onUnlock] and this have no caller in the tree yet: the lock screen and the wipe
     * flow are Phase 13's (§22.17).
     */
    fun onWipe() {
        messagingWiring.onWipe()
        syncController.onWipe()
    }
}
