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
import org.ghost.app.ui.AppPresence
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
        val dmKeys = DmKeys(
            stateKeys = KeystoreStateKeyWrapper(DatabaseAccess.AUTH_BOUND),
            random = random,
            // `DmBranch` is defined per build type: the plain derivation in `src/release`
            // and `src/debug`, the debug key-change hook in `src/gate` only (§21.13 point 7,
            // gate G-DM5). An argument fixed at build time, not a member a subclass could
            // override: the release carries no such seam (S12 review).
            messagingBranch = DmBranch.forApp(this),
        )
        return RuntimeStack(
            MessagingRuntime(
                stores = stores,
                // Phase 11 §13.7's media pipelines, wired where every Android port lives
                // (slices S5/S6): the sandbox, the transcoder, the ciphertext store under
                // `noBackupFilesDir/m`, the reader surface over the DM context. Null where the
                // pieces cannot load — the facade then answers CRYPTO_UNAVAILABLE.
                mediaPipeline = MediaWiring.pipelinePorts(this, noBackupFilesDir, org.ghost.messaging.port.NativeMediaReaders(dmKeys)),
                keys = dmKeys,
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
            // Phase 13 §3.5 (X-U14): ON_START runs only the local step (the DM stack's build);
            // the entitlement engine's foreground hook joins the session start at INTERACTIVE.
            visible = messagingWiring::onVisible,
            foregroundHook = entitlementWiring::onVisible,
            hidden = {
                entitlementWiring.onHidden()
                messagingWiring.onHidden()
            },
        )
    }

    /**
     * Phase 13 §3.5 (D33, X-U14): sessions follow INTERACTIVE. The process observer keeps only the
     * local step at ON_START; `SyncController.onAppForeground()` and the entitlement engine's
     * foreground hook run when presence becomes INTERACTIVE — after the unlock and the resume, so
     * nothing syncs while only the lock screen shows. A link-opened app waits a further U[0, 2 min]
     * at the first session (the LinkIntake half, S2's wiring).
     */
    val presence: AppPresence by lazy {
        AppPresence(object : AppPresence.Listener {
            override fun onInteractive() = wiring.onInteractive()

            override fun onNotInteractive() = wiring.onHidden()
        })
    }

    /** The notifier, cancelled at lock (§4.6). */
    private var notifier: org.ghost.app.ui.GhostNotifier? = null

    private fun toHubKind(kind: org.ghost.messaging.api.ChangeKind): org.ghost.app.ui.ChangeHub.ChangeKind =
        when (kind) {
            org.ghost.messaging.api.ChangeKind.CONTACTS -> org.ghost.app.ui.ChangeHub.ChangeKind.CONTACTS
            org.ghost.messaging.api.ChangeKind.MESSAGES -> org.ghost.app.ui.ChangeHub.ChangeKind.MESSAGES
            org.ghost.messaging.api.ChangeKind.REQUESTS -> org.ghost.app.ui.ChangeHub.ChangeKind.REQUESTS
            org.ghost.messaging.api.ChangeKind.TRUST -> org.ghost.app.ui.ChangeHub.ChangeKind.TRUST
            org.ghost.messaging.api.ChangeKind.OUTCOMES -> org.ghost.app.ui.ChangeHub.ChangeKind.OUTCOMES
            org.ghost.messaging.api.ChangeKind.STATUS -> org.ghost.app.ui.ChangeHub.ChangeKind.STATUS
        }

    override fun onCreate() {
        super.onCreate()        // Phase 11 design §9.2 (V-M19): Android instantiates the Application in every process,
        // including the isolated `:mdec` decoding service's. `wiring.onProcessStart()` and
        // `messagingWiring.onProcessStart` open no-backup files, the Keystore and system
        // services an isolated process may not touch, so a bind would die before connecting
        // (measured in S0: no onServiceConnected within 15 s). Nothing of GHOST runs here:
        // `MediaDecodeService` uses only platform decoder APIs. Mutant MC-M23 removes this.
        if (android.os.Process.isIsolated()) return
        // Phase 13 §5.5, CS-U1: a crash between W3 and W6 leaves data files without the key
        // envelope. The resumption tail (W4-W6) runs silently before any wiring - W5's file
        // deletion and W6's notification/clipboard cleanups, never W3's envelopes (the key is
        // already gone; that was the crash point). [WipeController.needsResumption] is the
        // predicate; at this stage no stacks run, so W4 is a no-op.
        val resumption = org.ghost.app.ui.WipeController(
            files = org.ghost.app.ui.ContextFilesystem(dataDir),
            stopStacks = {},
            deleteEnvelopes = {},
            deleteKeystoreAliases = {},
            cancelNotifications = {},
            clearClipboard = {},
            exitProcess = {},
        )
        if (resumption.needsResumption()) {
            resumption.deleteFiles()
            resumption.resumptionCleanups()
        }
        // The K20 hook (Phase 9 design §13.4) before anything can activate an identity.
        entitlementWiring.activationHook = messagingWiring.activationHook
        wiring.onProcessStart()
        messagingWiring.onProcessStart(keyExists = keys.exists())
        // Phase 13 §3.6, §4.6: the UI's hint listener (content-free kinds into the ChangeHub) and
        // the one constant notification, both held by the wiring across database reopens. The
        // notifier cancels at lock; the listener's hints ride the actor thread's hand-off rule.
        messagingWiring.setUiListener(org.ghost.messaging.api.MessagingListener { kinds ->
            kinds.forEach { kind -> org.ghost.app.ui.ChangeHub.hint(toHubKind(kind)) }
        })
        val notifier = org.ghost.app.ui.GhostNotifier(
            context = this,
            interactive = { presence.presence == org.ghost.app.ui.AppPresence.Presence.INTERACTIVE },
            lockScreenAllowed = { org.ghost.app.ui.GhostNotifier.countOption },
        )
        messagingWiring.setNotifier(notifier)
        this.notifier = notifier
        // ON_START when the first activity starts, ON_STOP shortly after the last one stops. A
        // process started for the background job has no activity and never sees ON_START.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            // X-U14: ON_START keeps only the local step; the foreground session waits for
            // INTERACTIVE (the unlock + resume), which the activity reports through [presence].
            override fun onStart(owner: LifecycleOwner) = wiring.onWindowVisible()

            override fun onStop(owner: LifecycleOwner) = wiring.onHidden()
        })
    }

    /**
     * Phase 13 §3.6: the missing creator of the database key envelope (§3.2's IdentityGateway
     * calls this at onboarding's step 2). The returned array belongs to the caller: the gateway
     * zeroes it and then runs [onDatabaseKeyCreated] (D18's order).
     */
    fun createDatabaseKey(): ByteArray {
        val key = keys.getOrCreate()
        onDatabaseKeyCreated()
        return key
    }

    /** Onboarding calls this right after the database key is first created (design §11.2 #17). */
    fun onDatabaseKeyCreated() {
        wiring.onKeyCreated()
        messagingWiring.onKeyCreated()
    }

    /**
     * The system's memory trim (ComponentCallbacks2): at TRIM_MEMORY_UI_HIDDEN the media layer's
     * RAM preview cache goes (Phase 11 design §10.5, slice S7) — pixels nobody is looking at.
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level == android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            messagingWiring.onTrimMemory()
        }
    }

    /**
     * The app locked (Phase 13's lock screen, FR-1.7): presence leaves INTERACTIVE (X-U14), the
     * DM context closes and its keys are zeroised (Phase 9 design §2.5, §13.7).
     */
    fun onLock() {
        presence.onLocked()
        messagingWiring.onLock()
        notifier?.cancelAll() // §4.6: nothing waits on the lock screen
    }

    /** The app unlocked: presence becomes INTERACTIVE when the activity also resumes (X-U14). */
    fun onUnlock() {
        presence.onUnlocked()
        messagingWiring.onUnlock()
    }

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
