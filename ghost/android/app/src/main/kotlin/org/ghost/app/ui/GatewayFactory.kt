package org.ghost.app.ui

import org.ghost.identity.IdentityManager
import org.ghost.entitlement.api.Entitlement
import org.ghost.storage.SqlExecutor
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.LockGateway
import org.ghost.ui.gateway.SettingsGateway
import org.ghost.ui.gateway.UpdateGateway

/**
 * The composition root of the gateway adapters (design §3.1, §3.2): one factory the app builds
 * once, the UI's only door to the engines. [update] is null in a build without :update (Q39,
 * F14 §8.2 (c)) — a store flavor gets no update gateway.
 *
 * **Build-type twin** (the DmBranch pattern): `src/release` and `src/debug` define this object
 * with the real adapters and nothing else; `src/gate` defines one that may serve a fixture to
 * the emulator's platform suites (§12.3). G-DM5 treats the three as one declaration and refuses
 * in the release halves anything only the gate half names.
 */
interface GatewaySet {
    fun lock(): LockGateway
    fun identity(): IdentityGateway
    fun settings(): SettingsGateway
    fun update(): UpdateGateway?
    fun access(): org.ghost.ui.gateway.AccessGateway
    fun dm(): org.ghost.ui.gateway.DmGateway
    fun contacts(): org.ghost.ui.gateway.ContactGateway
    fun channel(): org.ghost.ui.gateway.ChannelGateway
    fun media(): org.ghost.ui.gateway.MediaGateway
    fun wipe(): org.ghost.ui.gateway.WipeGateway
}

/** The seams the adapters need, provided by GhostApp. */
class GatewayDeps(
    val appContext: android.content.Context,
    val executor: () -> SqlExecutor?,
    val identity: () -> IdentityManager,
    val entitlement: () -> Entitlement?,
    val messaging: () -> org.ghost.messaging.api.Messaging?,
    val channels: () -> org.ghost.messaging.api.Channels?,
    val updates: () -> org.ghost.update.Updates?,
    val wipeController: () -> WipeController,
    val createDatabaseKey: () -> ByteArray,
    val genesisPolicyOn: Boolean,
    val strongBox: Boolean,
    val nowUnixSeconds: () -> Long,
) {
    val settingsStore: SettingsStore = SettingsStore(executor)
    val lock: LockGatewayAdapter = LockGatewayAdapter(
        executor = executor,
        strongBox = strongBox,
        settings = settingsStore,
    )
    val identityGateway: IdentityGatewayAdapter = IdentityGatewayAdapter(
        identity = identity,
        entitlement = entitlement,
        createKey = createDatabaseKey,
        genesisPolicyOn = genesisPolicyOn,
        nowUnixSeconds = nowUnixSeconds,
        random = java.security.SecureRandom(),
    )
    val accessGateway: AccessGatewayAdapter = AccessGatewayAdapter(entitlement)
    val dmGateway: DmGatewayAdapter = DmGatewayAdapter(messaging)
    val channelGateway: ChannelGatewayAdapter = ChannelGatewayAdapter(
        facade = channels,
        wordList = { org.ghost.identity.Bip39.wordlist },
    )
    val mediaGateway: MediaGatewayAdapter = MediaGatewayAdapter(appContext, messaging)
    val updateGateway: UpdateGatewayAdapter = UpdateGatewayAdapter(updates)
    val wipeGateway: WipeGatewayAdapter = WipeGatewayAdapter(
        controller = wipeController(),
        wipeThread = java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "ghost-wipe").apply { isDaemon = true }
        },
    )
}

/** The real gateway surface shared by release, debug and the inert gate fixture wrapper. */
class RealGatewaySet(private val deps: GatewayDeps) : GatewaySet {
    override fun lock(): LockGateway = deps.lock
    override fun identity(): IdentityGateway = deps.identityGateway
    override fun settings(): SettingsGateway = SettingsGatewayAdapter(deps.settingsStore)
    override fun update(): UpdateGateway? = deps.updateGateway
    override fun access(): org.ghost.ui.gateway.AccessGateway = deps.accessGateway
    override fun dm(): org.ghost.ui.gateway.DmGateway = deps.dmGateway
    override fun contacts(): org.ghost.ui.gateway.ContactGateway = deps.dmGateway
    override fun channel(): org.ghost.ui.gateway.ChannelGateway = deps.channelGateway
    override fun media(): org.ghost.ui.gateway.MediaGateway = deps.mediaGateway
    override fun wipe(): org.ghost.ui.gateway.WipeGateway = deps.wipeGateway
}
