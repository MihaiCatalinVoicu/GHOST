package org.ghost.entitlement.android

import android.os.SystemClock
import org.ghost.entitlement.api.Entitlement
import org.ghost.entitlement.api.IdentityActivationHook
import org.ghost.entitlement.engine.EngineDeps
import org.ghost.entitlement.engine.EntitlementEngine
import org.ghost.entitlement.port.EntitlementClock
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.port.SecureEntitlementRandom
import org.ghost.entitlement.port.SessionPort
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.entitlement.port.UserCallPort
import org.ghost.identity.IdentityManager
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.storage.SqlExecutor
import org.ghost.storage.queryLong
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncController
import org.ghost.sync.store.SyncStores

/**
 * The app's entitlement engine (design §11.1, D16): the native token crypto, the platform clocks, a
 * per-process PRF key, the identity and drop sealing over [IdentityManager], and the sync controller's
 * user calls and payment-screen hold. The app installs [participant] as the sync runtime's one
 * `SessionParticipant` at wiring, gives [entitlement] to Phase 13 and forwards visibility to [onVisible]
 * and [onHidden].
 */
class EntitlementWiring(
    controller: SyncController,
    stores: () -> SyncStores?,
    identity: IdentityManager,
    privacyMode: () -> PrivacyMode,
    private val whenStoresOpen: (block: () -> Unit) -> Unit,
    crypto: TokenCryptoPort = NativeTokenCrypto(),
    random: EntitlementRandom = SecureEntitlementRandom(),
) {
    /**
     * The K20 hook (Phase 9 design §13.4): the app sets it to the messaging layer's `ACTIVATE`
     * once both engines exist. Volatile and read through a supplier, because the two engines are
     * wired in one order and this reference points the other way; null until the app sets it, and
     * an activation that happens before then is picked up by the resumable activation of §21.12
     * point 2 at the next actor start or database open.
     */
    @Volatile
    var activationHook: IdentityActivationHook? = null

    private val engine = EntitlementEngine(
        EngineDeps(
            crypto,
            AndroidEntitlementClock,
            random,
            ManagerIdentity(identity),
            IdentitySeal(identity),
            ControllerUserCalls(controller),
            activationHook = { activationHook },
            privacyMode = privacyMode,
        ),
        stores,
    )

    val entitlement: Entitlement get() = engine

    /**
     * The Entitlement Schedule the open database accepted, for the DM layer's `EsSlots` (Phase 9
     * design §13.1, §5.2; slice S12). Opens the acceptance transaction the first time for a
     * database: never call it inside a transaction ([acceptedScheduleIfKnown] never opens one).
     */
    fun acceptedSchedule(): ScheduleSummary? = engine.acceptedSchedule()

    /** [acceptedSchedule] without a transaction: null until the engine accepted it for this database. */
    fun acceptedScheduleIfKnown(): ScheduleSummary? = engine.acceptedScheduleIfKnown()

    val participant: SessionParticipant = EntitlementParticipant(engine)

    /**
     * The app became visible: a pending onboarding trial retries as a user call (design §8.3). Called
     * on the main thread. The engine needs the sync runtime's stores, which at a cold start no session
     * has opened yet (and none opens while the payment hold lasts), so [whenStoresOpen] (the sync
     * runtime's `runWhenStoresOpen`) runs the engine's database and identity work on a thread of its own
     * once the runtime has opened the database.
     */
    fun onVisible() = whenStoresOpen { engine.onForeground() }

    /**
     * The app went to the background: an open payment screen's moment is kept as of now (§19.11).
     * Called on the main thread; the database write runs on a thread of its own.
     */
    fun onHidden() {
        Thread({ engine.onBackground() }, "ghost-entitlement-hidden").apply { isDaemon = true }.start()
    }

    override fun toString(): String = "EntitlementWiring"

    companion object {
        /**
         * The moment the payment screen was last visible (unix seconds, a whole minute), for
         * `SyncController.restorePaymentHold` at process start (§19.11); null when none is remembered.
         */
        fun paymentShownEpochSeconds(sql: SqlExecutor): Long? = sql.queryLong("SELECT payment_shown_minute FROM ent_state WHERE id = 1")
    }
}

/** Wall clock and elapsed realtime (counts deep sleep), like the sync runtime's clock. */
internal object AndroidEntitlementClock : EntitlementClock {
    override fun epochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)

    override fun monotonicMillis(): Long = SystemClock.elapsedRealtime()

    override fun sleep(millis: Long): Boolean = try {
        Thread.sleep(millis)
        true
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    override fun toString(): String = "AndroidEntitlementClock"
}

/** [UserCallPort] over the sync controller. */
internal class ControllerUserCalls(private val controller: SyncController) : UserCallPort {
    override fun runUserIssuerCall(block: (SessionPort) -> Unit) = controller.runUserIssuerCall { block(ParticipantSessionPort(it)) }

    override fun paymentScreenShown() = controller.onPaymentScreenShown()

    override fun paymentScreenHidden() = controller.onPaymentScreenHidden()

    override fun toString(): String = "ControllerUserCalls"
}
