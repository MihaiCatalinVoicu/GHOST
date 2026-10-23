package org.ghost.staging

import java.io.File
import java.security.SecureRandom
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.ghost.entitlement.android.ManagerIdentity
import org.ghost.entitlement.android.IdentitySeal
import org.ghost.entitlement.android.NativeTokenCrypto
import org.ghost.entitlement.engine.EngineDeps
import org.ghost.entitlement.engine.EntitlementEngine
import org.ghost.entitlement.port.EntitlementClock
import org.ghost.entitlement.port.SecureEntitlementRandom
import org.ghost.entitlement.port.UserCallPort
import org.ghost.entitlement.android.EntitlementParticipant
import org.ghost.identity.IdentityManager
import org.ghost.identity.SecretWrapper
import org.ghost.identity.WrappedSecretStore
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.ExpiryWake
import org.ghost.messaging.port.KeyWrapper
import org.ghost.storage.Checkpoint
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.SqlExecutor
import org.ghost.sync.android.DatabaseOpener
import org.ghost.sync.android.HostSync
import org.ghost.sync.android.AndroidSyncController
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.port.WakeScheduler
import org.ghost.sync.store.SyncStores
import org.ghost.network.OnionAddress

/**
 * The staging world (tools/staging-harness/README.md): the app's real engine stack - sync runtime
 * over the real Tor transport, entitlement engine over the real native token crypto, identity over
 * a software wrapper - against the live staging deployment. One instance per identity, rooted at
 * [stateDir]; every stage of the harness is idempotent and resumable (design §21.12).
 */
class StagingWorld(private val stateDir: File) : AutoCloseable {
    private val dbFile = File(stateDir, "ghost.db")
    private val secretsDir = File(stateDir, "identity")

    init {
        stateDir.mkdirs()
        secretsDir.mkdirs()
    }

    /** The one JDBC executor for this identity's database; the opener returns it while open. */
    val sql: JdbcSqlExecutor = JdbcSqlExecutor(dbFile.absolutePath)

    private val database = SyncDatabase(sql)

    val clock: EntitlementClock = object : EntitlementClock {
        override fun epochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)
        override fun monotonicMillis(): Long = (System.nanoTime() - START_NANOS) / 1_000_000
        override fun sleep(millis: Long): Boolean = try {
            Thread.sleep(millis); true
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt(); false
        }
        override fun toString(): String = "StagingClock"
    }

    private val syncClock = object : org.ghost.sync.port.SyncClock {
        override fun epochSeconds(): Long = clock.epochSeconds()
        override fun monotonicMillis(): Long = clock.monotonicMillis()
        override fun toString(): String = "StagingClock"
    }

    private val opener = object : DatabaseOpener {
        override fun keyExists(): Boolean = true
        override fun open(purpose: DatabaseOpener.Purpose): org.ghost.storage.SqlExecutor? = sql
    }

    private val stores = SyncStores(database, syncClock, KeyedRandomSources()) { PrivacyMode.STANDARD }

    private val identity = IdentityManager(JvmSecretWrapper(secretsDir), FileSecretStore(secretsDir), SecureRandom())

    /** The process's one controller (HostSync: real Tor transport, no Context, no JobScheduler). */
    val controller: AndroidSyncController = HostSync.controller(
        torState = File(stateDir, "tor/state"),
        torCache = File(stateDir, "tor/cache"),
        opener = opener,
    )

    private val engine = EntitlementEngine(
        EngineDeps(
            NativeTokenCrypto(),
            clock,
            SecureEntitlementRandom(),
            ManagerIdentity(identity),
            IdentitySeal(identity),
            ControllerUserCalls(controller),
            activationHook = { null },
            privacyMode = { PrivacyMode.STANDARD },
        ),
        { stores },
    )

    /** The engine as the sync runtime's one session participant. */
    val participant: EntitlementParticipant = EntitlementParticipant(engine)

    /** The app's foreground hook (§8.3 step 4): a pending onboarding trial retries its user call. */
    fun foreground() = engine.onForeground()

    val entitlement: org.ghost.entitlement.api.Entitlement get() = engine

    /**
     * The app's participant plus the DM layer's relay-session-start time trigger in front of it
     * (GhostApp's `messagingWiring.sessionHooks(entitlementWiring.participant)`, Phase 9 §21.9
     * rule 1). The DM stack builds lazily, so the first session's start also builds it.
     */
    private val combinedParticipant = object : SessionParticipant {
        override fun onRelaySession(session: ParticipantSession) {
            dm.onTimeTrigger(sessionStart = true)
            participant.onRelaySession(session)
        }

        override fun onQuietRun(session: ParticipantSession) = participant.onQuietRun(session)
        override fun toString() = "StagingParticipant"
    }

    init {
        stateDir.mkdirs()
        MigrationRunner(sql).migrate()
        seedRelayDirectory()
        controller.setParticipant(combinedParticipant)
        controller.onAppForeground()
    }

    // -------------------------------------------------------------- DM stack (Phase 9 wiring)

    private val dmRandom = object : DmRandom {
        private val sr = SecureRandom()
        override fun bytes(count: Int): ByteArray = sr.generateSeed(count)
    }

    private val dmClock = object : DmClock {
        override fun nowEpochSeconds(): Long = Math.floorDiv(System.currentTimeMillis(), 1000L)
        override fun monotonicMillis(): Long = (System.nanoTime() - START_NANOS) / 1_000_000
        override fun toString() = "StagingDmClock"
    }

    /**
     * `GhostApp.dmStack`'s recipe on JVM ports: the one `MessagingRuntime` over this world's own
     * stores (a second database object would interleave transactions and never hear a hint), the
     * software wrapper for both device keys, the ES slot table read from the relay directory by
     * `:app`'s DirectoryEsSlots rule, no wake scheduler, and the checkpoint over the database's own
     * connection. Built lazily so the executor is taken after migrations.
     */
    val dm: MessagingRuntime by lazy {
        val executor = database.transaction { tx -> tx.sql }
        val built = MessagingRuntime(
            stores = stores,
            keys = DmKeys(stateKeys = JvmSecretWrapper(secretsDir), random = dmRandom),
            contentKeys = JvmSecretWrapper(secretsDir),
            esSlots = stagingEsSlots(executor),
            clock = dmClock,
            random = dmRandom,
            alarm = ExpiryWake.NONE,
            checkpoint = DmCheckpoint { Checkpoint.truncate(executor) },
        )
        database.inbox.setListener(built.listener)
        controller.setConsumerTail(built.consumerTail)
        built.onTimeTrigger()
        built
    }

    /** The K20 hook's one turn (§8.3): opens the DM context from this identity and ACTIVATEs it. */
    fun activateDm(): ActivationOutcome =
        dm.reopenAndActivate({ identity.unlock() }, restored = false, wanted = { true })
            ?: ActivationOutcome.CRYPTO_UNAVAILABLE

    /** The DirectoryEsSlots mapping (its companion is `:app`-internal): slot -> serving relay. */
    private fun stagingEsSlots(executor: SqlExecutor): EsSlots {
        val scheduleSlots = org.ghost.entitlement.android.NativeTokenCrypto().scheduleSummary().slots
        return EsSlots { week ->
            val relays = if (database.inTransaction) activeRelays(executor)
            else database.transaction { tx -> activeRelays(tx.sql) }
            val out = ArrayList<EsSlot>()
            for (slot in scheduleSlots.filter { it.validIn(week) }.sortedBy { it.slot }) {
                val exact = relays.filter { it.address == slot.onion }
                val chosen = when {
                    exact.size == 1 -> exact.single()
                    exact.isEmpty() -> relays.filter { it.address.host == slot.onion.host }.singleOrNull()
                    else -> null
                } ?: continue
                if (out.any { it.slot == slot.slot }) continue
                out += EsSlot(slot.slot, chosen.id, chosen.operatorId)
            }
            out
        }
    }

    private class DirRelay(val id: org.ghost.sync.api.RelayId, val address: org.ghost.network.OnionAddress, operatorId: ByteArray) {
        private val operator = operatorId.copyOf()
        val operatorId: ByteArray get() = operator.copyOf()
    }

    private fun activeRelays(sql: SqlExecutor): List<DirRelay> {
        val out = ArrayList<DirRelay>()
        sql.query(
            "SELECT relay_id, onion_address, operator_id FROM relay_directory WHERE state = 'active' ORDER BY relay_id",
        ) { row -> out += DirRelay(org.ghost.sync.api.RelayId(row.long(0)), org.ghost.network.OnionAddress.parse(row.string(1)), row.blob(2)) }
        return out
    }

    /** The three real staging relays of the accepted ES (relay-directory.txt), Source.CONFIG. */
    private fun seedRelayDirectory() {
        val entries = listOf(
            Triple(StagingConfig.RELAY_A, "22169c983b89a692d5d1b2c36b251b28", 0),
            Triple(StagingConfig.RELAY_B, "19e423fe4ac8f8c5dbfafa5b3cd2cab0", 1),
            Triple(StagingConfig.RELAY_C, "be18a81f6242aeb5e6b7e667e9f9a4fd", 2),
        ).map { (onion, op, _) ->
            RelayEntry(OnionAddress.parse("$onion:443"), hex(op), RelayEntry.Source.CONFIG)
        }
        val relayIds = database.transaction { tx -> stores.relayDirectory.upsert(tx, entries) }
        check(relayIds.size == 3) { "staging relay seeding refused" }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    fun hasIdentity(): Boolean = identity.hasIdentity()

    /** Genesis bootstrap (design §8.6, E6): no trial, no access - the first pack is bought later. */
    fun genesis() {
        check(!identity.hasIdentity()) { "an identity already exists in $stateDir" }
        identity.create(IdentityManager.Activation.Genesis(policyAcknowledged = true)).root.zeroize()
    }

    override fun close() = sql.close()

    private companion object {
        val START_NANOS: Long = System.nanoTime()
    }
}

/** [UserCallPort] over the sync controller, like the app's EntitlementWiring. */
private class ControllerUserCalls(private val controller: SyncController) : UserCallPort {
    override fun runUserIssuerCall(block: (org.ghost.entitlement.port.SessionPort) -> Unit) =
        controller.runUserIssuerCall { block(org.ghost.entitlement.android.ParticipantSessionPort(it)) }

    override fun paymentScreenShown() = controller.onPaymentScreenShown()
    override fun paymentScreenHidden() = controller.onPaymentScreenHidden()
    override fun toString(): String = "ControllerUserCalls"
}

/** A software [SecretWrapper] for the harness (the app uses Android Keystore): AES-256-GCM with a
 * random data-encryption key kept beside the state, wrapped by a local key-encryption key file. */
private class JvmSecretWrapper(dir: File) : SecretWrapper, KeyWrapper {
    private val dek: ByteArray

    init {
        dir.mkdirs()
        val kekFile = File(dir, "kek.bin")
        val kek = if (kekFile.exists()) kekFile.readBytes() else SecureRandom().generateSeed(32).also { kekFile.writeBytes(it) }
        val dekFile = File(dir, "dek.bin")
        dek = if (dekFile.exists()) {
            val raw = dekFile.readBytes()
            unwrap(raw, kek)
        } else {
            SecureRandom().generateSeed(32).also { dekFile.writeBytes(wrap(it, kek)) }
        }
    }

    override fun wrap(secret: ByteArray): ByteArray = wrap(secret, dek)

    override fun unwrap(wrapped: ByteArray): ByteArray = unwrap(wrapped, dek)

    private fun wrap(secret: ByteArray, key: ByteArray): ByteArray {
        val iv = SecureRandom().generateSeed(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return iv + c.doFinal(secret)
    }

    private fun unwrap(wrapped: ByteArray, key: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, wrapped.copyOfRange(0, 12)))
        return c.doFinal(wrapped.copyOfRange(12, wrapped.size))
    }
}

/** A file-backed [WrappedSecretStore] for the harness (the app uses Keystore-bound envelopes). */
private class FileSecretStore(private val dir: File) : WrappedSecretStore {
    init {
        dir.mkdirs()
    }

    override fun write(name: String, wrapped: ByteArray) {
        File(dir, "$name.env").writeBytes(wrapped)
    }

    override fun read(name: String): ByteArray? {
        val f = File(dir, "$name.env")
        return if (f.exists()) f.readBytes() else null
    }

    override fun delete(name: String) {
        File(dir, "$name.env").delete()
    }
}
