package org.ghost.app

import org.ghost.crypto.bridge.DmNative
import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.ExpiryWake
import org.ghost.messaging.port.KeyWrapper
import org.ghost.network.EntitlementCrypto
import org.ghost.storage.Checkpoint
import org.ghost.sync.api.RelayEntry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.TimeUnit

/**
 * `MessagingWiring` over the **real** DM stack (Phase 9 design §13.7; slice S12): `MessagingRuntime`
 * with its actor, the real DM cryptography of `ghost-dm-host`, a real migrated database, and
 * `DirectoryEsSlots` resolving an accepted schedule against the relay directory — every port a
 * device has except the Keystore and `AlarmManager`, which are the platform's.
 *
 * It is what proves the wiring end to end: that a process start with a key reaches ACTIVATE through
 * the database-open time trigger alone (§21.12 point 2), with the slot table found through the
 * directory, and that lock and wipe take the facade down.
 */
class MessagingWiringRuntimeTest {

    private val week = 604_800L
    private val weekOrigin = 345_600L
    private val clock = TestClock(weekOrigin + 2_870 * week + 2 * 86_400L)
    private lateinit var db: TestDatabase
    private lateinit var wiring: MessagingWiring
    private var schedule: List<EntitlementCrypto.Slot>? = null

    private class PrefixWrapper : KeyWrapper {
        override fun wrap(key: ByteArray): ByteArray = PREFIX + key

        override fun unwrap(wrapped: ByteArray): ByteArray {
            require(wrapped.size > PREFIX.size && wrapped.copyOf(PREFIX.size).contentEquals(PREFIX)) { "not wrapped" }
            return wrapped.copyOfRange(PREFIX.size, wrapped.size)
        }

        companion object {
            val PREFIX = "GHOSTWRP".toByteArray(Charsets.US_ASCII)
        }
    }

    private class CountingRandom : DmRandom {
        private var n = 0

        override fun bytes(count: Int): ByteArray {
            val seed = n++
            val out = ByteArray(count)
            var at = 0
            var block = 0
            while (at < count) {
                val d = MessageDigest.getInstance("SHA-256").digest("wiring:$seed:$block".toByteArray())
                val k = minOf(d.size, count - at)
                System.arraycopy(d, 0, out, at, k)
                at += k
                block++
            }
            return out
        }
    }

    private class Inline : AbstractExecutorService() {
        override fun execute(command: Runnable) = command.run()

        override fun shutdown() = Unit

        override fun shutdownNow(): MutableList<Runnable> = ArrayList()

        override fun isShutdown(): Boolean = false

        override fun isTerminated(): Boolean = false

        override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = true
    }

    @Before
    fun setUp() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "ghost-dm-host is not on the classpath (-Dghost.dm.native); this test runs the real DM stack",
            !path.isNullOrEmpty() && DmNative.isAvailable(),
        )
        db = TestDatabase(clock)
        db.database.transaction { tx ->
            db.stores.relayDirectory.upsert(
                tx,
                (0 until 4).map { i -> RelayEntry(Onions.onion(i), Onions.operatorId(i % 2), RelayEntry.Source.CONFIG) },
            )
        }
        schedule = (0 until 4).map { i -> EntitlementCrypto.Slot(i, 0L, 0L, Onions.onion(i)) }
        val random = CountingRandom()
        wiring = MessagingWiring(
            controller = NullController,
            stores = { db.stores },
            whenStoresOpen = { block -> block() },
            stackFor = { stores ->
                val executor = stores.database.transaction { tx -> tx.sql }
                RuntimeStack(
                    MessagingRuntime(
                        stores = stores,
                        keys = DmKeys(PrefixWrapper(), random),
                        contentKeys = PrefixWrapper(),
                        esSlots = DirectoryEsSlots(stores.database) { schedule },
                        clock = clock,
                        random = random,
                        alarm = ExpiryWake.NONE,
                        checkpoint = { Checkpoint.truncate(executor) },
                    ),
                )
            },
            identity = { RootEntropy.fromRaw(ByteArray(32) { (it + 11).toByte() }) },
            primeSchedule = { },
            setAlarmHandler = { },
            hookExecutor = Inline(),
        )
    }

    @After
    fun tearDown() {
        if (::wiring.isInitialized) wiring.onWipe()
        if (::db.isInitialized) db.close()
    }

    private fun count(query: String): Long {
        var n = 0L
        db.sql.query(query) { n = it.long(0) }
        return n
    }

    @Test
    fun aProcessStartWithAKeyActivatesThroughTheDatabaseOpenAlone() {
        wiring.onProcessStart(keyExists = true)
        val messaging = requireNotNull(wiring.messaging) { "the first database open built the stack" }
        messaging.status() // queues behind the database-open pass on the actor
        assertEquals("dm_self", 1L, count("SELECT count(*) FROM dm_self"))
        assertEquals("X_0 and P_0", 2L, count("SELECT count(*) FROM dm_own_namespace"))
        assertEquals("the first bundle", 1L, count("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'bundle'"))
        assertTrue(
            "KEEPER installed the owner's READ credentials on the relays DirectoryEsSlots resolved",
            count("SELECT count(*) FROM relay_capability") > 0,
        )
        assertEquals(ActivationOutcome.ALREADY_ACTIVE, messaging.onActivated())
    }

    @Test
    fun theK20HookActivatesAndIsIdempotent() {
        wiring.onDatabaseOpen()
        wiring.messaging!!.status()
        wiring.activationHook.onIdentityActivated(restored = false)
        wiring.messaging!!.status()
        assertEquals(1L, count("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'bundle'"))
    }

    @Test
    fun anUnacceptedScheduleActivatesNothing() {
        // A schedule the entitlement engine refused (ES rule 5) is no slot table at all (§5.2).
        schedule = null
        wiring.onDatabaseOpen()
        wiring.messaging!!.status()
        assertEquals(0L, count("SELECT count(*) FROM dm_self"))
        assertEquals(ActivationOutcome.NO_RELAYS, wiring.messaging!!.onActivated())
    }

    @Test
    fun lockTakesTheCardAwayAndUnlockBringsTheSameOneBack() {
        wiring.onDatabaseOpen()
        val card = wiring.messaging!!.myCard()!!.card
        wiring.onLock()
        assertNull(wiring.messaging!!.myCard())
        assertEquals(DmKeys.Opened.OPENED, wiring.onUnlock())
        assertTrue(card.contentEquals(wiring.messaging!!.myCard()!!.card))
    }

    @Test
    fun wipeTakesTheFacadeDown() {
        wiring.onDatabaseOpen()
        assertNotNull(wiring.messaging)
        wiring.onWipe()
        assertNull(wiring.messaging)
    }

    private object NullController : org.ghost.sync.api.SyncController {
        override fun onAppForeground() = Unit
        override fun onAppBackground() = Unit
        override fun requestExpedite() = Unit
        override fun setPrivacyMode(mode: org.ghost.sync.api.PrivacyMode) = Unit
        override fun status(): org.ghost.sync.api.SyncStatus = throw UnsupportedOperationException()
        override fun onWipe() = Unit
        override fun setParticipant(p: org.ghost.sync.api.SessionParticipant?) = Unit
        override fun setConsumerTail(tail: org.ghost.sync.api.ConsumerTail?) = Unit
        override fun runUserIssuerCall(block: (org.ghost.sync.api.ParticipantSession) -> Unit) = Unit
        override fun onPaymentScreenShown() = Unit
        override fun onPaymentScreenHidden() = Unit
        override fun restorePaymentHold(lastShownEpochSeconds: Long) = Unit
    }
}
