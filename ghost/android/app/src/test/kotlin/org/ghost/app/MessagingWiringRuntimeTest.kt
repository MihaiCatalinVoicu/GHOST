package org.ghost.app

import org.ghost.crypto.bridge.DmNative
import org.ghost.identity.DerivationLabels
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
 * directory, that lock and wipe take the facade down and stay down (S12 review), and that the
 * `gate` key change reactivates through the restore variant.
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

    /** The alarm port: every request, in order, from any thread (null is a cancel). */
    private class RecordingAlarm : ExpiryWake {
        val requested: MutableList<Long?> = java.util.Collections.synchronizedList(ArrayList())

        override fun wakeIn(delaySeconds: Long?) {
            requested += delaySeconds
        }
    }

    private val alarm = RecordingAlarm()
    private var wiringCancels = 0

    /**
     * The `gate` key-change hook's shape (`GateKeyChange.alternateBranch`, which is in
     * `crypto-bridge/src/gate` and so not on every variant's test classpath): another MESSAGING
     * branch from the same root, switched by a flag, as `src/gate`'s `DmBranch` switches it.
     */
    @Volatile
    private var keyChanged = false

    private fun branch(root: RootEntropy): ByteArray {
        val derived = root.deriveBranch(DerivationLabels.MESSAGING)
        if (!keyChanged) return derived
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(derived, "HmacSHA256"))
        return mac.doFinal("ghost/v1/gate/key-change".toByteArray(Charsets.US_ASCII)).also { derived.fill(0) }
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
                        keys = DmKeys(PrefixWrapper(), random, messagingBranch = ::branch),
                        contentKeys = PrefixWrapper(),
                        esSlots = DirectoryEsSlots(stores.database) { schedule },
                        clock = clock,
                        random = random,
                        alarm = alarm,
                        checkpoint = { Checkpoint.truncate(executor) },
                    ),
                )
            },
            identity = { RootEntropy.fromRaw(ByteArray(32) { (it + 11).toByte() }) },
            primeSchedule = { },
            setAlarmHandler = { },
            cancelAlarm = { wiringCancels++ },
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

    /** `dm_own_namespace`'s namespaces, as hex. */
    private fun ownNamespaces(): Set<String> {
        val out = HashSet<String>()
        db.sql.query("SELECT namespace_id FROM dm_own_namespace") { row ->
            out += row.blob(0).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }
        return out
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
        // The close is posted; the facade call queues behind it on the actor.
        assertNull(wiring.messaging!!.myCard())
        wiring.onUnlock()
        assertTrue(card.contentEquals(wiring.messaging!!.myCard()!!.card))
    }

    @Test
    fun aLockIsNotUndoneByTheK20Hook() {
        wiring.onDatabaseOpen()
        wiring.messaging!!.status()
        wiring.onLock()
        // S12 review: the hook's reopen used to run whatever the app had said.
        wiring.activationHook.onIdentityActivated(restored = false)
        assertNull("the context stays closed", wiring.messaging!!.myCard())
    }

    @Test
    fun wipeTakesTheFacadeDown() {
        wiring.onDatabaseOpen()
        assertNotNull(wiring.messaging)
        wiring.onWipe()
        assertNull(wiring.messaging)
    }

    @Test
    fun aWipeIsFinalAndLeavesTheAlarmCancelled() {
        wiring.onDatabaseOpen()
        val old = requireNotNull(wiring.messaging)
        old.status()
        assertTrue("the database-open pass rescheduled the alarm (§10.7 trigger 5)", alarm.requested.isNotEmpty())
        wiring.onWipe()
        assertNull("§10.7: the stack's last turn cancelled the alarm", alarm.requested.last())
        assertEquals("and the wiring cancelled it as well", 1, wiringCancels)
        // The stores are still open (the sync runtime drops them after this): no trigger may build
        // a stack over them again, reopen a context or run a pass that re-arms the alarm.
        val requestsAtWipe = alarm.requested.size
        wiring.onDatabaseOpen()
        wiring.onRelaySessionStart()
        wiring.activationHook.onIdentityActivated(restored = false)
        wiring.onAlarm()
        assertNull(wiring.messaging)
        assertEquals("no pass ran after the wipe", requestsAtWipe, alarm.requested.size)
        // A facade call on the stopped stack is the facade's INTERNAL, not an executor's refusal.
        try {
            old.status()
            org.junit.Assert.fail("a stopped stack answered")
        } catch (e: IllegalStateException) {
            Unit
        }
    }

    /**
     * §15.10 step 5's path, as the `gate` instrumentation drives it (S12 review): after the switch to
     * a bound new Olm identity, `activate(restored = false)` finds the old identity's `dm_self` and
     * answers ALREADY_ACTIVE; `activate(restored = true)` recognises the rows as another identity's
     * (§22.13 item 7), clears them and activates.
     */
    @Test
    fun aKeyChangeReactivatesOnlyThroughTheRestoreVariant() {
        wiring.onDatabaseOpen()
        val before = wiring.messaging!!.myCard()!!.card
        wiring.messaging!!.status()
        assertEquals(1L, count("SELECT count(*) FROM dm_self"))
        val ownBefore = ownNamespaces()
        assertEquals(2, ownBefore.size)
        keyChanged = true
        assertEquals(ActivationOutcome.ALREADY_ACTIVE, wiring.activate(restored = false))
        assertEquals("the new identity is still running over the old one's rows", ownBefore, ownNamespaces())
        assertEquals(ActivationOutcome.ACTIVATED, wiring.activate(restored = true))
        val after = wiring.messaging!!.myCard()!!.card
        assertTrue("another card: every value derived from m changed", !before.contentEquals(after))
        val ownAfter = ownNamespaces()
        assertEquals(2, ownAfter.size)
        assertTrue("the old identity's own namespaces were cleared (§22.13 item 7)", ownAfter.none { it in ownBefore })
        assertEquals(1L, count("SELECT count(*) FROM dm_self"))
        assertEquals(ActivationOutcome.ALREADY_ACTIVE, wiring.activate(restored = true))
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
