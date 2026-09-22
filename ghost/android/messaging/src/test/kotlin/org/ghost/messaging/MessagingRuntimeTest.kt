package org.ghost.messaging

import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.NotificationPort
import org.ghost.messaging.api.RevocationReason
import org.ghost.messaging.engine.DmActor
import org.ghost.messaging.engine.DmKeys
import org.ghost.messaging.engine.MessagingRuntime
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.KeyWrapper
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

/**
 * The DM stack as `:app`'s `MessagingWiring` assembles it (Phase 9 design §13.7; slice S12):
 * **with the actor attached**, over a real migrated v5 database and the real DM cryptography of
 * `ghost-dm-host`.
 *
 * Every world before this slice drove its passes directly with no actor attached to the engine
 * (`DmWorld`'s own note: "the facade must not post to the actor's thread and wait for it"), so the
 * threading contract of §13.7 had never run. The first run of this class found two defects that
 * only an attached actor can reach, and each has a test here:
 *  - a time-triggered pass calls the owner maintenance, which posts to the actor and waits — on the
 *    actor's own thread, a deadlock that stopped the actor for the life of the process
 *    ([aTimeTriggeredPassActivatesOnTheActorWithoutDeadlock]);
 *  - a facade call whose answer is `null` ran its body a second time on the caller's thread
 *    ([aNullAnswerIsComputedOnceAndOnTheActor]).
 */
class MessagingRuntimeTest {

    private lateinit var sql: JdbcSqlExecutor
    private lateinit var stores: SyncStores
    private lateinit var clock: MovableClock
    private lateinit var alarm: RecordingWake
    private lateinit var runtime: MessagingRuntime
    private lateinit var keys: DmKeys
    private lateinit var slots: List<EsSlot>
    private val contentKeys = SwitchableKeyWrapper()
    private val stateKeys = SwitchableKeyWrapper()
    private var closed = false

    /** The content-key wrapper, able to refuse an unwrap and recording the thread of every one. */
    class SwitchableKeyWrapper : KeyWrapper {
        private val real = FakeKeyWrapper()

        @Volatile
        var refuse: Boolean = false
        val unwrapThreads = CopyOnWriteArrayList<String>()

        override fun wrap(key: ByteArray): ByteArray = real.wrap(key)

        override fun unwrap(wrapped: ByteArray): ByteArray {
            unwrapThreads += Thread.currentThread().name
            require(!refuse) { "the Keystore key is gone" }
            return real.unwrap(wrapped)
        }
    }

    private val rootBytes = ByteArray(32) { (it * 7 + 3).toByte() }

    private fun root(): RootEntropy = RootEntropy.fromRaw(rootBytes)

    @Before
    fun setUp() {
        assumeTrue(
            "ghost-dm-host is not on the classpath (-Dghost.dm.native); the runtime runs the real ratchet",
            DmWorld.nativeAvailable(),
        )
        sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        val database = SyncDatabase(sql)
        clock = MovableClock(DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY)
        stores = SyncStores(database, clock, FixedRandomSources()) { PrivacyMode.STANDARD }
        val ids = database.transaction { tx ->
            stores.relayDirectory.upsert(
                tx,
                (0 until 4).map { i -> RelayEntry(OwnerWorld.onion(i), OwnerWorld.operatorId(i % 2), RelayEntry.Source.CONFIG) },
            )
        }
        slots = (0 until 4).map { i -> EsSlot(i, ids.getValue(OwnerWorld.onion(i)), OwnerWorld.operatorId(i % 2)) }
        alarm = RecordingWake()
        keys = DmKeys(stateKeys = stateKeys, random = SequentialRandom(stream = "runtime-state"))
        runtime = MessagingRuntime(
            stores = stores,
            keys = keys,
            contentKeys = contentKeys,
            esSlots = EsSlots { slots },
            clock = clock,
            random = SequentialRandom(stream = "runtime"),
            alarm = alarm,
            checkpoint = RecordingCheckpoint { org.ghost.storage.Checkpoint.truncate(sql) },
        )
    }

    @After
    fun tearDown() {
        if (::runtime.isInitialized && !closed) {
            // Bounded, so that a regression of the actor's re-entrancy fails the test that found it
            // instead of hanging the whole suite here: a deadlocked actor never answers `lock()`
            // (checked by hand against the S12 fix reverted — the suite then hung in this method).
            val teardown = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
                Thread(r, "runtime-teardown").apply { isDaemon = true }
            }
            try {
                teardown.submit { runtime.lock() }.get(30, TimeUnit.SECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                Unit
            } finally {
                teardown.shutdownNow()
                runtime.close()
            }
        }
        if (::sql.isInitialized) sql.close()
    }

    private fun dmSelfExists(): Boolean {
        var found = false
        sql.query("SELECT 1 FROM dm_self") { found = true }
        return found
    }

    private fun bundleOps(): Int {
        var n = 0
        sql.query("SELECT count(*) FROM dm_outbound_op WHERE purpose = 'bundle'") { n = it.long(0).toInt() }
        return n
    }

    /** A facade call queues behind every pass posted before it: the actor's single thread. */
    private fun barrier() {
        runtime.messaging.status()
    }

    @Test
    fun unlockOpensTheContextFromTheRootAndLockClosesIt() {
        assertEquals(DmKeys.Opened.OPENED, runtime.unlock(::root))
        assertTrue(runtime.unlocked)
        val first = requireNotNull(runtime.messaging.myCard()) { "an open context answers a card" }.card

        runtime.lock()
        assertFalse(runtime.unlocked)
        assertNull("a locked context answers CRYPTO_UNAVAILABLE, not a card", runtime.messaging.myCard())

        // The card is a pure function of the seed (§3.3): the same root gives the same card.
        assertEquals(DmKeys.Opened.OPENED, runtime.unlock(::root))
        assertArrayEquals(first, requireNotNull(runtime.messaging.myCard()).card)
    }

    @Test
    fun anAbsentIdentityOpensNothing() {
        assertEquals(DmKeys.Opened.NO_IDENTITY, runtime.unlock { null })
        assertFalse(runtime.unlocked)
        assertNull(runtime.messaging.myCard())
    }

    @Test
    fun theRootIsZeroisedWhateverOpenDoes() {
        val handed = root()
        runtime.unlock { handed }
        assertTrue("the root entropy handed over is wiped", handed.rawForWrapping().all { it == 0.toByte() })
    }

    @Test
    fun aTimeTriggeredPassActivatesOnTheActorWithoutDeadlock() {
        runtime.unlock(::root)
        assertFalse(dmSelfExists())
        // §21.12 point 2: a database open (a time trigger) with an identity and no `dm_self` row
        // runs ACTIVATE, and the same pass runs the owner maintenance — which posts to the actor
        // from the actor. Before S12's fix this call never returned.
        runtime.onTimeTrigger()
        val done = java.util.concurrent.Executors.newSingleThreadExecutor().submit { barrier() }
        done.get(60, TimeUnit.SECONDS)
        assertTrue("the resumable ACTIVATE ran", dmSelfExists())
        assertEquals("the first bundle was enqueued", 1, bundleOps())
        assertEquals(ActivationOutcome.ALREADY_ACTIVE, runtime.messaging.onActivated())
    }

    @Test
    fun theKeyRestoresTheSameStateKeyAfterALock() {
        runtime.unlock(::root)
        assertEquals(ActivationOutcome.ACTIVATED, runtime.messaging.onActivated())
        var stored: ByteArray? = null
        sql.query("SELECT state_key_wrapped FROM dm_self") { stored = it.blob(0) }
        runtime.lock()
        assertEquals(DmKeys.Opened.OPENED, runtime.unlock(::root))
        // ACTIVATE persisted the wrapped key the context was opened with; a later unlock opens
        // with that stored key, never a fresh one (a fresh one would make every stored envelope
        // `STATE_CORRUPT`).
        assertArrayEquals(stored, keys.stateKeyWrapped())
    }

    @Test
    fun aStateKeyThatDoesNotUnwrapLeavesTheContextClosed() {
        runtime.unlock(::root)
        assertEquals(ActivationOutcome.ACTIVATED, runtime.messaging.onActivated())
        runtime.lock()
        // A device reset deleted the Keystore key: the stored envelope no longer opens.
        stateKeys.refuse = true
        assertEquals(DmKeys.Opened.STATE_KEY_UNAVAILABLE, runtime.unlock(::root))
        assertFalse(runtime.unlocked)
        assertNull(runtime.messaging.myCard())
    }

    @Test
    fun theFacadeRunsOnTheActorThread() {
        runtime.unlock(::root)
        val threads = CopyOnWriteArrayList<String>()
        runtime.messaging.setNotificationPort(NotificationPort { threads += Thread.currentThread().name })
        assertEquals(listOf(DmActor.THREAD_NAME), threads.distinct())
    }

    @Test
    fun aNullAnswerIsComputedOnceAndOnTheActor() {
        runtime.unlock(::root)
        assertEquals(ActivationOutcome.ACTIVATED, runtime.messaging.onActivated())
        // The facade used to read a null *answer* as "no actor attached" and run the body again on
        // the caller's thread. A content key that does not unwrap is a null path that leaves a
        // trace every time the body runs, because `SelfContexts` caches only a success.
        contentKeys.refuse = true
        contentKeys.unwrapThreads.clear()
        assertNull(runtime.messaging.issueRevocation(RevocationReason.DEVICE_LOST))
        assertEquals(
            "the body ran once, on the actor, and never again on the caller's thread",
            listOf(DmActor.THREAD_NAME),
            contentKeys.unwrapThreads.toList(),
        )
    }

    @Test
    fun hintsArePostedAndCoalescedWithoutTouchingTheCaller() {
        runtime.unlock(::root)
        runtime.messaging.onActivated()
        val caller = Thread.currentThread().name
        val threads = CopyOnWriteArrayList<String>()
        runtime.messaging.setNotificationPort(NotificationPort { threads += Thread.currentThread().name })
        threads.clear()
        repeat(5) { runtime.listener.onChanged(setOf(SyncChange.INBOX, SyncChange.OUTCOMES)) }
        barrier()
        assertFalse("the listener did no work on the committing thread", caller in threads)
    }

    @Test
    fun theConsumerTailRunsAPassAndReturnsByItsDeadline() {
        runtime.unlock(::root)
        val deadline = clock.monotonicMillis() + 30_000
        runtime.consumerTail.run(SessionKind.BACKGROUND, deadline)
        barrier()
        assertTrue("the tail's pass is time-triggered and resumed ACTIVATE", dmSelfExists())
    }

    @Test
    fun aPassSetsTheAlarmAndCancelWakesClearsIt() {
        runtime.unlock(::root)
        runtime.onTimeTrigger()
        barrier()
        val before = alarm.requested.size
        assertTrue("every pass reschedules the alarm (§10.7 trigger 5)", before > 0)
        runtime.cancelWakes()
        assertNull("§10.7: the alarm is cancelled at wipe", alarm.last)
    }

    @Test
    fun aClosedRuntimeDropsLateHintsInsteadOfThrowingIntoTheLane() {
        runtime.unlock(::root)
        runtime.lock()
        runtime.close()
        closed = true
        // A lane thread that commits after a wipe tore the stack down must not receive an
        // exception from the listener (`SyncDatabase`: "listeners must not throw").
        runtime.listener.onChanged(setOf(SyncChange.INBOX))
        runtime.onTimeTrigger()
    }
}
