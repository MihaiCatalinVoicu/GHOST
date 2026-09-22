package org.ghost.app

import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.engine.DmKeys
import org.ghost.sync.api.ConsumerTail
import org.ghost.sync.api.ParticipantSession
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SessionParticipant
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncController
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncListener
import org.ghost.sync.api.SyncStatus
import org.ghost.sync.api.TransportStatus
import org.ghost.sync.store.SyncStores
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * The app's DM decisions (Phase 9 design §13.7 "Wiring", §13.4, §21.12 point 2, §10.7; slice S12),
 * against a recording DM stack over a real migrated database: what is installed at process start,
 * what the first database open owes and in which order, what the K20 hook does, which triggers are
 * time triggers, and what lock and wipe close. `MessagingWiringRuntimeTest` runs the same wiring over
 * the real stack and the real DM cryptography.
 */
class MessagingWiringTest {

    private val log = ArrayList<String>()
    private val databases = ArrayList<TestDatabase>()

    @After
    fun tearDown() {
        databases.forEach { it.close() }
    }

    private fun newDatabase(): TestDatabase = TestDatabase().also { databases += it }

    /** A [Messaging] that records the name of every call and answers what the ACTIVATE calls answer. */
    private fun recordingMessaging(tag: String): Messaging =
        Proxy.newProxyInstance(Messaging::class.java.classLoader, arrayOf(Messaging::class.java)) { _, method, _ ->
            log += "$tag.${method.name}"
            when (method.name) {
                "onActivated", "onRestored" -> ActivationOutcome.ACTIVATED
                "toString" -> "RecordingMessaging"
                else -> null
            }
        } as Messaging

    private inner class RecordingStack(override val stores: SyncStores, private val tag: String) : DmStack {
        var opens: DmKeys.Opened = DmKeys.Opened.OPENED
        val changes = ArrayList<Set<SyncChange>>()
        override val messaging: Messaging = recordingMessaging(tag)
        override val listener: SyncListener = SyncListener { changes += it; log += "$tag.hint" }
        override val consumerTail: ConsumerTail = ConsumerTail { kind, _ -> log += "$tag.tail:$kind" }

        override fun onTimeTrigger() {
            log += "$tag.timeTrigger"
        }

        override fun unlock(root: () -> RootEntropy?): DmKeys.Opened {
            log += "$tag.unlock:" + (if (root() != null) "identity" else "none")
            return opens
        }

        override fun lock() {
            log += "$tag.lock"
        }

        override fun cancelWakes() {
            log += "$tag.cancelWakes"
        }

        override fun close() {
            log += "$tag.close"
        }
    }

    private class RecordingController(private val log: MutableList<String>) : SyncController {
        var tail: ConsumerTail? = null

        override fun onAppForeground() = Unit

        override fun onAppBackground() = Unit

        override fun requestExpedite() = Unit

        override fun setPrivacyMode(mode: PrivacyMode) = Unit

        override fun status(): SyncStatus = SyncStatus(TransportStatus.OFF, PrivacyMode.STANDARD, emptySet(), SyncCounts.EMPTY)

        override fun onWipe() = Unit

        override fun setParticipant(p: SessionParticipant?) = Unit

        override fun setConsumerTail(tail: ConsumerTail?) {
            this.tail = tail
            log += "controller.setConsumerTail"
        }

        override fun runUserIssuerCall(block: (ParticipantSession) -> Unit) = Unit

        override fun onPaymentScreenShown() = Unit

        override fun onPaymentScreenHidden() = Unit

        override fun restorePaymentHold(lastShownEpochSeconds: Long) = Unit
    }

    /** Runs what it is given at once, on the caller's thread; refuses everything after [shutdown]. */
    private class InlineExecutor : AbstractExecutorService() {
        private var down = false

        override fun execute(command: Runnable) {
            if (down) throw RejectedExecutionException("shut down")
            command.run()
        }

        override fun shutdown() {
            down = true
        }

        override fun shutdownNow(): MutableList<Runnable> {
            down = true
            return ArrayList()
        }

        override fun isShutdown(): Boolean = down

        override fun isTerminated(): Boolean = down

        override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = true
    }

    private var openStores: SyncStores? = null
    private val built = ArrayList<RecordingStack>()
    private var identityPresent = true
    private val controller = RecordingController(log)
    private var alarmHandler: (() -> Unit)? = null
    private val postedOpens = ArrayList<() -> Unit>()
    private val hookExecutor: ExecutorService = InlineExecutor()

    private fun wiring(runPosted: Boolean = true) = MessagingWiring(
        controller = controller,
        stores = { openStores },
        whenStoresOpen = { block ->
            log += "whenStoresOpen"
            if (runPosted) block() else postedOpens += block
        },
        stackFor = { stores ->
            val tag = "stack${built.size + 1}"
            log += "build:$tag"
            RecordingStack(stores, tag).also { built += it }
        },
        identity = { if (identityPresent) RootEntropy.fromRaw(ByteArray(32) { 9 }) else null },
        primeSchedule = { log += "primeSchedule" },
        setAlarmHandler = { handler ->
            alarmHandler = handler
            log += "setAlarmHandler:" + (if (handler != null) "set" else "cleared")
        },
        hookExecutor = hookExecutor,
    )

    @Test
    fun processStartInstallsTheTailAndTheAlarmHandlerBeforeAnythingElse() {
        wiring().onProcessStart(keyExists = false)
        assertEquals(listOf("controller.setConsumerTail", "setAlarmHandler:set"), log)
        assertNotNull(controller.tail)
        assertNotNull(alarmHandler)
    }

    @Test
    fun withAKeyTheProcessStartOpensTheDatabaseForTheDmLayer() {
        openStores = newDatabase().stores
        wiring().onProcessStart(keyExists = true)
        assertEquals(
            "§13.7: the listener, the context, then the database-open time trigger (sweep, R-K1 done, resumable ACTIVATE)",
            listOf(
                "controller.setConsumerTail", "setAlarmHandler:set", "whenStoresOpen", "primeSchedule",
                "build:stack1", "stack1.unlock:identity", "stack1.timeTrigger",
            ),
            log,
        )
    }

    @Test
    fun theInboxListenerOfTheOpenDatabaseIsTheStacks() {
        val db = newDatabase()
        openStores = db.stores
        wiring().onDatabaseOpen()
        // A committed directory change is a TOPOLOGY hint, delivered to the consumer listener slot
        // `Inbox.setListener` fills (§13.7): the stack's listener must be in it.
        db.database.transaction { tx ->
            db.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(1), Onions.operatorId(0), RelayEntry.Source.CONFIG)))
        }
        assertEquals(listOf(setOf(SyncChange.TOPOLOGY)), built.single().changes)
    }

    @Test
    fun aSecondOpenOfTheSameDatabaseBuildsNothingAndTriggersNothing() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.onDatabaseOpen()
        w.onVisible()
        assertEquals(listOf("primeSchedule", "whenStoresOpen", "primeSchedule"), log)
        assertEquals(1, built.size)
    }

    @Test
    fun noDatabaseNoStack() {
        val w = wiring()
        w.onDatabaseOpen()
        w.onRelaySessionStart()
        assertTrue(built.isEmpty())
        assertNull(w.messaging)
    }

    @Test
    fun aNewDatabaseReplacesTheStackAndTearsTheOldOneDown() {
        val first = newDatabase()
        openStores = first.stores
        val w = wiring()
        w.onDatabaseOpen()
        openStores = newDatabase().stores
        log.clear()
        w.onDatabaseOpen()
        assertEquals(
            listOf(
                "primeSchedule", "stack1.lock", "stack1.cancelWakes", "stack1.close",
                "build:stack2", "stack2.unlock:identity", "stack2.timeTrigger",
            ),
            log,
        )
        // The old database no longer delivers hints to the old stack.
        first.database.transaction { tx ->
            first.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(2), Onions.operatorId(1), RelayEntry.Source.CONFIG)))
        }
        assertTrue(built[0].changes.isEmpty())
    }

    @Test
    fun theK20HookReopensTheContextBeforeActivate() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.activationHook.onIdentityActivated(restored = false)
        assertEquals(listOf("stack1.unlock:identity", "stack1.onActivated"), log)
        log.clear()
        w.activationHook.onIdentityActivated(restored = true)
        assertEquals(listOf("stack1.unlock:identity", "stack1.onRestored"), log)
    }

    @Test
    fun theK20HookBuildsTheStackWhenTheDatabaseIsOpenButTheDmLayerIsNot() {
        openStores = newDatabase().stores
        val w = wiring()
        w.activationHook.onIdentityActivated(restored = false)
        assertEquals(
            listOf("build:stack1", "stack1.unlock:identity", "stack1.timeTrigger", "stack1.unlock:identity", "stack1.onActivated"),
            log,
        )
    }

    @Test
    fun aContextThatDoesNotOpenActivatesNothing() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        built.single().opens = DmKeys.Opened.CRYPTO_UNAVAILABLE
        log.clear()
        w.activationHook.onIdentityActivated(restored = false)
        assertEquals("§21.12 point 2's resume is the guarantee, not the hook", listOf("stack1.unlock:identity"), log)
    }

    @Test
    fun theK20HookNeverThrowsIntoTheEntitlementThread() {
        openStores = newDatabase().stores
        val w = wiring()
        hookExecutor.shutdown()
        w.activationHook.onIdentityActivated(restored = false)
        assertTrue(built.isEmpty())
    }

    @Test
    fun aRelaySessionStartIsATimeTriggerAndRunsBeforeTheParticipant() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        val participant = object : SessionParticipant {
            override fun onRelaySession(session: ParticipantSession) {
                log += "entitlement.onRelaySession"
            }

            override fun onQuietRun(session: ParticipantSession) {
                log += "entitlement.onQuietRun"
            }
        }
        val hooked = w.sessionHooks(participant)
        val session = Proxy.newProxyInstance(
            ParticipantSession::class.java.classLoader,
            arrayOf(ParticipantSession::class.java),
        ) { _, _, _ -> null } as ParticipantSession
        log.clear()
        hooked.onRelaySession(session)
        hooked.onQuietRun(session)
        assertEquals(
            "a quiet run is not a relay session: no DM trigger (§21.9 rule 1, P-7)",
            listOf("stack1.timeTrigger", "entitlement.onRelaySession", "entitlement.onQuietRun"),
            log,
        )
    }

    @Test
    fun theConsumerTailBuildsTheStackOfTheDatabaseTheJobOpened() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onProcessStart(keyExists = false)
        log.clear()
        // A background job opened the database; the tail runs after its transport closed.
        controller.tail!!.run(SessionKind.BACKGROUND, 1_000L)
        assertEquals(listOf("build:stack1", "stack1.unlock:identity", "stack1.timeTrigger", "stack1.tail:BACKGROUND"), log)
    }

    @Test
    fun theAlarmIsATimeTriggerAndWithoutAStackItOpensTheDatabase() {
        openStores = newDatabase().stores
        val w = wiring(runPosted = false)
        w.onProcessStart(keyExists = false)
        log.clear()
        alarmHandler!!.invoke()
        assertEquals(listOf("whenStoresOpen"), log)
        postedOpens.removeAt(0).invoke()
        log.clear()
        alarmHandler!!.invoke()
        assertEquals(listOf("stack1.timeTrigger"), log)
    }

    @Test
    fun lockClosesTheContextAndNothingElse() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.onLock()
        assertEquals(listOf("stack1.lock"), log)
        log.clear()
        assertEquals(DmKeys.Opened.OPENED, w.onUnlock())
        assertEquals(listOf("stack1.unlock:identity"), log)
    }

    @Test
    fun wipeClosesTheContextCancelsTheWakesUnsetsTheListenerAndStops() {
        val db = newDatabase()
        openStores = db.stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.onWipe()
        assertEquals(listOf("stack1.lock", "stack1.cancelWakes", "stack1.close"), log)
        assertNull(w.messaging)
        db.database.transaction { tx ->
            db.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(3), Onions.operatorId(0), RelayEntry.Source.CONFIG)))
        }
        assertTrue("the listener is gone with the stack", built.single().changes.isEmpty())
    }

    @Test
    fun anAbsentIdentityStillBuildsTheStackWithAClosedContext() {
        openStores = newDatabase().stores
        identityPresent = false
        wiring().onDatabaseOpen()
        assertSame(built.single().stores, openStores)
        assertTrue("stack1.unlock:none" in log)
    }
}
