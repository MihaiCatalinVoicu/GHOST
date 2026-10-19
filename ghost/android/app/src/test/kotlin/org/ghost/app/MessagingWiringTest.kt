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
 *
 * The recording stack runs a context open the way the actor does — it asks the wiring's `wanted`
 * predicate at the moment it would open — and can hold opens back ([RecordingStack.deferOpens]) to
 * stand for an actor that has not reached the turn yet. That is what the S12 review's lock and wipe
 * races are pinned with.
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
        var deferOpens = false
        var openThrows = false
        var activateThrows = false
        val deferred = ArrayList<() -> Unit>()
        val changes = ArrayList<Set<SyncChange>>()
        override val channels: org.ghost.messaging.api.Channels? = null
        override val messaging: Messaging = recordingMessaging(tag)
        override val listener: SyncListener = SyncListener { changes += it; log += "$tag.hint" }
        override val consumerTail: ConsumerTail = ConsumerTail { kind, _ -> log += "$tag.tail:$kind" }

        /** The kind of every time trigger, in order: true for a relay session start. */
        val sessionStarts = ArrayList<Boolean>()

        override fun onTimeTrigger(sessionStart: Boolean) {
            sessionStarts += sessionStart
            log += "$tag.timeTrigger"
        }

        private fun openNow(root: () -> RootEntropy?, wanted: () -> Boolean): DmKeys.Opened? {
            if (!wanted()) {
                log += "$tag.open:refused"
                return null
            }
            log += "$tag.open:" + (if (root() != null) "identity" else "none")
            return opens
        }

        override fun open(root: () -> RootEntropy?, wanted: () -> Boolean) {
            if (openThrows) throw IllegalStateException("the actor refused the turn")
            if (deferOpens) deferred += { openNow(root, wanted) } else openNow(root, wanted)
        }

        override fun openAndActivate(root: () -> RootEntropy?, restored: Boolean, wanted: () -> Boolean): ActivationOutcome? {
            if (activateThrows) throw IllegalStateException("INTERNAL")
            if (openNow(root, wanted) != DmKeys.Opened.OPENED) return null
            return if (restored) messaging.onRestored() else messaging.onActivated()
        }

        /** Runs the opens held back, as the actor reaching those turns would. */
        fun runDeferred() {
            val turns = deferred.toList()
            deferred.clear()
            turns.forEach { it() }
        }

        override fun lock() {
            log += "$tag.lock"
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

    /** Runs inside `stackFor`, before the stack is returned: a lock, a throw, whatever a race brings. */
    private var whileBuilding: () -> Unit = {}

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
            whileBuilding()
            RecordingStack(stores, tag).also { built += it }
        },
        identity = { if (identityPresent) RootEntropy.fromRaw(ByteArray(32) { 9 }) else null },
        primeSchedule = { log += "primeSchedule" },
        setAlarmHandler = { handler ->
            alarmHandler = handler
            log += "setAlarmHandler:" + (if (handler != null) "set" else "cleared")
        },
        cancelAlarm = { log += "cancelAlarm" },
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
                "build:stack1", "stack1.open:identity", "stack1.timeTrigger",
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

    /**
     * Phase review MD-2: only a relay session start is a session start. It is the one trigger that
     * may open the next bundle-fetch attempt (§21.7 point 5), so the alarm and the database open
     * must not claim to be one.
     */
    @Test
    fun onlyARelaySessionStartIsASessionStart() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onProcessStart(keyExists = true)
        w.onRelaySessionStart()
        w.onAlarm()
        w.onRelaySessionStart()
        assertEquals(1, built.size)
        assertEquals(
            "the database open, then a session start, the alarm and a session start",
            listOf(false, true, false, true),
            built.single().sessionStarts,
        )
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
            "the new stack is wired first; the old one stops after, outside the wiring's lock",
            listOf("primeSchedule", "build:stack2", "stack2.open:identity", "stack2.timeTrigger", "stack1.close"),
            log,
        )
        // The old database no longer delivers hints to the old stack.
        first.database.transaction { tx ->
            first.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(2), Onions.operatorId(1), RelayEntry.Source.CONFIG)))
        }
        assertTrue(built[0].changes.isEmpty())
    }

    @Test
    fun theK20HookReopensTheContextAndActivatesInOneTurn() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.activationHook.onIdentityActivated(restored = false)
        assertEquals(listOf("stack1.open:identity", "stack1.onActivated"), log)
        log.clear()
        w.activationHook.onIdentityActivated(restored = true)
        assertEquals(listOf("stack1.open:identity", "stack1.onRestored"), log)
    }

    @Test
    fun theK20HookBuildsTheStackWhenTheDatabaseIsOpenButTheDmLayerIsNot() {
        openStores = newDatabase().stores
        val w = wiring()
        w.activationHook.onIdentityActivated(restored = false)
        assertEquals(
            listOf("build:stack1", "stack1.open:identity", "stack1.timeTrigger", "stack1.open:identity", "stack1.onActivated"),
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
        assertEquals("§21.12 point 2's resume is the guarantee, not the hook", listOf("stack1.open:identity"), log)
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
    fun aHookWhoseActivationThrowsDoesNotEndTheWiringThread() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        built.single().activateThrows = true
        // On a device an exception out of the hook's runnable ends the process (S12 review).
        w.activationHook.onIdentityActivated(restored = false)
        assertNull(w.activate(restored = false))
    }

    @Test
    fun aStackThatCannotBeBuiltLeavesNothingBehindAndThrowsIntoNoCaller() {
        openStores = newDatabase().stores
        whileBuilding = { throw IllegalStateException("the database is closing") }
        val w = wiring()
        w.onProcessStart(keyExists = true)
        w.onRelaySessionStart()
        controller.tail!!.run(SessionKind.BACKGROUND, 1_000L)
        w.activationHook.onIdentityActivated(restored = false)
        assertTrue(built.isEmpty())
        assertNull(w.messaging)
        // The next trigger after the cause went away builds it.
        whileBuilding = {}
        w.onRelaySessionStart()
        assertEquals(1, built.size)
    }

    @Test
    fun aStackWhoseInstallFailsIsStoppedAndNotKept() {
        val db = newDatabase()
        openStores = db.stores
        // The stack is built, then its first turn is refused: it must not stay installed as an
        // orphan with a listener, an actor and a timer (§7.9: one actor per database).
        val refusing = MessagingWiring(
            controller = controller,
            stores = { openStores },
            whenStoresOpen = { it() },
            stackFor = { stores -> RecordingStack(stores, "stack1").also { it.openThrows = true; built += it } },
            identity = { RootEntropy.fromRaw(ByteArray(32) { 9 }) },
            primeSchedule = { },
            setAlarmHandler = { },
            cancelAlarm = { },
            hookExecutor = hookExecutor,
        )
        assertNull(refusing.ensureStack())
        assertNull(refusing.messaging)
        assertEquals("stopped at once", listOf("stack1.close"), log.filter { it.startsWith("stack1.") })
        db.database.transaction { tx ->
            db.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(4), Onions.operatorId(0), RelayEntry.Source.CONFIG)))
        }
        assertTrue("its listener was removed", built.single().changes.isEmpty())
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
        assertEquals(listOf("build:stack1", "stack1.open:identity", "stack1.timeTrigger", "stack1.tail:BACKGROUND"), log)
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
    fun lockClosesTheContextAndUnlockReopensIt() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        log.clear()
        w.onLock()
        assertEquals(listOf("stack1.lock"), log)
        log.clear()
        w.onUnlock()
        assertEquals(listOf("stack1.open:identity"), log)
    }

    @Test
    fun aLockRecordedAfterAnOpenWasPostedStillWins() {
        openStores = newDatabase().stores
        // The first open's context turn is still queued on the actor when the app locks.
        val deferring = MessagingWiring(
            controller = controller,
            stores = { openStores },
            whenStoresOpen = { it() },
            stackFor = { stores -> RecordingStack(stores, "stack1").also { it.deferOpens = true; built += it } },
            identity = { RootEntropy.fromRaw(ByteArray(32) { 9 }) },
            primeSchedule = { },
            setAlarmHandler = { },
            cancelAlarm = { },
            hookExecutor = hookExecutor,
        )
        deferring.onDatabaseOpen()
        deferring.onLock()
        built.single().runDeferred()
        assertEquals(
            "S12 review: the open reaches the actor after the lock and does nothing",
            listOf("stack1.timeTrigger", "stack1.lock", "stack1.open:refused"),
            log,
        )
    }

    @Test
    fun aLockDuringTheFirstBuildIsNotLost() {
        openStores = newDatabase().stores
        lateinit var w: MessagingWiring
        // The lock arrives while the stack is being built, before the wiring holds it: there is no
        // stack to post a close to, and the open that follows must see the lock.
        whileBuilding = { w.onLock() }
        w = wiring()
        w.onDatabaseOpen()
        assertEquals(listOf("primeSchedule", "build:stack1", "stack1.open:refused", "stack1.timeTrigger"), log)
    }

    @Test
    fun whileLockedNeitherTheK20HookNorANewDatabaseOpensTheContext() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onDatabaseOpen()
        w.onLock()
        log.clear()
        w.activationHook.onIdentityActivated(restored = false)
        openStores = newDatabase().stores
        w.onDatabaseOpen()
        assertEquals(
            listOf("primeSchedule", "build:stack2", "stack2.open:refused", "stack2.timeTrigger", "stack1.close"),
            log,
        )
        log.clear()
        w.onUnlock()
        assertEquals(listOf("stack2.open:identity"), log)
    }

    @Test
    fun wipeStopsTheStackCancelsTheAlarmAndClearsTheHandOff() {
        val db = newDatabase()
        openStores = db.stores
        val w = wiring()
        w.onProcessStart(keyExists = true)
        log.clear()
        w.onWipe()
        // Phase 13 S5: the wipe detaches the UI listener (and the notifier) before the close.
        // Phase 13 S5: the wipe detaches the UI listener on the stack before the close.
        assertEquals(listOf("stack1.setListener", "stack1.close", "cancelAlarm", "setAlarmHandler:cleared"), log)
        assertNull(w.messaging)
        assertNull(alarmHandler)
        db.database.transaction { tx ->
            db.stores.relayDirectory.upsert(tx, listOf(RelayEntry(Onions.onion(3), Onions.operatorId(0), RelayEntry.Source.CONFIG)))
        }
        assertTrue("the listener is gone with the stack", built.single().changes.isEmpty())
    }

    @Test
    fun wipeCancelsAnEarlierProcessAlarmEvenWithoutAStack() {
        val w = wiring()
        w.onProcessStart(keyExists = false)
        log.clear()
        w.onWipe()
        assertEquals(listOf("cancelAlarm", "setAlarmHandler:cleared"), log)
    }

    @Test
    fun aWipeIsFinalWhileTheStoresAreStillOpenAndUntilTheNextKey() {
        openStores = newDatabase().stores
        val w = wiring()
        w.onProcessStart(keyExists = true)
        w.onWipe()
        log.clear()
        // `SyncRuntime.wipe()` is posted: the stores stay non-null for a while after the DM layer's
        // wipe. Every trigger that can arrive in that window must build nothing (S12 review: each
        // one used to build a new stack, reopen the context and leave it running after the stores
        // were dropped).
        w.onDatabaseOpen()
        w.onVisible()
        w.onRelaySessionStart()
        controller.tail!!.run(SessionKind.BACKGROUND, 1_000L)
        w.activationHook.onIdentityActivated(restored = true)
        w.onAlarm()
        w.onUnlock()
        assertEquals(1, built.size)
        assertNull(w.messaging)
        assertEquals("nothing but the open request the runtime itself refuses while wiped", listOf("whenStoresOpen"), log)
        // Onboarding creates the next key: its database gets a stack.
        openStores = newDatabase().stores
        log.clear()
        w.onKeyCreated()
        assertEquals(
            listOf("setAlarmHandler:set", "whenStoresOpen", "primeSchedule", "build:stack2", "stack2.open:identity", "stack2.timeTrigger"),
            log,
        )
    }

    @Test
    fun anAbsentIdentityStillBuildsTheStackWithAClosedContext() {
        openStores = newDatabase().stores
        identityPresent = false
        wiring().onDatabaseOpen()
        assertSame(built.single().stores, openStores)
        assertTrue("stack1.open:none" in log)
    }
}
