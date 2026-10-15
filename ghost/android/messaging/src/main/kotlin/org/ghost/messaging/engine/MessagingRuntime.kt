package org.ghost.messaging.engine

import org.ghost.identity.RootEntropy
import org.ghost.messaging.api.ActivationOutcome
import org.ghost.messaging.api.MediaPort
import org.ghost.messaging.api.Messaging
import org.ghost.messaging.channel.engine.ChannelActor
import org.ghost.messaging.channel.engine.ChannelContexts
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.engine.ChannelEngine
import org.ghost.messaging.channel.engine.ChannelEnv
import org.ghost.messaging.channel.engine.ChannelSyncPorts
import org.ghost.messaging.channel.engine.SelfChannelKeys
import org.ghost.messaging.channel.store.ChannelStores
import org.ghost.messaging.port.ChannelPorts
import org.ghost.messaging.port.DmCheckpoint
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.port.ExpiryWake
import org.ghost.messaging.port.KeyWrapper
import org.ghost.messaging.port.NativeDmCrypto
import org.ghost.messaging.port.NativeDmEnvelopes
import org.ghost.messaging.store.ContactStore
import org.ghost.sync.api.ConsumerTail
import org.ghost.sync.api.SyncChange
import org.ghost.sync.api.SyncListener
import org.ghost.sync.store.SyncStores

/**
 * **The DM stack over one open database** (Phase 9 design §13.1, §13.7; slice S12): the engine,
 * its steps, the DM actor, the in-process expiry timer and the DM context, built from the ports
 * `:app`'s `MessagingWiring` supplies.
 *
 * **Why this class exists.** Every step of `:messaging` is `internal`, deliberately: `:app` must
 * reach the DM layer through the facade and the triggers, never through a step. But the wiring
 * lives in `:app` (§13.1's last row), so the one place allowed to put the stack together has to be
 * public and in this module. It is this class, and it holds no decision of its own: which ports,
 * when to open the context, when to trigger — every one of those is `MessagingWiring`'s, where
 * `MessagingWiringTest` pins them. The construction below is the same recipe `DmWorld`'s `DmDevice`
 * uses, written twice; what the actor's triggers are bound to — the listener, the consumer tail, the
 * time triggers, the in-process timer and the schedule of both wakes — is not written twice but built
 * by [DmTriggers] for both, so the worlds that run the production triggers run these bindings (the
 * review of §22.36, item 12).
 *
 * **One stack per [SyncStores].** A `SyncDatabase` serializes every transaction through its own
 * lock and delivers its hints to its own listener, so the DM layer must use the very instance the
 * sync engine uses — a second `SyncStores` over the same file would interleave transactions and
 * never hear a hint. A wipe drops the stores; the wiring [close]s this stack before they go and
 * builds a new one only over a database opened after the next key is created.
 *
 * **What it exposes**, all of it the wiring's to call:
 *  - [messaging], the facade of §13.2, attached to the actor so every call posts to it;
 *  - [listener] for `Inbox.setListener` and [consumerTail] for `SyncController.setConsumerTail`
 *    (§13.3 item 6, §13.7);
 *  - [onTimeTrigger], the relay-session-start, database-open and alarm trigger of §21.9 rule 1;
 *  - [unlock] and [lock], the DM context's lifecycle on the actor thread (§2.5, §13.8), with their
 *    posted forms [requestUnlock] and [requestLock], and [reopenAndActivate], the K20 hook's one
 *    turn;
 *  - [cancelWakes], §10.7's "cancelled … at wipe" (§22.14 item 11), and [close], which stops the
 *    stack for good with the context closed and both wakes cancelled.
 *
 * **Gate G-DM2.** The owner pass is bound here, as `DmDevice` binds it, which makes this file one
 * of the few that may name `runOwnerMaintenance`; `dm-enqueue-callers.sh` lists it for that
 * reason (slice S12). It makes no restricted call and drives no step.
 */
class MessagingRuntime(
    val stores: SyncStores,
    private val keys: DmKeys,
    contentKeys: KeyWrapper,
    esSlots: EsSlots,
    private val clock: DmClock,
    random: DmRandom,
    /** The one inexact alarm of §10.7 trigger 5 (`ExpiryAlarm` on a device, [ExpiryWake.NONE] on the JVM). */
    alarm: ExpiryWake,
    /** `Checkpoint.truncate` over the database's executor (§10.7), which `:messaging` cannot reach. */
    checkpoint: DmCheckpoint,
    media: MediaPort = MediaPort.NONE,
    /** The channel engine's own ports (Phase 10, slice S4); null builds the DM stack alone, as every Phase 9 caller does. */
    channelPorts: ChannelPorts? = null,
) : AutoCloseable {

    private val database = stores.database
    private val crypto = NativeDmCrypto(keys)
    private val envelopes = NativeDmEnvelopes(keys)
    private val contexts = SelfContexts(database, crypto, contentKeys)
    private val material = ContactMaterial(crypto, contexts)
    private val counters = DmCounters()
    private val relayResolver = RelaySetResolver(esSlots)
    private val sync = DmSyncPorts(
        stores.namespaces,
        stores.capabilities,
        stores.registrations,
        stores.outbox,
        stores.inbox,
    )
    private val steps = OwnerSteps(
        database = database,
        sync = OwnerSteps.SyncPorts(stores.namespaces, stores.capabilities, stores.registrations, stores.outbox),
        crypto = crypto,
        clock = clock,
        random = random,
        keyWrapper = contentKeys,
        esSlots = esSlots,
    )
    private val sendStep = SendStep(
        database, sync, envelopes, material, relayResolver, clock, random, contexts, counters = counters,
    )
    private val establishment = EstablishmentSteps(database, sync, envelopes, material, relayResolver, clock, contexts)
    private val bundleStep = BundleStep(envelopes, material, clock, contexts)
    private val contactSteps = ContactSteps(database, crypto, random, contexts, establishment)
    private val recognition = RecognitionKeys(envelopes)
    private val receiveStep = ReceiveStep(
        database, sync, envelopes, crypto, material, recognition, SessionSlots(), clock, random, contexts, counters,
    )
    private val peekOrder = PeekOrder(database, sync, envelopes, recognition, clock, contexts)
    private val keyDecision = KeyDecision(database, crypto, contexts)
    private val heldReplay = HeldReplay(database, envelopes, receiveStep, clock, contexts, counters)
    private val scheduledSteps = ScheduledSteps(database, crypto, sendStep, establishment, clock, random, contexts)
    private val pairKeys = PairKeySteps(envelopes)
    private val displayStep = DisplayStep(database, clock)
    private val mediaOrphans = MediaOrphanSteps(crypto, clock)
    private val sweeper = Sweeper(
        database = database,
        namespaces = stores.namespaces,
        envelopes = envelopes,
        pairKeys = pairKeys,
        checkpoint = checkpoint,
        clock = clock,
        contexts = contexts,
        media = media,
        mediaOrphans = mediaOrphans,
    )
    private val notices = UnreadNotices { sweeper.unreadCount() }

    /**
     * Every trigger the actor gets — the listener, the consumer tail, the time triggers, the
     * in-process timer of §10.7 trigger 1 — and the schedule of both wakes, bound in [DmTriggers],
     * which the test harness's worlds build theirs with too (the review of §22.36, item 12).
     */
    private val triggers = DmTriggers()

    private val schedule = triggers.schedule(sweeper, alarm, notices, triggers.timer, steps, clock)

    private val engine = MessagingEngine(
        database, steps, contactSteps, sendStep, establishment, keyDecision, heldReplay,
        scheduledSteps, displayStep, schedule, counters, clock, contexts, recognition,
    )

    /**
     * The channel engine (Phase 10 design §10.1; slice S4) on the same actor, database and content key as the DM layer
     * (D16): its user actions post to the actor, and its pass runs at the end of every actor pass. Null without
     * [channelPorts].
     */
    internal val channelEngine: ChannelEngine? = channelPorts?.let { ports ->
        val channelStores = ChannelStores()
        ChannelEngine(
            env = ChannelEnv(
                database = database,
                stores = channelStores,
                contexts = ChannelContexts(database, channelStores, ports.stateKeys, random, ports.seeds),
                keys = SelfChannelKeys(contexts),
                clock = clock,
                random = random,
                esSlots = esSlots,
                counters = ChannelCounters(),
                // §6.9: revealSeal signs with the DM context's identity key (the handle names it;
                // the key never crosses to Kotlin), and an opened reveal offers the author's card
                // through the DM layer's addContact — CardSource.LINK, trust unverified (§19.17).
                dmContext = keys,
                contactOffer = { card, source -> contactSteps.addContact(card, source) },
            ),
            sync = ChannelSyncPorts(
                stores.namespaces, stores.capabilities, stores.registrations, stores.outbox, stores.inbox, stores.funding,
            ),
            actor = object : ChannelActor {
                override fun <T> call(body: () -> T): T = actor.call(body)
            },
            checkpoint = checkpoint,
        )
    }

    private val actor = DmActor(
        database = database,
        sync = sync,
        establishment = establishment,
        bundleStep = bundleStep,
        sendStep = sendStep,
        receiveStep = receiveStep,
        outcomeStep = OutcomeStep(database, sync, sendStep, clock, contexts, mediaOrphans),
        heldReplay = heldReplay,
        scheduledSteps = scheduledSteps,
        contactKeeper = ContactKeeper(database, sync, material, relayResolver, clock, contexts),
        sweeper = sweeper,
        schedule = schedule,
        // §21.9 rule 1's owner pass, called by the actor from inside a time-triggered pass: the
        // facade's `onActor` runs it inline there (`DmActor.call`), which is why the actor is the
        // only thread that ever reaches OWNER-WEEK, KEEPER and REGROWS.
        ownerMaintenance = { engine.runOwnerMaintenance() },
        // §21.12 point 2's resume, wired to the step and not to the facade, exactly as `DmDevice`
        // wires it; `restored = true` is the side that is safe in both cases (see `DmActor`).
        resumeActivation = {
            steps.activate(restored = true)
            forgetCachedKeys()
        },
        peekOrder = peekOrder,
        material = material,
        clock = clock,
        contexts = contexts,
        channels = channelEngine,
    )

    init {
        engine.attach(actor)
        triggers.bind(actor)
    }

    /** The facade of §13.2. Every call posts to the DM actor and returns after its commit. */
    val messaging: Messaging get() = engine

    /**
     * The inbox listener of §13.7: it posts a coalesced flag and returns, touching nothing — the
     * committing thread can be a lane thread (`SyncDatabase` delivers hints there).
     */
    val listener: SyncListener = triggers.listener

    /** The `ConsumerTail` body (§13.3 item 6): a time-triggered pass that returns by the deadline. */
    val consumerTail: ConsumerTail = triggers.consumerTail

    /**
     * A relay session start, a database open or the alarm (§21.9 rule 1). Posts. [sessionStart] is
     * true for the first alone (see [DmActor.onTimeTrigger]); the in-process timer's wake is bound in
     * [DmTriggers] and is no session start either.
     */
    fun onTimeTrigger(sessionStart: Boolean = false) {
        triggers.onTimeTrigger(sessionStart)
    }

    /** One hint, as the listener would deliver it; for a caller that holds a [SyncChange] alone. */
    fun onChange(change: SyncChange) {
        triggers.onChange(change)
    }

    /**
     * Opens the DM context for the identity [root] supplies (§2.5, §13.7 "Wiring"), on the actor
     * thread, after closing the previous one and dropping every key cached from it. [root] is
     * called on the actor thread; its result is zeroised whatever happens. Waits for the answer.
     */
    fun unlock(root: () -> RootEntropy?): DmKeys.Opened = actor.call { reopen(root) }

    /**
     * [unlock], posted: the wiring's form (S12 review), which never waits behind a pass. [wanted]
     * is asked **on the actor thread, in the same turn**, right before the context would open; when
     * it answers false — the app locked or wiped after this was posted — nothing opens. That is what
     * makes a lock sticky: a lock recorded after an unlock was posted still wins, whichever reaches
     * the actor first.
     */
    fun requestUnlock(root: () -> RootEntropy?, wanted: () -> Boolean) {
        actor.post { if (wanted()) reopen(root) }
    }

    /**
     * The K20 hook's body (§13.4) in **one actor turn** (S12 review): the context reopened from the
     * identity now stored, then ACTIVATE with the hook's own [restored] flag. As two turns, a
     * time-triggered pass could run between them and resume ACTIVATE with `restored = true` on its
     * own. Null when [wanted] answers false on the actor or the context did not open. Waits.
     */
    fun reopenAndActivate(root: () -> RootEntropy?, restored: Boolean, wanted: () -> Boolean): ActivationOutcome? =
        actor.call {
            if (!wanted()) return@call null
            if (reopen(root) != DmKeys.Opened.OPENED) return@call null
            if (restored) engine.onRestored() else engine.onActivated()
        }

    private fun reopen(root: () -> RootEntropy?): DmKeys.Opened {
        lockOnActor()
        return keys.open(database, root())
    }

    /**
     * Closes the DM context — `ctxClose` zeroises the native keys (§2.5) — and zeroises the
     * Kotlin-side key material in the same actor turn: the cached content key, `seen_key` and the own
     * card's secrets, and the recognition and provisional keys (§13.7 "Lock and wipe close the DM
     * context … and zeroize the Kotlin-side key material"). Waits for the turn.
     */
    fun lock() {
        actor.call { lockOnActor() }
    }

    /**
     * [lock], posted (S12 review): the lock screen's form, which returns at once instead of waiting
     * behind a pass on the main thread. Every facade call made after it queues behind it, so none
     * sees the context open.
     */
    fun requestLock() {
        actor.post { lockOnActor() }
    }

    private fun lockOnActor() {
        keys.close()
        forgetCachedKeys()
        peekOrder.clear()
        // The channel context closes with the DM's (§10.4 "State key": held in native memory while unlocked).
        channelEngine?.clear()
    }

    private fun forgetCachedKeys() {
        contexts.invalidate()
        recognition.clear()
    }

    /** §10.7: the in-process timer and the one alarm are cancelled at wipe (§22.14 item 11). */
    fun cancelWakes() {
        actor.call { schedule.cancel() }
    }

    /** True while the DM context is open. */
    val unlocked: Boolean get() = keys.isOpen

    /**
     * Stops the stack for good (§13.7 "Lock and wipe"; S12 review), in the order that makes it
     * final: no pass that has not started runs any more; after the pass in flight, one actor turn
     * closes the context, zeroises the Kotlin-side keys and cancels **both** wakes — the in-process
     * timer and the one alarm (§10.7: "cancelled … at wipe") — and the actor stops; then the timer's
     * thread stops. Nothing can reschedule the alarm after that turn, because nothing of this stack
     * runs after it. Blocks for as long as the pass in flight takes; idempotent.
     */
    override fun close() {
        actor.retire {
            lockOnActor()
            schedule.cancel()
        }
        triggers.close()
    }

    override fun toString(): String = "MessagingRuntime"
}
