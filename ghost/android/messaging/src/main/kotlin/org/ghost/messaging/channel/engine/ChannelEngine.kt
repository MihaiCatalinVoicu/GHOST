package org.ghost.messaging.channel.engine

import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.api.PostId
import org.ghost.messaging.api.PostResult

/**
 * What the messaging actor runs of the channel engine (Phase 10 design §7.7, D16: one actor drains `Consumer.DM` and
 * `Consumer.CHANNEL`). The DM actor calls [runPass] at the end of each of its passes, with the same trigger, and
 * [clear] in the turn that closes the contexts (lock, wipe).
 */
internal interface ChannelPassSteps {
    /** One channel pass (see [ChannelEngine.runPass]). */
    fun runPass(timeTriggered: Boolean, deadlineMonotonicMillis: Long?, sessionStart: Boolean)

    /** Seconds until the channel engine's next wake (a settle point, a scheduled pass, a gap hold), or null. */
    fun nextWakeSeconds(): Long?

    /** Closes the native channel context and forgets what the passes kept in memory. */
    fun clear()
}

/** The single writer the user actions run on (`DmActor.call`; a test world runs them inline). */
internal interface ChannelActor {
    fun <T> call(body: () -> T): T
}

/**
 * **The channel engine** (Phase 10 design §10.1 `…messaging.channel.engine`, §10.4; slice S4): the user actions
 * `CH-CREATE`, `CH-INVITE`, `CH-ACCEPT` and `CH-POST`, each run on the messaging actor ([ChannelActor]) and each one
 * transaction; and the actor's pass over the channels ([runPass]), in this order:
 *
 *  1. `CH-OUTCOME` — the outcomes already in, so the receive step sees a settled outbox and the settle a verified own commit;
 *  2. `CH-RECV` and `CH-SETTLE`, repeated while a settle re-offered deferred blobs that the next receive can open — a
 *     returning member settles each missed epoch right after the receive that brought its blobs (CO-4's catch-up), up to
 *     [CATCH_UP_ROUNDS] rounds a pass;
 *  3. the pending posts of the channels that are current now (`CH-POST`'s encrypt-at-session, §6.3.1);
 *  4. on a **time-triggered** pass only (§21.9 rule 1 of Phase 9, T40): the scheduled passes (`CH-PASS`, CO-8 and
 *     CO-9: admissions by any committer under the work-age rule, the PCS cadence, the rank-255 self-update slots;
 *     a relay session start schedules them into `ch_schedule`) and the join expiry (`CH-SWEEP`'s join half). A pass
 *     a listener hint ran — something arrived — never commits, never enqueues a Welcome's op of its own accord and
 *     never removes a namespace: only an outcome of the user's own earlier action (the own winning commit's Welcomes
 *     at its settle) and the user's own pending posts can cause an enqueue in it.
 *
 * **Typed results, no logging, no network or coroutine class** (gates G-DM1, no-logging); the only exceptions caught are
 * the typed ones of `:sync` and `:storage` (`InsufficientReplicasException`, `StorageFullException`) and the facade's
 * `IllegalStateException` around a native call (gate sync-no-catch-all).
 */
internal class ChannelEngine(
    private val env: ChannelEnv,
    sync: ChannelSyncPorts,
    private val actor: ChannelActor,
    /** The receive step's peek window (§19.38); production keeps the default, a world may narrow it. */
    peekLimit: Int = ChannelReceiveStep.PEEK_LIMIT,
    /** Phase 7's fetched cap of a namespace, as the receive step reads pressure from it (§19.38). */
    fetchedCap: Int = org.ghost.sync.store.StoreLimits.FETCHED_CAP,
) : ChannelPassSteps {
    private val peekOrder = ChannelPeekOrder()
    val postStep = ChannelPostStep(env, sync)
    val createStep = ChannelCreateStep(env, sync)
    val inviteStep = ChannelInviteStep(env, postStep)
    val acceptStep = ChannelAcceptStep(env, sync)
    val joinStep = ChannelJoinStep(env, sync)
    val livenessStep = ChannelLivenessStep(env)
    val receiveStep = ChannelReceiveStep(env, sync, joinStep, peekOrder, peekLimit, fetchedCap, livenessStep)
    val passStep = ChannelPassStep(env, sync, postStep)
    val settleStep = ChannelSettleStep(env, sync, livenessStep)
    val outcomeStep = ChannelOutcomeStep(env, sync)
    val sweepStep = ChannelSweepStep(env, sync)

    /**
     * The second the last **time-triggered** pass began (§19.38, the DM actor's `lastTimeTriggeredSecond`): a wake term
     * that fell due at or before it was offered to that pass, whatever the pass made of it, so [nextWakeSeconds] stops
     * waking for it — a settle point whose only candidate is an own commit still unverified, a hold the pass could not end.
     */
    private var lastTimeTriggered: Long = Long.MIN_VALUE

    /** The counters (counts only, T3). */
    val counters: ChannelCounters get() = env.counters

    // ------------------------------------------------------------------------------------------- user actions

    /** `CH-CREATE` (§6.1). [name] is UTF-8, at most 48 bytes; [timerCode] 0 … 5; [sizeClass] 0 small, 1 large. */
    fun create(name: ByteArray, timerCode: Int, sizeClass: Int, passwordRequired: Boolean): CreateResult =
        actor.call { createStep.create(name, timerCode, sizeClass, passwordRequired) }

    /** `CH-INVITE` (§6.2.1): the link's bytes on success. [password] stays the caller's to zero. */
    fun invite(channel: ChannelId, expiryDays: Int, password: CharArray?): InviteResult =
        actor.call { inviteStep.invite(channel.toByteArray(), expiryDays, password) }

    /** `CH-ACCEPT` (§6.2.2): [link] is the `ghost://channel/` link's bytes. [password] stays the caller's to zero. */
    fun accept(link: ByteArray, password: CharArray?): AcceptResult = actor.call { acceptStep.accept(link, password) }

    /** `CH-POST` of a text post (§6.3.1); [replyTo] is a post's id or null. */
    fun post(channel: ChannelId, text: ByteArray, replyTo: PostId?): PostResult =
        actor.call {
            postStep.post(channel.toByteArray(), ChannelPostStep.KIND_POST, text, replyTo?.toByteArray(), null, null)
        }

    /**
     * `CH-PASS` at a user action: [member] removed from [channel], at once, whatever the committer's rank
     * (§6.6, §19.13 item 4: a moderator's Remove does not wait for the owner). CO-7 (D-1) settles first — in the
     * same actor step the pass then works in e + 1 where the channel is current; when the settle point has not
     * come the pass waits and answers [RemoveResult.NOTHING].
     */
    fun remove(channel: ChannelId, member: ByteArray): RemoveResult =
        actor.call {
            settleStep.settle(channel.toByteArray())
            when (passStep.removeMember(channel.toByteArray(), member)) {
                ChannelPassStep.Result.COMMITTED -> RemoveResult.REMOVED
                ChannelPassStep.Result.UNAVAILABLE -> RemoveResult.UNAVAILABLE
                ChannelPassStep.Result.REFUSED_ONLY, ChannelPassStep.Result.NOTHING -> RemoveResult.NOTHING
            }
        }

    /** `CH-POST` of a reaction (§5.5): an empty [grapheme] withdraws it. */
    fun react(channel: ChannelId, target: PostId, grapheme: ByteArray): PostResult =
        actor.call {
            postStep.post(channel.toByteArray(), ChannelPostStep.KIND_REACTION, null, null, target.toByteArray(), grapheme)
        }

    /** The user's retry of an own failed post (§6.11, `CH-POST`): the same op id, re-encrypted now. */
    fun retry(channel: ChannelId, post: PostId): PostResult =
        actor.call { postStep.retryPost(channel.toByteArray(), post.toByteArray()) }

    // ------------------------------------------------------------------------------------------- the pass

    override fun runPass(timeTriggered: Boolean, deadlineMonotonicMillis: Long?, sessionStart: Boolean) {
        if (env.keys.content() == null) return
        if (timeTriggered) lastTimeTriggered = env.now()
        outcomeStep.run()
        var rounds = 0
        while (rounds < CATCH_UP_ROUNDS) {
            rounds++
            receiveStep.consume(deadlineMonotonicMillis)
            if (settleStep.settleDue() == 0) break
        }
        livenessStep.evaluate()
        postStep.encryptPending()
        if (timeTriggered) {
            if (sessionStart) passStep.scheduleAtSessionStart()
            passStep.runScheduledPasses()
            sweepStep.sweepJoins()
        }
    }

    /**
     * A due term is a wake at once **until a time-triggered pass has begun at or after it** (§19.38): every actor pass
     * ends by re-arming the timer with this minimum, so a term at or before now that the pass could not clear — the settle
     * point of an own commit whose outcome has not come (CO-4 waits for it, and the outcome arrives as a hint), the end of
     * a hold the pass found still needed — would otherwise re-arm a wake at once, for ever: the actor spun (638 passes in
     * two seconds, measured by the review of S4). From then on the term is left to the passes that come anyway.
     */
    override fun nextWakeSeconds(): Long? {
        val now = env.now()
        return listOfNotNull(settleStep.nextDue(), passStep.nextDue(), peekOrder.holdEnds())
            .filter { due -> due > now || due > lastTimeTriggered }
            .minOrNull()
            ?.let { maxOf(0L, it - now) }
    }

    override fun clear() {
        env.contexts.close()
        peekOrder.clear()
        receiveStep.clear()
        lastTimeTriggered = Long.MIN_VALUE
    }

    override fun toString(): String = "ChannelEngine"

    /** What [remove] did (§10.3's `Result` shape; the facade maps it in Phase 13). */
    enum class RemoveResult {
        /** The Remove commit was built, enqueued and the own candidate recorded. */
        REMOVED,

        /** Nothing removed: a CO-7 precondition, an unknown target, or the native CO-2 rank rule refused. */
        NOTHING,

        /** The context or the content key is not available. */
        UNAVAILABLE,
    }

    companion object {
        /** CO-4's catch-up: receive and settle rounds per pass (a returning member's missed epochs, one per round). */
        const val CATCH_UP_ROUNDS: Int = 17
    }
}
