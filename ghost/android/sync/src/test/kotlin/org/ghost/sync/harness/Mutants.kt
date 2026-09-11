package org.ghost.sync.harness

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.engine.CallResult
import org.ghost.sync.engine.EngineContext
import org.ghost.sync.engine.ErrorClass
import org.ghost.sync.engine.ListStep
import org.ghost.sync.engine.Maintenance
import org.ghost.sync.engine.PageOutcome
import org.ghost.sync.engine.PairSchedule
import org.ghost.sync.engine.ReadItem
import org.ghost.sync.engine.StoreResult
import org.ghost.sync.engine.StoreStep
import org.ghost.sync.engine.Steps
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.engine.WorkContext
import org.ghost.sync.engine.relayCall
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose
import org.ghost.sync.store.DueStore
import org.ghost.sync.store.RetentionPolicy
import org.ghost.sync.store.StoreLease
import org.ghost.sync.store.Time

/** A substitution in the armed client (design §8.8: mutants live in test sources only). */
internal class Mutation(
    val steps: Steps? = null,
    val rewrite: ((World) -> (String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
    val consumeOutsideTransaction: Boolean = false,
)

/**
 * The mutant engines of design §8.8 (M1–M13) and §11.5 (M14 NoOwnTombstone, and the T19 mutants
 * M15 WorkFailureFeedsReadBreaker, M16 WorkPauseSuppressesLists, M17 ContinuationsUseEventWorkers).
 * Each is a classic bug, substituted as a step, a
 * statement rewrite (for the SQL-level ones) or a consumer change; `MutantDetectionTest` runs the
 * relevant scenario with each and expects the harness to report it.
 */
internal object Mutants {

    /** M1 CursorFirst: the cursor is committed in its own transaction before the page's hashes. */
    val M1 = Mutation(steps = Steps(list = object : ListStep() {
        override fun page(ctx: EngineContext, request: ReadItem): PageOutcome {
            val result = relayCall {
                ctx.port.list(request.relay, request.pair.namespace, request.token.token, request.cursor, request.limit, request.deadlineMillis)
            }
            val page = when (result) {
                is CallResult.Failed -> return PageOutcome.Failed(result)
                is CallResult.Ok -> result.value
            }
            val next = page.nextCursor
            if (next.isNotEmpty()) ctx.db.transaction { tx -> ctx.stores.cursorStore.put(tx, request.pair.relayId, request.pair.namespace, next) }
            val commit = ctx.db.transaction { tx ->
                ctx.stores.inboxStore.commitPage(tx, request.pair.relayId, request.pair.namespace, page.hashes, if (next.isNotEmpty()) next else request.cursor, next, ctx.now(), ctx.policy.backlogCap)
            }
            return PageOutcome.Committed(commit, page.hashes.size, next)
        }
    }))

    /** M2 QuorumOnAck: D1 counts acknowledged deliveries as if they were verified. */
    val M2 = Mutation(rewrite = { _ ->
        { sql, args ->
            Pair(sql.replace("WHERE d.operation_id = ?1 AND d.state = 'verified') >= required_operators", "WHERE d.operation_id = ?1 AND d.state IN ('verified', 'acked')) >= required_operators"), args)
        }
    })

    /** M3 ReencryptOnRetry: a retry sends freshly produced bytes instead of the frozen payload. */
    val M3 = Mutation(steps = Steps(store = object : StoreStep() {
        override fun attempt(ctx: WorkContext, due: DueStore): StoreResult {
            val relay = due.relayId
            val deadline = ctx.deadline(relay) ?: return StoreResult.SKIPPED
            val lease = ctx.db.transaction { tx -> ctx.stores.outboxStore.lease(tx, due.operationId, relay, ctx.now(), 60) } ?: return StoreResult.SKIPPED
            val pair = PairKey(relay, lease.namespace)
            val bytes = lease.ciphertext
            if (due.attempts > 0) bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor due.attempts).toByte()
            val stored = ctx.timed(relay) { relayCall { ctx.port.store(lease.relay, lease.namespace, lease.capability.token, bytes, lease.ttlSeconds, deadline) } }
            return when (stored) {
                is CallResult.Ok -> receipt(ctx, lease, stored.value)
                is CallResult.Failed -> storeFailed(ctx, lease, pair, stored)
            }
        }
    }))

    /** M4 ConsumeOutsideTx: markConsumed commits separately from the consumer's own effect. */
    val M4 = Mutation(consumeOutsideTransaction = true)

    /** M5 AckOnAnyResponse: `not_stored` and `malformed_response` on a store count as a receipt. */
    val M5 = Mutation(steps = Steps(store = object : StoreStep() {
        override fun storeFailed(ctx: WorkContext, lease: StoreLease, pair: PairKey, failed: CallResult.Failed): StoreResult {
            if (failed.category == "not_stored" || failed.category == "malformed_response") {
                ctx.db.transaction { tx ->
                    ctx.stores.outboxStore.recordReceipt(tx, lease.operationId, lease.relayId, ctx.now() + lease.ttlSeconds, ctx.now())
                }
                return StoreResult.ACKED
            }
            return super.storeFailed(ctx, lease, pair, failed)
        }
    }))

    /** M6 DedupByHashOnly: a listed hash known in any namespace is taken as already known here. */
    val M6 = Mutation(steps = Steps(list = object : ListStep() {
        override fun page(ctx: EngineContext, request: ReadItem): PageOutcome {
            val result = relayCall {
                ctx.port.list(request.relay, request.pair.namespace, request.token.token, request.cursor, request.limit, request.deadlineMillis)
            }
            val page = when (result) {
                is CallResult.Failed -> return PageOutcome.Failed(result)
                is CallResult.Ok -> result.value
            }
            val next = page.nextCursor
            val commit = ctx.db.transaction { tx ->
                val unknown = page.hashes.filter { h ->
                    var known = false
                    tx.sql.query("SELECT 1 FROM inbox_blob WHERE blob_hash = ?1 AND namespace_id <> ?2", listOf(h.toByteArray(), request.pair.namespace.toByteArray())) { known = true }
                    !known
                }
                ctx.stores.inboxStore.commitPage(tx, request.pair.relayId, request.pair.namespace, unknown, request.cursor, next, ctx.now(), ctx.policy.backlogCap)
            }
            return PageOutcome.Committed(commit, page.hashes.size, next)
        }
    }))

    /** M7 EmptyCursorStored: a caught-up page (empty next cursor) restarts the listing from the beginning. */
    val M7 = Mutation(steps = Steps(list = object : ListStep() {
        override fun page(ctx: EngineContext, request: ReadItem): PageOutcome {
            val out = super.page(ctx, request)
            if (out is PageOutcome.Committed && out.nextCursor.isEmpty()) {
                ctx.db.transaction { tx ->
                    tx.sql.execUpdate(
                        "DELETE FROM relay_cursor WHERE relay_id = ?1 AND namespace_id = ?2",
                        listOf(request.pair.relayId.value, request.pair.namespace.toByteArray()),
                    )
                }
            }
            return out
        }
    }))

    /** M8 RetainByFirstSeen: a fetched blob's tombstone ignores the relay expiry (first seen + 24 d). */
    val M8 = Mutation(rewrite = { w ->
        { sql, args ->
            if (sql.startsWith("UPDATE inbox_blob SET state = 'fetched'")) {
                val firstSeen = RetentionPolicy.ceil7(Time.day(w.clock.epochSeconds()) + RetentionPolicy.TAIL_DAYS)
                Pair(sql, args.toMutableList().also { it[1] = firstSeen })
            } else {
                Pair(sql, args)
            }
        }
    })

    /** M9 NoGenerationGuard: an old token's `unauthorized` marks the current generation rejected. */
    val M9 = Mutation(steps = Steps(store = object : StoreStep() {
        override fun storeFailed(ctx: WorkContext, lease: StoreLease, pair: PairKey, failed: CallResult.Failed): StoreResult {
            if (failed.errorClass != ErrorClass.NEEDS_CAPABILITY) return super.storeFailed(ctx, lease, pair, failed)
            ctx.db.transaction { tx ->
                val current = ctx.stores.capabilityStore.generation(tx, lease.relayId, lease.namespace, CapabilityKind.WRITE) ?: lease.capability.generation
                ctx.stores.outboxStore.parkForCapability(tx, lease.operationId, lease.relayId, lease.namespace, current, false, ctx.now())
            }
            return StoreResult.PARKED
        }
    }))

    /** M10 FailIgnoringCopies: D2 decides FAILED even when a copy may exist. */
    val M10 = Mutation(rewrite = { _ ->
        { sql, args ->
            if (sql.startsWith("UPDATE outbox_op SET outcome = CASE")) {
                Pair(
                    sql.replace("WHEN EXISTS (SELECT 1 FROM outbox_delivery d WHERE d.operation_id = ?1 AND d.copy_hour IS NOT NULL) THEN 'indeterminate' ", "")
                        .replace("AND ?2 < d.copy_hour + outbox_op.ttl_seconds - ?3)", "AND ?2 < d.copy_hour + outbox_op.ttl_seconds - ?3 AND 0)"),
                    args,
                )
            } else {
                Pair(sql, args)
            }
        }
    })

    /** M11 NoStoreWindow: stores continue after the store window (planning, lease and closure ignore it). */
    val M11 = Mutation(rewrite = { _ ->
        { sql, args ->
            Pair(
                sql.replace("x.copy_hour + ?2 <= ?1)", "x.copy_hour + ?2 <= ?1 AND 0)")
                    .replace("x.copy_hour + ?6 <= ?5)", "x.copy_hour + ?6 <= ?5 AND 0)")
                    .replace("x.copy_hour + ?4 <= ?5)", "x.copy_hour + ?4 <= ?5 AND 0)"),
                args,
            )
        }
    })

    /** M12 NoLeaseNormalization: M1 is omitted at session start. */
    val M12 = Mutation(steps = Steps(maintenance = object : Maintenance() {
        override fun normalize(ctx: EngineContext): Int = 0
    }))

    /** M13 SharedTick: one schedule for every pair (a single phase and step sequence). */
    val M13 = Mutation(steps = Steps(schedule = { random, policy -> SharedTick(random, policy) }))

    /**
     * M14 NoOwnTombstone (IN-2, S9 #4): the own `done` row (enqueue step 6 and a listening 0 → 1
     * transition) is written for another hash, so the client's own blobs are listed, fetched and
     * offered back to its consumer.
     */
    val M14 = Mutation(rewrite = { _ ->
        { sql, args ->
            if (sql.startsWith("INSERT INTO inbox_blob") && sql.contains("VALUES (?1, ?2, 'done', ?3)")) {
                Pair(sql.replace("VALUES (?1, ?2, 'done', ?3)", "VALUES (?1, zeroblob(length(?2)), 'done', ?3)"), args)
            } else {
                Pair(sql, args)
            }
        }
    })

    /**
     * M15 WorkFailureFeedsReadBreaker (T19): the failures a pair's fetches add to the work lane's
     * breaker are also counted against the read lane's breaker of that relay, so failing gets hold
     * back list events.
     */
    val M15 = Mutation(steps = Steps(fetch = object : org.ghost.sync.engine.FetchStep() {
        override fun run(ctx: WorkContext, pair: PairKey, limit: Int): Int {
            val session = ctx.engine.currentSession() ?: return super.run(ctx, pair, limit)
            val before = session.work.breaker.failures(pair.relayId)
            val fetched = super.run(ctx, pair, limit)
            val added = session.work.breaker.failures(pair.relayId) - before
            if (added > 0) session.read.breaker.failure(pair.relayId, added, ctx.monotonic())
            return fetched
        }
    }))

    /** M16 WorkPauseSuppressesLists (T19): a 24-hour pause of a pair's work (a refused get) also pauses its lists. */
    val M16 = Mutation(steps = Steps(fetch = object : org.ghost.sync.engine.FetchStep() {
        override fun run(ctx: WorkContext, pair: PairKey, limit: Int): Int {
            val fetched = super.run(ctx, pair, limit)
            if (ctx.engine.workPaused(pair, ctx.monotonic())) ctx.engine.pauseRead(pair, ctx.monotonic() + org.ghost.sync.engine.SyncEngine.PAUSE_MILLIS)
            return fetched
        }
    }))

    /**
     * M17 ContinuationsUseEventWorkers (T19): further STANDARD pages run inside the first page's item,
     * on an event worker, so inbound volume occupies event workers and moves or adds list requests.
     */
    val M17 = Mutation(steps = Steps(list = object : ListStep() {
        override fun page(ctx: EngineContext, request: ReadItem): PageOutcome {
            var out = super.page(ctx, request)
            var sent = request.cursor
            var page = request.page
            while (!request.continuation && page < request.pagesAllowed) {
                val committed = out as? PageOutcome.Committed ?: break
                val next = committed.nextCursor
                if (committed.hashes < request.limit || next.isEmpty() || next.contentEquals(sent)) break
                page++
                sent = next
                val result = relayCall {
                    ctx.port.list(request.relay, request.pair.namespace, request.token.token, sent, request.limit, request.deadlineMillis)
                }
                if (result !is CallResult.Ok) break
                val listed = result.value
                val commit = ctx.db.transaction { tx ->
                    ctx.stores.inboxStore.commitPage(
                        tx, request.pair.relayId, request.pair.namespace, listed.hashes, sent, listed.nextCursor, ctx.now(), ctx.policy.backlogCap,
                    )
                }
                out = PageOutcome.Committed(commit, listed.hashes.size, listed.nextCursor)
            }
            return out
        }
    }))

    private class SharedTick(private val random: RandomSources, private val policy: TrafficPolicy) : PairSchedule(random, policy) {
        private val shared = PairKey(org.ghost.sync.api.RelayId(0), org.ghost.sync.api.NamespaceId(ByteArray(32)))

        override fun firstTime(pair: PairKey, anchor: Long): Long =
            anchor + scaled(policy.intervalMillis, random.schedule(shared, SchedulePurpose.FOREGROUND_START, 0))

        override fun nextTime(pair: PairKey, index: Long, time: Long): Long =
            time + scaled(policy.intervalMillis, 0.5 + random.schedule(shared, SchedulePurpose.FOREGROUND_STEP, index))
    }
}
