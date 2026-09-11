package org.ghost.sync.engine

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Buckets
import org.ghost.sync.port.PairKey
import org.ghost.sync.store.CapabilityToken
import org.ghost.sync.store.sha256

/**
 * Fetch step of the work lane (design §4.2), run in a pair's event bundle after its list. Up to
 * [limit] listed rows for which the pair's relay is a source are leased (write-ahead backoff), fetched
 * and committed; a hostile relay therefore spends only its own pair's slots. The ciphertext's hash
 * and bucket size are checked here before the store sees them (Rust has checked them too).
 */
internal open class FetchStep {

    private class Plan(val relay: OnionAddress, val token: CapabilityToken, val due: List<Pair<BlobHash, Int>>)

    /** Returns the number of blobs fetched. */
    open fun run(ctx: WorkContext, pair: PairKey, limit: Int): Int {
        if (!ctx.allows(pair)) return 0
        val plan = ctx.db.transaction { tx ->
            val now = ctx.now()
            val token = ctx.stores.capabilityStore.forReading(tx, pair.relayId, pair.namespace, now)
            val relay = ctx.stores.directoryStore.address(tx, pair.relayId)
            if (token == null || relay == null) {
                null
            } else {
                val due = ctx.stores.inboxStore.dueFetches(tx, pair.relayId, pair.namespace, now, limit, ctx.policy.fetchedCap).map { hash ->
                    Pair(hash, ctx.stores.inboxStore.fetchAttempts(tx, pair.namespace, hash) ?: 0)
                }
                Plan(relay, token, due)
            }
        } ?: return 0
        var fetched = 0
        for ((hash, attempts) in plan.due) {
            if (!ctx.allows(pair)) break
            val deadline = ctx.deadline(pair.relayId) ?: break
            val backoff = Backoff.retrySeconds(attempts + 1, ctx.selection())
            val leased = ctx.db.transaction { tx -> ctx.stores.inboxStore.leaseFetch(tx, pair.namespace, hash, ctx.now(), backoff) }
            if (!leased) continue
            val result = ctx.timed(pair.relayId) {
                relayCall { ctx.port.get(plan.relay, pair.namespace, plan.token.token, hash, deadline) }
            }
            when (result) {
                is CallResult.Ok -> {
                    val ciphertext = result.value.ciphertext
                    if (ciphertext.size !in Buckets.SIZES || sha256(ciphertext) != hash) {
                        // Wrong bytes: the source is bad; another candidate may serve the blob.
                        ctx.db.transaction { tx -> ctx.stores.inboxStore.recordBadSource(tx, pair.relayId, pair.namespace, hash, ctx.now()) }
                        ctx.failure(pair.relayId, HOSTILE_WEIGHT)
                        continue
                    }
                    val stored = ctx.db.transaction { tx ->
                        ctx.stores.inboxStore.recordFetched(tx, pair.namespace, hash, ciphertext, result.value.expiryUnixSeconds)
                    }
                    ctx.success(pair.relayId)
                    if (stored) fetched++
                }
                is CallResult.Failed -> {
                    val action = ctx.readFailure(pair, plan.token, result, isGet = true)
                    when (action) {
                        ReadAction.NOT_FOUND -> ctx.db.transaction { tx ->
                            ctx.stores.inboxStore.recordNotFound(tx, pair.relayId, pair.namespace, hash, ctx.now())
                        }
                        ReadAction.HOSTILE -> ctx.db.transaction { tx ->
                            ctx.stores.inboxStore.recordBadSource(tx, pair.relayId, pair.namespace, hash, ctx.now())
                        }
                        ReadAction.SKIP -> Unit
                        // The transport stopped, the token was refused or the pair is paused: no further get now.
                        ReadAction.STOP, ReadAction.SUSPEND, ReadAction.PAUSE -> return fetched
                    }
                }
            }
        }
        return fetched
    }

    override fun toString(): String = "FetchStep"

    companion object {
        /** Breaker weight of a hostile answer (design §3.6). */
        const val HOSTILE_WEIGHT: Int = 2
    }
}
