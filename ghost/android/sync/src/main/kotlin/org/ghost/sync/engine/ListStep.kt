package org.ghost.sync.engine

import org.ghost.sync.store.PageCommit
import org.ghost.sync.store.StoreLimits

/** Result of one list request of the read lane. */
internal sealed class PageOutcome {
    /** The page came back and its transaction committed (or dropped it, see [PageCommit.disposition]). */
    class Committed(val commit: PageCommit, val hashes: Int, nextCursor: ByteArray) : PageOutcome() {
        private val next: ByteArray = nextCursor.copyOf()

        /** The relay's next cursor: empty when caught up, otherwise 8 opaque bytes. */
        val nextCursor: ByteArray get() = next.copyOf()

        override fun toString(): String = "Committed(${commit.disposition}, hashes=$hashes)"
    }

    /** The call failed; nothing was written except, for `unauthorized`, the token's refusal. */
    class Failed(val failure: CallResult.Failed) : PageOutcome() {
        override fun toString(): String = "Failed(${failure.errorClass})"
    }
}

/**
 * List step of the read lane (design §4.1). One request is sent from the lane's in-memory snapshot
 * (cursor, token, generation; no database read before the send), and its page is committed in
 * **one** transaction: rows, sources, own-copy verification and, only for a non-empty next cursor,
 * the cursor (IN-3; an empty cursor keeps the stored one, the sticky tail). The lane decides
 * whether a further page follows.
 *
 * Open so the exit-gate harness can substitute mutants (design §8.8 M1 CursorFirst, M7 EmptyCursorStored).
 */
internal open class ListStep {

    open fun page(ctx: EngineContext, request: ReadItem): PageOutcome {
        val result = relayCall {
            ctx.port.list(request.relay, request.pair.namespace, request.token.token, request.cursor, request.limit, request.deadlineMillis)
        }
        val page = when (result) {
            is CallResult.Failed -> {
                if (result.errorClass == ErrorClass.NEEDS_CAPABILITY) refuse(ctx, request)
                return PageOutcome.Failed(result)
            }
            is CallResult.Ok -> result.value
        }
        // Rust already bounds the page and the cursor; a page that is still out of bounds is hostile.
        val next = page.nextCursor
        if (page.hashes.size > request.limit || (next.isNotEmpty() && next.size != StoreLimits.CURSOR_SIZE)) {
            return PageOutcome.Failed(CallResult.Failed(null, ErrorClass.RELAY_HOSTILE))
        }
        val commit = ctx.db.transaction { tx ->
            ctx.stores.inboxStore.commitPage(
                tx, request.pair.relayId, request.pair.namespace, page.hashes, next, ctx.now(), ctx.policy.backlogCap,
            )
        }
        return PageOutcome.Committed(commit, page.hashes.size, next)
    }

    /** `unauthorized`: the token of the generation the request used is refused (generation-guarded, design §3.8). */
    protected open fun refuse(ctx: EngineContext, request: ReadItem) {
        ctx.db.transaction { tx ->
            ctx.stores.capabilityStore.refuse(
                tx, request.pair.relayId, request.pair.namespace, request.token.kind, request.token.generation, exhausted = false,
            )
        }
    }

    override fun toString(): String = "ListStep"
}
