package org.ghost.media.send

import java.util.concurrent.ConcurrentHashMap

/**
 * The preparation registry of Phase 11 design §6.5 (S0-23, S0 review I6): `QUEUED` carries a
 * `PreparationId`, and `preparationState` reports the preparation until its final state has been
 * read once. **Memory only**: a preparation writes no row before `MEDIA-COMMIT` (no history of
 * attempted sends, T33), and a process death loses it with its orphans — the UI then shows the
 * item as not sent. Thread-safe: the media worker writes, the facade reads.
 */
class Preparations {
    /** What `preparationState` answers. */
    sealed interface State {
        /** Work is running; [progress] is 0–99 (percent, a UI hint, not a protocol value). */
        data class Preparing(val progress: Int) : State

        /** `MEDIA-COMMIT` committed; the message id (16 bytes) is the item the UI follows. */
        class Committed(val messageId: ByteArray) : State

        /** The preparation failed with the typed reason; read once, then gone. */
        class Failed(val failure: PrepFailure) : State
    }

    private val states = ConcurrentHashMap<String, State>()

    /** Live (non-final) preparations: the [MediaSendLimits.MAX_CONCURRENT_PREPARATIONS] bound. */
    val liveCount: Int
        get() = states.count { it.value is State.Preparing }

    /**
     * Registers [id]; false when the concurrent-preparation bound is reached (the caller answers
     * `LIMIT_REACHED`-style, a local refusal visible to nobody else).
     */
    fun begin(id: String): Boolean {
        if (liveCount >= MediaSendLimits.MAX_CONCURRENT_PREPARATIONS) return false
        return states.putIfAbsent(id, State.Preparing(0)) == null
    }

    fun progress(id: String, percent: Int) {
        states.compute(id) { _, current ->
            if (current is State.Preparing) State.Preparing(percent.coerceIn(0, 99)) else current
        }
    }

    fun committed(id: String, messageId: ByteArray) {
        states[id] = State.Committed(messageId)
    }

    fun failed(id: String, failure: PrepFailure) {
        states[id] = State.Failed(failure)
    }

    /**
     * The state for [id]: null for an unknown id; **the final state is returned exactly once** —
     * a read of [State.Committed] or [State.Failed] removes it (§6.5: "null ... after the final
     * state was read once").
     */
    fun state(id: String): State? {
        val current = states[id] ?: return null
        if (current is State.Preparing) return current
        return if (states.remove(id, current)) current else null
    }

    override fun toString(): String = "Preparations"
}
