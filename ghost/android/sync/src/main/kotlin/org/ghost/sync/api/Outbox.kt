package org.ghost.sync.api

/**
 * One outbound blob. The ciphertext is exactly one bucket and is frozen at enqueue: every store of
 * the operation sends these bytes (design D2, OUT-3). [deadlineEpochSeconds] null = no deadline.
 */
class OutboundBlob(
    val operationId: OperationId,
    val namespace: NamespaceId,
    ciphertext: ByteArray,
    val ttl: TtlBucket,
    val deadlineEpochSeconds: Long? = null,
) {
    private val payload: ByteArray

    init {
        require(ciphertext.size in Buckets.SIZES) { "ciphertext is not one bucket" }
        payload = ciphertext.copyOf()
    }

    val ciphertext: ByteArray get() = payload.copyOf()

    internal val rawCiphertext: ByteArray get() = payload

    override fun toString(): String = "OutboundBlob(redacted)"
}

sealed interface EnqueueResult {
    data object Enqueued : EnqueueResult
    data object AlreadyEnqueued : EnqueueResult
}

/**
 * A decided, not yet released outcome. [resendNotAfterEpochSeconds] is set for
 * [Outcome.INDETERMINATE] only: the identical bytes may be enqueued again as a new operation
 * (after release) until this time, the earliest possible copy's hour + TTL − σ (design §11.2 #6).
 */
class OutboundOutcome(
    val operationId: OperationId,
    val namespace: NamespaceId,
    val outcome: Outcome,
    val resendNotAfterEpochSeconds: Long?,
) {
    override fun toString(): String = "OutboundOutcome($outcome)"
}

/** For UI ticks; counts only. [outcome] is null while undecided. */
class OutboxProgress(
    val acknowledgedOperators: Int,
    val verifiedOperators: Int,
    val requiredOperators: Int,
    val outcome: Outcome?,
) {
    override fun toString(): String =
        "OutboxProgress(acknowledged=$acknowledgedOperators, verified=$verifiedOperators, required=$requiredOperators, outcome=$outcome)"
}

interface Outbox {
    /**
     * In the caller's transaction. Throws on invalid input, a conflict, a closed resend window, or
     * fewer than 2 operators ([InsufficientReplicasException]); the caller's transaction then rolls
     * back. Never wakes anything.
     */
    fun enqueue(tx: SyncTransaction, blob: OutboundBlob): EnqueueResult

    /** True only while no attempt could have left a copy; the operation then ends FAILED. */
    fun cancel(tx: SyncTransaction, operationId: OperationId): Boolean

    fun progress(operationId: OperationId): OutboxProgress?

    /** Decided, not yet released outcomes of the consumer's namespaces. */
    fun outcomes(consumer: Consumer, limit: Int): List<OutboundOutcome>

    /** True exactly once per operation; make your effect conditional on it, in the same transaction. */
    fun release(tx: SyncTransaction, operationId: OperationId): Boolean
}
