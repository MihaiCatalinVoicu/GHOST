package org.ghost.messaging.engine

import org.ghost.media.send.PrepFailure
import org.ghost.media.store.MediaObjects
import org.ghost.media.store.RetryResult
import org.ghost.messaging.api.MediaSendResult
import org.ghost.messaging.api.PreparationId
import org.ghost.messaging.api.PreparationView
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.port.DmRandom
import org.ghost.sync.api.SyncDatabase
import java.util.concurrent.ExecutorService

/**
 * The facade's media half (Phase 11 design §6.5), holding what the [MessagingEngine] cannot own:
 * the [Preparations] registry (S0-23), the media worker of §13.7 (`ghost-media-prep`, one thread —
 * sandbox calls, Transformer, sealing; no transaction), and the bridge that runs a finished
 * preparation into `MEDIA-COMMIT` on the DM actor and then releases the reserved file names.
 *
 * Everything here is local: the change listener the facade fires is the engine's own; nothing a
 * preparation does reaches a relay except through the `MEDIA-FEED` the actor runs after a commit.
 */
internal class MediaEngineSupport(
    private val database: SyncDatabase,
    private val steps: MediaSteps,
    private val preparer: org.ghost.media.send.MediaPreparer,
    private val preparations: org.ghost.media.send.Preparations,
    private val pipeline: MediaPipelinePorts,
    private val worker: ExecutorService,
    private val random: DmRandom,
    private val contexts: SelfContexts,
    private val actorCall: (() -> Unit) -> Unit,
) {
    private val objects = MediaObjects(org.ghost.media.store.MediaFragments())

    /** §6.6's free-space check the engine's pre-checks read (the store's typed answer). */
    fun freeSpace(): Long = pipeline.files.freeSpace()

    /** The registry's concurrent bound (§6.5): false → `LIMIT_REACHED`. */
    fun begin(preparation: PreparationId): Boolean = preparations.begin(preparation.id)

    /** The worker-side runs, called inside [startPreparation]'s lambda. */
    fun prepareImage(source: ByteArray, destId: ByteArray, viewOnce: Boolean) =
        preparer.prepareImage(source, destId, viewOnce)

    fun prepareVideo(
        source: org.ghost.media.send.VideoSource,
        destId: ByteArray,
        viewOnce: Boolean,
        maxClass: Int,
    ) = preparer.prepareVideo(source, destId, viewOnce, maxClass)

    /** The actor-side steps, for the pass hooks (`DmActor` runs them on its thread). */
    fun stepsForPass(): MediaSteps = steps

    /** §13.7's worker thread name. */
    companion object {
        const val WORKER_THREAD: String = "ghost-media-prep"
    }

    /** The engine's pre-checks ran and the registry has the id: run the preparation off-actor. */
    fun startPreparation(
        preparation: PreparationId,
        run: () -> org.ghost.media.send.MediaPreparer.Prepared,
        caption: ByteArray,
        contactId: ByteArray,
    ) {
        worker.submit {
            try {
                val prepared = run()
                // The context is resolved on the actor, in the S8 rule's order (before the
                // commit's transaction, which the actor's seriality makes sound).
                var committed: ByteArray? = null
                var failure: PrepFailure? = null
                actorCall {
                    val self = contexts.get()
                    if (self == null) {
                        failure = PrepFailure.Cancelled
                        return@actorCall
                    }
                    when (val result = steps.commit(self, request(prepared, caption, contactId))) {
                        is MediaSteps.CommitResult.Committed -> {
                            steps.feed()
                            committed = result.messageId
                        }
                        // A commit-time refusal is a race the pre-checks could not see (the slot
                        // table, the disk). PrepFailure has no value for NO_REPLICAS; the refusal
                        // is cancellation-shaped and counted (§22.8 F-S5-8's reading).
                        is MediaSteps.CommitResult.Refused ->
                            failure = when (result.outcome) {
                                SendStep.Outcome.STORAGE_FULL -> PrepFailure.StorageFull
                                else -> PrepFailure.Cancelled
                            }
                        MediaSteps.CommitResult.NoReplicas -> failure = PrepFailure.Cancelled
                        MediaSteps.CommitResult.Unavailable -> failure = PrepFailure.Cancelled
                    }
                }
                prepared.releaseNames()
                val messageId = committed
                if (messageId != null) {
                    preparations.committed(preparation.id, messageId)
                } else {
                    preparations.failed(preparation.id, failure ?: PrepFailure.Cancelled)
                }
            } catch (e: org.ghost.media.send.MediaPreparer.Refused) {
                preparations.failed(preparation.id, e.failure)
            } catch (e: Throwable) {
                // A defect of the pipeline (a store refusal, an unexpected throw): the preparation
                // is cancelled; its orphans reconcile; the actor's crash fidelity is untouched
                // because this is the worker thread, not the actor's.
                preparations.failed(preparation.id, PrepFailure.Cancelled)
            }
        }
    }

    private fun request(
        prepared: org.ghost.media.send.MediaPreparer.Prepared,
        caption: ByteArray,
        contactId: ByteArray,
    ): MediaSteps.CommitRequest {
        val sealed = prepared.sealed
        return MediaSteps.CommitRequest(
            contactId = contactId,
            kind = if (prepared.kind == org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE) {
                org.ghost.media.store.MediaKind.IMAGE
            } else {
                org.ghost.media.store.MediaKind.VIDEO
            },
            viewOnce = prepared.viewOnce,
            classCode = sealed.classCode,
            objectId = prepared.objectId,
            manifestHash = sealed.manifestHash,
            caption = caption,
            keyEnv = sealed.keyEnv,
            manifestBlob = sealed.manifestBlob,
            manifestFile = sealed.manifestFile,
            fragmentHashes = sealed.fragmentHashes,
            fragmentFiles = sealed.fragmentFiles,
        )
    }

    /** §6.5's `preparationState`: the registry's answer, mapped; null after the final read. */
    fun preparationState(preparation: PreparationId): PreparationView? =
        when (val state = preparations.state(preparation.id)) {
            null -> null
            is org.ghost.media.send.Preparations.State.Preparing ->
                PreparationView.Preparing(state.progress)
            is org.ghost.media.send.Preparations.State.Committed ->
                PreparationView.Committed(org.ghost.messaging.api.MessageId(state.messageId))
            is org.ghost.media.send.Preparations.State.Failed ->
                PreparationView.Failed(state.failure)
        }

    /** §6.5's `retryMedia`: the object of the message must be a failed upload, before the deadline. */
    fun retryMedia(messageId: ByteArray): SendResult {
        val nowE = steps.nowE()
        val objectId = database.transaction { tx ->
            objects.byMessage(tx.sql, messageId, nowE)?.takeIf {
                it.role == org.ghost.media.store.MediaRole.OUT
            }?.objectId
        } ?: return SendResult.UNKNOWN
        return database.transaction { tx ->
            when (objects.retryUpload(tx, objectId, nowE)) {
                RetryResult.RETRIED -> {
                    steps.feed()
                    SendResult.QUEUED
                }
                RetryResult.DEADLINE_PASSED -> SendResult.DEADLINE_PASSED
                RetryResult.NOT_RETRYABLE -> SendResult.NOT_RETRYABLE
                RetryResult.RETRIES_EXHAUSTED,
                RetryResult.NOT_FAILED,
                -> SendResult.UNKNOWN
                RetryResult.NO_SUCH_OBJECT -> SendResult.UNKNOWN
            }
        }
    }

    /** A fresh local preparation id (S0-23: random, local, no row before the commit). */
    fun newPreparationId(): PreparationId =
        PreparationId(random.bytes(8).joinToString("") { "%02x".format(it) })

    fun close() {
        worker.shutdown()
    }
}
