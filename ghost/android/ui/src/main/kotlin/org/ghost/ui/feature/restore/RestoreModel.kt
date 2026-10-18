package org.ghost.ui.feature.restore

import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.RestoreResult
import org.ghost.ui.gateway.SettingsGateway
import org.ghost.ui.gateway.UserAction

/**
 * Phase 13 design §5.7: the restore journey — "what comes back and what does not" before any
 * typing, then D36's order (database key, PIN, the mode — and only then the words), the local
 * restore, the notification step, and the "next steps" screen. Contacts, conversations, access
 * tokens and unused credits do not come back (E11); the copy says exactly that.
 *
 * The NFR-10 clock (spec p.12, §5.7 step 6) runs from the first PIN key on the restore path to
 * the home screen; the model records it through [clockMillis] so the journey harness can report
 * the median.
 */
class RestoreModel(
    private val identity: IdentityGateway,
    private val settings: SettingsGateway,
    private val clockMillis: () -> Long = { 0L },
) {
    enum class Step { INTRO, LOCK, PRIVACY, WORDS, RESTORING, NEXT_STEPS, DONE }

    var step: Step = Step.INTRO
        private set

    private var clockStartMs = -1L

    /** The recorded NFR-10 duration in milliseconds; -1 until the journey finishes. */
    var recordedDurationMs: Long = -1L
        private set

    fun onIntroRead() {
        check(step == Step.INTRO) { "onIntroRead only from INTRO, was $step" }
        step = Step.LOCK
    }

    /** The first PIN key on the restore path starts the NFR-10 clock (§5.7 step 6). */
    fun onLockConfigured() {
        check(step == Step.LOCK) { "onLockConfigured only from LOCK, was $step" }
        if (clockStartMs < 0) clockStartMs = clockMillis()
        step = Step.PRIVACY
    }

    @UserAction
    suspend fun onChooseMode(mode: org.ghost.ui.gateway.PrivacyMode) {
        check(step == Step.PRIVACY) { "onChooseMode only from PRIVACY, was $step" }
        settings.setPrivacyMode(mode)
        step = Step.WORDS
    }

    /** The 24 words were typed on the WordKeyboard and validated locally (§5.7 step 3). */
    @UserAction
    suspend fun onWordsConfirmed(words: List<String>): RestoreResult {
        check(step == Step.WORDS) { "onWordsConfirmed only from WORDS, was $step" }
        step = Step.RESTORING
        val result = identity.restore(words)
        step = when (result) {
            RestoreResult.RESTORED -> Step.NEXT_STEPS
            else -> Step.WORDS
        }
        return result
    }

    fun onNextStepsRead() {
        check(step == Step.NEXT_STEPS) { "onNextStepsRead only from NEXT_STEPS, was $step" }
        step = Step.DONE
        recordedDurationMs = clockMillis() - clockStartMs
    }

    suspend fun activationState(): ActivationState = identity.activationState()
}
