package org.ghost.ui.feature.onboarding

import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.InvitePreview
import org.ghost.ui.gateway.RestoreResult
import org.ghost.ui.gateway.SettingsGateway
import org.ghost.ui.gateway.UserAction

/**
 * Phase 13 design §6.2 (J1) and D36's order: the onboarding state machine, one intent per user
 * action, each `on…` handler the only place a [UserAction] gateway call may sit (PV-14, G-U5).
 *
 * The order is the design's, not the code's: database key → PIN → **privacy mode** → invite →
 * activation → the 24 words → backup verification → notifications → disclosures. D36 moved the
 * mode before the words and the trial so a HIGH user's access follows HIGH from the first
 * session (MC-U12) — `onChooseMode` therefore runs before `onWordsShown`, and the words screen
 * is unreachable while no lock exists (MC-U13): the step order enforces it, and the model test
 * drives every illegal jump.
 *
 * States are content-free; the words travel as indices and the invite as its inspected text,
 * never joined secrets.
 */
class OnboardingModel(
    private val identity: IdentityGateway,
    private val settings: SettingsGateway,
) {
    enum class Step(val index: Int) {
        WELCOME(0), PREPARE(1), LOCK(2), PRIVACY(3), INVITE(4), ACTIVATING(5),
        WORDS(6), BACKUP(7), NOTIFICATIONS(8), DISCLOSURES(9), DONE(10),
    }

    var step: Step = Step.WELCOME
        private set

    /** The invitation text under activation, null before step INVITE accepts one. */
    private var pendingInvite: String? = null

    fun wordsAllowed(): Boolean = step >= Step.WORDS

    /** Welcome's "Am o invitație": the prepare step starts (§6.2 step 1→2). */
    fun onWelcomeInvite() {
        check(step == Step.WELCOME) { "onWelcomeInvite only from WELCOME, was $step" }
        step = Step.PREPARE
    }

    /** Step 1's exit: the database key exists; the flow moves to the lock step (§6.2 step 2→3). */
    fun onPrepared() {
        check(step == Step.PREPARE) { "onPrepared only from PREPARE, was $step" }
        step = Step.LOCK
    }

    /** The PIN is set (typed twice by the user on the lock step's keypad). */
    fun onLockSet() {
        check(step == Step.LOCK) { "onLockSet only from LOCK, was $step" }
        step = Step.PRIVACY
    }

    /** D36: the mode is chosen BEFORE the trial and the words (MC-U12). */
    @UserAction
    suspend fun onChooseMode(mode: org.ghost.ui.gateway.PrivacyMode) {
        check(step == Step.PRIVACY) { "onChooseMode only from PRIVACY, was $step" }
        settings.setPrivacyMode(mode)
        step = Step.INVITE
    }

    /** The user scanned/pasted an invite; it is inspected locally, then confirmed (§6.2 step 5). */
    suspend fun onInviteInspect(text: String): InvitePreview {
        check(step == Step.INVITE) { "onInviteInspect only from INVITE, was $step" }
        return identity.inspectInvite(text)
    }

    /** The confirmation screen's acceptance: ACTIVATE runs here, and only here. */
    @UserAction
    suspend fun onInviteConfirmed(text: String): ActivateResult {
        check(step == Step.INVITE) { "onInviteConfirmed only from INVITE, was $step" }
        step = Step.ACTIVATING
        val result = identity.activateInvite(text)
        step = when (result) {
            ActivateResult.ACTIVATED, ActivateResult.ALREADY_ACTIVE -> Step.WORDS
            else -> Step.INVITE
        }
        return result
    }

    /** Genesis builds only (Q21): the caller checks the build's policy before this runs. */
    @UserAction
    suspend fun onGenesisConfirmed(acknowledged: Boolean): ActivateResult {
        check(step == Step.INVITE) { "onGenesisConfirmed only from INVITE, was $step" }
        step = Step.ACTIVATING
        val result = identity.activateGenesis(acknowledged = true)
        step = if (result == ActivateResult.ACTIVATED || result == ActivateResult.ALREADY_ACTIVE) Step.WORDS else Step.INVITE
        return result
    }

    /** The user leaves the words screen; the backup check follows (§5.6). */
    fun onWordsShown() {
        check(wordsAllowed()) { "MC-U13: the words never show before a lock exists (step $step)" }
        check(step == Step.WORDS) { "onWordsShown only from WORDS, was $step" }
        step = Step.BACKUP
    }

    /** The backup check passed (four positions, or the offered full check). */
    fun onBackupVerified() {
        check(step == Step.BACKUP) { "onBackupVerified only from BACKUP, was $step" }
        step = Step.NOTIFICATIONS
    }

    fun onNotificationsAnswered() {
        check(step == Step.NOTIFICATIONS) { "onNotificationsAnswered only from NOTIFICATIONS, was $step" }
        step = Step.DISCLOSURES
    }

    /** The three mandatory cards were read; onboarding is complete (§6.2 step 11). */
    fun onDisclosuresRead() {
        check(step == Step.DISCLOSURES) { "onDisclosuresRead only from DISCLOSURES, was $step" }
        step = Step.DONE
    }

    /** The restore journey (§5.7) reuses the model after its words validate. */
    suspend fun onRestoreConfirmed(words: List<String>): RestoreResult {
        check(step == Step.WELCOME) { "onRestoreConfirmed only from WELCOME, was $step" }
        return identity.restore(words)
    }

    suspend fun activationState(): ActivationState = identity.activationState()
}
