package org.ghost.ui.feature.dm

import org.ghost.ui.gateway.DmGateway
import org.ghost.ui.gateway.UserAction

/**
 * Phase 13 design §4.7 (D34), §6.3's provenance step: after scanning a contact card, the user
 * answers ONE question — "Unde ai văzut acest cod?" The answer decides the trust path, and the
 * answer is the user's:
 *
 *  - «Pe telefonul persoanei, în fața mea» → [Provenance.QR_IN_PERSON]: the card is added with
 *    the in-person source, which the engine treats as the verified path (D34 amended the design:
 *    a scan alone never marks a contact verified — the question does).
 *  - «Într-o poză, un mesaj, un apel video sau pe alt ecran» and «Nu știu» (the preselected) →
 *    [Provenance.LINK]: added with the link source and the safety-number prompt follows (F9 §8.4:
 *    the code is compared, never trusted).
 *
 * PM-U30's mutant — every scan recorded as QR_IN_PERSON — is killed by [onScanned]'s explicit
 * parameter: the default is [Answer.DONT_KNOW], never the in-person value.
 */
class ContactAddModel(private val dm: DmGateway) {
    /** The question's answers; [DONT_KNOW] is the preselected one. */
    enum class Answer { IN_FRONT_OF_ME, ELSEWHERE_ON_A_SCREEN, DONT_KNOW }

    /** What the answer recorded. */
    enum class Provenance { QR_IN_PERSON, LINK }

    /** Needs the safety-number comparison before the contact can be VERIFIED. */
    var needsSafetyNumberPrompt: Boolean = false
        private set

    /**
     * The scan's confirmation: the card text and the user's answer. The in-person answer is the
     * ONLY path to [Provenance.QR_IN_PERSON]; everything else is a link, and a link asks for the
     * safety number.
     */
    @UserAction
    suspend fun onScanned(cardText: String, answer: Answer = Answer.DONT_KNOW): Provenance {
        val provenance = when (answer) {
            Answer.IN_FRONT_OF_ME -> Provenance.QR_IN_PERSON
            Answer.ELSEWHERE_ON_A_SCREEN, Answer.DONT_KNOW -> Provenance.LINK
        }
        needsSafetyNumberPrompt = provenance == Provenance.LINK
        dm.addContact(
            cardText = cardText,
            source = provenance.name,
            name = null,
        )
        return provenance
    }
}
