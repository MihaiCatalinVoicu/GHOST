package org.ghost.app.ui

import java.security.SecureRandom
import kotlinx.coroutines.withContext
import org.ghost.entitlement.api.Entitlement
import org.ghost.identity.Bip39
import org.ghost.identity.IdentityManager
import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.IdentityGateway
import org.ghost.ui.gateway.InvitePreview
import org.ghost.ui.gateway.RestoreResult

/**
 * Phase 13 design §3.2, §3.6: the production [IdentityGateway] — onboarding's identity half.
 * Everything runs on `ghost-ui-io` (CS-U6); the adapter composes [IdentityManager], the
 * [Entitlement] facade and the app's database-key creator, and never caches the facade instances
 * across a database reopen (they arrive through [entitlement], [identity] and [createKey] each
 * call).
 *
 * The word list is read from :identity (CR-15: :ui holds no copy); the mnemonic renders as
 * indices and the backup check runs over indices (§3.3, F-U4).
 */
class IdentityGatewayAdapter(
    private val identity: () -> IdentityManager,
    private val entitlement: () -> Entitlement?,
    private val createKey: () -> ByteArray,
    private val genesisPolicyOn: Boolean,
    private val nowUnixSeconds: () -> Long,
    private val random: SecureRandom,
) : IdentityGateway {

    override suspend fun createDatabaseKey(): Unit = onIo {
        createKey().fill(0)
    }

    override suspend fun inspectInvite(text: String): InvitePreview = onIo {
        val e = entitlement() ?: return@onIo InvitePreview(version = 0, expiryDay = null, refusedReason = "unavailable")
        val p = e.inspectInvite(text, nowUnixSeconds())
        InvitePreview(version = p.version, expiryDay = p.expiryDay?.toInt(), refusedReason = p.refusedReason)
    }

    override suspend fun activationState(): ActivationState = onIo {
        when (entitlement()?.activationState()) {
            org.ghost.entitlement.api.ActivationState.ACTIVE -> ActivationState.ACTIVE
            else -> ActivationState.NONE
        }
    }

    override suspend fun activateInvite(text: String): ActivateResult = onIo {
        val e = entitlement() ?: return@onIo ActivateResult.UNAVAILABLE
        when (e.activate(text)) {
            org.ghost.entitlement.api.ActivationResult.PENDING -> ActivateResult.ACTIVATED
            org.ghost.entitlement.api.ActivationResult.ALREADY_ACTIVE -> ActivateResult.ALREADY_ACTIVE
            org.ghost.entitlement.api.ActivationResult.UNAVAILABLE -> ActivateResult.UNAVAILABLE
            else -> ActivateResult.REFUSED
        }
    }

    override suspend fun activateGenesis(acknowledged: Boolean): ActivateResult = onIo {
        // Q21: genesis onboarding exists only in builds whose policy enables it (stagenet, the
        // owner's bootstrap build) — never in distributed mainnet builds.
        if (!genesisPolicyOn) return@onIo ActivateResult.REFUSED
        identity().create(IdentityManager.Activation.Genesis(acknowledged))
        ActivateResult.ACTIVATED
    }

    override suspend fun restore(words: List<String>): RestoreResult = onIo {
        val e = entitlement() ?: return@onIo RestoreResult.UNAVAILABLE
        when (e.restore(words)) {
            org.ghost.entitlement.api.RestoreResult.RESTORED -> RestoreResult.RESTORED
            org.ghost.entitlement.api.RestoreResult.ALREADY_ACTIVE -> RestoreResult.ALREADY_ACTIVE
            org.ghost.entitlement.api.RestoreResult.REFUSED_MNEMONIC -> RestoreResult.REFUSED_MNEMONIC
            org.ghost.entitlement.api.RestoreResult.UNAVAILABLE -> RestoreResult.UNAVAILABLE
        }
    }

    override suspend fun mnemonicIndices(): IntArray = onIo {
        identity().unlock().toMnemonicIndices()
    }

    override suspend fun wordList(): List<String> = onIo {
        Bip39.wordlist
    }

    override suspend fun backupChallenge(count: Int, carried: List<Int>): List<Int> = onIo {
        identity().backupChallenge(count, carried)
    }

    override suspend fun verifyBackup(
        indices: IntArray,
        positions: List<Int>,
        answers: List<String>,
    ): Boolean = onIo {
        val words = Bip39.wordlist
        if (positions.size != answers.size) return@onIo false
        positions.indices.all { i ->
            words[indices[positions[i]]] == answers[i].trim().lowercase()
        }
    }

    override suspend fun newPassphraseIndices(count: Int): IntArray = onIo {
        IntArray(count) { random.nextInt(2048) }
    }

    private suspend fun <T> onIo(block: () -> T): T = withContext(GhostUiIo.dispatcher) {
        GhostUiIo.assertThread()
        block()
    }
}
