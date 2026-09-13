package org.ghost.identity

import java.security.SecureRandom

/**
 * Onboarding and identity lifecycle (spec v2.0 §4.1). The root entropy exists in clear only inside
 * this process while unlocked; at rest it is a Keystore-wrapped envelope in no-backup storage.
 *
 * Activation policy (FR-1.5/FR-1.6): a new identity is created either from a verified invite or
 * under an explicitly configured genesis policy. There is no third path.
 */
class IdentityManager(
    private val wrapper: SecretWrapper,
    private val store: WrappedSecretStore,
    private val random: SecureRandom = SecureRandom(),
) {
    sealed class Activation {
        data class ViaInvite(val invite: Invite) : Activation()
        data class Genesis(val policyAcknowledged: Boolean) : Activation()

        /**
         * The invite path, resumed (Phase 8 design §8.3 step 5): a verified invite's trial and nonce
         * were recorded by an earlier process, which ended before the identity was created. Not a
         * third path: the invite was verified there, and its trial still has to succeed or the
         * identity is wiped.
         */
        data object ResumedInvite : Activation()
    }

    class Created(val root: RootEntropy, val activation: Activation) {
        val mnemonic: List<String> get() = root.toMnemonic()
        val identity: GhostIdentity get() = root.publicIdentity()
    }

    fun hasIdentity(): Boolean = store.read(ENVELOPE_NAME) != null

    /** Creates and persists a fresh identity. Throws if one already exists or the policy is not met. */
    fun create(activation: Activation): Created {
        check(!hasIdentity()) { "an identity already exists on this device" }
        if (activation is Activation.Genesis && !activation.policyAcknowledged) {
            throw IllegalStateException("genesis activation requires an explicitly configured policy")
        }
        val root = RootEntropy.generate(random)
        persist(root)
        return Created(root, activation)
    }

    /** Reinstall + mnemonic restores the same identity (FR-1.4 acceptance, NFR-10). */
    fun restore(mnemonic: List<String>): RootEntropy {
        check(!hasIdentity()) { "an identity already exists on this device" }
        val root = RootEntropy.fromMnemonic(mnemonic)
        persist(root)
        return root
    }

    /** Unwraps the persisted root entropy; requires the Keystore key (and user auth if configured). */
    fun unlock(): RootEntropy {
        val envelope = store.read(ENVELOPE_NAME) ?: throw IllegalStateException("no identity on this device")
        return RootEntropy.fromRaw(wrapper.unwrap(envelope))
    }

    /** Local wipe of the wrapped seed (device revocation flow, ADR-14; best-effort on flash, §8.1). */
    fun wipe() = store.delete(ENVELOPE_NAME)

    /**
     * Backup verification (FR-1.4): picks `count` distinct random positions the UI must ask the user
     * to re-enter before the mnemonic is considered backed up.
     */
    fun backupChallenge(count: Int = 4): List<Int> {
        require(count in 1..Bip39.WORD_COUNT)
        val positions = (0 until Bip39.WORD_COUNT).toMutableList()
        val chosen = ArrayList<Int>(count)
        repeat(count) { chosen += positions.removeAt(random.nextInt(positions.size)) }
        return chosen.sorted()
    }

    fun verifyBackupAnswers(mnemonic: List<String>, positions: List<Int>, answers: List<String>): Boolean {
        if (positions.size != answers.size) return false
        return positions.indices.all { i -> mnemonic[positions[i]] == answers[i].trim().lowercase() }
    }

    private fun persist(root: RootEntropy) {
        val raw = root.rawForWrapping()
        try {
            store.write(ENVELOPE_NAME, wrapper.wrap(raw))
        } finally {
            raw.fill(0)
        }
    }

    companion object {
        const val ENVELOPE_NAME = "root-entropy.v1"
    }
}
