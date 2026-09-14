package org.ghost.entitlement.port

import org.ghost.identity.Invite
import org.ghost.identity.InviteKeys

/**
 * The identity lifecycle as the activation sequence and the restore need it (Phase 8 design §8.3,
 * §8.4) and the per-invite keys an inviter needs (§8.4, §8.5). Production: `android.ManagerIdentity`
 * over `IdentityManager`.
 */
interface IdentityPort {
    fun hasIdentity(): Boolean

    /** Restores and stores the identity of a 24-word backup (FR-1.4); the words are not kept. */
    fun restore(mnemonic: List<String>)

    /**
     * Creates the identity of an invite activation (§8.3 step 3): [invite] is the verified invite, or
     * null when a pending trial is resumed in a later process (its invite was verified and its nonce
     * recorded before that process ended, step 5).
     */
    fun create(invite: Invite?)

    /** No identity survives a failed trial ("revoked invite fails closed", §8.3). */
    fun wipe()

    /** The signing key, drop namespace and drop key of invite [index]. */
    fun inviteKeys(index: Int): InviteKeys
}
