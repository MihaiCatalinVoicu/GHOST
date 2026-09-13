package org.ghost.entitlement.android

import org.ghost.entitlement.port.IdentityPort
import org.ghost.entitlement.port.SealPort
import org.ghost.identity.DropSeal
import org.ghost.identity.IdentityManager
import org.ghost.identity.Invite
import org.ghost.identity.InviteKeys

/**
 * [IdentityPort] over [IdentityManager] (design §8.3, §8.4). The root entropy is unwrapped only for
 * the derivation that needs it and zeroized right after.
 */
internal class ManagerIdentity(private val manager: IdentityManager) : IdentityPort {
    override fun hasIdentity(): Boolean = manager.hasIdentity()

    override fun create(invite: Invite?) {
        val activation = invite?.let { IdentityManager.Activation.ViaInvite(it) } ?: IdentityManager.Activation.ResumedInvite
        manager.create(activation).root.zeroize()
    }

    override fun wipe() = manager.wipe()

    override fun inviteKeys(index: Int): InviteKeys {
        val root = manager.unlock()
        try {
            return root.inviteKeys(index)
        } finally {
            root.zeroize()
        }
    }

    override fun toString(): String = "ManagerIdentity"
}

/** [SealPort] over [DropSeal]; drop keys are re-derived from the root entropy per invite index (§8.4). */
internal class IdentitySeal(private val manager: IdentityManager) : SealPort {
    override fun sealCredit(creditToken: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray): ByteArray =
        DropSeal.sealCredit(creditToken, dropKey, dropNamespace)

    override fun sealDummy(dropKey: ByteArray, dropNamespace: ByteArray): ByteArray = DropSeal.sealDummy(dropKey, dropNamespace)

    override fun open(inviteIndex: Int, blob: ByteArray, dropNamespace: ByteArray): DropSeal.Opened {
        val root = manager.unlock()
        try {
            return DropSeal.open(blob, root.inviteDropKeyPair(inviteIndex), dropNamespace)
        } finally {
            root.zeroize()
        }
    }

    override fun toString(): String = "IdentitySeal"
}
