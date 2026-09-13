package org.ghost.entitlement.port

import org.ghost.identity.DropSeal

/**
 * Drop sealing (Phase 8 design §9.3, §19.12; deviation X15): an invitee seals exactly one blob, its
 * credit or a dummy, to its inviter's drop; an inviter opens the blobs of its invites' drops with the
 * drop key of the invite index, re-derived from the root entropy and never stored (§8.4).
 * Production: `android.IdentitySeal` over [DropSeal] and the identity's root entropy.
 */
interface SealPort {
    fun sealCredit(creditToken: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray): ByteArray

    fun sealDummy(dropKey: ByteArray, dropNamespace: ByteArray): ByteArray

    fun open(inviteIndex: Int, blob: ByteArray, dropNamespace: ByteArray): DropSeal.Opened
}
