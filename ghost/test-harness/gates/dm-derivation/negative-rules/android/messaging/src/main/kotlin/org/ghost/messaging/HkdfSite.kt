package org.ghost.messaging

import org.ghost.identity.Hkdf

// Rule 1: a KDF keyed by a card's public key. Expected: line 7.
internal object HkdfSite {
    fun leak(cardPublicKey: ByteArray): ByteArray = Hkdf.derive(ikm = cardPublicKey, salt = null, info = ByteArray(0), length = 32)
}
