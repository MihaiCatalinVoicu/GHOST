package org.ghost.messaging

import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy

// Rule 1: a seed built from bytes the module chose. Expected: line 8.
internal object RootFromRaw {
    fun leak(publicKey: ByteArray) = RootEntropy.fromRaw(publicKey).deriveBranch(DerivationLabels.MESSAGING)
}
