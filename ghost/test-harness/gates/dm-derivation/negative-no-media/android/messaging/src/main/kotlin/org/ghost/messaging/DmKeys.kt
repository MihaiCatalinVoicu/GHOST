package org.ghost.messaging

import org.ghost.identity.DerivationLabels
import org.ghost.identity.RootEntropy

// A seed branch whose one DerivationLabels argument sits on its own line.
internal object DmKeys {
    fun branch(root: RootEntropy): ByteArray = root.deriveBranch(
        DerivationLabels.MESSAGING
    )
}
