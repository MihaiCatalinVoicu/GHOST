package org.ghost.messaging

import org.ghost.identity.DerivationLabels

// Rule 2: a seed label used outside deriveBranch. Expected: line 7.
internal object LabelOutsideBranch {
    val label = DerivationLabels.IDENTITY
}
