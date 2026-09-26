package org.ghost.messaging

import org.ghost.identity.RootEntropy

// Rule 2: a seed branch under a label the module chose. Expected: line 7.
internal object BranchFromString {
    fun leak(root: RootEntropy, label: String) = root.deriveBranch(label)
}
