package org.ghost.messaging

// Rule 2: a second deriveBranch, over raw bytes. Expected: line 4.
internal fun ByteArray.deriveBranch(label: String): ByteArray = this + label.toByteArray()
