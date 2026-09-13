package org.ghost.sync.ok

// A clean sync source: the only violation of this fixture root is the missing entitlement module.
object Clean {
    fun narrow(block: () -> Unit) {
        try { block() } catch (e: IllegalArgumentException) { }
    }
}
