package org.ghost.sync.evasion

// A catch whose parameter is on the next line, in the sync engine itself. Expected: line 6.
internal object SplitCatch {
    fun run(block: () -> Unit) {
        try { block() } catch (
            e: Throwable
        ) { }
    }
}
