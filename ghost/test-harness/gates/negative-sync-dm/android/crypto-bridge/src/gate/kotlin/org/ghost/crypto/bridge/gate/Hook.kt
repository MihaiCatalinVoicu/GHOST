package org.ghost.crypto.bridge.gate

// Negative fixture: the gate build type is a production source set too. One violation (line 8).
internal object Hook {
    fun fire(body: () -> Unit) {
        try {
            body()
        } catch (t: Throwable) {
            Unit
        }
    }
}
