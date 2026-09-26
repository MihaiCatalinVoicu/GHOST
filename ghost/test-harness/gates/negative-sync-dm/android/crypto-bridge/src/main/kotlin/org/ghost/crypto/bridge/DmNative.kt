package org.ghost.crypto.bridge

// Negative fixture: the allowlist permits one UnsatisfiedLinkError catch in this file and it holds
// two, so both are reported (lines 7 and 13).
internal object DmNative {
    fun load(): Boolean = try { System.loadLibrary("ghost_client_net"); true }
    catch (e: UnsatisfiedLinkError) {
        false
    }

    fun again(): Boolean = try {
        System.loadLibrary("ghost_client_net"); true
    } catch (e: UnsatisfiedLinkError) {
        false
    }
}
