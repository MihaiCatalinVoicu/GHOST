package org.ghost.crypto.bridge

/** Fixture: the equivalence-test entry point declared where the release build compiles it. */
object DmNative {
    @JvmStatic
    @JvmName("equivalence")
    internal external fun equivalence(kind: Int, input: ByteArray): ByteArray?
}
