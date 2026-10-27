package org.ghost.network

/**
 * §11.3's mutant selector (Phase 14 design §11.3; slice S6c), the test-source twin of the
 * host library's test-only JNI entry `UpdateMutants.select` (G-D5: the symbol exists only in
 * libraries built with `test-mutants`, which only `ghost-dm-host` enables). A JVM world
 * selects its mutant once, before its first native call, and resets to 0 (the shipped
 * behaviour at every site) when it closes. Loading piggybacks on any [UpdateNative] call —
 * the bridge's own [NativeLibrary] discipline, without reaching its internal object.
 */
object UpdateMutants {
    init {
        UpdateNative.apkChunkStep()
    }

    /** Selects the active mutant (0 = the shipped behaviour at every mutation site). */
    @JvmStatic
    external fun select(id: Int)
}
