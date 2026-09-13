package org.ghost.network

/**
 * Loads `libghost_client_net.so` once per process, on first use rather than at class load, so
 * pure-JVM code paths (decoders, argument checks) stay testable without it. A missing or
 * unloadable library surfaces as category `native_missing`, not as an Error.
 */
internal object NativeLibrary {
    private val loaded: Unit by lazy {
        try {
            System.loadLibrary("ghost_client_net")
        } catch (e: UnsatisfiedLinkError) {
            throw NetworkException("native_missing")
        }
    }

    fun ensureLoaded() = loaded
}
