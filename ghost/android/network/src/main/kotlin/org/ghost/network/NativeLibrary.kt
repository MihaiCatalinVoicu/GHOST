package org.ghost.network

/**
 * Loads the native network core once per process, on first use rather than at class load, so
 * pure-JVM code paths (decoders, argument checks, [PtInstaller]'s mocked-asset tests) stay
 * testable without it. A missing or unloadable library surfaces as category `native_missing`,
 * not as an Error.
 *
 * On a device the library is `libghost_client_net.so` from the APK's jniLibs. JVM tests load the
 * host build of the same crate through `-Dghost.net.native=<path to ghost_client_net.{dll,so}>`
 * (the same host-library discipline as crypto-bridge's `-Dghost.dm.native`; Phase 12 slice S2):
 * the JVM suites then call exactly the shipped validator, not a stand-in.
 */
internal object NativeLibrary {
    private val loaded: Unit by lazy {
        val host = System.getProperty("ghost.net.native")
        try {
            if (host.isNullOrEmpty()) {
                System.loadLibrary("ghost_client_net")
            } else {
                System.load(host)
            }
        } catch (e: UnsatisfiedLinkError) {
            throw NetworkException("native_missing")
        }
    }

    fun ensureLoaded() = loaded
}
