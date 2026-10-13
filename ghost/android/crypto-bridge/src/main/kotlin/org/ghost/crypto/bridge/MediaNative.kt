package org.ghost.crypto.bridge

/**
 * The closed JNI surface of the media cryptography (Phase 11 design `docs/design/faza11-media.md`
 * §13.2, gate G-M5; slice S2). **This is the only class in GHOST that declares a media native
 * method**, and no module outside `:crypto-bridge` references a type of it: everything goes
 * through the typed facade ([MediaCrypto]).
 *
 * Every function is `static native`, returns **one** byte array `code(1) || TLV fields`, which
 * [MediaResult] decodes, and — except `jpegCanonicalize` and `sniff`, which are stateless like
 * `safetyNumber` — takes the DM context handle `h`: sealers and readers are registry entries
 * inside the DM context, and `ctxClose` zeroises them with it (§13.2). No function performs I/O,
 * reads a clock, logs, or throws; a Rust panic is caught on the native side and comes back as
 * [MediaCode.INTERNAL], which the facade turns into `IllegalStateException` (rollback, crash,
 * poison guard).
 *
 * **Loading** (§2.7's practice). The media symbols live in the same libraries as the DM surface —
 * `libghost_client_net.so` on a device, the `ghost-dm-host` build in JVM tests — so this object
 * loads exactly what `DmNative` loads, from the same `-Dghost.dm.native` property, and a missing
 * library is [MediaCode.CRYPTO_UNAVAILABLE] here too, never a crash loop.
 *
 * **Visibility.** Every declaration is `internal` with an explicit `@JvmName`, like `DmNative`:
 * a module that depends on `:crypto-bridge` reaches the media cryptography through [MediaCrypto]
 * or not at all, and Kotlin's mangling of internal members' JVM names is pinned by the
 * annotation, which G-M5 checks both halves of.
 *
 * **Recorded deviation (slice S2, §22.3).** §13.2's table has M2 and M6 cross direct
 * `ByteBuffer`s; this tree ships `#![forbid(unsafe_code)]` in every client crate and JNI's
 * `GetDirectBufferAddress` cannot be read without an `unsafe` seam, so the two functions cross
 * byte arrays for now — safe, correct, one copy where the design wanted zero-copy. The
 * direct-buffer form is a pending owner decision.
 */
object MediaNative {

    @Volatile
    private var loadFailure: Throwable? = null

    private val loaded: Boolean by lazy {
        try {
            val hostPath = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
            if (hostPath.isNullOrEmpty()) {
                System.loadLibrary(DmNative.ANDROID_LIBRARY)
            } else {
                System.load(hostPath)
            }
            true
        } catch (e: UnsatisfiedLinkError) {
            loadFailure = e
            false
        } catch (e: SecurityException) {
            loadFailure = e
            false
        }
    }

    /**
     * Whether the native library is available. The facade maps `false` to
     * [MediaCode.CRYPTO_UNAVAILABLE] instead of letting an `UnsatisfiedLinkError` escape.
     */
    fun isAvailable(): Boolean = loaded

    /** Why the library did not load, for a diagnostic the caller may show; never logged here. */
    fun loadFailure(): Throwable? = loadFailure

    // §13.2 M1.
    @JvmStatic
    @JvmName("sealBegin")
    internal external fun sealBegin(
        handle: Long,
        destId: ByteArray,
        kind: Int,
        viewOnce: Int,
        maxClass: Int,
    ): ByteArray?

    // §13.2 M2.
    @JvmStatic
    @JvmName("sealAppend")
    internal external fun sealAppend(
        handle: Long,
        sealerId: Long,
        plaintext: ByteArray,
    ): ByteArray?

    // §13.2 M3.
    @JvmStatic
    @JvmName("sealFinish")
    internal external fun sealFinish(
        handle: Long,
        sealerId: Long,
        preview: ByteArray,
    ): ByteArray?

    // §13.2 M4.
    @JvmStatic
    @JvmName("sealAbort")
    internal external fun sealAbort(handle: Long, sealerId: Long): ByteArray?

    // §13.2 M5.
    @JvmStatic
    @JvmName("readerOpen")
    internal external fun readerOpen(
        handle: Long,
        keyEnv: ByteArray,
        role: Int,
        destId: ByteArray,
        objectId: ByteArray,
        manifestHash: ByteArray,
        manifestBlob: ByteArray,
        kind: Int,
        viewOnce: Int,
        classCode: Int,
        readable: Int,
    ): ByteArray?

    // §13.2 M6.
    @JvmStatic
    @JvmName("readerChunk")
    internal external fun readerChunk(
        handle: Long,
        readerId: Long,
        index: Int,
        fragments: ByteArray,
        mode: Int,
    ): ByteArray?

    // §13.2 M7.
    @JvmStatic
    @JvmName("readerValidateFinish")
    internal external fun readerValidateFinish(handle: Long, readerId: Long): ByteArray?

    // §13.2 M8.
    @JvmStatic
    @JvmName("readerClose")
    internal external fun readerClose(handle: Long, readerId: Long): ByteArray?

    // §13.2 M9. Stateless: no handle.
    @JvmStatic
    @JvmName("jpegCanonicalize")
    internal external fun jpegCanonicalize(bytes: ByteArray): ByteArray?

    // §13.2 M10. Stateless: no handle.
    @JvmStatic
    @JvmName("sniff")
    internal external fun sniff(first64: ByteArray): ByteArray?

    // --------------------------------------------------------------------------------------------
    // The two host-only test entries of §13.2 (§15.6's model-relay re-derivation; G-M5). The
    // design names them members of this class, and the JNI symbol pins the declaring class, so —
    // unlike DmEquivalence's test entries, whose symbol carries a test-only class name — these
    // two declarations have no test-source-set home: only this file can carry them. They are
    // exported by `ghost-dm-host` alone (the `test-vectors` feature): a shipped library carries
    // no such symbol, so on a device both are inert — nothing production may call them, and a
    // caller that did would get `UnsatisfiedLinkError`, not a key. Production code never sees a
    // chosen key (§15.1); the JVM tests of slice S2 are their only callers.

    // §13.2 host-only: `testSealBeginWithKey` (§15.6).
    @JvmStatic
    @JvmName("testSealBeginWithKey")
    internal external fun testSealBeginWithKey(
        handle: Long,
        fileKey: ByteArray,
        objectId: ByteArray,
        kind: Int,
        viewOnce: Int,
        maxClass: Int,
    ): ByteArray?

    // §13.2 host-only: `testVectors` (§15.6).
    @JvmStatic
    @JvmName("testVectors")
    internal external fun testVectors(handle: Long, request: ByteArray): ByteArray?
}
