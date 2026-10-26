package org.ghost.network

/**
 * The update decision of the Rust core (Phase 14 design §7.4, §9.2, §9.3): the trust epoch,
 * the bundle acceptance, the offer and the streaming APK check. Byte in, byte out: native
 * results are a one-byte `Code` followed by a fixed-layout big-endian payload decoded strictly
 * here — a wrong length is `malformed_response`. Kotlin never locates or parses ZIP
 * structures: it passes the file's length and last 22 bytes, reads exactly the footer range
 * the native side names, and streams the rest in order (RQ-D12). This file declares the whole
 * `UpdateNative` surface (G-D5, the G-R6 closed-list rule extended); nothing else may.
 */
object UpdateNative {
    /** §9.2's vocabulary, one byte per code; keep in sync with `codec::code_byte`. */
    const val OK = 0
    const val MALFORMED = 1
    const val WRONG_NETWORK = 2
    const val CLOCK_UNTRUSTED = 3
    const val ROOT_CHAIN_BROKEN = 4
    const val ROOT_UNLOGGED = 5
    const val ROOT_MISMATCH = 6
    const val BAD_SIGNATURE = 7
    const val FLOOR_INVALID = 8
    const val LOG_PROOF_INVALID = 9
    const val QUORUM_NOT_MET = 10
    const val NOT_YET_VALID = 11
    const val ROLLBACK = 12
    const val UNCHANGED = 13
    const val CONFLICT = 14
    const val NO_MANIFEST = 15
    const val STALE = 16
    const val SDK_UNSUPPORTED = 17
    const val UNSUPPORTED = 18
    const val UP_TO_DATE = 19
    const val APK_LAYOUT = 20
    const val APK_LENGTH = 21
    const val APK_HASH = 22
    const val APK_CORE = 23
    const val APK_SIGNER = 24
    const val ATTESTATION_QUORUM = 25
    const val OUT_OF_ORDER = 26

    private const val MALFORMED_RESPONSE = "malformed_response"

    /** The embedded root chain document (a GHRC), for the first start and `NO_CHANNEL`. */
    fun embeddedChain(): ByteArray {
        NativeLibrary.ensureLoaded()
        return nativeEmbeddedChain()
    }

    /** §7.4 step 0: the facts of the previous installed version (or empty) + the embedded
     * chain + the installed versionCode -> the facts to persist. */
    fun start(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray {
        NativeLibrary.ensureLoaded()
        val raw = nativeStart(stored, embeddedChain, installed)
        return decodeStoredResult(raw)
    }

    /** §7.4 steps 1–7: `[code][new stored blob]`. */
    fun accept(
        stored: ByteArray,
        bundle: ByteArray,
        dayTrusted: Boolean,
        day: Int,
        nowUnix: Long,
    ): Pair<Int, ByteArray> {
        NativeLibrary.ensureLoaded()
        return decodeStoredResultWithCode(nativeAccept(stored, bundle, dayTrusted, day, nowUnix))
    }

    /** §7.4 step 8: the offer, or its exact code. */
    fun offer(
        stored: ByteArray,
        installed: Int,
        sdk: Int,
        rolloutKey: ByteArray,
        dayTrusted: Boolean,
        day: Int,
    ): Offer {
        NativeLibrary.ensureLoaded()
        val raw = nativeOffer(stored, installed, sdk, rolloutKey, dayTrusted, day)
        val r = Reader(raw)
        val code = r.u8()
        if (code != OK) {
            r.end()
            return Offer.None(code)
        }
        val versionCode = r.u32()
        val nameLen = r.u16()
        val name = r.bytes(nameLen)
        val releaseIndex = r.u8()
        val apkSha256 = r.bytes(32)
        val apkLength = r.u64()
        r.end()
        return Offer.Update(versionCode, name.toString(Charsets.US_ASCII), releaseIndex, apkSha256, apkLength)
    }

    /** Step 9(a): begins a streaming check; returns the handle and the footer range to read. */
    fun apkBegin(
        stored: ByteArray,
        releaseIndex: Int,
        sdk: Int,
        length: Long,
        tail: ByteArray,
    ): Long {
        NativeLibrary.ensureLoaded()
        if (tail.size != 22) throw NetworkException(MALFORMED_RESPONSE)
        return nativeApkBegin(stored, releaseIndex, sdk, length, tail)
    }

    /** Steps 9(b), 9(c): the 24 bytes before cd_offset; the code is 0 or a refusal. */
    fun apkFooter(handle: Long, footer: ByteArray): Int {
        NativeLibrary.ensureLoaded()
        if (footer.size != 24) throw NetworkException(MALFORMED_RESPONSE)
        return decodeCode(nativeApkFooter(handle, footer))
    }

    /** Steps 9(d), 9(e): body bytes in order; the code is 0 or a refusal. */
    fun apkUpdate(handle: Long, offset: Long, chunk: ByteArray): Int {
        NativeLibrary.ensureLoaded()
        return decodeCode(nativeApkUpdate(handle, offset, chunk))
    }

    /** Step 10: finishes the check and closes the handle; the code is 0 or a refusal. */
    fun apkFinish(handle: Long): Int {
        NativeLibrary.ensureLoaded()
        return decodeCode(nativeApkFinish(handle))
    }

    /** Idempotent; unknown ids are ignored. */
    fun apkAbort(handle: Long) {
        NativeLibrary.ensureLoaded()
        nativeApkAbort(handle)
    }

    /** §7.8: builds the run's mirror set (two canonical onions + the offered APK's hash and
     * length) from the stored state, the embedded chain, the day and the run's 32-byte draw.
     * `offerSha256`/`offerLength` are ignored when `hasOffer` is false. */
    fun mirrorSet(
        stored: ByteArray,
        embeddedChain: ByteArray,
        noChannel: Boolean,
        dayTrusted: Boolean,
        day: Int,
        draw: ByteArray,
        hasOffer: Boolean,
        offerSha256: ByteArray,
        offerLength: Long,
    ): Long {
        NativeLibrary.ensureLoaded()
        if (draw.size != 32 || (hasOffer && offerSha256.size != 32)) {
            throw NetworkException(MALFORMED_RESPONSE)
        }
        return nativeMirrorSet(
            stored, embeddedChain, noChannel, dayTrusted, day, draw, hasOffer, offerSha256, offerLength,
        )
    }

    /** Closes a mirror set. Idempotent. */
    fun mirrorSetClose(handle: Long) {
        NativeLibrary.ensureLoaded()
        nativeMirrorSetClose(handle)
    }

    /** D19's bootstrap: the committed, gate-checked relay directory compiled into the native
     *  library. Each entry: the 56-char host label (no `.onion`), the port, the 16-byte operator
     *  id. */
    fun bootstrapRelays(): List<NativeRelay> {
        NativeLibrary.ensureLoaded()
        return decodeRelays(nativeBootstrapRelays())
    }

    /** §7.8: the relay list of a verified GHRM (the manifest relays carry no port; the native
     *  side answers the canonical 443). */
    fun manifestRelays(manifest: ByteArray): List<NativeRelay> {
        NativeLibrary.ensureLoaded()
        return decodeRelays(nativeManifestRelays(manifest))
    }

    /** One relay directory entry, both relay-list entry points' shape. */
    class NativeRelay(val host: String, val port: Int, val operatorId: ByteArray) {
        init {
            if (operatorId.size != 16) throw NetworkException(MALFORMED_RESPONSE)
        }
    }

    private fun decodeRelays(raw: ByteArray): List<NativeRelay> {
        val r = Reader(raw)
        if (r.u8() != OK) throw NetworkException(MALFORMED_RESPONSE)
        val n = r.u16()
        val out = ArrayList<NativeRelay>(n)
        repeat(n) {
            val len = r.u8()
            if (len != 56) throw NetworkException(MALFORMED_RESPONSE)
            val host = r.bytes(len).toString(Charsets.US_ASCII)
            val port = r.u16()
            if (port == 0) throw NetworkException(MALFORMED_RESPONSE)
            out.add(NativeRelay(host, port, r.bytes(16)))
        }
        r.end()
        return out
    }

    private fun decodeCode(raw: ByteArray): Int {
        val r = Reader(raw)
        val code = r.u8()
        r.end()
        return code
    }    private fun decodeStoredResult(raw: ByteArray): ByteArray = decodeStoredResultWithCode(raw).second

    private fun decodeStoredResultWithCode(raw: ByteArray): Pair<Int, ByteArray> {
        val r = Reader(raw)
        val code = r.u8()
        val rest = r.rest()
        return code to rest
    }

    sealed interface Offer {
        val code: Int

        data class Update(
            val versionCode: Int,
            val versionName: String,
            val releaseIndex: Int,
            val apkSha256: ByteArray,
            val apkLength: Long,
        ) : Offer {
            override val code: Int get() = OK
        }

        data class None(override val code: Int) : Offer
    }

    /** A strict big-endian reader: any overrun or trailing byte is `malformed_response`. */
    private class Reader(private val raw: ByteArray) {
        private var pos = 0

        fun u8(): Int {
            if (pos + 1 > raw.size) throw NetworkException(MALFORMED_RESPONSE)
            return raw[pos++].toInt() and 0xff
        }

        fun u16(): Int {
            if (pos + 2 > raw.size) throw NetworkException(MALFORMED_RESPONSE)
            return (u8() shl 8) or u8()
        }

        fun u32(): Int {
            if (pos + 4 > raw.size) throw NetworkException(MALFORMED_RESPONSE)
            return (u16() shl 16) or u16()
        }

        fun u64(): Long {
            if (pos + 8 > raw.size) throw NetworkException(MALFORMED_RESPONSE)
            return (u32().toLong() shl 32) or u32().toLong()
        }

        fun bytes(n: Int): ByteArray {
            if (n < 0 || pos + n > raw.size) throw NetworkException(MALFORMED_RESPONSE)
            val out = raw.copyOfRange(pos, pos + n)
            pos += n
            return out
        }

        fun rest(): ByteArray = bytes(raw.size - pos)

        fun end() {
            if (pos != raw.size) throw NetworkException(MALFORMED_RESPONSE)
        }
    }

    @JvmStatic private external fun nativeEmbeddedChain(): ByteArray
    @JvmStatic private external fun nativeStart(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray
    @JvmStatic private external fun nativeAccept(
        stored: ByteArray,
        bundle: ByteArray,
        dayTrusted: Boolean,
        day: Int,
        nowUnix: Long,
    ): ByteArray
    @JvmStatic private external fun nativeOffer(
        stored: ByteArray,
        installed: Int,
        sdk: Int,
        rolloutKey: ByteArray,
        dayTrusted: Boolean,
        day: Int,
    ): ByteArray
    @JvmStatic private external fun nativeApkBegin(
        stored: ByteArray,
        releaseIndex: Int,
        sdk: Int,
        length: Long,
        tail: ByteArray,
    ): Long
    @JvmStatic private external fun nativeApkFooter(handle: Long, footer: ByteArray): ByteArray
    @JvmStatic private external fun nativeApkUpdate(handle: Long, offset: Long, chunk: ByteArray): ByteArray
    @JvmStatic private external fun nativeApkFinish(handle: Long): ByteArray
    @JvmStatic private external fun nativeApkAbort(handle: Long)
    @JvmStatic private external fun nativeMirrorSet(
        stored: ByteArray,
        embeddedChain: ByteArray,
        noChannel: Boolean,
        dayTrusted: Boolean,
        day: Int,
        draw: ByteArray,
        hasOffer: Boolean,
        offerSha256: ByteArray,
        offerLength: Long,
    ): Long
    @JvmStatic private external fun nativeMirrorSetClose(handle: Long)
    @JvmStatic private external fun nativeBootstrapRelays(): ByteArray
    @JvmStatic private external fun nativeManifestRelays(manifest: ByteArray): ByteArray
}
