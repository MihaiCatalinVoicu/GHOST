package org.ghost.update

import org.ghost.network.UpdateNative

/**
 * The seam the [UpdateEngine] speaks through (Phase 14 design §9.3): the production delegate is
 * the closed `UpdateNative`/`TorMirrorTransport` surface; tests substitute a fake and drive the
 * engine's orchestration without a native library.
 */
interface UpdateNativeBridge {
    fun embeddedChain(): ByteArray

    /** §7.4 step 0: `[code][stored blob]`. */
    fun start(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray

    /** Steps 1–7: the code and the new stored blob. */
    fun accept(stored: ByteArray, bundle: ByteArray, dayTrusted: Boolean, day: Int, nowUnix: Long): Pair<Int, ByteArray>

    /** Step 8. */
    fun offer(stored: ByteArray, installed: Int, sdk: Int, rolloutKey: ByteArray, dayTrusted: Boolean, day: Int): UpdateNative.Offer

    /** §7.8's run draw. */
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
    ): Long

    fun mirrorSetClose(handle: Long)

    /** Steps 9–10, streaming. */
    fun apkBegin(stored: ByteArray, releaseIndex: Int, sdk: Int, length: Long, tail: ByteArray): Long
    fun apkFooter(handle: Long, footer: ByteArray): Int
    fun apkUpdate(handle: Long, offset: Long, chunk: ByteArray): Int
    fun apkFinish(handle: Long): Int
    fun apkAbort(handle: Long)

    /** D19's bootstrap relay list (compiled into the native library). */
    fun bootstrapRelays(): List<UpdateNative.NativeRelay>

    /** §7.8: the relay list of a verified manifest document. */
    fun manifestRelays(manifest: ByteArray): List<UpdateNative.NativeRelay>
}

/** The production bridge: one line per call, nothing else (the surface stays closed). */
object RealUpdateNativeBridge : UpdateNativeBridge {
    override fun embeddedChain(): ByteArray = UpdateNative.embeddedChain()

    override fun start(stored: ByteArray, embeddedChain: ByteArray, installed: Int): ByteArray =
        UpdateNative.start(stored, embeddedChain, installed)

    override fun accept(stored: ByteArray, bundle: ByteArray, dayTrusted: Boolean, day: Int, nowUnix: Long): Pair<Int, ByteArray> =
        UpdateNative.accept(stored, bundle, dayTrusted, day, nowUnix)

    override fun offer(stored: ByteArray, installed: Int, sdk: Int, rolloutKey: ByteArray, dayTrusted: Boolean, day: Int): UpdateNative.Offer =
        UpdateNative.offer(stored, installed, sdk, rolloutKey, dayTrusted, day)

    override fun mirrorSet(
        stored: ByteArray,
        embeddedChain: ByteArray,
        noChannel: Boolean,
        dayTrusted: Boolean,
        day: Int,
        draw: ByteArray,
        hasOffer: Boolean,
        offerSha256: ByteArray,
        offerLength: Long,
    ): Long = UpdateNative.mirrorSet(stored, embeddedChain, noChannel, dayTrusted, day, draw, hasOffer, offerSha256, offerLength)

    override fun mirrorSetClose(handle: Long) = UpdateNative.mirrorSetClose(handle)

    override fun apkBegin(stored: ByteArray, releaseIndex: Int, sdk: Int, length: Long, tail: ByteArray): Long =
        UpdateNative.apkBegin(stored, releaseIndex, sdk, length, tail)

    override fun apkFooter(handle: Long, footer: ByteArray): Int = UpdateNative.apkFooter(handle, footer)
    override fun apkUpdate(handle: Long, offset: Long, chunk: ByteArray): Int = UpdateNative.apkUpdate(handle, offset, chunk)
    override fun apkFinish(handle: Long): Int = UpdateNative.apkFinish(handle)
    override fun apkAbort(handle: Long) = UpdateNative.apkAbort(handle)

    /** D19/§7.8: the native relay lists (bootstrap and per-manifest). */
    override fun bootstrapRelays(): List<UpdateNative.NativeRelay> = UpdateNative.bootstrapRelays()
    override fun manifestRelays(manifest: ByteArray): List<UpdateNative.NativeRelay> = UpdateNative.manifestRelays(manifest)
}
