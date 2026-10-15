package org.ghost.media.sandbox

import android.app.Service
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorSpace
import android.graphics.ImageDecoder
import android.os.Binder
import android.os.Build
import android.os.Parcel
import android.os.Process
import android.os.SharedMemory
import org.ghost.media.send.MediaGeometry
import org.ghost.media.send.MediaSendLimits
import java.io.ByteArrayOutputStream

/**
 * The isolated decoding service of Phase 11 design §9.2 (ADR-46; T46): `android:isolatedProcess`,
 * `android:process=":mdec"`, not exported, no intent filter. One **fresh process instance per
 * request** (the main process binds with a random instance name and unbinds after the reply, so an
 * exploit delivered by one image sees only its own request's bytes); the service uses **only**
 * platform decoder APIs — `GhostApp.onCreate`'s early return on `Process.isIsolated()` (§9.2,
 * V-M19) keeps every GHOST object out of this process, and nothing here opens a file, a socket or
 * a GHOST class beyond [MediaGeometry] (pure).
 *
 * The protocol (§9.2): exactly two operations, inputs and outputs in `SharedMemory` regions the
 * main process creates, maps read-only for the input; the parcels carry only `SharedMemory`
 * handles and ints; a malformed reply is a typed failure the main process refuses to parse
 * further. Every region is zeroed before it is unmapped and closed, on both sides.
 *
 *  - `STRIP_IMAGE` (§8.2): decode with `ImageDecoder` (software allocator; the header listener
 *    refuses over 100 MP and sets the D29 target size), EXIF orientation applied by the decoder
 *    (V-M4), sRGB, gain map dropped (API 34+), alpha composited on white, baseline JPEG at
 *    q = 85 … 60, then the long-edge ladder down (2 048 → 1 024 → 512), until ≤ `IMAGE_MAX_CONTENT`.
 *  - `DECODE_IMAGE`: decode to ARGB_8888 pixels within the caller's bounds (the recipient-side
 *    preview path, §7.4).
 */
class MediaDecodeService : Service() {

    override fun onBind(intent: Intent?): Binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            val r = reply ?: return false
            when (code) {
                MediaSandbox.OP_STRIP -> {
                    r.writeNoException()
                    val input = SharedMemory.CREATOR.createFromParcel(data)
                    val inputLen = data.readInt()
                    val output = SharedMemory.CREATOR.createFromParcel(data)
                    val preview = data.readInt() == 1
                    val maxBytes = data.readInt()
                    val start = r.dataPosition()
                    try {
                        strip(input, inputLen, output, preview, maxBytes, r)
                    } catch (e: RuntimeException) {
                        // A decoder failure is a typed answer, never a Binder exception (§9.2);
                        // an Error (an OOM, a hard crash) propagates and kills the instance,
                        // which is the DeadObjectException path the client already handles.
                        r.setDataPosition(start)
                        r.writeInt(1)
                        r.writeInt(MediaSandbox.ERR_DECODE)
                    }
                }
                MediaSandbox.OP_DECODE -> {
                    r.writeNoException()
                    val input = SharedMemory.CREATOR.createFromParcel(data)
                    val inputLen = data.readInt()
                    val output = SharedMemory.CREATOR.createFromParcel(data)
                    val maxW = data.readInt()
                    val maxH = data.readInt()
                    val start = r.dataPosition()
                    try {
                        decode(input, inputLen, output, maxW, maxH, r)
                    } catch (e: RuntimeException) {
                        // See the STRIP arm: a decoder failure is a typed answer; an Error kills
                        // the instance, which is the DeadObjectException path (§9.2).
                        r.setDataPosition(start)
                        r.writeInt(1)
                        r.writeInt(MediaSandbox.ERR_DECODE)
                    }
                }
                else -> return super.onTransact(code, data, reply, flags)
            }
            return true
        }
    }

    /** `STRIP_IMAGE` of §8.2: the source's pixels re-encoded as a canonical-geometry JPEG. */
    private fun strip(
        input: SharedMemory,
        inputLen: Int,
        output: SharedMemory,
        preview: Boolean,
        maxBytes: Int,
        reply: Parcel,
    ) {
        val inBuf = input.mapReadOnly()
        try {
            inBuf.limit(inputLen)
            // The D29 target comes from the source's own header size — the main process never
            // parses image headers, and the one pinned implementation is MediaGeometry (S1's
            // ladder, replayed against media_object.txt by MediaGeometryTest).
            var decoded = ImageDecoder.decodeBitmap(ImageDecoder.createSource(inBuf)) { decoder, info, _ ->
                val w = info.size.width
                val h = info.size.height
                require(w.toLong() * h <= MediaSendLimits.IMAGE_SOURCE_MAX_MEGAPIXELS) { "over 100 MP" }
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                // Mutable: the eraseColor(0) hygiene below, and the gain-map/alpha handling.
                decoder.isMutableRequired = true
                val target = if (preview) {
                    MediaGeometry.previewTarget(w, h)
                } else {
                    MediaGeometry.imageTarget(w, h)
                }
                decoder.setTargetSize(target.first, target.second)
                decoder.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB))
            }
            if (Build.VERSION.SDK_INT >= 34) {
                decoded.gainmap = null
            }
            var bmp = decoded
            if (bmp.hasAlpha()) {
                val flat = Bitmap.createBitmap(bmp.width, bmp.height, Bitmap.Config.ARGB_8888)
                val canvas = Canvas(flat)
                canvas.drawColor(Color.WHITE)
                canvas.drawBitmap(bmp, 0f, 0f, null)
                erase(bmp)
                bmp = flat
            }
            var bytes: ByteArray? = null
            var long = maxOf(bmp.width, bmp.height)
            while (bytes == null) {
                for (q in intArrayOf(85, 80, 75, 70, 65, 60)) {
                    val bos = ByteArrayOutputStream()
                    bmp.compress(Bitmap.CompressFormat.JPEG, q, bos)
                    if (bos.size() <= maxBytes) {
                        bytes = bos.toByteArray()
                        break
                    }
                }
                if (bytes == null) {
                    // The long-edge ladder down (2 048 -> 1 024 -> 512), the geometry stays
                    // canonical (the one pinned implementation is MediaGeometry); a source that
                    // does not fit at 512 refuses.
                    require(long > 512) { "does not fit at 512 px" }
                    long /= 2
                    val next = MediaGeometry.targetAt(bmp.width, bmp.height, long)
                    val smaller = Bitmap.createScaledBitmap(bmp, next.first, next.second, true)
                    erase(bmp)
                    bmp = smaller
                }
            }
            val outBuf = output.mapReadWrite()
            try {
                require(bytes.size <= outBuf.capacity()) { "output region too small" }
                outBuf.put(bytes)
            } finally {
                SharedMemory.unmap(outBuf)
            }
            reply.writeInt(0)
            reply.writeInt(bytes.size)
            reply.writeInt(bmp.width)
            reply.writeInt(bmp.height)
            erase(bmp)
        } finally {
            SharedMemory.unmap(inBuf)
            input.close()
            output.close()
        }
    }

    /** `DECODE_IMAGE`: canonical JPEG → ARGB_8888 pixels within the caller's bounds. */
    private fun decode(
        input: SharedMemory,
        inputLen: Int,
        output: SharedMemory,
        maxW: Int,
        maxH: Int,
        reply: Parcel,
    ) {
        val inBuf = input.mapReadOnly()
        try {
            inBuf.limit(inputLen)
            val bmp = ImageDecoder.decodeBitmap(ImageDecoder.createSource(inBuf)) { decoder, info, _ ->
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                decoder.isMutableRequired = true
                val w = info.size.width
                val h = info.size.height
                if (w > maxW || h > maxH) {
                    val s = minOf(maxW.toDouble() / w, maxH.toDouble() / h)
                    decoder.setTargetSize(
                        maxOf(1, (w * s).toInt()),
                        maxOf(1, (h * s).toInt()),
                    )
                }
                decoder.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB))
            }
            val need = bmp.width * bmp.height * 4
            val outBuf = output.mapReadWrite()
            try {
                require(need <= outBuf.capacity()) { "output region too small" }
                bmp.copyPixelsToBuffer(outBuf)
            } finally {
                SharedMemory.unmap(outBuf)
            }
            reply.writeInt(0)
            reply.writeInt(bmp.width)
            reply.writeInt(bmp.height)
            erase(bmp)
        } finally {
            SharedMemory.unmap(inBuf)
            input.close()
            output.close()
        }
    }

    private fun erase(bitmap: Bitmap) {
        // Each bitmap is erased exactly once, while mutable (isMutableRequired at decode).
        bitmap.eraseColor(0)
        bitmap.recycle()
    }

}
