package org.ghost.media.send

import android.media.MediaDataSource
import android.media.MediaMetadataRetriever

/**
 * Fallback only for the internally generated calibration stream, never for picked or received media.
 * The decoded RGB grid is checked by ColourGrid; the stream's colour label selects the conversion.
 */
internal object CalibrationFrameProbe {
    fun decode(stream: ByteArray): Yuv420.Frame? {
        val retriever = MediaMetadataRetriever()
        val source = object : MediaDataSource() {
            override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
                if (position >= stream.size) return -1
                val count = minOf(size.toLong(), stream.size - position).toInt()
                stream.copyInto(buffer, offset, position.toInt(), position.toInt() + count)
                return count
            }
            override fun getSize(): Long = stream.size.toLong()
            override fun close() = Unit
        }
        return try {
            retriever.setDataSource(source)
            val bitmap = retriever.getFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                ?: return null
            try {
                val matrix = when (
                    retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_COLOR_STANDARD)
                ) {
                    "1" -> Yuv420.Matrix.BT_709
                    else -> Yuv420.Matrix.BT_601
                }
                val width = bitmap.width
                val height = bitmap.height
                val pixels = IntArray(width * height)
                bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
                val yPlane = ByteArray(width * height)
                val uPlane = ByteArray((width / 2) * (height / 2))
                val vPlane = ByteArray(uPlane.size)
                for (y in 0 until height) {
                    for (x in 0 until width) {
                        val rgb = pixels[y * width + x]
                        val r = (rgb shr 16) and 0xff
                        val g = (rgb shr 8) and 0xff
                        val b = rgb and 0xff
                        val yv: Int
                        val uv: Int
                        val vv: Int
                        if (matrix == Yuv420.Matrix.BT_709) {
                            yv = 16 + (47_223 * r + 157_243 * g + 15_874 * b) / 255_000
                            uv = 128 + (-25_447 * r - 98_552 * g + 124_000 * b) / 255_000
                            vv = 128 + (124_000 * r - 116_133 * g - 7_867 * b) / 255_000
                        } else {
                            yv = 16 + (65_481 * r + 128_553 * g + 24_966 * b) / 255_000
                            uv = 128 + (-37_797 * r - 74_203 * g + 112_000 * b) / 255_000
                            vv = 128 + (112_000 * r - 93_786 * g - 18_214 * b) / 255_000
                        }
                        yPlane[y * width + x] = yv.coerceIn(0, 255).toByte()
                        if (x % 2 == 0 && y % 2 == 0) {
                            val at = (y / 2) * (width / 2) + x / 2
                            uPlane[at] = uv.coerceIn(0, 255).toByte()
                            vPlane[at] = vv.coerceIn(0, 255).toByte()
                        }
                    }
                }
                Yuv420.Frame(width, height, yPlane, width, uPlane, width / 2, vPlane, width / 2)
            } finally {
                bitmap.recycle()
            }
        } catch (e: RuntimeException) {
            null
        } finally {
            retriever.release()
        }
    }
}
