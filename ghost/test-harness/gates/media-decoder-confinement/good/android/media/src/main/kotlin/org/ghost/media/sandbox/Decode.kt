package org.ghost.media.sandbox

import android.media.ImageDecoder
import android.graphics.BitmapFactory

/** The only package that may name platform decoders (§13.1). */
class Decode {
    fun decode(src: ImageDecoder.Source) = BitmapFactory.decodeByteArray(ByteArray(0), 0, 0)
}
