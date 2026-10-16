package org.ghost.media.play

import android.graphics.Bitmap

/**
 * The bitmap half of §10.5's RAM hygiene (slice S7, RV-P12): `recycle()` frees a bitmap's
 * pixel memory **without any documented overwrite**, so every bitmap GHOST creates from
 * media pixels is overwritten with `eraseColor(0)` before it is recycled — when its screen
 * closes, when a cache evicts it, and at lock. Memory the platform owns (the compositor's
 * textures, codec output buffers, Media3's sample arrays) cannot be erased from here and
 * stays a declared residue (L9-M7).
 */
object MediaBitmaps {

    /** Overwrite [bitmap]'s pixels with transparent black, then release its memory. */
    fun eraseAndRecycle(bitmap: Bitmap) {
        if (!bitmap.isRecycled) {
            bitmap.eraseColor(0)
            bitmap.recycle()
        }
    }

    /** Overwrite the pixels of a bitmap that stays alive (a cache entry leaving the screen). */
    fun erase(bitmap: Bitmap) {
        if (!bitmap.isRecycled) bitmap.eraseColor(0)
    }
}
