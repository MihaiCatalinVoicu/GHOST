package org.ghost.media.play

import android.content.Context

/** A plaintext cache write: §10.3's temp-and-cache row. */
class Bad(context: Context) {
    val dir = context.cacheDir
}
