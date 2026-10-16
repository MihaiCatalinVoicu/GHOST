package org.ghost.media.play

import android.content.Context
import androidx.media3.transformer.Transformer

/** Transformer outside GhostTranscoder: §16.1's clause. */
class Bad(context: Context) {
    val t = Transformer.Builder(context).build()
}
