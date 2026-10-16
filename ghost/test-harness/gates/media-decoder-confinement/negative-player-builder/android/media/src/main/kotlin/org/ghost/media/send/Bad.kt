package org.ghost.media.send

import android.content.Context
import androidx.media3.exoplayer.ExoPlayer

/** The one-arg builder outside GhostPlayer: G-M3's configuration rule. */
class Bad(context: Context) {
    val player = ExoPlayer.Builder(context).build()
}
