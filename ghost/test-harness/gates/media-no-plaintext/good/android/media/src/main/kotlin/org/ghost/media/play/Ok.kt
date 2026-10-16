package org.ghost.media.play

/** A clean playback source: nothing the gate bans. */
class Ok(private val playable: MediaPlayable) {
    fun length(): Long = playable.contentLength
}
