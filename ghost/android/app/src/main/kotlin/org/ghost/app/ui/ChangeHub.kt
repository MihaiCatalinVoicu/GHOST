package org.ghost.app.ui

import kotlinx.coroutines.flow.MutableSharedFlow

/**
 * Phase 13 design §3.2: the content-free hint bus. Engine listeners feed it with `tryEmit` from
 * the engine's thread (the listener must never block the actor, F9 §13.7); a lost hint is
 * harmless because screen models re-query. Kinds are coarse and carry no data.
 */
object ChangeHub {
    /** The hint kinds (the DM listener's ChangeKind of §3.6 plus the other engines'). */
    enum class ChangeKind { CONTACTS, MESSAGES, REQUESTS, TRUST, OUTCOMES, STATUS, CHANNELS, MEDIA, ACCESS, SETTINGS }

    val flow: MutableSharedFlow<ChangeKind> = MutableSharedFlow(
        extraBufferCapacity = 64,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST,
    )

    /** The only write site; safe from any thread. */
    fun hint(kind: ChangeKind) {
        flow.tryEmit(kind)
    }
}
