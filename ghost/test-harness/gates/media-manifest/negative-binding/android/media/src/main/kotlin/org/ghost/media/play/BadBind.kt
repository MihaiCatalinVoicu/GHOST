package org.ghost.media.play

import android.content.Context
import android.content.Intent

/** A bind outside the sandbox package: G-M4's source half. */
class BadBind(private val context: Context) {
    fun bind(intent: Intent, conn: android.content.ServiceConnection) {
        context.bindIsolatedService(intent, 0, "m0", { it.run() }, conn)
    }
}
