package org.ghost.spike.r8

import android.content.Context

/** Base flavour: no Media3 at all (the size baseline of V-M7). */
object Probe {
    fun run(ctx: Context): String = "base " + ctx.packageName
}
