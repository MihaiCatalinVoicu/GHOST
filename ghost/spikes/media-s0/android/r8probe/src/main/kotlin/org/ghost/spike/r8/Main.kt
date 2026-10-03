package org.ghost.spike.r8

import android.app.Activity
import android.os.Bundle

/** The R8 entry point: both flavours call [Probe.run], whose body differs by flavour. */
class Main : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = Probe.run(this)
    }
}
