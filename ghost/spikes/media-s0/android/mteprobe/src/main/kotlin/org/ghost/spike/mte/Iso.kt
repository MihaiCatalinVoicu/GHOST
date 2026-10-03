package org.ghost.spike.mte

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder

/** An empty isolated service: V-M15 looks only at what the package manager records. */
class Iso : Service() {
    override fun onBind(intent: Intent?): IBinder = Binder()
}
