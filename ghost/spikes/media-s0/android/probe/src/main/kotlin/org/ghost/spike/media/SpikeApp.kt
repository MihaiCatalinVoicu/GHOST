package org.ghost.spike.media

import android.app.Application
import android.net.ConnectivityManager
import android.os.Process
import android.os.SystemClock
import java.io.File
import java.security.KeyStore

/**
 * The probe's Application. It reproduces what design §9.2 / V-M19 is about: Android creates the
 * app's Application in **every** process, isolated ones included, and `GhostApp.onCreate` opens
 * no-backup files, the Keystore and system services.
 *
 * - In the main process it does that GhostApp-like work ([ghostAppLikeWork]).
 * - In an isolated process it records that it ran (V-M19's "log-free probe of what ran": a static
 *   field the service reports over Binder) and returns right after `super.onCreate()` — the
 *   design's `Process.isIsolated()` early return — **unless** the process name contains
 *   `unguarded`, in which case it does the same work as the main process, uncaught: that is
 *   mutant MC-M23 (the early return removed), used to observe how a bind fails.
 */
class SpikeApp : Application() {
    override fun onCreate() {
        super.onCreate()
        onCreateUptimeMs = SystemClock.uptimeMillis()
        onCreateProcessName = getProcessName()
        if (Process.isIsolated()) {
            ranInIsolatedProcess = true
            if (onCreateProcessName?.contains("unguarded") == true) {
                ghostAppLikeWork()
            }
            return
        }
        ghostAppLikeWork()
    }

    /** What GhostApp's wiring touches at process start (design Appendix C.1: GhostApp.kt:146-158). */
    fun ghostAppLikeWork() {
        // Written once per install, so the file inventories of V-M1/V-M11/V-M23 see no write from
        // process start (in an isolated process even the existence check fails: no data access).
        val f = File(noBackupFilesDir, "spike-app-start")
        if (!f.exists()) f.writeBytes(byteArrayOf(1))
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        getSystemService(ConnectivityManager::class.java).activeNetwork
    }

    companion object {
        @Volatile var ranInIsolatedProcess = false
        @Volatile var onCreateUptimeMs = -1L
        @Volatile var onCreateProcessName: String? = null
    }
}
