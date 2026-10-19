package org.ghost.backupctl

import android.app.Activity
import android.app.Application
import android.os.Bundle
import java.io.File

/**
 * T4's control (design faza13-ux.md Appendix B.2): writes the canary file at first start, so a
 * backup run must carry it. GHOST's own backup rules are the strict counterpart — its archive
 * must be empty.
 */
class BackupCtlApp : Application() {
    override fun onCreate() {
        super.onCreate()
        File(filesDir, "t4_canary.txt").writeText("T4-CANARY-${packageName}\n")
    }
}

/** The launcher activity the manifest needs; does nothing. */
class BackupCtlActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
