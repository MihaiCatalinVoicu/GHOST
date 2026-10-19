package org.ghost.backupctl

import android.app.Activity
import android.app.Application
import android.os.Bundle
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

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

/** The launcher activity the manifest needs; does nothing visible, but T6's dynamic run makes
 * it the positive control: a DNS resolution and a clearnet connection that the capture and the
 * per-uid socket snapshots MUST see - so zero attributed traffic from GHOST proves the
 * measurement, not a broken tap. Repeated so the snapshots cannot miss the socket. */
class BackupCtlActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread {
            try {
                // A query the capture must see (the DNS positive control)...
                InetAddress.getByName("example.com")
                // ...and a socket held in SYN-SENT against TEST-NET-1 (192.0.2.1, no host
                // answers), so the per-uid socket snapshots cannot miss it.
                Socket().connect(InetSocketAddress("192.0.2.1", 80), 20_000)
            } catch (_: Exception) {
                // The connect eventually times out; the DNS query and the SYN are the evidence.
            }
        }.start()
        // No finish(): a finished activity lets API 29 cull the process before the probe's
        // connect; a blank resumed activity keeps it alive for the run.
    }
}
