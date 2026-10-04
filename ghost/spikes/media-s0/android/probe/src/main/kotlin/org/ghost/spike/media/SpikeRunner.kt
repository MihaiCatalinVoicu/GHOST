package org.ghost.spike.media

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle

/**
 * Self-instrumentation entry point (no AndroidX test coordinate, the ghost/android practice of
 * `DeviceRunner`): `am instrument -w -e probe <name> [-e key value …] org.ghost.spike.media/.SpikeRunner`.
 * Every probe adds report lines; the instrumentation result's `stream` carries them, one per line,
 * and ends with `probe <name>: OK` or `probe <name>: FAILED <exception>`.
 */
class SpikeRunner : Instrumentation() {
    private var args: Bundle = Bundle()

    override fun onCreate(arguments: Bundle?) {
        args = arguments ?: Bundle()
        instance = this
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        Report.lines.clear()
        val name = args.getString("probe") ?: "env"
        report(deviceLine())
        var ok = true
        try {
            Probes(this, args).run(name)
            report("probe $name: OK")
        } catch (t: Throwable) {
            ok = false
            report("probe $name: FAILED ${t.javaClass.name}: ${t.message}")
            for (e in t.stackTrace.take(12)) report("  at $e")
            var c = t.cause
            while (c != null) {
                report("  caused by ${c.javaClass.name}: ${c.message}")
                for (e in c.stackTrace.take(6)) report("    at $e")
                c = c.cause
            }
        }
        val sb = StringBuilder()
        for (l in ArrayList(Report.lines)) sb.append(l).append('\n')
        val out = Bundle()
        out.putString("stream", sb.toString())
        finish(if (ok) Activity.RESULT_OK else Activity.RESULT_CANCELED, out)
    }

    companion object {
        @Volatile lateinit var instance: SpikeRunner
    }
}
