package org.ghost.device

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import org.junit.runner.Description
import org.junit.runner.JUnitCore
import org.junit.runner.notification.Failure
import org.junit.runner.notification.RunListener
import java.util.Collections

/**
 * **The instrumentation runner of the emulator job** (Phase 9 design §15.9; slice S12): JUnit 4 on a
 * device with nothing but `junit:junit`, which the JVM tests already use.
 *
 * §16.3 adds no Gradle coordinate in Phase 9, and the AndroidX test runner is one; so the
 * instrumented suites run through this `Instrumentation`, which hands the classes a subclass names
 * to `JUnitCore` and reports through the instrumentation result. `dm-emulator.yml` runs it with
 * `am instrument -w` and reads two things from the output:
 *  - the **summary line** `device tests: <run> run, <failed> failed, <skipped> skipped`, which must
 *    say 0 failed and 0 skipped — a skipped device test is a green tick over nothing, the same rule
 *    the JVM gates apply to `-Dghost.dm.native`;
 *  - the **report lines** a test adds with [report] (`dm-equivalence: …`, `dm-device: …`), which
 *    `dm-emulator.yml` checks by name.
 * The result code is `RESULT_OK` only when every test passed and none was skipped or ignored, and
 * at least one ran.
 *
 * It is compiled into `androidTest` APKs only (`src/deviceRunner` is an `androidTest` source
 * directory of the modules that use it), never into a release source set (gate G-DM5).
 *
 * **No Kotlin standard-library function here, and none in a runner of a release test APK**
 * (found on the first emulator run, design §22.32). `:app`'s smoke test runs against the R8-shrunk
 * release: AGP leaves the Kotlin standard library out of that test APK, because the tested app
 * carries it, and maps the test's references through the app's `mapping.txt` — so a call resolves
 * against the app's *shrunk* copy. `listOf(x)`, `plus` and `joinToString`, which the first version
 * called, have no caller in the release, R8 removed them, and the instrumentation died with
 * `NoSuchMethodError` in `AppDeviceRunner.<init>` before any test ran. Only JDK and Android calls
 * (and inline functions, which leave no call) are safe in this file.
 */
abstract class DeviceRunner(private val classes: List<Class<*>>) : Instrumentation() {

    override fun onCreate(arguments: Bundle?) {
        args = arguments ?: Bundle()
        current = this
        reports.clear()
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        val failures = Collections.synchronizedList(ArrayList<String>())
        val core = JUnitCore()
        core.addListener(object : RunListener() {
            override fun testFailure(failure: Failure) {
                failures += "${failure.description.displayName}: ${failure.message}"
            }

            override fun testAssumptionFailure(failure: Failure) {
                failures += "${failure.description.displayName}: skipped (${failure.message})"
            }

            override fun testIgnored(description: Description) {
                failures += "${description.displayName}: ignored"
            }
        })
        val result = core.run(*classes.toTypedArray())
        val skipped = result.ignoreCount + result.assumptionFailureCount
        val summary = "device tests: ${result.runCount} run, ${result.failureCount} failed, $skipped skipped"
        // JDK calls only, no Kotlin collection function (see the class note): in the release smoke
        // test this code runs against the R8-shrunk app's copy of the Kotlin standard library.
        val stream = StringBuilder()
        for (line in ArrayList<String>(reports)) stream.append(line).append('\n')
        for (line in ArrayList<String>(failures)) stream.append(line).append('\n')
        stream.append(summary).append('\n')
        val out = Bundle()
        out.putString("stream", stream.toString())
        val ok = result.runCount > 0 && result.failureCount == 0 && skipped == 0
        finish(if (ok) Activity.RESULT_OK else Activity.RESULT_CANCELED, out)
    }

    companion object {
        /** The `am instrument -e` arguments of this run. */
        @Volatile
        lateinit var args: Bundle
            private set

        /** The running instrumentation: its `context` is the test APK's (assets), `targetContext` the target's. */
        @Volatile
        lateinit var current: Instrumentation
            private set

        private val reports: MutableList<String> = Collections.synchronizedList(ArrayList())

        /** Adds a report line to the run's output (see the class note). */
        fun report(line: String) {
            reports += line
        }
    }
}
