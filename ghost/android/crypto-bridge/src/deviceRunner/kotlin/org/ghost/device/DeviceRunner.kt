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
        val out = Bundle()
        out.putString(
            "stream",
            (reports + failures + summary).joinToString(separator = "\n", postfix = "\n"),
        )
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
