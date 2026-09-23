package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * The **host half** of the host/Android equivalence test (Phase 9 design §15.9 item 7, RG-2, V-16;
 * slice S12): every case of `protocol/test-vectors/dm_equivalence.txt` through JNI on the host
 * library `ghost-dm-host`, recorded as the fixture `build/dm-equivalence/dm_equivalence_host.txt`
 * that `dm-emulator.yml` replays on the emulator's x86_64 test library.
 *
 * It also proves the comparator on the JVM, where it can be read: the host against itself is all
 * identical with the control detected; a fixture with one changed output byte is reported at that
 * case; a fixture of another commit is refused before anything runs. A comparator that could not
 * fail would make the emulator's "identical" worth nothing.
 */
class DmEquivalenceHostTest {

    private lateinit var cases: List<DmEquivalence.Case>

    private val commit: String = System.getProperty("ghost.dm.commit")?.takeIf { it.isNotBlank() } ?: "unrecorded"

    @Before
    fun setUp() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "ghost-dm-host is not on the classpath (-Dghost.dm.native); the equivalence cases run natively",
            !path.isNullOrEmpty() && DmNative.isAvailable(),
        )
        cases = DmEquivalence.parseCases(File(CASES).readText())
    }

    private fun record(): DmEquivalence.HostFixture {
        val outputs = LinkedHashMap<String, ByteArray>()
        for (case in cases) outputs[case.id] = requireNotNull(DmEquivalence.run(case.kind, case.input)) { case.id }
        return DmEquivalence.HostFixture(commit, outputs)
    }

    @Test
    fun everyCaseRunsDeterministicallyThroughJniAndIsRecorded() {
        val fixture = record()
        for (case in cases) {
            val again = requireNotNull(DmEquivalence.run(case.kind, case.input))
            assertTrue("${case.id} is deterministic through JNI", again.contentEquals(fixture.outputs.getValue(case.id)))
            val code = again[0].toInt()
            if (case.id.startsWith("ok_")) assertEquals("${case.id} succeeds", 0, code)
            if (case.id.startsWith("refuse_")) assertTrue("${case.id} is refused", code != 0)
        }
        val out = File(FIXTURE)
        out.parentFile.mkdirs()
        out.writeText(fixture.render(cases.map { it.id }))
        // The recorded file parses back to the same outputs (the emulator reads it with `parse`).
        val back = DmEquivalence.HostFixture.parse(out.readText())
        assertEquals(commit, back.commit)
        for (case in cases) assertTrue(back.outputs.getValue(case.id).contentEquals(fixture.outputs.getValue(case.id)))
        println("dm-equivalence host: ${cases.size} cases recorded (commit $commit)")
    }

    @Test
    fun theHostAgainstItselfIsIdenticalWithTheControlDetected() {
        val report = DmEquivalence.compare(cases, record(), commit, DmEquivalence::run)
        assertTrue(report.line, report.passed)
        assertEquals("dm-equivalence: ${cases.size} cases, ${cases.size} identical, control detected", report.line)
    }

    @Test
    fun oneChangedOutputByteIsReportedAtItsCase() {
        val host = record()
        val victim = cases.first { it.id.startsWith("ok_seal_intro") }.id
        val changed = LinkedHashMap(host.outputs)
        changed[victim] = host.outputs.getValue(victim).copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val report = DmEquivalence.compare(cases, DmEquivalence.HostFixture(commit, changed), commit, DmEquivalence::run)
        assertFalse(report.passed)
        assertEquals(cases.size - 1, report.identical)
        assertEquals(victim, report.firstDifference)
    }

    @Test
    fun aFixtureOfAnotherCommitIsRefusedBeforeAnythingRuns() {
        var ran = 0
        val report = DmEquivalence.compare(cases, record(), "another-commit") { k, input ->
            ran += 1
            DmEquivalence.run(k, input)
        }
        assertFalse(report.passed)
        assertEquals(0, ran)
        assertTrue(report.line, report.line.startsWith("dm-equivalence: refused"))
    }

    @Test
    fun aComparatorThatIgnoredTheControlWouldBeCaught() {
        // The control's flipped input must not reproduce the recorded output: a runner that answers
        // the recorded bytes whatever it is given (a comparator comparing a fixture with itself) is
        // "control NOT detected".
        val host = record()
        val byInput = cases.associate { it.input.toList() to host.outputs.getValue(it.id) }
        val echo = DmEquivalence.compare(cases, host, commit) { _, input -> byInput[input.toList()] ?: host.outputs.getValue(DmEquivalence.CONTROL_ID) }
        assertFalse(echo.controlDetected)
        assertFalse(echo.passed)
    }

    private companion object {
        const val CASES = "../../protocol/test-vectors/dm_equivalence.txt"
        const val FIXTURE = "build/dm-equivalence/dm_equivalence_host.txt"
    }
}
