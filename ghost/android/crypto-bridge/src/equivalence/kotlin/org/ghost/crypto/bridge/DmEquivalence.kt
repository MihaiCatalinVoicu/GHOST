package org.ghost.crypto.bridge

import java.security.MessageDigest

/**
 * **The host/Android equivalence entry point** (Phase 9 design §15.9 item 7, RG-2, V-16; §22.8.10
 * point 6; slice S12) and the comparison built on it.
 *
 * This source set (`src/equivalence`) is compiled into `:crypto-bridge`'s JVM tests and its
 * `androidTest` APK and into nothing else: gate G-DM5 fails if `DmEquivalence` reaches a release
 * source set or R8's release mapping, and G-R6 fails if a shipped library exports its symbol. The
 * native half is `ghost_client_dm::equivalence`, compiled with the `test-vectors` feature into
 * `ghost-dm-host` only — the JVM tests' host library and, cross-compiled for `x86_64-linux-android`,
 * the emulator's test library.
 *
 * The protocol, end to end:
 *  1. `protocol/test-vectors/dm_equivalence.txt` holds the deterministic **inputs** (`id kind hex`),
 *     generated and checked by `client-core/dm/tests/equivalence.rs`;
 *  2. `dm-emulator.yml` runs every case through [run] on the host library (the JVM test
 *     `DmEquivalenceHostTest`) and writes the **host fixture** ([HostFixture.render]): a header
 *     naming the commit, then `id sha256 hex(output)` (design §22.17 item 8: the emulator job
 *     records it itself, in the same job and checkout, not ci.yml's `android` job);
 *  3. the same job replays the same file on the emulator's library and [compare]s byte for
 *     byte, printing the first differing case, refusing a fixture of another commit, and running
 *     the **control**: the control case's input with one byte flipped must be reported different,
 *     so the comparator is not vacuous.
 */
object DmEquivalence {

    /** The control case's id in the case file (§15.9 item 7: "a self-test case"). */
    const val CONTROL_ID: String = "control"

    /** `ghost_client_dm::equivalence::run`: `code(1) ‖ fields`, or null if the reply could not be built. */
    @JvmStatic
    @JvmName("run")
    external fun run(kind: Int, input: ByteArray): ByteArray?

    /**
     * MC-20 and KC5b's binding hooks of the DM context [handle] (design §15.5 KC5b, §15.7 MC-20,
     * §22.37; `ghost_client_dm::binding::hooks`): the second test-vectors entry point, in the test
     * libraries only like [run] (G-R6 `--test`). [omit] leaves one binding v3 field out of every
     * transcript the context signs or verifies — the mutant; [perturb] has every intro the context
     * seals carry the sender's genuine signature over another value of one field than the envelope
     * carries — KC5b's replayed binding. [BINDING_NONE] clears; false for a code out of range.
     */
    @JvmStatic
    @JvmName("bindingHooks")
    external fun bindingHooks(handle: Long, omit: Int, perturb: Int): Boolean

    /**
     * ME-24's state-wrap hook of the DM context [handle] (design §15.7 ME-24, §22.38;
     * `ghost_client_dm::wrap::hooks`): the third test-vectors entry point, in the test libraries
     * only like [run]. [unwrapped] true has the context store its Olm session states **unwrapped**
     * and read them back as stored, so a mutated world still runs its ratchet and only what
     * `olm_session.state_env` holds differs; false wraps them again. Always true.
     */
    @JvmStatic
    @JvmName("stateWrapHook")
    external fun stateWrapHook(handle: Long, unwrapped: Boolean): Boolean

    /**
     * MC-30's sidecar-log hook of the DM context [handle] (design §15.7 MC-30, §22.38;
     * `ghost_client_dm::olm::state::hooks`): the fourth test-vectors entry point, in the test
     * libraries only like [run]. [on] true has the context keep every session's first-seen sidecar as
     * an insert-only **log** — an entry outlives the key the pickle no longer holds — instead of the
     * projection §7.7 point 4 rebuilds at every store; false rebuilds projections again. Always true.
     */
    @JvmStatic
    @JvmName("sidecarLogHook")
    external fun sidecarLogHook(handle: Long, on: Boolean): Boolean

    /** [bindingHooks]: no field. */
    const val BINDING_NONE: Int = 0

    /** [bindingHooks]: the recipient namespace. */
    const val BINDING_NAMESPACE: Int = 1

    /** [bindingHooks]: the binding minute (perturbed to a stale one). */
    const val BINDING_MINUTE: Int = 2

    /** [bindingHooks]: the X-Wing ciphertext, as its SHA-256. */
    const val BINDING_CIPHERTEXT: Int = 3

    /** [bindingHooks]: the base key of the Olm PreKey message. */
    const val BINDING_BASE_KEY: Int = 4

    /** One case of the case file. */
    class Case(val id: String, val kind: Int, input: ByteArray) {
        private val bytes = input.copyOf()
        val input: ByteArray get() = bytes.copyOf()

        override fun toString(): String = "Case($id)"
    }

    /** Parses `dm_equivalence.txt`: comments and blank lines skipped, `id kind hex` otherwise. */
    fun parseCases(text: String): List<Case> {
        val out = ArrayList<Case>()
        for (raw in text.replace("\r\n", "\n").lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parts = line.split(' ')
            require(parts.size == 3) { "a case line is `id kind hex`" }
            out += Case(parts[0], parts[1].toInt(16), unhex(parts[2]))
        }
        require(out.map { it.id }.toSet().size == out.size) { "duplicate case id" }
        require(out.any { it.id == CONTROL_ID }) { "the case file has no control case" }
        return out
    }

    /** The recorded outputs of one build: its commit and, per case, the output bytes. */
    class HostFixture(val commit: String, val outputs: Map<String, ByteArray>) {
        /** `# commit`, `# cases`, then `id sha256(output) hex(output)` per case, in case order. */
        fun render(order: List<String>): String = buildString {
            append("# GHOST Phase 9 host/Android equivalence fixture (design §15.9 item 7).\n")
            append("# commit ").append(commit).append('\n')
            append("# cases ").append(order.size).append('\n')
            for (id in order) {
                val out = requireNotNull(outputs[id]) { "no output for $id" }
                append(id).append(' ').append(hex(sha256(out))).append(' ').append(hex(out)).append('\n')
            }
        }

        override fun toString(): String = "HostFixture(${outputs.size} cases)"

        companion object {
            fun parse(text: String): HostFixture {
                var commit: String? = null
                val outputs = LinkedHashMap<String, ByteArray>()
                for (raw in text.replace("\r\n", "\n").lineSequence()) {
                    val line = raw.trim()
                    if (line.isEmpty()) continue
                    if (line.startsWith("# commit ")) {
                        commit = line.removePrefix("# commit ").trim()
                        continue
                    }
                    if (line.startsWith("#")) continue
                    val parts = line.split(' ')
                    require(parts.size == 3) { "a fixture line is `id sha256 hex`" }
                    val out = unhex(parts[2])
                    require(hex(sha256(out)) == parts[1]) { "the fixture's digest of ${parts[0]} does not match its bytes" }
                    outputs[parts[0]] = out
                }
                return HostFixture(requireNotNull(commit) { "the fixture names no commit" }, outputs)
            }
        }
    }

    /** What a comparison found. [line] is the report line `dm-report-check.sh`-style checks read. */
    class Report(
        val cases: Int,
        val identical: Int,
        val controlDetected: Boolean,
        val firstDifference: String?,
        val refusal: String?,
    ) {
        val passed: Boolean get() = refusal == null && identical == cases && controlDetected

        val line: String
            get() = when {
                refusal != null -> "dm-equivalence: refused ($refusal)"
                else -> "dm-equivalence: $cases cases, $identical identical, " +
                    (if (controlDetected) "control detected" else "control NOT detected") +
                    (firstDifference?.let { ", first difference $it" } ?: "")
            }

        override fun toString(): String = line
    }

    /**
     * Replays [cases] through [runner] (this build's library) and compares with [host], byte for
     * byte. A fixture of another [commit] is refused before anything runs (§15.9: "the comparison
     * refuses fixtures from another commit"); a fixture that lacks a case is a difference. The
     * control case runs twice here: as recorded (it must be identical) and with the last byte of its
     * input flipped (it must differ from the host's output).
     */
    fun compare(
        cases: List<Case>,
        host: HostFixture,
        commit: String,
        runner: (Int, ByteArray) -> ByteArray?,
    ): Report {
        if (host.commit != commit) {
            return Report(cases.size, 0, false, null, "the host fixture is of commit ${host.commit}, this build is $commit")
        }
        var identical = 0
        var first: String? = null
        var control = false
        for (case in cases) {
            val mine = runner(case.kind, case.input)
            val theirs = host.outputs[case.id]
            if (mine != null && theirs != null && mine.contentEquals(theirs)) {
                identical += 1
            } else if (first == null) {
                first = case.id
            }
            if (case.id == CONTROL_ID && theirs != null) {
                val flipped = case.input.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
                val changed = runner(case.kind, flipped)
                control = changed != null && !changed.contentEquals(theirs)
            }
        }
        return Report(cases.size, identical, control, first, null)
    }

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0) { "odd hex length" }
        return ByteArray(text.length / 2) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
