package org.ghost.sync.android

/**
 * The bootstrap configuration of one attempt of the reduced auto mode (Phase 12 design
 * `faza12-transports.md` §6.5; Q6, X-T2; ADR-62 point 5). Never anything but Tor: a direct
 * attempt or exactly one bridge line — there is no clearnet shape to represent (R12-6).
 */
internal sealed interface BootstrapAttempt {
    /** What [org.ghost.network.TorRelayTransport.create] receives as its bridge lines. */
    val bridgeLines: List<String>

    /** The direct attempt: Tor without bridges (today's Phase 6 client). */
    object Direct : BootstrapAttempt {
        override val bridgeLines: List<String> = emptyList()
        override fun toString(): String = "Direct"
    }

    /** One PT-or-plain bridge line, one fresh client, its own 180 s native deadline (D11). */
    data class Bridges(val line: String) : BootstrapAttempt {
        override val bridgeLines: List<String> get() = listOf(line)
        override fun toString(): String = "Bridges(<one line>)"
    }
}

/**
 * Q6's reduced auto mode as a pure policy (§6.5, PT-U4): direct first when allowed, then the
 * configured bridge lines in order, one client per attempt; when the sequence is exhausted the
 * holder fails fast with the spent rule until the caller gives up and surfaces the transport
 * state. A new epoch starts when the holder is aborted (a session's end — the next session
 * re-runs the sequence from the top).
 *
 * The providers are read at claim time, so a bridge-line change (Phase 13's settings write)
 * takes effect with the next epoch; [allowDirect] false is the bridges-only mode of §6.5 point 3
 * (a Phase 13 setting; in Phase 12 the host entry sets the flag).
 */
internal class BootstrapPlan(
    private val lines: () -> List<String>,
    private val allowDirect: () -> Boolean = { true },
) {
    /** Attempts claimed in the current epoch; [reset] starts a new epoch. */
    private var claimed = 0

    @Synchronized
    fun reset() {
        claimed = 0
    }

    /**
     * The config of the next attempt, or null when this epoch's sequence is exhausted (the holder
     * then fails fast with the spent category, without creating a client). Each non-null claim
     * advances the epoch's position by one.
     */
    @Synchronized
    fun claim(): BootstrapAttempt? {
        val sequence = sequence()
        if (claimed >= sequence.size) return null
        return sequence[claimed++]
    }

    /** The whole epoch sequence: direct (when allowed), then each configured line in order. */
    internal fun sequence(): List<BootstrapAttempt> {
        val out = ArrayList<BootstrapAttempt>()
        if (allowDirect()) out += BootstrapAttempt.Direct
        for (line in lines()) out += BootstrapAttempt.Bridges(line)
        return out
    }
}
