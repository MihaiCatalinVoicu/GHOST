package org.ghost.network

import org.ghost.storage.SqlExecutor
import org.ghost.storage.TransportBridgeRepository

/**
 * PT-3/PT-4 (design `faza12-transports.md` §6, §8.2, §8.5; ADR-62): the bridge-line storage
 * facade — the seam Phase 13's paste/QR settings screen will call, and the host-side test entry
 * (Q4) drives today. The lines are user-provided only (D6): no built-in list, no fetch. What
 * crosses this boundary:
 *
 *  - [set] validates the whole list through the **single Rust validator**
 *    (`nativeValidateBridgeLines`, the same grammar table `build_config` re-runs at client
 *    creation, §6.2) and stores only the validated, deduped lines, wrapped in the SQLCipher
 *    database like everything else — no new key, the existing no-backup posture (D7). A refusal
 *    throws [NetworkException] with the `bridge_line_invalid` / `bridge_line_unsupported_transport`
 *    category and the failing index as the exception detail — never the line's text (§6.6, T58,
 *    G-T7).
 *  - [list] returns the stored lines in insertion order (§6.3); they are config at this
 *    boundary, but they never enter a log.
 *
 * Nothing here logs; the typed errors and the wrapped storage are the whole privacy shape.
 */
class BridgeLines(
    db: SqlExecutor,
    clockDay: () -> Long,
) {

    private val repo = TransportBridgeRepository(db, clockDay)

    /**
     * PT-3: validates [lines] and replaces the configured set. An empty list clears it. Throws
     * [NetworkException] `bridge_line_invalid:<index>` (structural failure, the length cap, the
     * 8-line cap) or `bridge_line_unsupported_transport:<index>` (an unknown transport name,
     * snowflake's 12b deferral included) — the index as [NetworkException.detail], never line
     * text.
     */
    fun set(lines: List<String>) {
        val result = TorRelayTransport.validateBridgeLines(lines)
        val error = Regex("^(${PtErrorCategories.BRIDGE_LINE_INVALID}|${PtErrorCategories.BRIDGE_LINE_UNSUPPORTED_TRANSPORT}):([0-9]+)$")
            .find(result)
        if (error != null) {
            throw NetworkException(error.groupValues[1], error.groupValues[2])
        }
        val validated = if (result.isEmpty()) emptyList() else result.split("\n")
        repo.replaceAll(validated)
    }

    /** PT-4: the configured lines in insertion order; empty when none are configured. */
    fun list(): List<String> = repo.list()

    /** Deletes one exact line (the UI's remove action and the host entry); true when a row went. */
    fun delete(line: String): Boolean = repo.delete(line)
}
