package org.ghost.sync.api

import org.ghost.network.OnionAddress

/** Local relay directory (Phase 14 fills it from the signed manifest; until then source CONFIG). */
interface RelayDirectory {
    /** Inserts or updates each entry; a retired address is reactivated with its cursors and capabilities. */
    fun upsert(tx: SyncTransaction, entries: List<RelayEntry>): Map<OnionAddress, RelayId>

    /**
     * Retires the relay: deliveries to it that could still store or be verified become failed (a
     * possible copy is kept), cursors and capabilities are kept for a later re-add.
     */
    fun retire(tx: SyncTransaction, relay: RelayId)

    fun active(): List<RelayEntry>
}

class RelayEntry(val address: OnionAddress, operatorId: ByteArray, val source: Source) {
    enum class Source(internal val code: String) {
        MANIFEST("manifest"), CONFIG("config");

        companion object {
            internal fun ofCode(code: String): Source =
                entries.firstOrNull { it.code == code } ?: throw IllegalStateException("unknown relay source")
        }
    }

    private val operator: ByteArray

    init {
        require(operatorId.size == OPERATOR_ID_SIZE) { "operator id has the wrong length" }
        operator = operatorId.copyOf()
    }

    val operatorId: ByteArray get() = operator.copyOf()

    internal val rawOperatorId: ByteArray get() = operator

    override fun equals(other: Any?): Boolean =
        other is RelayEntry && other.address == address && other.operator.contentEquals(operator) && other.source == source

    override fun hashCode(): Int = (address.hashCode() * 31 + operator.contentHashCode()) * 31 + source.hashCode()

    /** Never shows the onion address or the operator id (T3). */
    override fun toString(): String = "RelayEntry(redacted)"

    companion object {
        const val OPERATOR_ID_SIZE: Int = 16
    }
}
