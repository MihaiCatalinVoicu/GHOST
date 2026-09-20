package org.ghost.crypto.bridge

/**
 * The L1 (Olm message) header, as the typed facade of Phase 9 design §2.6 exposes it:
 * `L1.parse(bytes) → PreKey(OI, baseKey, fallbackKey, sessionId) | Normal(ratchetKey, chainIndex)
 * | Invalid`.
 *
 * **Where the fields come from.** L1 never leaves an AEAD on the wire (T29): the seal of §6
 * carries it whole, and the header is parsed **in Rust**, inside `openOuter` (§2.6 function 11,
 * which returns the Olm header of a pair or provisional envelope) and `openIntro` (function 12,
 * which returns the PreKey header of an intro envelope). This type is therefore a view over what
 * those calls returned, not a Kotlin parser — ADR-19 puts no protocol logic in Kotlin, and a
 * Kotlin protobuf reader over attacker-supplied bytes is exactly what that rule forbids.
 *
 * Those two functions are on the closed list and arrive with slice S7; until then this type is the
 * shape `:messaging` codes against, and [Invalid] is what a caller gets from a reply that does not
 * carry a complete header.
 */
sealed interface L1 {

    /** A first flight: the message that creates a session. */
    data class PreKey(
        /** The sender's Olm identity key, checked against the pinned one (§8.2 rule 3). */
        val olmIdentity: ByteArray,
        /** The sender's base key, which binding v3 signs (§3.4). */
        val baseKey: ByteArray,
        /** The fallback key used: it must be the named generation's (§3.4). */
        val fallbackKey: ByteArray,
        /** The raw session id, matched against the two stored slots (D2b, §7.6). */
        val sessionId: ByteArray,
        /** The inner ratchet key of the wrapped normal message. */
        val ratchetKey: ByteArray,
        /** The inner chain index, used by the gap hold (§7.7 point 2). */
        val chainIndex: Long,
    ) : L1 {
        override fun equals(other: Any?): Boolean =
            other is PreKey &&
                olmIdentity.contentEquals(other.olmIdentity) &&
                baseKey.contentEquals(other.baseKey) &&
                fallbackKey.contentEquals(other.fallbackKey) &&
                sessionId.contentEquals(other.sessionId) &&
                ratchetKey.contentEquals(other.ratchetKey) &&
                chainIndex == other.chainIndex

        override fun hashCode(): Int {
            var result = olmIdentity.contentHashCode()
            result = 31 * result + baseKey.contentHashCode()
            result = 31 * result + fallbackKey.contentHashCode()
            result = 31 * result + sessionId.contentHashCode()
            result = 31 * result + ratchetKey.contentHashCode()
            result = 31 * result + chainIndex.hashCode()
            return result
        }
    }

    /** A normal message of an established session. */
    data class Normal(
        /** The receiver chain this message belongs to. */
        val ratchetKey: ByteArray,
        /** The index inside that chain. */
        val chainIndex: Long,
    ) : L1 {
        override fun equals(other: Any?): Boolean =
            other is Normal &&
                ratchetKey.contentEquals(other.ratchetKey) &&
                chainIndex == other.chainIndex

        override fun hashCode(): Int = 31 * ratchetKey.contentHashCode() + chainIndex.hashCode()
    }

    /** No usable header: the blob is dropped with no state change and no traffic (T28). */
    data object Invalid : L1

    /** Whether this is a first flight. */
    val isPreKey: Boolean get() = this is PreKey

    /** The ratchet key, for the gap hold; `null` for [Invalid]. */
    val ratchetKeyOrNull: ByteArray?
        get() = when (this) {
            is PreKey -> ratchetKey
            is Normal -> ratchetKey
            Invalid -> null
        }

    /** The chain index, for the gap hold; `null` for [Invalid]. */
    val chainIndexOrNull: Long?
        get() = when (this) {
            is PreKey -> chainIndex
            is Normal -> chainIndex
            Invalid -> null
        }
}
