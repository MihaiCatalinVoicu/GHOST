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
 * Those two functions are on the closed list and arrived with slice S7. [L1.parse] is the third
 * source, added by S8 for the one caller that holds bare L1 bytes and no envelope — the HELD
 * replay — and it is still Rust's parse, not Kotlin's. [Invalid] is what a caller gets from bytes
 * that do not carry a complete header of the kind it asked for.
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

    /**
     * The DM context is closed or the library is missing — **not** a statement about the bytes.
     *
     * It is a separate answer from [Invalid] because the two have opposite consequences for the
     * one caller that holds the only copy of the ciphertext: HELD **deletes** a row it cannot
     * parse, and a row that failed to parse because the library was not loaded would be destroyed
     * for a reason that has nothing to do with it. Every other typed facade of §2.6 already
     * separates them (`Unavailable` on `DmCards`, `DmSeal`, `DmSessions`, `DmPairing`,
     * `DmRevocations`), and this one did not.
     */
    data object Unavailable : L1

    /** Whether this is a first flight. */
    val isPreKey: Boolean get() = this is PreKey

    /** The ratchet key, for the gap hold; `null` for [Invalid] and [Unavailable]. */
    val ratchetKeyOrNull: ByteArray?
        get() = when (this) {
            is PreKey -> ratchetKey
            is Normal -> ratchetKey
            Invalid, Unavailable -> null
        }

    /** The chain index, for the gap hold; `null` for [Invalid] and [Unavailable]. */
    val chainIndexOrNull: Long?
        get() = when (this) {
            is PreKey -> chainIndex
            is Normal -> chainIndex
            Invalid, Unavailable -> null
        }

    companion object {
        /**
         * §2.6's `L1.parse(bytes)`, through function 24 of the closed surface (added by S8).
         *
         * **The one caller that needs it holds no envelope.** `openOuter` and `openIntro` return
         * the header beside the L1 they just opened, so every S7 caller had its fields for free;
         * a `dm_held` row stores the L1 alone (§8.3), and §22.8.1 rule 1 has HELD group the rows
         * by `session_id` and order each group by the inner chain index **before** the first
         * `sessionInbound` runs. The parse stays in Rust — this is a view over what the crate
         * returned, not a Kotlin protobuf reader over attacker-supplied bytes (ADR-19).
         *
         * [isPreKey] says which kind the caller expects; a mismatch is [Invalid], as is anything
         * that does not decode or carries a non-canonical Curve25519 key (R2-06). A closed context
         * or a missing library is [Unavailable] and never [Invalid]: see that type for why the
         * distinction is load-bearing here and nowhere else.
         */
        fun parse(l1: ByteArray, isPreKey: Boolean): L1 {
            if (!DmNative.isAvailable()) return Unavailable
            val result = dmCall { DmNative.l1Parse(l1, if (isPreKey) 1 else 0) }
            return when (result.code) {
                DmCode.OK ->
                    if (result.byte(DmField.FLAGS) and DM_FLAG_PRE_KEY != 0) {
                        PreKey(
                            olmIdentity = result.bytes(DmField.OLM_IDENTITY),
                            baseKey = result.bytes(DmField.BASE_KEY),
                            fallbackKey = result.bytes(DmField.ONE_TIME_KEY),
                            sessionId = result.bytes(DmField.SESSION_ID),
                            ratchetKey = result.bytes(DmField.RATCHET_KEY),
                            chainIndex = result.i64(DmField.CHAIN_INDEX),
                        )
                    } else {
                        Normal(
                            ratchetKey = result.bytes(DmField.RATCHET_KEY),
                            chainIndex = result.i64(DmField.CHAIN_INDEX),
                        )
                    }
                DmCode.NON_CANONICAL -> Invalid
                DmCode.CRYPTO_UNAVAILABLE -> Unavailable
                else -> unexpected(result.code, "l1Parse")
            }
        }
    }
}
