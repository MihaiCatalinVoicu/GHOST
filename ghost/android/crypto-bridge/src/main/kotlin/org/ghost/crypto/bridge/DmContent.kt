package org.ghost.crypto.bridge

/**
 * The L0 content codec of Phase 9 design §7.1, as the typed facade exposes it (§2.6 function 18).
 *
 * The codec is **in Rust** (ADR-19: no protocol logic in Kotlin), and this class carries fields,
 * not bytes. Two of them never cross in clear:
 *
 *  - the `seal_root` TLV goes **in** as the wrapped `dm_pair_offer.offer_env`, because its value
 *    carries the 32-byte root (§9.4: the offered bytes are stored wrapped so re-attachment until
 *    acknowledgement repeats them exactly);
 *  - a received `seal_root` comes **out** as the wrapped `dm_pair_offer.root_env`, which the
 *    caller hands to [DmPairing.keys] and never opens (rule R-S6).
 *
 * The TLVs R-C3 allows on a user-initiated send are the only ones [encode] writes; a PQ-C TLV
 * (§9.4, slice S13) is neither written nor acted on, and [Decoded.sawPqTlv] is how a receiver
 * counts one.
 */
object DmContent {

    /** The content kinds of §7.1. `0x05` MEDIA is Phase 11 and is refused. */
    enum class Kind(val wire: Int) {
        /** UTF-8 text. */
        TEXT(0x01),

        /** A conversation timer change; no body (§10.5). */
        TIMER_SET(0x02),

        /** A reaction: the target `message_id` and one grapheme, or nothing to remove it. */
        REACTION(0x03),

        /** A control message: no body, TLVs only (§7.1). */
        CONTROL(0x04),
        ;

        internal companion object {
            fun fromWire(wire: Int): Kind? = entries.firstOrNull { it.wire == wire }
        }
    }

    /** A decoded L0 (§7.1). */
    class Decoded(
        /**
         * The bucket R-B1 chooses for this record's **body length** (§6.6).
         *
         * It comes back from the crate for the same reason [Encoded.Ok] carries one: a caller
         * re-sealing a stored L0 — a pending send flushed at `EST-READY`, a FAILED item retried —
         * must use the bucket the original send chose, and deriving it in Kotlin from the encoded
         * record or from a ciphertext would be mutants ME-22 and ME-3.
         */
        val bucket: Int,
        /** What this message is. */
        val kind: Kind,
        /** The end-to-end idempotency key; never relay-visible. */
        val messageId: ByteArray,
        /** Minutes since the Unix epoch at compose, before any HIGH send delay (R-C1). */
        val authorMinute: Long,
        /** Order of the sender's own messages within [authorMinute] (§7.7). */
        val minuteIndex: Int,
        /** This message's own timer code. */
        val timerCode: Int,
        /** The sender's conversation timer version (§10.5). */
        val timerVersion: Long,
        /** The quoted message's id, or null; never copied text. */
        val quoteRef: ByteArray?,
        /** The body, whose rules depend on [kind]. */
        val body: ByteArray,
        /** The `seal_root` the message carried, or null (§6.3). */
        val sealRoot: SealRoot?,
        /** Whether the message carried a `session_reset` (§8.6). */
        val sessionReset: Boolean,
        /** The revocation certificate v2 the message carried, or null (§8.5). */
        val revocation: ByteArray?,
        /** Whether it carried a PQ-C TLV, which Phase 9 counts and ignores (§9.4). */
        val sawPqTlv: Boolean,
    ) {
        /** Never shows the body: it is the message the user wrote (T3). */
        override fun toString(): String = "Decoded(kind=$kind, bodyLen=${body.size})"
    }

    /** A received `seal_root`: the root stays wrapped (§6.3, rule R-S6). */
    class SealRoot(
        /** The generation number, which only increases per contact. */
        val rootGen: Int,
        /** The ISO week the root's first week key belongs to. */
        val baseWeek: Long,
        /** The wrapped root, for [DmPairing.keys]. */
        val rootEnv: ByteArray,
    ) {
        override fun toString(): String = "SealRoot(gen=$rootGen, baseWeek=$baseWeek)"
    }

    /**
     * The API cap of §6.6 and §12.6: content longer than this is `TOO_LARGE` at the facade, and
     * waits for Phase 11 media. It mirrors the crate's `seal::MAX_BODY_BYTES`, which
     * `DmBucketsTest` pins against the source so the two cannot drift.
     */
    const val MAX_BODY_BYTES: Int = 61_440

    /** The outcome of [encode]. */
    sealed interface Encoded {
        /** The canonical L0 bytes and the bucket R-B1 chose from the body length (§6.6). */
        data class Ok(val l0: ByteArray, val bucket: Int) : Encoded

        /** A field is out of range, or the TLV list is not the shape R-C4 admits. */
        data object NonCanonical : Encoded

        /** The content is larger than any bucket carries (R-B1, R-C4). */
        data object Oversize : Encoded

        /** The offer envelope does not open under its binding (§22.8.3). */
        data object StateCorrupt : Encoded

        /** The native library is missing or the context is closed. */
        data object Unavailable : Encoded
    }

    /** The outcome of [decode]. */
    sealed interface DecodeResult {
        /** The L0 parsed exactly (R-C4). */
        data class Ok(val content: Decoded) : DecodeResult

        /**
         * An over-read, a trailing byte, a non-ascending TLV list, an unknown critical TLV,
         * invalid UTF-8 or a non-zero reserved bit: `drop(bad_content)` at `RECV` R8, with the
         * session state still committed because the message key was used.
         */
        data object NonCanonical : DecodeResult

        /** A record no bucket carries: the same `drop(bad_content)` (R-B1). */
        data object Oversize : DecodeResult

        /** The root could not be wrapped for storage (§22.8.3). */
        data object StateCorrupt : DecodeResult

        /** The native library is missing or the context is closed. */
        data object Unavailable : DecodeResult
    }

    /**
     * §2.6 function 18: `l0Encode`.
     *
     * [offerEnv] and [offerRootGen] attach the `seal_root` of §6.3; [revocation] attaches the
     * certificate of §8.5; [sessionReset] attaches the reconnect notice of §8.6. All three are
     * R-C3 TLVs, which ride **only** on a user-initiated or scheduled-user send.
     */
    @Suppress("LongParameterList")
    fun encode(
        handle: Long,
        kind: Kind,
        messageId: ByteArray,
        authorMinute: Long,
        minuteIndex: Int,
        timerCode: Int,
        timerVersion: Long,
        quoteRef: ByteArray?,
        body: ByteArray,
        contactId: ByteArray = DM_NO_CONTACT,
        offerRootGen: Int = 0,
        offerEnv: ByteArray = DM_NO_BYTES,
        revocation: ByteArray = DM_NO_BYTES,
        sessionReset: Boolean = false,
    ): Encoded {
        if (!DmNative.isAvailable()) return Encoded.Unavailable
        val result = dmCall {
            DmNative.l0Encode(
                handle,
                kind.wire,
                messageId,
                Math.toIntExact(authorMinute),
                minuteIndex,
                timerCode,
                Math.toIntExact(timerVersion),
                quoteRef ?: DM_NO_BYTES,
                body,
                contactId,
                offerRootGen,
                offerEnv,
                revocation,
                if (sessionReset) 1 else 0,
            )
        }
        return when (result.code) {
            DmCode.OK -> Encoded.Ok(
                l0 = result.bytes(DmField.L0),
                bucket = result.u32(DmField.BUCKET).toInt(),
            )
            DmCode.NON_CANONICAL -> Encoded.NonCanonical
            DmCode.OVERSIZE -> Encoded.Oversize
            DmCode.STATE_CORRUPT -> Encoded.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Encoded.Unavailable
            else -> unexpected(result.code, "l0Encode")
        }
    }

    /** §2.6 function 18: `l0Decode(h, contactId, l0)`. */
    fun decode(handle: Long, contactId: ByteArray, l0: ByteArray): DecodeResult {
        if (!DmNative.isAvailable()) return DecodeResult.Unavailable
        val result = dmCall { DmNative.l0Decode(handle, contactId, l0) }
        return when (result.code) {
            DmCode.OK -> {
                val flags = result.byte(DmField.TLV_FLAGS)
                val kind = Kind.fromWire(result.byte(DmField.CONTENT_KIND))
                    ?: throw IllegalStateException("DM l0Decode named an unknown kind")
                DecodeResult.Ok(
                    Decoded(
                        bucket = result.u32(DmField.BUCKET).toInt(),
                        kind = kind,
                        messageId = result.bytes(DmField.MESSAGE_ID),
                        authorMinute = result.u32(DmField.AUTHOR_MINUTE),
                        minuteIndex = result.u32(DmField.MINUTE_INDEX).toInt(),
                        timerCode = result.byte(DmField.TIMER_CODE),
                        timerVersion = result.u32(DmField.TIMER_VERSION),
                        quoteRef = result.bytesOrNull(DmField.QUOTE_REF),
                        body = result.bytes(DmField.BODY),
                        sealRoot = if (flags and DM_TLV_SEAL_ROOT != 0) {
                            SealRoot(
                                rootGen = result.u32(DmField.ROOT_GEN).toInt(),
                                baseWeek = result.i64(DmField.BASE_WEEK),
                                rootEnv = result.bytes(DmField.PAIR_ROOT_ENV),
                            )
                        } else {
                            null
                        },
                        sessionReset = flags and DM_TLV_SESSION_RESET != 0,
                        revocation = if (flags and DM_TLV_REVOCATION != 0) {
                            result.bytes(DmField.REVOCATION)
                        } else {
                            null
                        },
                        sawPqTlv = flags and DM_TLV_PQ != 0,
                    ),
                )
            }
            DmCode.NON_CANONICAL -> DecodeResult.NonCanonical
            DmCode.OVERSIZE -> DecodeResult.Oversize
            DmCode.STATE_CORRUPT -> DecodeResult.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> DecodeResult.Unavailable
            else -> unexpected(result.code, "l0Decode")
        }
    }
}
