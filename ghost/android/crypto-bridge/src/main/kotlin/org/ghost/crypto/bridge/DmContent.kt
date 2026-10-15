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
 * The TLVs R-C3 allows on a user-initiated send are the only ones [encode] writes.
 *
 * **Slice S13 (PQ-C, §9.4).** [encode] takes a `seal_root_pq` (as the same wrapped `offer_env`,
 * 1 194 bytes instead of 70) and a `pq_key` ([PqKeyCandidate]) as **candidates** that the crate
 * attaches only under the slack rule R-C5, and [Encoded.Ok] says which rode; [decode] returns a
 * received `seal_root_pq` ([Decoded.sealRootPq], opened by [DmPairing.pqOpen]) and `pq_key`
 * ([Decoded.pqKey], already validated whole).
 */
object DmContent {

    /**
     * The largest `timer_version` the codec encodes or accepts (§10.5, R-T9), mirroring
     * `codec::MAX_TIMER_VERSION`.
     *
     * The field is a `u32` on the wire and R-T9 only says it never decreases, so nothing bounded
     * it until the S9 review: a peer that sent `0xFFFF_FFFF` on one ordinary L0 was adopted, and
     * the next send of any kind re-encoded the stored version through [Math.toIntExact] and threw
     * out of the facade — that conversation could never send again. The bound leaves room for the
     * `version + 1` a local `TIMER_SET` writes on top of it.
     */
    const val MAX_TIMER_VERSION: Long = Int.MAX_VALUE - 1L

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

        /** A media descriptor (Phase 11 design §4.1): the object id, the zero key slot and the
         * manifest hash, with the caption as the body. The key slot is filled inside `encrypt`. */
        MEDIA(0x05),
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
        /** The `seal_root_pq` the message carried, or null (§9.4, slice S13). */
        val sealRootPq: SealRootPq?,
        /** The `pq_key` the message carried, validated whole, or null (§9.4, §22.8.2 rule 3). */
        val pqKey: PqKey?,
        /** A `seal_root_pq` beside a classical `seal_root`: ignored, the classical one applies. */
        val pqIgnored: Boolean,
        /** A `pq_key` whose X-Wing key fails validation: ignored and counted (§22.8.2 rule 3). */
        val pqKeyInvalid: Boolean,
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
     * A received `seal_root_pq` (§9.4): its root exists only once [DmPairing.pqOpen] decapsulated
     * [tlv] with this device's generation [peerGenId]; `root_rand` alone keys nothing.
     */
    class SealRootPq(
        /** The generation number, which only increases per contact. */
        val rootGen: Int,
        /** The ISO week the root's first week key belongs to. */
        val baseWeek: Long,
        /** The generation of **this device** the root was encapsulated to (a `u32`). */
        val peerGenId: Long,
        /** The 1 166-byte TLV value, for [DmPairing.pqOpen]. */
        val tlv: ByteArray,
    ) {
        override fun toString(): String = "SealRootPq(gen=$rootGen, baseWeek=$baseWeek)"
    }

    /** A received `pq_key` (§9.4): the peer's generation and its X-Wing key, valid whole. */
    class PqKey(
        /** The peer's generation id (a `u32`). */
        val genId: Long,
        /** The ISO week of that generation's bundle: the key is usable until `start(week + 5)`. */
        val bundleWeek: Long,
        /** The 1 216-byte X-Wing encapsulation key. */
        val xwingPublic: ByteArray,
    ) {
        override fun toString(): String = "PqKey(week=$bundleWeek)"
    }

    /**
     * This device's generation to announce in a `pq_key` (§9.4): the row of `olm_prekey_gen` whose
     * X-Wing public key the crate recomputes from the wrapped seed.
     */
    class PqKeyCandidate(
        /** `olm_prekey_gen.gen_id` (a `u32`). */
        val genId: Long,
        /** `olm_prekey_gen.bundle_week`. */
        val bundleWeek: Long,
        /** `olm_prekey_gen.secrets_env`. */
        val secretsEnv: ByteArray,
        /** `olm_prekey_gen.fallback_pub`: half of `secrets_env`'s wrap binding (§22.8.3). */
        val fallbackPublic: ByteArray,
    ) {
        override fun toString(): String = "PqKeyCandidate(week=$bundleWeek)"
    }

    /**
     * The API cap of §6.6 and §12.6: content longer than this is `TOO_LARGE` at the facade, and
     * waits for Phase 11 media. It mirrors the crate's `seal::MAX_BODY_BYTES`, which
     * `DmBucketsTest` pins against the source so the two cannot drift.
     */
    const val MAX_BODY_BYTES: Int = 61_440

    /** The outcome of [encode]. */
    sealed interface Encoded {
        /**
         * The canonical L0 bytes and the bucket R-B1 chose from the body length (§6.6), and which
         * of the root and key TLVs **rode** (slice S13): a PQ-C candidate that did not fit the
         * slack of that bucket (R-C5) is not in [l0], and the caller must not record it as sent.
         */
        data class Ok(
            val l0: ByteArray,
            val bucket: Int,
            /** A classical `seal_root` is in [l0]. */
            val sealRootRode: Boolean = false,
            /** A `seal_root_pq` is in [l0]. */
            val sealRootPqRode: Boolean = false,
            /** A `pq_key` is in [l0]. */
            val pqKeyRode: Boolean = false,
            /**
             * The `pq_key` candidate could not be built from its stored generation (a row whose
             * secrets do not unwrap) and was left out; [l0] is the message without it (slice S13
             * review — before it, the whole encode failed and so did every such send).
             */
            val pqKeyDropped: Boolean = false,
        ) : Encoded

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
     * [offerEnv] and [offerRootGen] attach the root offer of §6.3 — a `seal_root`, or, when the
     * envelope holds the PQ-C form, a `seal_root_pq` under the slack rule; [revocation] attaches
     * the certificate of §8.5; [sessionReset] attaches the reconnect notice of §8.6; [pqKey]
     * offers this device's generation key as a `pq_key` under the slack rule (slice S13). [pqKeyFirst]
     * puts the announcement ahead of the offer in R-C5's priority order: SEND sets it when the
     * offer is a re-attachment of one that already rode. All of
     * them are R-C3 TLVs, which ride **only** on a user-initiated or scheduled-user send.
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
        pqKey: PqKeyCandidate? = null,
        pqKeyFirst: Boolean = false,
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
                pqKey?.genId?.toInt() ?: 0,
                pqKey?.bundleWeek ?: 0L,
                pqKey?.secretsEnv ?: DM_NO_BYTES,
                pqKey?.fallbackPublic ?: DM_NO_BYTES,
                if (pqKeyFirst) 1 else 0,
            )
        }
        return when (result.code) {
            DmCode.OK -> {
                val flags = result.byte(DmField.TLV_FLAGS)
                Encoded.Ok(
                    l0 = result.bytes(DmField.L0),
                    bucket = result.u32(DmField.BUCKET).toInt(),
                    sealRootRode = flags and DM_TLV_SEAL_ROOT != 0,
                    sealRootPqRode = flags and DM_TLV_SEAL_ROOT_PQ != 0,
                    pqKeyRode = flags and DM_TLV_PQ_KEY != 0,
                    pqKeyDropped = flags and DM_TLV_PQ_KEY_DROPPED != 0,
                )
            }
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
                        sealRootPq = if (flags and DM_TLV_SEAL_ROOT_PQ != 0) {
                            SealRootPq(
                                rootGen = result.u32(DmField.ROOT_GEN).toInt(),
                                baseWeek = result.i64(DmField.BASE_WEEK),
                                peerGenId = result.u32(DmField.PEER_GEN_ID),
                                tlv = result.bytes(DmField.SEAL_ROOT_PQ_TLV),
                            )
                        } else {
                            null
                        },
                        pqKey = if (flags and DM_TLV_PQ_KEY != 0) {
                            PqKey(
                                genId = result.u32(DmField.GEN_ID),
                                bundleWeek = result.i64(DmField.BUNDLE_WEEK),
                                xwingPublic = result.bytes(DmField.XWING_PUBLIC),
                            )
                        } else {
                            null
                        },
                        pqIgnored = flags and DM_TLV_PQ != 0,
                        pqKeyInvalid = flags and DM_TLV_PQ_KEY_INVALID != 0,
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
