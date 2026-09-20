package org.ghost.crypto.bridge

/**
 * The closed DM result-code list of Phase 9 design §2.6, amended by §22.8.2 and §22.8.3.
 *
 * The wire bytes are the ones `ghost-client-dm`'s `result.rs` fixes; `DmResultCodesTest` asserts
 * that this enumeration and that one agree, byte for byte and name for name. The list is closed:
 * adding a code later would change the JNI surface, so every code the whole surface can ever
 * produce is here, including the ones only functions that arrive in S6, S7 and S13 return.
 */
enum class DmCode(val wire: Int) {
    /** The call succeeded. */
    OK(0x00),

    /** The native library is missing, or the context handle is closed or foreign (§2.5). */
    CRYPTO_UNAVAILABLE(0x01),

    /** A contact card that does not parse, verify or carry a supported version (§3.3). */
    INVALID_CARD(0x02),

    /** A seal, an inner layer or a KEM ciphertext that does not open (§22.8.2 rule 4). */
    NOT_OPEN(0x03),

    /** An Ed25519 signature that does not verify under the expected key (§3.4). */
    BAD_SIGNATURE(0x04),

    /** A blob or an L0 that opens but does not parse exactly (R-S2, R-C4). */
    NON_CANONICAL(0x05),

    /** A malformed or non-contributory public key (§22.8.2 rules 1, 3 and 4). */
    INVALID_KEY(0x06),

    /** Content that no bucket can carry, or a session state past `SESSION_STATE_MAX`. */
    OVERSIZE(0x07),

    /** A sealed blob that does not fit its bucket: a GHOST bug, never a peer's doing (R-B1). */
    NO_FIT(0x08),

    /** Stored state that does not open under its binding or does not parse (§22.8.3). */
    STATE_CORRUPT(0x09),

    /** Any library encryption error (§22.8.2 rule 2). */
    INVALID_SESSION(0x0a),

    /** A PreKey message naming a fallback key the generation does not hold (§2.2). */
    MISSING_KEY(0x0b),

    /** A PreKey message whose identity is not the pinned one (§8.2 rule 3). */
    IDENTITY_MISMATCH(0x0c),

    /** A MAC, padding or format failure inside the session layer. */
    UNDECRYPTABLE(0x0d),

    /** The message key is gone: used, evicted or never stored (D2a). */
    DUPLICATE_OR_LOST(0x0e),

    /** A forward gap beyond Olm's 2 000 (§7.7). */
    GAP_TOO_BIG(0x0f),

    /** `chainPosition`: the receiver chains are readable and none matches. A value, not an error. */
    NEW_CHAIN(0x10),

    /** A caught Rust panic, and nothing else (§2.6). */
    INTERNAL(0xff),
    ;

    companion object {
        private val byWire: Map<Int, DmCode> = entries.associateBy(DmCode::wire)

        /** The code of a wire byte, or `null` for a byte this version does not define. */
        fun fromWire(wire: Int): DmCode? = byWire[wire and 0xff]
    }
}

/**
 * The TLV field tags of a reply (§2.6: "outputs are one byte array `code(1) || TLV fields`").
 *
 * A field is `tag(1) || len(u32 big-endian) || value`. Unknown tags are a decode failure, not a
 * skip: the surface is closed, so a tag this version does not know means the native library and
 * this class disagree, which is [DmCode.STATE_CORRUPT] territory rather than something to ignore.
 */
enum class DmField(val tag: Int) {
    /** `ctxOpen`: the context handle, `i64` big-endian. */
    HANDLE(0x01),

    /** A wrapped `olm_session.state_env`. */
    STATE(0x02),

    /** A raw 32-byte session id. */
    SESSION_ID(0x03),

    /** Olm message bytes. */
    L1(0x04),

    /** L0 content bytes. */
    L0(0x05),

    /** Bit 0: the output is a PreKey message. Bit 1: the session is acknowledged. */
    FLAGS(0x06),

    /** Which stored slot decrypted: 0 = current, 1 = previous. */
    SLOT_USED(0x07),

    /** A wrapped `reply_seed` (`olm_session.prov_env`). */
    REPLY_SEED(0x08),

    /** A receiver chain's next index, `u64` big-endian. */
    CHAIN_INDEX(0x09),

    /** How many skipped keys `sessionPrune` removed, `u32` big-endian. */
    PRUNED(0x0a),

    /** The 60 safety-number digits, ASCII. */
    DIGITS(0x0b),

    /** The 65-byte scannable safety number. */
    SCANNABLE(0x0c),

    /** The own contact card v2, 131 bytes. */
    CARD(0x0d),

    /** The inbox namespace `X_i`. */
    INBOX_NAMESPACE(0x0e),

    /** The bundle namespace `P_i`. */
    BUNDLE_NAMESPACE(0x0f),

    /** The recognition key of `KIO_i` (§6.2 rule R-S6). */
    RECOGNITION_INTRO(0x10),

    /** The recognition key of `KB_i`. */
    RECOGNITION_BUNDLE(0x11),

    /** The own Olm identity public key. */
    OLM_IDENTITY(0x12),

    /** A sealed blob of a bucket size (here: the 4 KiB bundle). */
    BLOB(0x13),

    /** A generation's Olm fallback public key `F_g`. */
    FALLBACK_PUBLIC(0x14),

    /** A generation's X-Wing public key `Q_g`. */
    XWING_PUBLIC(0x15),

    /** A wrapped `olm_prekey_gen.secrets_env`. */
    GENERATION_SECRETS(0x16),

    /** The inbox read secret `RX_{i,s}`: a bearer secret that goes into a credential v3 (§4.3). */
    READ_SECRET(0x17),

    /** `t_pub(w) − start(w)` in seconds, `u32` big-endian: the weekly publication offset (§5.4). */
    PUBLICATION_OFFSET(0x18),

    /** The own deposit secret `D_{i,s}` (§3.2). */
    DEPOSIT_SECRET(0x19),

    /** The own bundle fetch secret `RP_{i,s}` (§3.2), registered as kind FETCH (§22.8.7). */
    FETCH_SECRET(0x1a),
    ;

    companion object {
        private val byTag: Map<Int, DmField> = entries.associateBy(DmField::tag)

        /** The field of a wire tag, or `null` for a tag this version does not define. */
        fun fromTag(tag: Int): DmField? = byTag[tag and 0xff]
    }
}

/** Bit 0 of [DmField.FLAGS]. */
const val DM_FLAG_PRE_KEY: Int = 0x01

/** Bit 1 of [DmField.FLAGS]. */
const val DM_FLAG_ACKNOWLEDGED: Int = 0x02

/**
 * A decoded reply of [DmNative]: a code and the fields that came with it.
 *
 * Decoding is strict — a truncated reply, a length that overruns the array, an unknown tag or a
 * repeated tag is [DmCode.STATE_CORRUPT] — because the only producer of these bytes is GHOST's own
 * native code: anything else means the two sides disagree about the surface.
 */
class DmResult private constructor(
    /** The result code. */
    val code: DmCode,
    private val fields: Map<DmField, ByteArray>,
) {

    /** Whether the call succeeded. */
    val isOk: Boolean get() = code == DmCode.OK

    /** The raw bytes of a field, or `null` when the reply did not carry it. */
    fun bytesOrNull(field: DmField): ByteArray? = fields[field]

    /** The raw bytes of a field; a missing field is a surface disagreement. */
    fun bytes(field: DmField): ByteArray =
        fields[field] ?: throw IllegalStateException("DM reply is missing ${field.name}")

    /** A one-byte field as an unsigned int. */
    fun byte(field: DmField): Int = bytes(field).let {
        if (it.size != 1) throw IllegalStateException("${field.name} is not one byte")
        it[0].toInt() and 0xff
    }

    /** A `u32` big-endian field. */
    fun u32(field: DmField): Long = bytes(field).let {
        if (it.size != 4) throw IllegalStateException("${field.name} is not four bytes")
        var value = 0L
        for (b in it) value = (value shl 8) or (b.toLong() and 0xff)
        value
    }

    /** A `u64`/`i64` big-endian field. */
    fun i64(field: DmField): Long = bytes(field).let {
        if (it.size != 8) throw IllegalStateException("${field.name} is not eight bytes")
        var value = 0L
        for (b in it) value = (value shl 8) or (b.toLong() and 0xff)
        value
    }

    /** An ASCII field as a string. */
    fun text(field: DmField): String = String(bytes(field), Charsets.US_ASCII)

    companion object {
        /**
         * Decodes `code(1) || (tag(1) || len(u32 big-endian) || value)*`.
         *
         * A `null` array — the native side could not allocate the reply — and any malformed reply
         * decode to a code, never to an exception, so the caller's `when` stays exhaustive.
         */
        fun decode(reply: ByteArray?): DmResult {
            if (reply == null || reply.isEmpty()) {
                return DmResult(DmCode.INTERNAL, emptyMap())
            }
            val code = DmCode.fromWire(reply[0].toInt())
                ?: return DmResult(DmCode.STATE_CORRUPT, emptyMap())
            val fields = LinkedHashMap<DmField, ByteArray>()
            var offset = 1
            while (offset < reply.size) {
                if (offset + 5 > reply.size) return DmResult(DmCode.STATE_CORRUPT, emptyMap())
                val field = DmField.fromTag(reply[offset].toInt())
                    ?: return DmResult(DmCode.STATE_CORRUPT, emptyMap())
                var length = 0L
                for (i in 1..4) {
                    length = (length shl 8) or (reply[offset + i].toLong() and 0xff)
                }
                offset += 5
                if (length < 0 || offset + length > reply.size) {
                    return DmResult(DmCode.STATE_CORRUPT, emptyMap())
                }
                val end = offset + length.toInt()
                if (fields.put(field, reply.copyOfRange(offset, end)) != null) {
                    return DmResult(DmCode.STATE_CORRUPT, emptyMap())
                }
                offset = end
            }
            return DmResult(code, fields)
        }

        /** A reply that never reached the native side, because the library is not loadable. */
        fun unavailable(): DmResult = DmResult(DmCode.CRYPTO_UNAVAILABLE, emptyMap())
    }
}
