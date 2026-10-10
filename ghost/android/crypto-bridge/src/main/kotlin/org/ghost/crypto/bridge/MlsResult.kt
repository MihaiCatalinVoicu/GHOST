package org.ghost.crypto.bridge

/**
 * The closed channel result-code list (Phase 10 design §10.2; the bytes are `ghost-client-mls`'s
 * `result.rs`). `MlsResultCodesTest` reads that file and asserts this enumeration agrees with it,
 * name for name and byte for byte, so a code added on one side only fails the build.
 */
enum class MlsCode(val wire: Int) {
    /** The call succeeded. */
    OK(0),

    /** A caught Rust panic, and nothing else; the facade throws on it. */
    INTERNAL(1),

    /** The library is missing, the handle is closed or foreign, or the channel is not open on it. */
    CRYPTO_UNAVAILABLE(2),

    /** A key input of the wrong length or form (the state key, a pseudonym seed). */
    INVALID_KEY(3),

    /** A policy, a context or an argument combination the protocol refuses. */
    INVALID_POLICY(4),

    /** No KeyPackage of this member matches the Welcome (fn 5). */
    NOT_FOR_ME(5),

    /** A Welcome OpenMLS refuses, or one that fails the committers anchor or §5.3 (fn 5). */
    INVALID_WELCOME(6),

    /** A Welcome whose bootstrap does not match (§5.4). */
    INVALID_BOOTSTRAP(7),

    /** A stored row or an envelope that does not open, or a state that does not load. */
    STATE_CORRUPT(8),

    /** A commit that fails validation; the reason is [MlsCommitReason]. */
    INVALID_COMMIT(9),

    /** A message that does not decrypt. */
    UNDECRYPTABLE(10),

    /** A message of another epoch than the call's. */
    WRONG_EPOCH(11),

    /** An application message whose `ChannelOrder` disagrees with its MLS sender (CS-S7). */
    ORDER_MISMATCH(12),

    /** Bytes or arguments that do not decode canonically. */
    NON_CANONICAL(13),

    /** A body larger than its bucket's capacity, or a commit above the class floor (§5.7). */
    NO_FIT(14),

    /** A KeyPackage that is not the canonical one; [MlsReply.index] names it in a request. */
    INVALID_KEYPACKAGE(15),

    /** Admission evidence that does not verify; [MlsReply.index] names it. */
    INVALID_EVIDENCE(16),

    /** `encrypt` while the own pending commit removes a pseudonym; `commit` while one is pending. */
    PENDING_COMMIT(17),

    /** A blob whose hint does not match or whose AEAD refuses. */
    NOT_OPEN(18),

    /** An invite of a suite this version does not run. */
    UNSUPPORTED_SUITE(19),

    /** A password invite parsed without a password (§19.28.4). */
    PASSWORD_REQUIRED(20),

    /** The invite's AEAD refused: a wrong password or a tampered link (§19.28.4). */
    WRONG_PASSWORD(21),

    /** A signature that does not verify. */
    BAD_SIGNATURE(22),

    /** A KeyPackage of the wrong purpose for the request. */
    WRONG_PURPOSE(23),
    ;

    companion object {
        private val byWire: Map<Int, MlsCode> = entries.associateBy(MlsCode::wire)

        /** The code of a wire byte, or `null` for a byte this version does not define. */
        fun fromWire(wire: Int): MlsCode? = byWire[wire and 0xff]
    }
}

/** Why a commit is `INVALID_COMMIT` (§6.4 CO-2; the bytes are `result.rs`'s `CommitReason`). */
enum class MlsCommitReason(val wire: Int) {
    /** A non-canonical KeyPackage lifetime (§19.29.1). */
    LIFETIME(1),

    /** Any other refusal of OpenMLS's processing. */
    REFUSED(2),

    /** The sender is not a member (CO-1). */
    NOT_A_MEMBER(3),

    /** The body exceeds the class floor (§5.7). */
    SIZE(4),

    /** The authenticated data is not a canonical `GhostCommitAad`. */
    AAD(5),

    /** Admission or swap evidence missing or not verifying. */
    EVIDENCE(6),

    /** The update-path leaf's `refresh_epoch` is wrong (§19.5). */
    REFRESH_EPOCH(7),

    /** A non-canonical leaf or KeyPackage, or an invalid HPKE key in the tree. */
    NON_CANONICAL_LEAF(8),

    /** A leaf changes its member's signature key or credential (§19.14). */
    CONTINUITY(9),

    /** An admission or restore changes `committers` (S0-15). */
    COMMITTERS_CHANGED(10),

    /** The resulting context is invalid, or breaks the password policy. */
    CONTEXT(11),

    /** A rank rule of CO-1/CO-2. */
    PERMISSION(12),

    /** A proposal type GHOST never commits. */
    PROPOSAL(13),

    /** CO-14: a rank-255 self-update too soon after the last one. */
    RATE(14),
    ;

    companion object {
        private val byWire: Map<Int, MlsCommitReason> = entries.associateBy(MlsCommitReason::wire)

        /** The reason of a wire byte, or `null`. */
        fun fromWire(wire: Int): MlsCommitReason? = byWire[wire and 0xff]
    }
}

/**
 * The field tags of the channel wire (Phase 10 design §10.2: "`code(1) ‖ TLV fields`"; the bytes are
 * `ghost-client-mls`'s `jni.rs` `Field`). A field is `tag(1) || len(u32 big-endian) || value`;
 * a [record] field's value is itself a field list; only a [repeatable] tag may occur more than
 * once in one list (a list is its tag repeated, in order). `MlsResultCodesTest` compares the tags,
 * the repeatable set and the record set with the Rust file.
 */
enum class MlsField(val tag: Int, val repeatable: Boolean = false, val record: Boolean = false) {
    HANDLE(0x01),
    PSEUDONYM(0x02),
    CHANGE(0x03, repeatable = true, record = true),
    ROW(0x04, repeatable = true, record = true),
    SCOPE(0x05),
    KEY(0x06),
    ENV(0x07),
    EPOCH(0x08),
    K_ENV(0x09),
    R_EP(0x0a),
    EPOCH_AUTHENTICATOR(0x0b),
    GENERATION(0x0c),
    OPEN_EPOCH(0x0d),
    G_ENV(0x0e),
    NS(0x0f),
    JK_ENV(0x10),
    R_JOIN(0x11),
    SLOT(0x12, repeatable = true, record = true),
    SLOT_INDEX(0x13),
    READ_CREDENTIAL(0x14),
    READ_VERIFIER(0x15),
    DEPOSIT_CREDENTIAL(0x16),
    DEPOSIT_VERIFIER(0x17),
    BOX_PK(0x18),
    BOX_ENV(0x19),
    KEY_PACKAGE(0x1a),
    KP_REF(0x1b),
    CONTEXT(0x1c, record = true),
    CHANNEL_ID(0x1d),
    SIZE_CLASS(0x1e),
    TIMER_CODE(0x1f),
    TIMER_VERSION(0x20),
    HISTORY_POLICY(0x21),
    FLAGS(0x22),
    IDLE_EVICT_DAYS(0x23),
    PW_VERSION(0x24),
    NAME(0x25),
    COMMITTER(0x26, repeatable = true),
    FUNDER(0x27, repeatable = true),
    MEMBER(0x28, repeatable = true, record = true),
    LEAF(0x29),
    REFRESH_EPOCH(0x2a),
    TREE_HASH(0x2b),
    MESSAGE(0x2c, repeatable = true),
    ITEM(0x2d, repeatable = true, record = true),
    ITEM_KIND(0x2e),
    CONTENT(0x2f, record = true),
    SENDER(0x30),
    SEQ(0x31),
    SUMMARY(0x32, record = true),
    ERROR_CODE(0x33),
    REASON(0x34),
    INDEX(0x35),
    HASH(0x36),
    SIZE(0x37),
    RANK(0x38),
    AAD(0x39, record = true),
    COMMIT_MINUTE(0x3a),
    ROTATE(0x3b),
    EVIDENCE(0x3c, repeatable = true, record = true),
    SWAP_EVIDENCE(0x3d, repeatable = true, record = true),
    ADD(0x3e, repeatable = true, record = true),
    REMOVE(0x3f, repeatable = true, record = true),
    SWAP(0x40, repeatable = true, record = true),
    KP_BIND(0x41, record = true),
    PURPOSE(0x42),
    DAY(0x43),
    CONSTANT_LIFETIME(0x44),
    CANONICAL(0x45),
    SWAP_KIND(0x46),
    ROTATES(0x47),
    UPDATE_LEAF(0x48, record = true),
    SIGNATURE_KEY(0x49),
    SENDER_REFRESH_EPOCH(0x4a),
    MEMBER_COUNT(0x4b),
    VERDICT(0x4c),
    INVITE_ID(0x4d),
    INVITE_PK(0x4e),
    EXPIRY_DAY(0x4f),
    SPONSOR(0x50),
    SPONSOR_SIG(0x51),
    INVITE_SIG(0x52),
    LAST_EPOCH(0x53),
    LAST_HASH(0x54),
    REJOIN_SIG(0x55),
    MLS(0x56),
    WELCOME(0x57, repeatable = true),
    JOINER(0x58, repeatable = true),
    KEPT_ADD(0x59, repeatable = true),
    KEPT_SWAP(0x5a, repeatable = true),
    KEPT_REMOVE(0x5b, repeatable = true),
    CONTEXT_KEPT(0x5c),
    FLOOR(0x5d),
    STANDING(0x5e),
    ADDED(0x5f, repeatable = true),
    REMOVED(0x60, repeatable = true),
    SENDER_LEAF(0x61),
    BLOB(0x62),
    ORDER_EPOCH(0x63),
    ORDER_LEAF(0x64),
    ORDER_SEQ(0x65),
    BODY(0x66),
    HEADER_EPOCH(0x67),
    CONTENT_TYPE(0x68),
    AAD_LEAF(0x69),
    AAD_SEQ(0x6a),
    INVITE(0x6b),
    KDF_CODE(0x6c),
    SUITE(0x6d),
    HANDSHAKE_TTL_CODE(0x6e),
    COMMITTERS_DIGEST(0x6f),
    INVITE_SEED_ENV(0x70),
    REQUEST_TYPE(0x71),
    KIND(0x72),
    OP_ID(0x73),
    AUTHOR_MINUTE(0x74),
    TEXT(0x75),
    REPLY_TO(0x76),
    TARGET(0x77),
    GRAPHEME(0x78),
    HPKE_ENC(0x79),
    CIPHERTEXT(0x7a),
    HELD(0x7b, repeatable = true, record = true),
    CANDIDATE(0x7c),
    TRIAL_SENDER(0x7d, repeatable = true),
    ENCODED(0x7e),
    CARD(0x7f),
    ;

    companion object {
        private val byTag: Map<Int, MlsField> = entries.associateBy(MlsField::tag)

        /** The field of a wire tag, or `null` for a tag this version does not define. */
        fun fromTag(tag: Int): MlsField? = byTag[tag and 0xff]
    }
}

/**
 * One decoded field list: the fields in wire order, every record among them already decoded and
 * checked. Accessors throw `IllegalStateException` for a missing field or a value of the wrong
 * width: the only producer is GHOST's own native code, so either means the two sides disagree.
 *
 * **One copy of each value.** A record field keeps its decoded record only, never its raw bytes
 * too (review of S2b: a received post's text was held three times — in its `ITEM`'s bytes, its
 * `CONTENT`'s bytes and its `TEXT` —, so erasing the one the caller owns left two). A value's
 * array is the one the accessor returns, so its owner's erasure reaches the only copy.
 */
class MlsRecord internal constructor(
    private val fields: List<Pair<MlsField, ByteArray>>,
    private val records: Map<Int, MlsRecord>,
) {
    /** Whether the list carries [field]. */
    fun has(field: MlsField): Boolean = fields.any { it.first == field }

    /** The raw bytes of a field, or `null`; a record field is read with [record]. */
    fun bytesOrNull(field: MlsField): ByteArray? {
        check(!field.record) { "${field.name} is a record: read it with record()" }
        return fields.firstOrNull { it.first == field }?.second
    }

    /** The raw bytes of a field; a missing field is a surface disagreement. */
    fun bytes(field: MlsField): ByteArray =
        bytesOrNull(field) ?: throw IllegalStateException("channel reply is missing ${field.name}")

    /** Every value of a repeatable field, in order; a record field is read with [records]. */
    fun all(field: MlsField): List<ByteArray> {
        check(!field.record) { "${field.name} is a record: read it with records()" }
        return fields.filter { it.first == field }.map { it.second }
    }

    /** Every array this list and its records hold, depth first: what an owner must erase. */
    internal fun values(): List<ByteArray> = fields.indices.flatMap { i ->
        listOf(fields[i].second) + (records[i]?.values() ?: emptyList())
    }

    /** A one-byte field as an unsigned int. */
    fun byte(field: MlsField): Int = sized(field, 1)[0].toInt() and 0xff

    /** A one-byte flag (0 or 1). */
    fun flag(field: MlsField): Boolean = when (byte(field)) {
        0 -> false
        1 -> true
        else -> throw IllegalStateException("${field.name} is not a flag")
    }

    /** A `u16` big-endian field. */
    fun u16(field: MlsField): Int = unsigned(sized(field, 2)).toInt()

    /** A `u32` big-endian field. */
    fun u32(field: MlsField): Long = unsigned(sized(field, 4))

    /** A `u64`/`i64` big-endian field (epochs fit a `Long`). */
    fun i64(field: MlsField): Long = unsigned(sized(field, 8))

    /** An optional `u32`. */
    fun u32OrNull(field: MlsField): Long? = if (has(field)) u32(field) else null

    /** An optional `u64`. */
    fun i64OrNull(field: MlsField): Long? = if (has(field)) i64(field) else null

    /** An optional `u16`. */
    fun u16OrNull(field: MlsField): Int? = if (has(field)) u16(field) else null

    /** Every value of a repeatable `u32` field. */
    fun allU32(field: MlsField): List<Long> = all(field).map {
        if (it.size != 4) throw IllegalStateException("${field.name} is not four bytes")
        unsigned(it)
    }

    /** The record a [MlsField.record] field carries. */
    fun record(field: MlsField): MlsRecord =
        recordOrNull(field) ?: throw IllegalStateException("channel reply is missing ${field.name}")

    /** The record of an optional record field, or `null`. */
    fun recordOrNull(field: MlsField): MlsRecord? {
        val index = fields.indexOfFirst { it.first == field }
        return if (index < 0) null else records[index]
    }

    /** Every record of a repeatable record field, in order. */
    fun records(field: MlsField): List<MlsRecord> =
        fields.indices.filter { fields[it].first == field }.map { records.getValue(it) }

    private fun sized(field: MlsField, width: Int): ByteArray = bytes(field).also {
        if (it.size != width) throw IllegalStateException("${field.name} is not $width bytes")
    }

    private fun unsigned(bytes: ByteArray): Long {
        var value = 0L
        for (b in bytes) value = (value shl 8) or (b.toLong() and 0xff)
        return value
    }

    internal companion object {
        /** A strict decode, or `null`: unknown tag, repeated scalar, overrun, malformed record. */
        fun parse(bytes: ByteArray, from: Int, until: Int): MlsRecord? {
            val fields = ArrayList<Pair<MlsField, ByteArray>>()
            val records = HashMap<Int, MlsRecord>()
            var offset = from
            while (offset < until) {
                if (offset + 5 > until) return null
                val field = MlsField.fromTag(bytes[offset].toInt()) ?: return null
                var length = 0L
                for (i in 1..4) length = (length shl 8) or (bytes[offset + i].toLong() and 0xff)
                offset += 5
                if (offset + length > until) return null
                val end = offset + length.toInt()
                if (!field.repeatable && fields.any { it.first == field }) return null
                if (field.record) {
                    records[fields.size] = parse(bytes, offset, end) ?: return null
                    fields.add(field to NO_VALUE)
                } else {
                    fields.add(field to bytes.copyOfRange(offset, end))
                }
                offset = end
            }
            return MlsRecord(fields, records)
        }

        /** An empty list. */
        val EMPTY: MlsRecord = MlsRecord(emptyList(), emptyMap())

        /** What a record field holds beside its decoded record: nothing (one copy of each value). */
        private val NO_VALUE = ByteArray(0)
    }
}

/**
 * A decoded reply of [MlsNative]: the code, an `INVALID_COMMIT` [reason] or an `INVALID_KEYPACKAGE`
 * / `INVALID_EVIDENCE` [index] when the native side named one, and the fields of a success.
 *
 * Decoding is strict — a truncated reply, an overrun, an unknown tag, a repeated scalar, a
 * malformed record — and its failure is [MlsCode.STATE_CORRUPT]: the only producer of these bytes is
 * GHOST's own native code. A `null` or empty reply is [MlsCode.INTERNAL]; the native side never
 * returns one. A reply the JVM cannot allocate is not a code: the call **throws** the JVM's
 * `OutOfMemoryError`, which the facade does not catch (measured by the review of S2b at `-Xmx48m`).
 */
class MlsReply private constructor(
    /** The result code. */
    val code: MlsCode,
    /** The reason of an `INVALID_COMMIT`, when the reply names one. */
    val reason: MlsCommitReason?,
    /** The index of an `INVALID_KEYPACKAGE` or `INVALID_EVIDENCE`, when the reply names one. */
    val index: Int?,
    /** The fields of the reply (empty on an error). */
    val fields: MlsRecord,
) {
    /** Whether the call succeeded. */
    val isOk: Boolean get() = code == MlsCode.OK

    companion object {
        /**
         * Decodes `code(1) || fields`. [reply] is **erased** once its fields are copied out (the
         * Phase 9 review's A-1 rule): it can hold a post's plaintext, bearer credentials and
         * recognition keys, whose decoded copies have owners and the native array has none.
         */
        fun decode(reply: ByteArray?): MlsReply {
            if (reply == null || reply.isEmpty()) return MlsReply(MlsCode.INTERNAL, null, null, MlsRecord.EMPTY)
            try {
                val code = MlsCode.fromWire(reply[0].toInt()) ?: return corrupt()
                val fields = MlsRecord.parse(reply, 1, reply.size) ?: return corrupt()
                if (code == MlsCode.OK) return MlsReply(code, null, null, fields)
                val reason = fields.bytesOrNull(MlsField.REASON)?.let {
                    if (it.size != 1) return corrupt()
                    MlsCommitReason.fromWire(it[0].toInt()) ?: return corrupt()
                }
                val index = fields.bytesOrNull(MlsField.INDEX)?.let {
                    if (it.size != 2) return corrupt()
                    ((it[0].toInt() and 0xff) shl 8) or (it[1].toInt() and 0xff)
                }
                return MlsReply(code, reason, index, MlsRecord.EMPTY)
            } finally {
                reply.fill(0)
            }
        }

        /** A reply that never reached the native side: the library is not loadable. */
        fun unavailable(): MlsReply = MlsReply(MlsCode.CRYPTO_UNAVAILABLE, null, null, MlsRecord.EMPTY)

        private fun corrupt(): MlsReply = MlsReply(MlsCode.STATE_CORRUPT, null, null, MlsRecord.EMPTY)
    }
}

/**
 * A field list under construction, for the arguments that carry lists or records (`rows`, a batch
 * of messages, a policy, a commit request, a content). The buffer grows by hand and erases the
 * array it outgrew, and [consume] hands a native call its copy and erases both afterwards: a content
 * argument is a post's plaintext.
 */
class MlsTlv {
    private var buffer = ByteArray(64)
    private var size = 0

    /** Appends one field. */
    fun put(field: MlsField, value: ByteArray): MlsTlv {
        ensure(5 + value.size)
        buffer[size] = field.tag.toByte()
        for (i in 0 until 4) buffer[size + 1 + i] = (value.size ushr (24 - 8 * i)).toByte()
        System.arraycopy(value, 0, buffer, size + 5, value.size)
        size += 5 + value.size
        return this
    }

    /** One byte. */
    fun u8(field: MlsField, value: Int): MlsTlv = put(field, byteArrayOf(value.toByte()))

    /** A flag (0 or 1). */
    fun flag(field: MlsField, value: Boolean): MlsTlv = u8(field, if (value) 1 else 0)

    /** A `u16` big-endian. */
    fun u16(field: MlsField, value: Int): MlsTlv =
        put(field, byteArrayOf((value ushr 8).toByte(), value.toByte()))

    /** A `u32` big-endian. */
    fun u32(field: MlsField, value: Long): MlsTlv = put(field, bigEndian(value, 4))

    /** A `u64` big-endian. */
    fun u64(field: MlsField, value: Long): MlsTlv = put(field, bigEndian(value, 8))

    /** A record: [record]'s list as the value of [field]; [record] is erased afterwards. */
    fun record(field: MlsField, record: MlsTlv): MlsTlv {
        val bytes = record.toByteArray()
        try {
            put(field, bytes)
        } finally {
            bytes.fill(0)
            record.erase()
        }
        return this
    }

    /** A copy of the list; the caller erases it (see [consume]). */
    fun toByteArray(): ByteArray = buffer.copyOf(size)

    /** Erases the buffer. */
    fun erase() {
        buffer.fill(0)
        size = 0
    }

    /**
     * Runs [call] with a copy of the list — the array a native call reads — and erases the copy and
     * the list afterwards, however [call] ends (review of S2b: the facade handed its calls
     * `toByteArray()` and erased only the list, so every `contentEncode` left its plaintext in the
     * copy).
     */
    inline fun <T> consume(call: (ByteArray) -> T): T {
        val bytes = toByteArray()
        try {
            return call(bytes)
        } finally {
            bytes.fill(0)
            erase()
        }
    }

    private fun ensure(more: Int) {
        if (size + more <= buffer.size) return
        val grown = ByteArray(maxOf(size + more, buffer.size * 2))
        System.arraycopy(buffer, 0, grown, 0, size)
        buffer.fill(0)
        buffer = grown
    }

    private fun bigEndian(value: Long, width: Int): ByteArray =
        ByteArray(width) { i -> (value ushr (8 * (width - 1 - i))).toByte() }
}
