package org.ghost.crypto.bridge

/**
 * The closed media result-code list of Phase 11 design §13.2 (slice S2).
 *
 * The wire bytes are the ones `ghost-client-dm`'s `jni_media.rs` fixes; `MediaResultCodesTest`
 * asserts that this enumeration and that one agree, byte for byte and name for name. The list is
 * closed: adding a code later would change the JNI surface, so every code the whole media surface
 * can ever produce is here. `DmCode` and `MediaCode` are separate lists: no wire byte means the
 * same thing on the two surfaces.
 */
enum class MediaCode(val wire: Int) {
    /** The call succeeded. */
    OK(0x00),

    /** The native library is missing, or the context handle is closed or foreign. */
    CRYPTO_UNAVAILABLE(0x01),

    /** Bytes that do not parse exactly, break a canonical-format rule, or disagree with the descriptor or the walked stream. */
    NON_CANONICAL(0x02),

    /** A chunk or manifest whose ChaCha20-Poly1305 tag does not verify. */
    NOT_OPEN(0x03),

    /** A manifest whose commitment is not the one the key derives. */
    COMMIT_MISMATCH(0x04),

    /** A fragment or manifest that is not the blob its hash names. */
    HASH_MISMATCH(0x05),

    /** A chunk index outside the object. */
    INDEX_RANGE(0x06),

    /** A second seal of one chunk index: a GHOST bug, never a peer's doing. */
    INDEX_REUSED(0x07),

    /** Content above the caps, or an out buffer that cannot hold what the call returns. */
    OVERSIZE(0x08),

    /** A source outside the allowlist (`sniff`, §6.1). */
    UNSUPPORTED(0x09),

    /** A call the sealer or reader state machine does not allow at this point, or a read on an object the database does not hold readable. */
    SEQUENCE(0x0a),

    /** A registry cap: two live sealers, eight live readers. */
    LIMIT(0x0b),

    /** Stored state that does not open under its binding: a `key_env` of `readerOpen` (§4.2). */
    STATE_CORRUPT(0x0c),

    /** A caught Rust panic, and nothing else. */
    INTERNAL(0xff),
    ;

    companion object {
        private val byWire: Map<Int, MediaCode> = entries.associateBy(MediaCode::wire)

        /** The code of a wire byte, or `null` for a byte this version does not define. */
        fun fromWire(wire: Int): MediaCode? = byWire[wire and 0xff]
    }
}

/**
 * The TLV field tags of a `MediaNative` reply (Phase 11 design §13.2: "outputs are one byte array
 * `code(1) || TLV fields`").
 *
 * A field is `tag(1) || len(u32 big-endian) || value`. Unknown tags are a decode failure, not a
 * skip: the surface is closed, so a tag this version does not know means the native library and
 * this class disagree. `MediaResultCodesTest` compares this enumeration with the Rust
 * `MediaField::ALL`, the same drill `DmResultCodesTest` runs for the DM surface.
 */
enum class MediaField(val tag: Int) {
    /** M1/M3: the sealer's registry id, `i64` big-endian. */
    SEALER_ID(0x01),

    /** M5: the reader's registry id, `i64` big-endian. */
    READER_ID(0x02),

    /** M1: the object's 16-byte id. */
    OBJECT_ID(0x03),

    /**
     * M2/M3: `u32_be(count) || (u32_be(index) || frag(65 536)×4 || hash(32)×4)*` — the fragments
     * of every chunk the call completed, and their hashes.
     */
    CHUNKS(0x04),

    /** M3: the 65 536-byte manifest blob. */
    MANIFEST_BLOB(0x05),

    /** M3: SHA-256 of the manifest blob. */
    MANIFEST_HASH(0x06),

    /** M3/M5: the class code, one byte. */
    CLASS_CODE(0x07),

    /** M3/M5: `content_len`, `u64` big-endian. */
    CONTENT_LEN(0x08),

    /** M3/M5: the walked width, `u16` big-endian. */
    WIDTH(0x09),

    /** M3/M5: the walked height, `u16` big-endian. */
    HEIGHT(0x0a),

    /** M3/M5: the walked duration, `u32` big-endian. */
    DURATION_MS(0x0b),

    /** M3: the object's `key_env` (60 bytes), bound to `(out, destId, objectId, manifestHash)`. */
    KEY_ENV(0x0c),

    /** M5: the manifest's preview (a canonical JPEG, or absent for view-once). */
    PREVIEW(0x0d),

    /** M5: `32 × F` bytes, the manifest's ordered fragment hashes. */
    HASHES(0x0e),

    /** M5: the manifest's kind, one byte (1 image, 2 video). */
    KIND(0x0f),

    /** M5: the manifest's flags, one byte (bit 0 view-once). */
    FLAGS(0x10),

    /** M6 (read mode): the chunk's content bytes, at most 262 128. */
    CHUNK_CONTENT(0x11),

    /** M9: the canonical JPEG. */
    CANONICAL(0x12),

    /** M10: the source type, one byte (1 JPEG, 2 PNG, 3 WebP, 4 ISO-BMFF video). */
    SOURCE_TYPE(0x13),
    ;

    companion object {
        private val byTag: Map<Int, MediaField> = entries.associateBy(MediaField::tag)

        /** The field of a wire tag, or `null` for a tag this version does not define. */
        fun fromTag(tag: Int): MediaField? = byTag[tag and 0xff]
    }
}

/**
 * A decoded reply of [MediaNative]: a code and the fields that came with it.
 *
 * Decoding is strict — a truncated reply, a length that overruns the array, an unknown tag or a
 * repeated tag decodes to [MediaCode.INTERNAL], never to an exception, so the caller's `when`
 * stays exhaustive: the only producer of these bytes is GHOST's own native code, and a
 * disagreement between the two sides of the surface is the poison-guard case the facade throws
 * on, exactly like `DmResult`'s strictness.
 */
class MediaResult private constructor(
    /** The result code. */
    val code: MediaCode,
    private val fields: Map<MediaField, ByteArray>,
) {

    /** Whether the call succeeded. */
    val isOk: Boolean get() = code == MediaCode.OK

    /** The raw bytes of a field, or `null` when the reply did not carry it. */
    fun bytesOrNull(field: MediaField): ByteArray? = fields[field]

    /** The raw bytes of a field; a missing field is a surface disagreement. */
    fun bytes(field: MediaField): ByteArray =
        fields[field] ?: throw IllegalStateException("Media reply is missing ${field.name}")

    /** A one-byte field as an unsigned int. */
    fun byte(field: MediaField): Int = bytes(field).let {
        if (it.size != 1) throw IllegalStateException("${field.name} is not one byte")
        it[0].toInt() and 0xff
    }

    /** A `u16` big-endian field. */
    fun u16(field: MediaField): Int = bytes(field).let {
        if (it.size != 2) throw IllegalStateException("${field.name} is not two bytes")
        (it[0].toInt() and 0xff shl 8) or (it[1].toInt() and 0xff)
    }

    /** A `u32` big-endian field. */
    fun u32(field: MediaField): Long = bytes(field).let {
        if (it.size != 4) throw IllegalStateException("${field.name} is not four bytes")
        var value = 0L
        for (b in it) value = (value shl 8) or (b.toLong() and 0xff)
        value
    }

    /** A `u64` big-endian field. */
    fun u64(field: MediaField): Long = bytes(field).let {
        if (it.size != 8) throw IllegalStateException("${field.name} is not eight bytes")
        var value = 0L
        for (b in it) value = (value shl 8) or (b.toLong() and 0xff)
        value
    }

    /** An `i64` big-endian field (a registry id). */
    fun i64(field: MediaField): Long = u64(field)

    companion object {
        /**
         * Decodes `code(1) || (tag(1) || len(u32 big-endian) || value)*`.
         *
         * A `null` array — the native side could not allocate the reply — and any malformed
         * reply decode to a code, never to an exception, so the caller's `when` stays
         * exhaustive. [reply] is erased once its fields are copied out, as `DmResult.decode`
         * erases its reply: a `sealFinish` reply carries `key_env`.
         */
        fun decode(reply: ByteArray?): MediaResult {
            if (reply == null || reply.isEmpty()) {
                return MediaResult(MediaCode.INTERNAL, emptyMap())
            }
            try {
                return decodeFields(reply)
            } finally {
                reply.fill(0)
            }
        }

        private fun decodeFields(reply: ByteArray): MediaResult {
            val code = MediaCode.fromWire(reply[0].toInt())
                ?: return MediaResult(MediaCode.INTERNAL, emptyMap())
            val fields = LinkedHashMap<MediaField, ByteArray>()
            var offset = 1
            while (offset < reply.size) {
                if (offset + 5 > reply.size) return MediaResult(MediaCode.INTERNAL, emptyMap())
                val field = MediaField.fromTag(reply[offset].toInt())
                    ?: return MediaResult(MediaCode.INTERNAL, emptyMap())
                var length = 0L
                for (i in 1..4) {
                    length = (length shl 8) or (reply[offset + i].toLong() and 0xff)
                }
                offset += 5
                if (length < 0 || offset + length > reply.size) {
                    return MediaResult(MediaCode.INTERNAL, emptyMap())
                }
                val end = offset + length.toInt()
                if (fields.put(field, reply.copyOfRange(offset, end)) != null) {
                    return MediaResult(MediaCode.INTERNAL, emptyMap())
                }
                offset = end
            }
            return MediaResult(code, fields)
        }

        /** A reply that never reached the native side, because the library is not loadable. */
        fun unavailable(): MediaResult = MediaResult(MediaCode.CRYPTO_UNAVAILABLE, emptyMap())
    }
}
