package org.ghost.crypto.bridge

import org.junit.Assert.assertTrue
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * The host-library side of the media JVM verification (Phase 11 design §13.2, §15.6; slice S2's
 * post-sweep step): thin wrappers over the two host-only [MediaNative] entries and a reader for
 * the `media_object.txt` sections the suites replay. Test source set only.
 *
 * [MediaResult] cannot decode `testVectors`' replies: its four field tags (`0x14..0x17`) are
 * host-only on purpose and the shipped [MediaField] knows them not — a strict decode maps an
 * unknown tag to `INTERNAL`. The wrappers therefore parse those replies' TLVs by raw tag.
 */
internal object MediaHostVectors {

    private const val VECTORS = "../../protocol/test-vectors/media_object.txt"
    private const val GOLDENS = "../../protocol/test-vectors/media-goldens/media3-1.11.1/"

    /** A decoded reply of a host-only media test entry, keyed by raw TLV tag. */
    class RawReply(val code: MediaCode, val fields: Map<Int, ByteArray>)

    private fun raw(reply: ByteArray?): RawReply {
        if (reply == null || reply.isEmpty()) return RawReply(MediaCode.INTERNAL, emptyMap())
        val code = MediaCode.fromWire(reply[0].toInt()) ?: return RawReply(MediaCode.INTERNAL, emptyMap())
        val fields = LinkedHashMap<Int, ByteArray>()
        var at = 1
        while (at < reply.size) {
            if (at + 5 > reply.size) return RawReply(MediaCode.INTERNAL, emptyMap())
            val tag = reply[at].toInt() and 0xff
            var length = 0
            for (i in 1..4) length = (length shl 8) or (reply[at + i].toInt() and 0xff)
            at += 5
            if (at + length > reply.size) return RawReply(MediaCode.INTERNAL, emptyMap())
            fields[tag] = reply.copyOfRange(at, at + length)
            at += length
        }
        reply.fill(0)
        return RawReply(code, fields)
    }

    /** `0x01 || K_f(32) || object_id(16)` → the derivations (tags `0x14..0x16`). */
    fun derivations(fileKey: ByteArray, objectId: ByteArray): RawReply {
        assertTrue("K_f", fileKey.size == 32)
        assertTrue("object_id", objectId.size == 16)
        val request = ByteArray(49)
        request[0] = 0x01
        fileKey.copyInto(request, 1)
        objectId.copyInto(request, 33)
        return raw(MediaNative.testVectors(0, request))
    }

    /** `0x02 || object_id(16) || ordinal(i16) || retry_gen(1) || resend_count(1)` → `op_id`. */
    fun opId(objectId: ByteArray, ordinal: Int, retryGen: Int, resendCount: Int): RawReply {
        val request = ByteArray(21)
        request[0] = 0x02
        objectId.copyInto(request, 1)
        request[17] = (ordinal shr 8).toByte()
        request[18] = ordinal.toByte()
        request[19] = retryGen.toByte()
        request[20] = resendCount.toByte()
        return raw(MediaNative.testVectors(0, request))
    }

    /** `0x03 || ...` → `key_env` (tag `0x0c`) through the shipped wrap code. */
    fun keyEnv(
        stateKey: ByteArray,
        role: Int,
        destId: ByteArray,
        objectId: ByteArray,
        manifestHash: ByteArray,
        nonce: ByteArray,
        fileKey: ByteArray,
    ): RawReply {
        val request = ByteArray(142)
        request[0] = 0x03
        stateKey.copyInto(request, 1)
        request[33] = role.toByte()
        destId.copyInto(request, 34)
        objectId.copyInto(request, 50)
        manifestHash.copyInto(request, 66)
        nonce.copyInto(request, 98)
        fileKey.copyInto(request, 110)
        return raw(MediaNative.testVectors(0, request))
    }

    /** `testSealBeginWithKey` through JNI; the reply decodes with [MediaResult] (no host-only tags). */
    fun sealBeginWithKey(
        handle: Long,
        fileKey: ByteArray,
        objectId: ByteArray,
        kind: Int,
        viewOnce: Int,
        maxClass: Int,
    ): MediaResult = MediaResult.decode(
        MediaNative.testSealBeginWithKey(handle, fileKey, objectId, kind, viewOnce, maxClass),
    )

    /** One `[object]` section of `media_object.txt`, resolved to bytes. */
    class ObjectVector(
        val kf: ByteArray,
        val objectId: ByteArray,
        val kind: Int,
        val viewOnce: Boolean,
        val content: ByteArray,
        val contentLen: Long,
        val width: Int,
        val height: Int,
        val durationMs: Long,
        val preview: ByteArray,
        val caption: ByteArray,
        val kp: ByteArray,
        val km: ByteArray,
        val commit: ByteArray,
        val classCode: Int,
        val chunks: Int,
        val fragmentHashes: List<ByteArray>,
        val manifestHash: ByteArray,
    )

    /** Parses `[object <name>]`; recipes resolve against the committed goldens. */
    fun objectVector(name: String): ObjectVector {
        val values = section("object $name")
        val chunks = values.getValue("chunks").toInt()
        return ObjectVector(
            kf = hex(values.getValue("k_f")),
            objectId = hex(values.getValue("object_id")),
            kind = values.getValue("kind").toInt(),
            viewOnce = values.getValue("view_once") == "1",
            content = recipe(values.getValue("content")),
            contentLen = values.getValue("content_len").toLong(),
            width = values.getValue("width").toInt(),
            height = values.getValue("height").toInt(),
            durationMs = values.getValue("duration_ms").toLong(),
            preview = recipe(values.getValue("preview")),
            caption = hex(values.getValue("caption_utf8")),
            kp = hex(values.getValue("k_p")),
            km = hex(values.getValue("k_m")),
            commit = hex(values.getValue("commit")),
            classCode = values.getValue("class_code").toInt(),
            chunks = chunks,
            fragmentHashes = (0 until chunks * 4).map { hex(values.getValue("fragment_sha256[$it]")) },
            manifestHash = hex(values.getValue("manifest_hash")),
        )
    }

    /** The `[key_env]` section's pinned wrap fixture (§4.2's dev cycle back). */
    class KeyEnvVector(
        val stateKey: ByteArray,
        val nonce: ByteArray,
        val destId: ByteArray,
        val objectId: ByteArray,
        val manifestHash: ByteArray,
        val kf: ByteArray,
        val out: ByteArray,
        val inEnv: ByteArray,
    )

    fun keyEnvVector(): KeyEnvVector {
        val values = section("key_env")
        return KeyEnvVector(
            stateKey = hex(values.getValue("state_key")),
            nonce = hex(values.getValue("nonce")),
            destId = hex(values.getValue("dest_id")),
            objectId = hex(values.getValue("object_id")),
            manifestHash = hex(values.getValue("manifest_hash")),
            kf = hex(values.getValue("k_f")),
            out = hex(values.getValue("out")),
            inEnv = hex(values.getValue("in")),
        )
    }

    /** The `key = value` rows of one section, comments and blanks skipped. */
    private fun section(name: String): Map<String, String> {
        val lines = File(VECTORS).readLines()
        val start = lines.indexOf("[$name]")
        assertTrue("section [$name] in $VECTORS", start >= 0)
        val values = LinkedHashMap<String, String>()
        for (line in lines.drop(start + 1)) {
            if (line.isBlank()) continue
            if (line.startsWith("[")) break
            if (line.startsWith("#")) continue
            val split = line.indexOf('=')
            if (split < 0) continue
            values[line.substring(0, split).trim()] = line.substring(split + 1).trim()
        }
        return values
    }

    /** A byte recipe: `hex:..`, `golden:<path under media3-1.11.1/>[a..b]`, `+`-joined parts. */
    private fun recipe(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (part in text.split('+')) {
            when {
                part.startsWith("hex:") -> out.write(hex(part.substring(4)))
                part.startsWith("golden:") -> out.write(golden(part.substring(7)))
                else -> error("unknown recipe part: $part")
            }
        }
        return out.toByteArray()
    }

    private fun golden(spec: String): ByteArray {
        val slice = spec.indexOf('[')
        val (path, range) = if (slice < 0) spec to null else spec.substring(0, slice) to spec.substring(slice)
        val bytes = File(GOLDENS + path).readBytes()
        if (range == null) return bytes
        // "[a..b]"; either bound may be empty.
        val body = range.substring(1, range.length - 1)
        val dots = body.indexOf("..")
        val from = if (dots == 0) 0 else body.substring(0, dots).toInt()
        val to = if (dots == body.length - 2) bytes.size else body.substring(dots + 2).toInt()
        return bytes.copyOfRange(from, to)
    }

    /** Lowercase hex, two characters per byte (the vector files' encoding). */
    fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "odd hex length" }
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            out[i] = (
                (Character.digit(text[2 * i], 16) shl 4) or
                    Character.digit(text[2 * i + 1], 16)
                ).toByte()
        }
        return out
    }
}
