package org.ghost.media.vectors

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The independent JDK replay of the media vectors (Phase 11 design `faza11-media.md` §3.9 and §15.2
 * item 1: "replayed … by an independent JDK implementation in `android/media/src/test` (JCA
 * `ChaCha20-Poly1305` and a test HKDF)"; slice S1's exit condition).
 *
 * Written from the design text and the vector files' own headers, sharing no code with
 * `ghost-client-media`: SunJCE's `ChaCha20-Poly1305`, HKDF from RFC 5869 over `HmacSHA256`,
 * `SHA-256`, and this file's own manifest, descriptor, chunk-layer, reader, sniffer and canonical-
 * JPEG implementations. No native library is loaded, so the test never skips.
 *
 * - `media_object.txt`: every derivation, nonce, AD, fragment hash, manifest, blob hash and
 *   descriptor of the three objects is recomputed and compared; each object then opens and
 *   validates through this file's reader; every `[negative]` case is applied with this file's
 *   operations and must give its code (and every step before it must pass); the separation checks
 *   are recomputed apart.
 * - `media_descriptor.txt`, `media_sniff.txt`, `media_jpeg.txt`: every case.
 * - `media_fmp4.txt` is the Rust walker's alone (no second fMP4 walker; design §22.2). A video
 *   object's `width`, `height` and `duration_ms` are what that walker reported: this reader
 *   compares the manifest against them where the Rust reader compares it against its own walk. An
 *   **image** object's content is walked here, by this file's canonical-JPEG walker (the review of
 *   S1: the replay took the image's geometry from the file and accepted EXIF-bearing content), so
 *   its geometry is this walk's and an APPn segment in it fails validation.
 */
class MediaVectorReplayTest {

    // ---------------------------------------------------------------------------------------------
    // Files and recipes.

    private val vectors = File("../../protocol/test-vectors").canonicalFile
    private val goldens = File(vectors, "media-goldens/media3-1.11.1")

    private class Section(val name: String, val values: LinkedHashMap<String, String>) {
        fun get(key: String): String = requireNotNull(values[key]) { "[$name] has no $key" }
    }

    private fun sections(file: String): List<Section> {
        val f = File(vectors, file)
        assertTrue("$f must exist", f.isFile)
        val out = ArrayList<Section>()
        for (raw in f.readLines()) {
            val line = raw.trimEnd('\r')
            if (line.isEmpty() || line.startsWith("#")) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                out.add(Section(line.substring(1, line.length - 1), LinkedHashMap()))
                continue
            }
            val at = line.indexOf(" = ")
            require(at > 0 && out.isNotEmpty()) { "$file: $line" }
            out.last().values[line.substring(0, at)] = line.substring(at + 3)
        }
        return out
    }

    private fun hex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex" }
        return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun recipe(r: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (part in r.split(" + ")) {
            when {
                part.isEmpty() -> {}
                part.startsWith("hex:") -> out.write(hex(part.removePrefix("hex:")))
                part.startsWith("golden:") -> {
                    val spec = part.removePrefix("golden:")
                    val bracket = spec.indexOf('[')
                    val path = if (bracket < 0) spec else spec.substring(0, bracket)
                    val data = File(goldens, path).readBytes()
                    var from = 0
                    var to = data.size
                    if (bracket >= 0) {
                        val range = spec.substring(bracket + 1, spec.length - 1).split("..")
                        if (range[0].isNotEmpty()) from = range[0].toInt()
                        if (range[1].isNotEmpty()) to = range[1].toInt()
                    }
                    out.write(data, from, to - from)
                }
                else -> error("unknown recipe part $part")
            }
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------------------------------------
    // Primitives.

    private class Refused(val code: String) : Exception(code)

    private fun refuse(code: String): Nothing = throw Refused(code)

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        for (p in parts) d.update(p)
        return d.digest()
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 with L = 32: one block, `T(1) = HMAC(PRK, info || 0x01)`. */
    private fun hkdf32(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
        val prk = hmac(salt, ikm)
        return hmac(prk, info.toByteArray(Charsets.US_ASCII) + byteArrayOf(1))
    }

    private fun aead(mode: Int, key: ByteArray, nonce: ByteArray, ad: ByteArray, input: ByteArray): ByteArray {
        val c = Cipher.getInstance("ChaCha20-Poly1305")
        c.init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        c.updateAAD(ad)
        return c.doFinal(input)
    }

    private fun seal(key: ByteArray, nonce: ByteArray, ad: ByteArray, pt: ByteArray) =
        aead(Cipher.ENCRYPT_MODE, key, nonce, ad, pt)

    private fun open(key: ByteArray, nonce: ByteArray, ad: ByteArray, ct: ByteArray): ByteArray = try {
        aead(Cipher.DECRYPT_MODE, key, nonce, ad, ct)
    } catch (e: AEADBadTagException) {
        refuse("NOT_OPEN")
    }

    private fun be(v: Long, n: Int) = ByteArray(n) { i -> (v ushr (8 * (n - 1 - i))).toByte() }
    private fun u8(b: ByteArray, o: Int) = b[o].toInt() and 0xff
    private fun u16(b: ByteArray, o: Int) = (u8(b, o) shl 8) or u8(b, o + 1)
    private fun u32(b: ByteArray, o: Int): Long = (u16(b, o).toLong() shl 16) or u16(b, o + 2).toLong()
    private fun u64(b: ByteArray, o: Int): Long = (u32(b, o) shl 32) or u32(b, o + 4)

    // ---------------------------------------------------------------------------------------------
    // The format (design §3.1–§3.6, §4.1), written from the text.

    private val frag = 65536
    private val chunkCt = 4 * frag
    private val chunkPt = chunkCt - 16
    private val classes = intArrayOf(16, 24, 36, 56, 84, 128, 192, 288, 432, 648, 804)
    private val maxContent = 52_428_800L
    private val imageMax = 4L * chunkPt
    private val mpLen = frag - 32 - 16
    private val previewMax = 32768
    private val hashesAt = 38 + previewMax
    private val videoMaxMs = 160_000L

    private fun capacity(c: Int) = minOf(classes[c] / 4L * chunkPt, maxContent)

    private fun classFor(len: Long): Int? {
        if (len < 1 || len > maxContent) return null
        return classes.indices.first { capacity(it) >= len }
    }

    private class Keys(val kp: ByteArray, val km: ByteArray, val commit: ByteArray)

    private fun derive(kf: ByteArray, oid: ByteArray) = Keys(
        hkdf32(kf, oid, "ghost/v1/media/payload"),
        hkdf32(kf, oid, "ghost/v1/media/manifest"),
        hkdf32(kf, oid, "ghost/v1/media/commit"),
    )

    private fun nonce(i: Int, last: Boolean) = ByteArray(7) + be(i.toLong(), 4) + byteArrayOf(if (last) 1 else 0)
    private fun chunkAd(oid: ByteArray, kind: Int) =
        "ghost/v1/media/ad/chunk".toByteArray() + byteArrayOf(1) + oid + byteArrayOf(kind.toByte())
    private fun manifestAd(oid: ByteArray, commit: ByteArray) =
        "ghost/v1/media/ad/manifest".toByteArray() + byteArrayOf(1) + oid + commit

    private fun opId(oid: ByteArray, ordinal: Int, gen: Int, resend: Int): ByteArray =
        sha256("ghost/v1/media/op".toByteArray() + oid + be(ordinal.toLong(), 2) + byteArrayOf(gen.toByte(), resend.toByte()))
            .copyOf(16)

    private fun imageGeometry(w: Int, h: Int): Boolean {
        val long = maxOf(w, h)
        val short = minOf(w, h)
        return long in setOf(512, 1024, 2048) && short >= 16 && short <= long && short % 16 == 0
    }

    private fun previewGeometry(w: Int, h: Int): Boolean {
        val short = minOf(w, h)
        return maxOf(w, h) == 320 && short >= 16 && short % 16 == 0
    }

    private fun videoGeometry(w: Int, h: Int) = (w == 1280 && h == 720) || (w == 720 && h == 1280)

    /** D29's short edge: `max(16, 16 · round(long · short / long_src / 16))`, half up, at most `long`. */
    private fun shortEdge(long: Long, srcLong: Long, srcShort: Long): Long =
        minOf(long, maxOf(16L, 16L * ((2 * long * srcShort + 16 * srcLong) / (32 * srcLong))))

    /** The ladder (§8.2, Q37): the largest of 512, 1 024, 2 048 not above the source's long edge. */
    private fun imageTarget(w: Long, h: Long): Pair<Long, Long> {
        val srcLong = maxOf(w, h)
        val long = listOf(2048L, 1024L, 512L).firstOrNull { it <= srcLong } ?: 512L
        val short = shortEdge(long, srcLong, minOf(w, h))
        return if (w >= h) Pair(long, short) else Pair(short, long)
    }

    private fun previewTarget(w: Long, h: Long): Pair<Long, Long> {
        val short = shortEdge(320L, maxOf(w, h), minOf(w, h))
        return if (w >= h) Pair(320L, short) else Pair(short, 320L)
    }

    /** The fields of a manifest plaintext MP (§3.5). */
    private class Mp(
        val kind: Int, val flags: Int, val clazz: Int, val oid: ByteArray, val contentLen: Long,
        val width: Int, val height: Int, val durationMs: Long, val preview: ByteArray, val hashes: List<ByteArray>,
    )

    private fun encodeMp(m: Mp): ByteArray {
        val out = ByteArray(mpLen)
        out[0] = 1
        out[1] = m.kind.toByte()
        out[2] = m.flags.toByte()
        out[3] = m.clazz.toByte()
        m.oid.copyInto(out, 4)
        be(m.contentLen, 8).copyInto(out, 20)
        be(m.width.toLong(), 2).copyInto(out, 28)
        be(m.height.toLong(), 2).copyInto(out, 30)
        be(m.durationMs, 4).copyInto(out, 32)
        be(m.preview.size.toLong(), 2).copyInto(out, 36)
        m.preview.copyInto(out, 38)
        m.hashes.forEachIndexed { j, h -> h.copyInto(out, hashesAt + 32 * j) }
        return out
    }

    /** Parses MP under every rule of §3.5; NON_CANONICAL otherwise. */
    private fun decodeMp(mp: ByteArray): Mp {
        fun nc(): Nothing = refuse("NON_CANONICAL")
        if (mp.size != mpLen || u8(mp, 0) != 1) nc()
        val kind = u8(mp, 1)
        val flags = u8(mp, 2)
        val clazz = u8(mp, 3)
        if (kind != 1 && kind != 2) nc()
        if (flags and 1.inv() != 0) nc()
        if (clazz > 10) nc()
        val oid = mp.copyOfRange(4, 20)
        val contentLen = u64(mp, 20)
        val w = u16(mp, 28)
        val h = u16(mp, 30)
        val duration = u32(mp, 32)
        val previewLen = u16(mp, 36)
        if (previewLen > previewMax) nc()
        if (kind == 1 && clazz != 0) nc()
        if (classFor(contentLen) != clazz) nc()
        if (kind == 1) {
            if (contentLen > imageMax || !imageGeometry(w, h) || duration != 0L) nc()
        } else {
            if (!videoGeometry(w, h) || duration < 1 || duration > videoMaxMs) nc()
        }
        val preview = mp.copyOfRange(38, 38 + previewLen)
        if ((38 + previewLen until hashesAt).any { mp[it] != 0.toByte() }) nc()
        if (flags and 1 == 1 && previewLen != 0) nc()
        if (previewLen > 0) {
            val info = jpegWalk(preview, strip = false).second
            if (!previewGeometry(info[0], info[1])) nc()
        }
        val f = classes[clazz]
        val hashes = (0 until f).map { mp.copyOfRange(hashesAt + 32 * it, hashesAt + 32 * it + 32) }
        if (hashes.map { hex(it) }.toSet().size != f) nc()
        if ((hashesAt + 32 * f until mpLen).any { mp[it] != 0.toByte() }) nc()
        return Mp(kind, flags, clazz, oid, contentLen, w, h, duration, preview, hashes)
    }

    private fun sealBlob(k: Keys, oid: ByteArray, mp: ByteArray): ByteArray =
        k.commit + seal(k.km, ByteArray(12), manifestAd(oid, k.commit), mp)

    // ---------------------------------------------------------------------------------------------
    // The reader (§3.4, §7.3, §13.2 M5–M7), this file's own.

    private class Expected(val oid: ByteArray, var kind: Int, var viewOnce: Boolean, var clazz: Int, var manifestHash: ByteArray)

    private inner class Reader(kf: ByteArray, val e: Expected, blob: ByteArray) {
        val keys = derive(kf, e.oid)
        val mp: Mp
        val n: Int

        init {
            if (blob.size != frag || !sha256(blob).contentEquals(e.manifestHash)) refuse("HASH_MISMATCH")
            if (!blob.copyOfRange(0, 32).contentEquals(keys.commit)) refuse("COMMIT_MISMATCH")
            val plain = open(keys.km, ByteArray(12), manifestAd(e.oid, keys.commit), blob.copyOfRange(32, frag))
            mp = decodeMp(plain)
            if (!mp.oid.contentEquals(e.oid)) refuse("NON_CANONICAL")
            if (mp.kind != e.kind || (mp.flags == 1) != e.viewOnce || mp.clazz != e.clazz) refuse("NON_CANONICAL")
            n = classes[mp.clazz] / 4
        }

        /** The content bytes of chunk i. */
        fun read(i: Int, chunk: ByteArray?): ByteArray {
            if (i < 0 || i >= n) refuse("INDEX_RANGE")
            if (chunk == null || chunk.size != chunkCt) refuse("HASH_MISMATCH")
            for (k in 0 until 4) {
                val f = chunk.copyOfRange(k * frag, (k + 1) * frag)
                if (!sha256(f).contentEquals(mp.hashes[4 * i + k])) refuse("HASH_MISMATCH")
            }
            val pt = open(keys.kp, nonce(i, i == n - 1), chunkAd(e.oid, e.kind), chunk)
            val content = maxOf(0L, minOf(chunkPt.toLong(), mp.contentLen - i.toLong() * chunkPt)).toInt()
            if ((content until chunkPt).any { pt[it] != 0.toByte() }) refuse("NON_CANONICAL")
            return pt.copyOf(content)
        }

        /**
         * Every chunk in order, then the manifest against the walked values: an image's content is
         * walked here (media_jpeg.txt's check), a video's values are the Rust walker's.
         */
        fun validate(chunks: List<ByteArray>, videoWalked: Triple<Int, Int, Long>): ByteArray {
            val all = java.io.ByteArrayOutputStream()
            for (i in 0 until n) all.write(read(i, chunks.getOrNull(i)))
            val content = all.toByteArray()
            val walked = if (e.kind == 1) imageWalk(content) else videoWalked
            if (Triple(mp.width, mp.height, mp.durationMs) != walked) refuse("NON_CANONICAL")
            return content
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The canonical JPEG profile and jpegCanonicalize (§8.2), from media_jpeg.txt's header.

    /** Walks `data`; `strip` drops APPn and COM. Returns the kept bytes and (width, height, Nf). */
    private fun jpegWalk(data: ByteArray, strip: Boolean): Pair<ByteArray, IntArray> {
        fun nc(): Nothing = refuse("NON_CANONICAL")
        val out = java.io.ByteArrayOutputStream()
        if (data.size < 2 || u8(data, 0) != 0xFF || u8(data, 1) != 0xD8) nc()
        out.write(data, 0, 2)
        var p = 2
        var sof: IntArray? = null
        var ids = IntArray(0)
        var tqs = IntArray(0)
        var scans = 0
        var restart = 0
        var dqt = 0 // bit Tq: that quantisation table is defined
        var dht = 0 // bit 2 * Tc + Th: that Huffman table is defined
        var dri = false
        val scanned = HashSet<Int>()
        while (true) {
            if (p + 1 >= data.size || u8(data, p) != 0xFF) nc()
            val m = u8(data, p + 1)
            when {
                m == 0xD9 -> {
                    if (scans == 0) nc()
                    if (scanned.size != ids.size) nc() // every SOF0 component coded by one scan
                    if (p + 2 != data.size) nc()
                    out.write(data, p, 2)
                    val s = sof ?: nc()
                    return Pair(out.toByteArray(), s)
                }
                m == 0xC0 || m == 0xC4 || m == 0xDB || m == 0xDD || m == 0xDA || m in 0xE0..0xEF || m == 0xFE -> {}
                else -> nc()
            }
            if (p + 4 > data.size) nc()
            val len = u16(data, p + 2)
            if (len < 2 || p + 2 + len > data.size) nc()
            val seg = data.copyOfRange(p + 4, p + 2 + len)
            val app = m in 0xE0..0xEF || m == 0xFE
            if (app && !strip) nc()
            if (!app) out.write(data, p, 2 + len)
            p += 2 + len
            when (m) {
                0xDB -> {
                    if (seg.isEmpty() || seg.size % 65 != 0 || seg.size / 65 > 4) nc()
                    for (t in 0 until seg.size / 65) {
                        val pq = u8(seg, 65 * t)
                        if (pq shr 4 != 0 || pq and 15 > 3) nc()
                        val bit = 1 shl (pq and 3)
                        if (dqt and bit != 0) nc() // a table defined twice
                        dqt = dqt or bit
                    }
                }
                0xC0 -> {
                    if (sof != null || seg.size < 6) nc()
                    val nf = u8(seg, 5)
                    if (u8(seg, 0) != 8 || u16(seg, 1) == 0 || u16(seg, 3) == 0 || (nf != 1 && nf != 3)) nc()
                    if (seg.size != 6 + 3 * nf) nc()
                    ids = IntArray(nf) { u8(seg, 6 + 3 * it) }
                    tqs = IntArray(nf) { u8(seg, 8 + 3 * it) }
                    for (c in 0 until nf) {
                        val hv = u8(seg, 7 + 3 * c)
                        if (hv shr 4 !in 1..4 || hv and 15 !in 1..4 || u8(seg, 8 + 3 * c) > 3) nc()
                    }
                    if (ids.toSet().size != nf) nc()
                    sof = intArrayOf(u16(seg, 3), u16(seg, 1), nf)
                }
                0xC4 -> {
                    var q = 0
                    if (seg.isEmpty()) nc()
                    while (q < seg.size) {
                        if (q + 17 > seg.size) nc()
                        val tcth = u8(seg, q)
                        if (tcth shr 4 > 1 || tcth and 15 > 1) nc()
                        var total = 0
                        for (k in 1..16) total += u8(seg, q + k)
                        if (total == 0 || total > 256 || q + 17 + total > seg.size) nc()
                        val bit = 1 shl (2 * (tcth shr 4) + (tcth and 15))
                        if (dht and bit != 0) nc() // a table defined twice
                        dht = dht or bit
                        q += 17 + total
                    }
                }
                0xDD -> {
                    if (seg.size != 2 || dri) nc()
                    dri = true
                    restart = u16(seg, 0)
                }
                0xDA -> {
                    if (sof == null || seg.isEmpty()) nc()
                    val ns = u8(seg, 0)
                    if (ns == 0 || ns > ids.size || seg.size != 4 + 2 * ns) nc()
                    val seen = HashSet<Int>()
                    for (c in 0 until ns) {
                        val cs = u8(seg, 1 + 2 * c)
                        val tdta = u8(seg, 2 + 2 * c)
                        if (cs !in ids || !seen.add(cs) || tdta shr 4 > 1 || tdta and 15 > 1) nc()
                    }
                    if (u8(seg, 1 + 2 * ns) != 0 || u8(seg, 2 + 2 * ns) != 63 || u8(seg, 3 + 2 * ns) != 0) nc()
                    // Each component in one scan only, its tables defined before it.
                    for (c in 0 until ns) {
                        val cs = u8(seg, 1 + 2 * c)
                        val tdta = u8(seg, 2 + 2 * c)
                        if (!scanned.add(cs)) nc()
                        if (dqt and (1 shl tqs[ids.indexOf(cs)]) == 0) nc()
                        if (dht and (1 shl (tdta shr 4)) == 0 || dht and (1 shl (2 + (tdta and 15))) == 0) nc()
                    }
                    scans++
                    // Entropy-coded data: FF 00 stuffing and RSTn in order, up to the next marker.
                    var rst = 0
                    while (true) {
                        if (p >= data.size) nc()
                        val b = u8(data, p)
                        if (b != 0xFF) {
                            out.write(b)
                            p++
                            continue
                        }
                        if (p + 1 >= data.size) nc()
                        val next = u8(data, p + 1)
                        when {
                            next == 0x00 -> {
                                out.write(data, p, 2)
                                p += 2
                            }
                            next in 0xD0..0xD7 -> {
                                if (restart == 0 || next != 0xD0 + rst) nc()
                                rst = (rst + 1) % 8
                                out.write(data, p, 2)
                                p += 2
                            }
                            next == 0xFF -> nc()
                            else -> break
                        }
                    }
                }
            }
        }
    }

    /** An image object's content: a canonical JPEG with the geometry of D29; its (width, height, 0). */
    private fun imageWalk(content: ByteArray): Triple<Int, Int, Long> {
        val info = jpegWalk(content, strip = false).second
        if (!imageGeometry(info[0], info[1])) refuse("NON_CANONICAL")
        return Triple(info[0], info[1], 0L)
    }

    // ---------------------------------------------------------------------------------------------
    // The sniffer (§6.1, §13.2 M10), from media_sniff.txt's header.

    private val imageBrands = setOf(
        "mif1", "mif2", "mif3", "msf1", "miaf", "1pic", "heic", "heix", "heim", "heis", "hevc", "hevx", "hevm", "hevs",
        "avci", "avcs", "jpeg", "jpgs", "vvic", "vvis", "evbi", "evbs", "j2ki", "j2is",
        "avif", "avis", "avio", "MA1A", "MA1B", "MiHA", "MiHB", "MiHE",
    )

    private fun sniff(input: ByteArray): String {
        val h = input.copyOf(minOf(input.size, 64))
        fun at(o: Int, s: String) = h.size >= o + s.length && String(h, o, s.length, Charsets.ISO_8859_1) == s
        if (h.size >= 3 && u8(h, 0) == 0xFF && u8(h, 1) == 0xD8 && u8(h, 2) == 0xFF) return "JPEG"
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
        if (h.size >= 8 && h.copyOf(8).contentEquals(png)) {
            return if (h.size >= 16 && u32(h, 8) == 13L && at(12, "IHDR")) "PNG" else "UNSUPPORTED"
        }
        if (at(0, "RIFF") && at(8, "WEBP")) {
            return when {
                at(12, "VP8 ") || at(12, "VP8L") -> "WEBP"
                at(12, "VP8X") && h.size > 20 && u8(h, 20) and 0x02 == 0 -> "WEBP"
                else -> "UNSUPPORTED"
            }
        }
        if (at(4, "ftyp")) {
            val size = u32(h, 0)
            if (size < 16 || size > h.size || size % 4 != 0L) return "UNSUPPORTED"
            val brands = mutableListOf(String(h, 8, 4, Charsets.ISO_8859_1))
            var o = 16
            while (o + 4 <= size) {
                brands.add(String(h, o, 4, Charsets.ISO_8859_1))
                o += 4
            }
            return if (brands.any { it in imageBrands }) "UNSUPPORTED" else "ISO_BMFF_VIDEO"
        }
        return "UNSUPPORTED"
    }

    // ---------------------------------------------------------------------------------------------
    // The descriptor (§4.1, R-D3), from media_descriptor.txt's header.

    private class Desc(val kind: Int, val flags: Int, val clazz: Int, val oid: ByteArray, val slot: ByteArray, val mh: ByteArray, val caption: ByteArray)

    private fun strictUtf8(b: ByteArray): Boolean = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(b))
        true
    } catch (e: java.nio.charset.CharacterCodingException) {
        false
    }

    private fun decodeDescriptor(b: ByteArray): Desc {
        fun nc(): Nothing = refuse("NON_CANONICAL")
        if (b.size < 86 || b.size > 1110 || u8(b, 0) != 1) nc()
        val kind = u8(b, 1)
        val flags = u8(b, 2)
        val clazz = u8(b, 3)
        if (kind != 1 && kind != 2) nc()
        if (flags and 1.inv() != 0 || clazz > 10 || (kind == 1 && clazz != 0)) nc()
        val captionLen = u16(b, 84)
        if (captionLen > 1024 || b.size != 86 + captionLen) nc()
        val caption = b.copyOfRange(86, b.size)
        if (!strictUtf8(caption)) nc()
        return Desc(kind, flags, clazz, b.copyOfRange(4, 20), b.copyOfRange(20, 52), b.copyOfRange(52, 84), caption)
    }

    private fun encodeDescriptor(d: Desc): ByteArray =
        byteArrayOf(1, d.kind.toByte(), d.flags.toByte(), d.clazz.toByte()) + d.oid + d.slot + d.mh +
            be(d.caption.size.toLong(), 2) + d.caption

    // ---------------------------------------------------------------------------------------------
    // media_object.txt.

    private inner class Obj(val s: Section) {
        val kf = hex(s.get("k_f"))
        val oid = hex(s.get("object_id"))
        val kind = s.get("kind").toInt()
        val viewOnce = s.get("view_once") == "1"
        val content = recipe(s.get("content"))
        val preview = recipe(s.get("preview"))
        /** An image's walk is this file's; a video's is the Rust walker's (the file's values). */
        val walked = if (s.get("kind").toInt() == 1) {
            imageWalk(content)
        } else {
            Triple(s.get("width").toInt(), s.get("height").toInt(), s.get("duration_ms").toLong())
        }
        val keys = derive(kf, oid)
        val clazz = classFor(content.size.toLong())!!
        val n = classes[clazz] / 4
        val plaintexts = (0 until n).map { i ->
            val from = minOf(i * chunkPt, content.size)
            val to = minOf((i + 1) * chunkPt, content.size)
            content.copyOfRange(from, to).copyOf(chunkPt)
        }
        val chunks = plaintexts.mapIndexed { i, p -> seal(keys.kp, nonce(i, i == n - 1), chunkAd(oid, kind), p) }
        val mp = encodeMp(
            Mp(
                kind, if (viewOnce) 1 else 0, clazz, oid, content.size.toLong(), walked.first, walked.second,
                walked.third, preview, chunks.flatMap { c -> (0 until 4).map { sha256(c.copyOfRange(it * frag, (it + 1) * frag)) } },
            ),
        )
        val blob = sealBlob(keys, oid, mp)
    }

    private var compared = 0

    private fun check(what: String, want: String, got: String) {
        assertEquals(what, want, got)
        compared++
    }

    @Test
    fun mediaObjectVectors() {
        val all = sections("media_object.txt")
        val constants = all.first { it.name == "constants" }
        check("CHUNK_PT", constants.get("CHUNK_PT"), chunkPt.toString())
        check("MANIFEST_PT", constants.get("MANIFEST_PT"), mpLen.toString())
        check("HASHES_OFFSET", constants.get("HASHES_OFFSET"), hashesAt.toString())
        check("IMAGE_MAX_CONTENT", constants.get("IMAGE_MAX_CONTENT"), imageMax.toString())
        val classesSection = all.first { it.name == "classes" }
        for ((k, v) in classesSection.values) {
            if (k.startsWith("class[")) {
                val c = k.substring(6, k.length - 1).toInt()
                val f = classes[c]
                check(k, v, "F $f chunks ${f / 4} cap ${capacity(c)} blobs ${f + 1} bytes_per_relay ${(f + 1L) * frag}")
            } else if (k.startsWith("boundary[")) {
                val len = k.substring(9, k.length - 1).toLong()
                check(k, v, classFor(len)?.toString() ?: "none")
            }
        }
        val ladder = all.first { it.name == "ladder" }
        for ((k, v) in ladder.values) {
            val (w, h) = k.substring(k.indexOf('[') + 1, k.length - 1).split("x").map { it.toLong() }
            val t = if (k.startsWith("image")) imageTarget(w, h) else previewTarget(w, h)
            check(k, v, "${t.first}x${t.second}")
        }
        val labels = all.first { it.name == "labels" }
        val names = labels.values.values.toList()
        for (a in names) for (b in names) if (a != b) assertTrue("$a is a prefix of $b", !b.startsWith(a))
        val objects = LinkedHashMap<String, Obj>()
        for (s in all.filter { it.name.startsWith("object ") }) {
            val o = Obj(s)
            objects[s.name.removePrefix("object ")] = o
            check("content_len", s.get("content_len"), o.content.size.toString())
            check("width", s.get("width"), o.walked.first.toString())
            check("height", s.get("height"), o.walked.second.toString())
            check("duration_ms", s.get("duration_ms"), o.walked.third.toString())
            check("content_sha256", s.get("content_sha256"), hex(sha256(o.content)))
            check("k_p", s.get("k_p"), hex(o.keys.kp))
            check("k_m", s.get("k_m"), hex(o.keys.km))
            check("commit", s.get("commit"), hex(o.keys.commit))
            check("class_code", s.get("class_code"), o.clazz.toString())
            check("chunks", s.get("chunks"), o.n.toString())
            check("chunk_ad", s.get("chunk_ad"), hex(chunkAd(o.oid, o.kind)))
            for (i in 0 until o.n) check("chunk_nonce[$i]", s.get("chunk_nonce[$i]"), hex(nonce(i, i == o.n - 1)))
            for (j in 0 until 4 * o.n) {
                val f = o.chunks[j / 4].copyOfRange((j % 4) * frag, (j % 4 + 1) * frag)
                check("fragment_sha256[$j]", s.get("fragment_sha256[$j]"), hex(sha256(f)))
            }
            check("manifest_ad", s.get("manifest_ad"), hex(manifestAd(o.oid, o.keys.commit)))
            check("manifest_plaintext_head", s.get("manifest_plaintext_head"), hex(o.mp.copyOf(38)))
            check("manifest_plaintext_sha256", s.get("manifest_plaintext_sha256"), hex(sha256(o.mp)))
            check("manifest_hash", s.get("manifest_hash"), hex(sha256(o.blob)))
            check("manifest_blob_tail16", s.get("manifest_blob_tail16"), hex(o.blob.copyOfRange(frag - 16, frag)))
            val desc = encodeDescriptor(
                Desc(o.kind, if (o.viewOnce) 1 else 0, o.clazz, o.oid, ByteArray(32), sha256(o.blob), hex(s.get("caption_utf8"))),
            )
            check("descriptor", s.get("descriptor"), hex(desc))
            for ((k, v) in s.values.filterKeys { it.startsWith("op_id[") }) {
                val (ordinal, gen, resend) = k.substring(6, k.length - 1).split(",").map { it.toInt() }
                check(k, v, hex(opId(o.oid, ordinal, gen, resend)))
            }
            // The honest object opens, reads back its content and validates.
            val e = Expected(o.oid, o.kind, o.viewOnce, o.clazz, sha256(o.blob))
            val back = Reader(o.kf, e, o.blob).validate(o.chunks, o.walked)
            assertArrayEquals("${s.name} reads back", o.content, back)
        }
        // The negative cases.
        var negatives = 0
        for (s in all.filter { it.name.startsWith("negative ") }) {
            val base = objects.getValue(s.get("object"))
            val st = State(base)
            for ((k, v) in s.values) if (k.startsWith("op")) st.apply(v, objects)
            val step = s.get("step")
            val want = s.get("expect")
            if (step != "open") assertEquals("${s.name}: the open before its step", "OK", st.run("open"))
            assertEquals(s.name, want, st.run(step))
            negatives++
        }
        // The separation checks, apart.
        val sep = all.first { it.name == "separation" }
        val img = objects.getValue("image_class0")
        val other = derive(hex(sep.get("other_k_f")), img.oid)
        check("other_k_f_commit", sep.get("other_k_f_commit"), hex(other.commit))
        val otherId = derive(img.kf, hex(sep.get("other_object_id")))
        check("other_object_id_k_p", sep.get("other_object_id_k_p"), hex(otherId.kp))
        check("other_object_id_commit", sep.get("other_object_id_commit"), hex(otherId.commit))
        assertTrue(!other.commit.contentEquals(img.keys.commit) && !otherId.kp.contentEquals(img.keys.kp))
        println("media_object.txt: $compared values compared and equal; $negatives negative cases refused with their codes; 3 separation values")
        assertTrue(negatives >= 50)
    }

    /** A negative case's state (media_object.txt's header). */
    private inner class State(val base: Obj) {
        var kf = base.kf
        val oid = base.oid
        val kind = base.kind
        var chunks = base.chunks.map { it.copyOf() }.toMutableList()
        var plaintexts = base.plaintexts.map { it.copyOf() }.toMutableList()
        var mp = base.mp.copyOf()
        var blob = base.blob.copyOf()
        val expected = Expected(oid, kind, base.viewOnce, base.clazz, sha256(base.blob))

        private fun resealManifest() {
            blob = sealBlob(base.keys, oid, mp)
            expected.manifestHash = sha256(blob)
        }

        private fun fragment(j: Int) = chunks[j / 4].copyOfRange((j % 4) * frag, (j % 4 + 1) * frag)
        private fun putFragment(j: Int, f: ByteArray) = f.copyInto(chunks[j / 4], (j % 4) * frag)
        private fun sealChunk(i: Int, last: Boolean, o: ByteArray, k: Int, p: ByteArray) =
            seal(base.keys.kp, nonce(i, last), chunkAd(o, k), p)

        fun apply(op: String, objects: Map<String, Obj>) {
            if (op.startsWith("reseal_content ")) {
                // The content := the recipe (the rest of the line), cut into the object's chunks and
                // zero padded, each sealed with its index and honest last flag; content_len := its
                // length; reseal MP (the hash list is rehash's).
                val content = recipe(op.removePrefix("reseal_content "))
                val n = plaintexts.size
                require(content.size <= n * chunkPt) { "reseal_content: more than the class" }
                for (i in 0 until n) {
                    val from = minOf(i * chunkPt, content.size)
                    val to = minOf((i + 1) * chunkPt, content.size)
                    val p = content.copyOfRange(from, to).copyOf(chunkPt)
                    plaintexts[i] = p
                    chunks[i] = sealChunk(i, i == n - 1, oid, kind, p)
                }
                be(content.size.toLong(), 8).copyInto(mp, 20)
                resealManifest()
                return
            }
            val w = op.split(" ")
            fun n(k: Int) = w[k].toInt()
            when (w[0]) {
                "flip_fragment" -> {
                    val at = (n(1) % 4) * frag + n(2)
                    chunks[n(1) / 4][at] = (chunks[n(1) / 4][at].toInt() xor (1 shl n(3))).toByte()
                }
                "swap_fragments" -> {
                    val a = fragment(n(1))
                    val b = fragment(n(2))
                    putFragment(n(1), b)
                    putFragment(n(2), a)
                }
                "swap_chunks" -> java.util.Collections.swap(chunks, n(1), n(2))
                "foreign_fragment" -> {
                    val other = objects.getValue(w[2]).chunks
                    val j2 = n(3)
                    putFragment(n(1), other[j2 / 4].copyOfRange((j2 % 4) * frag, (j2 % 4 + 1) * frag))
                }
                "reseal_chunk" -> chunks[n(1)] = sealChunk(n(1), n(2) == 1, oid, kind, plaintexts[n(1)])
                "reseal_chunk_ad" -> chunks[n(1)] = sealChunk(n(1), n(1) == plaintexts.size - 1, hex(w[2]), n(3), plaintexts[n(1)])
                "reseal_chunk_pad" -> {
                    val p = plaintexts[n(1)].copyOf()
                    p[n(2)] = n(3).toByte()
                    chunks[n(1)] = sealChunk(n(1), n(1) == plaintexts.size - 1, oid, kind, p)
                }
                "rehash" -> {
                    for (j in 0 until 4 * chunks.size) sha256(fragment(j)).copyInto(mp, hashesAt + 32 * j)
                    resealManifest()
                }
                "manifest_set" -> {
                    hex(w[2]).copyInto(mp, n(1))
                    resealManifest()
                }
                "manifest_flip" -> blob[n(1)] = (blob[n(1)].toInt() xor (1 shl n(2))).toByte()
                "manifest_flip_rehash" -> {
                    blob[n(1)] = (blob[n(1)].toInt() xor (1 shl n(2))).toByte()
                    expected.manifestHash = sha256(blob)
                }
                "key" -> kf = hex(w[1])
                "expect" -> when (w[1]) {
                    "kind" -> expected.kind = n(2)
                    "view_once" -> expected.viewOnce = n(2) == 1
                    "class_code" -> expected.clazz = n(2)
                    else -> error("unknown field ${w[1]}")
                }
                "truncate_class" -> {
                    val c = n(1)
                    mp[3] = c.toByte()
                    be(minOf(u64(mp, 20), capacity(c)), 8).copyInto(mp, 20)
                    for (i in hashesAt + 32 * classes[c] until mpLen) mp[i] = 0
                    chunks = chunks.subList(0, classes[c] / 4).toMutableList()
                    plaintexts = plaintexts.subList(0, classes[c] / 4).toMutableList()
                    expected.clazz = c
                    resealManifest()
                }
                else -> error("unknown operation ${w[0]}")
            }
        }

        fun run(step: String): String = try {
            val r = Reader(kf, expected, blob)
            val w = step.split(" ")
            when (w[0]) {
                "open" -> {}
                "read" -> r.read(w[1].toInt(), chunks.getOrNull(w[1].toInt()))
                "validate" -> r.validate(chunks, base.walked)
                else -> error("unknown step $step")
            }
            "OK"
        } catch (e: Refused) {
            e.code
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The other files.

    @Test
    fun mediaDescriptorVectors() {
        var n = 0
        for (s in sections("media_descriptor.txt")) {
            val body = hex(s.get("body"))
            val got = try {
                val d = decodeDescriptor(body)
                assertArrayEquals("${s.name} re-encodes", body, encodeDescriptor(d))
                check("${s.name} kind", s.get("kind"), d.kind.toString())
                check("${s.name} view_once", s.get("view_once"), (d.flags and 1).toString())
                check("${s.name} class_code", s.get("class_code"), d.clazz.toString())
                check("${s.name} object_id", s.get("object_id"), hex(d.oid))
                check("${s.name} key_slot", s.get("key_slot"), hex(d.slot))
                check("${s.name} manifest_hash", s.get("manifest_hash"), hex(d.mh))
                check("${s.name} caption", s.get("caption_utf8"), hex(d.caption))
                "OK"
            } catch (e: Refused) {
                e.code
            }
            assertEquals(s.name, s.get("expect"), got)
            n++
        }
        assertTrue(n >= 17)
    }

    @Test
    fun mediaSniffVectors() {
        var n = 0
        for (s in sections("media_sniff.txt")) {
            assertEquals(s.name, s.get("expect"), sniff(recipe(s.get("input"))))
            n++
        }
        assertTrue(n >= 58)
    }

    @Test
    fun mediaJpegVectors() {
        var n = 0
        for (s in sections("media_jpeg.txt")) {
            val input = recipe(s.get("input"))
            val check = try {
                jpegWalk(input, strip = false)
                "OK"
            } catch (e: Refused) {
                e.code
            }
            assertEquals("${s.name} check", s.get("check"), check)
            val canonical = try {
                val (out, info) = jpegWalk(input, strip = true)
                assertEquals("${s.name} width", s.get("width"), info[0].toString())
                assertEquals("${s.name} height", s.get("height"), info[1].toString())
                // The output is canonical and a fixed point.
                assertArrayEquals(out, jpegWalk(out, strip = false).first)
                "sha256:" + hex(sha256(out))
            } catch (e: Refused) {
                e.code
            }
            assertEquals("${s.name} canonical", s.get("canonical"), canonical)
            n++
        }
        assertTrue(n >= 35)
    }
}
