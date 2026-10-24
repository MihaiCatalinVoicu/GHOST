package org.ghost.update

import org.ghost.network.NetworkException

/**
 * The Kotlin half of the stored-facts codec (Phase 14 design §9.6, mirroring
 * `ghost-client-update`'s `codec.rs` byte for byte): the JNI boundary speaks this blob, the
 * SQLCipher columns store its fields. Big-endian throughout; any wrong length or trailing byte
 * is `malformed_response`, never a partial read (the strict-reader rule of the network module).
 */
object UpdateCodec {
    const val VERSION: Int = 1

    class Facts(
        val network: Int,
        val epoch: ByteArray,
        val epochVersionCode: Int,
        /** The chain as a GHRC document (what `nativeStart` returns and `nativeAccept` re-derives). */
        val chain: ByteArray,
        /** The trusted root's own version: the last root of the chain (`root_version` column). */
        val rootVersion: Int,
        val manifestRoot: Int,
        val manifestSeq: Long,
        val manifestSha256: ByteArray?,
        val manifestFile: ByteArray?,
        val proofFile: ByteArray?,
        val floorVersionCode: Int,
        val floorRoot: Int,
        /** §7.5's flag; the root version at which it was seen is the `conflict_root` column and
         * travels through the store, not the blob (the native decision sets and clears the flag;
         * the column value is what the triggers order). */
        val conflict: Boolean,
        val rootConflict: Boolean,
    )

    private class Reader(private val raw: ByteArray) {
        var pos: Int = 0
            private set

        fun u8(): Int {
            if (pos + 1 > raw.size) throw NetworkException(MALFORMED)
            return raw[pos++].toInt() and 0xff
        }

        fun u32(): Int {
            if (pos + 4 > raw.size) throw NetworkException(MALFORMED)
            return (u8() shl 24) or (u8() shl 16) or (u8() shl 8) or u8()
        }

        fun u64(): Long = ((u32().toLong() shl 32) or (u32().toLong() and 0xffffffffL))

        fun bytes(n: Int): ByteArray {
            if (n < 0 || pos + n > raw.size) throw NetworkException(MALFORMED)
            val out = raw.copyOfRange(pos, pos + n)
            pos += n
            return out
        }

        fun lp32(): ByteArray {
            val n = u32()
            if (n < 0 || n > raw.size) throw NetworkException(MALFORMED)
            return bytes(n)
        }

        fun end() {
            if (pos != raw.size) throw NetworkException(MALFORMED)
        }
    }

    private fun le32(out: java.io.ByteArrayOutputStream, n: Int) {
        out.write((n ushr 24) and 0xff)
        out.write((n ushr 16) and 0xff)
        out.write((n ushr 8) and 0xff)
        out.write(n and 0xff)
    }

    private fun le64(out: java.io.ByteArrayOutputStream, n: Long) {
        le32(out, (n ushr 32).toInt())
        le32(out, (n and 0xffffffffL).toInt())
    }

    private fun lp32(out: java.io.ByteArrayOutputStream, data: ByteArray) {
        le32(out, data.size)
        out.write(data)
    }

    /** Packs the facts to the wire/blob layout of `codec.rs`. */
    fun encode(f: Facts): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(VERSION)
        out.write(f.epoch)
        le32(out, f.epochVersionCode)
        lp32(out, f.chain)
        le32(out, f.rootVersion)
        le32(out, f.manifestRoot)
        le64(out, f.manifestSeq)
        if (f.manifestFile != null && f.manifestSha256 != null && f.proofFile != null) {
            out.write(1)
            lp32(out, f.manifestFile)
            out.write(f.manifestSha256)
            lp32(out, f.proofFile)
        } else {
            out.write(0)
        }
        le32(out, f.floorVersionCode)
        le32(out, f.floorRoot)
        out.write(if (f.conflict) 1 else 0)
        out.write(if (f.rootConflict) 1 else 0)
        return out.toByteArray()
    }

    /**
     * Decodes the blob strictly. `network` travels in its own column (§9.6), so it is an input
     * here, not read from the blob.
     */
    fun decode(blob: ByteArray, network: Int): Facts {
        val r = Reader(blob)
        if (r.u8() != VERSION) throw NetworkException(MALFORMED)
        val epoch = r.bytes(32)
        val epochVersionCode = r.u32()
        if (epochVersionCode == 0) throw NetworkException(MALFORMED)
        val chain = r.lp32()
        val rootVersion = r.u32()
        val manifestRoot = r.u32()
        val manifestSeq = r.u64()
        val (sha, manifest, proof) = if (r.u8() == 1) {
            val manifest = r.lp32()
            val sha = r.bytes(32)
            val proof = r.lp32()
            Triple(sha as ByteArray?, manifest, proof)
        } else {
            Triple(null, null, null)
        }
        val floorVersionCode = r.u32()
        val floorRoot = r.u32()
        val conflict = r.u8() != 0
        val rootConflict = r.u8() != 0
        r.end()
        return Facts(
            network = network,
            epoch = epoch,
            epochVersionCode = epochVersionCode,
            chain = chain,
            rootVersion = rootVersion,
            manifestRoot = manifestRoot,
            manifestSeq = manifestSeq,
            manifestSha256 = sha,
            manifestFile = manifest,
            proofFile = proof,
            floorVersionCode = floorVersionCode,
            floorRoot = floorRoot,
            conflict = conflict,
            rootConflict = rootConflict,
        )
    }

    const val MALFORMED: String = "malformed_response"
}
