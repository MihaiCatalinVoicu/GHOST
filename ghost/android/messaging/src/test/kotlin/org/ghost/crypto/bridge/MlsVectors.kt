package org.ghost.crypto.bridge

/**
 * The test-vectors entry of the host library, as `:crypto-bridge`'s test source declares it
 * (`MlsVectors.kt` there): the JNI symbol `Java_org_ghost_crypto_bridge_MlsVectors_run` is
 * registered by `ghost-dm-host` under this fully-qualified name, so the declaration must match it
 * byte for byte. `:crypto-bridge`'s test outputs are not on this module's test classpath, and this
 * file is a test source (G-M6 scans production sources only). Only the one case the channel
 * engine's tests need is listed.
 */
object MlsVectors {
    /** `[state_key, channel_id, pseudonym_seed, not_before(u64), not_after(u64), rows, day] ->
     *  [key_package, commit]`: a commit adding a finite-lifetime (non-canonical) KeyPackage
     *  (MM-46 / SCN-CM's lifetime cases; `MlsContext::test_finite_lifetime_commit`). */
    const val FINITE_KP_COMMIT: Int = 14

    /** The case runner (the library is loaded by [MlsNative]). */
    @JvmStatic
    external fun run(kind: Int, input: ByteArray): ByteArray?

    /** The positional input of [run]. */
    fun input(vararg items: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (item in items) {
            out.write(u32(item.size.toLong()))
            out.write(item)
        }
        return out.toByteArray()
    }

    /**
     * The raw row encoding the test-vectors entries' `rows_of` parses — `scope(1) | u32 | key |
     * u32 | env` per row — which is **not** the facade's `MlsRow.encode` TLV array.
     */
    fun rows(rows: List<MlsRow>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (r in rows) {
            out.write(r.scope)
            out.write(u32(r.key.size.toLong()))
            out.write(r.key)
            out.write(u32(r.env.size.toLong()))
            out.write(r.env)
        }
        return out.toByteArray()
    }

    /** Runs a case and returns its code and outputs. */
    fun raw(kind: Int, vararg items: ByteArray): Pair<Int, List<ByteArray>> {
        check(MlsNative.isAvailable()) { "the host library is not loaded" }
        val reply = requireNotNull(run(kind, input(*items))) { "no reply" }
        val outputs = ArrayList<ByteArray>()
        var offset = 1
        while (offset < reply.size) {
            var length = 0
            for (i in 0 until 4) length = (length shl 8) or (reply[offset + i].toInt() and 0xff)
            offset += 4
            outputs.add(reply.copyOfRange(offset, offset + length))
            offset += length
        }
        return (reply[0].toInt() and 0xff) to outputs
    }

    /** Runs a case that must succeed. */
    fun call(kind: Int, vararg items: ByteArray): List<ByteArray> {
        val (code, outputs) = raw(kind, *items)
        check(code == MlsCode.OK.wire) { "MlsVectors case $kind answered $code" }
        return outputs
    }

    /** A big-endian `u32`. */
    fun u32(value: Long): ByteArray = ByteArray(4) { i -> (value ushr (24 - 8 * i)).toByte() }

    /** A big-endian `u64`. */
    fun u64(value: Long): ByteArray = ByteArray(8) { i -> (value ushr (56 - 8 * i)).toByte() }
}
