package org.ghost.crypto.bridge

import org.junit.Assert.assertEquals

/**
 * The vector-replay entry point of the host library (Phase 10 design §12.2's Kotlin half; slice
 * S2b): `ghost_client_mls::testvec`, exported by `ghost-dm-host` alone as
 * `Java_org_ghost_crypto_bridge_MlsVectors_run`. Its declaration lives in this **test** source set
 * only: G-M6 refuses a native declaration in any production source set but [MlsNative]'s, and
 * G-DM5 refuses this class in a release mapping.
 *
 * The input is positional (`(u32_be(len) || bytes)*`), the reply `code(1)` and the outputs the
 * same way; [call] asserts `OK` and returns the outputs.
 */
object MlsVectors {
    const val WRAP_KEY: Int = 1
    const val DERIVE_EPOCH: Int = 2
    const val DERIVE_GENERATION: Int = 3
    const val SEAL_KEYS: Int = 4
    const val INVITE_KEY: Int = 5
    const val COMMITTERS_DIGEST: Int = 6
    const val INVITE_SEAL: Int = 7
    const val ARGON2ID: Int = 8
    const val SEAL: Int = 9
    const val INVITE_BUILD: Int = 10
    const val LINK: Int = 11
    const val PANIC_IN_CONTEXT: Int = 12

    /** `[state_key, channel_id, pseudonym_seed, rows, day] → [proposal]`: a real MLS Proposal by
     *  the member (F-S4-6, MM-30's test entry; `MlsContext::test_proposal`). */
    const val PROPOSAL: Int = 13

    /** `[state_key, channel_id, pseudonym_seed, not_before(u64), not_after(u64), rows, day] →
     *  [key_package, commit]`: a commit adding a finite-lifetime (non-canonical) KeyPackage
     *  (MM-46 / SCN-CM's lifetime cases; `MlsContext::test_finite_lifetime_commit`). */
    const val FINITE_KP_COMMIT: Int = 14

    /** The case runner (the library is loaded by [MlsNative]). */
    @JvmStatic
    external fun run(kind: Int, input: ByteArray): ByteArray?

    /** The positional input of [items]. */
    fun input(vararg items: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (item in items) {
            out.write(u32(item.size.toLong()))
            out.write(item)
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
        assertEquals("MlsVectors case $kind", MlsCode.OK.wire, code)
        return outputs
    }

    /** A big-endian `u32`. */
    fun u32(value: Long): ByteArray = ByteArray(4) { i -> (value ushr (24 - 8 * i)).toByte() }

    /** A big-endian `u64`. */
    fun u64(value: Long): ByteArray = ByteArray(8) { i -> (value ushr (56 - 8 * i)).toByte() }
}
