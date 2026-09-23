package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The JDK replay of `protocol/test-vectors/dm_derive.txt` `[pq_root]` (Phase 9 design §9.4, §15.2;
 * slice S13): the PQ-C root derivation recomputed with `java.security` and `javax.crypto` alone,
 * from the recorded X-Wing shared secret on.
 *
 * The JDK 17 provider set has no ML-KEM, so the KEM half is anchored on the Rust side, where
 * `client-core/dm/tests/pq_root.rs` re-derives the recorded key, ciphertext and `ss` with RustCrypto
 * `x-wing`, independently of libcrux. Everything after `ss` — the salt over both Olm identities in
 * their roles, the generation, the key and the ciphertext; the HKDF over `root_rand || ss`; the
 * pair ratchet's base-week key over the result — is a second implementation here, in another
 * language, of the text of §9.4. No native library is needed, so this test never skips.
 */
class PqRootVectorTest {

    private fun section(name: String): Map<String, String> {
        // The module is ghost/android/crypto-bridge; the vectors are ghost/protocol/test-vectors.
        val file = File("../../protocol/test-vectors/dm_derive.txt").canonicalFile
        assertTrue("$file must exist", file.isFile)
        val out = LinkedHashMap<String, String>()
        var inside = false
        for (raw in file.readLines()) {
            val line = raw.trimEnd('\r')
            if (line.startsWith("[")) {
                inside = line == "[$name]"
                continue
            }
            if (!inside || line.isEmpty() || line.startsWith("#")) continue
            val at = line.indexOf(" = ")
            out[line.substring(0, at)] = line.substring(at + 3)
        }
        assertTrue("dm_derive.txt has no [$name] section", out.isNotEmpty())
        return out
    }

    private fun hex(values: Map<String, String>, key: String): ByteArray {
        val text = requireNotNull(values[key]) { "$key missing" }
        require(text.length % 2 == 0) { "$key is not hex" }
        return ByteArray(text.length / 2) { i -> text.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return digest.digest()
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 with L = 32: one expand block. An empty salt is 32 zero bytes, as the RFC says. */
    private fun hkdf32(ikm: ByteArray, salt: ByteArray?, info: ByteArray): ByteArray {
        val prk = hmac(salt ?: ByteArray(32), ikm)
        return hmac(prk, info + byteArrayOf(1))
    }

    private fun u32(value: Long): ByteArray = ByteBuffer.allocate(4).putInt(value.toInt()).array()

    private fun u64(value: Long): ByteArray = ByteBuffer.allocate(8).putLong(value).array()

    private fun root(v: Map<String, String>, offerer: ByteArray, target: ByteArray): ByteArray {
        val label = "ghost/v1/dm/pq-root".toByteArray(Charsets.US_ASCII)
        val salt = sha256(
            label,
            offerer,
            target,
            u32(v.getValue("peer_gen_id").toLong()),
            hex(v, "peer_xwing_pk"),
            hex(v, "xwing_ct"),
        )
        return hkdf32(hex(v, "root_rand") + hex(v, "ss"), salt, label)
    }

    @Test
    fun theRecordedPqRootIsSection94ComputedByTheJdk() {
        val v = section("pq_root")
        assertEquals("ghost/v1/dm/pq-root", v["pq_root_label"])
        assertEquals(1_216, hex(v, "peer_xwing_pk").size)
        assertEquals(1_120, hex(v, "xwing_ct").size)
        assertEquals(32, hex(v, "ss").size)

        val label = "ghost/v1/dm/pq-root".toByteArray(Charsets.US_ASCII)
        val salt = sha256(
            label,
            hex(v, "oi_offerer"),
            hex(v, "oi_target"),
            u32(v.getValue("peer_gen_id").toLong()),
            hex(v, "peer_xwing_pk"),
            hex(v, "xwing_ct"),
        )
        assertArrayEquals("the salt", hex(v, "salt"), salt)

        val root = root(v, hex(v, "oi_offerer"), hex(v, "oi_target"))
        assertArrayEquals("the offerer's root", hex(v, "pq_root"), root)
        assertArrayEquals("the opener's root", hex(v, "pq_root_decapsulated"), root)

        // The roles are an order: swapped, the salt and the root are another pair's.
        val swapped = root(v, hex(v, "oi_target"), hex(v, "oi_offerer"))
        assertArrayEquals(hex(v, "pq_root_roles_swapped"), swapped)
        assertFalse(swapped.contentEquals(root))

        // `root_rand` alone is not the root, and nothing downstream knows the root's form: the
        // pair ratchet's base-week key is §6.3's HKDF over it.
        assertFalse(hex(v, "root_rand").contentEquals(root))
        val week = hkdf32(
            root,
            null,
            "ghost/v1/dm/pair-epoch".toByteArray(Charsets.US_ASCII) + u64(v.getValue("base_week").toLong()),
        )
        assertArrayEquals(hex(v, "week_key_2873"), week)
    }

    /** §7.1's layout of the recorded TLV value, field by field. */
    @Test
    fun theRecordedSealRootPqValueHasTheRegistryLayout() {
        val v = section("pq_root")
        val tlv = hex(v, "seal_root_pq")
        assertEquals(1_166, tlv.size)
        assertEquals(1_166L, v.getValue("seal_root_pq_len").toLong())
        assertArrayEquals(hex(v, "root_rand"), tlv.copyOfRange(0, 32))
        assertArrayEquals(u64(v.getValue("base_week").toLong()), tlv.copyOfRange(32, 40))
        assertArrayEquals(byteArrayOf(0, v.getValue("root_gen").toInt().toByte()), tlv.copyOfRange(40, 42))
        assertArrayEquals(u32(v.getValue("peer_gen_id").toLong()), tlv.copyOfRange(42, 46))
        assertArrayEquals(hex(v, "xwing_ct"), tlv.copyOfRange(46, 1_166))
    }
}
