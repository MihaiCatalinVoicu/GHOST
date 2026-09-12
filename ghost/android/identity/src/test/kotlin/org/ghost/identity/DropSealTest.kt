package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Points of small order in X25519 u-coordinate encoding (RFC 7748; the list libsodium refuses):
 * 0, 1, the two points of order 8, and p - 1, p, p + 1.
 */
internal val X25519_LOW_ORDER_POINTS = listOf(
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
)

/**
 * Drop sealing (Phase 8 design §9.3, §19.12; deviation X15): vectors from an independent
 * implementation, a differential test against the JDK's own X25519 and ChaCha20-Poly1305, the RFC
 * 7748 known answer of X25519 as used here, and fail-closed opening.
 */
class DropSealTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { it.toByte() })
    private val drop = root.inviteDropKeyPair(0)
    private val ns = root.inviteDropNamespace(0)
    private val credit = ByteArray(DropSeal.CREDIT_TOKEN_BYTES) { (if (it == 0) 0 else if (it == 1) 2 else 3 * it).toByte() }
    private val info = "ghost/v1/drop-seal".toByteArray()

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun vectors(resource: String): Map<String, String> =
        javaClass.getResourceAsStream(resource)!!.bufferedReader().readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }

    private fun creditPlaintext(token: ByteArray) = ByteArray(DropSeal.PLAINTEXT_BYTES).also { it[0] = 1; token.copyInto(it, 1) }

    @Test
    fun independentVectors() {
        val v = vectors("/drop_seal_vectors.txt")
        assertEquals(v.getValue("drop_namespace"), hex(ns))
        assertEquals(v.getValue("drop_pub"), hex(drop.publicKey))
        assertArrayEquals(drop.publicKey, X25519KeyPair.fromSecret(unhex(v.getValue("drop_secret"))).publicKey)
        val eph = X25519KeyPair.fromSecret(unhex(v.getValue("eph_credit_secret")))
        assertEquals(v.getValue("eph_credit_pub"), hex(eph.publicKey))
        assertEquals(v.getValue("credit_shared"), hex(eph.agree(drop.publicKey)))
        assertEquals(v.getValue("credit_shared"), hex(drop.agree(eph.publicKey)))
        assertEquals(v.getValue("credit_key"), hex(Hkdf.derive(eph.agree(drop.publicKey), ns, info, 32)))
        val token = unhex(v.getValue("credit_token"))
        assertEquals(v.getValue("credit_blob"), hex(DropSeal.seal(creditPlaintext(token), drop.publicKey, ns, eph)))
        val dummyEph = X25519KeyPair.fromSecret(unhex(v.getValue("eph_dummy_secret")))
        assertEquals(v.getValue("eph_dummy_pub"), hex(dummyEph.publicKey))
        assertEquals(v.getValue("dummy_blob"), hex(DropSeal.seal(ByteArray(DropSeal.PLAINTEXT_BYTES), drop.publicKey, ns, dummyEph)))
        val opened = DropSeal.open(unhex(v.getValue("credit_blob")), drop, ns)
        assertTrue(opened is DropSeal.Opened.Credit)
        assertArrayEquals(token, (opened as DropSeal.Opened.Credit).token)
        assertSame(DropSeal.Opened.Dummy, DropSeal.open(unhex(v.getValue("dummy_blob")), drop, ns))
    }

    @Test
    fun rfc7748X25519KnownAnswer() {
        val alice = X25519KeyPair.fromSecret(unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        val bob = X25519KeyPair.fromSecret(unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", hex(alice.publicKey))
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", hex(bob.publicKey))
        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(shared, hex(alice.agree(bob.publicKey)))
        assertEquals(shared, hex(bob.agree(alice.publicKey)))
    }

    /** Little-endian 32-byte u-coordinate of a JDK X25519 public key. */
    private fun le32(u: BigInteger): ByteArray {
        val be = u.toByteArray()
        return ByteArray(32) { i -> if (i < be.size) be[be.size - 1 - i] else 0 }
    }

    /** (scalar, public key) of a JDK-generated X25519 key pair. */
    private fun jdkKeyPair(): Pair<ByteArray, ByteArray> {
        val kp = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        return (kp.private as XECPrivateKey).scalar.get() to le32((kp.public as XECPublicKey).u)
    }

    private fun jdkAgree(scalar: ByteArray, peer: ByteArray): ByteArray {
        val kf = KeyFactory.getInstance("XDH")
        val priv = kf.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, scalar))
        val pub = kf.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger(1, peer.reversedArray())))
        return KeyAgreement.getInstance("XDH").run {
            init(priv)
            doPhase(pub, true)
            generateSecret()
        }
    }

    /** RFC 5869 with one 32-byte output block, on javax.crypto only (independent of Hkdf.kt). */
    private fun jdkHkdf(ikm: ByteArray, salt: ByteArray): ByteArray {
        val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(salt, "HmacSHA256")); doFinal(ikm) }
        return Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(prk, "HmacSHA256")); doFinal(info + 1.toByte()) }
    }

    private fun jdkAead(mode: Int, key: ByteArray, aad: ByteArray, input: ByteArray): ByteArray =
        Cipher.getInstance("ChaCha20-Poly1305").run {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(ByteArray(12)))
            updateAAD(aad)
            doFinal(input)
        }

    @Test
    fun matchesTheJdkX25519HkdfAndChaCha20Poly1305() {
        val random = SecureRandom()
        repeat(40) {
            val (dropScalar, dropPub) = jdkKeyPair()
            val (ephScalar, ephPub) = jdkKeyPair()
            val namespace = ByteArray(32).also(random::nextBytes)
            val plaintext = ByteArray(DropSeal.PLAINTEXT_BYTES).also(random::nextBytes)
            assertArrayEquals(dropPub, X25519KeyPair.fromSecret(dropScalar).publicKey)
            val ours = DropSeal.seal(plaintext, dropPub, namespace, X25519KeyPair.fromSecret(ephScalar))
            val theirs = ephPub + jdkAead(Cipher.ENCRYPT_MODE, jdkHkdf(jdkAgree(ephScalar, dropPub), namespace), namespace, plaintext)
            assertArrayEquals(theirs, ours)
            // And the other way: a credit sealed by the JDK opens here.
            val sealedByJdk = ephPub + jdkAead(Cipher.ENCRYPT_MODE, jdkHkdf(jdkAgree(ephScalar, dropPub), namespace), namespace, creditPlaintext(credit))
            val opened = DropSeal.open(sealedByJdk, X25519KeyPair.fromSecret(dropScalar), namespace)
            assertArrayEquals(credit, (opened as DropSeal.Opened.Credit).token)
        }
    }

    @Test
    fun creditAndDummyFillOneBucketAndOpenToWhatWasSealed() {
        val c = DropSeal.sealCredit(credit, drop.publicKey, ns)
        val d = DropSeal.sealDummy(drop.publicKey, ns)
        assertEquals(DropSeal.BLOB_BYTES, c.size)
        assertEquals(DropSeal.BLOB_BYTES, d.size)
        assertArrayEquals(credit, (DropSeal.open(c, drop, ns) as DropSeal.Opened.Credit).token)
        assertSame(DropSeal.Opened.Dummy, DropSeal.open(d, drop, ns))
        // A fresh ephemeral key per blob: no AEAD key, hence no (key, zero nonce) pair, is ever reused.
        val again = DropSeal.sealCredit(credit, drop.publicKey, ns)
        assertFalse(c.copyOfRange(0, 32).contentEquals(again.copyOfRange(0, 32)))
        assertFalse(c.contentEquals(again))
    }

    @Test
    fun tamperAtEveryByteOpensAsInvalid() {
        val c = DropSeal.sealCredit(credit, drop.publicKey, ns)
        for (i in c.indices) {
            for (flip in listOf(0x01, 0x80)) {
                val t = c.copyOf().also { it[i] = (it[i].toInt() xor flip).toByte() }
                assertSame("byte $i flip $flip", DropSeal.Opened.Invalid, DropSeal.open(t, drop, ns))
            }
        }
    }

    @Test
    fun anotherDropNamespaceOrLengthOpensAsInvalid() {
        val c = DropSeal.sealCredit(credit, drop.publicKey, ns)
        assertSame(DropSeal.Opened.Invalid, DropSeal.open(c, root.inviteDropKeyPair(1), ns))
        assertSame(DropSeal.Opened.Invalid, DropSeal.open(c, drop, root.inviteDropNamespace(1)))
        for (size in listOf(0, 32, 1023, 1025, 4096)) assertSame(DropSeal.Opened.Invalid, DropSeal.open(c.copyOf(size), drop, ns))
    }

    @Test
    fun onlyTheTwoPlaintextShapesAreAccepted() {
        fun open(plaintext: ByteArray) = DropSeal.open(DropSeal.seal(plaintext, drop.publicKey, ns, X25519KeyPair.generate()), drop, ns)
        val good = creditPlaintext(credit)
        assertTrue(open(good) is DropSeal.Opened.Credit)
        for (mark in listOf(2, 0x80, 0xff)) assertSame(DropSeal.Opened.Invalid, open(good.copyOf().also { it[0] = mark.toByte() }))
        for (i in listOf(355, 600, 975)) assertSame(DropSeal.Opened.Invalid, open(good.copyOf().also { it[i] = 1 }))
        for (i in listOf(1, 354, 355, 975)) assertSame(DropSeal.Opened.Invalid, open(ByteArray(DropSeal.PLAINTEXT_BYTES).also { it[i] = 1 }))
        assertThrows(IllegalArgumentException::class.java) { DropSeal.seal(ByteArray(975), drop.publicKey, ns, X25519KeyPair.generate()) }
        assertThrows(IllegalArgumentException::class.java) { DropSeal.sealCredit(ByteArray(353), drop.publicKey, ns) }
        assertThrows(IllegalArgumentException::class.java) { DropSeal.sealDummy(drop.publicKey, ByteArray(31)) }
    }

    @Test
    fun smallOrderAndNonCanonicalKeysAreRefused() {
        for (p in X25519_LOW_ORDER_POINTS) {
            assertThrows(p, IllegalArgumentException::class.java) { DropSeal.sealDummy(unhex(p), ns) }
            // A blob whose ephemeral key has small order would be keyed by a public constant.
            assertSame(p, DropSeal.Opened.Invalid, DropSeal.open(unhex(p) + ByteArray(DropSeal.BLOB_BYTES - 32), drop, ns))
            assertFalse(p, X25519KeyPair.isUsablePublicKey(unhex(p)))
        }
        assertTrue(X25519KeyPair.isUsablePublicKey(drop.publicKey))
        // Bit 255 is masked by RFC 7748, so a set bit would be a second spelling of the same key.
        val aliased = drop.publicKey.also { it[31] = (it[31].toInt() or 0x80).toByte() }
        assertFalse(X25519KeyPair.isUsablePublicKey(aliased))
        assertThrows(IllegalArgumentException::class.java) { DropSeal.sealDummy(aliased, ns) }
        val blob = DropSeal.sealCredit(credit, drop.publicKey, ns)
        assertSame(DropSeal.Opened.Invalid, DropSeal.open(blob.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() }, drop, ns))
    }

    @Test
    fun openedCreditsAndKeysAreRedacted() {
        val opened = DropSeal.open(DropSeal.sealCredit(credit, drop.publicKey, ns), drop, ns)
        assertEquals("Credit(redacted)", opened.toString())
        assertFalse(opened.toString().contains(hex(credit)))
        assertEquals("X25519KeyPair(redacted)", drop.toString())
        // The token accessor hands out a copy.
        (opened as DropSeal.Opened.Credit).token[0] = 9
        assertArrayEquals(credit, opened.token)
    }
}
