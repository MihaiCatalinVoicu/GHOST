package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The JDK replay of the channel vectors (Phase 10 design §5.2 rule (4), §12.2's Kotlin half;
 * slice S2b): `protocol/test-vectors/ch_derive.txt`, `ch_seal.txt`, `ch_content.txt`,
 * `ch_invite.txt` and `ch_join.txt`, **byte for byte**, two ways where the JDK can:
 *
 *  1. **through the host library** — the crate the shipped `libghost_client_net.so` links:
 *     [MlsNative] through the facade [ChannelCrypto] wherever the closed surface reaches a value
 *     (`channelOpen`'s `P`, `generation`'s namespace, credentials and `R_join`, `open`,
 *     `contentEncode`/`contentDecode`, `inviteParse`, `joinRequest`, `joinVerify`), and the test
 *     entry [MlsVectors] for what it never returns or draws at random (`RB_g`, `DB_g`, the seal keys,
 *     a seal or an invite under the vector's fixed salt, the Argon2id output);
 *  2. **independently in the JDK** — HMAC-SHA256 and HKDF, SHA-256, ChaCha20-Poly1305 and Ed25519
 *     of `javax.crypto` and `java.security`, written from §5 and §19.28 with no GHOST code — for
 *     every value those primitives compute; Argon2id is not in the JDK, so a password invite opens
 *     through the host library only.
 *
 * Skipped (not failed) without `-Dghost.dm.native=<ghost_dm_host>`, like every native test of this
 * module; CI and the slice's verification check `skipped=0` in the JUnit report.
 */
class ChannelVectorReplayTest {

    private val stateKey = ByteArray(32) { (it * 7 + 1).toByte() }
    private lateinit var crypto: ChannelCrypto

    @Before
    fun setUp() {
        val path = System.getProperty(MlsNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "ghost-dm-host is not loaded (-Dghost.dm.native); the channel vectors replay natively",
            !path.isNullOrEmpty() && MlsNative.isAvailable(),
        )
        crypto = (ChannelCrypto.open(stateKey) as MlsOutcome.Ok).value
    }

    @org.junit.After
    fun tearDown() {
        if (::crypto.isInitialized) crypto.close()
    }

    // ---- ch_derive --------------------------------------------------------------------------------

    @Test
    fun chDeriveReplaysThroughTheHostLibraryAndTheJdk() {
        val v = vectors("ch_derive.txt")
        val kEp = v.hex("epoch", "k_ep")
        val rEp = v.hex("epoch", "r_ep")
        assertArrayEquals(rEp, MlsVectors.call(MlsVectors.DERIVE_EPOCH, kEp)[0])
        assertArrayEquals(rEp, Jdk.hkdf(kEp, null, "ghost/v1/ch-recognition".ascii()))

        val g = v.hex("generation", "g")
        val ns = v.hex("generation", "ns")
        val rb = v.hex("generation", "read_base")
        val db = v.hex("generation", "deposit_base")
        val jk = v.hex("generation", "join_key")
        val rJoin = v.hex("generation", "r_join")
        assertArrayEquals(ns, Jdk.hkdf(g, null, "ghost/v1/ch/ns".ascii()))
        assertArrayEquals(rb, Jdk.hkdf(g, null, "ghost/v1/ch/read-base".ascii()))
        assertArrayEquals(db, Jdk.hkdf(g, null, "ghost/v1/ch/deposit-base".ascii()))
        assertArrayEquals(jk, Jdk.hkdf(g, null, "ghost/v1/ch/join-key".ascii()))
        assertArrayEquals(rJoin, Jdk.hkdf(jk, null, "ghost/v1/ch-recognition".ascii()))
        for (slot in intArrayOf(0, 7)) {
            val out = MlsVectors.call(MlsVectors.DERIVE_GENERATION, g, byteArrayOf(slot.toByte()))
            val rs = v.hex("generation", "read_secret_slot_$slot")
            val ds = v.hex("generation", "deposit_secret_slot_$slot")
            val expected = listOf(
                ns, rb, db, jk, rJoin, rs, ds,
                v.hex("generation", "read_credential_slot_$slot"),
                v.hex("generation", "read_verifier_slot_$slot"),
                v.hex("generation", "deposit_credential_slot_$slot"),
                v.hex("generation", "deposit_verifier_slot_$slot"),
            )
            assertEquals(expected.size, out.size)
            for (i in expected.indices) assertArrayEquals("generation output $i, slot $slot", expected[i], out[i])
            // The JDK half: the per-slot secrets, credentials v3 and verifiers of §5.2.
            assertArrayEquals(rs, Jdk.hkdf(rb, null, "ghost/v1/ch/read".ascii() + byteArrayOf(slot.toByte())))
            assertArrayEquals(ds, Jdk.hkdf(db, null, "ghost/v1/ch/deposit".ascii() + byteArrayOf(slot.toByte())))
            assertArrayEquals(expected[7], byteArrayOf(3, 1, slot.toByte()) + ns + rs)
            assertArrayEquals(expected[9], byteArrayOf(3, 3, slot.toByte()) + ns + ds)
            assertArrayEquals(
                expected[8],
                Jdk.sha256("ghost/v1/read-verifier".ascii(), byteArrayOf(slot.toByte()), ns, rs),
            )
            assertArrayEquals(
                expected[10],
                Jdk.sha256("ghost/v1/deposit-verifier".ascii(), byteArrayOf(slot.toByte()), ns, ds),
            )
        }
        // Through the shipped surface: `generation` on G wrapped under this context.
        val channel = v.hex("committers", "channel_id")
        val gEnv = MlsVectors.call(MlsVectors.WRAP_KEY, stateKey, byteArrayOf(2), channel, g, MlsVectors.u64(0))[0]
        val gen = (crypto.generation(channel, gEnv, 2, 0, byteArrayOf(0, 7)) as MlsOutcome.Ok).value
        assertArrayEquals(ns, gen.values.ns)
        assertArrayEquals(rJoin, gen.values.rJoin)
        assertEquals(2L, gen.values.generation)
        for ((index, slot) in intArrayOf(0, 7).withIndex()) {
            val s = gen.slots[index]
            assertEquals(slot, s.slot)
            assertArrayEquals(v.hex("generation", "read_credential_slot_$slot"), s.readCredential)
            assertArrayEquals(v.hex("generation", "read_verifier_slot_$slot"), s.readVerifier)
            assertArrayEquals(v.hex("generation", "deposit_credential_slot_$slot"), s.depositCredential)
            assertArrayEquals(v.hex("generation", "deposit_verifier_slot_$slot"), s.depositVerifier)
        }
        // A G of another channel's envelope does not open here (the AD binds the channel id).
        val other = channel.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(MlsCode.STATE_CORRUPT, crypto.generation(other, gEnv, 2, 0, byteArrayOf(0)).code)

        val salt = v.hex("seal_keys", "salt")
        val sealNs = v.hex("seal_keys", "ns")
        val keys = MlsVectors.call(MlsVectors.SEAL_KEYS, kEp, jk, salt, sealNs)
        assertArrayEquals(v.hex("seal_keys", "epoch_seal_key"), keys[0])
        assertArrayEquals(v.hex("seal_keys", "join_seal_key"), keys[1])
        assertArrayEquals(keys[0], Jdk.hkdf(kEp, salt, "ghost/v1/ch-seal".ascii() + sealNs))
        assertArrayEquals(keys[1], Jdk.hkdf(jk, salt, "ghost/v1/ch-seal".ascii() + sealNs))

        // The pseudonym key through `channelOpen`, and the same seed signing in the JDK.
        val ps = v.hex("pseudonym", "pseudonym_seed")
        val pk = v.hex("pseudonym", "pseudonym_key")
        assertArrayEquals(pk, (crypto.openChannel(channel, ps) as MlsOutcome.Ok).value)
        assertTrue(Jdk.seedSignsFor(ps, pk))

        val seed = v.hex("invite_key", "invite_seed")
        val invitePk = v.hex("invite_key", "invite_pk")
        assertArrayEquals(invitePk, MlsVectors.call(MlsVectors.INVITE_KEY, seed)[0])
        assertTrue(Jdk.seedSignsFor(seed, invitePk))

        val committers = v.get("committers", "committers").split(",").map { hex(it) }
        val digest = v.hex("committers", "digest")
        val joined = committers.fold(ByteArray(0)) { a, b -> a + b }
        assertArrayEquals(digest, MlsVectors.call(MlsVectors.COMMITTERS_DIGEST, channel, joined)[0])
        val reversed = committers.reversed().fold(ByteArray(0)) { a, b -> a + b }
        assertArrayEquals(
            v.hex("committers", "digest_reordered"),
            MlsVectors.call(MlsVectors.COMMITTERS_DIGEST, channel, reversed)[0],
        )
        assertArrayEquals(
            v.hex("committers", "digest_first_two"),
            MlsVectors.call(MlsVectors.COMMITTERS_DIGEST, channel, committers[0] + committers[1])[0],
        )
        val sorted = committers.sortedWith { a, b -> compareUnsigned(a, b) }
        assertArrayEquals(
            digest,
            Jdk.sha256("ghost/v1/ch/committers".ascii(), channel, byteArrayOf(committers.size.toByte()), *sorted.toTypedArray()),
        )

        val isalt = v.hex("invite_seal", "salt")
        val password = v.hex("invite_seal", "password_nfkd_utf8")
        // Kotlin's half of the password: NFKD UTF-8 from the characters typed.
        val typed = String(password, Charsets.UTF_8).toCharArray()
        assertArrayEquals(password, ChannelPassword.nfkdUtf8(typed))
        val seal = MlsVectors.call(MlsVectors.INVITE_SEAL, isalt, password)
        assertArrayEquals(v.hex("invite_seal", "open_seal_key"), seal[0])
        assertArrayEquals(v.hex("invite_seal", "argon2id_ikm"), seal[1])
        assertArrayEquals(v.hex("invite_seal", "password_seal_key"), seal[2])
        assertArrayEquals(seal[0], Jdk.hkdf(isalt, isalt, "ghost/v1/ch/invite-seal".ascii() + byteArrayOf(0)))
        assertArrayEquals(seal[2], Jdk.hkdf(seal[1], isalt, "ghost/v1/ch/invite-seal".ascii() + byteArrayOf(1)))

        val tag = MlsVectors.call(
            MlsVectors.ARGON2ID,
            MlsVectors.u32(32), MlsVectors.u32(3), MlsVectors.u32(4),
            v.hex("argon2id_rfc9106_5_3", "password"),
            v.hex("argon2id_rfc9106_5_3", "salt"),
            v.hex("argon2id_rfc9106_5_3", "secret"),
            v.hex("argon2id_rfc9106_5_3", "associated_data"),
        )[0]
        assertArrayEquals(v.hex("argon2id_rfc9106_5_3", "tag"), tag)
    }

    // ---- ch_seal ----------------------------------------------------------------------------------

    @Test
    fun chSealReplaysEveryModeAndBucketWithItsHintAndRefusals() {
        val v = vectors("ch_seal.txt")
        val d = vectors("ch_derive.txt")
        val channel = d.hex("committers", "channel_id")
        var replayed = 0
        for (section in v.sections().filter { it.startsWith("mode_") }) {
            val mode = Integer.parseInt(v.get(section, "mode"), 16)
            val epochKey = v.get(section, "key_class") == "epoch"
            val key = v.hex(section, "key")
            val ns = v.hex(section, "ns")
            val bucket = v.get(section, "bucket").toInt()
            val salt = v.hex(section, "salt")
            val order = v.hex(section, "order")
            val body = v.hex(section, "body")
            val orderEpoch = BigInteger(1, order.copyOfRange(0, 8)).toLong()
            val classByte = if (epochKey) 1 else 3
            // Through the host library, under the vector's fixed salt: the blob byte for byte.
            val blob = MlsVectors.call(
                MlsVectors.SEAL, byteArrayOf(classByte.toByte()), key, MlsVectors.u64(orderEpoch), ns,
                MlsVectors.u32(bucket.toLong()), byteArrayOf(mode.toByte()), salt, order, body,
            )[0]
            assertEquals(bucket, blob.size)
            v.opt(section, "blob")?.let { assertArrayEquals("$section blob", hex(it), blob) }
            assertArrayEquals("$section blob_sha256", v.hex(section, "blob_sha256"), Jdk.sha256(blob))
            assertArrayEquals("$section hint", v.hex(section, "hint"), blob.copyOfRange(16, 32))
            // The hint as Kotlin matches it, with the recognition key of the vector's key.
            val recognition = Jdk.hkdf(key, null, "ghost/v1/ch-recognition".ascii())
            assertArrayEquals(v.hex(section, "hint"), ChannelRecognition.hint(recognition, mode, salt))
            assertTrue(ChannelRecognition.matches(blob, recognition, mode))
            assertFalse(ChannelRecognition.matches(blob, recognition, mode xor 1))
            val decoy = ChannelRecognition.Candidate(ByteArray(32) { 9 }, mode, "decoy")
            val real = ChannelRecognition.Candidate(recognition, mode, "real")
            assertEquals("real", ChannelRecognition.matchFirst(blob, sequenceOf(decoy, real))?.value)
            assertNull(ChannelRecognition.matchFirst(blob, sequenceOf(decoy)))
            // The JDK half: the seal key, the AD and the plaintext layout of §5.6, opened with no
            // GHOST code at all.
            val k = Jdk.hkdf(key, salt, "ghost/v1/ch-seal".ascii() + ns)
            val ad = "ghost/v1/ch-seal".ascii() + byteArrayOf(1) + ns + MlsVectors.u32(bucket.toLong()) +
                byteArrayOf(mode.toByte())
            val p = Jdk.chachaOpen(k, ByteArray(12), ad, blob.copyOfRange(32, blob.size))
            assertEquals(bucket - 48, p.size)
            assertEquals(mode, p[0].toInt() and 0xff)
            val len = ((p[1].toInt() and 0xff) shl 16) or ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff)
            assertEquals(body.size, len)
            assertArrayEquals(order, p.copyOfRange(4, 20))
            assertArrayEquals(body, p.copyOfRange(20, 20 + len))
            assertTrue("padding is zero", p.copyOfRange(20 + len, p.size).all { it.toInt() == 0 })
            // Through the shipped surface: `open` with the key wrapped under this context.
            val env = MlsVectors.call(
                MlsVectors.WRAP_KEY, stateKey, byteArrayOf(classByte.toByte()), channel, key, MlsVectors.u64(orderEpoch),
            )[0]
            val opened = crypto.open(channel, env, classByte, ns, mode, blob)
            if (epochKey) {
                // A mode-0x11 body must be an MLS PrivateMessage of the key's epoch (CS-S7, §19.31
                // M1): the vector's body is not one, so the seal layer opens and the header check
                // refuses it — the vector replays the seal, the MLS half is the channel tests'.
                assertEquals("$section through open", MlsCode.NON_CANONICAL, opened.code)
            } else {
                val o = (opened as MlsOutcome.Ok).value
                assertArrayEquals(body, o.body)
                assertEquals(0L, o.order.epoch)
                assertNull(o.headerEpoch)
                for (refusal in v.get(section, "refused").split(",")) {
                    val (b, n, m) = mutate(refusal, blob, ns, mode)
                    assertEquals("$section $refusal", MlsCode.NOT_OPEN, crypto.open(channel, env, classByte, n, m, b).code)
                }
                // `seal` itself, with a fresh salt: the same layout, and it opens both ways.
                val fresh = (crypto.seal(channel, env, classByte, ns, bucket, mode, ChannelCrypto.SealOrder.NONE, body) as MlsOutcome.Ok).value
                assertEquals(bucket, fresh.size)
                assertFalse(fresh.copyOfRange(0, 16).contentEquals(salt))
                assertTrue(ChannelRecognition.matches(fresh, recognition, mode))
                assertArrayEquals(body, (crypto.open(channel, env, classByte, ns, mode, fresh) as MlsOutcome.Ok).value.body)
                val k2 = Jdk.hkdf(key, fresh.copyOfRange(0, 16), "ghost/v1/ch-seal".ascii() + ns)
                assertEquals(bucket - 48, Jdk.chachaOpen(k2, ByteArray(12), ad, fresh.copyOfRange(32, fresh.size)).size)
            }
            replayed++
        }
        assertEquals("nine mode and bucket sections", 9, replayed)

        // [capacity]: C(B) = B − 68, and `seal` refuses one byte more (NO_FIT).
        for (bucket in intArrayOf(4096, 16384, 65536)) assertEquals(bucket - 68, v.get("capacity", "c_$bucket").toInt())
        val jk = d.hex("generation", "join_key")
        val ns = d.hex("generation", "ns")
        val jkEnv = MlsVectors.call(MlsVectors.WRAP_KEY, stateKey, byteArrayOf(3), channel, jk, MlsVectors.u64(0))[0]
        assertEquals(MlsCode.OK, crypto.seal(channel, jkEnv, 3, ns, 4096, 0x12, ChannelCrypto.SealOrder.NONE, ByteArray(4028)).code)
        assertEquals(MlsCode.NO_FIT, crypto.seal(channel, jkEnv, 3, ns, 4096, 0x12, ChannelCrypto.SealOrder.NONE, ByteArray(4029)).code)
        assertEquals(
            MlsCode.NO_FIT,
            crypto.seal(channel, jkEnv, 3, ns, 65536, 0x12, ChannelCrypto.SealOrder.NONE, ByteArray(v.get("capacity", "no_fit").toInt())).code,
        )
        // A join key is not an epoch key, and a mode the key does not seal is refused.
        assertEquals(MlsCode.INVALID_POLICY, crypto.seal(channel, jkEnv, 3, ns, 4096, 0x11, ChannelCrypto.SealOrder.NONE, ByteArray(1)).code)
        assertEquals(MlsCode.STATE_CORRUPT, crypto.seal(channel, jkEnv, 1, ns, 4096, 0x11, ChannelCrypto.SealOrder.NONE, ByteArray(1)).code)
        // [ttl] has no JNI path: the TTL table of §5.8 is read by the slices that schedule blobs
        // (S4, S8). Its rows are present and well formed.
        assertEquals(6, v.keys("ttl").size)
    }

    // ---- ch_content -------------------------------------------------------------------------------

    @Test
    fun chContentDecodesAndReEncodesEveryCanonicalContentAndRefusesTheRest() {
        val v = vectors("ch_content.txt")
        var ok = 0
        var bad = 0
        for (section in v.sections()) {
            when {
                section.startsWith("ok_") -> {
                    val bytes = v.hex(section, "bytes")
                    val f = (ChannelCrypto.contentDecode(bytes) as MlsOutcome.Ok).value
                    assertEquals(v.get(section, "kind").toInt(), f.kind)
                    assertArrayEquals(v.hex(section, "op_id"), f.opId)
                    assertEquals(v.get(section, "author_minute").toLong(), f.authorMinute)
                    assertEquals(v.get(section, "timer_code").toInt(), f.timerCode)
                    expectOptional(v, section, "text", f.text)
                    expectOptional(v, section, "reply_to", f.replyTo)
                    expectOptional(v, section, "target", f.target)
                    expectOptional(v, section, "grapheme", f.grapheme)
                    expectOptional(v, section, "invite_id", f.inviteId)
                    expectOptional(v, section, "invite_pk", f.invitePk)
                    expectOptional(v, section, "sponsor_sig", f.sponsorSig)
                    expectOptional(v, section, "committers_digest", f.committersDigest)
                    expectOptional(v, section, "hpke_enc", f.hpkeEnc)
                    expectOptional(v, section, "ciphertext", f.ciphertext)
                    v.opt(section, "expiry_day")?.let { assertEquals(it.toLong(), f.expiryDay) }
                    v.opt(section, "pw_version")?.let {
                        assertEquals(if (it == "-") null else it.toInt(), f.pwVersion)
                    }
                    // Re-encoded from the fields: the same bytes.
                    assertArrayEquals("$section re-encodes", bytes, (ChannelCrypto.contentEncode(f) as MlsOutcome.Ok).value)
                    ok++
                }
                section.startsWith("bad_") -> {
                    val bytes = v.opt(section, "bytes")?.let { hex(it) } ?: run {
                        // `bad_post_text_16001`'s recipe: ok_post's header, TLV 0x0001 of 16 001 'a'.
                        val header = v.hex("ok_post", "bytes").copyOfRange(0, 23)
                        header + byteArrayOf(0, 1, (16001 ushr 8).toByte(), 16001.toByte()) + ByteArray(16001) { 0x61 }
                    }
                    assertEquals("$section", MlsCode.NON_CANONICAL, ChannelCrypto.contentDecode(bytes).code)
                    bad++
                }
            }
        }
        assertEquals(8, ok)
        assertEquals(17, bad)
        // [sizes]: the longest text post's content (16 000 bytes of text).
        val longest = ChannelContentFields(
            kind = 1, opId = ByteArray(16), authorMinute = 29_000_000, timerCode = 4, text = ByteArray(16000) { 0x61 },
        )
        assertEquals(v.get("sizes", "longest_text_post_content").toInt(), (ChannelCrypto.contentEncode(longest) as MlsOutcome.Ok).value.size)
        val tooLong = ChannelContentFields(
            kind = 1, opId = ByteArray(16), authorMinute = 29_000_000, timerCode = 4, text = ByteArray(16001) { 0x61 },
        )
        assertEquals(MlsCode.NON_CANONICAL, ChannelCrypto.contentEncode(tooLong).code)
    }

    // ---- ch_invite --------------------------------------------------------------------------------

    @Test
    fun chInviteBuildsParsesAndLinksEveryInviteByteForByte() {
        val v = vectors("ch_invite.txt")
        val sections = v.sections().filter { it.startsWith("open_") || it.startsWith("password_") }
        assertEquals(4, sections.size)
        for (section in sections) {
            val kdf = v.get(section, "kdf_code").toInt()
            val password = v.opt(section, "password")?.let { hex(it) }
            val name = v.opt(section, "name")?.let { hex(it) } ?: ByteArray(0)
            val invite = v.hex(section, "invite")
            assertEquals(ChannelInvite.INVITE_BYTES, invite.size)
            // Through the host library, under the vector's fixed salt: the invite byte for byte.
            val built = MlsVectors.call(
                MlsVectors.INVITE_BUILD,
                byteArrayOf(kdf.toByte()), password ?: ByteArray(0), v.hex(section, "salt"),
                byteArrayOf(v.get(section, "size_class").toInt().toByte()),
                byteArrayOf(v.get(section, "handshake_ttl_code").toInt().toByte()),
                v.hex(section, "channel_id"), MlsVectors.u32(v.get(section, "generation").toLong()),
                v.hex(section, "ns"), v.hex(section, "read_base"), v.hex(section, "deposit_base"),
                v.hex(section, "join_key"), v.hex(section, "invite_id"), v.hex(section, "invite_seed"),
                v.hex(section, "committers_digest"), MlsVectors.u32(v.get(section, "expiry_day").toLong()), name,
            )[0]
            assertArrayEquals("$section invite", invite, built)
            // The link: Kotlin's codec, the native one, and the vector.
            val link = v.get(section, "link")
            assertEquals(ChannelInvite.LINK_CHARS, link.length)
            assertEquals(link, ChannelInvite.toLink(invite))
            assertEquals(link, String(MlsVectors.call(MlsVectors.LINK, invite)[0], Charsets.US_ASCII))
            assertArrayEquals(invite, ChannelInvite.fromLink(link))
            assertEquals(kdf == 1, ChannelInvite.needsPassword(invite))
            // Parsed through the shipped surface: every field of the vector.
            val chars = password?.let { String(it, Charsets.UTF_8).toCharArray() }
            val p = (crypto.inviteParse(invite, chars, byteArrayOf(0)) as MlsOutcome.Ok).value
            assertEquals(kdf, p.kdfCode)
            assertEquals(Integer.parseInt(v.get(section, "suite"), 16), p.suite)
            assertEquals(v.get(section, "size_class").toInt(), p.sizeClass)
            assertEquals(v.get(section, "handshake_ttl_code").toInt(), p.handshakeTtlCode)
            assertArrayEquals(v.hex(section, "channel_id"), p.channelId)
            assertEquals(v.get(section, "generation").toLong(), p.generation)
            assertArrayEquals(v.hex(section, "ns"), p.ns)
            assertArrayEquals(v.hex(section, "invite_id"), p.inviteId)
            assertArrayEquals(v.hex(section, "invite_pk"), p.invitePk)
            assertArrayEquals(v.hex(section, "committers_digest"), p.committersDigest)
            assertEquals(v.get(section, "expiry_day").toLong(), p.expiryDay)
            assertArrayEquals(name, p.name)
            // The secrets came back wrapped; what Kotlin holds in clear matches the JDK.
            val jk = v.hex(section, "join_key")
            assertArrayEquals(Jdk.hkdf(jk, null, "ghost/v1/ch-recognition".ascii()), p.rJoin)
            val rs0 = Jdk.hkdf(v.hex(section, "read_base"), null, "ghost/v1/ch/read".ascii() + byteArrayOf(0))
            assertArrayEquals(byteArrayOf(3, 1, 0) + p.ns + rs0, p.slots.single().readCredential)
            assertFalse(p.jkEnv.indexOf(jk) >= 0)
            // The wrapped join key opens a join blob sealed under the vector's key.
            val blob = MlsVectors.call(
                MlsVectors.SEAL, byteArrayOf(3), jk, MlsVectors.u64(0), p.ns, MlsVectors.u32(4096), byteArrayOf(0x12),
                ByteArray(16) { 5 }, ByteArray(16), "join".ascii(),
            )[0]
            assertArrayEquals("join".ascii(), (crypto.open(p.channelId, p.jkEnv, 3, p.ns, 0x12, blob) as MlsOutcome.Ok).value.body)
            if (kdf == 0) {
                // The JDK opens an open invite on its own: the salt-derived key of §19.29.3.
                val salt = v.hex(section, "salt")
                val k = Jdk.hkdf(salt, salt, "ghost/v1/ch/invite-seal".ascii() + byteArrayOf(0))
                val inner = Jdk.chachaOpen(k, ByteArray(12), "ghost/v1/ch/invite-v2".ascii() + invite.copyOfRange(0, 18), invite.copyOfRange(18, invite.size))
                assertEquals(301, inner.size)
                assertArrayEquals(v.hex(section, "channel_id"), inner.copyOfRange(4, 36))
                assertArrayEquals(v.hex(section, "invite_seed"), inner.copyOfRange(184, 216))
            }
        }
        // [refusals], on password_name_0.
        val invite = v.hex("password_name_0", "invite")
        val right = String(v.hex("password_name_0", "password"), Charsets.UTF_8)
        val wrong = v.get("refusals", "wrong_password")
        assertEquals(MlsCode.PASSWORD_REQUIRED, crypto.inviteParse(invite, null, ByteArray(0)).code)
        assertEquals(MlsCode.WRONG_PASSWORD, crypto.inviteParse(invite, wrong.toCharArray(), ByteArray(0)).code)
        val flipped = invite.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        assertEquals(MlsCode.WRONG_PASSWORD, crypto.inviteParse(flipped, right.toCharArray(), ByteArray(0)).code)
        val openHeader = invite.copyOf().also { it[1] = 0 }
        assertEquals(MlsCode.WRONG_PASSWORD, crypto.inviteParse(openHeader, right.toCharArray(), ByteArray(0)).code)
        val version = invite.copyOf().also { it[0] = 1 }
        assertEquals(MlsCode.NON_CANONICAL, crypto.inviteParse(version, right.toCharArray(), ByteArray(0)).code)
        val kdf2 = invite.copyOf().also { it[1] = 2 }
        assertEquals(MlsCode.NON_CANONICAL, crypto.inviteParse(kdf2, right.toCharArray(), ByteArray(0)).code)
        assertEquals(
            MlsCode.NON_CANONICAL,
            crypto.inviteParse(invite.copyOf(invite.size - 1), right.toCharArray(), ByteArray(0)).code,
        )
        assertEquals(v.get("refusals", "link_characters").toInt(), ChannelInvite.toLink(invite).length)
        // A link that is not exactly canonical has no bytes.
        val link = ChannelInvite.toLink(invite)
        assertNull(ChannelInvite.fromLink(link.uppercase()))
        assertNull(ChannelInvite.fromLink(link.dropLast(1)))
        assertNull(ChannelInvite.fromLink(link.replaceRange(20, 21, "1")))
        // An unpaired surrogate has no UTF-8 encoding: refused before any native call.
        assertEquals(MlsCode.NON_CANONICAL, crypto.inviteParse(invite, charArrayOf('a', '\uD800'), ByteArray(0)).code)
    }

    // ---- ch_join ----------------------------------------------------------------------------------

    @Test
    fun chJoinRequestsAreSignedAndVerifiedByteForByte() {
        val v = vectors("ch_join.txt")
        val d = vectors("ch_derive.txt")
        val kp = v.hex("key_package", "bytes")
        assertEquals(v.get("key_package", "length").toInt(), kp.size)
        assertArrayEquals(v.hex("key_package", "sha256"), Jdk.sha256(kp))
        val channel = v.hex("join_request", "channel_id")
        val inviteId = v.hex("join_request", "invite_id")
        val seed = v.hex("join_request", "invite_seed")
        val invitePk = d.hex("invite_key", "invite_pk")
        // The invite_sig message of §5.6 and the signature, in the JDK.
        val message = v.hex("join_request", "invite_sig_message")
        assertArrayEquals("ghost/v1/ch/join".ascii() + channel + inviteId + Jdk.sha256(kp), message)
        assertTrue(Jdk.verify(invitePk, message, v.hex("join_request", "invite_sig")))
        // Through the shipped surface: the invite seed wrapped as `inviteParse` returns it, and the
        // request byte for byte (Ed25519 is deterministic).
        val seedEnv = MlsVectors.call(MlsVectors.WRAP_KEY, stateKey, byteArrayOf(5), channel, seed, MlsVectors.u64(0))[0]
        val body = (crypto.joinRequest(channel, inviteId, seedEnv, kp) as MlsOutcome.Ok).value
        assertArrayEquals(v.hex("join_request", "body"), body)
        val verified = (crypto.joinVerify(channel, body, invitePk, null, 2) as MlsOutcome.Ok).value
        assertEquals(1, verified.requestType)
        assertArrayEquals(kp, verified.keyPackage)
        assertArrayEquals(v.hex("key_package", "kp_ref"), verified.kpRef)
        assertArrayEquals(v.hex("key_package", "pseudonym_key"), verified.pseudonym)
        assertArrayEquals(v.hex("key_package", "box_pk"), verified.boxPk)
        val bind = v.hex("key_package", "kp_bind")
        assertArrayEquals(bind.copyOfRange(1, 33), verified.kpBind.bytes(MlsField.CHANNEL_ID))
        assertEquals(bind[33].toInt(), verified.kpBind.byte(MlsField.PURPOSE))
        assertEquals(BigInteger(1, bind.copyOfRange(34, 38)).toLong(), verified.kpBind.u32(MlsField.DAY))
        assertArrayEquals(inviteId, verified.auth.bytes(MlsField.INVITE_ID))
        // Another invite key, another channel, a KeyPackage of another channel: refused.
        assertEquals(MlsCode.BAD_SIGNATURE, crypto.joinVerify(channel, body, ByteArray(32) { 1 }, null, 2).code)
        val other = channel.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(MlsCode.INVALID_KEYPACKAGE, crypto.joinVerify(other, body, invitePk, null, 2).code)
        assertEquals(MlsCode.STATE_CORRUPT, crypto.joinRequest(other, inviteId, seedEnv, kp).code)

        // [rejoin_request]: the sample KeyPackage is a **join** KeyPackage, so the codec vector is
        // not a valid rejoin — its signature verifies in the JDK, and the shipped surface refuses
        // the purpose on both sides (§19.3: a rejoin carries a rejoin KeyPackage).
        val ps = v.hex("rejoin_request", "pseudonym_seed")
        val p = d.hex("pseudonym", "pseudonym_key")
        val rmsg = v.hex("rejoin_request", "rejoin_sig_message")
        assertTrue(Jdk.verify(p, rmsg, v.hex("rejoin_request", "rejoin_sig")))
        assertArrayEquals(
            "ghost/v1/ch/rejoin".ascii() + channel + MlsVectors.u32(3) + MlsVectors.u32(20726) + MlsVectors.u64(41) +
                v.hex("rejoin_request", "last_hash") + Jdk.sha256(kp),
            rmsg,
        )
        assertArrayEquals(p, (crypto.openChannel(channel, ps) as MlsOutcome.Ok).value)
        assertEquals(
            MlsCode.WRONG_PURPOSE,
            crypto.rejoinRequest(channel, 3, 20726, 41, v.hex("rejoin_request", "last_hash"), kp).code,
        )
        assertEquals(MlsCode.WRONG_PURPOSE, crypto.joinVerify(channel, v.hex("rejoin_request", "body"), null, p, 3).code)

        // [sponsor_sig] and [welcome_blob]: their layouts and the signature, in the JDK (the native
        // side signs `sponsor_sig` inside `inviteBuild` and reads the Welcome blob in `welcomeJoin`).
        val smsg = v.hex("sponsor_sig", "message")
        assertArrayEquals(
            "ghost/v1/ch/invite".ascii() + channel + inviteId + v.hex("sponsor_sig", "invite_pk") + MlsVectors.u32(20732),
            smsg,
        )
        assertTrue(Jdk.verify(v.hex("sponsor_sig", "sponsor_key"), smsg, v.hex("sponsor_sig", "sponsor_sig")))
        val kpRef = v.hex("welcome_blob", "kp_ref")
        val welcome = v.hex("welcome_blob", "welcome")
        assertArrayEquals(
            byteArrayOf(1, kpRef.size.toByte()) + kpRef + byteArrayOf(0, 0, welcome.size.toByte()) + welcome,
            v.hex("welcome_blob", "bytes"),
        )
    }

    // ---- helpers ----------------------------------------------------------------------------------

    private fun mutate(kind: String, blob: ByteArray, ns: ByteArray, mode: Int): Triple<ByteArray, ByteArray, Int> =
        when {
            kind.startsWith("flip_byte_") -> {
                val i = kind.removePrefix("flip_byte_").toInt()
                Triple(blob.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }, ns, mode)
            }
            kind == "truncate_1" -> Triple(blob.copyOf(blob.size - 1), ns, mode)
            kind == "other_ns" -> Triple(blob, ns.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, mode)
            kind == "other_mode" -> Triple(blob, ns, if (mode == 0x12) 0x13 else 0x12)
            else -> error("unknown mutation $kind")
        }

    private fun expectOptional(v: Vectors, section: String, key: String, actual: ByteArray?) {
        val want = v.opt(section, key) ?: return
        if (want == "-") assertTrue("$section $key absent or empty", actual == null || actual.isEmpty()) else assertArrayEquals("$section $key", hex(want), actual)
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (c != 0) return c
        }
        return a.size - b.size
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        outer@ for (i in 0..size - needle.size) {
            for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    private fun String.ascii(): ByteArray = toByteArray(Charsets.US_ASCII)

    /** A vector file: `section -> key -> value`, as the Rust replay reads it. */
    class Vectors(private val sections: Map<String, Map<String, String>>) {
        fun sections(): List<String> = sections.keys.toList()
        fun keys(section: String): Set<String> = sections.getValue(section).keys
        fun opt(section: String, key: String): String? = sections[section]?.get(key)
        fun get(section: String, key: String): String = opt(section, key) ?: error("$section.$key missing")
        fun hex(section: String, key: String): ByteArray = hex(get(section, key))
    }

    private fun vectors(name: String): Vectors {
        val file = File("../../protocol/test-vectors/$name").canonicalFile
        assertTrue("$file must exist", file.isFile)
        val out = LinkedHashMap<String, LinkedHashMap<String, String>>()
        var section = ""
        for (line in file.readLines()) {
            if (line.startsWith("#") || line.isBlank()) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length - 1)
                out[section] = LinkedHashMap()
                continue
            }
            val at = line.indexOf(" = ")
            if (at > 0) out.getValue(section)[line.substring(0, at)] = line.substring(at + 3)
        }
        return Vectors(out)
    }

    /** The JDK's own primitives: no GHOST code, no native code. */
    private object Jdk {
        fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            for (p in parts) mac.update(p)
            return mac.doFinal()
        }

        /** HKDF-SHA256 (RFC 5869), L = 32; an absent salt is 32 zero bytes. */
        fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray): ByteArray {
            val prk = hmac(salt ?: ByteArray(32), ikm)
            return hmac(prk, info, byteArrayOf(1))
        }

        fun sha256(vararg parts: ByteArray): ByteArray {
            val d = MessageDigest.getInstance("SHA-256")
            for (p in parts) d.update(p)
            return d.digest()
        }

        fun chachaOpen(key: ByteArray, nonce: ByteArray, ad: ByteArray, ct: ByteArray): ByteArray {
            val c = Cipher.getInstance("ChaCha20-Poly1305")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            c.updateAAD(ad)
            return c.doFinal(ct)
        }

        private fun publicKey(raw: ByteArray): java.security.PublicKey {
            val le = raw.copyOf()
            val xOdd = (le[31].toInt() and 0x80) != 0
            le[31] = (le[31].toInt() and 0x7f).toByte()
            val y = BigInteger(1, le.reversedArray())
            return KeyFactory.getInstance("Ed25519")
                .generatePublic(EdECPublicKeySpec(NamedParameterSpec.ED25519, EdECPoint(xOdd, y)))
        }

        fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            val s = Signature.getInstance("Ed25519")
            s.initVerify(publicKey(publicKey))
            s.update(message)
            return s.verify(signature)
        }

        /** The JDK's Ed25519 key of [seed] signs, and the signature verifies under [publicKey]. */
        fun seedSignsFor(seed: ByteArray, publicKey: ByteArray): Boolean {
            val key = KeyFactory.getInstance("Ed25519")
                .generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed))
            val s = Signature.getInstance("Ed25519")
            s.initSign(key)
            val message = "ghost channel vector".toByteArray()
            s.update(message)
            return verify(publicKey, message, s.sign())
        }
    }

    private companion object {
        fun hex(s: String): ByteArray =
            if (s == "-") ByteArray(0) else ByteArray(s.length / 2) { Integer.parseInt(s.substring(2 * it, 2 * it + 2), 16).toByte() }
    }
}
