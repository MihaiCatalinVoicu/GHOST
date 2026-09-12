package org.ghost.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Invariant T16 extended (Phase 8 design §8.8) and FR-1.5/FR-1.6 acceptance for Invite v2: tampered
 * (at every bit and in every field), expired, replayed, wrong-length and v1 invites are refused; an
 * invite carries no web host and no identity key; two invites of one inviter share no key.
 */
class InviteTest {
    private val root = RootEntropy.fromRaw(ByteArray(32) { it.toByte() })

    /** 2025-09-10 08:00 UTC: UTC day 20341, ISO week 2905, invite epoch 726 (days 20332..20359). */
    private val now = 1_757_491_200L
    private val today = 20_341L
    private val epoch = 726L
    private val token = token(0x42)
    private val schedule = TestSchedule().add(token, "invite", epoch)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    /**
     * An RFC 9578 type 0x0002 token shape; its content is opaque to :identity. The step of 13 keeps
     * the bytes from ever running 00 01 02 ... like the fixed root entropy the leak check looks for.
     */
    private fun token(fill: Int) = ByteArray(Invite.TOKEN_BYTES) { i -> (if (i == 0) 0 else if (i == 1) 2 else fill + 13 * i).toByte() }

    /**
     * Stand-in for the native `nativeVerifyToken(token, INVITE)`: known tokens with their (kind,
     * epoch). It answers an epoch only for INVITE tokens and refuses everything else, like the ES check.
     */
    private class TestSchedule : Invite.TokenCheck {
        private val known = HashMap<List<Byte>, Pair<String, Long>>()
        fun add(token: ByteArray, kind: String, epoch: Long) = apply { known[token.toList()] = kind to epoch }
        override fun inviteEpoch(token: ByteArray): Long? = known[token.toList()]?.takeIf { it.first == "invite" }?.second
    }

    private fun create(index: Int = 0, expiry: Long = today + 14, tok: ByteArray = token, tokEpoch: Long = epoch, slots: List<Int> = listOf(5, 0, 17)) =
        Invite.create(tok, tokEpoch, expiry, slots, root.inviteKeys(index))

    private fun parse(text: String, store: Invite.NonceStore = Invite.InMemoryNonceStore(), at: Long = now, check: Invite.TokenCheck = schedule): Invite =
        Invite.parseAndVerify(text, at, check, store)

    /** Invite fields laid out and signed by the test itself (design §8.2), for re-signed tampering. */
    private inner class Draft {
        var version = 2
        var token = this@InviteTest.token
        var nonce = ByteArray(16) { (0xa0 + it).toByte() }
        var expiry = today + 14
        var namespace = root.inviteDropNamespace(0)
        var slots = byteArrayOf(5, 0, 17)
        var dropKey = root.inviteDropKeyPair(0).publicKey
        var signer = root.inviteSigningKeyPair(0)
        var claimedSigner: ByteArray? = null

        fun payload(): ByteArray {
            val signed = ByteBuffer.allocate(Invite.PAYLOAD_BYTES - 64).put(version.toByte()).put(token).put(nonce).putInt(expiry.toInt())
                .put(namespace).put(slots).put(dropKey).put(claimedSigner ?: signer.publicKey).array()
            return signed + signer.sign(signed)
        }

        fun text(): String = Invite.SCHEME + ZBase32.encode(payload())
    }

    private fun vectors(resource: String): Map<String, String> =
        javaClass.getResourceAsStream(resource)!!.bufferedReader().readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }

    @Test
    fun roundTripAcceptsAValidInvite() {
        val inv = create()
        val parsed = parse(inv.encode())
        assertEquals(inv, parsed)
        assertEquals(2, parsed.version)
        assertArrayEquals(token, parsed.inviteToken)
        assertEquals(today + 14, parsed.expiryDay)
        assertEquals(listOf(5, 0, 17), parsed.dropSlots)
        // An invite laid out by the test itself parses too: the layout is the one of design §8.2.
        val draft = Draft()
        assertArrayEquals(draft.payload(), parse(draft.text()).bytes())
    }

    @Test
    fun wireFormIs538BytesIn876Characters() {
        val inv = create()
        assertEquals(538, Invite.PAYLOAD_BYTES)
        assertEquals(538, inv.bytes().size)
        val text = inv.encode()
        assertEquals(876, text.length)
        assertTrue(text.startsWith("ghost://invite/"))
        // One QR code in byte mode: version 21-L holds 929 bytes, 20-L only 858 (design §8.2).
        assertTrue(text.length in 859..929)
    }

    @Test
    fun independentWireVector() {
        val v = vectors("/invite_vectors.txt")
        val tok = unhex(v.getValue("invite_token"))
        val nonce = unhex(v.getValue("nonce"))
        val tokenEpoch = v.getValue("invite_epoch").toLong()
        val fixedNonce = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                nonce.copyInto(bytes)
            }
        }
        val inv = Invite.create(
            tok, tokenEpoch, v.getValue("expiry_day").toLong(), v.getValue("drop_slots").split(" ").map { it.toInt() },
            root.inviteKeys(v.getValue("index").toInt()), fixedNonce,
        )
        assertEquals(v.getValue("payload"), hex(inv.bytes()))
        assertEquals(v.getValue("text"), inv.encode())
        assertEquals(inv, parse(v.getValue("text"), check = TestSchedule().add(tok, "invite", tokenEpoch)))
    }

    @Test
    fun payloadCarriesNoIdentityKeyWebHostOrPayoutAddress() {
        val inv = create()
        val bytes = inv.bytes()
        fun inviteBranch(label: String, index: Int) =
            Hkdf.derive(root.rawForWrapping(), null, label.toByteArray() + byteArrayOf((index ushr 8).toByte(), index.toByte()), 32)
        val identityMaterial = listOf(
            root.identityKeyPair().publicKey, root.deriveBranch(DerivationLabels.IDENTITY), root.rawForWrapping(),
            root.deriveBranch(DerivationLabels.MESSAGING), root.deriveBranch(DerivationLabels.BACKUP_WRAP),
            // The retired one-per-identity invite key would link every invite of one inviter.
            Ed25519KeyPair.fromSeed(root.deriveBranch(DerivationLabels.INVITE_SIGNING)).publicKey,
            // The per-invite secrets stay with the inviter; only their public halves travel.
            inviteBranch(DerivationLabels.INVITE_SIGNING, 0), X25519KeyPair.clamp(inviteBranch(DerivationLabels.INVITE_DROP_KEY, 0)),
        )
        for (m in identityMaterial) {
            assertFalse(hex(m), (0..bytes.size - m.size).any { i -> m.indices.all { bytes[i + it] == m[it] } })
        }
        val text = inv.encode()
        assertFalse(text.contains(root.publicIdentity().encode()))
        // After the scheme only z-base-32 follows: no host, path, port, query or payout address.
        assertTrue(Regex("[ybndrfg8ejkmcpqxot1uwisza345h769]{861}").matches(text.removePrefix(Invite.SCHEME)))
    }

    @Test
    fun everyBitFlipOfEveryByteIsRejectedWithoutConsumingANonce() {
        val inv = create()
        val bytes = inv.bytes()
        val store = Invite.InMemoryNonceStore()
        val canaries = listOf(hex(token), hex(inv.dropKey), hex(inv.dropNamespace), hex(inv.nonce))
        var rejected = 0
        for (i in bytes.indices) for (bit in 0 until 8) {
            val t = bytes.copyOf()
            t[i] = (t[i].toInt() xor (1 shl bit)).toByte()
            try {
                parse(Invite.SCHEME + ZBase32.encode(t), store)
            } catch (e: Invite.Rejection) {
                rejected++
                for (c in canaries) assertFalse(e.message!!.contains(c))
            }
        }
        assertEquals(bytes.size * 8, rejected)
        // No tampered copy recorded the nonce: the genuine invite is still accepted, once.
        assertEquals(inv, parse(inv.encode(), store))
        assertThrows(Invite.Rejection.Replayed::class.java) { parse(inv.encode(), store) }
    }

    @Test
    fun everyFieldTamperedAndResignedIsRejected() {
        val access = token(0x10)
        val credit = token(0x11)
        val unknown = token(0x12)
        val wrongOrigin = token(0x13)
        val twoBack = token(0x15)
        val next = token(0x16)
        // The schedule check refuses a token whose challenge names another origin (verified in Rust);
        // here it is a token the stand-in knows but refuses.
        val es = TestSchedule().add(token, "invite", epoch).add(access, "access", 2905).add(credit, "credit", 223)
            .add(wrongOrigin, "refused", epoch).add(twoBack, "invite", epoch - 2).add(next, "invite", epoch + 1)
        fun expect(kind: Class<out Invite.Rejection>, what: String, edit: Draft.() -> Unit) {
            val text = Draft().apply(edit).text()
            val e = assertThrows(what, Invite.Rejection::class.java) { parse(text, check = es) }
            assertEquals(what, kind, e.javaClass)
        }
        val malformed = Invite.Rejection.Malformed::class.java
        val version = Invite.Rejection.UnsupportedVersion::class.java
        val refused = Invite.Rejection.TokenRefused::class.java
        val expired = Invite.Rejection.Expired::class.java
        for (v in listOf(0, 1, 3, 255)) expect(version, "version $v") { this.version = v }
        for (type in listOf(0x0000, 0x0001, 0x0003, 0x0200, 0xffff)) {
            expect(malformed, "token type $type") { token = token.copyOf().also { it[0] = (type ushr 8).toByte(); it[1] = type.toByte() } }
        }
        expect(malformed, "slot 32") { slots = byteArrayOf(5, 32, 17) }
        expect(malformed, "slot 255") { slots = byteArrayOf(-1, 0, 17) }
        expect(malformed, "repeated slot") { slots = byteArrayOf(5, 17, 5) }
        for (point in X25519_LOW_ORDER_POINTS) expect(malformed, "drop key $point") { dropKey = unhex(point) }
        expect(malformed, "drop key with bit 255 set") { dropKey = dropKey.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() } }
        expect(malformed, "expiry after the acceptance window") { expiry = Invite.maxExpiryDay(epoch) + 1 }
        expect(malformed, "largest expiry") { expiry = 0xFFFF_FFFFL }
        expect(expired, "expiry today") { expiry = today }
        expect(expired, "expiry yesterday") { expiry = today - 1 }
        expect(refused, "unknown token") { token = unknown }
        expect(refused, "an ACCESS token") { token = access }
        expect(refused, "a CREDIT token") { token = credit }
        expect(refused, "wrong challenge origin") { token = wrongOrigin }
        expect(refused, "next epoch, not open yet") { token = next; expiry = today + 1 }
        expect(expired, "epoch - 2 within its window") { token = twoBack; expiry = Invite.maxExpiryDay(epoch - 2) }
        expect(malformed, "epoch - 2 beyond its window") { token = twoBack; expiry = today + 1 }
        expect(Invite.Rejection.BadSignature::class.java, "another signing key claimed") { claimedSigner = root.inviteSigningKeyPair(1).publicKey }
        expect(Invite.Rejection.BadSignature::class.java, "the identity key claimed") { claimedSigner = root.identityKeyPair().publicKey }
        // The previous epoch is still accepted until its window closes (the issuer accepts e_now - 1).
        val previous = token(0x14)
        val prev = Draft().apply { token = previous; expiry = Invite.maxExpiryDay(epoch - 1) }
        assertArrayEquals(prev.payload(), parse(prev.text(), check = TestSchedule().add(previous, "invite", epoch - 1)).bytes())
    }

    @Test
    fun everyLengthOtherThan538IsRejected() {
        val bytes = create().bytes()
        for (n in 0..700) {
            if (n == Invite.PAYLOAD_BYTES) continue
            val t = bytes.copyOf(n)
            val e = assertThrows("length $n", Invite.Rejection::class.java) { parse(Invite.SCHEME + ZBase32.encode(t)) }
            assertTrue("length $n: ${e.javaClass}", e is Invite.Rejection.Malformed || e is Invite.Rejection.UnsupportedVersion)
        }
        val text = create().encode()
        for (bad in listOf(text.dropLast(1), text + "y", text.dropLast(2), text + "yy", Invite.SCHEME)) {
            assertThrows(Invite.Rejection.Malformed::class.java) { parse(bad) }
        }
    }

    @Test
    fun aV1InviteIsRefusedAsUnsupported() {
        // The Phase 3 layout: version = 1 || token(32) || commitment(32) || nonce(16) || expiry(8) || key(32) || signature(64).
        val signer = root.inviteSigningKeyPair(0)
        val signed = ByteBuffer.allocate(1 + 32 + 32 + 16 + 8 + 32).put(1.toByte()).put(ByteArray(32) { 0x42 }).put(ByteArray(32) { 7 })
            .put(ByteArray(16) { 9 }).putLong(now + 3600).put(signer.publicKey).array()
        val v1 = Invite.SCHEME + ZBase32.encode(signed + signer.sign(signed))
        // 185 bytes = 296 z-base-32 characters: another length than v2, refused by its version byte.
        assertEquals(Invite.SCHEME.length + 296, v1.length)
        val e = assertThrows(Invite.Rejection.UnsupportedVersion::class.java) { parse(v1) }
        assertEquals("invite version unsupported", e.message)
        // A v2-sized payload that says version 1 is refused the same way.
        assertThrows(Invite.Rejection.UnsupportedVersion::class.java) { parse(Draft().apply { version = 1 }.text()) }
    }

    @Test
    fun expiryIsTheFirstDayOnWhichTheInviteIsRefused() {
        assertEquals(20_388L, Invite.maxExpiryDay(epoch))
        assertEquals(epoch, Invite.inviteEpochOfDay(today))
        // Usable on every day before expiry_day, refused from expiry_day on.
        val inv = create(expiry = today + 1)
        assertEquals(inv, parse(inv.encode()))
        assertThrows(Invite.Rejection.Expired::class.java) { parse(inv.encode(), at = (today + 1) * 86_400) }
        // The latest expiry is the end of the issuer's acceptance window: still usable in the next epoch.
        val longest = create(expiry = Invite.maxExpiryDay(epoch))
        val lastDay = (Invite.maxExpiryDay(epoch) - 1) * 86_400 + 3600
        assertEquals(epoch + 1, Invite.inviteEpochOfDay(lastDay / 86_400))
        assertEquals(longest, parse(longest.encode(), at = lastDay))
        assertThrows(Invite.Rejection.Expired::class.java) { parse(longest.encode(), at = Invite.maxExpiryDay(epoch) * 86_400) }
        // Creation refuses an expiry beyond the window.
        assertThrows(IllegalArgumentException::class.java) { create(expiry = Invite.maxExpiryDay(epoch) + 1) }
    }

    @Test
    fun theInviteGridIsTheOneOfDesignSection4() {
        // ISO weeks start on Monday 1970-01-05 (day 4); an invite epoch is 4 weeks.
        assertEquals(4L + 28 * 2, Invite.maxExpiryDay(0))
        assertEquals(0L, Invite.inviteEpochOfDay(4))
        assertEquals(0L, Invite.inviteEpochOfDay(31))
        assertEquals(1L, Invite.inviteEpochOfDay(32))
        assertEquals(-1L, Invite.inviteEpochOfDay(3))
        // week(t) = floor((t - 345 600) / 604 800) and invite_epoch = floor(week / 4).
        for (t in listOf(now, 1_800_000_000L, 345_600L + 604_800L * 4 - 1, 345_600L + 604_800L * 4)) {
            assertEquals(Math.floorDiv(Math.floorDiv(t - 345_600L, 604_800L), 4L), Invite.inviteEpochOfDay(Math.floorDiv(t, 86_400L)))
        }
    }

    @Test
    fun replayIsRejectedAndARefusedInviteKeepsItsNonce() {
        val inv = create()
        val store = Invite.InMemoryNonceStore()
        // Refusals come before the nonce is recorded.
        assertThrows(Invite.Rejection.TokenRefused::class.java) { parse(inv.encode(), store, check = Invite.TokenCheck { null }) }
        assertThrows(Invite.Rejection.Expired::class.java) { parse(inv.encode(), store, at = (today + 30) * 86_400) }
        assertEquals(inv, parse(inv.encode(), store))
        assertThrows(Invite.Rejection.Replayed::class.java) { parse(inv.encode(), store) }
        // Another capitalisation is the same payload, hence the same nonce.
        assertThrows(Invite.Rejection.Replayed::class.java) { parse(Invite.SCHEME + inv.encode().removePrefix(Invite.SCHEME).uppercase(), store) }
    }

    @Test
    fun nonAsciiLookalikesOfTheAlphabetAreRejectedWithoutConsumingTheNonce() {
        val inv = create()
        val body = inv.encode().removePrefix(Invite.SCHEME)
        val store = Invite.InMemoryNonceStore()
        fun replaced(letter: Char, by: Char): String {
            val at = body.indexOf(letter)
            assertTrue("no '$letter' in the body", at >= 0)
            return Invite.SCHEME + body.substring(0, at) + by + body.substring(at + 1)
        }
        // U+212A KELVIN SIGN lowercases to 'k' and keeps the length; U+0130 lowercases to 'i' plus a
        // combining dot. Only ASCII case folds, so neither is a second spelling of the invite.
        for (text in listOf(replaced('k', 'K'), replaced('i', 'İ'), replaced('k', 'ｋ'))) {
            assertEquals(Invite.SCHEME.length + 861, text.length)
            assertThrows(Invite.Rejection.Malformed::class.java) { parse(text, store) }
        }
        // ASCII upper case is the same invite; the lookalikes consumed no nonce.
        assertEquals(inv, parse(replaced('k', 'K'), store))
        assertThrows(Invite.Rejection.Replayed::class.java) { parse(inv.encode(), store) }
    }

    @Test
    fun webHostsSchemesAndUrlStructureAreRejected() {
        val body = create().encode().removePrefix(Invite.SCHEME)
        val bad = listOf(
            "https://example.org/invite/$body", "http://ghost.example/$body", "ghost://invite$body", "GHOST://invite/$body",
            Invite.SCHEME + body + "?ref=x", Invite.SCHEME + body + "#x", Invite.SCHEME + "abc.onion/" + body,
            Invite.SCHEME + body.substring(0, 400) + " " + body.substring(400),
        )
        for (text in bad) assertThrows(text.take(40), Invite.Rejection.Malformed::class.java) { parse(text) }
    }

    @Test
    fun twoInvitesOfOneInviterCarryDifferentKeysAndDrops() {
        val a = parse(create(index = 0).encode())
        val b = parse(create(index = 1).encode())
        assertFalse(a.inviteSigningPublicKey.contentEquals(b.inviteSigningPublicKey))
        assertFalse(a.dropKey.contentEquals(b.dropKey))
        assertFalse(a.dropNamespace.contentEquals(b.dropNamespace))
        assertFalse(a.nonce.contentEquals(b.nonce))
        for ((i, inv) in listOf(a, b).withIndex()) {
            assertArrayEquals(root.inviteSigningKeyPair(i).publicKey, inv.inviteSigningPublicKey)
            assertArrayEquals(root.inviteDropKeyPair(i).publicKey, inv.dropKey)
            assertArrayEquals(root.inviteDropNamespace(i), inv.dropNamespace)
            assertFalse(inv.inviteSigningPublicKey.contentEquals(root.identityKeyPair().publicKey))
        }
    }

    @Test
    fun createRefusesMalformedInputs() {
        assertThrows(IllegalArgumentException::class.java) { create(tok = ByteArray(353)) }
        assertThrows(IllegalArgumentException::class.java) { create(tok = token.copyOf().also { it[1] = 1 }) }
        for (slots in listOf(listOf(1, 1, 2), listOf(0, 1), listOf(0, 1, 2, 3), listOf(0, 1, 32), listOf(-1, 0, 1))) {
            assertThrows(slots.toString(), IllegalArgumentException::class.java) { create(slots = slots) }
        }
        assertThrows(IllegalArgumentException::class.java) { create(expiry = -1) }
        assertThrows(IllegalArgumentException::class.java) { root.inviteKeys(-1) }
        assertThrows(IllegalArgumentException::class.java) { root.inviteKeys(65536) }
    }

    @Test
    fun holdersOfInviteMaterialAreRedacted() {
        val inv = create()
        val keys = root.inviteKeys(0)
        val canaries = listOf(hex(token), hex(inv.dropKey), hex(inv.dropNamespace), hex(inv.nonce), hex(keys.signing.publicKey))
        for (s in listOf(inv.toString(), keys.toString(), keys.drop.toString())) {
            assertTrue(s, s.endsWith("(redacted)"))
            for (c in canaries) assertFalse(s.contains(c))
        }
        // Accessors hand out copies: the parsed invite cannot be changed through them.
        inv.inviteToken[5] = 0
        inv.dropNamespace[0] = 0
        assertArrayEquals(token, inv.inviteToken)
        assertArrayEquals(root.inviteDropNamespace(0), inv.dropNamespace)
    }
}
