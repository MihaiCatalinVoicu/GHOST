package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * PQ-C through the **real** closed surface (Phase 9 design §9.4, §7.1 R-C5, §22.8.2, §22.8.6;
 * slice S13): `pqRootSeal`, `pqRootOpen`, and the two PQ-C TLVs in and out of `l0Encode` and
 * `l0Decode`, between two contexts in one process.
 *
 * What only this layer can get wrong, and what each test pins:
 *  - the **roles** of the two Olm identities in the root's salt, which the offerer passes as
 *    (own, peer) and the opener as (peer, own) — swapped, both sides compute *a* root and the
 *    conversation goes silent ([anOfferedPqRootOpensToTheSameWeekKeysOnBothSides]);
 *  - the generation the opener loads, and the typed refusals of §22.8.2 and §22.8.6
 *    ([aPqRootOpensOnlyWithTheGenerationItNames], [anInvalidPeerKeyIsInvalidKeyAtTheOffer]);
 *  - the slack rule at the JNI boundary, where the bucket crosses to Kotlin: a PQ-C TLV rides
 *    exactly when it fits the bucket the body chose, and the bucket never moves (PQ4's JNI half,
 *    [theSlackRuleDecidesWhatRidesAndTheBucketNeverMoves]);
 *  - the `pq_key` round trip and its whole-key validation on receipt
 *    ([aPqKeyRoundTripsAndAnInvalidOneIsFlaggedNotApplied]).
 *
 * Skipped without `-Dghost.dm.native`, like every native test of this module.
 */
class DmPqRootNativeTest {

    private val baseWeek = 2_880L

    private fun requireNative() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        assertTrue(
            "the host library must load from $path: ${DmNative.loadFailure()}",
            DmNative.isAvailable(),
        )
    }

    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    private fun context(branch: Int): Long {
        val handle = DmSessions.openContext(
            messagingBranch = bytes(branch, 32),
            identitySeed = bytes(branch + 1, 32),
            sessionStateKey = bytes(branch + 2, 32),
        )
        assertNotNull("ctxOpen", handle)
        return handle!!
    }

    /** A (the offerer, `contactOfB` its id for B) and B (the target, with one generation). */
    private class Parties(
        val a: Long,
        val b: Long,
        val oiA: ByteArray,
        val oiB: ByteArray,
        val genB: TestGeneration,
        val contactOfB: ByteArray,
        val contactOfA: ByteArray,
    )

    private fun <T> withPair(body: (Parties) -> T): T {
        val a = context(0x61)
        val b = context(0x71)
        try {
            return body(
                Parties(
                    a = a,
                    b = b,
                    oiA = TestGeneration.olmIdentityOf(a),
                    oiB = TestGeneration.olmIdentityOf(b),
                    genB = TestGeneration.of(b, genId = 0x7e_01_02_03),
                    contactOfB = bytes(0x3b, 16),
                    contactOfA = bytes(0x3a, 16),
                ),
            )
        } finally {
            DmSessions.closeContext(a)
            DmSessions.closeContext(b)
        }
    }

    private fun pqOffer(p: Parties, rootGen: Int = 3): DmPairing.Offer {
        val result = DmPairing.pqOffer(
            p.a, p.contactOfB, rootGen, baseWeek, p.oiB, p.genB.genId.toLong() and 0xffff_ffffL,
            p.genB.xwingPublic,
        )
        assertTrue("pqRootSeal: $result", result is DmPairing.PqOfferResult.Ok)
        return (result as DmPairing.PqOfferResult.Ok).offer
    }

    private fun encodeText(
        handle: Long,
        body: ByteArray,
        contactId: ByteArray = DM_NO_CONTACT,
        offerRootGen: Int = 0,
        offerEnv: ByteArray = DM_NO_BYTES,
        pqKey: DmContent.PqKeyCandidate? = null,
    ): DmContent.Encoded.Ok {
        val encoded = DmContent.encode(
            handle = handle,
            kind = DmContent.Kind.TEXT,
            messageId = bytes(0x44, 16),
            authorMinute = 29_010_000L,
            minuteIndex = 0,
            timerCode = 4,
            timerVersion = 0,
            quoteRef = null,
            body = body,
            contactId = contactId,
            offerRootGen = offerRootGen,
            offerEnv = offerEnv,
            pqKey = pqKey,
        )
        assertTrue("encode: $encoded", encoded is DmContent.Encoded.Ok)
        return encoded as DmContent.Encoded.Ok
    }

    private fun decode(handle: Long, contactId: ByteArray, l0: ByteArray): DmContent.Decoded {
        val decoded = DmContent.decode(handle, contactId, l0)
        assertTrue("decode: $decoded", decoded is DmContent.DecodeResult.Ok)
        return (decoded as DmContent.DecodeResult.Ok).content
    }

    private fun weekKey(
        handle: Long,
        contactId: ByteArray,
        direction: DmSeal.PairDirection,
        rootGen: Int,
        rootEnv: ByteArray,
    ): DmPairing.WeekKey {
        val keys = DmPairing.keys(
            handle, contactId, direction, rootGen, DmPairing.From.ROOT, rootEnv, baseWeek, baseWeek,
            baseWeek,
        )
        assertTrue("pairKeys: $keys", keys is DmPairing.KeysResult.Ok)
        return (keys as DmPairing.KeysResult.Ok).weeks.single()
    }

    /**
     * §9.4 end to end: A offers a PQ root for `B → A`, the offer rides in an L0, B decodes it, opens
     * it with the generation it names, and the week key B will seal with is the one A recognises
     * — the same recognition key on both sides, which is what makes a pair envelope from B open.
     */
    @Test
    fun anOfferedPqRootOpensToTheSameWeekKeysOnBothSides() {
        requireNative()
        withPair { p ->
            val offer = pqOffer(p)
            assertEquals("a PQ offer_env is 1 166 + 28 bytes (§13.6)", 1_194, offer.offerEnv.size)
            assertEquals(60, offer.rootEnv.size)

            val encoded = encodeText(
                p.a, "with a pq root".toByteArray(), p.contactOfB, offerRootGen = 3,
                offerEnv = offer.offerEnv,
            )
            assertTrue("the PQ offer rode", encoded.sealRootPqRode)
            assertFalse("and it replaced the classical form", encoded.sealRootRode)
            assertEquals(4096, encoded.bucket)

            val content = decode(p.b, p.contactOfA, encoded.l0)
            assertNull("no classical root", content.sealRoot)
            val received = requireNotNull(content.sealRootPq)
            assertEquals(3, received.rootGen)
            assertEquals(baseWeek, received.baseWeek)
            assertEquals(p.genB.genId.toLong() and 0xffff_ffffL, received.peerGenId)
            assertEquals(1_166, received.tlv.size)

            val opened = DmPairing.pqOpen(
                p.b, p.contactOfA, received.rootGen, received.peerGenId, p.genB.secretsEnv,
                p.genB.fallbackPublic, received.tlv, p.oiA,
            )
            assertTrue("pqRootOpen: $opened", opened is DmPairing.PqOpenResult.Ok)
            opened as DmPairing.PqOpenResult.Ok
            assertEquals(3, opened.rootGen)
            assertEquals(baseWeek, opened.baseWeek)

            // A's in-key (the offer's root) and B's out-key (the opened root) are one key.
            val atA = weekKey(p.a, p.contactOfB, DmSeal.PairDirection.IN, 3, offer.rootEnv)
            val atB = weekKey(p.b, p.contactOfA, DmSeal.PairDirection.OUT, 3, opened.rootEnv)
            assertArrayEquals(atA.recognitionKey, atB.recognitionKey)

            // Swapped roles at the opener — B passing its own identity as the offerer's — derive
            // another root: the silent failure the role-typed parties exist to prevent.
            val swapped = DmPairing.pqOpen(
                p.b, p.contactOfA, 3, received.peerGenId, p.genB.secretsEnv, p.genB.fallbackPublic,
                received.tlv, p.oiB,
            ) as DmPairing.PqOpenResult.Ok
            val atBSwapped = weekKey(p.b, p.contactOfA, DmSeal.PairDirection.OUT, 3, swapped.rootEnv)
            assertFalse(atA.recognitionKey.contentEquals(atBSwapped.recognitionKey))

            // Two offers to the same key are two roots (fresh `root_rand` and encapsulation).
            val second = pqOffer(p)
            val atA2 = weekKey(p.a, p.contactOfB, DmSeal.PairDirection.IN, 3, second.rootEnv)
            assertFalse(atA.recognitionKey.contentEquals(atA2.recognitionKey))
        }
    }

    /** §22.8.6 rule 3: another generation is `NOT_OPEN`, a wrong generation binding is corrupt. */
    @Test
    fun aPqRootOpensOnlyWithTheGenerationItNames() {
        requireNative()
        withPair { p ->
            val offer = pqOffer(p)
            val encoded = encodeText(
                p.a, "x".toByteArray(), p.contactOfB, offerRootGen = 3, offerEnv = offer.offerEnv,
            )
            val received = requireNotNull(decode(p.b, p.contactOfA, encoded.l0).sealRootPq)
            val other = TestGeneration.of(p.b, genId = 0x7e_09_09_09)
            // B's other generation, correctly wrapped, but not the one the TLV names.
            assertEquals(
                DmPairing.PqOpenResult.NotOpen,
                DmPairing.pqOpen(
                    p.b, p.contactOfA, 3, other.genId.toLong() and 0xffff_ffffL, other.secretsEnv,
                    other.fallbackPublic, received.tlv, p.oiA,
                ),
            )
            // The named id with another generation's secrets: the envelope's binding refuses it.
            assertEquals(
                DmPairing.PqOpenResult.StateCorrupt,
                DmPairing.pqOpen(
                    p.b, p.contactOfA, 3, received.peerGenId, other.secretsEnv, p.genB.fallbackPublic,
                    received.tlv, p.oiA,
                ),
            )
            // A root_gen that is not the TLV's is a caller disagreement.
            assertEquals(
                DmPairing.PqOpenResult.NonCanonical,
                DmPairing.pqOpen(
                    p.b, p.contactOfA, 4, received.peerGenId, p.genB.secretsEnv,
                    p.genB.fallbackPublic, received.tlv, p.oiA,
                ),
            )
            // A low-order X25519 half of the ciphertext (§22.8.2 rule 5 d): typed, never a crash.
            val lowOrder = received.tlv.copyOf()
            for (i in lowOrder.size - 32 until lowOrder.size) lowOrder[i] = 0
            assertEquals(
                DmPairing.PqOpenResult.NotOpen,
                DmPairing.pqOpen(
                    p.b, p.contactOfA, 3, received.peerGenId, p.genB.secretsEnv,
                    p.genB.fallbackPublic, lowOrder, p.oiA,
                ),
            )
        }
    }

    /** §22.8.2 rules 3 and 4: an invalid key is `INVALID_KEY` at the offer, never a crash. */
    @Test
    fun anInvalidPeerKeyIsInvalidKeyAtTheOffer() {
        requireNative()
        withPair { p ->
            val lowOrder = p.genB.xwingPublic.copyOf()
            for (i in 1184 until 1216) lowOrder[i] = 0
            val badMlKem = p.genB.xwingPublic.copyOf()
            badMlKem[0] = 0xff.toByte()
            badMlKem[1] = (badMlKem[1].toInt() or 0x0f).toByte()
            for (key in listOf(lowOrder, badMlKem, p.genB.xwingPublic.copyOf(1215))) {
                assertEquals(
                    DmPairing.PqOfferResult.InvalidKey,
                    DmPairing.pqOffer(p.a, p.contactOfB, 3, baseWeek, p.oiB, 1L, key),
                )
            }
        }
    }

    /**
     * PQ4 at the boundary (§7.1 R-C5, mutant ME-23): at 4 KiB a `pq_key` rides with a body of at
     * most 1 148 bytes and a `seal_root_pq` with at most 1 210, the two never ride together there,
     * and in every case the bucket is the one the body alone chose.
     */
    @Test
    fun theSlackRuleDecidesWhatRidesAndTheBucketNeverMoves() {
        requireNative()
        withPair { p ->
            val genA = TestGeneration.of(p.a, genId = 0x6e_00_00_01)
            val candidate = DmContent.PqKeyCandidate(
                genId = genA.genId.toLong() and 0xffff_ffffL,
                bundleWeek = baseWeek,
                secretsEnv = genA.secretsEnv,
                fallbackPublic = genA.fallbackPublic,
            )
            val offer = pqOffer(p)
            for ((body, keyRides) in listOf(1_148 to true, 1_149 to false, 0 to true, 2_220 to false)) {
                val encoded = encodeText(p.a, ByteArray(body) { 0x41 }, pqKey = candidate)
                assertEquals("pq_key at body $body", keyRides, encoded.pqKeyRode)
                assertEquals("bucket at body $body", 4096, encoded.bucket)
            }
            for ((body, offerRides) in listOf(1_210 to true, 1_211 to false)) {
                val encoded = encodeText(
                    p.a, ByteArray(body) { 0x41 }, p.contactOfB, offerRootGen = 3,
                    offerEnv = offer.offerEnv,
                )
                assertEquals("seal_root_pq at body $body", offerRides, encoded.sealRootPqRode)
                assertEquals(4096, encoded.bucket)
                // A deferred PQ offer is not replaced by a classical one in the same L0.
                assertFalse(encoded.sealRootRode)
            }
            // Both pending at 4 KiB: the offer rides, the announcement waits.
            val both = encodeText(
                p.a, "hi".toByteArray(), p.contactOfB, offerRootGen = 3, offerEnv = offer.offerEnv,
                pqKey = candidate,
            )
            assertTrue(both.sealRootPqRode)
            assertFalse(both.pqKeyRode)
            // At 16 KiB both ride, and the bucket is still the body's.
            val large = encodeText(
                p.a, ByteArray(2_221) { 0x41 }, p.contactOfB, offerRootGen = 3,
                offerEnv = offer.offerEnv, pqKey = candidate,
            )
            assertTrue(large.sealRootPqRode && large.pqKeyRode)
            assertEquals(16_384, large.bucket)
            // The same body without candidates: the same bucket.
            val bare = encodeText(p.a, ByteArray(2_221) { 0x41 })
            assertEquals(large.bucket, bare.bucket)
        }
    }

    /** §9.4 and §22.8.2 rule 3: a `pq_key` round-trips, and an invalid one is flagged, not applied. */
    @Test
    fun aPqKeyRoundTripsAndAnInvalidOneIsFlaggedNotApplied() {
        requireNative()
        withPair { p ->
            val genA = TestGeneration.of(p.a, genId = 0xfe_00_00_02.toInt())
            val candidate = DmContent.PqKeyCandidate(
                genId = genA.genId.toLong() and 0xffff_ffffL,
                bundleWeek = baseWeek + 1,
                secretsEnv = genA.secretsEnv,
                fallbackPublic = genA.fallbackPublic,
            )
            val encoded = encodeText(p.a, "key".toByteArray(), pqKey = candidate)
            assertTrue(encoded.pqKeyRode)
            val content = decode(p.b, p.contactOfA, encoded.l0)
            val key = requireNotNull(content.pqKey)
            assertEquals("a u32 above 2^31 survives", 0xfe_00_00_02L, key.genId)
            assertEquals(baseWeek + 1, key.bundleWeek)
            assertArrayEquals("the key the bundle publishes", genA.xwingPublic, key.xwingPublic)
            assertFalse(content.pqKeyInvalid)

            // `pq_key` is the highest TLV type, so its key is the L0's last 1 216 bytes: an
            // all-zero X25519 half is a low-order key, refused whole on receipt.
            val bad = encoded.l0.copyOf()
            for (i in bad.size - 32 until bad.size) bad[i] = 0
            val flagged = decode(p.b, p.contactOfA, bad)
            assertNull(flagged.pqKey)
            assertTrue(flagged.pqKeyInvalid)
            assertEquals("the rest of the L0 applies", "key", String(flagged.body))

            // A wrong generation binding for the candidate is corrupt, never a silent omission.
            val wrongBinding = DmContent.PqKeyCandidate(
                candidate.genId, candidate.bundleWeek, candidate.secretsEnv, ByteArray(32) { 9 },
            )
            assertEquals(
                DmContent.Encoded.StateCorrupt,
                DmContent.encode(
                    handle = p.a, kind = DmContent.Kind.TEXT, messageId = bytes(1, 16),
                    authorMinute = 29_010_000L, minuteIndex = 0, timerCode = 4, timerVersion = 0,
                    quoteRef = null, body = "x".toByteArray(), pqKey = wrongBinding,
                ),
            )
        }
    }

    /**
     * An L0 with a classical `seal_root` **and** a `seal_root_pq`: §9.4's PQ form replaces the
     * classical one, so no sender following it writes both; a receiver applies the classical root
     * and flags the PQ one as ignored, rather than choosing between two roots of one message.
     */
    @Test
    fun aPqRootBesideAClassicalRootIsIgnored() {
        requireNative()
        withPair { p ->
            val classical = DmPairing.offer(p.a, p.contactOfB, 2, baseWeek)
                as DmPairing.OfferResult.Ok
            val encoded = encodeText(
                p.a, "both".toByteArray(), p.contactOfB, offerRootGen = 2,
                offerEnv = classical.offer.offerEnv,
            )
            assertTrue(encoded.sealRootRode)
            // Append a `seal_root_pq` TLV by hand: `type(2) || len(2) || value(1 166)`, and grow
            // `ext_len`, which sits right after the body.
            val pq = encodeText(
                p.a, "x".toByteArray(), p.contactOfB, offerRootGen = 3,
                offerEnv = pqOffer(p).offerEnv,
            )
            val pqTlv = pq.l0.copyOfRange(pq.l0.size - (4 + 1_166), pq.l0.size)
            val extLenAt = 34 + "both".length
            val extLen = ((encoded.l0[extLenAt].toInt() and 0xff) shl 8) or
                (encoded.l0[extLenAt + 1].toInt() and 0xff)
            val grown = extLen + pqTlv.size
            val spliced = encoded.l0.copyOf() + pqTlv
            spliced[extLenAt] = (grown shr 8).toByte()
            spliced[extLenAt + 1] = grown.toByte()
            val content = decode(p.b, p.contactOfA, spliced)
            assertNotNull(content.sealRoot)
            assertNull(content.sealRootPq)
            assertTrue(content.pqIgnored)
        }
    }
}
