package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.identity.Ed25519KeyPair
import org.ghost.network.EntitlementCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer

/**
 * Replays the whole `[ghost]` section of `protocol/test-vectors/blind_rsa_pp2.txt` (Phase 8 design
 * §2.9, §11.9) through the harness's `TestTokenCrypto` (BigInteger + JCA): the test schedule key and
 * the committed test ES's digest and signature, redemption contexts, challenges, SPKI and key ids of
 * the committed test keys, the permutation proof (and its tampered copy), every pinned seed-derived
 * position (nonce, salt, r, blinded message), the blind signatures of the harness signer (which must
 * equal the Rust signer's byte for byte), finalized tokens and nullifiers, layout and request
 * digests; a test checks that every vector and field of the section is read. The same file is
 * replayed by `ghost-entitlement` (`tests/ghost_vectors.rs`).
 */
class TestTokenCryptoVectorsTest {

    /** One vector; every field read is recorded in [used] ("id.field"), so a test can prove the section was consumed. */
    private class Vector(val id: String, val fields: Map<String, String>, private val used: MutableSet<String>) {
        fun hex(key: String): ByteArray {
            used += "$id.$key"
            return Bytes.unhex(fields[key] ?: error("vector $id: missing field $key"))
        }

        fun u64(key: String): Long = ByteBuffer.wrap(hex(key)).long
        fun u32(key: String): Int = ByteBuffer.wrap(hex(key)).int
    }

    /** Every `[ghost]` field this test instance read (JUnit makes one instance per test method). */
    private val used = HashSet<String>()
    private val ghost: List<Vector> by lazy { section("ghost") }

    private fun section(name: String): List<Vector> {
        val file = File(VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        var current: String? = null
        val out = ArrayList<Pair<String, LinkedHashMap<String, String>>>()
        for (raw in file.readLines()) {
            val line = raw.trimEnd()
            if (line.isEmpty() || line.startsWith("#")) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                current = line.substring(1, line.length - 1)
                continue
            }
            if (current != name) continue
            if (line.startsWith("vector ")) {
                out += Pair(line.removePrefix("vector ").split(Regex("\\s+")).first(), LinkedHashMap())
                continue
            }
            val at = line.indexOf(" =")
            check(at > 0) { "malformed line: $line" }
            check(out.last().second.put(line.substring(0, at), line.substring(at + 2).trim()) == null) { "duplicate field" }
        }
        return out.map { Vector(it.first, it.second, used) }
    }

    private fun vector(id: String): Vector = ghost.firstOrNull { it.id == id } ?: error("no [ghost] vector $id")

    /** The committed test schedule: access_per_slot 16, trial_per_slot 8, its slot table. */
    private val committed = TestSchedule(16, 8, TestSchedule.committedSlots())

    @Test
    fun challengesSpkisAndKeyIdsOfTheTestKeys() {
        assertArrayEquals(vector("schedule").hex("issuer_name"), Bytes.ascii(committed.issuerName))
        for (id in listOf("challenge-01", "challenge-02", "challenge-03")) {
            val v = vector(id)
            val kind = v.hex("kind")[0].toInt()
            val epoch = v.u64("epoch")
            val slot = v.hex("slot").firstOrNull()?.toInt()
            assertArrayEquals(id, v.hex("redemption_context"), TestSchedule.redemptionContext(kind, epoch))
            assertArrayEquals(id, v.hex("challenge"), committed.challenge(kind, epoch, slot))
            assertArrayEquals(id, v.hex("challenge_digest"), committed.challengeDigest(kind, epoch, slot))
            val key = checkNotNull(committed.key(kind, epoch))
            assertArrayEquals(id, v.hex("spki"), key.spki)
            assertArrayEquals(id, v.hex("key_id"), key.keyId)
            assertEquals(key.n, RsaKey.modulusOf(v.hex("spki")))
        }
        assertEquals("every key of the committed test schedule", 26 + 7 + 3, committed.keys.size)
    }

    /** Checks every `pN.*` group of [v] against a fresh derivation; returns how many. */
    private fun positions(v: Vector, seed: ByteArray, list: List<org.ghost.entitlement.engine.Position>): Int {
        val prk = Batch.prk(seed)
        var seen = 0
        for (field in v.fields.keys.filter { it.endsWith(".nonce") }) {
            val tag = field.removeSuffix(".nonce")
            val j = tag.substring(1).toInt()
            fun f(name: String) = v.hex("$tag.$name")
            val d = Batch.derive(committed, prk, list, j)
            assertEquals(tag, f("kind")[0].toInt(), d.position.kind)
            assertEquals(tag, ByteBuffer.wrap(f("epoch")).long, d.position.epoch)
            assertEquals(tag, f("slot")[0].toInt() and 0xff, d.position.slot ?: 0xff)
            assertArrayEquals(tag, f("nonce"), d.nonce)
            assertArrayEquals(tag, f("salt"), d.salt)
            assertArrayEquals(tag, f("r"), Bytes.i2osp(d.r, 256))
            assertArrayEquals(tag, f("blinded"), d.blinded)
            val key = checkNotNull(committed.key(d.position.kind, d.position.epoch))
            assertArrayEquals("$tag: the harness signer equals the Rust signer", f("blind_sig"), key.blindSign(d.blinded))
            assertTrue(tag, key.checkBlindSignature(d.blinded, f("blind_sig")))
            // Finalize: s = s' * r^-1 mod n, then the token verifies (JCA) under its schedule key.
            val final = Bytes.i2osp(Bytes.os2ip(f("blind_sig")).multiply(d.inv).mod(key.n), 256)
            val token = d.input + final
            assertArrayEquals(tag, f("token"), token)
            assertArrayEquals(tag, f("nullifier"), TestSchedule.nullifier(token))
            val verified = committed.verify(token, d.position.kind)
            assertNotNull(tag, verified)
            assertEquals(tag, d.position.epoch, checkNotNull(verified).epoch)
            assertEquals(tag, d.position.slot, verified.slot)
            seen++
        }
        return seen
    }

    private fun signAll(list: List<org.ghost.entitlement.engine.Position>, request: ByteArray): ByteArray {
        val out = ByteArray(request.size)
        for (j in list.indices) {
            val p = list[j]
            SigningCache.sign(checkNotNull(committed.key(p.kind, p.epoch)), request.copyOfRange(j * 256, (j + 1) * 256)).copyInto(out, j * 256)
        }
        return out
    }

    @Test
    fun aPackPaidInXmrEveryPinnedPositionTheResponseAndTheTokens() {
        val v = vector("pack-xmr")
        val seed = v.hex("seed")
        val base = v.u64("base_week")
        val list = checkNotNull(committed.positions(EntitlementCrypto.PRODUCT_PACK_XMR, base))
        assertEquals(v.u32("positions"), list.size)
        assertEquals("5 weeks x 3 slots x 16 + 2 invites + 1 credit", 243, list.size)
        assertArrayEquals(v.hex("layout_digest"), Batch.layoutDigest(list))
        val request = Batch.blind(committed, seed, list)
        assertArrayEquals(v.hex("request_sha256"), Bytes.sha256(request))
        assertArrayEquals(v.hex("request_digest"), Batch.requestDigest(v.hex("invoice_id"), request))
        assertArrayEquals("a retry recomputes identical blinded messages", request, Batch.blind(committed, seed, list))
        val response = signAll(list, request)
        assertArrayEquals("the whole response of the harness signer", v.hex("response_sha256"), Bytes.sha256(response))
        val tokens = checkNotNull(Batch.finalize(committed, seed, list, response))
        assertArrayEquals(v.hex("tokens_sha256"), Bytes.sha256(tokens.fold(ByteArray(0)) { acc, t -> acc + t }))
        assertEquals(10, positions(v, seed, list))
        // One flipped signature byte refuses the whole response.
        val bad = response.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        assertEquals(null, Batch.finalize(committed, seed, list, bad))
    }

    @Test
    fun aPackPaidWithCreditsATrialAndARefresh() {
        val credits = vector("pack-credits")
        val cList = checkNotNull(committed.positions(EntitlementCrypto.PRODUCT_PACK_CREDITS, credits.u64("base_week")))
        assertEquals(credits.u32("positions"), cList.size)
        assertArrayEquals(credits.hex("layout_digest"), Batch.layoutDigest(cList))

        val v = vector("trial")
        val seed = v.hex("seed")
        val base = v.u64("base_week")
        val list = checkNotNull(committed.positions(EntitlementCrypto.PRODUCT_TRIAL, base))
        assertEquals("2 weeks x 3 slots x 8", 48, list.size)
        assertEquals(v.u32("positions"), list.size)
        assertArrayEquals(v.hex("layout_digest"), Batch.layoutDigest(list))
        val request = Batch.blind(committed, seed, list)
        assertArrayEquals(v.hex("request_sha256"), Bytes.sha256(request))
        assertArrayEquals(v.hex("trial_digest"), Batch.trialDigest(v.hex("invite_nullifier"), base, request))
        assertArrayEquals(v.hex("response_sha256"), Bytes.sha256(signAll(list, request)))
        assertEquals(1, positions(v, seed, list))

        val refresh = vector("refresh")
        val rList = checkNotNull(committed.positions(EntitlementCrypto.PRODUCT_REFRESH, Grid.creditEpoch(TestSchedule.FIRST_WEEK)))
        assertEquals(refresh.u32("positions"), rList.size)
        assertArrayEquals(refresh.hex("layout_digest"), Batch.layoutDigest(rList))
    }

    @Test
    fun theTestScheduleKeyAndTheCommittedTestSchedule() {
        val v = vector("schedule")
        val key = Ed25519KeyPair.fromSeed(Bytes.sha256(Bytes.ascii("ghost/test/schedule-key"))).publicKey
        assertArrayEquals("the test schedule key: Ed25519 from SHA-256(\"ghost/test/schedule-key\")", v.hex("schedule_key"), key)
        val file = File(SCHEDULE)
        assertTrue("test schedule missing: ${file.absolutePath}", file.isFile)
        val bytes = file.readBytes()
        assertArrayEquals("SHA-256 of the committed test schedule", v.hex("schedule_sha256"), Bytes.sha256(bytes))
        val body = bytes.copyOfRange(0, bytes.size - SIGNATURE_BYTES)
        val signature = bytes.copyOfRange(bytes.size - SIGNATURE_BYTES, bytes.size)
        assertTrue("the committed test schedule is signed by the test schedule key", Ed25519KeyPair.verify(key, Bytes.ascii(SIGNATURE_DOMAIN) + body, signature))
    }

    @Test
    fun thePermutationProofVerifiesAndItsTamperedCopyDoesNot() {
        val v = vector("perm-proof")
        val n = checkNotNull(RsaKey.modulusOf(v.hex("spki"))) { "perm-proof: not a type 0x0002 RSASSA-PSS SPKI" }
        val challenges = PermutationProof.challenges(n).fold(ByteArray(0)) { acc, rho -> acc + Bytes.i2osp(rho, RsaKey.MODULUS_BYTES) }
        assertArrayEquals("the hash-derived challenges", v.hex("challenges"), challenges)
        assertTrue("the proof verifies", PermutationProof.verify(n, PermutationProof.EXPONENT, v.hex("proof")))
        assertFalse("the tampered proof is refused", PermutationProof.verify(n, PermutationProof.EXPONENT, v.hex("tampered_proof")))
    }

    /** The replays together read every field of every `[ghost]` vector: a vector added there is never ignored. */
    @Test
    fun everyGhostVectorAndFieldIsReplayed() {
        challengesSpkisAndKeyIdsOfTheTestKeys()
        theTestScheduleKeyAndTheCommittedTestSchedule()
        thePermutationProofVerifiesAndItsTamperedCopyDoesNot()
        aPackPaidInXmrEveryPinnedPositionTheResponseAndTheTokens()
        aPackPaidWithCreditsATrialAndARefresh()
        val all = ghost.flatMap { v -> v.fields.keys.map { "${v.id}.$it" } }.toSortedSet()
        assertEquals("[ghost] fields no replay reads", emptySet<String>(), all - used)
    }

    companion object {
        /** Test working directory is the module directory (ghost/android/entitlement). */
        const val VECTORS = "../../protocol/test-vectors/blind_rsa_pp2.txt"

        /** The committed test ES the vector's `schedule_sha256` pins (signed by the test schedule key). */
        const val SCHEDULE = "../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes"
        const val SIGNATURE_DOMAIN = "ghost/v1/entitlement-schedule"
        const val SIGNATURE_BYTES = 64
    }
}
