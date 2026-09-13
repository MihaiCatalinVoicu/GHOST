package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Layouts
import org.ghost.entitlement.engine.Position
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.identity.Hkdf
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Byte helpers of the harness (hex, digests, HMAC, big-endian integers). */
internal object Bytes {
    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    fun sha256(vararg parts: ByteArray): ByteArray = digest("SHA-256", parts)

    fun sha384(vararg parts: ByteArray): ByteArray = digest("SHA-384", parts)

    private fun digest(algorithm: String, parts: Array<out ByteArray>): ByteArray {
        val md = MessageDigest.getInstance(algorithm)
        parts.forEach(md::update)
        return md.digest()
    }

    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach(mac::update)
        return mac.doFinal()
    }

    fun u64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()

    fun u16(v: Int): ByteArray = byteArrayOf((v ushr 8).toByte(), v.toByte())

    fun ascii(s: String): ByteArray = s.toByteArray(Charsets.US_ASCII)

    /** I2OSP: [x] as exactly [len] big-endian bytes (x < 256^len). */
    fun i2osp(x: BigInteger, len: Int): ByteArray {
        val raw = x.toByteArray()
        val start = raw.indexOfFirst { it != 0.toByte() }.let { if (it < 0) raw.size else it }
        val trimmed = raw.copyOfRange(start, raw.size)
        require(trimmed.size <= len) { "integer too large" }
        return ByteArray(len - trimmed.size) + trimmed
    }

    fun os2ip(b: ByteArray): BigInteger = BigInteger(1, b)
}

/**
 * One RSA-2048 key of the committed test schedule (Phase 8 design §2.4): the private CRT key from
 * `issuer/crates/entitlement/tests/fixtures/test_keys.txt`, its RSASSA-PSS SPKI (SHA-384,
 * MGF1-SHA-384, salt 48) and `token_key_id = SHA-256(SPKI)` (§2.1).
 */
internal class RsaKey(val kind: Int, val epoch: Long, private val key: RSAPrivateCrtKey) {
    val n: BigInteger = key.modulus
    val e: BigInteger = key.publicExponent
    val spki: ByteArray = Bytes.unhex(SPKI_PREFIX) + Bytes.i2osp(n, MODULUS_BYTES) + Bytes.unhex(SPKI_EXPONENT)
    val keyId: ByteArray = Bytes.sha256(spki)
    val keyIdHex: String = Bytes.hex(keyId)
    val publicKey: PublicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))

    /** `s' = B^d mod n` by the CRT; deterministic in (key, B) (§2.5). */
    fun blindSign(block: ByteArray): ByteArray {
        val c = Bytes.os2ip(block)
        require(c.signum() > 0 && c < n) { "blinded value out of range" }
        val m1 = c.modPow(key.primeExponentP, key.primeP)
        val m2 = c.modPow(key.primeExponentQ, key.primeQ)
        val h = key.crtCoefficient.multiply(m1.subtract(m2)).mod(key.primeP)
        return Bytes.i2osp(m2.add(h.multiply(key.primeQ)), MODULUS_BYTES)
    }

    /** `s'^e == B (mod n)`, the client's and the issuer's fault check. */
    fun checkBlindSignature(blinded: ByteArray, blindSig: ByteArray): Boolean =
        blindSig.size == MODULUS_BYTES && Bytes.os2ip(blindSig) < n && Bytes.os2ip(blindSig).modPow(e, n) == Bytes.os2ip(blinded)

    override fun toString(): String = "RsaKey($kind, $epoch)"

    companion object {
        const val MODULUS_BYTES = 256

        /** SPKI DER up to the modulus: id-RSASSA-PSS with SHA-384, MGF1-SHA-384, saltLength 48. */
        const val SPKI_PREFIX =
            "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202" +
                "a2030201300382010f003082010a0282010100"
        const val SPKI_EXPONENT = "0203010001"

        /** The modulus of an SPKI of exactly this layout, or null. */
        fun modulusOf(spki: ByteArray): BigInteger? {
            val prefix = Bytes.unhex(SPKI_PREFIX)
            if (spki.size != prefix.size + MODULUS_BYTES + 5) return null
            if (!spki.copyOfRange(0, prefix.size).contentEquals(prefix)) return null
            return Bytes.os2ip(spki.copyOfRange(prefix.size, prefix.size + MODULUS_BYTES))
        }
    }
}

/** The test keys of the committed test schedule, loaded once per JVM. */
internal object TestKeys {
    /** Relative to the module directory (ghost/android/entitlement), the Gradle test working directory. */
    const val FILE = "../../issuer/crates/entitlement/tests/fixtures/test_keys.txt"

    val all: Map<Pair<Int, Long>, RsaKey> by lazy {
        val file = File(FILE)
        check(file.isFile) { "test keys missing: ${file.absolutePath}" }
        val factory = KeyFactory.getInstance("RSA")
        file.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { line ->
            val f = line.trim().split(' ')
            val kind = f[0].toInt()
            val epoch = f[1].toLong()
            val key = factory.generatePrivate(PKCS8EncodedKeySpec(Bytes.unhex(f[2]))) as RSAPrivateCrtKey
            Pair(kind, epoch) to RsaKey(kind, epoch, key)
        }
    }
}

/** RSASSA-PSS (SHA-384, MGF1-SHA-384, sLen 48) and the RFC 9474 blinding arithmetic, on BigInteger + JCA. */
internal object Pss {
    private const val H_LEN = 48
    const val SALT_LEN = 48
    private const val EM_LEN = 256
    private val pssParams = PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, SALT_LEN, 1)

    /** EMSA-PSS-ENCODE (RFC 8017 §9.1.1) for emBits = 2047. */
    fun encode(message: ByteArray, salt: ByteArray): ByteArray {
        require(salt.size == SALT_LEN) { "salt length" }
        val mHash = Bytes.sha384(message)
        val h = Bytes.sha384(ByteArray(8), mHash, salt)
        val db = ByteArray(EM_LEN - H_LEN - 1)
        db[db.size - SALT_LEN - 1] = 1
        salt.copyInto(db, db.size - SALT_LEN)
        val mask = mgf1(h, db.size)
        for (i in db.indices) db[i] = (db[i].toInt() xor mask[i].toInt()).toByte()
        db[0] = (db[0].toInt() and 0x7f).toByte()
        return db + h + byteArrayOf(0xbc.toByte())
    }

    private fun mgf1(seed: ByteArray, len: Int): ByteArray {
        val out = ByteArray(len)
        var pos = 0
        var counter = 0
        while (pos < len) {
            val block = Bytes.sha384(seed, ByteBuffer.allocate(4).putInt(counter).array())
            val n = minOf(block.size, len - pos)
            block.copyInto(out, pos, 0, n)
            pos += n
            counter++
        }
        return out
    }

    /** RSASSA-PSS verification by the JCA provider (an implementation independent of this file's arithmetic). */
    fun verify(key: PublicKey, message: ByteArray, signature: ByteArray): Boolean = try {
        val v = Signature.getInstance("RSASSA-PSS")
        v.setParameter(pssParams)
        v.initVerify(key)
        v.update(message)
        v.verify(signature)
    } catch (e: java.security.GeneralSecurityException) {
        false
    }
}

/**
 * The test Entitlement Schedule of the JVM harness (Phase 8 design §19.17 point 3): the keys, issuer
 * name and key ids of the committed test schedule (`test_schedule.ghes`, access weeks 2957…2982,
 * invite epochs 739…745, credit epochs 227…229), with the constants and the slot table a world or a
 * vector file chooses. The harness worlds use S = 3, `access_per_slot = 4`, `trial_per_slot = 2`;
 * `issuer_semantics.txt` uses 1 and 1.
 */
internal class TestSchedule(
    val accessPerSlot: Int,
    val trialPerSlot: Int,
    val slots: List<EntitlementCrypto.Slot>,
    val revoked: Set<Pair<Int, Long>> = emptySet(),
    val prices: Map<Long, Long> = DEFAULT_PRICES,
    val seq: Long = 1,
) {
    val issuerName: String = ISSUER_NAME
    val keys: Map<Pair<Int, Long>, RsaKey> = TestKeys.all
    private val byId: Map<String, RsaKey> = keys.values.associateBy { it.keyIdHex }

    val constants = EntitlementCrypto.Constants(
        confirmations = 10, invoiceBlocks = 720, graceBlocks = 2160, accessPerSlot = accessPerSlot, trialPerSlot = trialPerSlot,
        invitesPerPack = 2, creditsPerFreePack = 10, minClaimCredits = 10, maxClaimCredits = 50, earlyWindowHours = 24,
        capabilityQuotaBytes = QUOTA,
    )

    /**
     * The summary the engine sees. Network 2 (stagenet): the committed test schedule is a regtest
     * one, which the production client refuses (ES rule 6); nothing network-specific is read here.
     */
    val summary: EntitlementCrypto.ScheduleSummary by lazy {
        val keyIds = keys.values.sortedWith(compareBy({ it.kind }, { it.epoch })).map { EntitlementCrypto.KeyId(it.kind, it.epoch, it.keyId) }
        val priceList = prices.entries.sortedBy { it.key }.map { EntitlementCrypto.Price(it.key, it.value) }
        val revokedList = revoked.sortedWith(compareBy({ it.first }, { it.second })).map { EntitlementCrypto.Revoked(it.first, it.second) }
        val md = MessageDigest.getInstance("SHA-256")
        md.update(Bytes.ascii("harness-es:$seq:$accessPerSlot:$trialPerSlot"))
        slots.forEach { md.update(Bytes.ascii("${it.slot}:${it.validFromWeek}:${it.validUntilWeek}:${it.onion}")) }
        priceList.forEach { md.update(Bytes.ascii("${it.priceEpoch}:${it.packPriceAtomic}")) }
        keyIds.forEach { md.update(it.keyId()) }
        revokedList.forEach { md.update(Bytes.ascii("r${it.kind}:${it.epoch}")) }
        EntitlementCrypto.ScheduleSummary(md.digest(), seq, NETWORK, FIRST_WEEK, LAST_WEEK, constants, slots, priceList, keyIds, revokedList)
    }

    fun key(kind: Int, epoch: Long): RsaKey? = keys[kind to epoch]

    fun keyById(id: ByteArray): RsaKey? = byId[Bytes.hex(id)]

    fun slotsInWeek(week: Long): List<Int> = summary.slotsInWeek(week)

    /** The onion the slot table lists for [slot] in [week], or null. */
    fun slotOnion(slot: Int, week: Long): OnionAddress? = slots.firstOrNull { it.slot == slot && it.validIn(week) }?.onion

    fun isRevoked(kind: Int, epoch: Long): Boolean = (kind to epoch) in revoked

    fun price(priceEpoch: Long): Long? = prices[priceEpoch]

    fun creditValue(creditEpoch: Long): Long? = price(creditEpoch)?.let { it / 10 }

    /** `challenge_digest` of (kind, epoch, slot) under the issuer name (design §2.2). */
    fun challengeDigest(kind: Int, epoch: Long, slot: Int?): ByteArray = Bytes.sha256(challenge(kind, epoch, slot))

    fun challenge(kind: Int, epoch: Long, slot: Int?): ByteArray {
        val origin = when (kind) {
            EntitlementCrypto.KIND_ACCESS -> "relay-slot-%02d".format(checkNotNull(slot) { "an access challenge names a slot" })
            EntitlementCrypto.KIND_INVITE -> "issuer-invite"
            else -> "issuer-credit"
        }
        val name = Bytes.ascii(issuerName)
        val context = redemptionContext(kind, epoch)
        val o = Bytes.ascii(origin)
        return Bytes.u16(2) + Bytes.u16(name.size) + name + byteArrayOf(context.size.toByte()) + context + Bytes.u16(o.size) + o
    }

    /**
     * The positions of a product (design §4.2, §4.3, §19.8), in the order the engine stores tokens
     * ([Layouts]); null when the schedule cannot cover it (a week without a slot, a missing key).
     */
    fun positions(product: Int, index: Long): List<Position>? {
        val list = when (product) {
            EntitlementCrypto.PRODUCT_PACK_XMR -> Layouts.pack(summary, index, true)
            EntitlementCrypto.PRODUCT_PACK_CREDITS -> Layouts.pack(summary, index, false)
            EntitlementCrypto.PRODUCT_TRIAL -> Layouts.trial(summary, index)
            EntitlementCrypto.PRODUCT_REFRESH -> listOf(Position(EntitlementCrypto.KIND_CREDIT, index, null))
            else -> return null
        }
        val weeks = when (product) {
            EntitlementCrypto.PRODUCT_TRIAL -> index until index + Layouts.TRIAL_WEEKS
            EntitlementCrypto.PRODUCT_REFRESH -> LongRange.EMPTY
            else -> index until index + Layouts.PACK_WEEKS
        }
        if (weeks.any { slotsInWeek(it).isEmpty() }) return null
        if (list.isEmpty() || list.any { key(it.kind, it.epoch) == null }) return null
        return list
    }

    /** One verified token: its key's (kind, epoch), its challenge slot and its nullifier. */
    class Verified(val kind: Int, val epoch: Long, val slot: Int?, val nullifier: ByteArray)

    /**
     * The offline verification of a token as [kind] (design §2.1–§2.3): length and type, a key of the
     * schedule of that kind and not revoked, the challenge of that (kind, epoch) (for ACCESS, of one
     * of the week's slots, or of [slot] when given), and the PSS signature.
     */
    fun verify(token: ByteArray, kind: Int, slot: Int? = null, ignoreRevocation: Boolean = false): Verified? {
        if (token.size != TOKEN_BYTES || token[0] != 0.toByte() || token[1] != 2.toByte()) return null
        val key = keyById(token.copyOfRange(66, 98)) ?: return null
        if (key.kind != kind || (!ignoreRevocation && isRevoked(key.kind, key.epoch))) return null
        val digest = token.copyOfRange(34, 66)
        val candidates: List<Int?> = when {
            kind != EntitlementCrypto.KIND_ACCESS -> listOf(null)
            slot != null -> listOf(slot)
            else -> slotsInWeek(key.epoch)
        }
        val match = candidates.indexOfFirst { challengeDigest(kind, key.epoch, it).contentEquals(digest) }
        if (match < 0) return null
        val input = token.copyOfRange(0, TOKEN_INPUT_BYTES)
        if (!Pss.verify(key.publicKey, input, token.copyOfRange(TOKEN_INPUT_BYTES, TOKEN_BYTES))) return null
        return Verified(kind, key.epoch, candidates[match], nullifier(input))
    }

    override fun toString(): String = "TestSchedule($accessPerSlot, $trialPerSlot)"

    companion object {
        const val ISSUER_NAME = "ghost-issuer-test"
        const val FIRST_WEEK = 2957L
        const val LAST_WEEK = 2982L
        const val NETWORK = 2
        const val QUOTA = 268_435_456L
        const val TOKEN_BYTES = 354
        const val TOKEN_INPUT_BYTES = 98

        /** One pack price, 0.2 XMR, in every price epoch the keys reach (225…230; issuer_semantics.txt reads epoch 227). */
        val DEFAULT_PRICES: Map<Long, Long> = (225L..230L).associateWith { 200_000_000_000L }

        fun redemptionContext(kind: Int, epoch: Long): ByteArray =
            Bytes.sha256(Bytes.ascii("ghost/v1/redemption-context"), byteArrayOf(kind.toByte()), Bytes.u64(epoch))

        fun nullifier(input: ByteArray): ByteArray = Bytes.sha256(Bytes.ascii("ghost/v1/nullifier"), input.copyOfRange(0, TOKEN_INPUT_BYTES))

        /** An onion whose service key is SHA-256([label]) (the vector files' onion labels). */
        fun onion(label: String, port: Int = 443): OnionAddress = onionOfKey(Bytes.sha256(Bytes.ascii(label)), port)

        /** The v3 onion of a 32-byte service key (checksum and version byte). */
        fun onionOfKey(key: ByteArray, port: Int = 443): OnionAddress {
            val md = MessageDigest.getInstance("SHA3-256")
            md.update(Bytes.ascii(".onion checksum"))
            md.update(key)
            md.update(3.toByte())
            val raw = key + md.digest().copyOf(2) + byteArrayOf(3)
            return OnionAddress.parse(base32(raw) + ".onion:" + port)
        }

        private fun base32(raw: ByteArray): String {
            val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
            val sb = StringBuilder()
            var buffer = 0
            var bits = 0
            for (b in raw) {
                buffer = ((buffer shl 8) or (b.toInt() and 0xff)) and 0xffff
                bits += 8
                while (bits >= 5) {
                    bits -= 5
                    sb.append(alphabet[(buffer shr bits) and 31])
                }
            }
            return sb.toString()
        }

        /** The committed test schedule's slot table (redeem.txt): relay-a, relay-b, relay-c then relay-d for slot 2 from week 2967. */
        fun committedSlots(): List<EntitlementCrypto.Slot> = listOf(
            EntitlementCrypto.Slot(0, FIRST_WEEK, 0, onion("ghost/test/relay-a")),
            EntitlementCrypto.Slot(1, FIRST_WEEK, 0, onion("ghost/test/relay-b")),
            EntitlementCrypto.Slot(2, FIRST_WEEK, 2967, onion("ghost/test/relay-c")),
            EntitlementCrypto.Slot(2, 2967, 0, onion("ghost/test/relay-d")),
        )
    }
}

/**
 * Seed-derived batches (design §2.6), as `ghost-entitlement::batch` computes them and the JNI does
 * inside one call; replayed against the `[ghost]` section of `blind_rsa_pp2.txt`.
 */
internal object Batch {
    private val PRK_SALT = Bytes.ascii("ghost/v1/blind-batch")
    private const val R_TRIES = 256

    class Derived(val position: Position, val nonce: ByteArray, val salt: ByteArray, val r: BigInteger, val input: ByteArray, val blinded: ByteArray, val inv: BigInteger)

    fun layoutDigest(positions: List<Position>): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(Bytes.ascii("ghost/v1/layout"))
        positions.forEach { md.update(encode(it)) }
        return md.digest()
    }

    private fun encode(p: Position): ByteArray = byteArrayOf(p.kind.toByte()) + Bytes.u64(p.epoch) + byteArrayOf((p.slot ?: 0xff).toByte())

    fun derive(s: TestSchedule, prk: ByteArray, positions: List<Position>, j: Int): Derived {
        val p = positions[j]
        val key = checkNotNull(s.key(p.kind, p.epoch)) { "no key for a position" }
        val info = encode(p) + Bytes.u16(j)
        val okm = Hkdf.expand(prk, info + Bytes.ascii("n"), 32 + Pss.SALT_LEN)
        val nonce = okm.copyOfRange(0, 32)
        val salt = okm.copyOfRange(32, 32 + Pss.SALT_LEN)
        var r: BigInteger? = null
        for (c in 0 until R_TRIES) {
            val candidate = Bytes.os2ip(Hkdf.expand(prk, info + Bytes.ascii("r") + byteArrayOf(c.toByte()), RsaKey.MODULUS_BYTES))
            if (candidate > BigInteger.ONE && candidate < key.n && candidate.gcd(key.n) == BigInteger.ONE) {
                r = candidate
                break
            }
        }
        val rr = checkNotNull(r) { "no admissible r" }
        val input = byteArrayOf(0, 2) + nonce + s.challengeDigest(p.kind, p.epoch, p.slot) + key.keyId
        val em = Bytes.os2ip(Pss.encode(input, salt))
        check(em.gcd(key.n) == BigInteger.ONE) { "encoded message shares a factor with n" }
        val blinded = Bytes.i2osp(em.multiply(rr.modPow(key.e, key.n)).mod(key.n), RsaKey.MODULUS_BYTES)
        return Derived(p, nonce, salt, rr, input, blinded, rr.modInverse(key.n))
    }

    fun prk(seed: ByteArray): ByteArray = Hkdf.extract(PRK_SALT, seed)

    /** `B_0 ‖ … ‖ B_{N−1}`. */
    fun blind(s: TestSchedule, seed: ByteArray, positions: List<Position>): ByteArray {
        val prk = prk(seed)
        val out = ByteArray(positions.size * RsaKey.MODULUS_BYTES)
        for (j in positions.indices) derive(s, prk, positions, j).blinded.copyInto(out, j * RsaKey.MODULUS_BYTES)
        return out
    }

    /**
     * Finalizes N blind signatures: every `s'^e == B` checked, every signature unblinded and verified
     * by the JCA; one bad position refuses the whole response (null).
     */
    fun finalize(s: TestSchedule, seed: ByteArray, positions: List<Position>, sigs: ByteArray): List<ByteArray>? {
        if (sigs.size != positions.size * RsaKey.MODULUS_BYTES) return null
        val prk = prk(seed)
        return positions.indices.map { j ->
            val d = derive(s, prk, positions, j)
            val key = checkNotNull(s.key(d.position.kind, d.position.epoch))
            val sig = sigs.copyOfRange(j * RsaKey.MODULUS_BYTES, (j + 1) * RsaKey.MODULUS_BYTES)
            if (!key.checkBlindSignature(d.blinded, sig)) return null
            val final = Bytes.i2osp(Bytes.os2ip(sig).multiply(d.inv).mod(key.n), RsaKey.MODULUS_BYTES)
            if (!Pss.verify(key.publicKey, d.input, final)) return null
            d.input + final
        }
    }

    fun requestDigest(invoiceId: ByteArray, request: ByteArray): ByteArray = Bytes.sha256(Bytes.ascii("ghost/v1/blindsign"), invoiceId, request)

    fun trialDigest(inviteNullifier: ByteArray, baseWeek: Long, request: ByteArray): ByteArray =
        Bytes.sha256(Bytes.ascii("ghost/v1/trial"), inviteNullifier, Bytes.u64(baseWeek), request)

    fun claimHash(claimKey: ByteArray): ByteArray = Bytes.sha256(Bytes.ascii("ghost/v1/issuer-claim"), claimKey)
}

/**
 * Signs one token directly with a test key (the vector files' `credits`, `invite` and pinned
 * tokens; never through an issuer): a one-position batch from a label's seed.
 */
internal fun TestSchedule.mint(kind: Int, epoch: Long, label: String, slot: Int? = null): ByteArray {
    val position = Position(kind, epoch, if (kind == EntitlementCrypto.KIND_ACCESS) slot ?: slotsInWeek(epoch).first() else null)
    val seed = Bytes.sha256(Bytes.ascii(label))
    val blinded = Batch.blind(this, seed, listOf(position))
    val sig = SigningCache.sign(checkNotNull(key(kind, epoch)), blinded)
    return checkNotNull(Batch.finalize(this, seed, listOf(position), sig)).single()
}

/**
 * Blind signatures cached per (key, B) (design §13.2, §19.17 point 3): signing is deterministic,
 * so a crash enumeration that replays a world signs each distinct block once. Bounded; an evicted
 * entry is simply signed again.
 */
internal object SigningCache {
    private const val MAX_ENTRIES = 60_000
    private val map = ConcurrentHashMap<String, ByteArray>()

    fun sign(key: RsaKey, blinded: ByteArray): ByteArray {
        val k = key.keyIdHex + Bytes.hex(Bytes.sha256(blinded))
        map[k]?.let { return it.copyOf() }
        val sig = key.blindSign(blinded)
        if (map.size >= MAX_ENTRIES) map.clear()
        map[k] = sig
        return sig.copyOf()
    }
}

/**
 * [TokenCryptoPort] over a [TestSchedule] (design §11.9 `TestTokenCrypto`): the summary, the layout
 * digests and position counts, and the offline token check with real RSA verification. Monero
 * addresses: 95 characters starting with `5` (standard) or `7` (subaddress).
 */
internal class TestTokenCrypto(val schedule: TestSchedule) : TokenCryptoPort {
    override fun scheduleSummary(): EntitlementCrypto.ScheduleSummary = schedule.summary

    override fun layout(product: Int, index: Long): EntitlementCrypto.Layout {
        val positions = schedule.positions(product, index) ?: throw NetworkException("invalid_argument")
        return EntitlementCrypto.Layout(Batch.layoutDigest(positions), positions.size)
    }

    override fun verifyToken(token: ByteArray, kind: Int): EntitlementCrypto.VerifiedToken? {
        val v = schedule.verify(token, kind) ?: return null
        return EntitlementCrypto.VerifiedToken(v.kind, v.epoch, v.slot, v.nullifier)
    }

    override fun validateAddress(address: String, purpose: Int): EntitlementCrypto.AddressInfo? {
        val type = when (HarnessAddresses.type(address)) {
            '5' -> EntitlementCrypto.ADDRESS_STANDARD
            '7' -> EntitlementCrypto.ADDRESS_SUBADDRESS
            else -> return null
        }
        if (purpose == EntitlementCrypto.PURPOSE_INVOICE && type != EntitlementCrypto.ADDRESS_SUBADDRESS) return null
        return EntitlementCrypto.AddressInfo(TestSchedule.NETWORK, type)
    }

    override fun paymentUri(subaddress: String, amountAtomic: Long): String = "monero:$subaddress?tx_amount=$amountAtomic"

    override fun toString(): String = "TestTokenCrypto"
}
