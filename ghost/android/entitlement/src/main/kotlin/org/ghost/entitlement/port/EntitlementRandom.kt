package org.ghost.entitlement.port

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The engine's randomness, from the client only (design R1: nothing issuer-supplied reaches a relay).
 *  - [bytes] and [uniform]: a CSPRNG, for secrets and ids (seeds, claim keys, purchase, claim, request
 *    and operation ids) and for draws that are persisted with their result (the drop time, activation
 *    offsets, due times);
 *  - [prf]: HMAC-SHA-256 under a per-process key that is never persisted (design §11.3 "never
 *    persisted: PRF keys"), a pure function of the key, [domain] and input: the redeem timing of a
 *    (relay, namespace, kind, week) (§12.4) and the surfacing delays of flags (§19.11, §19.13).
 */
interface EntitlementRandom {
    fun bytes(size: Int): ByteArray

    /** Uniform in [0, 1). */
    fun uniform(): Double

    /** Uniform in [0, 1) for ([domain], [input]). */
    fun prf(domain: Int, input: ByteArray): Double

    companion object {
        /** PRF(relay_id ‖ namespace ‖ kind ‖ week) of the redeem lane (design §12.4). */
        const val DOMAIN_REDEEM = 1

        /** The client-random delay U[0, 12 h] before `ENTITLEMENT_NEEDED` is surfaced (§19.13). */
        const val DOMAIN_NEED_SURFACE = 2

        /** The delay U[1 h, 6 h] after an invoice arrived before `PAYMENT_READY` is surfaced (§19.11). */
        const val DOMAIN_PAYMENT_READY = 3
    }
}

/**
 * Production [EntitlementRandom]: [SecureRandom] for [bytes] and [uniform]; the PRF key is 32 bytes
 * from the same CSPRNG, fresh per process, held only here and never exposed or persisted.
 */
class SecureEntitlementRandom(private val secure: SecureRandom = SecureRandom()) : EntitlementRandom {
    private val keySpec = SecretKeySpec(ByteArray(KEY_SIZE).also(secure::nextBytes), ALGORITHM)
    private val mac: ThreadLocal<Mac> = ThreadLocal.withInitial { Mac.getInstance(ALGORITHM).apply { init(keySpec) } }

    override fun bytes(size: Int): ByteArray {
        require(size in 1..MAX_BYTES) { "random size out of range" }
        return ByteArray(size).also(secure::nextBytes)
    }

    override fun uniform(): Double = (secure.nextLong() ushr 11) * TWO_POW_MINUS_53

    override fun prf(domain: Int, input: ByteArray): Double {
        val m = checkNotNull(mac.get()) { "no mac" }
        val out = m.doFinal(ByteBuffer.allocate(4 + input.size).putInt(domain).put(input).array())
        return (ByteBuffer.wrap(out, 0, 8).long ushr 11) * TWO_POW_MINUS_53
    }

    /** Never shows the key (T3). */
    override fun toString(): String = "SecureEntitlementRandom(redacted)"

    private companion object {
        const val KEY_SIZE = 32
        const val MAX_BYTES = 64
        const val ALGORITHM = "HmacSHA256"
        const val TWO_POW_MINUS_53: Double = 1.0 / (1L shl 53)
    }
}
