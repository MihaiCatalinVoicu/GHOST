package org.ghost.network

import java.security.SecureRandom

/**
 * Issuer calls of the Rust core (Phase 8 design §5.3, §8.3, §9.4, §19.8, §11.7) on the Tor client
 * of a [TorRelayTransport]: one Tor transport per process, the same native handle.
 *
 * Every call names its issuer flow with 16 random bytes ([newFlow]), one flow per purchase step,
 * trial, claim, refresh or revocation: the flow's calls share circuits with no other flow and no
 * namespace, and [endFlow] drops the flow's circuits. The destination is the issuer onion of the
 * Entitlement Schedule built into the native library; no caller chooses it, and no request carries
 * a client timestamp. Before any I/O the native side checks the request (the layout recomputed and
 * compared with [layoutDigest][EntitlementCrypto.Layout], the request recomputed from the seed so
 * every retry is byte-identical, credits and invites verified under the ES); every answer is
 * validated there against the ES (amounts, subaddress network, signature counts, `s'^e == B`,
 * `ring`) and decoded strictly here. Protocol outcomes (`WRONG_PERIOD`, `CREDITS_SPENT`,
 * `CLAIM_CONFLICT`, `OTHER_REQUEST_ISSUED`, `REPLAYED`, `ADDRESS_REJECTED`) are results, not
 * exceptions. Seeds, blinded messages and blind signatures never reach Kotlin.
 *
 * Blocking: run off the main thread. Failures are [NetworkException] with a constant category
 * (issuer statuses map onto the existing ones, design §5.7), or [IllegalArgumentException] for
 * arguments refused before the native call.
 */
class TorIssuerTransport internal constructor(private val native: HandleCall) {
    constructor(tor: TorRelayTransport) : this(HandleCall { block -> tor.withHandle(block) })

    /** Runs one native call with the transport's handle id. */
    internal fun interface HandleCall {
        fun run(block: (Long) -> ByteArray): ByteArray
    }

    /**
     * `RequestInvoice`: [claimHash] (32 bytes), [credits] (none for XMR, or the smallest covering
     * set of CREDIT tokens), [baseWeek] from the device clock under `clockTrusted()` (never a relay
     * value, §19.4).
     */
    fun requestInvoice(
        flow: ByteArray,
        claimHash: ByteArray,
        credits: List<ByteArray>,
        baseWeek: Long,
        deadlineMillis: Int = MAX_DEADLINE_MILLIS,
    ): InvoiceAnswer {
        requireFlow(flow)
        require(claimHash.size == 32) { "claim hash must be 32 bytes" }
        require(baseWeek >= 0) { "base week must not be negative" }
        requireDeadline(deadlineMillis, MAX_DEADLINE_MILLIS)
        val packed = packTokens(credits, MAX_DISCOUNT_CREDITS)
        val raw = native.run { nativeRequestInvoice(it, flow, claimHash, packed, baseWeek, deadlineMillis) }
        return decodeInvoice(raw, credits.size)
    }

    /**
     * `BlindSign` of a pack ([product] pack-xmr or pack-credits) whose layout has [positions]
     * positions and the stored [layoutDigest]. On `SIGNED` the answer holds the tokens with their
     * nullifiers, in layout order.
     */
    fun blindSign(
        flow: ByteArray,
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int = MAX_SIGNING_DEADLINE_MILLIS,
    ): SignAnswer {
        requireFlow(flow)
        require(invoiceId.size == 16 && claimKey.size == 32 && seed.size == 32 && layoutDigest.size == 32) {
            "invoice id 16, claim key 32, seed 32, layout digest 32 bytes"
        }
        require(product == EntitlementCrypto.PRODUCT_PACK_XMR || product == EntitlementCrypto.PRODUCT_PACK_CREDITS) {
            "blind sign takes a pack"
        }
        require(baseWeek >= 0 && positions in 1..MAX_LAYOUT_POSITIONS) { "base week or positions out of range" }
        requireDeadline(deadlineMillis, MAX_SIGNING_DEADLINE_MILLIS)
        val raw = native.run {
            nativeBlindSign(it, flow, invoiceId, claimKey, seed, product, baseWeek, layoutDigest, deadlineMillis)
        }
        return decodeSign(raw, positions)
    }

    /** `InvoiceStatus` (the optional "check now", a declared presence sample): never signs. */
    fun invoiceStatus(flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMillis: Int = MAX_DEADLINE_MILLIS): StatusAnswer {
        requireFlow(flow)
        require(invoiceId.size == 16 && claimKey.size == 32) { "invoice id 16, claim key 32 bytes" }
        requireDeadline(deadlineMillis, MAX_DEADLINE_MILLIS)
        return decodeStatus(native.run { nativeInvoiceStatus(it, flow, invoiceId, claimKey, deadlineMillis) })
    }

    /** `RedeemInvite` for a trial of [positions] positions (the invite token is verified offline natively first). */
    fun redeemInvite(
        flow: ByteArray,
        inviteToken: ByteArray,
        seed: ByteArray,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
        deadlineMillis: Int = MAX_SIGNING_DEADLINE_MILLIS,
    ): TrialAnswer {
        requireFlow(flow)
        require(inviteToken.size == TOKEN_BYTES && seed.size == 32 && layoutDigest.size == 32) {
            "invite token 354, seed 32, layout digest 32 bytes"
        }
        require(baseWeek >= 0 && positions in 1..MAX_LAYOUT_POSITIONS) { "base week or positions out of range" }
        requireDeadline(deadlineMillis, MAX_SIGNING_DEADLINE_MILLIS)
        val raw = native.run { nativeRedeemInvite(it, flow, inviteToken, seed, baseWeek, layoutDigest, deadlineMillis) }
        return decodeTrial(raw, positions)
    }

    /** `ClaimPayout` of [credits] (`min_claim_credits .. max_claim_credits`) to an ES-network [payoutAddress]. */
    fun claimPayout(
        flow: ByteArray,
        claimId: ByteArray,
        credits: List<ByteArray>,
        payoutAddress: String,
        deadlineMillis: Int = MAX_DEADLINE_MILLIS,
    ): ClaimAnswer {
        requireFlow(flow)
        require(claimId.size == 16) { "claim id must be 16 bytes" }
        require(credits.isNotEmpty()) { "a claim needs credits" }
        requireDeadline(deadlineMillis, MAX_DEADLINE_MILLIS)
        val packed = packTokens(credits, MAX_MASKED_CREDITS)
        val raw = native.run { nativeClaimPayout(it, flow, claimId, packed, payoutAddress, deadlineMillis) }
        return decodeClaim(raw, credits.size)
    }

    /** `RefreshCredit` of a received credit for one fresh credit of the same epoch (§19.8). */
    fun refreshCredit(
        flow: ByteArray,
        receivedCredit: ByteArray,
        seed: ByteArray,
        layoutDigest: ByteArray,
        deadlineMillis: Int = MAX_DEADLINE_MILLIS,
    ): RefreshAnswer {
        requireFlow(flow)
        require(receivedCredit.size == TOKEN_BYTES && seed.size == 32 && layoutDigest.size == 32) {
            "credit 354, seed 32, layout digest 32 bytes"
        }
        requireDeadline(deadlineMillis, MAX_DEADLINE_MILLIS)
        val raw = native.run { nativeRefreshCredit(it, flow, receivedCredit, seed, layoutDigest, deadlineMillis) }
        return decodeRefresh(raw)
    }

    /** Ends a flow: its circuits are never used again. Idempotent. */
    fun endFlow(flow: ByteArray) {
        requireFlow(flow)
        native.run {
            nativeEndFlow(it, flow)
            ByteArray(0)
        }
    }

    /** One issued token and its nullifier (bearer value: never printed). */
    class IssuedToken(nullifier: ByteArray, token: ByteArray) {
        private val nullifierBytes = nullifier.copyOf()
        private val tokenBytes = token.copyOf()
        fun nullifier(): ByteArray = nullifierBytes.copyOf()
        fun token(): ByteArray = tokenBytes.copyOf()
        override fun toString(): String = "IssuedToken(..)"
    }

    /** `RequestInvoice`: [result] one of the `INVOICE_*` values. */
    class InvoiceAnswer(val result: Int, invoiceId: ByteArray, val amountAtomic: Long, val subaddress: String?, val spentMask: Long) {
        private val id = invoiceId.copyOf()
        fun invoiceId(): ByteArray = id.copyOf()
        override fun toString(): String = "InvoiceAnswer(result=$result)"
    }

    /** `BlindSign`: [state] one of the `STATE_*` values; [tokens] on `STATE_SIGNED` only. */
    class SignAnswer(val state: Int, val creditedAtomic: Long, val seenAtomic: Long, val tokens: List<IssuedToken>) {
        override fun toString(): String = "SignAnswer(state=$state, tokens=${tokens.size})"
    }

    class StatusAnswer(val state: Int, val creditedAtomic: Long, val seenAtomic: Long) {
        override fun toString(): String = "StatusAnswer(state=$state)"
    }

    /** `RedeemInvite`: [result] one of the `TRIAL_*` values; [tokens] on `TRIAL_OK` only. */
    class TrialAnswer(val result: Int, val tokens: List<IssuedToken>) {
        override fun toString(): String = "TrialAnswer(result=$result, tokens=${tokens.size})"
    }

    /** `ClaimPayout`: [result] one of the `CLAIM_*` values; [spentMask] bit i names credit i. */
    class ClaimAnswer(val result: Int, val queuedAtomic: Long, val spentMask: Long) {
        override fun toString(): String = "ClaimAnswer(result=$result)"
    }

    /** `RefreshCredit`: [result] one of the `REFRESH_*` values; [token] on `REFRESH_OK` only. */
    class RefreshAnswer(val result: Int, val token: IssuedToken?) {
        override fun toString(): String = "RefreshAnswer(result=$result)"
    }

    companion object {
        const val FLOW_BYTES = 16
        const val TOKEN_BYTES = 354
        const val ISSUED_TOKEN_BYTES = 32 + TOKEN_BYTES

        /** Deadline bound of ordinary issuer calls and of `BlindSign`/`RedeemInvite` (native bounds too). */
        const val MAX_DEADLINE_MILLIS = 60_000
        const val MAX_SIGNING_DEADLINE_MILLIS = 120_000

        /** Largest layout (5 weeks x 32 slots x 16 + 3), a credits-paid set, a claim's mask. */
        const val MAX_LAYOUT_POSITIONS = 2_563
        const val MAX_DISCOUNT_CREDITS = 20
        const val MAX_MASKED_CREDITS = 64

        const val INVOICE_OK = 1
        const val INVOICE_WRONG_PERIOD = 2
        const val INVOICE_CREDITS_SPENT = 3
        const val INVOICE_CLAIM_CONFLICT = 4

        const val STATE_SIGNED = 1
        const val STATE_AWAITING_PAYMENT = 2
        const val STATE_AWAITING_CONFIRMATIONS = 3
        const val STATE_UNDERPAID = 4
        const val STATE_EXPIRED = 5
        const val STATE_OTHER_REQUEST_ISSUED = 6

        const val TRIAL_OK = 1
        const val TRIAL_REPLAYED = 2
        const val TRIAL_WRONG_PERIOD = 3

        const val CLAIM_QUEUED = 1
        const val CLAIM_CREDITS_SPENT = 2
        const val CLAIM_CONFLICT = 3
        const val CLAIM_ADDRESS_REJECTED = 4

        const val REFRESH_OK = 1
        const val REFRESH_REPLAYED = 2

        private const val MALFORMED = "malformed_response"
        private const val SUBADDRESS_CHARS = 95

        /** A fresh 16-byte flow id from [random] (a CSPRNG; one per flow instance, never reused). */
        fun newFlow(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(FLOW_BYTES).also(random::nextBytes)

        internal fun requireFlow(flow: ByteArray) = require(flow.size == FLOW_BYTES) { "flow id must be 16 bytes" }

        internal fun requireDeadline(deadlineMillis: Int, max: Int) =
            require(deadlineMillis in 1..max) { "deadline must be 1..$max ms" }

        /** Tokens of 354 bytes each, at most [max], concatenated. */
        internal fun packTokens(tokens: List<ByteArray>, max: Int): ByteArray {
            require(tokens.size <= max) { "at most $max tokens" }
            require(tokens.all { it.size == TOKEN_BYTES }) { "tokens must be 354 bytes" }
            val out = ByteArray(tokens.size * TOKEN_BYTES)
            tokens.forEachIndexed { i, t -> t.copyInto(out, i * TOKEN_BYTES) }
            return out
        }

        private fun malformed(): Nothing = throw NetworkException(MALFORMED)

        private fun long(raw: ByteArray, at: Int): Long {
            var v = 0L
            for (i in at until at + 8) v = (v shl 8) or (raw[i].toLong() and 0xff)
            return v
        }

        private fun nonNegative(raw: ByteArray, at: Int): Long = long(raw, at).also { if (it < 0) malformed() }

        private fun u32(raw: ByteArray, at: Int): Long {
            var v = 0L
            for (i in at until at + 4) v = (v shl 8) or (raw[i].toLong() and 0xff)
            return v
        }

        /** `count x (nullifier(32) || token(354))` from [at] to the end. */
        private fun issued(raw: ByteArray, at: Int, count: Int): List<IssuedToken> {
            if (raw.size != at + count * ISSUED_TOKEN_BYTES) malformed()
            return List(count) { i ->
                val o = at + i * ISSUED_TOKEN_BYTES
                IssuedToken(raw.copyOfRange(o, o + 32), raw.copyOfRange(o + 32, o + ISSUED_TOKEN_BYTES))
            }
        }

        /** A mask naming only the first [count] credits, at least one. */
        private fun maskFits(mask: Long, count: Int): Boolean =
            mask != 0L && (count >= 64 || (mask ushr count) == 0L)

        /** `result(1) || invoice_id(16) || amount(8) || subaddress(0 or 95) || spent_mask(4)`. */
        internal fun decodeInvoice(raw: ByteArray, creditCount: Int): InvoiceAnswer {
            if (raw.size != 29 && raw.size != 29 + SUBADDRESS_CHARS) malformed()
            val result = raw[0].toInt() and 0xff
            val id = raw.copyOfRange(1, 17)
            val amount = nonNegative(raw, 17)
            val subaddress = if (raw.size > 29) String(raw.copyOfRange(25, 25 + SUBADDRESS_CHARS), Charsets.US_ASCII) else null
            val mask = u32(raw, raw.size - 4)
            val bare = id.all { it == 0.toByte() } && amount == 0L && subaddress == null
            val ok = when (result) {
                INVOICE_OK -> mask == 0L && (subaddress != null) == (amount > 0) &&
                    (subaddress == null || subaddress.all { it.code in 0x21..0x7e }) && (creditCount == 0) == (amount > 0)
                INVOICE_CREDITS_SPENT -> bare && creditCount > 0 && maskFits(mask, creditCount)
                INVOICE_WRONG_PERIOD, INVOICE_CLAIM_CONFLICT -> bare && mask == 0L
                else -> false
            }
            if (!ok) malformed()
            return InvoiceAnswer(result, id, amount, subaddress, mask)
        }

        /** `state(1) || credited(8) || seen(8)`, then on SIGNED [positions] issued tokens. */
        internal fun decodeSign(raw: ByteArray, positions: Int): SignAnswer {
            if (raw.size < 17) malformed()
            val state = raw[0].toInt() and 0xff
            if (state !in STATE_SIGNED..STATE_OTHER_REQUEST_ISSUED) malformed()
            val tokens = issued(raw, 17, if (state == STATE_SIGNED) positions else 0)
            return SignAnswer(state, nonNegative(raw, 1), nonNegative(raw, 9), tokens)
        }

        /** `state(1) || credited(8) || seen(8)`. */
        internal fun decodeStatus(raw: ByteArray): StatusAnswer {
            if (raw.size != 17) malformed()
            val state = raw[0].toInt() and 0xff
            if (state !in STATE_SIGNED..STATE_OTHER_REQUEST_ISSUED) malformed()
            return StatusAnswer(state, nonNegative(raw, 1), nonNegative(raw, 9))
        }

        /** `result(1)`, then on OK [positions] issued tokens. */
        internal fun decodeTrial(raw: ByteArray, positions: Int): TrialAnswer {
            if (raw.isEmpty()) malformed()
            val result = raw[0].toInt() and 0xff
            if (result !in TRIAL_OK..TRIAL_WRONG_PERIOD) malformed()
            return TrialAnswer(result, issued(raw, 1, if (result == TRIAL_OK) positions else 0))
        }

        /** `result(1) || queued(8) || spent_mask(8)`. */
        internal fun decodeClaim(raw: ByteArray, creditCount: Int): ClaimAnswer {
            if (raw.size != 17) malformed()
            val result = raw[0].toInt() and 0xff
            val queued = nonNegative(raw, 1)
            val mask = long(raw, 9)
            val ok = when (result) {
                CLAIM_QUEUED -> queued > 0 && mask == 0L
                CLAIM_CREDITS_SPENT -> queued == 0L && maskFits(mask, creditCount)
                CLAIM_CONFLICT, CLAIM_ADDRESS_REJECTED -> queued == 0L && mask == 0L
                else -> false
            }
            if (!ok) malformed()
            return ClaimAnswer(result, queued, mask)
        }

        /** `result(1)`, then on OK one issued token. */
        internal fun decodeRefresh(raw: ByteArray): RefreshAnswer {
            if (raw.isEmpty()) malformed()
            val result = raw[0].toInt() and 0xff
            if (result != REFRESH_OK && result != REFRESH_REPLAYED) malformed()
            val tokens = issued(raw, 1, if (result == REFRESH_OK) 1 else 0)
            return RefreshAnswer(result, tokens.firstOrNull())
        }

        @JvmStatic private external fun nativeRequestInvoice(
            id: Long, flow: ByteArray, claimHash: ByteArray, credits: ByteArray, baseWeek: Long, deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeBlindSign(
            id: Long, flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, seed: ByteArray, product: Int,
            baseWeek: Long, layoutDigest: ByteArray, deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeInvoiceStatus(
            id: Long, flow: ByteArray, invoiceId: ByteArray, claimKey: ByteArray, deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeRedeemInvite(
            id: Long, flow: ByteArray, inviteToken: ByteArray, seed: ByteArray, baseWeek: Long, layoutDigest: ByteArray,
            deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeClaimPayout(
            id: Long, flow: ByteArray, claimId: ByteArray, credits: ByteArray, address: String, deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeRefreshCredit(
            id: Long, flow: ByteArray, receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray, deadlineMs: Int,
        ): ByteArray
        @JvmStatic private external fun nativeEndFlow(id: Long, flow: ByteArray)
    }
}
