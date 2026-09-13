package org.ghost.network

/**
 * Stateless entitlement functions of the Rust core (Phase 8 design §11.7) over the Entitlement
 * Schedule built into `libghost_client_net.so`, which the native side verifies under the pinned
 * schedule key at first use. Kotlin never handles the ES bytes, keys, blinded messages or blind
 * signatures: it gets the verified [ScheduleSummary], layout digests, offline token verdicts,
 * validated addresses and the payment URI. Native results are fixed-layout byte strings
 * (integers big-endian) decoded strictly here: a length, count or value outside the layout is
 * `malformed_response`. Failures are [NetworkException] categories (`internal` if the embedded
 * schedule does not verify).
 */
object EntitlementCrypto {
    const val PRODUCT_PACK_XMR = 1
    const val PRODUCT_PACK_CREDITS = 2
    const val PRODUCT_TRIAL = 3
    const val PRODUCT_REFRESH = 4

    const val KIND_ACCESS = 1
    const val KIND_INVITE = 2
    const val KIND_CREDIT = 3

    const val PURPOSE_INVOICE = 1
    const val PURPOSE_PAYOUT = 2

    const val ADDRESS_STANDARD = 1
    const val ADDRESS_SUBADDRESS = 2

    /** Slot byte of a token without a relay slot (invite, credit). */
    const val NO_SLOT = 0xFF

    const val TOKEN_BYTES = 354

    private const val MALFORMED = "malformed_response"
    private const val MAX_SLOT = 31

    /** The verified summary of the embedded ES (read it once per process and keep it). */
    fun scheduleSummary(): ScheduleSummary {
        NativeLibrary.ensureLoaded()
        return decodeSummary(nativeScheduleSummary())
    }

    /**
     * The frozen layout of [product] at [index] (the base week of a pack or trial, the credit epoch
     * of a refresh): its digest, stored at purchase time, and its number of positions.
     */
    fun layout(product: Int, index: Long): Layout {
        require(product in PRODUCT_PACK_XMR..PRODUCT_REFRESH) { "unknown product" }
        require(index >= 0) { "index must not be negative" }
        NativeLibrary.ensureLoaded()
        return decodeLayout(nativeLayoutDigest(product, index))
    }

    /**
     * The offline check of a token under the embedded ES for [kind] (access: any slot of its week),
     * or null when the schedule refuses it (unknown or revoked key, another kind, a wrong
     * challenge or authenticator). The acceptance window of the epoch is the caller's check.
     */
    fun verifyToken(token: ByteArray, kind: Int): VerifiedToken? {
        require(kind in KIND_ACCESS..KIND_CREDIT) { "unknown token kind" }
        NativeLibrary.ensureLoaded()
        val raw = try {
            nativeVerifyToken(token, kind)
        } catch (e: NetworkException) {
            if (e.category == "rejected") return null
            throw e
        }
        return decodeVerified(raw, kind)
    }

    /**
     * Validates a Monero address of the ES network for [purpose] (an invoice takes a subaddress, a
     * payout a standard address or a subaddress), or null when it is refused.
     */
    fun validateAddress(address: String, purpose: Int): AddressInfo? {
        require(purpose == PURPOSE_INVOICE || purpose == PURPOSE_PAYOUT) { "unknown address purpose" }
        NativeLibrary.ensureLoaded()
        val code = try {
            nativeValidateAddress(address, purpose)
        } catch (e: NetworkException) {
            if (e.category == "rejected") return null
            throw e
        }
        return decodeAddress(code)
    }

    /** `monero:<subaddress>?tx_amount=<12 decimals>`, built natively from validated values. */
    fun paymentUri(subaddress: String, amountAtomic: Long): String {
        require(amountAtomic > 0) { "amount must be positive" }
        NativeLibrary.ensureLoaded()
        return nativePaymentUri(subaddress, amountAtomic)
    }

    /** Protocol constants of the ES. */
    data class Constants(
        val confirmations: Int,
        val invoiceBlocks: Int,
        val graceBlocks: Int,
        val accessPerSlot: Int,
        val trialPerSlot: Int,
        val invitesPerPack: Int,
        val creditsPerFreePack: Int,
        val minClaimCredits: Int,
        val maxClaimCredits: Int,
        val earlyWindowHours: Int,
        val capabilityQuotaBytes: Long,
    )

    /** Slot [slot] is served by [onion] in weeks `[validFromWeek, validUntilWeek)` (0 = open). */
    data class Slot(val slot: Int, val validFromWeek: Long, val validUntilWeek: Long, val onion: OnionAddress) {
        fun validIn(week: Long): Boolean = validFromWeek <= week && (validUntilWeek == 0L || week < validUntilWeek)
    }

    data class Price(val priceEpoch: Long, val packPriceAtomic: Long)

    /** A key of the ES: its (kind, epoch) and key id (what `ent_key` remembers). */
    class KeyId(val kind: Int, val epoch: Long, keyId: ByteArray) {
        private val id = keyId.copyOf()
        fun keyId(): ByteArray = id.copyOf()
        override fun equals(other: Any?): Boolean =
            other is KeyId && other.kind == kind && other.epoch == epoch && other.id.contentEquals(id)
        override fun hashCode(): Int = 31 * (31 * kind + epoch.hashCode()) + id.contentHashCode()
        override fun toString(): String = "KeyId(kind=$kind, epoch=$epoch)"
    }

    data class Revoked(val kind: Int, val epoch: Long)

    /** The verified ES as Kotlin sees it (rule 5 memory: keys, week slot sets, prices, revocations). */
    class ScheduleSummary(
        digest: ByteArray,
        val seq: Long,
        val network: Int,
        val firstWeek: Long,
        val lastWeek: Long,
        val constants: Constants,
        val slots: List<Slot>,
        val prices: List<Price>,
        val keys: List<KeyId>,
        val revoked: List<Revoked>,
    ) {
        private val digestBytes = digest.copyOf()
        fun digest(): ByteArray = digestBytes.copyOf()

        /** Slot numbers valid in [week], ascending (the layout order, design §4.2). */
        fun slotsInWeek(week: Long): List<Int> = slots.filter { it.validIn(week) }.map { it.slot }.distinct().sorted()

        override fun toString(): String = "ScheduleSummary(seq=$seq, network=$network, weeks=$firstWeek..$lastWeek)"
    }

    /** A frozen layout: the digest stored at purchase time and the number of positions. */
    class Layout(digest: ByteArray, val positions: Int) {
        private val digestBytes = digest.copyOf()
        fun digest(): ByteArray = digestBytes.copyOf()
        override fun toString(): String = "Layout(positions=$positions)"
    }

    /** A token that verified offline: its (kind, epoch, slot) and nullifier (a secret, R10). */
    class VerifiedToken(val kind: Int, val epoch: Long, val slot: Int?, nullifier: ByteArray) {
        private val nullifierBytes = nullifier.copyOf()
        fun nullifier(): ByteArray = nullifierBytes.copyOf()
        override fun toString(): String = "VerifiedToken(kind=$kind, epoch=$epoch)"
    }

    data class AddressInfo(val network: Int, val type: Int)

    /** Strict big-endian reader: any read past the end is `malformed_response`. */
    private class Reader(private val raw: ByteArray) {
        var at = 0
            private set

        fun u8(): Int {
            if (at + 1 > raw.size) throw NetworkException(MALFORMED)
            return raw[at++].toInt() and 0xff
        }

        fun u16(): Int = (u8() shl 8) or u8()

        /** An unsigned 64-bit value that must fit a non-negative Long. */
        fun u64(): Long {
            var v = 0L
            repeat(8) { v = (v shl 8) or u8().toLong() }
            if (v < 0) throw NetworkException(MALFORMED)
            return v
        }

        fun bytes(n: Int): ByteArray {
            if (n < 0 || at + n > raw.size) throw NetworkException(MALFORMED)
            return raw.copyOfRange(at, at + n).also { at += n }
        }

        fun end() {
            if (at != raw.size) throw NetworkException(MALFORMED)
        }
    }

    private fun kindOk(kind: Int) = kind in KIND_ACCESS..KIND_CREDIT

    /** Layout of `client-core/net/src/entitlement.rs` `schedule_summary`. */
    internal fun decodeSummary(raw: ByteArray): ScheduleSummary {
        val r = Reader(raw)
        val digest = r.bytes(32)
        val seq = r.u64()
        val network = r.u8()
        val first = r.u64()
        val last = r.u64()
        if (seq < 1 || network !in 1..3 || last < first) throw NetworkException(MALFORMED)
        val constants = Constants(
            confirmations = r.u8(),
            invoiceBlocks = r.u16(),
            graceBlocks = r.u16(),
            accessPerSlot = r.u8(),
            trialPerSlot = r.u8(),
            invitesPerPack = r.u8(),
            creditsPerFreePack = r.u8(),
            minClaimCredits = r.u8(),
            maxClaimCredits = r.u8(),
            earlyWindowHours = r.u8(),
            capabilityQuotaBytes = r.u64(),
        )
        val slots = List(r.u8()) {
            val slot = r.u8()
            val from = r.u64()
            val until = r.u64()
            val text = String(r.bytes(r.u8()), Charsets.US_ASCII)
            if (slot > MAX_SLOT || (until != 0L && until <= from)) throw NetworkException(MALFORMED)
            val onion = try {
                OnionAddress.parse(text)
            } catch (e: IllegalArgumentException) {
                throw NetworkException(MALFORMED)
            }
            Slot(slot, from, until, onion)
        }
        val prices = List(r.u16()) { Price(r.u64(), r.u64()) }
        val keys = List(r.u16()) {
            val kind = r.u8()
            val epoch = r.u64()
            if (!kindOk(kind)) throw NetworkException(MALFORMED)
            KeyId(kind, epoch, r.bytes(32))
        }
        val revoked = List(r.u16()) {
            val kind = r.u8()
            if (!kindOk(kind)) throw NetworkException(MALFORMED)
            Revoked(kind, r.u64())
        }
        r.end()
        return ScheduleSummary(digest, seq, network, first, last, constants, slots, prices, keys, revoked)
    }

    /** `digest(32) || N(4)`, N >= 1. */
    internal fun decodeLayout(raw: ByteArray): Layout {
        val r = Reader(raw)
        val digest = r.bytes(32)
        val n = (r.u16() shl 16) or r.u16()
        r.end()
        if (n < 1) throw NetworkException(MALFORMED)
        return Layout(digest, n)
    }

    /** `kind(1) || epoch(8) || slot(1) || nullifier(32)` for a token checked as [kind]. */
    internal fun decodeVerified(raw: ByteArray, kind: Int): VerifiedToken {
        val r = Reader(raw)
        val gotKind = r.u8()
        val epoch = r.u64()
        val slot = r.u8()
        val nullifier = r.bytes(32)
        r.end()
        if (gotKind != kind) throw NetworkException(MALFORMED)
        val slotOk = if (kind == KIND_ACCESS) slot <= MAX_SLOT else slot == NO_SLOT
        if (!slotOk) throw NetworkException(MALFORMED)
        return VerifiedToken(kind, epoch, if (kind == KIND_ACCESS) slot else null, nullifier)
    }

    /** `(network << 8) | type`, network 1..3, type standard or subaddress. */
    internal fun decodeAddress(code: Int): AddressInfo {
        val network = code ushr 8
        val type = code and 0xff
        if (network !in 1..3 || (type != ADDRESS_STANDARD && type != ADDRESS_SUBADDRESS)) throw NetworkException(MALFORMED)
        return AddressInfo(network, type)
    }

    @JvmStatic private external fun nativeScheduleSummary(): ByteArray
    @JvmStatic private external fun nativeLayoutDigest(product: Int, index: Long): ByteArray
    @JvmStatic private external fun nativeVerifyToken(token: ByteArray, kind: Int): ByteArray
    @JvmStatic private external fun nativeValidateAddress(address: String, purpose: Int): Int
    @JvmStatic private external fun nativePaymentUri(subaddress: String, amountAtomic: Long): String
}
