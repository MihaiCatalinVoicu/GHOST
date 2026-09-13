package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Position
import org.ghost.network.EntitlementCrypto
import org.ghost.network.TorIssuerTransport
import java.security.MessageDigest

/**
 * The issuer of the `:entitlement` harness (Phase 8 design §13.2 "Conformance models"): exactly the
 * rules pinned by `protocol/test-vectors/issuer_semantics.txt`, which [ModelIssuerConformanceTest]
 * replays against it (the real issuer replays the same file, `semantics_vectors.rs`), so the model
 * cannot drift from the issuer. A behaviour the vectors do not pin is not one the harness relies on.
 *
 * Rules (design §5.4–§5.6, §19.1, §19.5, §19.6, §19.8, §19.9, §19.22):
 *  - `RequestInvoice`: sizes; idempotency by `claim_hash` first (the same digest R re-serves the
 *    invoice, another is `CLAIM_CONFLICT`); the schedule covers the layout; `base_week ∈ {week(t −
 *    4 h), week(t + 4 h)}` else `WRONG_PERIOD` (nothing recorded); the price; credits (valid CREDIT
 *    tokens of `c_now − 4 … c_now`, distinct, the smallest covering set) else `PERMISSION_DENIED`,
 *    spent ones `CREDITS_SPENT`; XMR needs a synced scanner tick younger than 2 minutes, else
 *    `UNAVAILABLE`. XMR invoices take the next pool minor; credits-paid ones are CONFIRMED at once.
 *  - The scanner (a tick): credited = transfers with ≥ C confirmations mined at a height in
 *    [created − 20, grace]; seen = pool transfers and those below C; CONFIRMED once credited ≥ amount;
 *    EXPIRED only from a synced view at wallet height ≥ grace + C; ISSUED keeps its amounts
 *    current; purge 5 040 blocks after issuance or expiry (21 600 for CONFIRMED-unissued).
 *  - `BlindSign`: sizes; the claim key (an unknown invoice and a wrong key answer alike); unpaid
 *    states answer their state; every block in [1, n − 1] under its position's key; CONFIRMED signs
 *    and records the digest D; ISSUED re-signs D byte-identically, another digest is
 *    `OTHER_REQUEST_ISSUED`.
 *  - `RedeemInvite`: a valid INVITE token of any listed epoch; idempotency by (epoch, nullifier)
 *    before validity (the same trial digest re-signs, another is `REPLAYED`); new redemptions need
 *    `e_now` or `e_now − 1`, a base week within the tolerance, the trial layout.
 *  - `ClaimPayout`: sizes; idempotency by claim id; the address; 10…50 valid credits; spent credits;
 *    the address of a queued claim is refused.
 *  - `RefreshCredit`: a valid CREDIT token of any listed epoch; idempotency by nullifier (the same
 *    refresh digest re-signs, any other use is `REPLAYED`); new refreshes of `c_now` or `c_now − 1`.
 *
 * Categories are the client's (`for_issuer`, §5.7): `rejected`, `unauthorized`, `relay_unavailable`.
 * Signing goes through [SigningCache] (deterministic per (key, B)). The model also keeps what the
 * harness invariants read: every invoice ever created with every `BlindSign` digest it received
 * (MS-1), and a mutation count (crash classification).
 */
internal class ModelIssuer(
    val schedule: TestSchedule,
    /** Issuer randomness: invoice ids (NI-1 worlds vary it). */
    private val idSeed: Long = 0,
    /** The first pool minor handed out (NI-1 worlds vary it). */
    firstMinor: Int = 1,
    startBlocks: Long = START_BLOCKS,
) {
    sealed class Reply<out T> {
        class Ok<T>(val value: T) : Reply<T>()

        class Err(val category: String) : Reply<Nothing>() {
            override fun toString(): String = "Err($category)"
        }
    }

    class InvoiceAnswer(val result: Int, invoiceId: ByteArray, val amount: Long, val subaddress: String?, val spentMask: Long) {
        private val id = invoiceId.copyOf()
        fun invoiceId(): ByteArray = id.copyOf()
    }

    class SignAnswer(val state: Int, val credited: Long, val seen: Long, val signatures: ByteArray)

    class StatusAnswer(val state: Int, val credited: Long, val seen: Long)

    class TrialAnswer(val result: Int, val signatures: ByteArray)

    class ClaimAnswer(val result: Int, val queued: Long, val spentMask: Long)

    class RefreshAnswer(val result: Int, val signature: ByteArray)

    enum class State { CREATED, SEEN, CONFIRMED, ISSUED, EXPIRED }

    class Invoice(
        val id: ByteArray,
        val claimHash: ByteArray,
        val r: ByteArray,
        val xmr: Boolean,
        val minor: Int,
        val subaddress: String?,
        val amount: Long,
        val baseWeek: Long,
        val createdHeight: Long,
        val graceHeight: Long,
        var state: State,
    ) {
        var credited = 0L
        var seen = 0L
        var confirmedHeight = 0L
        var issuedHeight = 0L
        var purgeHeight = 0L
        var issuedDigest: ByteArray? = null
        var purged = false

        /** Every `BlindSign` digest D this invoice was ever asked for (MS-1: at most one). */
        val requestDigests = LinkedHashSet<String>()

        /** The tokens the harness client finalized from this invoice's signatures (MS-6). */
        val finalized = LinkedHashSet<String>()

        override fun toString(): String = "Invoice($state)"
    }

    private class Refusal(val category: String) : Exception(category)

    private class Transfer(val minor: Int, val amount: Long, var height: Long?)

    private class Tick(val at: Long, val synced: Boolean, val height: Long)

    private class Claim(val digest: ByteArray, val amount: Long, val address: String)

    private class Presented(val epoch: Long, val nullifier: ByteArray, val value: Long) {
        val key: String get() = "$epoch:${Bytes.hex(nullifier)}"
    }

    var blocks: Long = startBlocks
        private set
    var synced: Boolean = true
    private val transfers = ArrayList<Transfer>()
    private var lastTick: Tick? = null
    private var lastWalletHeight: Long? = null
    private var nextMinor = firstMinor
    private var ids = 0L

    /** State changes (crash-point classification of the harness). */
    var mutations: Long = 0
        private set

    private val invoices = LinkedHashMap<String, Invoice>()
    private val claimIndex = HashMap<String, String>()
    private val creditUse = HashMap<String, String>()
    private val inviteUse = HashMap<String, String>()
    private val claims = HashMap<String, Claim>()

    /** Every invoice ever created, purged ones included (the harness invariants read it). */
    val history = LinkedHashMap<String, Invoice>()

    private val c: Long get() = schedule.constants.confirmations.toLong()

    // ------------------------------------------------------------------ the wallet's chain

    /** A pool transfer to [minor]. */
    fun pay(minor: Int, amount: Long) {
        transfers += Transfer(minor, amount, null)
        mutations++
    }

    fun minorOf(invoiceId: ByteArray): Int = checkNotNull(history[Bytes.hex(invoiceId)]) { "unknown invoice" }.minor

    fun invoice(invoiceId: ByteArray): Invoice? = history[Bytes.hex(invoiceId)]

    /** The invoice holding [subaddress] (the user pays what the payment instructions show). */
    fun bySubaddress(subaddress: String): Invoice? = history.values.firstOrNull { it.subaddress == subaddress }

    /** Mines every pool transfer into the next block and adds [n] blocks (the scanner is not run). */
    fun mine(n: Long) {
        require(n >= 1) { "mine at least one block" }
        for (t in transfers) if (t.height == null) t.height = blocks
        blocks += n
        mutations++
    }

    /**
     * The scanner of a running issuer ticks every [periodSeconds] (the harness ticks lazily, before a
     * call, when the last tick is that old; the vector file ticks explicitly).
     */
    fun tickIfStale(now: Long, periodSeconds: Long = SCANNER_PERIOD_SECS) {
        val t = lastTick
        if (t == null || now - t.at >= periodSeconds || now < t.at) tick(now)
    }

    /** One scanner tick at [now] (design §7.3): recomputes every open XMR invoice, then purges. */
    fun tick(now: Long) {
        lastTick = Tick(now, synced, blocks)
        lastWalletHeight = blocks
        for (inv in invoices.values) {
            if (inv.state == State.CONFIRMED && inv.confirmedHeight == 0L) inv.confirmedHeight = blocks
            if (inv.state == State.ISSUED && inv.issuedHeight == 0L) inv.issuedHeight = blocks
            if (!inv.xmr) continue
            when (inv.state) {
                State.EXPIRED -> Unit
                State.ISSUED -> amounts(inv).let { (credited, seen) ->
                    inv.credited = credited
                    inv.seen = seen
                }
                else -> recompute(inv)
            }
        }
        val doomed = invoices.values.filter { purgeDue(it) }
        for (inv in doomed) {
            inv.purged = true
            invoices.remove(Bytes.hex(inv.id))
            claimIndex.remove(Bytes.hex(inv.claimHash))
        }
        mutations++
    }

    private fun amounts(inv: Invoice): Pair<Long, Long> {
        val floor = maxOf(0L, inv.createdHeight - REORG_MARGIN_BLOCKS)
        var credited = 0L
        var seen = 0L
        for (t in transfers) {
            if (t.minor != inv.minor) continue
            val h = t.height
            when {
                h == null -> seen += t.amount
                h < floor -> Unit
                blocks - h < c -> seen += t.amount
                h <= inv.graceHeight -> credited += t.amount
            }
        }
        return Pair(credited, seen)
    }

    private fun recompute(inv: Invoice) {
        val (credited, seen) = amounts(inv)
        inv.credited = credited
        inv.seen = seen
        when {
            credited >= inv.amount -> {
                if (inv.state != State.CONFIRMED) inv.confirmedHeight = blocks
                inv.state = State.CONFIRMED
            }
            synced && blocks >= inv.graceHeight + c -> {
                inv.state = State.EXPIRED
                inv.purgeHeight = blocks + PURGE_AFTER_BLOCKS
            }
            credited + seen > 0 -> inv.state = State.SEEN
            else -> inv.state = State.CREATED
        }
    }

    private fun purgeDue(inv: Invoice): Boolean = when (inv.state) {
        State.ISSUED -> inv.issuedHeight > 0 && blocks >= inv.issuedHeight + PURGE_AFTER_BLOCKS
        State.EXPIRED -> blocks >= inv.purgeHeight
        State.CONFIRMED -> inv.confirmedHeight > 0 && blocks >= inv.confirmedHeight + UNISSUED_KEEP_BLOCKS
        else -> false
    }

    // ------------------------------------------------------------------ handlers

    private inline fun <T> reply(block: () -> T): Reply<T> = try {
        Reply.Ok(block())
    } catch (r: Refusal) {
        Reply.Err(r.category)
    }

    fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long, now: Long): Reply<InvoiceAnswer> = reply {
        if (claimHash.size != 32 || credits.size > MAX_DISCOUNT_CREDITS || credits.any { it.size != TestSchedule.TOKEN_BYTES }) throw Refusal(REJECTED)
        val nullifiers = credits.map { TestSchedule.nullifier(it) }
        val r = requestInvoiceDigest(baseWeek, nullifiers)
        known(claimHash, r)?.let { return@reply it }
        val xmr = credits.isEmpty()
        schedule.positions(if (xmr) EntitlementCrypto.PRODUCT_PACK_XMR else EntitlementCrypto.PRODUCT_PACK_CREDITS, baseWeek) ?: throw Refusal(UNAVAILABLE)
        if (!baseWeekOk(baseWeek, now)) return@reply InvoiceAnswer(TorIssuerTransport.INVOICE_WRONG_PERIOD, ByteArray(16), 0, null, 0)
        val price = schedule.price(Grid.priceEpoch(baseWeek)) ?: throw Refusal(UNAVAILABLE)
        var presented: List<Presented> = emptyList()
        if (!xmr) {
            if (credits.any { !typed(it) }) throw Refusal(UNAUTHORIZED)
            presented = verifyCredits(credits, now) ?: throw Refusal(UNAUTHORIZED)
            if (!covers(presented.map { it.value }, price, schedule.constants.creditsPerFreePack, MAX_DISCOUNT_CREDITS)) throw Refusal(UNAUTHORIZED)
            val mask = spentMask(presented)
            if (mask != 0L) return@reply InvoiceAnswer(TorIssuerTransport.INVOICE_CREDITS_SPENT, ByteArray(16), 0, null, mask)
        }
        val height = if (xmr) {
            val t = lastTick
            if (t == null || !t.synced || t.at > now || now - t.at >= TICK_FRESH_SECS) throw Refusal(UNAVAILABLE)
            t.height
        } else {
            lastWalletHeight ?: 0L
        }
        val id = freshId()
        val inv = if (xmr) {
            val minor = nextMinor++
            Invoice(id, claimHash.copyOf(), r, true, minor, HarnessAddresses.subaddress(minor), price, baseWeek, height,
                height + schedule.constants.invoiceBlocks + schedule.constants.graceBlocks, State.CREATED)
        } else {
            Invoice(id, claimHash.copyOf(), r, false, 0, null, 0, baseWeek, height, 0, State.CONFIRMED)
        }
        presented.forEach { creditUse[it.key] = USE_DISCOUNT }
        invoices[Bytes.hex(id)] = inv
        history[Bytes.hex(id)] = inv
        claimIndex[Bytes.hex(claimHash)] = Bytes.hex(id)
        mutations++
        InvoiceAnswer(TorIssuerTransport.INVOICE_OK, id, inv.amount, inv.subaddress, 0)
    }

    private fun known(claimHash: ByteArray, r: ByteArray): InvoiceAnswer? {
        val id = claimIndex[Bytes.hex(claimHash)] ?: return null
        val inv = invoices[id] ?: throw Refusal(UNAVAILABLE)
        return if (inv.r.contentEquals(r)) {
            InvoiceAnswer(TorIssuerTransport.INVOICE_OK, inv.id, inv.amount, inv.subaddress, 0)
        } else {
            InvoiceAnswer(TorIssuerTransport.INVOICE_CLAIM_CONFLICT, ByteArray(16), 0, null, 0)
        }
    }

    private fun freshId(): ByteArray {
        while (true) {
            val id = Bytes.sha256(Bytes.ascii("model-invoice/$idSeed/${ids++}")).copyOf(16)
            if (!history.containsKey(Bytes.hex(id))) return id
        }
    }

    /** Steps 1–2 of §5.5: sizes, then the invoice and its claim key (no existence oracle). */
    private fun authorize(invoiceId: ByteArray, claimKey: ByteArray): Invoice {
        if (invoiceId.size != 16 || claimKey.size != 32) throw Refusal(REJECTED)
        val inv = invoices[Bytes.hex(invoiceId)] ?: throw Refusal(UNAUTHORIZED)
        if (!MessageDigest.isEqual(Batch.claimHash(claimKey), inv.claimHash)) throw Refusal(UNAUTHORIZED)
        return inv
    }

    fun blindSign(invoiceId: ByteArray, claimKey: ByteArray, blinded: ByteArray, now: Long): Reply<SignAnswer> = reply {
        if (blinded.isEmpty() || blinded.size % BLOCK != 0 || blinded.size > MAX_LAYOUT_POSITIONS * BLOCK) throw Refusal(REJECTED)
        val inv = authorize(invoiceId, claimKey)
        inv.requestDigests += Bytes.hex(Batch.requestDigest(inv.id, blinded))
        if (inv.state != State.CONFIRMED && inv.state != State.ISSUED) return@reply SignAnswer(reported(inv), inv.credited, inv.seen, ByteArray(0))
        val positions = schedule.positions(if (inv.xmr) EntitlementCrypto.PRODUCT_PACK_XMR else EntitlementCrypto.PRODUCT_PACK_CREDITS, inv.baseWeek)
            ?: throw Refusal(UNAVAILABLE)
        if (!blocksOk(positions, blinded)) throw Refusal(REJECTED)
        val digest = Batch.requestDigest(inv.id, blinded)
        if (inv.state == State.ISSUED) {
            if (!digest.contentEquals(inv.issuedDigest)) {
                return@reply SignAnswer(TorIssuerTransport.STATE_OTHER_REQUEST_ISSUED, inv.credited, inv.seen, ByteArray(0))
            }
            return@reply SignAnswer(TorIssuerTransport.STATE_SIGNED, inv.credited, inv.seen, signAll(positions, blinded))
        }
        val sigs = signAll(positions, blinded)
        inv.state = State.ISSUED
        inv.issuedDigest = digest
        inv.issuedHeight = lastWalletHeight ?: 0L
        mutations++
        SignAnswer(TorIssuerTransport.STATE_SIGNED, inv.credited, inv.seen, sigs)
    }

    fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray): Reply<StatusAnswer> = reply {
        val inv = authorize(invoiceId, claimKey)
        StatusAnswer(reported(inv), inv.credited, inv.seen)
    }

    /** The wire state of an invoice (a CONFIRMED, unissued one reads AWAITING_CONFIRMATIONS). */
    private fun reported(inv: Invoice): Int = when (inv.state) {
        State.CREATED, State.SEEN -> {
            val total = inv.credited + inv.seen
            when {
                total == 0L -> TorIssuerTransport.STATE_AWAITING_PAYMENT
                total < inv.amount -> TorIssuerTransport.STATE_UNDERPAID
                else -> TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS
            }
        }
        State.CONFIRMED -> TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS
        State.ISSUED -> TorIssuerTransport.STATE_SIGNED
        State.EXPIRED -> TorIssuerTransport.STATE_EXPIRED
    }

    fun redeemInvite(inviteToken: ByteArray, baseWeek: Long, blinded: ByteArray, now: Long): Reply<TrialAnswer> = reply {
        if (inviteToken.size != TestSchedule.TOKEN_BYTES || blinded.isEmpty() || blinded.size % BLOCK != 0 || blinded.size > MAX_LAYOUT_POSITIONS * BLOCK) {
            throw Refusal(REJECTED)
        }
        if (!typed(inviteToken)) throw Refusal(UNAUTHORIZED)
        val v = schedule.verify(inviteToken, EntitlementCrypto.KIND_INVITE, ignoreRevocation = true) ?: throw Refusal(UNAUTHORIZED)
        val digest = Batch.trialDigest(v.nullifier, baseWeek, blinded)
        val key = "${v.epoch}:${Bytes.hex(v.nullifier)}"
        inviteUse[key]?.let { stored ->
            val positions = schedule.positions(EntitlementCrypto.PRODUCT_TRIAL, baseWeek)
            val same = stored == Bytes.hex(digest) && positions != null && blinded.size == positions.size * BLOCK
            return@reply if (same) TrialAnswer(TorIssuerTransport.TRIAL_OK, signAll(checkNotNull(positions), blinded)) else TrialAnswer(TorIssuerTransport.TRIAL_REPLAYED, ByteArray(0))
        }
        val eNow = Grid.inviteEpoch(Grid.week(now))
        if (!(v.epoch == eNow || v.epoch + 1 == eNow) || schedule.isRevoked(EntitlementCrypto.KIND_INVITE, v.epoch)) throw Refusal(UNAUTHORIZED)
        if (!baseWeekOk(baseWeek, now)) return@reply TrialAnswer(TorIssuerTransport.TRIAL_WRONG_PERIOD, ByteArray(0))
        val positions = schedule.positions(EntitlementCrypto.PRODUCT_TRIAL, baseWeek) ?: throw Refusal(UNAVAILABLE)
        if (!blocksOk(positions, blinded)) throw Refusal(REJECTED)
        val sigs = signAll(positions, blinded)
        inviteUse[key] = Bytes.hex(digest)
        mutations++
        TrialAnswer(TorIssuerTransport.TRIAL_OK, sigs)
    }

    fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, address: String, now: Long): Reply<ClaimAnswer> = reply {
        if (claimId.size != 16 || credits.size > MAX_ENTRY_CREDITS || credits.any { it.size != TestSchedule.TOKEN_BYTES } || address.length > MAX_ADDRESS_TEXT) {
            throw Refusal(REJECTED)
        }
        val digest = claimDigest(address, credits)
        claims[Bytes.hex(claimId)]?.let { known ->
            return@reply if (known.digest.contentEquals(digest)) {
                ClaimAnswer(TorIssuerTransport.CLAIM_QUEUED, known.amount, 0)
            } else {
                ClaimAnswer(TorIssuerTransport.CLAIM_CONFLICT, 0, 0)
            }
        }
        if (HarnessAddresses.type(address) == null) return@reply ClaimAnswer(TorIssuerTransport.CLAIM_ADDRESS_REJECTED, 0, 0)
        val max = minOf(schedule.constants.maxClaimCredits, MAX_ENTRY_CREDITS)
        if (credits.size < schedule.constants.minClaimCredits || credits.size > max || credits.any { !typed(it) }) throw Refusal(UNAUTHORIZED)
        val presented = verifyCredits(credits, now) ?: throw Refusal(UNAUTHORIZED)
        val mask = spentMask(presented)
        if (mask != 0L) return@reply ClaimAnswer(TorIssuerTransport.CLAIM_CREDITS_SPENT, 0, mask)
        val amount = presented.sumOf { it.value }
        if (claims.values.any { it.address == address }) return@reply ClaimAnswer(TorIssuerTransport.CLAIM_ADDRESS_REJECTED, 0, 0)
        claims[Bytes.hex(claimId)] = Claim(digest, amount, address)
        presented.forEach { creditUse[it.key] = USE_PAYOUT }
        mutations++
        ClaimAnswer(TorIssuerTransport.CLAIM_QUEUED, amount, 0)
    }

    fun refreshCredit(credit: ByteArray, blinded: ByteArray, now: Long): Reply<RefreshAnswer> = reply {
        if (credit.size != TestSchedule.TOKEN_BYTES || blinded.size != BLOCK) throw Refusal(REJECTED)
        if (!typed(credit)) throw Refusal(UNAUTHORIZED)
        val v = schedule.verify(credit, EntitlementCrypto.KIND_CREDIT, ignoreRevocation = true) ?: throw Refusal(UNAUTHORIZED)
        val digest = Bytes.sha256(Bytes.ascii("ghost/v1/refresh-credit"), v.nullifier, blinded)
        val key = "${v.epoch}:${Bytes.hex(v.nullifier)}"
        val positions = listOf(Position(EntitlementCrypto.KIND_CREDIT, v.epoch, null))
        creditUse[key]?.let { used ->
            return@reply if (used == USE_REFRESH + Bytes.hex(digest)) {
                RefreshAnswer(TorIssuerTransport.REFRESH_OK, signAll(positions, blinded))
            } else {
                RefreshAnswer(TorIssuerTransport.REFRESH_REPLAYED, ByteArray(0))
            }
        }
        val cNow = Grid.creditEpoch(Grid.week(now))
        if (!(v.epoch == cNow || v.epoch + 1 == cNow) || schedule.isRevoked(EntitlementCrypto.KIND_CREDIT, v.epoch)) throw Refusal(UNAUTHORIZED)
        if (!blocksOk(positions, blinded)) throw Refusal(REJECTED)
        val sig = signAll(positions, blinded)
        creditUse[key] = USE_REFRESH + Bytes.hex(digest)
        mutations++
        RefreshAnswer(TorIssuerTransport.REFRESH_OK, sig)
    }

    // ------------------------------------------------------------------ shared rules

    private fun typed(token: ByteArray): Boolean = token.size == TestSchedule.TOKEN_BYTES && token[0] == 0.toByte() && token[1] == 2.toByte()

    /** Valid CREDIT tokens (not revoked) of `c_now − 4 … c_now`, distinct; null refuses the set. */
    private fun verifyCredits(credits: List<ByteArray>, now: Long): List<Presented>? {
        val cNow = Grid.creditEpoch(Grid.week(now))
        val seen = HashSet<String>()
        return credits.map { token ->
            val v = schedule.verify(token, EntitlementCrypto.KIND_CREDIT) ?: return null
            if (v.epoch > cNow || v.epoch + ACCEPTED_PAST_EPOCHS < cNow || !seen.add(Bytes.hex(v.nullifier))) return null
            Presented(v.epoch, v.nullifier, schedule.creditValue(v.epoch) ?: return null)
        }
    }

    private fun spentMask(presented: List<Presented>): Long {
        var mask = 0L
        presented.take(64).forEachIndexed { i, p -> if (creditUse.containsKey(p.key)) mask = mask or (1L shl i) }
        return mask
    }

    private fun blocksOk(positions: List<Position>, blinded: ByteArray): Boolean {
        if (blinded.size != positions.size * BLOCK) return false
        return positions.indices.all { j ->
            val key = schedule.key(positions[j].kind, positions[j].epoch) ?: throw Refusal(UNAVAILABLE)
            val b = Bytes.os2ip(blinded.copyOfRange(j * BLOCK, (j + 1) * BLOCK))
            b.signum() > 0 && b < key.n
        }
    }

    private fun signAll(positions: List<Position>, blinded: ByteArray): ByteArray {
        val out = ByteArray(blinded.size)
        for (j in positions.indices) {
            val key = schedule.key(positions[j].kind, positions[j].epoch) ?: throw Refusal(UNAVAILABLE)
            SigningCache.sign(key, blinded.copyOfRange(j * BLOCK, (j + 1) * BLOCK)).copyInto(out, j * BLOCK)
        }
        return out
    }

    /** Digest of the whole state (crash-point classification of the harness). */
    fun digest(): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(Bytes.ascii("blocks=$blocks synced=$synced minor=$nextMinor ids=$ids tick=${lastTick?.at}/${lastTick?.height}"))
        for (t in transfers) md.update(Bytes.ascii("t${t.minor}:${t.amount}:${t.height}"))
        for ((id, inv) in history) {
            md.update(Bytes.ascii("$id:${inv.state}:${inv.credited}:${inv.seen}:${inv.purged}:${inv.issuedDigest?.let(Bytes::hex)}:${inv.requestDigests}"))
        }
        creditUse.toSortedMap().forEach { (k, v) -> md.update(Bytes.ascii("c$k=$v")) }
        inviteUse.toSortedMap().forEach { (k, v) -> md.update(Bytes.ascii("i$k=$v")) }
        claims.toSortedMap().forEach { (k, v) -> md.update(Bytes.ascii("q$k=${v.amount}:${v.address}")) }
        return Bytes.hex(md.digest())
    }

    override fun toString(): String = "ModelIssuer"

    companion object {
        const val START_BLOCKS = 1_000L
        const val SCANNER_PERIOD_SECS = 60L
        const val REJECTED = "rejected"
        const val UNAUTHORIZED = "unauthorized"
        const val UNAVAILABLE = "relay_unavailable"
        private const val BLOCK = 256
        private const val MAX_LAYOUT_POSITIONS = 2_563
        private const val MAX_DISCOUNT_CREDITS = 20
        private const val MAX_ENTRY_CREDITS = 64
        private const val MAX_ADDRESS_TEXT = 128
        private const val TICK_FRESH_SECS = 120L
        private const val BASE_WEEK_TOLERANCE_SECS = 4 * 3_600L
        private const val REORG_MARGIN_BLOCKS = 20L
        private const val PURGE_AFTER_BLOCKS = 5_040L
        private const val UNISSUED_KEEP_BLOCKS = 21_600L
        private const val ACCEPTED_PAST_EPOCHS = 4L
        private const val USE_DISCOUNT = "discount"
        private const val USE_PAYOUT = "payout"
        private const val USE_REFRESH = "refresh:"

        fun baseWeekOk(baseWeek: Long, now: Long): Boolean =
            baseWeek == Grid.week(now - BASE_WEEK_TOLERANCE_SECS) || baseWeek == Grid.week(now + BASE_WEEK_TOLERANCE_SECS)

        /** `R = SHA-256("ghost/v1/request-invoice" ‖ rail ‖ product ‖ base_week ‖ nullifiers)` (§5.6 step 2). */
        fun requestInvoiceDigest(baseWeek: Long, nullifiers: List<ByteArray>): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(Bytes.ascii("ghost/v1/request-invoice"))
            md.update(byteArrayOf(1, 1))
            md.update(Bytes.u64(baseWeek))
            nullifiers.forEach(md::update)
            return md.digest()
        }

        /** `SHA-256("ghost/v1/claim-payout" ‖ u16 len ‖ address ‖ u8 count ‖ credits)` (§5.6 step 2). */
        fun claimDigest(address: String, credits: List<ByteArray>): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(Bytes.ascii("ghost/v1/claim-payout"))
            val a = address.toByteArray(Charsets.UTF_8)
            md.update(Bytes.u16(minOf(a.size, 0xffff)))
            md.update(a)
            md.update(byteArrayOf(minOf(credits.size, 255).toByte()))
            credits.forEach(md::update)
            return md.digest()
        }

        /** The smallest covering set rule (`ghost_entitlement::credit::covers`, §4.6, §19.8). */
        fun covers(values: List<Long>, price: Long, floor: Int, max: Int): Boolean {
            val n = values.size
            if (n == 0 || n < floor || n > max) return false
            val sum = values.sum()
            val least = values.min()
            return sum >= price && (n == floor || sum - least < price)
        }
    }
}
