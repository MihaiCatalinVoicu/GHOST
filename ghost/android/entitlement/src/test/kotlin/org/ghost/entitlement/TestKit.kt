package org.ghost.entitlement

import org.ghost.entitlement.engine.EngineContext
import org.ghost.entitlement.engine.EngineDeps
import org.ghost.entitlement.engine.EntitlementEngine
import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Layouts
import org.ghost.entitlement.engine.Pricing
import org.ghost.entitlement.port.EntitlementClock
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.port.IdentityPort
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.port.RedeemPort
import org.ghost.entitlement.port.SealPort
import org.ghost.entitlement.port.SessionPort
import org.ghost.entitlement.port.TokenCryptoPort
import org.ghost.entitlement.port.UserCallPort
import org.ghost.entitlement.store.PurchaseRow
import org.ghost.entitlement.store.TokenRow
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.identity.InviteKeys
import org.ghost.identity.RootEntropy
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.TorIssuerTransport
import org.ghost.network.TorRelayTransport
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SessionKind
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.SyncStores
import org.ghost.sync.store.Time
import java.nio.ByteBuffer
import java.security.MessageDigest

/** ISO week 2958 starts Monday 2026-09-14 00:00 UTC; T0 is its Wednesday 12:00 (invite epoch 739, credit epoch 227). */
internal const val WEEK0: Long = 2958L
internal val T0: Long = Grid.start(WEEK0) + 2 * Grid.DAY + 12 * Grid.HOUR

internal object TestBytes {
    /** Deterministic bytes, distinct for every seed: SHA-256 blocks of "seed:counter". */
    fun of(size: Int, seed: Int): ByteArray {
        val out = ByteArray(size)
        var pos = 0
        var counter = 0
        while (pos < size) {
            val block = MessageDigest.getInstance("SHA-256").digest("$seed:$counter".toByteArray(Charsets.US_ASCII))
            val n = minOf(block.size, size - pos)
            System.arraycopy(block, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    /** An RFC 9578 type 0x0002 token shape (354 bytes). */
    fun token(seed: Int): ByteArray = byteArrayOf(0, 2) + of(352, 300_000 + seed)

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach(md::update)
        return md.digest()
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
}

/** Valid v3 onion addresses (checksum and version byte) from a seed. */
internal object TestOnions {
    private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

    fun of(seed: Int, port: Int = 443): OnionAddress {
        val key = TestBytes.of(32, 700_000 + seed)
        val md = MessageDigest.getInstance("SHA3-256")
        md.update(".onion checksum".toByteArray(Charsets.US_ASCII))
        md.update(key)
        md.update(3.toByte())
        val raw = key + md.digest().copyOf(2) + byteArrayOf(3)
        return OnionAddress.parse(base32(raw) + ".onion:" + port)
    }

    private fun base32(raw: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in raw) {
            buffer = ((buffer shl 8) or (b.toInt() and 0xff)) and 0xffff
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(ALPHABET[(buffer shr bits) and 31])
            }
        }
        return sb.toString()
    }
}

/**
 * A test Entitlement Schedule (the harness ES of design §19.17: S = 3, access_per_slot = 4,
 * trial_per_slot = 2) and the offline token check of known tokens. Mutable, so tests can model a
 * later or a conflicting schedule.
 */
internal class TestCrypto : TokenCryptoPort {
    var seq = 1L
    var network = 2
    var firstWeek = WEEK0 - 4
    var lastWeek = WEEK0 + 30
    val onions: List<OnionAddress> = List(3) { TestOnions.of(it) }
    var slots: List<EntitlementCrypto.Slot> = onions.mapIndexed { i, o -> EntitlementCrypto.Slot(i, 0, 0, o) }
    var price = PRICE
    val priceOverrides = HashMap<Long, Long>()
    val droppedPrices = HashSet<Long>()

    /** Weeks whose keys (and the prices they reach) are listed; the horizon by default. */
    var keyFirstWeek: Long? = null
    var keyLastWeek: Long? = null
    val keyOverrides = HashMap<Pair<Int, Long>, ByteArray>()
    var revoked: List<EntitlementCrypto.Revoked> = emptyList()
    var failSummary: String? = null
    val constants = EntitlementCrypto.Constants(
        confirmations = 10, invoiceBlocks = 720, graceBlocks = 2160, accessPerSlot = 4, trialPerSlot = 2, invitesPerPack = 2,
        creditsPerFreePack = 10, minClaimCredits = 10, maxClaimCredits = 50, earlyWindowHours = 24, capabilityQuotaBytes = 268_435_456L,
    )
    private val known = HashMap<List<Byte>, EntitlementCrypto.VerifiedToken>()

    fun keyId(kind: Int, epoch: Long): ByteArray = keyOverrides[kind to epoch] ?: TestBytes.sha256("key:$kind:$epoch".toByteArray())

    private fun keys(): List<EntitlementCrypto.KeyId> {
        val first = keyFirstWeek ?: firstWeek
        val last = keyLastWeek ?: lastWeek
        val out = ArrayList<EntitlementCrypto.KeyId>()
        for (w in first..last) out += EntitlementCrypto.KeyId(EntitlementCrypto.KIND_ACCESS, w, keyId(EntitlementCrypto.KIND_ACCESS, w))
        for (e in Grid.inviteEpoch(first)..Grid.inviteEpoch(last)) out += EntitlementCrypto.KeyId(EntitlementCrypto.KIND_INVITE, e, keyId(EntitlementCrypto.KIND_INVITE, e))
        // Credits stay acceptable for their epoch and the four following (§19.8), so a schedule lists
        // the CREDIT keys and prices of the four epochs before its first week too.
        for (e in Grid.creditEpoch(first) - CREDIT_EPOCHS_BACK..Grid.creditEpoch(last)) {
            out += EntitlementCrypto.KeyId(EntitlementCrypto.KIND_CREDIT, e, keyId(EntitlementCrypto.KIND_CREDIT, e))
        }
        return out
    }

    override fun scheduleSummary(): EntitlementCrypto.ScheduleSummary {
        failSummary?.let { throw NetworkException(it) }
        val prices = (Grid.priceEpoch(keyFirstWeek ?: firstWeek) - CREDIT_EPOCHS_BACK..Grid.priceEpoch((keyLastWeek ?: lastWeek) + 4))
            .filter { it !in droppedPrices }
            .map { EntitlementCrypto.Price(it, priceOverrides[it] ?: price) }
        val keys = keys()
        val md = MessageDigest.getInstance("SHA-256")
        md.update("es:$seq:$network:$firstWeek:$lastWeek".toByteArray())
        slots.forEach { md.update("${it.slot}:${it.validFromWeek}:${it.validUntilWeek}:${it.onion}".toByteArray()) }
        prices.forEach { md.update("${it.priceEpoch}:${it.packPriceAtomic}".toByteArray()) }
        keys.forEach { md.update(it.keyId()) }
        revoked.forEach { md.update("r${it.kind}:${it.epoch}".toByteArray()) }
        return EntitlementCrypto.ScheduleSummary(md.digest(), seq, network, firstWeek, lastWeek, constants, slots, prices, keys, revoked)
    }

    override fun layout(product: Int, index: Long): EntitlementCrypto.Layout {
        val s = scheduleSummary()
        val positions = when (product) {
            EntitlementCrypto.PRODUCT_PACK_XMR -> Layouts.pack(s, index, true).size
            EntitlementCrypto.PRODUCT_PACK_CREDITS -> Layouts.pack(s, index, false).size
            EntitlementCrypto.PRODUCT_TRIAL -> Layouts.trial(s, index).size
            else -> 1
        }
        return EntitlementCrypto.Layout(TestBytes.sha256("layout:$product:$index".toByteArray()), positions)
    }

    override fun verifyToken(token: ByteArray, kind: Int): EntitlementCrypto.VerifiedToken? = known[token.toList()]?.takeIf { it.kind == kind }

    fun register(token: ByteArray, kind: Int, epoch: Long, slot: Int? = null) {
        known[token.toList()] = EntitlementCrypto.VerifiedToken(kind, epoch, slot, TestBytes.sha256(token))
    }

    override fun validateAddress(address: String, purpose: Int): EntitlementCrypto.AddressInfo? {
        if (address.length != 95) return null
        val type = when (address[0]) {
            '5' -> EntitlementCrypto.ADDRESS_STANDARD
            '7' -> EntitlementCrypto.ADDRESS_SUBADDRESS
            else -> return null
        }
        if (purpose == EntitlementCrypto.PURPOSE_INVOICE && type != EntitlementCrypto.ADDRESS_SUBADDRESS) return null
        return EntitlementCrypto.AddressInfo(network, type)
    }

    override fun paymentUri(subaddress: String, amountAtomic: Long): String = "monero:$subaddress?tx_amount=$amountAtomic"

    companion object {
        const val PRICE = 1_000_000_000_000L
        val SUBADDRESS = "7" + "a".repeat(94)
        private const val CREDIT_EPOCHS_BACK = 4L
    }
}

/** Wall and monotonic time under test control; [sleep] advances both. */
internal class ManualClock(var now: Long) : EntitlementClock, SyncClock {
    var monotonic = 1_000_000L
    private var carry = 0L

    override fun epochSeconds(): Long = now

    override fun monotonicMillis(): Long = monotonic

    override fun sleep(millis: Long): Boolean {
        monotonic += millis
        carry += millis
        now += carry / 1000
        carry %= 1000
        return true
    }
}

/** Deterministic randomness: counter bytes, a settable uniform (or a queue) and a settable or hashed PRF. */
internal class TestRandom : EntitlementRandom {
    private var counter = 0
    var uniformValue = 0.5
    val uniforms = ArrayDeque<Double>()
    var prfValue: Double? = null

    override fun bytes(size: Int): ByteArray = TestBytes.of(size, 500_000 + counter++)

    override fun uniform(): Double = uniforms.removeFirstOrNull() ?: uniformValue

    override fun prf(domain: Int, input: ByteArray): Double {
        prfValue?.let { return it }
        val h = TestBytes.sha256(ByteBuffer.allocate(4).putInt(domain).array(), input)
        return (ByteBuffer.wrap(h, 0, 8).long ushr 11) * (1.0 / (1L shl 53))
    }
}

/** The issuer as the engine sees it: every call recorded with its arguments; answers set by the test. */
internal class FakeIssuer(private val crypto: TestCrypto, private val clock: ManualClock) : IssuerPort {
    class Call(val name: String, val at: Long, val args: List<String>) {
        override fun toString(): String = "Call($name)"
    }

    val calls = ArrayList<Call>()
    var fail: String? = null
    var failOnce: String? = null
    var invoiceResult = TorIssuerTransport.INVOICE_OK
    var invoiceMask = 0L
    var amountOverride: Long? = null
    var signState = TorIssuerTransport.STATE_SIGNED
    var credited = 0L
    var seen = 0L
    var statusState = TorIssuerTransport.STATE_AWAITING_PAYMENT
    var trialResult = TorIssuerTransport.TRIAL_OK
    var claimResult = TorIssuerTransport.CLAIM_QUEUED
    var claimMask = 0L
    var refreshResult = TorIssuerTransport.REFRESH_OK

    fun named(name: String): List<Call> = calls.filter { it.name == name }

    private fun describe(a: Any?): String = when (a) {
        is ByteArray -> TestBytes.hex(a)
        is List<*> -> a.joinToString(",") { describe(it) }
        else -> a.toString()
    }

    private fun record(name: String, vararg args: Any?) {
        calls += Call(name, clock.now, args.map { describe(it) })
        failOnce?.let {
            failOnce = null
            throw NetworkException(it)
        }
        fail?.let { throw NetworkException(it) }
    }

    /** Tokens that depend on the seed only, so an identical retry gets identical tokens. */
    private fun issued(seed: ByteArray, count: Int, tag: String): List<TorIssuerTransport.IssuedToken> = List(count) { i ->
        val token = byteArrayOf(0, 2) + TestBytes.sha256(tag.toByteArray(), seed, ByteBuffer.allocate(4).putInt(i).array()).let { h ->
            ByteArray(352) { h[it % 32] }.also { ByteBuffer.wrap(it).putInt(i) }
        }
        TorIssuerTransport.IssuedToken(TestBytes.sha256(token), token)
    }

    override fun requestInvoice(claimHash: ByteArray, credits: List<ByteArray>, baseWeek: Long): TorIssuerTransport.InvoiceAnswer {
        record("requestInvoice", claimHash, credits, baseWeek)
        return when (invoiceResult) {
            TorIssuerTransport.INVOICE_OK -> {
                val amount = amountOverride ?: if (credits.isEmpty()) checkNotNull(Pricing.price(crypto.scheduleSummary(), Grid.priceEpoch(baseWeek))) else 0L
                TorIssuerTransport.InvoiceAnswer(TorIssuerTransport.INVOICE_OK, claimHash.copyOf(16), amount, if (amount > 0) TestCrypto.SUBADDRESS else null, 0)
            }
            TorIssuerTransport.INVOICE_CREDITS_SPENT -> TorIssuerTransport.InvoiceAnswer(invoiceResult, ByteArray(16), 0, null, invoiceMask)
            else -> TorIssuerTransport.InvoiceAnswer(invoiceResult, ByteArray(16), 0, null, 0)
        }
    }

    override fun blindSign(
        invoiceId: ByteArray,
        claimKey: ByteArray,
        seed: ByteArray,
        product: Int,
        baseWeek: Long,
        layoutDigest: ByteArray,
        positions: Int,
    ): TorIssuerTransport.SignAnswer {
        record("blindSign", invoiceId, claimKey, seed, product, baseWeek, layoutDigest, positions)
        val tokens = if (signState == TorIssuerTransport.STATE_SIGNED) issued(seed, positions, "pack") else emptyList()
        return TorIssuerTransport.SignAnswer(signState, credited, seen, tokens)
    }

    override fun invoiceStatus(invoiceId: ByteArray, claimKey: ByteArray): TorIssuerTransport.StatusAnswer {
        record("invoiceStatus", invoiceId, claimKey)
        return TorIssuerTransport.StatusAnswer(statusState, credited, seen)
    }

    override fun redeemInvite(inviteToken: ByteArray, seed: ByteArray, baseWeek: Long, layoutDigest: ByteArray, positions: Int): TorIssuerTransport.TrialAnswer {
        record("redeemInvite", inviteToken, seed, baseWeek, layoutDigest, positions)
        return TorIssuerTransport.TrialAnswer(trialResult, if (trialResult == TorIssuerTransport.TRIAL_OK) issued(seed, positions, "trial") else emptyList())
    }

    override fun claimPayout(claimId: ByteArray, credits: List<ByteArray>, payoutAddress: String): TorIssuerTransport.ClaimAnswer {
        record("claimPayout", claimId, credits, payoutAddress)
        return when (claimResult) {
            TorIssuerTransport.CLAIM_QUEUED -> TorIssuerTransport.ClaimAnswer(claimResult, credits.size * (TestCrypto.PRICE / 10), 0)
            TorIssuerTransport.CLAIM_CREDITS_SPENT -> TorIssuerTransport.ClaimAnswer(claimResult, 0, claimMask)
            else -> TorIssuerTransport.ClaimAnswer(claimResult, 0, 0)
        }
    }

    override fun refreshCredit(receivedCredit: ByteArray, seed: ByteArray, layoutDigest: ByteArray): TorIssuerTransport.RefreshAnswer {
        record("refreshCredit", receivedCredit, seed, layoutDigest)
        if (refreshResult != TorIssuerTransport.REFRESH_OK) return TorIssuerTransport.RefreshAnswer(refreshResult, null)
        val fresh = issued(seed, 1, "refresh").single()
        val epoch = crypto.verifyToken(receivedCredit, EntitlementCrypto.KIND_CREDIT)?.epoch ?: Grid.creditEpoch(WEEK0)
        // The issuer refreshes only credits of c_now and c_now − 1 (`refresh_credit_at`, step 4).
        val cNow = Grid.creditEpoch(Grid.week(clock.now))
        if (epoch != cNow && epoch + 1 != cNow) throw NetworkException("unauthorized")
        crypto.register(fresh.token(), EntitlementCrypto.KIND_CREDIT, epoch)
        return TorIssuerTransport.RefreshAnswer(TorIssuerTransport.REFRESH_OK, fresh)
    }
}

/**
 * Relays as the redeem lane sees them: every redemption recorded; answers set by the test. Like the
 * real relay (`capability_expiry(p)`), a capability expires one hour after the end of the redeemed
 * token's week, whatever the relay's own week.
 */
internal class FakeRedeem(private val clock: ManualClock, private val crypto: TestCrypto) : RedeemPort {
    class Call(val relay: OnionAddress, val namespace: NamespaceId, token: ByteArray, requestId: ByteArray) {
        val token: List<Byte> = token.toList()
        val requestId: List<Byte> = requestId.toList()
    }

    val calls = ArrayList<Call>()
    var result = TorRelayTransport.REDEEM_OK
    var fail: String? = null
    var failOnce: String? = null
    var relayPeriod: Long? = null

    /** The relays' clock minus the device clock (a relay set that lies about the time shifts it). */
    var skewSeconds = 0L

    /**
     * Answer as the real relay's period check does (`access_accepts`): a token of week w only from
     * `start(w) − 24 h` to `start(w + 1) + 1 h` of the relays' clock, `WRONG_PERIOD` otherwise.
     */
    var periods = false

    /** The answers given, in call order. */
    val answers = ArrayList<Int>()

    /** Redeem-lane steps reported (Q29). */
    var steps = 0

    override fun stepDone() {
        steps++
    }

    override fun redeem(relay: OnionAddress, namespace: NamespaceId, token: ByteArray, requestId: ByteArray): TorRelayTransport.RedeemAnswer {
        calls += Call(relay, namespace, token, requestId)
        failOnce?.let {
            failOnce = null
            throw NetworkException(it)
        }
        fail?.let { throw NetworkException(it) }
        val relayNow = clock.now + skewSeconds
        val period = relayPeriod ?: Grid.week(relayNow)
        val minute = Math.floorDiv(relayNow, 60L)
        val tokenWeek = crypto.verifyToken(token, EntitlementCrypto.KIND_ACCESS)?.epoch
        val inWindow = tokenWeek == null || relayNow in (Grid.start(tokenWeek) - Grid.DAY) until (Grid.start(tokenWeek + 1) + Grid.HOUR)
        val answer = if (periods && !inWindow) TorRelayTransport.REDEEM_WRONG_PERIOD else result
        answers += answer
        return if (answer == TorRelayTransport.REDEEM_OK) {
            val week = crypto.verifyToken(token, EntitlementCrypto.KIND_ACCESS)?.epoch ?: period
            TorRelayTransport.RedeemAnswer(result, period, minute, Grid.start(week + 1) + 3600, TestBytes.of(98, 800_000 + calls.size))
        } else {
            TorRelayTransport.RedeemAnswer(answer, period, minute, 0, null)
        }
    }
}

internal class FakeIdentity : IdentityPort {
    val root: RootEntropy = RootEntropy.fromRaw(ByteArray(32) { (it * 7 + 3).toByte() })
    var exists = false
    val log = ArrayList<String>()

    /** The process ends inside the restore, before the identity is stored. */
    var failRestore = false

    /** The process ends inside a derivation of invite keys. */
    var failInviteKeys = false

    override fun hasIdentity(): Boolean = exists

    override fun restore(mnemonic: List<String>) {
        check(!exists) { "identity exists" }
        check(RootEntropy.fromMnemonic(mnemonic).toMnemonic() == root.toMnemonic()) { "the backup of another identity" }
        check(!failRestore) { "the process ended before the identity was stored" }
        exists = true
        log += "restore"
    }

    override fun create(invite: Invite?) {
        check(!exists) { "identity exists" }
        exists = true
        log += if (invite == null) "create-resumed" else "create"
    }

    override fun wipe() {
        exists = false
        log += "wipe"
    }

    override fun inviteKeys(index: Int): InviteKeys {
        check(!failInviteKeys) { "the process ended inside a derivation" }
        return root.inviteKeys(index)
    }
}

/** Real drop sealing; drop keys from the fake identity's root entropy. */
internal class TestSeal(private val identity: FakeIdentity) : SealPort {
    override fun sealCredit(creditToken: ByteArray, dropKey: ByteArray, dropNamespace: ByteArray): ByteArray =
        DropSeal.sealCredit(creditToken, dropKey, dropNamespace)

    override fun sealDummy(dropKey: ByteArray, dropNamespace: ByteArray): ByteArray = DropSeal.sealDummy(dropKey, dropNamespace)

    override fun open(inviteIndex: Int, blob: ByteArray, dropNamespace: ByteArray): DropSeal.Opened =
        DropSeal.open(blob, identity.root.inviteDropKeyPair(inviteIndex), dropNamespace)
}

internal class FakeSession(
    override val kind: SessionKind,
    override val issuer: IssuerPort? = null,
    override val redeem: RedeemPort? = null,
    var trusted: Boolean = true,
) : SessionPort {
    @Volatile
    override var closed: Boolean = false

    override fun clockTrusted(): Boolean = trusted && !closed
}

/** User calls run synchronously (or are held when [deferred]); payment-screen events are logged. */
internal class FakeUserCalls : UserCallPort {
    var issuer: IssuerPort? = null
    var trusted = true
    var deferred = false
    val pending = ArrayList<(SessionPort) -> Unit>()
    val log = ArrayList<String>()

    override fun runUserIssuerCall(block: (SessionPort) -> Unit) {
        log += "call"
        if (deferred) pending += block else block(FakeSession(SessionKind.USER_ISSUER_CALL, issuer = issuer, trusted = trusted))
    }

    override fun paymentScreenShown() {
        log += "shown"
    }

    override fun paymentScreenHidden() {
        log += "hidden"
    }
}

/**
 * The real engine over the real v3 schema and the real sync stores (sqlite-jdbc), with fake ports: a
 * relay directory holding the three ES slot relays (operators 0, 1, 0) and one relay in no ES slot.
 */
internal class World(configure: (TestCrypto) -> Unit = {}) : AutoCloseable {
    val clock = ManualClock(T0)
    val sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
    var mode = PrivacyMode.STANDARD
    val stores = SyncStores(SyncDatabase(sql), clock, KeyedRandomSources(ByteArray(32) { 7 }), { mode })
    val crypto = TestCrypto().also(configure)
    val issuer = FakeIssuer(crypto, clock)
    val redeem = FakeRedeem(clock, crypto)
    val random = TestRandom()
    val identity = FakeIdentity()
    val seal = TestSeal(identity)
    val userCalls = FakeUserCalls().also { it.issuer = issuer }
    var storesOpen = true
    val deps = EngineDeps(crypto, clock, random, identity, seal, userCalls) { mode }
    val engine = EntitlementEngine(deps) { if (storesOpen) stores else null }
    val relayIds: List<RelayId>
    val outsider: RelayId
    private var tokenSeed = 10_000

    init {
        val entries = crypto.onions.mapIndexed { i, o -> RelayEntry(o, operator(i % 2), RelayEntry.Source.CONFIG) } +
            RelayEntry(TestOnions.of(9), operator(3), RelayEntry.Source.CONFIG)
        val ids = tx { stores.relayDirectory.upsert(it, entries) }
        relayIds = crypto.onions.map { checkNotNull(ids[it]) }
        outsider = checkNotNull(ids[TestOnions.of(9)])
        engine.context()
    }

    fun operator(i: Int): ByteArray = ByteArray(16) { (i + 1).toByte() }

    fun ctx(): EngineContext = checkNotNull(engine.context())

    /** The engine of a new process over the same database and ports (in-process memory starts empty). */
    fun newProcess(): EntitlementEngine = EntitlementEngine(deps) { if (storesOpen) stores else null }

    fun <T> tx(block: (SyncTransaction) -> T): T = stores.database.transaction(block)

    fun quiet(trusted: Boolean = true) = engine.onQuietRun(FakeSession(SessionKind.QUIET, issuer = issuer, trusted = trusted))

    fun relaySession(trusted: Boolean = true) = FakeSession(SessionKind.FOREGROUND, redeem = redeem, trusted = trusted)

    fun laneStep(trusted: Boolean = true) = ctx().redeemLane.step(relaySession(trusted), redeem)

    /** Fresh ACCESS tokens of ([week], [slot]); returns their token bytes. */
    fun addAccess(week: Long, slot: Int, count: Int, eligibleMinute: Long = Time.floorMinute(T0) - Grid.DAY): List<ByteArray> = tx { t ->
        List(count) {
            val token = TestBytes.token(tokenSeed++)
            ctx().tokens.insertFresh(t, TestBytes.sha256(token), "access", week, slot, token, eligibleMinute)
            crypto.register(token, EntitlementCrypto.KIND_ACCESS, week, slot)
            token
        }
    }

    /** Fresh INVITE or CREDIT tokens of [epoch], known to the offline check. */
    fun addTokens(kind: String, epoch: Long, count: Int): List<ByteArray> = tx { t ->
        List(count) {
            val token = TestBytes.token(tokenSeed++)
            ctx().tokens.insertFresh(t, TestBytes.sha256(token), kind, epoch, null, token, Time.floorMinute(T0) - Grid.DAY)
            crypto.register(token, if (kind == "invite") EntitlementCrypto.KIND_INVITE else EntitlementCrypto.KIND_CREDIT, epoch)
            token
        }
    }

    fun purchase(id: ByteArray): PurchaseRow? = tx { ctx().purchases.get(it, id) }

    fun purchases(): List<PurchaseRow> = tx { ctx().purchases.all(it) }

    fun tokenRows(kind: String): List<TokenRow> = tx { t ->
        val ids = ArrayList<ByteArray>()
        t.sql.query("SELECT nullifier FROM ent_token WHERE kind = ?1 ORDER BY nullifier", listOf(kind)) { ids += it.blob(0) }
        ids.map { checkNotNull(ctx().tokens.get(t, it)) }
    }

    fun count(sqlText: String, args: List<Any?> = emptyList()): Long {
        var n = 0L
        sql.query(sqlText, args) { n = it.long(0) }
        return n
    }

    /** A signed invite of an inviter (another root) whose token the schedule knows as an INVITE token of epoch 739. */
    fun inviteText(expiryDay: Long = Grid.day(T0) + 14, seed: Int = 77, index: Int = 0): String {
        val token = TestBytes.token(seed)
        crypto.register(token, EntitlementCrypto.KIND_INVITE, Grid.inviteEpoch(WEEK0))
        return Invite.create(token, Grid.inviteEpoch(WEEK0), expiryDay, listOf(0, 1, 2), INVITER.inviteKeys(index)).encode()
    }

    override fun close() = sql.close()

    companion object {
        val INVITER: RootEntropy = RootEntropy.fromRaw(ByteArray(32) { (it * 11 + 5).toByte() })
    }
}
