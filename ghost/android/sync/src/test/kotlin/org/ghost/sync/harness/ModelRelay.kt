package org.ghost.sync.harness

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Buckets
import org.ghost.sync.api.NamespaceId
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.TreeMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Model of one relay (design §8.7): exactly the rules pinned by
 * `protocol/test-vectors/relay_semantics.txt` and `protocol/test-vectors/register.txt`, which
 * [ModelRelayConformanceTest] replays against it (the Rust relay replays the same files), so the
 * model cannot drift from the relay.
 *
 * Rules: a store names exactly one TTL bucket of [TTL_BUCKETS] no larger than the relay's maximum
 * (`rejected` otherwise; Phase 9 design §10.2); expiry = now + ttl rounded up to the hour; a store
 * over a live membership whose expiry + 1 h reaches the wanted expiry is a free no-op; a live but
 * shorter membership is extended (charged, same sequence); an expired one, pruned or not, is
 * renewed (charged, new sequence); quota is
 * charged per token before anything changes; get/check take the namespace from the capability;
 * write grants read; list walks index entries (live and expired-unpruned) after the cursor, at
 * most 1024 per call, returns the live ones, and its cursor is the last examined sequence or empty
 * at the end of the index; an emptied namespace restarts from the hour seed `(now / 3600) << 32`.
 *
 * Phase 9 adds key registrations (§4.4–§4.6): [registerKey] records the verifier of a bearer
 * secret for one ISO week against a write capability, records accumulate and are never replaced,
 * and a bearer credential v3 of that secret then authorizes what its kind allows at the relay of
 * its [slot] — deposits charged to the registration's own allowance ([DepositLedger] of §4.5),
 * reads answered with week-coarse times (§21.9 point 4, §22.8.7 point 1). Registrations are soft
 * state: [restart] keeps them and empties the ledgers, [loseKeys] models a lost `keys.redb`.
 *
 * The list cursor stays the model's raw sequence, unlike the relay's sealed one (§21.9 point 4):
 * the Phase 7 harness invariants and `ListStepTest` read it, and the slice that builds `DmWorld`
 * either seals it or keeps it out of the effective view (design §15.1).
 *
 * Times are the relay's unix seconds. Categories are the client's (`rejected`, `unauthorized`,
 * `quota`, `not_found`). The model also keeps a history the harness invariants read: every
 * membership ever held, charges and state-changing stores per (namespace, hash).
 */
internal class ModelRelay(val name: String, key: ByteArray, var maxTtlSeconds: Long = MAX_TTL) {

    sealed class Reply<out T> {
        class Ok<T>(val value: T) : Reply<T>()
        class Err(val category: String) : Reply<Nothing>() {
            override fun toString(): String = "Err($category)"
        }
    }

    class Receipt(val hash: BlobHash, val expiry: Long)

    /** A served blob with the times the caller's token may see (§21.9 point 4, §22.8.7). */
    class Served(val data: ByteArray, val expiry: Long, val uploaded: Long)

    class Page(val hashes: List<BlobHash>, val next: ByteArray)

    class Member(val hash: BlobHash, var expiry: Long, val seq: Long, val createdAt: Long) {
        /** The upload minute the relay keeps (`time_bucket` of the store). */
        val uploaded: Long = createdAt - Math.floorMod(createdAt, 60L)
    }

    class Header(val kind: Int, val namespace: NamespaceId, val quota: Long, val expiry: Long)

    /** A bearer credential v3 (design §4.3): version 3, kind, slot, namespace, secret. */
    class Credential(val kind: Int, val slot: Int, val namespace: NamespaceId, val secret: ByteArray)

    /** A `bearer_keys` record: what one verifier may do in one namespace for one period. */
    class Registration(val period: Long, val validUntil: Long, var quotaBytes: Long, val serials: MutableList<String>)

    /** One relay sweep: memberships removed, and the key sweep's own report (§4.5, §4.6). */
    class Sweep(val memberships: Int, val keyRecordsRemoved: Int, val keySerialsRemoved: Int, val keySweepRan: Boolean)

    /** A registration a deposit may be charged to, in charging order (§4.5). */
    private class Allowance(val record: DepositKey, val quotaBytes: Long, val validUntil: Long)

    /** What authorized an operation: a relay-minted capability, or a credential's registrations. */
    private sealed class Auth {
        class Capability(val header: Header) : Auth()
        class Bearer(val credential: Credential, val allowances: List<Allowance>) : Auth()

        val namespace: NamespaceId
            get() = when (this) {
                is Capability -> header.namespace
                is Bearer -> credential.namespace
            }
    }

    private class Space {
        val members = HashMap<BlobHash, Member>()
        val index = TreeMap<Long, BlobHash>()
        var nextSeq: Long? = null
    }

    private var macKey: ByteArray = key.copyOf()
    private val spaces = HashMap<NamespaceId, Space>()
    private val content = HashMap<BlobHash, ByteArray>()

    /**
     * The ES slot this relay serves, or null for a relay started without one: a relay without a
     * slot refuses every credential v3, and one with a slot refuses a credential naming another
     * (design §21.2 point 3).
     */
    var slot: Int? = null

    /** Quota ledger: SHA-256 of the token → (bytes used, capability expiry). */
    private val ledger = HashMap<BlobHash, Pair<Long, Long>>()

    /** `bearer_keys`: (namespace, period, kind, verifier) → the registration. */
    private val records = HashMap<RecordKey, Registration>()

    /** `serial_use`: (namespace, period, kind, serial) → (verifier, valid until). */
    private val serialUse = HashMap<SerialKey, Pair<String, Long>>()

    /** The key sweep never runs below this minute (the ADR-25 point 3 clock rule). */
    private var sweepHighWaterMinute: Long? = null

    /** Deposit ledger, in memory: registration → (bytes used, valid until). */
    private val deposits = HashMap<DepositKey, Pair<Long, Long>>()
    private var depositsPrunedThrough: Long = 0

    /** Every (namespace, hash) that ever had a membership here. */
    val everHeld = HashSet<Pair<NamespaceId, BlobHash>>()

    /** Charged stores per (namespace, hash). */
    val charges = HashMap<Pair<NamespaceId, BlobHash>, Int>()

    /** Relay times of stores that created, renewed or extended a membership, per (namespace, hash). */
    val changingStores = HashMap<Pair<NamespaceId, BlobHash>, MutableList<Long>>()

    /** Count of state changes (stores that changed something, prunes that removed something, drops). */
    var mutations: Long = 0
        private set

    // ------------------------------------------------------------------ capabilities

    fun mint(kind: Int, namespace: NamespaceId, quota: Long, expiry: Long): ByteArray {
        require(kind == KIND_READ || kind == KIND_WRITE) { "capability kind out of range" }
        val body = ByteBuffer.allocate(BODY_BYTES).put(VERSION).put(kind.toByte()).put(namespace.toByteArray())
            .putLong(quota).putLong(expiry).array()
        return body + mac(body)
    }

    /** Key rotation (FR-5.7): every outstanding capability stops verifying. */
    fun rotateKey(newKey: ByteArray) {
        macKey = newKey.copyOf()
    }

    private fun mac(body: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(macKey, "HmacSHA256")) }.doFinal(body)

    /** The relay's current MAC key (the `:entitlement` harness mints redeemed v2 capabilities with it). */
    fun key(): ByteArray = macKey.copyOf()

    /** Verifies [token] for [required] on [namespace]; null = refused (`unauthorized`). */
    private fun verify(token: ByteArray, required: Int, namespace: NamespaceId, now: Long): Header? {
        val bodyBytes = bodyBytes(token) ?: return null
        val body = token.copyOfRange(0, bodyBytes)
        if (!MessageDigest.isEqual(mac(body), token.copyOfRange(bodyBytes, token.size))) return null
        val cap = header(token) ?: return null
        if (cap.expiry <= now) return null
        val scope = cap.namespace == namespace && (cap.kind == required || (cap.kind == KIND_WRITE && required == KIND_READ))
        return if (scope) cap else null
    }

    private fun verifyAny(token: ByteArray, now: Long): Header? {
        val h = header(token) ?: return null
        return verify(token, h.kind, h.namespace, now)
    }

    /**
     * Authorizes [token] for [op] (design §4.5, §21.2 point 5): a bearer credential v3 through its
     * live registrations, anything else as a relay-minted capability. [namespace] is the one the
     * request names, for the operations that name one; get and check take it from the token. Every
     * refusal is one answer, `unauthorized`: no oracle.
     */
    private fun authorize(token: ByteArray, op: Op, namespace: NamespaceId?, now: Long): Auth? {
        val credential = credential(token)
        if (credential != null) {
            if (!allows(credential.kind, op) || slot == null || slot != credential.slot) return null
            if (namespace != null && namespace != credential.namespace) return null
            val live = liveRecords(credential, now)
            return if (live.isEmpty()) null else Auth.Bearer(credential, live)
        }
        val header = when {
            op == Op.STORE && namespace != null -> verify(token, KIND_WRITE, namespace, now)
            op == Op.LIST && namespace != null -> verify(token, KIND_READ, namespace, now)
            else -> verifyAny(token, now)
        }
        return header?.let { Auth.Capability(it) }
    }

    /** The registrations behind [credential] that are live at [now], earliest validity first. */
    private fun liveRecords(credential: Credential, now: Long): List<Allowance> {
        val verifier = verifierOf(credential).hex()
        val week = week(now)
        return ((week - 3)..(week + 1)).mapNotNull { period ->
            val record = records[RecordKey(credential.namespace, period, credential.kind, verifier)]
            if (record == null || now >= record.validUntil) {
                null
            } else {
                Allowance(DepositKey(credential.namespace, period, verifier), record.quotaBytes, record.validUntil)
            }
        }.sortedWith(compareBy({ it.validUntil }, { it.record.period }))
    }

    /** What a deposit charge did, mirroring `DepositLedger::charge` and its two `CapError`s. */
    private sealed class Charge {
        class Charged(val record: DepositKey) : Charge()

        /** No allowance covers the bytes: RESOURCE_EXHAUSTED, `quota` at the client. */
        object Exhausted : Charge()

        /**
         * Every candidate is valid only until the ledger's prune high-water, so none is ever
         * charged again: `CapError::Expired`, PERMISSION_DENIED, `unauthorized` at the client
         * (`relay/crates/capability/src/lib.rs`, `node/src/lib.rs` `cap_error`).
         */
        object Expired : Charge()
    }

    /**
     * Charges [bytes] to the first registration whose allowance still covers them (design §4.5).
     * The used bytes live in memory and restart empty (E29). A candidate at or below the prune
     * high-water is skipped; when every candidate is, the answer is [Charge.Expired] and not
     * [Charge.Exhausted] (`register.txt` section 6).
     */
    private fun chargeDeposit(allowances: List<Allowance>, bytes: Long): Charge {
        var expired = true
        for (a in allowances) {
            if (a.validUntil <= depositsPrunedThrough) continue
            expired = false
            val (used, _) = deposits[a.record] ?: Pair(0L, a.validUntil)
            if (used + bytes <= a.quotaBytes) {
                deposits[a.record] = Pair(used + bytes, a.validUntil)
                return Charge.Charged(a.record)
            }
        }
        return if (expired && allowances.isNotEmpty()) Charge.Expired else Charge.Exhausted
    }

    // ------------------------------------------------------------------ operations

    fun store(namespace: NamespaceId, data: ByteArray, token: ByteArray, ttlSeconds: Long, now: Long): Reply<Receipt> {
        if (ttlSeconds !in TTL_BUCKETS || ttlSeconds > maxTtlSeconds) return Reply.Err("rejected")
        if (data.size !in Buckets.SIZES) return Reply.Err("rejected")
        val auth = authorize(token, Op.STORE, namespace, now) ?: return Reply.Err("unauthorized")
        val hash = sha256(data)
        if (hash in refusedStores) return Reply.Err("unauthorized")
        val wanted = ceilHour(now + ttlSeconds)
        val space = spaces.getOrPut(namespace) { Space() }
        val existing = space.members[hash]
        if (existing != null && existing.expiry > now && existing.expiry + HOUR >= wanted) {
            return Reply.Ok(Receipt(hash, existing.expiry + longExpirySeconds))
        }
        when (auth) {
            is Auth.Capability -> {
                val cap = auth.header
                val scope = sha256(token)
                val (used, _) = ledger[scope] ?: Pair(0L, cap.expiry)
                if (used + data.size > cap.quota) return Reply.Err("quota")
                ledger[scope] = Pair(used + data.size, cap.expiry)
            }
            is Auth.Bearer -> {
                when (chargeDeposit(auth.allowances, data.size.toLong())) {
                    is Charge.Charged -> Unit
                    Charge.Exhausted -> return Reply.Err("quota")
                    Charge.Expired -> return Reply.Err("unauthorized")
                }
            }
        }
        val key = Pair(namespace, hash)
        charges[key] = (charges[key] ?: 0) + 1
        changingStores.getOrPut(key) { ArrayList() } += now
        mutations++
        if (existing != null && existing.expiry > now) {
            existing.expiry = wanted
        } else {
            if (existing != null) removeMembership(namespace, space, existing)
            val seq = space.nextSeq ?: seed(now)
            space.nextSeq = seq + 1
            space.members[hash] = Member(hash, wanted, seq, now)
            space.index[seq] = hash
            content[hash] = data.copyOf()
            everHeld += key
        }
        return Reply.Ok(Receipt(hash, wanted + longExpirySeconds))
    }

    /**
     * Serves a blob of the token's namespace. A read or fetch credential sees `uploaded` floored
     * to the start of its ISO week, and a fetch credential also sees the expiry rounded up to the
     * next week boundary (design §21.9 point 4, §22.8.7 point 1); a capability sees the upload
     * minute and the hour-rounded expiry.
     */
    fun get(hash: BlobHash, token: ByteArray, now: Long): Reply<Served> {
        val auth = authorize(token, Op.GET, null, now) ?: return Reply.Err("unauthorized")
        val m = spaces[auth.namespace]?.members?.get(hash)
        if (m == null || m.expiry <= now) return Reply.Err("not_found")
        val fetch = auth is Auth.Bearer && auth.credential.kind == KIND_FETCH
        val uploaded = if (auth is Auth.Bearer) weekFloor(m.uploaded) else m.uploaded
        val expiry = if (fetch) weekCeil(m.expiry) else m.expiry
        return Reply.Ok(Served(content.getValue(hash).copyOf(), expiry, uploaded))
    }

    fun check(hashes: List<BlobHash>, token: ByteArray, now: Long): Reply<List<BlobHash>> {
        if (hashes.size > MAX_BATCH) return Reply.Err("rejected")
        val auth = authorize(token, Op.CHECK, null, now) ?: return Reply.Err("unauthorized")
        val members = spaces[auth.namespace]?.members
        return Reply.Ok(hashes.filter { h -> members?.get(h)?.let { it.expiry > now } == true })
    }

    fun list(namespace: NamespaceId, token: ByteArray, cursor: ByteArray, limit: Int, now: Long): Reply<Page> {
        if (limit <= 0 || limit > MAX_BATCH) return Reply.Err("rejected")
        authorize(token, Op.LIST, namespace, now) ?: return Reply.Err("unauthorized")
        val start = when (cursor.size) {
            0 -> 0L
            8 -> ByteBuffer.wrap(cursor).long + 1
            else -> return Reply.Err("rejected")
        }
        val space = spaces[namespace] ?: return Reply.Ok(Page(emptyList(), ByteArray(0)))
        val hashes = ArrayList<BlobHash>()
        var last: Long? = null
        var exhausted = true
        var scanned = 0
        for ((seq, hash) in space.index.tailMap(start, true)) {
            if (hashes.size == limit || scanned == MAX_LIST_SCAN) {
                exhausted = false
                break
            }
            scanned++
            last = seq
            if ((space.members[hash]?.expiry ?: 0L) > now) hashes += hash
        }
        val next = if (exhausted || last == null) ByteArray(0) else cursorOf(last)
        return Reply.Ok(Page(hashes, next))
    }

    /**
     * `RegisterKey` (design §4.4), in the order the relay applies it: lengths and kind, a usable
     * write capability of this relay for the namespace, the period against the **capability's**
     * week (never the relay's clock), then one accumulating record. `Ok` carries
     * [RESULT_WRONG_PERIOD] when the period is neither the capability's week nor the next, and
     * nothing is recorded then either.
     */
    fun registerKey(
        namespaceBytes: ByteArray,
        period: Long,
        kind: Int,
        verifier: ByteArray,
        capability: ByteArray?,
        requestId: ByteArray,
        now: Long,
        version: Int = 1,
    ): Reply<RegisterAnswer> {
        val answer = { result: Int, validUntil: Long -> RegisterAnswer(result, week(now), now / 60, validUntil) }
        if (version != 1 || namespaceBytes.size != 32 || verifier.size != 32 || requestId.size != 16) {
            return Reply.Err("rejected")
        }
        if (kind != KIND_READ && kind != KIND_DEPOSIT && kind != KIND_FETCH) return Reply.Err("rejected")
        val namespace = NamespaceId(namespaceBytes)
        val token = capability ?: return Reply.Err("unauthorized")
        val cap = verify(token, KIND_WRITE, namespace, now) ?: return Reply.Err("unauthorized")
        val capWeek = capabilityWeek(token, cap.expiry, now)
        if (period != capWeek && period != capWeek + 1) return Reply.Ok(answer(RESULT_WRONG_PERIOD, 0))
        val validUntil = registrationValidUntil(period)
        val verifierHex = verifier.hex()
        val serial = capabilitySerial(token).hex()
        val useKey = SerialKey(namespace, period, kind, serial)
        var wrote = false
        when (serialUse[useKey]?.first) {
            null -> {
                serialUse[useKey] = Pair(verifierHex, validUntil)
                wrote = true
            }
            verifierHex -> Unit
            // One capability registers at most one verifier per (namespace, week, kind).
            else -> return Reply.Err("unauthorized")
        }
        val recordKey = RecordKey(namespace, period, kind, verifierHex)
        val record = records[recordKey]
        if (record == null) {
            records[recordKey] = Registration(period, validUntil, cap.quota, mutableListOf(serial))
            wrote = true
        } else if (serial !in record.serials && record.serials.size < MAX_SERIALS) {
            record.serials += serial
            record.quotaBytes += cap.quota
            wrote = true
        }
        // An identical retry writes nothing (the relay aborts its transaction), so it is no state
        // change the harness has to classify.
        if (wrote) mutations++
        return Reply.Ok(answer(RESULT_OK, validUntil))
    }

    /** The stored registration of (namespace, period, kind, verifier), live or not. */
    fun record(namespace: NamespaceId, period: Long, kind: Int, verifier: ByteArray): Registration? =
        records[RecordKey(namespace, period, kind, verifier.hex())]

    /** Bytes the deposit ledger charged to a registration (0 without an entry). */
    fun depositsUsed(namespace: NamespaceId, period: Long, verifier: ByteArray): Long =
        deposits[DepositKey(namespace, period, verifier.hex())]?.first ?: 0

    /** Entries in the deposit ledger. */
    fun depositLedgerSize(): Int = deposits.size

    /** A relay restart: registrations and blobs stay, the in-memory ledgers empty (§4.5, E29). */
    fun restart() {
        ledger.clear()
        deposits.clear()
        depositsPrunedThrough = 0
    }

    /**
     * `keys.redb` lost (design §4.6, hostile mode LOSE_KEYS): the relay starts with no
     * registration, so every credential is refused until the owner registers again; blobs are
     * untouched.
     */
    fun loseKeys() {
        restart()
        records.clear()
        serialUse.clear()
        sweepHighWaterMinute = null
    }

    /** One sweep: removes every membership with expiry <= now; returns how many. */
    fun prune(now: Long): Int = sweep(now).memberships

    /**
     * One relay sweep at [now] (`ghost_relay_prune::sweep`): expired memberships, quota ledgers
     * and deposit-ledger entries always; the key registrations only at or above the persisted
     * high-water minute (the ADR-25 point 3 clock rule).
     */
    fun sweep(now: Long): Sweep {
        var removed = 0
        for ((ns, space) in spaces) {
            val doomed = space.members.values.filter { it.expiry <= now }
            for (m in doomed) {
                removeMembership(ns, space, m)
                removed++
            }
        }
        ledger.entries.removeIf { it.value.second <= now }
        if (removed > 0) mutations++
        val minute = now / 60
        val high = sweepHighWaterMinute
        val keySweepRan = high == null || minute >= high
        var recordsRemoved = 0
        var serialsRemoved = 0
        if (keySweepRan) {
            sweepHighWaterMinute = minute
            val records0 = records.size
            records.entries.removeIf { it.value.validUntil <= now }
            recordsRemoved = records0 - records.size
            val serials0 = serialUse.size
            serialUse.entries.removeIf { it.value.second <= now }
            serialsRemoved = serials0 - serialUse.size
        }
        depositsPrunedThrough = maxOf(depositsPrunedThrough, now)
        deposits.entries.removeIf { it.value.second <= now }
        return Sweep(removed, recordsRemoved, serialsRemoved, keySweepRan)
    }

    private fun removeMembership(namespace: NamespaceId, space: Space, m: Member) {
        space.members.remove(m.hash)
        space.index.remove(m.seq)
        if (space.index.isEmpty()) space.nextSeq = null
        check(namespace in spaces) { "unknown namespace" }
    }

    // ------------------------------------------------------------------ hostile helpers and introspection

    /**
     * REFUSE_ONE_SENDER (design §21.2 point 10, §21.9 point 3): the relay refuses the stores of
     * these blobs, whoever presents them. A depositor cannot be told apart by what it presents —
     * every card holder sends the same credential bytes — so a relay that wants to cut one sender
     * off has to pick it by something else; the world knows which blob is whose. A sender refused
     * this way still presents the same credential on its next try (no fallback, §21.2 point 7).
     */
    val refusedStores = HashSet<BlobHash>()

    /**
     * LONG_EXPIRY: store receipts claim this many seconds more than the relay really holds. The
     * client refuses the receipt above `ceil_hour(now + ttl) + σ` (design §10.2 point 6, T30).
     */
    var longExpirySeconds: Long = 0

    /** An ack-and-drop relay forgets a membership it acknowledged. */
    fun drop(namespace: NamespaceId, hash: BlobHash) {
        val space = spaces[namespace] ?: return
        val m = space.members[hash] ?: return
        removeMembership(namespace, space, m)
        mutations++
    }

    /** Another client's write straight into the relay (no capability, no quota; design §8.1). */
    fun inject(namespace: NamespaceId, data: ByteArray, ttlSeconds: Long, now: Long): BlobHash {
        val token = mint(KIND_WRITE, namespace, Long.MAX_VALUE / 4, now + 400L * 86_400)
        val reply = store(namespace, data, token, ttlSeconds, now)
        check(reply is Reply.Ok) { "injected store refused: $reply" }
        return reply.value.hash
    }

    fun member(namespace: NamespaceId, hash: BlobHash): Member? = spaces[namespace]?.members?.get(hash)

    fun live(namespace: NamespaceId, hash: BlobHash, now: Long): Boolean = (member(namespace, hash)?.expiry ?: 0L) > now

    /** Live memberships of [namespace] at [now]. */
    fun liveMembers(namespace: NamespaceId, now: Long): List<Member> =
        spaces[namespace]?.members?.values?.filter { it.expiry > now }.orEmpty()

    fun namespaces(): Set<NamespaceId> = spaces.keys.toSet()

    /**
     * The quota-ledger scopes (SHA-256 of each capability that authorized a store and has not
     * expired): what the Phase 9 entitlement world reads to see that every capability-authorized
     * store was authorized by a capability a redeem relay minted.
     */
    fun capabilityScopes(): Set<BlobHash> = ledger.keys.toSet()

    /**
     * Digest of the key registrations (`bearer_keys`, `serial_use`, the sweep high-water) and the
     * in-memory deposit ledger, which [digest] leaves out: an extension that registers keys adds it
     * to its crash digest (`World.extraState`), so two crash points whose worlds differ only
     * relay-side in a registration or a deposit charge never classify alike.
     */
    fun keysDigest(): String {
        // Keys spelled out: a NamespaceId's toString is redacted.
        val lines = ArrayList<String>()
        for ((k, r) in records) {
            lines += "r|${k.namespace.toByteArray().hex()}|${k.period}|${k.kind}|${k.verifier}|${r.validUntil}|${r.quotaBytes}|${r.serials.joinToString(",")}"
        }
        for ((k, v) in serialUse) lines += "s|${k.namespace.toByteArray().hex()}|${k.period}|${k.kind}|${k.serial}|${v.first}|${v.second}"
        for ((k, v) in deposits) lines += "d|${k.namespace.toByteArray().hex()}|${k.period}|${k.verifier}|${v.first}|${v.second}"
        lines.sort()
        lines += "h|$sweepHighWaterMinute|$depositsPrunedThrough"
        val md = MessageDigest.getInstance("SHA-256")
        md.update(lines.joinToString("\n").toByteArray())
        return md.digest().hex()
    }

    /** Digest of the whole state (memberships, index, sequences, ledger), for crash-point classification checks. */
    fun digest(): String {
        val md = MessageDigest.getInstance("SHA-256")
        for (ns in spaces.keys.sortedBy { it.toByteArray().hex() }) {
            val s = spaces.getValue(ns)
            md.update(ns.toByteArray())
            md.update(ByteBuffer.allocate(8).putLong(s.nextSeq ?: -1).array())
            for ((seq, h) in s.index) {
                val m = s.members.getValue(h)
                md.update(ByteBuffer.allocate(16).putLong(seq).putLong(m.expiry).array())
                md.update(h.toByteArray())
            }
        }
        for (k in ledger.keys.sortedBy { it.toByteArray().hex() }) {
            md.update(k.toByteArray())
            md.update(ByteBuffer.allocate(8).putLong(ledger.getValue(k).first).array())
        }
        return md.digest().hex()
    }

    override fun toString(): String = "ModelRelay($name)"

    companion object {
        const val KIND_READ = 1
        const val KIND_WRITE = 2
        const val VERSION: Byte = 1
        const val BODY_BYTES = 1 + 1 + 32 + 8 + 8
        const val TOKEN_BYTES = BODY_BYTES + 32

        /**
         * Capability v2 (Phase 8 design §10.3, X9): the v1 header plus a 16-byte serial, so a
         * redeemed capability is 98 bytes and its MAC covers bytes 0..66. The header fields sit
         * where v1 has them (`ghost_relay_api::capability_header` parses both).
         */
        const val VERSION_2: Byte = 2
        const val BODY_V2_BYTES = BODY_BYTES + 16
        const val TOKEN_V2_BYTES = BODY_V2_BYTES + 32

        /** The MAC-covered body length of a v1 or v2 capability, or null for anything else. */
        fun bodyBytes(token: ByteArray): Int? = when {
            token.size == TOKEN_BYTES && token[0] == VERSION -> BODY_BYTES
            token.size == TOKEN_V2_BYTES && token[0] == VERSION_2 -> BODY_V2_BYTES
            else -> null
        }
        const val MAX_BATCH = 256
        const val MAX_LIST_SCAN = 1024
        const val HOUR = 3_600L
        const val MAX_TTL = 7_776_000L

        /** The only TTLs a relay stores, in seconds (`ghost_relay_api::TTL_BUCKETS_SECONDS`). */
        val TTL_BUCKETS: Set<Long> = setOf(3_600L, 86_400L, 604_800L, 2_592_000L, 7_776_000L)

        fun ceilHour(t: Long): Long = -Math.floorDiv(-t, HOUR) * HOUR

        fun seed(now: Long): Long = (now / HOUR) shl 32

        fun cursorOf(seq: Long): ByteArray = ByteBuffer.allocate(8).putLong(seq).array()

        fun seqOf(cursor: ByteArray): Long = ByteBuffer.wrap(cursor).long

        fun sha256(bytes: ByteArray): BlobHash = BlobHash(MessageDigest.getInstance("SHA-256").digest(bytes))

        /** The public header of a v1 or v2 token (ghost_relay_api::capability_header), or null. */
        fun header(token: ByteArray): Header? {
            if (bodyBytes(token) == null) return null
            val kind = token[1].toInt()
            if (kind != KIND_READ && kind != KIND_WRITE) return null
            val b = ByteBuffer.wrap(token)
            return Header(kind, NamespaceId(token.copyOfRange(2, 34)), b.getLong(34), b.getLong(42))
        }

        // -------------------------------------------------------------- Phase 9: keys (§4.3-§4.6)

        /** Bearer kinds (`KeyKind` of relay.proto); 2 is Write in capability headers, never a kind. */
        const val KIND_DEPOSIT = 3
        const val KIND_FETCH = 4

        const val CREDENTIAL_VERSION: Byte = 3
        const val CREDENTIAL_BYTES = 1 + 1 + 1 + 32 + 32

        /** `RegisterResult` of relay.proto. */
        const val RESULT_OK = 1
        const val RESULT_WRONG_PERIOD = 2

        /** Capability credits one record keeps at most (design §4.4 point 4). */
        const val MAX_SERIALS = 4

        const val WEEK = 604_800L
        const val WEEK_OFFSET = 345_600L

        /** ISO week of an instant and its first second (`ghost_entitlement::grid`). */
        fun week(t: Long): Long = if (t < WEEK_OFFSET) 0 else (t - WEEK_OFFSET) / WEEK

        fun weekStart(p: Long): Long = WEEK_OFFSET + WEEK * p

        /** The start of an instant's ISO week (what a bearer read sees, §21.9 point 4). */
        fun weekFloor(t: Long): Long = minOf(weekStart(week(t)), t)

        /** The next ISO week boundary at or after an instant (what a fetch get sees, §22.8.7). */
        fun weekCeil(t: Long): Long {
            val start = weekStart(week(t))
            return if (start >= t) start else weekStart(week(t) + 1)
        }

        /** When a registration of [period] lapses: `start(period + 2) + 1 h` (§4.4 point 4). */
        fun registrationValidUntil(period: Long): Long = weekStart(period + 2) + HOUR

        /**
         * The ISO week a write capability belongs to (§4.4 point 3): a v2 capability's expiry is
         * `start(week + 1) + 1 h`, so its week is `week(expiry - 3601)`; an operator-minted v1
         * capability is of the week of the registration.
         */
        fun capabilityWeek(token: ByteArray, expiry: Long, now: Long): Long =
            if (bodyBytes(token) == BODY_V2_BYTES) week(expiry - (HOUR + 1)) else week(now)

        /** The serial a capability registers under: v2's own serial, else its scope hash's head. */
        fun capabilitySerial(token: ByteArray): ByteArray =
            if (bodyBytes(token) == BODY_V2_BYTES) {
                token.copyOfRange(BODY_BYTES, BODY_V2_BYTES)
            } else {
                sha256(token).toByteArray().copyOfRange(0, 16)
            }

        /** The operations of the relay's kind/operation matrix (design §4.3 "Rights"). */
        enum class Op { STORE, GET, CHECK, LIST }

        /** read → list, get, check; deposit → store, check; fetch → list, get. */
        fun allows(kind: Int, op: Op): Boolean = when (kind) {
            KIND_READ -> op != Op.STORE
            KIND_DEPOSIT -> op == Op.STORE || op == Op.CHECK
            KIND_FETCH -> op == Op.GET || op == Op.LIST
            else -> false
        }

        /** A bearer credential v3, or null for anything that is not exactly one. */
        fun credential(token: ByteArray): Credential? {
            if (token.size != CREDENTIAL_BYTES || token[0] != CREDENTIAL_VERSION) return null
            val kind = token[1].toInt()
            if (kind != KIND_READ && kind != KIND_DEPOSIT && kind != KIND_FETCH) return null
            return Credential(kind, token[2].toInt() and 0xff, NamespaceId(token.copyOfRange(3, 35)), token.copyOfRange(35, 67))
        }

        /** The 67 credential bytes of a secret. */
        fun credentialBytes(kind: Int, slot: Int, namespace: NamespaceId, secret: ByteArray): ByteArray {
            require(secret.size == 32) { "a bearer secret is 32 bytes" }
            return ByteBuffer.allocate(CREDENTIAL_BYTES)
                .put(CREDENTIAL_VERSION).put(kind.toByte()).put(slot.toByte())
                .put(namespace.toByteArray()).put(secret).array()
        }

        /** `SHA-256(label(kind) || slot || namespace || secret)` (design §4.3). */
        fun verifierOf(c: Credential): ByteArray {
            val label = when (c.kind) {
                KIND_READ -> "ghost/v1/read-verifier"
                KIND_DEPOSIT -> "ghost/v1/deposit-verifier"
                KIND_FETCH -> "ghost/v1/fetch-verifier"
                else -> throw IllegalArgumentException("no such bearer kind")
            }
            val md = MessageDigest.getInstance("SHA-256")
            md.update(label.toByteArray(Charsets.US_ASCII))
            md.update(byteArrayOf(c.slot.toByte()))
            md.update(c.namespace.toByteArray())
            md.update(c.secret)
            return md.digest()
        }
    }

    /** A `RegisterKey` answer (design §4.2). */
    class RegisterAnswer(val result: Int, val relayPeriodId: Long, val relayMinute: Long, val validUntil: Long)

    private data class RecordKey(val namespace: NamespaceId, val period: Long, val kind: Int, val verifier: String)

    private data class SerialKey(val namespace: NamespaceId, val period: Long, val kind: Int, val serial: String)

    /** A deposit registration, the unit the ledger charges (design §4.5). */
    data class DepositKey(val namespace: NamespaceId, val period: Long, val verifier: String)
}
