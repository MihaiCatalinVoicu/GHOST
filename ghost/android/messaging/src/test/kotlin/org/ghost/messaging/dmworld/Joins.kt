package org.ghost.messaging.dmworld

import org.ghost.identity.GhostIdentity
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The outcome of one exact join (Phase 9 design §15.6: "Exact joins (must find 0)"). */
internal class JoinResult(
    val id: String,
    /** What the join looked at; a join over nothing found nothing and proves nothing. */
    val scanned: Long,
    val violations: List<String>,
    val detail: String,
) {
    val passed: Boolean get() = violations.isEmpty()

    /** The report line; `dm-report-check.sh` requires `PASS 0 …` and a non-zero denominator. */
    fun line(): String =
        "dm $id: ${if (passed) "PASS" else "FAIL"} ${violations.size} over $scanned; $detail"

    fun failureMessage(): String =
        "$id found ${violations.size} over $scanned: " + violations.take(5).joinToString("; ")
}

/**
 * A dictionary of byte strings, searched for as **16-byte windows** anywhere inside a corpus.
 *
 * Matching the 16-byte prefix of an entry, rather than the whole entry, is deliberately stronger
 * than §15.6's "exact": a namespace or a verifier built from the first half of a hash of identity
 * material is found too. Two independent uniform 16-byte strings collide with probability 2⁻¹²⁸,
 * so a hit is a join and never chance.
 */
internal class ByteDictionary {

    class Entry(val name: String, val bytes: ByteArray)

    private val index = HashMap<Long, MutableList<Entry>>()

    var size: Int = 0
        private set

    fun add(name: String, bytes: ByteArray) {
        require(bytes.size >= WINDOW) { "$name is shorter than a window" }
        index.getOrPut(long(bytes, 0)) { ArrayList(1) } += Entry(name, bytes)
        size++
    }

    /** Calls [onHit] for every window of [corpus] equal to the first 16 bytes of an entry. */
    fun scan(corpus: ByteArray, onHit: (Entry, Int) -> Unit) {
        if (corpus.size < WINDOW) return
        for (p in 0..corpus.size - WINDOW) {
            val candidates = index[long(corpus, p)] ?: continue
            for (entry in candidates) {
                if (long(entry.bytes, 8) == long(corpus, p + 8)) onHit(entry, p)
            }
        }
    }

    private companion object {
        const val WINDOW = 16

        fun long(bytes: ByteArray, at: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (bytes[at + i].toLong() and 0xff)
            return v
        }
    }
}

/**
 * The exact joins JD1, JD2, JD3, JD4, JD5, JD6, JD7 and JD9 of Phase 9 design §15.6 over a finished
 * [PrivacyWorld]. JD8 and JD10 are not here; §22.16 says why.
 */
internal class Joins(private val world: PrivacyWorld) {

    private val events = world.relay.events

    /** Every distinct byte string of the effective view: JD1's and JD2's corpus. */
    private val corpus: List<Pair<String, ByteArray>> by lazy {
        val seen = HashSet<GroundTruth.Key>()
        val out = ArrayList<Pair<String, ByteArray>>()
        fun add(what: String, bytes: ByteArray?) {
            bytes ?: return
            if (seen.add(GroundTruth.Key(bytes))) out += what to bytes
        }
        for (e in events) {
            add("${e.op} namespace", e.namespace)
            add("${e.op} blob", e.bytes)
            add("${e.op} blob hash", e.blobHash)
            add("${e.op} credential", e.credential)
            add("${e.op} credential scope", e.credential?.let { sha256(it) })
            add("REGISTER verifier (keys.redb)", e.verifier)
        }
        out
    }

    val corpusBytes: Long by lazy { corpus.sumOf { it.second.size.toLong() } }

    // ------------------------------------------------------------------ JD1

    /**
     * JD1 (§15.6): "identity dictionary (every `ghost1` hash, Ed25519 key, Olm identity key in its
     * 32-byte form and base64 forms, safety-number bytes, and for each SHA-256, SHA-256 with every
     * label, HKDF with every label) scanned over every captured field, circuit-level byte, stored
     * blob and `keys.redb` record".
     */
    fun jd1(): JoinResult {
        val dictionary = identityDictionary(world)
        return scan("JD1", dictionary, "identity dictionary of ${dictionary.size} entries")
    }

    // ------------------------------------------------------------------ JD2

    /**
     * JD2 (§15.6): "Olm header strings (identity keys, base keys, fallback keys, ratchet keys, 32-byte
     * prefixes of X-Wing public keys …) absent". The strings are the ones the running sessions
     * produced, recorded at the port ([GroundTruth]); X-Wing **ciphertext** prefixes and `gen_id`
     * values are not in it (§22.16).
     */
    fun jd2(): JoinResult {
        val dictionary = ByteDictionary()
        for (key in world.truth.olmHeaderKeys) dictionary.add("olm header ${key}", key.bytes)
        for (key in world.truth.bundleKeys) dictionary.add("bundle key ${key}", key.bytes)
        for (t in world.truth.clients.values) t.olmIdentity?.let { dictionary.add("OI of c${t.index}", it) }
        return scan("JD2", dictionary, "${dictionary.size} Olm header and bundle key strings")
    }

    private fun scan(id: String, dictionary: ByteDictionary, what: String): JoinResult {
        val violations = ArrayList<String>()
        for ((name, bytes) in corpus) {
            dictionary.scan(bytes) { entry, offset ->
                violations += "${entry.name} found in a $name at offset $offset"
            }
        }
        return JoinResult(
            id, corpus.size.toLong(), violations,
            "$what over ${corpus.size} distinct captured byte strings ($corpusBytes bytes)",
        )
    }

    // ------------------------------------------------------------------ JD3

    /**
     * JD3 (§15.6): "per (relay, inbox, week) the deposit-credential store scopes ⊆ {the deposit
     * scope}, and no redeem or register by an honest client for a namespace it does not own".
     *
     * The expected scope is computed here, from the owner's own secrets and §4.3's layout, and not
     * read back from the sender. No redeem happens in this world (§22.16), so the second half is the
     * registrations only.
     */
    fun jd3(): JoinResult {
        val owner = world.ownerOf()
        val inboxes = world.truth.clients.values.mapNotNull { t -> t.inboxNamespace?.let { hex(it) to t.index } }.toMap()
        val expected = HashMap<Pair<Int, String>, String>()
        val violations = ArrayList<String>()
        var stores = 0L
        val scopes = HashMap<Triple<Int, String, Long>, MutableSet<String>>()
        for (e in events) {
            if (e.op == ViewOp.REGISTER) {
                stores++
                val ns = hex(e.namespace)
                if (owner[ns] != e.client) violations += "c${e.client} registered ${ns.take(12)} it does not own"
                continue
            }
            if (e.op != ViewOp.STORE) continue
            val ns = hex(e.namespace)
            val recipient = inboxes[ns] ?: continue
            stores++
            val want = expected.getOrPut(e.relaySlot to ns) {
                val secret = requireNotNull(world.clients[recipient].device.crypto.ownSecrets(0, e.relaySlot)) {
                    "no DM context for c$recipient"
                }.deposit
                hex(sha256(byteArrayOf(3, 3, e.relaySlot.toByte()) + e.namespace + secret))
            }
            val got = e.credential?.let { hex(sha256(it)) }
            if (got != want) {
                violations += "c${e.client} stored into c$recipient's inbox at slot ${e.relaySlot} with " +
                    (if (got == null) "no credential" else "scope ${got.take(12)} ≠ the deposit scope ${want.take(12)}")
            }
            scopes.getOrPut(Triple(e.relaySlot, ns, world.weekOf(e.second))) { HashSet() } += got ?: "none"
        }
        for ((key, set) in scopes) {
            if (set.size > 1) violations += "slot ${key.first} inbox ${key.second.take(12)} week ${key.third}: ${set.size} scopes"
        }
        return JoinResult("JD3", stores, violations, "inbox stores and registrations; ${scopes.size} (relay, inbox, week) cells")
    }

    // ------------------------------------------------------------------ JD4

    /**
     * JD4 (§15.6): "`size_bucket` = class(body length) for every DM store", with class the R-B1
     * function of §6.6 computed **here**, from the body length the engine handed the encoder.
     */
    fun jd4(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        var boundary = 0
        val seen = HashSet<GroundTruth.Key>()
        for (e in events) {
            if (e.op != ViewOp.STORE) continue
            val key = GroundTruth.Key(e.blobHash!!)
            if (!seen.add(key)) continue
            n++
            val size = e.bytes!!.size
            if (key in world.truth.bundleBlobs) {
                if (size != 4096) violations += "a bundle stored at $size bytes"
                continue
            }
            val body = world.truth.bodyLengthOfBlob[key]
            if (body == null) {
                violations += "a DM store with no recorded body length (${key})"
                continue
            }
            if (body in 2_221..14_508) boundary++
            val want = rb1(body)
            if (size != want) violations += "a body of $body bytes stored at $size, R-B1 says $want"
        }
        return JoinResult("JD4", n, violations, "distinct DM stores, $boundary of them with a body in the 16 KiB class")
    }

    // ------------------------------------------------------------------ JD5

    /**
     * JD5 (§15.6): "TTL = the §10.1 table, no store after the deadline". The table is written out
     * here from §10.1 rather than read from `DmTimers`. The relay-side membership expiry half is a
     * relay property the model relay does not have (§22.16).
     */
    fun jd5(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        val seen = HashSet<GroundTruth.Key>()
        for (e in events) {
            if (e.op != ViewOp.STORE) continue
            if (!seen.add(GroundTruth.Key(e.blobHash!!))) continue
            n++
            val ttl = e.ttlSeconds!!
            if (ttl !in setOf(3_600L, 86_400L, 604_800L, 2_592_000L, 7_776_000L)) violations += "TTL $ttl is not a bucket"
            e.deadlineSecond?.let { if (e.second > it) violations += "a store ${e.second - it} s after its deadline" }
            val cause = e.cause ?: continue
            val timer = cause.timerCode ?: continue
            if (cause.kind == 1 && ttl != table(timer)) {
                violations += "a text with timer code $timer stored with TTL $ttl, §10.1 says ${table(timer)}"
            }
            if (cause.kind == 2 && ttl < table(timer)) {
                violations += "a TIMER_SET to code $timer stored with TTL $ttl, below its bucket (R-T3)"
            }
        }
        return JoinResult("JD5", n, violations, "distinct stores against the §10.1 table and their deadlines")
    }

    // ------------------------------------------------------------------ JD6

    /**
     * JD6 (§15.6): "every store maps to an `oracle_user_action`, a scheduled action, a bundle
     * publication or an identical resend". The oracle is the message ids each user action created
     * ([PrivacyWorld.userAction]); the mapping is the sender's own `dm_outbound_op` row.
     */
    fun jd6(): JoinResult {
        val violations = ArrayList<String>()
        val classes = LinkedHashMap<String, Int>()
        val seenOps = HashSet<GroundTruth.Key>()
        val seenHashes = HashSet<GroundTruth.Key>()
        for (e in events) {
            if (e.op != ViewOp.STORE) continue
            val cause = e.cause!!
            if (!seenOps.add(GroundTruth.Key(cause.operationId))) continue
            val kind = when {
                !seenHashes.add(GroundTruth.Key(e.blobHash!!)) -> "identical resend"
                cause.purpose == "bundle" -> "bundle publication"
                cause.purpose == "item" && cause.control != null -> {
                    violations += "c${e.client}: a ${cause.control} control no user action scheduled"
                    "control"
                }
                cause.purpose == "item" && cause.messageRef != null &&
                    hex(cause.messageRef) in world.clients[e.client].userMessages -> "user action"
                else -> {
                    violations += "c${e.client}: a store at ${e.second} maps to no user action " +
                        "(purpose ${cause.purpose}, message ${cause.messageRef?.let { hex(it).take(8) }})"
                    "unmapped"
                }
            }
            classes.merge(kind, 1, Int::plus)
        }
        return JoinResult("JD6", seenOps.size.toLong(), violations, "ops by cause $classes")
    }

    // ------------------------------------------------------------------ JD7

    /**
     * JD7 (§15.6): "every list or get is on own namespaces, except one bundle fetch per
     * establishment, reset or reconnect (≤ 3 attempts, list events only inside attempt windows)".
     */
    fun jd7(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        var bundleReads = 0
        for (e in events) {
            if (e.op != ViewOp.LIST && e.op != ViewOp.GET) continue
            n++
            val ns = hex(e.namespace)
            if (ns in world.ownNamespaces(e.client)) continue
            if (ns in world.contactBundles && e.establishmentWindow) {
                bundleReads++
                continue
            }
            violations += "c${e.client} ${e.op} on ${ns.take(12)} at ${e.second}, not its own and not an open " +
                "bundle fetch (reader's contact row: ${e.readerState})"
        }
        return JoinResult("JD7", n, violations, "reads, $bundleReads of them bundle fetches inside a window")
    }

    // ------------------------------------------------------------------ JD9

    /**
     * JD9 (§15.6): "every DM namespace's relay set equals `set(ns, w)` or the declared 6-week union".
     * `set(ns, w)` is computed here from §5.2's text over the world's ES table (four slots, two
     * operators, one slot table for the whole world), not by `RelaySets`.
     */
    fun jd9(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        val sets = HashMap<String, Set<Int>>()
        for (e in events) {
            if (e.op == ViewOp.REGISTER) continue
            n++
            val ns = hex(e.namespace)
            val set = sets.getOrPut(ns) { relaySet(e.namespace) }
            if (e.relaySlot !in set) {
                violations += "c${e.client} ${e.op} on ${ns.take(12)} at slot ${e.relaySlot}, set(ns) = $set"
            }
        }
        // And every set the view shows is the whole set: a namespace stored at only two of its
        // three relays is a different set as much as one stored at a fourth.
        val storesBy = events.filter { it.op == ViewOp.STORE }.groupBy { hex(it.blobHash!!) + hex(it.namespace) }
        for ((_, stores) in storesBy) {
            val ns = hex(stores.first().namespace)
            val slots = stores.map { it.relaySlot }.toSet()
            if (slots != sets[ns]) violations += "a blob of ${ns.take(12)} stored at $slots, set(ns) = ${sets[ns]}"
        }
        return JoinResult("JD9", n, violations, "relay events over ${sets.size} namespaces")
    }

    companion object {
        /** R-B1 of §6.6 with `O_MAX = 1 664` and `EXT_RESERVE = 160`. */
        fun rb1(body: Int): Int = listOf(4096, 16384, 65536).first { 52 + body + 160 <= it - 1664 }

        /** §10.1's timer → TTL table (ADR-27 point 11). */
        fun table(timerCode: Int): Long = when (timerCode) {
            0 -> 2_592_000L
            1, 2 -> 3_600L
            3 -> 86_400L
            4 -> 604_800L
            5 -> 2_592_000L
            else -> error("timer code $timerCode")
        }

        /** §5.2's `set(ns, w)` over slot i → relay i, operator i mod 2, written from the text. */
        fun relaySet(namespace: ByteArray, slots: Int = PrivacyWorld.SLOTS, operators: Int = PrivacyWorld.OPERATORS): Set<Int> {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(namespace, "HmacSHA256"))
            val ordered = (0 until slots).map { slot ->
                mac.reset()
                mac.update("ghost/v1/dm/slot-order".toByteArray(Charsets.US_ASCII))
                mac.update(slot.toByte())
                slot to mac.doFinal()
            }.sortedWith { a, b ->
                var c = 0
                for (i in 0 until 32) {
                    c = (a.second[i].toInt() and 0xff) - (b.second[i].toInt() and 0xff)
                    if (c != 0) break
                }
                if (c != 0) c else a.first - b.first
            }.map { it.first }
            val chosen = LinkedHashSet<Int>()
            val ops = HashSet<Int>()
            for (slot in ordered) {
                if (chosen.size >= 3 && ops.size >= 2) break
                if (chosen.size >= 3 && (slot % operators) in ops) continue
                chosen += slot
                ops += slot % operators
            }
            return chosen
        }

        /**
         * Every label a DM, card, seal, binding or verifier derivation uses (Rust `derive.rs`,
         * `seal.rs`, `binding.rs`, `bundle.rs`, `card.rs`, `safety.rs`, `revocation.rs`, Kotlin
         * `CredentialV3`, `RelaySets`), each also with the parameters its derivations append.
         */
        val LABELS: List<ByteArray> by lazy {
            val names = listOf(
                "ghost/v1/identity",
                "ghost/v1/dm/olm-identity", "ghost/v1/dm/olm-account-signing", "ghost/v1/dm/card",
                "ghost/v1/dm/inbox-read", "ghost/v1/dm/schedule", "ghost/v1/dm/pair-epoch",
                "ghost/v1/dm/pair-next", "ghost/v1/dm/prov", "ghost/v1/dm/pq-root", "ghost/v1/dm/pub-offset",
                "ghost/v1/dm/slot-order",
                "ghost/v1/card/inbox-ns", "ghost/v1/card/bundle-ns", "ghost/v1/card/deposit",
                "ghost/v1/card/bundle-read", "ghost/v1/card/bundle-seal", "ghost/v1/card/intro-outer",
                "ghost/v1/dm-seal", "ghost/v1/dm-hint", "ghost/v1/dm-recognition", "ghost/v1/dm-pair-ad",
                "ghost/v1/dm-intro-kem", "ghost/v1/dm-intro-inner", "ghost/v1/dm-intro",
                "ghost/v1/dm-binding/v3", "ghost/v1/dm-bundle/v2", "ghost/v1/contact-card",
                "ghost/v1/revocation", "ghost/v1/safety-number", "ghost/v1/dm-session-binding",
                "ghost/v1/read-verifier", "ghost/v1/deposit-verifier", "ghost/v1/fetch-verifier",
            ).map { it.toByteArray(Charsets.US_ASCII) }
            val out = ArrayList<ByteArray>()
            for (label in names) {
                out += label
                out += label + byteArrayOf(0, 0)
                for (s in 0 until PrivacyWorld.SLOTS) {
                    out += label + byteArrayOf(s.toByte())
                    out += label + byteArrayOf(0, 0, s.toByte())
                }
            }
            out
        }

        /**
         * JD1's dictionary over every client of [world]: its identity material in raw, hashed and
         * encoded forms, the safety numbers of its accepted edges, and every labelled SHA-256 and HKDF
         * of each. Also S-DM3's attacker dictionary (its 32-byte entries, by owner).
         */
        fun identityDictionary(world: PrivacyWorld, byOwner: MutableMap<GroundTruth.Key, Int>? = null): ByteDictionary {
            val dictionary = ByteDictionary()
            fun add(owner: Int, name: String, bytes: ByteArray) {
                dictionary.add("c$owner $name", bytes)
                if (bytes.size == 32) byOwner?.put(GroundTruth.Key(bytes), owner)
            }
            for (t in world.truth.clients.values) {
                val pk = t.identityPk ?: continue
                val oi = t.olmIdentity ?: continue
                val identity = GhostIdentity.fromPublicKey(pk)
                val ghost1 = identity.encode().toByteArray(Charsets.US_ASCII)
                val base = linkedMapOf(
                    "Ed25519 key" to pk,
                    "ghost1 hash" to identity.publicKeyHash,
                    "Olm identity key" to oi,
                )
                for ((name, value) in base) {
                    add(t.index, name, value)
                    for (encoded in encodings(value)) add(t.index, "$name (base64)", encoded)
                    add(t.index, "SHA-256($name)", sha256(value))
                    for (label in LABELS) {
                        val l = String(label, Charsets.ISO_8859_1)
                        add(t.index, "SHA-256($l‖$name)", sha256(label + value))
                        add(t.index, "HKDF($name, $l)", hkdf(value, label))
                    }
                }
                add(t.index, "ghost1 string", ghost1)
                add(t.index, "SHA-256(ghost1 string)", sha256(ghost1))
            }
            for ((u, v) in world.acceptedEdges) {
                val a = world.truth.clients[u] ?: continue
                val b = world.truth.clients[v] ?: continue
                for ((own, peer) in listOf(a to b, b to a)) {
                    val number = world.clients[own.index].device.crypto.safetyNumber(
                        own.identityPk!!, own.olmIdentity!!, peer.identityPk!!, peer.olmIdentity!!,
                    ) ?: continue
                    add(own.index, "safety number with c${peer.index} (scannable)", number.scannable)
                    add(own.index, "safety number with c${peer.index} (digits)", number.digits.toByteArray(Charsets.US_ASCII))
                    add(own.index, "SHA-256(safety number with c${peer.index})", sha256(number.scannable))
                }
            }
            return dictionary
        }

        private fun encodings(value: ByteArray): List<ByteArray> = listOf(
            Base64.getEncoder().encode(value),
            Base64.getEncoder().withoutPadding().encode(value),
            Base64.getUrlEncoder().withoutPadding().encode(value),
        )

        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        /** HKDF-SHA256(ikm, salt = ∅, info, L = 32). */
        fun hkdf(ikm: ByteArray, info: ByteArray): ByteArray {
            val extract = Mac.getInstance("HmacSHA256")
            extract.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            val prk = extract.doFinal(ikm)
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(info)
            expand.update(1.toByte())
            return expand.doFinal()
        }

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}
