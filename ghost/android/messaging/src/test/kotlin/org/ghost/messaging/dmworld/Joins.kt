package org.ghost.messaging.dmworld

import org.ghost.identity.GhostIdentity
import org.ghost.messaging.DmWorld
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
 * A dictionary of byte strings, searched for as **16-byte windows** anywhere inside a corpus: every
 * entry is found wherever its **first or last** 16 bytes appear.
 *
 * Matching a 16-byte end of an entry, rather than the whole entry, is deliberately stronger than
 * §15.6's "exact": a namespace or a verifier built from either half of a hash of identity material
 * is found too (a value built from a **middle** slice of one is not). Two independent uniform 16-byte
 * strings collide with probability 2⁻¹²⁸, so a hit is a join and never chance.
 *
 * **Compact by construction.** JD1's dictionary is every labelled SHA-256 and HKDF of every client's
 * identity material — about 330 000 entries at the PR scale and 1.6 million at the gate's — so an
 * entry is four `long`s (its two windows) in flat arrays, indexed by an open-addressing table on each
 * window's first eight bytes, and its name is built by its family's rule only when it matched.
 */
internal class ByteDictionary {

    /** A dictionary hit: the entry, its name and its owner (a client index, or null). */
    class Entry(val id: Int, val name: String, val owner: Int?)

    private class Family(val owner: Int?, val nameOf: (Int) -> String)

    private val families = ArrayList<Family>()
    private var familyOf = IntArray(INITIAL)
    private var formOf = IntArray(INITIAL)

    /** Per entry: the two longs of its first 16 bytes, then the two of its last 16. */
    private var windows = LongArray(4 * INITIAL)

    var size: Int = 0
        private set

    private var keys = LongArray(INITIAL)
    private var slots = IntArray(INITIAL) { EMPTY }
    private var used = 0

    /** One entry of its own name. */
    fun add(name: String, bytes: ByteArray, owner: Int? = null) {
        add(family(owner) { name }, 0, bytes)
    }

    /**
     * Starts a family of entries sharing an owner; [nameOf] names each entry of the family by the
     * `form` it was [add]ed with, and runs only when that entry matched.
     */
    fun family(owner: Int?, nameOf: (Int) -> String): Int {
        families += Family(owner, nameOf)
        return families.size - 1
    }

    fun add(family: Int, form: Int, bytes: ByteArray) {
        require(bytes.size >= WINDOW) { "an entry is shorter than a window" }
        if (size == familyOf.size) {
            familyOf = familyOf.copyOf(size * 2)
            formOf = formOf.copyOf(size * 2)
            windows = windows.copyOf(size * 8)
        }
        val e = size++
        familyOf[e] = family
        formOf[e] = form
        val last = bytes.size - WINDOW
        windows[4 * e] = long(bytes, 0)
        windows[4 * e + 1] = long(bytes, 8)
        windows[4 * e + 2] = long(bytes, last)
        windows[4 * e + 3] = long(bytes, last + 8)
        insert(windows[4 * e], e * 2)
        if (last != 0) insert(windows[4 * e + 2], e * 2 + 1)
    }

    /**
     * Calls [onHit] for every window of [corpus] equal to the first or the last 16 bytes of an
     * entry, with the entry and the window's offset.
     */
    fun scan(corpus: ByteArray, onHit: (Entry, Int) -> Unit) {
        if (corpus.size < WINDOW || used == 0) return
        val mask = keys.size - 1
        for (p in 0..corpus.size - WINDOW) {
            val k = long(corpus, p)
            var i = mix(k) and mask
            var second = 0L
            var secondRead = false
            while (slots[i] != EMPTY) {
                if (keys[i] == k) {
                    if (!secondRead) {
                        second = long(corpus, p + 8)
                        secondRead = true
                    }
                    val v = slots[i]
                    val e = v ushr 1
                    if (windows[4 * e + 2 * (v and 1) + 1] == second) onHit(entry(e), p)
                }
                i = (i + 1) and mask
            }
        }
    }

    private fun entry(e: Int): Entry {
        val family = families[familyOf[e]]
        return Entry(e, family.nameOf(formOf[e]), family.owner)
    }

    private fun insert(key: Long, value: Int) {
        if ((used + 1) * 2 > keys.size) grow()
        val mask = keys.size - 1
        var i = mix(key) and mask
        while (slots[i] != EMPTY) i = (i + 1) and mask
        keys[i] = key
        slots[i] = value
        used++
    }

    private fun grow() {
        val oldKeys = keys
        val oldSlots = slots
        keys = LongArray(oldKeys.size * 2)
        slots = IntArray(oldKeys.size * 2) { EMPTY }
        val mask = keys.size - 1
        for (j in oldKeys.indices) {
            if (oldSlots[j] == EMPTY) continue
            var i = mix(oldKeys[j]) and mask
            while (slots[i] != EMPTY) i = (i + 1) and mask
            keys[i] = oldKeys[j]
            slots[i] = oldSlots[j]
        }
    }

    private companion object {
        const val WINDOW = 16
        const val INITIAL = 1 shl 10
        const val EMPTY = -1

        fun long(bytes: ByteArray, at: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (bytes[at + i].toLong() and 0xff)
            return v
        }

        fun mix(k: Long): Int {
            val h = k * -0x61c8864680b583ebL
            return (h xor (h ushr 29)).toInt()
        }
    }
}

/**
 * The exact joins JD1, JD2, JD3, JD4, JD5, JD6, JD7 and JD9 of Phase 9 design §15.6 over a finished
 * [PrivacyWorld]. JD8 and JD10 are not here: JD10 is deferred (§22.16 item 10), and JD8 runs on
 * the entitlement world's twins, which have the real redeem lane this world lacks (`entworld/
 * EntDmJd8.kt`, §22.26).
 *
 * **Every oracle is the world's or the recorder's, never the engine's own record of the property
 * checked**: JD5's timers come from the users' timer changes and the relay view, JD6's user actions
 * from what each facade call was for, JD7's establishments from the sessions the crypto port saw.
 * The one engine table read is the sender's `dm_outbound_item.message_ref` (which message an op
 * carries), and JD6 bounds it: one ciphertext per user message.
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
     * blob and `keys.redb` record". The labelled forms cover the Ed25519 key, the `ghost1` hash and
     * string and the Olm identity key; the base64 forms and the safety numbers are in raw and hashed
     * form only (§22.16).
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
        for (key in world.truth.olmHeaderKeys) dictionary.add("olm header $key", key.bytes)
        for (key in world.truth.bundleKeys) dictionary.add("bundle key $key", key.bytes)
        for (t in world.truth.clients.values) t.olmIdentity?.let { dictionary.add("OI of c${t.index}", it) }
        return scan("JD2", dictionary, "${dictionary.size} Olm header and bundle key strings")
    }

    private fun scan(id: String, dictionary: ByteDictionary, what: String): JoinResult {
        val violations = ArrayList<String>()
        for ((name, bytes) in corpus) {
            // One violation per entry and captured string: a whole entry inside a blob matches at
            // both of its windows.
            val found = HashSet<Int>()
            dictionary.scan(bytes) { entry, offset ->
                if (found.add(entry.id)) violations += "${entry.name} found in a $name at offset $offset"
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
     * registrations only. And **every store is into a card's namespace**: a card's inbox (with the
     * deposit scope) or the storer's own bundle namespace — a namespace no card names is one the
     * dictionary of JD1 need not know the label of (§3.2: every DM namespace is card-derived).
     */
    fun jd3(): JoinResult {
        val owner = world.ownerOf()
        val inboxes = world.truth.clients.values.mapNotNull { t -> t.inboxNamespace?.let { hex(it) to t.index } }.toMap()
        val bundles = world.truth.clients.values.mapNotNull { t -> t.bundleNamespace?.let { hex(it) to t.index } }.toMap()
        val expected = HashMap<Pair<Int, String>, String>()
        val violations = ArrayList<String>()
        var stores = 0L
        var bundleStores = 0
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
            stores++
            val recipient = inboxes[ns]
            if (recipient == null) {
                if (bundles[ns] == e.client) {
                    bundleStores++
                } else {
                    violations += "c${e.client} stored into ${ns.take(12)} at slot ${e.relaySlot}, which is no card's " +
                        "inbox and not its own bundle namespace" +
                        (bundles[ns]?.let { " (the bundle namespace of c$it)" } ?: "")
                }
                continue
            }
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
        return JoinResult(
            "JD3", stores, violations,
            "stores and registrations ($bundleStores stores into the storer's own bundle namespace, every other " +
                "into a card's inbox); ${scopes.size} (relay, inbox, week) cells",
        )
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
     * JD5 (§15.6): "TTL = the §10.1 table, no store after the deadline". Every TTL must be a bucket;
     * every user text's TTL must be §10.1's table of **the conversation's timer as the users set
     * it**, and every TIMER_SET's must be the larger of the old and the new bucket (R-T3).
     *
     * **The timer is not read from the engine.** A conversation starts at 7 d; a timer change
     * ([PrivacyWorld.timerChanges]) takes effect for the setter's own stores from the minute it was
     * made, and for the peer's from the first blob the setter stored after it that the peer fetched
     * (R-T9: the greater version is adopted from any message) — both read off the relay view. So a
     * responder that ignores a TIMER_SET, or a sender whose `dm_message.timer_code` agrees with its
     * own wrong TTL, fails here (R-T2: one bucket per conversation, in both directions).
     *
     * **Not here:** the deadline half is checked but cannot fail in this world — the model relay
     * stores every op in the session that enqueued it, and no world has an outage (PM-9's relay-
     * outage world, §22.16) — and the relay-side "membership expiry ≤ the T30 bound" clause, which
     * needs a relay model with memberships (§22.16). **Nor the pending path:** the world sets a
     * conversation's timer after `EST-READY` ([Plan]'s edges), so a TIMER_SET queued for a session
     * — the path where the engine takes the new timer's TTL, NI-DM2's declared open defect (§22.21
     * item 2) — is at most an accident here; the line counts those it saw, and a FAILED item's
     * retry (the defect's other half) is run by no world.
     */
    fun jd5(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        var texts = 0
        var timerSets = 0
        var queuedTimerSets = 0
        val inboxes = world.truth.clients.values.mapNotNull { t -> t.inboxNamespace?.let { hex(it) to t.index } }.toMap()
        // When each client first fetched each blob, and what each sender stored into each inbox.
        val firstGet = HashMap<Pair<Int, GroundTruth.Key>, Long>()
        val storedInto = HashMap<Pair<Int, Int>, MutableList<Pair<Long, GroundTruth.Key>>>()
        for (e in events) {
            when (e.op) {
                ViewOp.GET -> firstGet.putIfAbsent(e.client to GroundTruth.Key(e.blobHash!!), e.second)
                ViewOp.STORE -> inboxes[hex(e.namespace)]?.let { r ->
                    storedInto.getOrPut(e.client to r) { ArrayList() } += e.second to GroundTruth.Key(e.blobHash!!)
                }
                else -> Unit
            }
        }
        val changeByMessage = world.timerChanges.filter { it.messageId != null }.associateBy { it.messageId!! }
        // When a change takes effect for one side of its conversation (null: not yet, for the peer).
        fun effective(change: PrivacyWorld.TimerChange, side: Int): Long? =
            if (side == change.setter) {
                change.at
            } else {
                storedInto[change.setter to change.peer].orEmpty()
                    .filter { it.first >= change.at }
                    .mapNotNull { firstGet[change.peer to it.second] }
                    .minOrNull()
            }
        fun expectedCode(sender: Int, peer: Int, at: Long): Int {
            var best: Pair<Long, Int>? = null
            for (change in world.timerChanges) {
                val same = (change.setter == sender && change.peer == peer) || (change.setter == peer && change.peer == sender)
                if (!same) continue
                val from = effective(change, sender) ?: continue
                if (from <= at && (best == null || from >= best.first)) best = from to change.newCode
            }
            return best?.second ?: org.ghost.messaging.api.Timer.DAYS_7.code
        }
        val seen = HashSet<GroundTruth.Key>()
        for (e in events) {
            if (e.op != ViewOp.STORE) continue
            if (!seen.add(GroundTruth.Key(e.blobHash!!))) continue
            n++
            val ttl = e.ttlSeconds!!
            if (ttl !in setOf(3_600L, 86_400L, 604_800L, 2_592_000L, 7_776_000L)) violations += "TTL $ttl is not a bucket"
            e.deadlineSecond?.let { if (e.second > it) violations += "a store ${e.second - it} s after its deadline" }
            val ref = e.cause?.messageRef?.let(::hex) ?: continue
            world.userTexts[ref]?.let { (sender, peer) ->
                texts++
                val code = expectedCode(sender, peer, e.second)
                if (ttl != table(code)) {
                    violations += "a text of c$sender to c$peer stored with TTL $ttl; the timer the users set " +
                        "(code $code) gives ${table(code)}"
                }
            }
            changeByMessage[ref]?.let { change ->
                timerSets++
                if (change.queued) queuedTimerSets++
                val want = maxOf(table(change.oldCode), table(change.newCode))
                if (ttl != want) {
                    violations += "a TIMER_SET from code ${change.oldCode} to ${change.newCode} stored with TTL $ttl, " +
                        "R-T3 says the larger bucket, $want"
                }
            }
        }
        return JoinResult(
            "JD5", n, violations,
            "distinct stores against the §10.1 table: $texts user texts against the timer the users set, " +
                "$timerSets TIMER_SETs against R-T3's larger bucket (${timerSets - queuedTimerSets} set over a " +
                "session, $queuedTimerSets queued for EST-READY's flush: that path is NI-DM2's declared open " +
                "defect and a FAILED item's retry is run by no world, §22.21); the deadline half cannot fail in a " +
                "world without outages",
        )
    }

    // ------------------------------------------------------------------ JD6

    /**
     * JD6 (§15.6): "every store maps to an `oracle_user_action`, a scheduled action, a bundle
     * publication or an identical resend". The oracle is the one message each user action was for
     * ([PrivacyWorld.userAction]: the text a send created with the typed text, the TIMER_SET of a
     * timer change — never anything else the call created); the mapping is the sender's own
     * `dm_outbound_op` row, **bounded**: a user message may reach the relays under one ciphertext
     * only (no store fails in this world, so a second ciphertext is a re-encryption or a copy no user
     * asked for).
     */
    fun jd6(): JoinResult {
        val violations = ArrayList<String>()
        val classes = LinkedHashMap<String, Int>()
        val seenOps = HashSet<GroundTruth.Key>()
        val seenHashes = HashSet<GroundTruth.Key>()
        val ciphertexts = HashMap<Pair<Int, String>, MutableSet<GroundTruth.Key>>()
        for (e in events) {
            if (e.op != ViewOp.STORE) continue
            val cause = e.cause!!
            if (!seenOps.add(GroundTruth.Key(cause.operationId))) continue
            val hash = GroundTruth.Key(e.blobHash!!)
            val ref = cause.messageRef?.let(::hex)
            val kind = when {
                !seenHashes.add(hash) -> "identical resend"
                cause.purpose == "bundle" -> "bundle publication"
                cause.purpose == "item" && cause.control != null -> {
                    violations += "c${e.client}: a ${cause.control} control no user action scheduled"
                    "control"
                }
                cause.purpose == "item" && ref != null && ref in world.clients[e.client].userMessages -> "user action"
                else -> {
                    violations += "c${e.client}: a store at ${e.second} maps to no user action " +
                        "(purpose ${cause.purpose}, message ${ref?.take(8)})"
                    "unmapped"
                }
            }
            if (kind == "user action" || kind == "identical resend") {
                ref?.let { ciphertexts.getOrPut(e.client to it) { HashSet() } += hash }
            }
            classes.merge(kind, 1, Int::plus)
        }
        for ((key, hashes) in ciphertexts) {
            if (hashes.size > 1) {
                violations += "c${key.first}: a user message ${key.second.take(8)} reached the relays under " +
                    "${hashes.size} ciphertexts"
            }
        }
        val unexplained = world.clients.sumOf { it.unexplained.size }
        return JoinResult(
            "JD6", seenOps.size.toLong(), violations,
            "ops by cause $classes; ${ciphertexts.size} user messages, each under one ciphertext; " +
                "$unexplained messages a user action created beyond what it was for",
        )
    }

    // ------------------------------------------------------------------ JD7

    /**
     * JD7 (§15.6): "every list or get is on own namespaces, except one bundle fetch per
     * establishment, reset or reconnect (≤ 3 attempts, list events only inside attempt windows)".
     *
     * **The establishments are the world's, not the reader's.** One is every user send (or timer
     * change) to a peer the sender holds no session with, by what the crypto port saw
     * ([PrivacyWorld.establishments]); this world has no reset, key change or restore. Each gives the
     * reader at most three attempt windows (§21.7), as the production triggers open and close them
     * (§22.36): the first opens at the send, each later one at a **relay session start** of the reader
     * at least six hours after the previous one closed (`Due.START` waits for one, phase review MD-2;
     * the world's record of them, [PrivacyWorld.sessionStarts]); a window lasts 15 minutes and closes
     * at its end, which the alarm and the actor timer both carry (the fetch deadline is a row term), so
     * a read after it is outside it whatever relay round comes next. Every read of a card's bundle
     * namespace must fall inside one; every read of any other namespace that is not the reader's own
     * fails. Nothing here reads the reader's `dm_contact` row (its state is printed only to explain a
     * failure).
     */
    fun jd7(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        var bundleReads = 0
        val bundleOwner = world.truth.clients.values.mapNotNull { t -> t.bundleNamespace?.let { hex(it) to t.index } }.toMap()
        val establishments = world.establishments.groupBy { it.reader to it.owner }
            .mapValues { (_, list) -> list.sortedBy { it.at } }
        val windows = HashMap<Pair<Int, Int>, Windows>()
        for (e in events) {
            if (e.op != ViewOp.LIST && e.op != ViewOp.GET) continue
            n++
            val ns = hex(e.namespace)
            if (ns in world.ownNamespaces(e.client)) continue
            val owner = bundleOwner[ns]
            if (owner == null) {
                violations += "c${e.client} ${e.op} on ${ns.take(12)} at ${e.second}, not its own and not an open " +
                    "bundle fetch (no card's bundle namespace)"
                continue
            }
            bundleReads++
            val state = windows.getOrPut(e.client to owner) {
                Windows(establishments[e.client to owner].orEmpty(), world.sessionStarts[e.client] ?: java.util.TreeSet())
            }
            if (!state.accept(e.second)) {
                violations += "c${e.client} ${e.op} on c$owner's bundle namespace at ${e.second}, not its own and not " +
                    "an open bundle fetch (outside every attempt window of its " +
                    "${establishments[e.client to owner].orEmpty().size} establishments; reader's row, for " +
                    "diagnosis only: ${e.readerState})"
            }
        }
        val opened = windows.values.sumOf { it.total }
        val most = windows.values.maxOfOrNull { it.most } ?: 0
        lastJd7Exhausted = windows.values.sumOf { it.exhausted }
        lastJd7Binding = windows.values.sumOf { it.binding() }
        return JoinResult(
            "JD7", n, violations,
            "reads, $bundleReads of them bundle reads inside $opened attempt windows of " +
                "${world.establishments.size} establishments (at most $most windows for one)",
        )
    }

    /** How many establishments the last [jd7] saw open their third attempt window. */
    private var lastJd7Exhausted = 0

    /** How many of those the last [jd7] saw followed by a session where a fourth attempt would fall. */
    private var lastJd7Binding = 0

    /**
     * **JD7's WITHHOLD_ALL_BUNDLES variant** (§21.7 point 6: "a JD7 variant requires ≤ 3 attempts
     * and `P_c` list events only inside attempt windows"; PM-31's detector). The world is run with
     * [PrivacyWorldConfig.withholdAllBundles], so no establishment ever gets a candidate and the
     * attempt bound is the only thing that ends one; the check is [jd7]'s own, unchanged — every
     * read of a card's bundle namespace inside one of **at most three** windows of an establishment
     * the world recorded.
     *
     * **What makes it able to fail** — the one requirement that decides whether the bound was put
     * to the test: at least one establishment whose reads fell in all three windows **and** after
     * whose third window the reader had a relay session start at which an engine with no bound makes
     * a fourth attempt — at least six hours after the third window closed, before the pair's next
     * establishment (a new send with no session, which starts a new count) and before the world
     * ended ([Windows.binding]). Only there does a fourth attempt have somewhere to fall that no
     * window covers; an establishment that reached its third window in the world's last six hours,
     * or whose peer was written to again within six hours, bounds nothing.
     *
     * Two further requirements guard **the harness**, not the engine, and say so: the relay model
     * answered at least one bundle list empty over a live bundle (a world in which nobody had
     * published would withhold nothing), and no GET of a card's bundle namespace happened (the
     * model's mode skips every such namespace before any GET, so this can fail only if the model's
     * own bookkeeping and the recorder's disagree).
     */
    fun jd7Withheld(): JoinResult {
        val base = jd7()
        val violations = ArrayList(base.violations)
        val bundleOwner = world.truth.clients.values.mapNotNull { t -> t.bundleNamespace?.let { hex(it) } }.toSet()
        val bundleGets = events.count {
            it.op == ViewOp.GET && hex(it.namespace) in bundleOwner && hex(it.namespace) !in world.ownNamespaces(it.client)
        }
        val withheld = world.relay.bundleListsWithheld
        val exhausted = lastJd7Exhausted
        val binding = lastJd7Binding
        if (!world.config.withholdAllBundles) violations += "the variant ran on a world without WITHHOLD_ALL_BUNDLES"
        if (withheld == 0) violations += "the relay model withheld no live bundle from a list: nothing was published to withhold"
        if (bundleGets > 0) violations += "$bundleGets GETs of a card's bundle namespace: the relay model leaked a bundle"
        if (binding == 0) {
            violations += "no establishment reached its third attempt window with a later session where a fourth " +
                "attempt would fall ($exhausted reached the third): the bound was never put to the test"
        }
        return JoinResult(
            "JD7 WITHHOLD_ALL_BUNDLES", base.scanned, violations,
            "${base.detail}; $exhausted establishments reached their third attempt window, $binding of them " +
                "followed by a relay session of the reader at least 6 h after it closed and before the pair's next " +
                "establishment (where an unbounded engine makes a fourth attempt); harness guards: $withheld bundle " +
                "lists answered empty over a live bundle, $bundleGets bundle GETs",
        )
    }

    /**
     * The attempt windows of one (reader, bundle owner) pair, opened as its reads arrive: JD7's
     * oracle of §21.7 points 2 and 5 under the production triggers (§22.36): at most
     * [MAX_ATTEMPTS] windows of [WINDOW] each; the first at the establishment, each later one at a
     * relay session **start** of the reader ([starts]) at least [NEXT_ATTEMPT] after the previous
     * one closed — `Due.START` waits for a session start, and the session-start pass runs before the
     * session's read lane, so the first read of a later window is in the second its session started;
     * each window closes at its end, the fetch deadline the alarm and the actor timer both wake for
     * (`EST-END`, or `EST-READY` earlier). [establishments] are the pair's, sorted by time.
     *
     * The first version, written for a world in which every foreground minute started a relay session
     * (the design's cadence), let a later window open at any relay round and close at the first round
     * at or after its end; with the production triggers a round is no session start and the window's
     * end is a wake of its own, so that reading would have accepted a read up to a round past the end
     * and refused a later attempt that production makes six hours after the actual close.
     */
    internal class Windows(private val establishments: List<PrivacyWorld.Establishment>, private val starts: java.util.TreeSet<Long>) {
        private var current: PrivacyWorld.Establishment? = null
        private var attempts = 0
        private var until = Long.MIN_VALUE
        var total = 0
            private set
        var most = 0
            private set

        /** Establishments whose reads opened their [MAX_ATTEMPTS]th window (the bound was reached). */
        var exhausted = 0
            private set

        /** Each exhausted establishment with the end of its last window. */
        private val lastClosed = ArrayList<Pair<PrivacyWorld.Establishment, Long>>()

        /**
         * The exhausted establishments after which a fourth attempt had somewhere to fall: a relay
         * session start of the reader at least [NEXT_ATTEMPT] after the third window closed, earlier
         * than the pair's next establishment (which restarts the count). There, an engine with no bound
         * opens a fourth window and reads the bundle namespace in that session, and no window covers it.
         */
        fun binding(): Int = lastClosed.count { (establishment, closed) ->
            val next = establishments.firstOrNull { it.at > establishment.at }?.at ?: Long.MAX_VALUE
            val session = starts.ceiling(closed + NEXT_ATTEMPT) ?: return@count false
            session < next
        }

        fun accept(t: Long): Boolean {
            val establishment = establishments.lastOrNull { it.at <= t } ?: return false
            if (establishment !== current) {
                current = establishment
                attempts = 0
                until = Long.MIN_VALUE
            }
            while (true) {
                if (attempts > 0 && t <= until) return true
                if (attempts >= MAX_ATTEMPTS) return false
                // `EST-START` runs at the send for the first attempt, and for a later one at the
                // session-start pass of the reader's relay session that this read belongs to.
                val start = if (attempts == 0) establishment.at else starts.floor(t) ?: return false
                if (attempts > 0 && start < until + NEXT_ATTEMPT) return false
                until = ceilMinute(start + WINDOW)
                attempts++
                total++
                most = maxOf(most, attempts)
                if (attempts == MAX_ATTEMPTS) {
                    exhausted++
                    lastClosed += establishment to until
                }
            }
        }

        companion object {
            /** §21.7 point 5: at most three attempts per establishment. */
            const val MAX_ATTEMPTS = 3

            /** §21.7 point 2: a 15-minute attempt window. */
            const val WINDOW = 15 * DmWorld.MINUTE

            /** §21.7 point 5: the next attempt at least six hours after a window closed. */
            const val NEXT_ATTEMPT = 6 * DmWorld.HOUR

            fun ceilMinute(t: Long): Long = Math.floorDiv(t + DmWorld.MINUTE - 1, DmWorld.MINUTE) * DmWorld.MINUTE
        }
    }

    // ------------------------------------------------------------------ JD9

    /**
     * JD9 (§15.6): "every DM namespace's relay set equals `set(ns, w)` or the declared 6-week union".
     * `set(ns, w)` is computed here from §5.2's text over the world's ES table (four slots, two
     * operators, one slot table for the whole world), not by `RelaySets`. Every event is checked —
     * stores, lists, gets and **registrations**, whose `keys.redb` records are part of the view (§4.7).
     */
    fun jd9(): JoinResult {
        val violations = ArrayList<String>()
        var n = 0L
        val sets = HashMap<String, Set<Int>>()
        for (e in events) {
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
        return JoinResult("JD9", n, violations, "relay events (registrations included) over ${sets.size} namespaces")
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
         * `CredentialV3`, `RelaySets`), each also with the parameters its derivations append. A
         * label **not** here is not in JD1's dictionary: JD3's "every store into a card's namespace"
         * and JD7's "every read on an own or an establishing bundle namespace" are what catch a
         * namespace derived under a label nobody listed.
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
         * JD1's dictionary over every client of [world]: its Ed25519 key, `ghost1` hash, `ghost1`
         * string and Olm identity key, each raw, SHA-256'd and under every labelled SHA-256 and HKDF
         * of [LABELS]; the three keys' base64 forms; and the safety numbers of its accepted edges,
         * raw and SHA-256'd. Each entry's owner is the client whose material it is — S-DM3's
         * attacker names that owner.
         */
        fun identityDictionary(world: PrivacyWorld): ByteDictionary {
            val dictionary = ByteDictionary()
            val labelNames = LABELS.map { String(it, Charsets.ISO_8859_1) }
            for (t in world.truth.clients.values.sortedBy { it.index }) {
                val pk = t.identityPk ?: continue
                val oi = t.olmIdentity ?: continue
                val identity = GhostIdentity.fromPublicKey(pk)
                val ghost1 = identity.encode().toByteArray(Charsets.US_ASCII)
                val base = linkedMapOf(
                    "Ed25519 key" to pk,
                    "ghost1 hash" to identity.publicKeyHash,
                    "Olm identity key" to oi,
                    "ghost1 string" to ghost1,
                )
                for ((name, value) in base) {
                    // Forms: 0 raw, 1 SHA-256, 2 + 2i SHA-256(label_i ‖ ·), 3 + 2i HKDF(·, label_i).
                    val family = dictionary.family(t.index) { form ->
                        "c${t.index} " + when {
                            form == 0 -> name
                            form == 1 -> "SHA-256($name)"
                            form % 2 == 0 -> "SHA-256(${labelNames[(form - 2) / 2]}‖$name)"
                            else -> "HKDF($name, ${labelNames[(form - 3) / 2]})"
                        }
                    }
                    dictionary.add(family, 0, value)
                    dictionary.add(family, 1, sha256(value))
                    for ((i, label) in LABELS.withIndex()) {
                        dictionary.add(family, 2 + 2 * i, sha256(label + value))
                        dictionary.add(family, 3 + 2 * i, hkdf(value, label))
                    }
                    if (name != "ghost1 string") {
                        for (encoded in encodings(value)) dictionary.add("c${t.index} $name (base64)", encoded, t.index)
                    }
                }
            }
            for ((u, v) in world.acceptedEdges) {
                val a = world.truth.clients[u] ?: continue
                val b = world.truth.clients[v] ?: continue
                for ((own, peer) in listOf(a to b, b to a)) {
                    val number = world.clients[own.index].device.crypto.safetyNumber(
                        own.identityPk!!, own.olmIdentity!!, peer.identityPk!!, peer.olmIdentity!!,
                    ) ?: continue
                    dictionary.add("c${own.index} safety number with c${peer.index} (scannable)", number.scannable, own.index)
                    dictionary.add(
                        "c${own.index} safety number with c${peer.index} (digits)",
                        number.digits.toByteArray(Charsets.US_ASCII), own.index,
                    )
                    dictionary.add("c${own.index} SHA-256(safety number with c${peer.index})", sha256(number.scannable), own.index)
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
