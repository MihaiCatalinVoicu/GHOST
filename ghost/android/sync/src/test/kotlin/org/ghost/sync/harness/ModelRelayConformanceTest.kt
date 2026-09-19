package org.ghost.sync.harness

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Replays `protocol/test-vectors/relay_semantics.txt` and `protocol/test-vectors/register.txt`
 * against [ModelRelay] (design §8.7, Phase 9 design §4.7). The Rust relay replays the same files
 * (`relay/crates/node/tests/semantics_vectors.rs`, `.../register_vectors.rs`), so the model the
 * exit-gate harness relies on cannot drift from the real relay. The files are declared Gradle test
 * inputs; every line must pass, and every operation of each grammar must occur.
 */
class ModelRelayConformanceTest {

    private class Section(maxTtl: Long) {
        val relay = ModelRelay("vectors", ByteArray(32) { (it * 11 + 5).toByte() }, maxTtl)
        var now = BASE
        val tokens = HashMap<String, ByteArray>()
        val blobs = HashMap<String, ByteArray>()
        val cursors = HashMap<String, ByteArray>()

        fun token(name: String): ByteArray = tokens[name] ?: error("unknown capability $name")
        fun blob(name: String): ByteArray = blobs[name] ?: error("unknown blob $name")
        fun hashOf(name: String): BlobHash = ModelRelay.sha256(blob(name))
        fun nameOf(hash: BlobHash): String =
            blobs.filter { ModelRelay.sha256(it.value) == hash }.keys.minOrNull() ?: "<undeclared>"
        fun relative(unix: Long): String = (unix - BASE).toString()
    }

    private fun namespace(name: String): NamespaceId =
        NamespaceId(MessageDigest.getInstance("SHA-256").digest(name.toByteArray(Charsets.US_ASCII)))

    private fun blobBytes(name: String, size: Int): ByteArray {
        val ascii = name.toByteArray(Charsets.US_ASCII)
        check(ascii.size <= size) { "blob $name longer than its size" }
        return ascii.copyOf(size)
    }

    private fun args(words: List<String>): Map<String, String> =
        words.mapNotNull { w -> w.indexOf('=').takeIf { it > 0 }?.let { w.substring(0, it) to w.substring(it + 1) } }.toMap()

    private fun names(list: String): List<String> = if (list == "none") emptyList() else list.split(',')

    /** Checks an outcome against `ok ...` or a category; returns the ok fields, or null for a matching failure. */
    private fun <T> outcome(got: ModelRelay.Reply<T>, expect: List<String>): Pair<T, Map<String, String>>? {
        val want = expect.firstOrNull() ?: error("empty expectation")
        return when (got) {
            is ModelRelay.Reply.Ok -> {
                check(want == "ok") { "expected $want, the call succeeded" }
                Pair(got.value, args(expect.drop(1)))
            }
            is ModelRelay.Reply.Err -> {
                check(want != "ok") { "expected ok, got ${got.category}" }
                check(expect.size == 1) { "a failure expectation is one category" }
                assertEquals("category", want, got.category)
                null
            }
        }
    }

    private fun hexDecode(s: String): ByteArray =
        if (s == "empty") ByteArray(0) else ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun runLine(state: Array<Section?>, words: List<String>, expect: List<String>?): String {
        val op = words[0]
        val a = args(words.drop(1))
        if (op == "relay") {
            state[0] = Section(a.getValue("max_ttl").toLong())
            return op
        }
        val s = state[0] ?: error("a `relay` line must come first")
        when (op) {
            "at" -> {
                val t = BASE + words[1].toLong()
                check(t >= s.now) { "the clock never moves back" }
                s.now = t
            }
            "blob" -> check(s.blobs.put(words[1], blobBytes(words[1], a.getValue("size").toInt())) == null) { "blob declared twice" }
            "cap" -> {
                val kind = when (a.getValue("kind")) {
                    "read" -> ModelRelay.KIND_READ
                    "write" -> ModelRelay.KIND_WRITE
                    else -> error("unknown kind")
                }
                val token = s.relay.mint(kind, namespace(a.getValue("ns")), a.getValue("quota").toLong(), BASE + a.getValue("expiry").toLong())
                check(s.tokens.values.none { it.contentEquals(token) }) { "two capabilities with identical fields" }
                check(s.tokens.put(words[1], token) == null)
            }
            "token" -> {
                val token = a["hex"]?.let(::hexDecode) ?: s.token(a.getValue("from")).copyOf().also {
                    val i = a.getValue("xor").toInt()
                    it[i] = (it[i].toInt() xor 1).toByte()
                }
                check(s.tokens.put(words[1], token) == null)
            }
            "store" -> {
                val got = s.relay.store(namespace(a.getValue("ns")), s.blob(a.getValue("blob")), s.token(a.getValue("cap")), a.getValue("ttl").toLong(), s.now)
                outcome(got, expect!!)?.let { (receipt, fields) ->
                    assertEquals("stored hash", s.hashOf(a.getValue("blob")), receipt.hash)
                    assertEquals("store expiry", fields.getValue("expiry"), s.relative(receipt.expiry))
                }
            }
            "get" -> {
                val blob = a.getValue("blob")
                outcome(s.relay.get(s.hashOf(blob), s.token(a.getValue("cap")), s.now), expect!!)?.let { (served, fields) ->
                    assertTrue("get returns the stored bytes", served.data.contentEquals(s.blob(blob)))
                    assertEquals("get expiry", fields.getValue("expiry"), s.relative(served.expiry))
                }
            }
            "check" -> {
                val asked = names(a.getValue("blobs"))
                outcome(s.relay.check(asked.map { s.hashOf(it) }, s.token(a.getValue("cap")), s.now), expect!!)?.let { (held, fields) ->
                    assertEquals("available", names(fields.getValue("available")), held.map { s.nameOf(it) })
                }
            }
            "list" -> {
                val cursor = when (val k = a.getValue("cursor")) {
                    "start" -> ByteArray(0)
                    else -> s.cursors[k] ?: error("unknown cursor $k")
                }
                val got = s.relay.list(namespace(a.getValue("ns")), s.token(a.getValue("cap")), cursor, a.getValue("limit").toInt(), s.now)
                outcome(got, expect!!)?.let { (page, fields) ->
                    assertEquals("listed hashes", names(fields.getValue("hashes")), page.hashes.map { s.nameOf(it) })
                    when (val next = fields.getValue("next")) {
                        "end" -> assertTrue("expected an empty cursor", page.next.isEmpty())
                        else -> {
                            assertEquals("expected an 8-byte cursor", 8, page.next.size)
                            check(s.cursors.put(next, page.next) == null) { "cursor $next bound twice" }
                        }
                    }
                }
            }
            "fill" -> {
                check(expect == listOf("ok")) { "fill expects ok" }
                val prefix = a.getValue("prefix")
                for (i in 0 until a.getValue("count").toInt()) {
                    val name = "$prefix$i"
                    check(s.blobs.put(name, blobBytes(name, a.getValue("size").toInt())) == null)
                    val got = s.relay.store(namespace(a.getValue("ns")), s.blob(name), s.token(a.getValue("cap")), a.getValue("ttl").toLong(), s.now)
                    check(got is ModelRelay.Reply.Ok) { "fill store $name failed: $got" }
                }
            }
            "prune" -> {
                val removed = s.relay.prune(s.now)
                val fields = outcome(ModelRelay.Reply.Ok(removed), expect!!)!!.second
                assertEquals("memberships removed", fields.getValue("removed"), removed.toString())
            }
            else -> error("unknown operation $op")
        }
        return op
    }

    @Test
    fun theModelRelayMatchesTheSharedSemanticsVectors() {
        val file = File(VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        val state = arrayOfNulls<Section>(1)
        val seen = sortedSetOf<String>()
        var sections = 0
        var lines = 0
        file.readLines().forEachIndexed { index, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            val (opPart, expectPart) = if ("->" in line) Pair(line.substringBefore("->"), line.substringAfter("->")) else Pair(line, null)
            val words = opPart.trim().split(Regex("\\s+"))
            val expect = expectPart?.trim()?.split(Regex("\\s+"))
            val op = try {
                runLine(state, words, expect)
            } catch (e: Throwable) {
                throw AssertionError("relay_semantics.txt:${index + 1}: `$line`: ${e.message}", e)
            }
            if (op == "relay") sections++
            seen += op
            lines++
        }
        assertEquals(sortedSetOf("relay", "at", "blob", "cap", "token", "store", "get", "check", "list", "fill", "prune"), seen)
        assertTrue("the vector file lost a section", sections >= 9)
        assertTrue(lines > 150)
    }

    // ------------------------------------------------------------------ register.txt (Phase 9)

    /** One `relay` section of `register.txt`: a model relay with its slot, clock and symbols. */
    private class KeySection(val slot: Int?, var now: Long) {
        val relay = ModelRelay("register", RELAY_KEY).also { it.slot = slot }
        val tokens = HashMap<String, ByteArray>()
        val credentials = HashMap<String, ModelRelay.Credential>()
        val blobs = HashMap<String, ByteArray>()

        fun token(name: String): ByteArray = tokens[name] ?: error("unknown token $name")
        fun credential(name: String): ModelRelay.Credential = credentials[name] ?: error("unknown credential $name")
        fun blob(name: String): ByteArray = blobs[name] ?: error("unknown blob $name")
        fun hashOf(name: String): BlobHash = ModelRelay.sha256(blob(name))
        fun nameOf(hash: BlobHash): String =
            blobs.filter { ModelRelay.sha256(it.value) == hash }.keys.minOrNull() ?: "<undeclared>"

        /** A restart keeps registrations and blobs; the in-memory ledgers start empty. */
        fun restart() = relay.restart()

        /** `keys.redb` lost: no registration survives (design §4.6). */
        fun loseKeys() = relay.loseKeys()
    }

    /** `<week>+<s>` or `<week>-<s>`: `start(week) ± s` (as in redeem.txt). */
    private fun at(spec: String): Long {
        val plus = spec.lastIndexOf('+')
        val minus = spec.lastIndexOf('-')
        val cut = maxOf(plus, minus)
        check(cut > 0) { "not a time: $spec" }
        val week = spec.substring(0, cut).toLong()
        val offset = spec.substring(cut + 1).toLong()
        return ModelRelay.weekStart(week) + if (cut == plus) offset else -offset
    }

    private fun sha256(text: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.US_ASCII))

    private fun hmac(key: ByteArray, body: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(body)

    private fun kindOf(name: String): Int = when (name) {
        "read" -> ModelRelay.KIND_READ
        "deposit" -> ModelRelay.KIND_DEPOSIT
        "fetch" -> ModelRelay.KIND_FETCH
        else -> error("unknown kind $name")
    }

    /** A `KeyKind` wire value: a kind name, `none` (unspecified) or a raw number. */
    private fun keyKindValue(name: String): Int = when (name) {
        "none" -> 0
        "read", "deposit", "fetch" -> kindOf(name)
        else -> name.toInt()
    }

    private fun capabilityOf(s: KeySection, words: List<String>, a: Map<String, String>): ByteArray {
        val namespace = namespace(a.getValue("ns"))
        val body = when (words[2]) {
            "v2" -> {
                val quota = a["quota"]?.toLong() ?: 268_435_456L
                val serial = sha256("ghost/test/serial/${a.getValue("serial")}").copyOfRange(0, 16)
                ByteBuffer.allocate(ModelRelay.BODY_V2_BYTES)
                    .put(ModelRelay.VERSION_2).put(ModelRelay.KIND_WRITE.toByte()).put(namespace.toByteArray())
                    .putLong(quota).putLong(ModelRelay.weekStart(a.getValue("week").toLong() + 1) + 3_600)
                    .put(serial).array()
            }
            "v1" -> ByteBuffer.allocate(ModelRelay.BODY_BYTES)
                .put(ModelRelay.VERSION).put(kindName(a.getValue("kind")).toByte()).put(namespace.toByteArray())
                .putLong(a.getValue("quota").toLong()).putLong(at(a.getValue("expiry"))).array()
            else -> error("unknown capability layout ${words[2]}")
        }
        check(s.relay.key().contentEquals(RELAY_KEY)) { "the section relay key changed" }
        return body + hmac(RELAY_KEY, body)
    }

    private fun kindName(name: String): Int = when (name) {
        "read" -> ModelRelay.KIND_READ
        "write" -> ModelRelay.KIND_WRITE
        else -> error("unknown capability kind $name")
    }

    /** Checks a register outcome against its expectation. */
    private fun registerOutcome(got: ModelRelay.Reply<ModelRelay.RegisterAnswer>, expect: List<String>, now: Long) {
        when (val want = expect[0]) {
            "ok", "wrong_period" -> {
                check(got is ModelRelay.Reply.Ok) { "expected $want, got $got" }
                val answer = got.value
                assertEquals("relay period", ModelRelay.week(now), answer.relayPeriodId)
                assertEquals("relay minute", now / 60, answer.relayMinute)
                if (want == "ok") {
                    assertEquals("register result", ModelRelay.RESULT_OK, answer.result)
                    assertEquals("valid until", at(args(expect.drop(1)).getValue("valid_until")), answer.validUntil)
                } else {
                    assertEquals("register result", ModelRelay.RESULT_WRONG_PERIOD, answer.result)
                    assertEquals("wrong_period carries no validity", 0L, answer.validUntil)
                }
            }
            "rejected_capability" -> assertEquals("category", "unauthorized", (got as ModelRelay.Reply.Err).category)
            "rejected_size" -> assertEquals("category", "rejected", (got as ModelRelay.Reply.Err).category)
            else -> error("unknown expectation $want")
        }
    }

    private fun runKeyLine(state: Array<KeySection?>, words: List<String>, expect: List<String>?, seen: MutableSet<String>): String {
        val op = words[0]
        val a = args(words.drop(1))
        if (op == "relay") {
            val slot = a.getValue("slot").let { if (it == "none") null else it.toInt() }
            state[0] = KeySection(slot, at(a.getValue("start")))
            return op
        }
        val s = state[0] ?: error("a `relay` line must come first")
        /** The outcome of a blob operation against its expectation; null for a matching failure. */
        fun <T> outcome(got: ModelRelay.Reply<T>, want: List<String>): Pair<T, Map<String, String>>? {
            seen += "$op:${want[0]}"
            val category = when (want[0]) {
                "ok" -> null
                "unauthorized", "quota", "not_found" -> want[0]
                "rejected_ttl" -> "rejected"
                else -> error("unknown expectation ${want[0]}")
            }
            return when (got) {
                is ModelRelay.Reply.Ok -> {
                    check(category == null) { "expected ${want[0]}, the call succeeded" }
                    Pair(got.value, args(want.drop(1)))
                }
                is ModelRelay.Reply.Err -> {
                    check(category != null) { "expected ok, got ${got.category}" }
                    assertEquals("category", category, got.category)
                    null
                }
            }
        }
        when (op) {
            "restart" -> s.restart()
            "lose-keys" -> s.loseKeys()
            "at" -> s.now = at(words[1])
            "blob" -> {
                val size = a.getValue("size").toInt()
                check(s.blobs.put(words[1], blobBytes(words[1], size)) == null) { "blob declared twice" }
            }
            "cap" -> check(s.tokens.put(words[1], capabilityOf(s, words, a)) == null) { "capability declared twice" }
            "credential" -> {
                val c = ModelRelay.Credential(
                    kindOf(a.getValue("kind")),
                    a.getValue("slot").toInt(),
                    namespace(a.getValue("ns")),
                    sha256("ghost/test/secret/${a.getValue("secret")}"),
                )
                check(s.tokens.put(words[1], ModelRelay.credentialBytes(c.kind, c.slot, c.namespace, c.secret)) == null)
                s.credentials[words[1]] = c
            }
            "token" -> {
                val from = s.token(a.getValue("from")).copyOf()
                val token = when {
                    a.containsKey("xor") -> from.also {
                        val i = a.getValue("xor").toInt()
                        val mask = (a["mask"] ?: "01").toInt(16)
                        it[i] = (it[i].toInt() xor mask).toByte()
                    }
                    else -> from.copyOf(a.getValue("len").toInt())
                }
                check(s.tokens.put(words[1], token) == null)
            }
            "register" -> {
                val cut = a["cut"]
                fun short(bytes: ByteArray, field: String): ByteArray =
                    if (cut == field) bytes.copyOf(bytes.size - 1) else bytes
                val got = s.relay.registerKey(
                    short(namespace(a.getValue("ns")).toByteArray(), "namespace"),
                    a.getValue("period").toLong(),
                    keyKindValue(a.getValue("kind")),
                    short(ModelRelay.verifierOf(s.credential(a.getValue("verifier"))), "verifier"),
                    a.getValue("cap").let { if (it == "none") null else s.token(it) },
                    short(sha256("ghost/test/request/${a.getValue("req")}").copyOfRange(0, 16), "request"),
                    s.now,
                    a["version"]?.toInt() ?: 1,
                )
                seen += "register:${expect!![0]}"
                registerOutcome(got, expect, s.now)
            }
            "store" -> {
                val got = s.relay.store(
                    namespace(a.getValue("ns")), s.blob(a.getValue("blob")), s.token(a.getValue("cred")),
                    a.getValue("ttl").toLong(), s.now,
                )
                outcome(got, expect!!)?.let { (receipt, fields) ->
                    assertEquals("stored hash", s.hashOf(a.getValue("blob")), receipt.hash)
                    assertEquals("store expiry", at(fields.getValue("expiry")), receipt.expiry)
                }
            }
            "get" -> {
                val blob = a.getValue("blob")
                outcome(s.relay.get(s.hashOf(blob), s.token(a.getValue("cred")), s.now), expect!!)?.let { (served, fields) ->
                    assertTrue("get returns the stored bytes", served.data.contentEquals(s.blob(blob)))
                    assertEquals("uploaded_at", at(fields.getValue("uploaded")), served.uploaded)
                    assertEquals("get expiry", at(fields.getValue("expiry")), served.expiry)
                }
            }
            "check" -> {
                val asked = names(a.getValue("blobs"))
                outcome(s.relay.check(asked.map { s.hashOf(it) }, s.token(a.getValue("cred")), s.now), expect!!)?.let { (held, fields) ->
                    assertEquals("available", names(fields.getValue("available")), held.map { s.nameOf(it) })
                }
            }
            "list" -> {
                val got = s.relay.list(namespace(a.getValue("ns")), s.token(a.getValue("cred")), ByteArray(0), 256, s.now)
                outcome(got, expect!!)?.let { (page, fields) ->
                    assertEquals("listed hashes", names(fields.getValue("hashes")), page.hashes.map { s.nameOf(it) })
                    assertTrue("a complete listing ends the cursor", page.next.isEmpty())
                }
            }
            "record" -> {
                val record = s.relay.record(
                    namespace(a.getValue("ns")), a.getValue("period").toLong(),
                    kindOf(a.getValue("kind")), ModelRelay.verifierOf(s.credential(a.getValue("verifier"))),
                )
                if (expect!! == listOf("none")) {
                    assertEquals("no record expected", null, record)
                } else {
                    val fields = args(expect)
                    val r = record ?: error("expected a record, found none")
                    assertEquals("record quota", fields.getValue("quota").toLong(), r.quotaBytes)
                    assertEquals("record serials", fields.getValue("serials").toInt(), r.serials.size)
                    assertEquals("record validity", at(fields.getValue("valid_until")), r.validUntil)
                }
            }
            "deposits" -> {
                val used = s.relay.depositsUsed(
                    namespace(a.getValue("ns")), a.getValue("period").toLong(),
                    ModelRelay.verifierOf(s.credential(a.getValue("verifier"))),
                )
                assertEquals("deposit ledger used bytes", args(expect!!).getValue("used").toLong(), used)
            }
            "ledger" -> assertEquals("deposit ledger entries", expect!![0].toInt(), s.relay.depositLedgerSize())
            "sweep" -> {
                val report = s.relay.sweep(s.now)
                seen += "sweep:${expect!![0]}"
                if (expect == listOf("skipped")) {
                    assertTrue("a skipped sweep runs no key sweep", !report.keySweepRan)
                    assertEquals("a skipped sweep removes no registration", 0, report.keyRecordsRemoved)
                    assertEquals("nor a serial", 0, report.keySerialsRemoved)
                } else {
                    assertTrue("the sweep ran", report.keySweepRan)
                    assertEquals("registrations removed", args(expect.drop(1)).getValue("removed").toInt(), report.keyRecordsRemoved)
                }
            }
            else -> error("unknown operation $op")
        }
        return op
    }

    @Test
    fun theModelRelayMatchesTheRegisterVectors() {
        val file = File(REGISTER_VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        val state = arrayOfNulls<KeySection>(1)
        val ops = sortedSetOf<String>()
        val seen = sortedSetOf<String>()
        var sections = 0
        var cases = 0
        file.readLines().forEachIndexed { index, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            val (opPart, expectPart) = if ("->" in line) Pair(line.substringBefore("->"), line.substringAfter("->")) else Pair(line, null)
            val words = opPart.trim().split(Regex("\\s+"))
            val expect = expectPart?.trim()?.split(Regex("\\s+"))
            val op = try {
                runKeyLine(state, words, expect, seen)
            } catch (e: Throwable) {
                throw AssertionError("register.txt:${index + 1}: `$line`: ${e.message}", e)
            }
            if (op == "relay") sections++
            if (expect != null) cases++
            ops += op
        }
        // Every operation and every expectation of the grammar is exercised, so a replayer that
        // skips one is noticed (the Rust replayer asserts the same sets).
        assertEquals(
            sortedSetOf(
                "relay", "restart", "lose-keys", "at", "blob", "cap", "credential", "token",
                "register", "store", "get", "check", "list", "record", "deposits", "ledger", "sweep",
            ),
            ops,
        )
        assertEquals(
            sortedSetOf(
                "register:ok", "register:wrong_period", "register:rejected_capability", "register:rejected_size",
                "store:ok", "store:unauthorized", "store:quota", "store:rejected_ttl",
                "get:ok", "get:unauthorized", "get:not_found",
                "check:ok", "check:unauthorized",
                "list:ok", "list:unauthorized",
                "sweep:ok", "sweep:skipped",
            ),
            seen,
        )
        assertTrue("the vector file lost a section", sections >= 5)
        assertTrue("the vector file lost cases ($cases)", cases >= 45)
    }

    companion object {
        const val BASE = 1_800_000_000L

        /** Test working directory is the module directory (ghost/android/sync). */
        const val VECTORS = "../../protocol/test-vectors/relay_semantics.txt"
        const val REGISTER_VECTORS = "../../protocol/test-vectors/register.txt"

        /** The relay key of every `register.txt` section. */
        val RELAY_KEY = ByteArray(32) { 0x42 }
    }
}
