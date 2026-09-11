package org.ghost.sync.harness

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Replays `protocol/test-vectors/relay_semantics.txt` against [ModelRelay] (design §8.7). The Rust
 * relay replays the same file (`relay/crates/node/tests/semantics_vectors.rs`), so the model the
 * exit-gate harness relies on cannot drift from the real relay. The file is a declared Gradle test
 * input; every line must pass, and every operation of the grammar must occur.
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
        assertTrue("the vector file lost a section", sections >= 8)
        assertTrue(lines > 150)
    }

    companion object {
        const val BASE = 1_800_000_000L

        /** Test working directory is the module directory (ghost/android/sync). */
        const val VECTORS = "../../protocol/test-vectors/relay_semantics.txt"
    }
}
