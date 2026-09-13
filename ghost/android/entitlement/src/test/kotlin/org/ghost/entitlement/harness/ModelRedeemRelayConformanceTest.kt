package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.network.EntitlementCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.RSAPublicKeySpec

/**
 * Replays `protocol/test-vectors/redeem.txt` against [ModelRedeemRelay] (Phase 8 design §10.8,
 * §13.2 "Conformance models"). The real relay replays the same file (`relay/crates/node/tests/
 * redeem_vectors.rs`), so the redeem relay the `:entitlement` harness relies on cannot drift from
 * the real one. Every pinned token is checked to be what its line declares (nonce, challenge, key
 * id, a signature that verifies under the declared signer), every minted capability is recomputed
 * here from the documented formulas, and every operation and expectation of the grammar must occur.
 */
class ModelRedeemRelayConformanceTest {

    private class Section(
        val key: ByteArray,
        val schedule: TestSchedule?,
        val slot: Int,
        val onionLabel: String,
        var now: Long,
    ) {
        val disk = ModelRedeemRelay.Disk()
        var relay: ModelRedeemRelay? = null
        val caps = HashMap<String, ByteArray>()

        fun open(mode: ModelRedeemRelay.Mode): ModelRedeemRelay =
            ModelRedeemRelay.open(schedule, slot, TestSchedule.onion(onionLabel), { key }, disk, mode, now)

        fun relay(): ModelRedeemRelay = relay ?: error("no running relay in this section")
    }

    private val base: TestSchedule by lazy { TestSchedule(16, 8, TestSchedule.committedSlots()) }

    private fun args(words: List<String>): Map<String, String> =
        words.mapNotNull { w -> w.indexOf('=').takeIf { it > 0 }?.let { w.substring(0, it) to w.substring(it + 1) } }.toMap()

    /** `<week>+<s>` or `<week>-<s>`. */
    private fun at(spec: String): Long {
        val i = spec.indexOfFirst { it == '+' || it == '-' }
        val start = Grid.start(spec.substring(0, i).toLong())
        val s = spec.substring(i + 1).toLong()
        return if (spec[i] == '+') start + s else start - s
    }

    private fun namespace(name: String) = Bytes.sha256(Bytes.ascii(name))

    private fun request(name: String) = Bytes.sha256(Bytes.ascii("ghost/test/request/$name")).copyOf(16)

    private fun kind(name: String): Int = when (name) {
        "access" -> EntitlementCrypto.KIND_ACCESS
        "invite" -> EntitlementCrypto.KIND_INVITE
        "credit" -> EntitlementCrypto.KIND_CREDIT
        else -> error("unknown kind $name")
    }

    /** A pinned token is what its line declares, and its signature verifies under the declared signer. */
    private fun checkPinned(name: String, a: Map<String, String>, t: ByteArray) {
        assertEquals("token $name: length", TestSchedule.TOKEN_BYTES, t.size)
        assertArrayEquals("token $name: nonce", Bytes.sha256(Bytes.ascii("ghost/test/redeem-nonce/$name")), t.copyOfRange(2, 34))
        val digest = base.challengeDigest(kind(a.getValue("kind")), a.getValue("epoch").toLong(), a["slot"]?.toInt())
        assertArrayEquals("token $name: challenge", digest, t.copyOfRange(34, 66))
        val signer = a.getValue("signer")
        val publicKey = if (signer.startsWith("spki:")) {
            val spki = Bytes.unhex(signer.removePrefix("spki:"))
            assertArrayEquals("token $name: key id", Bytes.sha256(spki), t.copyOfRange(66, 98))
            assertNull("an spki signer is outside the schedule", base.keyById(t.copyOfRange(66, 98)))
            val n = checkNotNull(RsaKey.modulusOf(spki)) { "token $name: unexpected SPKI layout" }
            KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, BigInteger.valueOf(65_537)))
        } else {
            val (k, epoch) = signer.split(':')
            val key = checkNotNull(base.key(kind(k), epoch.toLong()))
            assertArrayEquals("token $name: key id", key.keyId, t.copyOfRange(66, 98))
            key.publicKey
        }
        assertTrue("token $name: signature", Pss.verify(publicKey, t.copyOfRange(0, 98), t.copyOfRange(98, 354)))
    }

    /** The capability the documented formulas give (an HMAC path independent of the model's). */
    private fun expectedCapability(key: ByteArray, token: ByteArray, ns: ByteArray): ByteArray {
        val p = checkNotNull(base.keyById(token.copyOfRange(66, 98))).epoch
        val n = TestSchedule.nullifier(token)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256").apply { init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256")) }
        val serial = mac.doFinal(Bytes.ascii("ghost/v1/cap-serial") + Bytes.u64(p) + n).copyOf(16)
        val expiry = 345_600L + 604_800L * (p + 1) + 3_600L
        val body = byteArrayOf(2, 2) + ns + Bytes.u64(268_435_456L) + Bytes.u64(expiry) + serial
        return body + mac.doFinal(body)
    }

    private val tokens = HashMap<String, ByteArray>()
    private var pinned = 0
    private val expectations = sortedSetOf<String>()
    private var section: Section? = null

    private fun runLine(words: List<String>, expect: List<String>?): String {
        val op = words[0]
        val a = args(words.drop(1))
        when (op) {
            "relay" -> {
                val schedule = when (a["schedule"]) {
                    "none" -> null
                    null -> a["revoke"]?.let { list ->
                        TestSchedule(16, 8, TestSchedule.committedSlots(), revoked = list.split(',').map { EntitlementCrypto.KIND_ACCESS to it.toLong() }.toSet(), seq = 2)
                    } ?: base
                    else -> error("unknown schedule=${a["schedule"]}")
                }
                val mode = when (a["nullifiers"] ?: "create") {
                    "create" -> ModelRedeemRelay.Mode.CREATE
                    "reset" -> ModelRedeemRelay.Mode.RESET
                    "existing" -> ModelRedeemRelay.Mode.EXISTING
                    else -> error("unknown nullifiers=${a["nullifiers"]}")
                }
                val s = Section(a["key"]?.let(Bytes::unhex) ?: ByteArray(32) { 0x42 }, schedule, a["slot"]?.toInt() ?: 0, a["onion"] ?: RELAY_A, at(a.getValue("start")))
                section = s
                val opened = try {
                    s.open(mode)
                } catch (e: ModelRedeemRelay.Refused) {
                    null
                }
                when (expect) {
                    null -> s.relay = checkNotNull(opened) { "the relay refused to start" }
                    listOf("refused") -> {
                        assertNull("the relay started; expected a refusal", opened)
                        expectations += "refused"
                    }
                    else -> error("unknown relay expectation $expect")
                }
            }
            "restart" -> {
                val s = checkNotNull(section)
                val mode = when (a["nullifiers"] ?: "existing") {
                    "existing" -> ModelRedeemRelay.Mode.EXISTING
                    "reset" -> ModelRedeemRelay.Mode.RESET
                    else -> error("unknown nullifiers=${a["nullifiers"]}")
                }
                s.relay = s.open(mode)
            }
            "at" -> checkNotNull(section).now = at(words[1])
            "token" -> {
                val name = words[1]
                if ("hex" in a) {
                    val t = Bytes.unhex(a.getValue("hex"))
                    checkPinned(name, a, t)
                    pinned++
                    check(tokens.put(name, t) == null) { "token $name twice" }
                } else {
                    val t = (tokens[a.getValue("from")] ?: error("unknown token ${a["from"]}")).copyOf()
                    val derived = if ("xor" in a) {
                        val i = a.getValue("xor").toInt()
                        t[i] = (t[i].toInt() xor (a["mask"]?.toInt(16) ?: 1)).toByte()
                        t
                    } else {
                        t.copyOf(a.getValue("len").toInt())
                    }
                    check(tokens.put(name, derived) == null) { "token $name twice" }
                }
            }
            "redeem" -> redeem(a, checkNotNull(expect))
            "capability" -> {
                val s = checkNotNull(section)
                val actual = Bytes.hex(s.caps[words[1]] ?: error("unbound ${words[1]}"))
                assertEquals("capability ${words[1]} pin", a.getValue("hex"), actual)
            }
            "distinct" -> {
                val s = checkNotNull(section)
                val names = words[1].split(',')
                val caps = names.map { Bytes.hex(s.caps[it] ?: error("unbound $it")) }.toSet()
                assertEquals("capabilities $names are not distinct", names.size, caps.size)
            }
            "sweep" -> {
                val s = checkNotNull(section)
                val e = checkNotNull(expect)
                val beforeHigh = s.disk.sweepHighWater
                val beforeClosed = s.disk.closedThrough
                val beforeRows = s.disk.rows.toMap()
                val report = s.relay().sweep(s.now)
                if (e == listOf("skipped")) {
                    assertNull("the sweep ran", report)
                    assertTrue(beforeHigh != null && Math.floorDiv(s.now, 60L) < beforeHigh)
                    assertEquals(beforeClosed, s.disk.closedThrough)
                    assertEquals(beforeRows, s.disk.rows.toMap())
                    expectations += "skipped"
                } else {
                    assertEquals("ok", e[0])
                    val f = args(e.drop(1))
                    assertNotNull("the sweep was skipped", report)
                    val closed = f.getValue("closed").let { if (it == "none") null else it.toLong() }
                    assertEquals("closed-through period", closed, checkNotNull(report).closedThrough)
                    assertEquals(closed, s.disk.closedThrough)
                    assertEquals(Math.floorDiv(s.now, 60L), s.disk.sweepHighWater)
                    assertEquals("removed", f.getValue("removed").toInt(), report.removed)
                }
            }
            "nullifiers" -> assertEquals("nullifier rows", checkNotNull(expect)[0].toInt(), checkNotNull(section).relay().count())
            else -> error("unknown operation $op")
        }
        return op
    }

    private fun redeem(a: Map<String, String>, expect: List<String>) {
        val s = checkNotNull(section)
        val token = tokens[a.getValue("token")] ?: error("unknown token ${a["token"]}")
        val ns = namespace(a.getValue("ns"))
        val answer = s.relay().redeem(token, ns, request(a.getValue("req")), s.now)
        assertEquals("relay_period_id", Grid.week(s.now), answer.relayPeriod)
        assertEquals("relay_minute", Math.floorDiv(s.now, 60L), answer.relayMinute)
        val want = expect[0]
        expectations += want
        when (val r = answer.result) {
            is ModelRedeemRelay.Result.Ok -> {
                assertEquals("expected $want, got ok", "ok", want)
                assertArrayEquals("capability bytes", expectedCapability(s.key, token, ns), r.capability)
                val name = args(expect.drop(1)).getValue("cap")
                val bound = s.caps.putIfAbsent(name, r.capability)
                if (bound != null) assertArrayEquals("capability $name changed", bound, r.capability)
            }
            ModelRedeemRelay.Result.Replayed -> assertEquals("replayed", want)
            ModelRedeemRelay.Result.WrongPeriod -> assertEquals("wrong_period", want)
            is ModelRedeemRelay.Result.Denied -> assertEquals(want, r.status)
        }
    }

    @Test
    fun theModelRedeemRelayMatchesTheSharedRedeemVectors() {
        val file = File(VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        val seen = sortedSetOf<String>()
        var sections = 0
        file.readLines().forEachIndexed { index, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            val (opPart, expectPart) = if ("->" in line) Pair(line.substringBefore("->"), line.substringAfter("->")) else Pair(line, null)
            val words = opPart.trim().split(Regex("\\s+"))
            val expect = expectPart?.trim()?.split(Regex("\\s+"))
            val op = try {
                runLine(words, expect)
            } catch (e: Throwable) {
                throw AssertionError("redeem.txt:${index + 1}: `${line.take(120)}`: ${e.message}", e)
            }
            if (op == "relay") sections++
            seen += op
        }
        assertEquals("the vector file lost a pinned token", 15, pinned)
        assertEquals(sortedSetOf("relay", "restart", "at", "token", "redeem", "capability", "distinct", "sweep", "nullifiers"), seen)
        assertEquals(
            sortedSetOf("ok", "replayed", "wrong_period", "rejected_token", "rejected_size", "unavailable", "unimplemented", "refused", "skipped"),
            expectations,
        )
        assertTrue("the vector file lost a section", sections >= 12)
    }

    companion object {
        /** Test working directory is the module directory (ghost/android/entitlement). */
        const val VECTORS = "../../protocol/test-vectors/redeem.txt"
        const val RELAY_A = "ghost/test/relay-a"
    }
}
