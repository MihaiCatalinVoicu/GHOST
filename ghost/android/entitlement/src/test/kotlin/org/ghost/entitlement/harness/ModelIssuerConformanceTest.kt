package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.network.EntitlementCrypto
import org.ghost.network.TorIssuerTransport
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Replays `protocol/test-vectors/issuer_semantics.txt` against [ModelIssuer] (Phase 8 design §13.2
 * "Conformance models"). The real issuer replays the same file (`issuer/crates/service/tests/
 * semantics_vectors.rs`), so the issuer the `:entitlement` harness relies on cannot drift from the
 * real one. The client side of every line is the harness's `TestTokenCrypto` (seed-derived blinded
 * requests, finalization with every signature verified); every line must pass and every operation
 * of the grammar must occur. The file is a declared Gradle test input.
 */
class ModelIssuerConformanceTest {

    private class Line(
        val no: Int,
        val op: String,
        val names: List<String>,
        val args: Map<String, String>,
        val expect: String?,
        val fields: Map<String, String>,
    )

    private fun parse(no: Int, raw: String): Line? {
        val text = raw.substringBefore('#').trim()
        if (text.isEmpty()) return null
        val left = if ("->" in text) text.substringBefore("->").trim() else text
        val right = if ("->" in text) text.substringAfter("->").trim() else null
        val words = left.split(Regex("\\s+"))
        val names = ArrayList<String>()
        val args = LinkedHashMap<String, String>()
        for (w in words.drop(1)) {
            val i = w.indexOf('=')
            if (i > 0) args[w.substring(0, i)] = w.substring(i + 1) else names += w
        }
        var expect: String? = null
        val fields = LinkedHashMap<String, String>()
        if (right != null) {
            val ws = right.split(Regex("\\s+"))
            expect = ws[0]
            for (f in ws.drop(1)) {
                val i = f.indexOf('=')
                check(i > 0) { "key=value field expected: $f" }
                fields[f.substring(0, i)] = f.substring(i + 1)
            }
        }
        return Line(no, words[0], names, args, expect, fields)
    }

    private class Invoice(val id: ByteArray, val baseWeek: Long, val xmr: Boolean)

    private class Section {
        val issuer = ModelIssuer(SCHEDULE)
        var now = BASE
        val invoices = HashMap<String, Invoice>()
        val credits = HashMap<String, List<ByteArray>>()
        val tokens = HashMap<String, ByteArray>()
        val answers = HashMap<String, ByteArray>()

        init {
            issuer.tick(now)
        }

        fun sameAnswer(key: String, bytes: ByteArray) {
            val previous = answers.putIfAbsent(key, bytes.copyOf())
            if (previous != null) assertArrayEquals("not byte-identical", previous, bytes)
        }
    }

    private fun claimKey(name: String) = Bytes.sha256(Bytes.ascii("vector-claim/$name"))

    private fun seed(name: String) = Bytes.sha256(Bytes.ascii("vector-seed/$name"))

    private fun payoutId(name: String) = Bytes.sha256(Bytes.ascii("vector-payout/$name")).copyOf(16)

    private fun week(line: Line): Long = BASE_WEEK + line.args.getValue("week").toLong()

    private fun amount(spec: String): Long = when (spec) {
        "price" -> PRICE
        "half" -> PRICE / 2
        else -> spec.toLong()
    }

    private fun address(spec: String): String = when (spec) {
        "valid" -> HarnessAddresses.standard("valid")
        "other" -> HarnessAddresses.standard("other")
        "checksum" -> HarnessAddresses.badChecksum(HarnessAddresses.standard("valid"))
        "stagenet" -> HarnessAddresses.otherNetwork("stagenet")
        else -> error("unknown address $spec")
    }

    private fun creditSet(s: Section, spec: String): List<ByteArray> {
        val parts = spec.split('/')
        val all = s.credits[parts[0]] ?: error("unknown credits ${parts[0]}")
        return if (parts.size == 3) all.subList(parts[1].toInt(), parts[2].toInt()) else all
    }

    /** A failure reply must be the expected category; returns the value of a success. */
    private fun <T> value(reply: ModelIssuer.Reply<T>, expect: String): T? = when (reply) {
        is ModelIssuer.Reply.Err -> {
            assertEquals("category", expect, reply.category)
            null
        }
        is ModelIssuer.Reply.Ok -> reply.value
    }

    private fun amounts(line: Line, credited: Long, seen: Long) {
        line.fields["credited"]?.let { assertEquals("credited", it.toLong(), credited) }
        line.fields["seen"]?.let { assertEquals("seen", it.toLong(), seen) }
    }

    private fun stateWord(state: Int): String = when (state) {
        TorIssuerTransport.STATE_SIGNED -> "signed"
        TorIssuerTransport.STATE_AWAITING_PAYMENT -> "awaiting_payment"
        TorIssuerTransport.STATE_AWAITING_CONFIRMATIONS -> "awaiting_confirmations"
        TorIssuerTransport.STATE_UNDERPAID -> "underpaid"
        TorIssuerTransport.STATE_EXPIRED -> "expired"
        TorIssuerTransport.STATE_OTHER_REQUEST_ISSUED -> "other_request_issued"
        else -> "unspecified"
    }

    private fun run(s: Section, l: Line) {
        when (l.op) {
            "at" -> {
                val t = BASE + l.names[0].toLong()
                check(t >= s.now) { "the clock never moves back in a section" }
                s.now = t
            }
            "week" -> s.now = Grid.start(BASE_WEEK + l.names[0].toLong()) + 43_200
            "tick" -> s.issuer.tick(s.now)
            "mine" -> {
                s.issuer.mine(l.names[0].toLong())
                s.issuer.tick(s.now)
            }
            "synced" -> s.issuer.synced = l.names[0] == "yes"
            "pay" -> {
                val inv = s.invoices[l.names[0]] ?: error("unknown invoice")
                s.issuer.pay(s.issuer.minorOf(inv.id), amount(l.names[1]))
            }
            "credits" -> {
                val name = l.names[0]
                val epoch = l.args.getValue("epoch").toLong()
                s.credits[name] = List(l.args.getValue("count").toInt()) { i -> SCHEDULE.mint(EntitlementCrypto.KIND_CREDIT, epoch, "vector-credit/$name/$i") }
            }
            "invite" -> s.tokens[l.names[0]] = SCHEDULE.mint(EntitlementCrypto.KIND_INVITE, l.args.getValue("epoch").toLong(), "vector-invite/${l.names[0]}")
            "token" -> {
                val bytes = (s.tokens[l.args.getValue("from")] ?: error("unknown token")).copyOf()
                val i = l.args.getValue("flip").toInt()
                bytes[i] = (bytes[i].toInt() xor 1).toByte()
                s.tokens[l.names[0]] = bytes
            }
            "request" -> request(s, l)
            "sign" -> sign(s, l)
            "status" -> {
                val expect = checkNotNull(l.expect)
                val inv = s.invoices[l.names[0]] ?: error("unknown invoice")
                value(s.issuer.invoiceStatus(inv.id, claimKey(l.args.getValue("claim"))), expect)?.let {
                    assertEquals(expect, stateWord(it.state))
                    amounts(l, it.credited, it.seen)
                }
            }
            "redeem" -> redeem(s, l)
            "payout" -> payout(s, l)
            else -> error("unknown operation ${l.op}")
        }
    }

    private fun request(s: Section, l: Line) {
        val expect = checkNotNull(l.expect)
        val credits = l.args["credits"]?.let { creditSet(s, it) } ?: emptyList()
        val base = week(l)
        val r = value(s.issuer.requestInvoice(Batch.claimHash(claimKey(l.names[0])), credits, base, s.now), expect) ?: return
        val word = when (r.result) {
            TorIssuerTransport.INVOICE_OK -> "ok"
            TorIssuerTransport.INVOICE_WRONG_PERIOD -> "wrong_period"
            TorIssuerTransport.INVOICE_CREDITS_SPENT -> "credits_spent"
            TorIssuerTransport.INVOICE_CLAIM_CONFLICT -> "claim_conflict"
            else -> "unspecified"
        }
        assertEquals(expect, word)
        when (word) {
            "ok" -> {
                assertEquals("amount", amount(l.fields.getValue("amount")), r.amount)
                assertEquals("a subaddress iff an amount", r.amount != 0L, r.subaddress != null)
                val name = l.fields.getValue("invoice")
                val known = s.invoices[name]
                if (known != null) assertArrayEquals("another invoice", known.id, r.invoiceId()) else s.invoices[name] = Invoice(r.invoiceId(), base, credits.isEmpty())
            }
            "credits_spent" -> assertEquals("mask", l.fields.getValue("mask").toLong(16), r.spentMask)
        }
    }

    private fun sign(s: Section, l: Line) {
        val expect = checkNotNull(l.expect)
        val inv = s.invoices[l.names[0]] ?: error("unknown invoice")
        val product = if (inv.xmr) EntitlementCrypto.PRODUCT_PACK_XMR else EntitlementCrypto.PRODUCT_PACK_CREDITS
        val positions = checkNotNull(SCHEDULE.positions(product, inv.baseWeek))
        val sd = seed(l.args.getValue("seed"))
        val blinded = Batch.blind(SCHEDULE, sd, positions)
        if (l.args["block"] == "zero") blinded.fill(0, 0, 256)
        val r = value(s.issuer.blindSign(inv.id, claimKey(l.args.getValue("claim")), blinded, s.now), expect) ?: return
        assertEquals(expect, stateWord(r.state))
        amounts(l, r.credited, r.seen)
        if (expect == "signed") {
            val tokens = checkNotNull(Batch.finalize(SCHEDULE, sd, positions, r.signatures)) { "the signatures do not finalize" }
            assertEquals(positions.size, tokens.size)
            s.sameAnswer("sign/${l.names[0]}/${l.args.getValue("seed")}", r.signatures)
        } else {
            assertEquals("no signatures", 0, r.signatures.size)
        }
    }

    private fun redeem(s: Section, l: Line) {
        val expect = checkNotNull(l.expect)
        val base = week(l)
        val positions = checkNotNull(SCHEDULE.positions(EntitlementCrypto.PRODUCT_TRIAL, base))
        val sd = seed(l.args.getValue("seed"))
        val token = s.tokens[l.names[0]] ?: error("unknown token")
        val r = value(s.issuer.redeemInvite(token, base, Batch.blind(SCHEDULE, sd, positions), s.now), expect) ?: return
        val word = when (r.result) {
            TorIssuerTransport.TRIAL_OK -> "ok"
            TorIssuerTransport.TRIAL_REPLAYED -> "replayed"
            TorIssuerTransport.TRIAL_WRONG_PERIOD -> "wrong_period"
            else -> "unspecified"
        }
        assertEquals(expect, word)
        if (word == "ok") {
            checkNotNull(Batch.finalize(SCHEDULE, sd, positions, r.signatures)) { "the trial signatures do not finalize" }
            s.sameAnswer("redeem/${l.names[0]}/${l.args.getValue("seed")}/$base", r.signatures)
        }
    }

    private fun payout(s: Section, l: Line) {
        val expect = checkNotNull(l.expect)
        val r = value(s.issuer.claimPayout(payoutId(l.names[0]), creditSet(s, l.args.getValue("credits")), address(l.args.getValue("address")), s.now), expect) ?: return
        val word = when (r.result) {
            TorIssuerTransport.CLAIM_QUEUED -> "queued"
            TorIssuerTransport.CLAIM_CREDITS_SPENT -> "credits_spent"
            TorIssuerTransport.CLAIM_CONFLICT -> "claim_conflict"
            TorIssuerTransport.CLAIM_ADDRESS_REJECTED -> "address_rejected"
            else -> "unspecified"
        }
        assertEquals(expect, word)
        when (word) {
            "queued" -> assertEquals("amount", l.fields.getValue("amount").toLong(), r.queued)
            "credits_spent" -> assertEquals("mask", l.fields.getValue("mask").toLong(16), r.spentMask)
        }
    }

    @Test
    fun theModelIssuerMatchesTheSharedSemanticsVectors() {
        val file = File(VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        var section: Section? = null
        var sections = 0
        var outcomes = 0
        val seen = sortedSetOf<String>()
        file.readLines().forEachIndexed { index, raw ->
            val line = parse(index + 1, raw) ?: return@forEachIndexed
            seen += line.op
            if (line.op == "issuer") {
                section = Section()
                sections++
                return@forEachIndexed
            }
            if (line.expect != null) outcomes++
            val s = section ?: error("line ${line.no}: an operation before any section")
            try {
                run(s, line)
            } catch (e: Throwable) {
                throw AssertionError("issuer_semantics.txt:${line.no}: `${raw.trim()}`: ${e.message}", e)
            }
        }
        assertEquals(6, sections)
        assertTrue("only $outcomes outcomes replayed", outcomes >= 60)
        assertEquals(
            sortedSetOf("issuer", "at", "week", "tick", "mine", "synced", "pay", "credits", "invite", "token", "request", "sign", "status", "redeem", "payout"),
            seen,
        )
    }

    companion object {
        /** Test working directory is the module directory (ghost/android/entitlement). */
        const val VECTORS = "../../protocol/test-vectors/issuer_semantics.txt"

        /** Monday of access week 2960, 12:00 UTC (invite epoch 740, credit epoch 227). */
        const val BASE = 1_790_596_800L
        const val BASE_WEEK = 2960L
        const val PRICE = 200_000_000_000L

        /** The committed test schedule with access_per_slot = 1 and trial_per_slot = 1 (the vector file's world). */
        internal val SCHEDULE: TestSchedule by lazy { TestSchedule(1, 1, TestSchedule.committedSlots()) }
    }
}
