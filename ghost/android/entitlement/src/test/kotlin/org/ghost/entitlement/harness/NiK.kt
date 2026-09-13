package org.ghost.entitlement.harness

import org.ghost.entitlement.api.PayWith
import org.ghost.sync.harness.JournalMode
import org.ghost.sync.harness.RunSpec
import org.ghost.sync.harness.Runner
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs
import org.ghost.sync.harness.violation

/** When the user of an NI-K world pays its invoice (the chain timing NI-1 varies). */
internal enum class NiPay {
    /** At the first check once the invoice is there. */
    PROMPT,

    /** At the first check after the first `BlindSign` attempt left (which so answers AWAITING_PAYMENT). */
    AFTER_FIRST_ATTEMPT,

    /** One check (30 minutes) later than [AFTER_FIRST_ATTEMPT]. */
    AFTER_FIRST_ATTEMPT_LATER,
}

/**
 * One world of an NI-K comparison: the payment timing, the issuer's randomness and answer times
 * ([issuerVaried]: another invoice-id seed and pool minors, answers after 0.7–30 s), one issuer call
 * answered UNAVAILABLE ([unavailableCall], by index), and more relay activity ([busy]: one more
 * namespace, more writes, more inbound blobs).
 */
internal class NiVariant(
    val label: String,
    val pay: NiPay,
    val issuerVaried: Boolean = false,
    val unavailableCall: Int? = null,
    val busy: Boolean = false,
) {
    override fun toString(): String = label
}

/** What an NI-K world leaves for the comparisons. */
internal class NiViews(
    /** Every relay-facing call of the subject in time order: its relay-port calls and its redemptions with every request byte (time, line). */
    val relay: List<Pair<Long, String>>,
    /** Every issuer call as the issuer sees it: time, operation, flow, request size. */
    val issuer: List<String>,
    /** The first UTC-day boundary at or after the first pack finalization + 4 h, virtual ms (none: MAX). */
    val activationMillis: Long,
    /** The distinct `eligible_minute`s the subject stored tokens with. */
    val eligible: List<Long>,
    /** The relays' final state (blob stores, ledgers, nullifier stores). */
    val relayState: List<String>,
    /** The issuer's final state (invoices, pool, spent credits): what NI-1 varies. */
    val issuerState: String,
)

/**
 * The NI-K world (Phase 8 design §13.4 NI-K, §19.14): the real `EntitlementEngine` with the
 * production `QuietRunScheduler` over the Phase 7 sync harness, `TestTokenCrypto`, the model issuer
 * and the model redeem relays. A genesis client on Friday of week 2975 holds four tokens per slot of
 * weeks 2975 and 2976, listens to one namespace on A and B and writes to four more (A C, B C, A B,
 * A C); it buys an XMR pack at once and pays it by the variant's timing; periodic jobs every 15
 * minutes for 96 hours, the user's foreground windows and writes at fixed times, other writers'
 * blobs. Scripted times fall 7 minutes after a job, never inside a quiet run (whose issuer answer
 * takes up to 30 s), so the variants' timelines differ only where the engine lets them.
 */
internal class NiWorld(private val seed: Long, private val v: NiVariant, m: EntMutant?) : EntScenario("NI-K seed $seed") {
    var views: NiViews? = null
        private set
    private val paid = HashSet<String>()
    private val deferred = HashSet<String>()

    init {
        mutant = m
    }

    private val namespaces: Int get() = if (v.busy) BASE_NAMESPACES + 1 else BASE_NAMESPACES

    override fun config(): EntConfig {
        val unavailable: (Int) -> Boolean = { i -> i == v.unavailableCall }
        val base = if (v.issuerVaried) {
            EntConfig(issuerSeed = 1, firstMinor = 9, issuerLatencyMillis = { i -> 700L + keyed("latency", i) % 29_300L }, issuerUnavailable = unavailable)
        } else {
            EntConfig(issuerUnavailable = unavailable)
        }
        return configured(base, namespaces)
    }

    private fun keyed(label: String, i: Int): Long = java.nio.ByteBuffer.wrap(Bytes.sha256(Bytes.ascii("ni-k|$seed|$label|$i"))).long ushr 1

    override fun build(w: World) {
        val e = standard(w)
        accessTokens(WEEK0, SETUP_PER_SLOT)
        accessTokens(WEEK0 + 1, SETUP_PER_SLOT)
        val (a, b, c) = Triple(w.relays[0], w.relays[1], w.relays[2])
        // A and C share an operator: every namespace spans two operators (B and one of them, or all three).
        val inbox = e.c.namespace("inbox", listOf(a, b), listen = true)
        val dm = listOf(listOf(b, c), listOf(a, b, c), listOf(a, b), listOf(b, c)).mapIndexed { i, set -> e.c.namespace("dm${i + 1}", set, listen = false) }
        w.purchase(0, PayWith.XMR, emptyList())
        w.jobs(e.c, MINUTE, END)
        var t = PAY_FIRST
        while (t <= END) {
            w.at(t, "pay check") { payCheck() }
            t += PAY_EVERY
        }
        for (start in WINDOWS) w.foreground(e.c, start, start + 15 * MINUTE)
        val writes = listOf(dm[0], dm[1], dm[2], dm[3], dm[0], dm[1])
        writes.forEachIndexed { i, ns -> w.at(WINDOWS[i] + 3 * MINUTE, "enqueue w$i") { e.c.enqueue("w$i", ns) } }
        val inbound = listOf(3 * HOUR to a, 20 * HOUR to b, 50 * HOUR to a, 80 * HOUR to b)
        inbound.forEachIndexed { i, (at, node) -> w.at(at + 8 * MINUTE, "inbound i$i") { w.otherWrite(node, inbox, "i$i") } }
        if (v.busy) {
            val busy = e.c.namespace("busy", listOf(a, b, c), listen = false)
            w.at(12 * HOUR + 8 * MINUTE, "enqueue b0") { e.c.enqueue("b0", inbox) }
            val extra = listOf(busy, dm[0], busy, dm[2], busy)
            extra.forEachIndexed { i, ns -> w.at(WINDOWS[i + 1] + 6 * MINUTE, "enqueue b${i + 1}") { e.c.enqueue("b${i + 1}", ns) } }
            val more = listOf(5 * HOUR to a, 30 * HOUR to b, 60 * HOUR to a, 70 * HOUR to b, 85 * HOUR to a)
            more.forEachIndexed { i, (at, node) -> w.at(at + 8 * MINUTE, "inbound j$i") { w.otherWrite(node, inbox, "j$i") } }
        }
        w.endMillis = END
    }

    /** The user pays an invoice once, by the variant's timing (the model issuer confirms it at once). */
    private fun payCheck() {
        val rows = ArrayList<Pair<String, Long>>()
        alice.c.jdbc.query("SELECT purchase_id, attempt FROM ent_purchase WHERE kind = 'pack' AND pay_with = 'xmr' AND state = 'invoiced'") {
            rows += Bytes.hex(it.blob(0)) to it.long(1)
        }
        for ((id, attempt) in rows) {
            if (id in paid) continue
            if (v.pay != NiPay.PROMPT && attempt < 1) continue
            if (v.pay == NiPay.AFTER_FIRST_ATTEMPT_LATER && deferred.add(id)) continue
            paid += id
            alice.payInvoiced()
        }
    }

    override fun finalChecks(w: World) {
        super.finalChecks(w)
        val start = w.clock.startEpochSeconds
        val finalized = ent.records.finalizedAt.firstOrNull()
        val activation = if (finalized == null) {
            Long.MAX_VALUE
        } else {
            val boundary = -Math.floorDiv(-(finalized + ACTIVATION_DELAY_SECONDS), DAY_SECONDS) * DAY_SECONDS
            (boundary - start) * 1_000
        }
        val calls = alice.c.port.calls.map { call ->
            val hashes = call.hashes.joinToString(",") { h -> Bytes.hex(h.toByteArray()) }
            call.startMillis to "call|${call.startMillis}|${call.kind}|${call.relay}|${Bytes.hex(call.namespace.toByteArray())}|${call.limit}|$hashes|${call.result}"
        }
        val redeems = ent.records.relayLog.map { line -> line.substringAfter("t=").substringBefore('|').toLong() to line }
        val state = w.relays.map { r -> "${r.name} ${r.model.digest()} ${ent.redeemRelay(r)?.disk?.digest() ?: "-"}" }
        views = NiViews(
            (calls + redeems).sortedWith(compareBy({ it.first }, { it.second })), ent.records.issuerLog.toList(), activation,
            ent.records.eligible.toList(), state, ent.issuer.digest(),
        )
    }

    companion object {
        /** inbox and dm1…dm4. */
        const val BASE_NAMESPACES = 5
        const val END = 96 * HOUR

        /** Setup tokens per slot of weeks 2975 and 2976: B serves six pairs in the busy world. */
        private const val SETUP_PER_SLOT = 6
        private const val PAY_FIRST = 8 * MINUTE
        private const val PAY_EVERY = 30 * MINUTE
        private const val ACTIVATION_DELAY_SECONDS = 4 * 3_600L
        private const val DAY_SECONDS = 86_400L

        /** The user's foreground windows (15 minutes each), 4 minutes after a job. */
        private val WINDOWS = listOf(10 * HOUR + 5 * MINUTE, 14 * HOUR + 35 * MINUTE, 26 * HOUR + 5 * MINUTE, 38 * HOUR + 5 * MINUTE, 66 * HOUR + 5 * MINUTE, 90 * HOUR + 5 * MINUTE)
    }
}

/**
 * The NI-K comparisons (Phase 8 design §13.4): NI-1 — the subject's relay-facing calls (time, relay,
 * namespace, bytes) are identical when the issuer's answers vary; NI-2 — its issuer calls (time,
 * flow, sizes) are identical when its namespaces and relay activity vary. NI-1 compares whole runs
 * when both worlds' tokens activate alike (the variation stayed within one L-cell), and otherwise
 * everything before the earlier activation start: before it no pack token is usable, so nothing the
 * issuer did may show at a relay.
 */
internal object NiK {
    val BASE = NiVariant("base", NiPay.AFTER_FIRST_ATTEMPT)
    val SAME_CELL = NiVariant("issuer varied, first BlindSign unavailable, paid later", NiPay.AFTER_FIRST_ATTEMPT_LATER, issuerVaried = true, unavailableCall = 1)
    val PROMPT = NiVariant("prompt payment", NiPay.PROMPT)
    val PROMPT_VARIED = NiVariant("prompt payment, issuer varied, first RequestInvoice unavailable", NiPay.PROMPT, issuerVaried = true, unavailableCall = 0)
    val BUSY = NiVariant("busy", NiPay.AFTER_FIRST_ATTEMPT, busy = true)

    /** A comparison needs this many relay-facing calls (a prefix before a Saturday activation holds 15 to 50). */
    private const val MIN_RELAY_ENTRIES = 10

    fun views(seed: Long, v: NiVariant, mutant: EntMutant?): NiViews {
        val s = NiWorld(seed, v, mutant)
        Runner(s, JournalMode.WAL, seed).run(RunSpec())
        return checkNotNull(s.views) { "the NI-K world left no views" }
    }

    /** NI-1 between [a] and [b]; returns a line for the report. */
    fun ni1(seed: Long, a: NiVariant, b: NiVariant, mutant: EntMutant? = null): String {
        val va = views(seed, a, mutant)
        val vb = views(seed, b, mutant)
        if (va.issuerState == vb.issuerState) violation("NI-1 world (seed $seed): the issuer variation changed nothing at the issuer")
        val full = va.eligible == vb.eligible
        val cutoff = if (full) Long.MAX_VALUE else minOf(va.activationMillis, vb.activationMillis)
        val ra = va.relay.filter { it.first < cutoff }.map { it.second }
        val rb = vb.relay.filter { it.first < cutoff }.map { it.second }
        if (ra.size < MIN_RELAY_ENTRIES) violation("NI-1 world (seed $seed): too few relay-facing calls to compare (${ra.size})")
        compare("NI-1", "relay view", ra, rb, a, b, seed)
        if (full && va.relayState != vb.relayState) violation("NI-1: the relays' state differs between '$a' and '$b' (seed $seed)")
        return "seed $seed ${if (full) "whole run" else "before ${cutoff / HOUR} h"}: ${ra.size} relay calls"
    }

    /** NI-2 between [a] and [b]; returns a line for the report. */
    fun ni2(seed: Long, a: NiVariant, b: NiVariant, mutant: EntMutant? = null): String {
        val va = views(seed, a, mutant)
        val vb = views(seed, b, mutant)
        if (va.relay.map { it.second } == vb.relay.map { it.second }) violation("NI-2 world (seed $seed): the activity variation changed nothing at the relays")
        if (va.issuer.size < 2) violation("NI-2 world (seed $seed): too few issuer calls to compare (${va.issuer.size})")
        compare("NI-2", "issuer view", va.issuer, vb.issuer, a, b, seed)
        return "seed $seed: ${va.issuer.size} issuer calls"
    }

    private fun compare(label: String, what: String, x: List<String>, y: List<String>, a: NiVariant, b: NiVariant, seed: Long) {
        if (x == y) return
        val i = x.indices.firstOrNull { it >= y.size || x[it] != y[it] } ?: x.size
        violation("$label: the $what differs between '$a' and '$b' (seed $seed, ${x.size} vs ${y.size} entries, first difference at $i: ${x.getOrNull(i)} / ${y.getOrNull(i)})")
    }
}
