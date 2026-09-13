package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.ClockEstimate
import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.Pricing
import org.ghost.entitlement.engine.QuietRunWork
import org.ghost.entitlement.engine.RedeemPlanner
import org.ghost.entitlement.engine.RetryPolicy
import org.ghost.entitlement.engine.Slots
import org.ghost.entitlement.port.EntitlementRandom
import org.ghost.entitlement.store.SyncTables
import org.ghost.entitlement.store.TokenRow
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Replays `protocol/test-vectors/entitlement_policy.txt` against the real Kotlin engine (Phase 8
 * design §11.9, §13.4): redemption planning (the ±1 h guard, the slots a relay serves, the plan of a
 * need, the relay-facing clock), activation slots, the `BlindSign` attempt plan and the one retry of
 * capped calls, failure categories, quiet-run work selection and the credits of a credits-paid pack.
 * The Rust T2 reference policy (S10) replays the same file, so the reference cannot drift from the
 * engine on anything pinned here. Every line must pass and every operation must occur.
 */
class PolicyVectorsTest {

    /** Fixed draws: a PRF value and a queue of uniforms. */
    private class Draws(private val prfValue: Double, uniforms: List<Double>) : EntitlementRandom {
        val queue = ArrayDeque(uniforms)

        override fun bytes(size: Int): ByteArray = ByteArray(size)

        override fun uniform(): Double = queue.removeFirstOrNull() ?: error("a uniform too many")

        override fun prf(domain: Int, input: ByteArray): Double = prfValue
    }

    private val slots = ArrayList<EntitlementCrypto.Slot>()
    private var estimate = ClockEstimate()

    private fun summary(prices: Map<Long, Long> = TestSchedule.DEFAULT_PRICES): EntitlementCrypto.ScheduleSummary =
        TestSchedule(4, 2, slots.toList(), prices = prices).summary

    private fun time(spec: String): Long {
        val i = spec.indexOfFirst { it == '+' || it == '-' }
        val start = Grid.start(spec.substring(0, i).toLong())
        val s = spec.substring(i + 1).toLong()
        return if (spec[i] == '+') start + s else start - s
    }

    private fun optionalTime(spec: String): Long? = if (spec == "none") null else time(spec)

    private fun onion(spec: String) = TestSchedule.onion(spec.substringBeforeLast(':'), spec.substringAfterLast(':').toInt())

    private fun list(spec: String): String = spec

    private fun show(slots: List<Int>): String = if (slots.isEmpty()) "none" else slots.joinToString(",")

    private fun showTime(t: Long?): String {
        if (t == null) return "none"
        val week = Grid.week(t)
        val s = t - Grid.start(week)
        // The file's spelling: the nearer boundary (week+s up to half a week, next-week−s after).
        return if (s <= Grid.WEEK / 2) "$week+$s" else "${week + 1}-${Grid.start(week + 1) - t}"
    }

    private fun sameTime(expected: String, actual: Long?) {
        assertEquals(if (expected == "none") null else time(expected), actual)
    }

    private fun run(words: List<String>, expect: List<String>?): String {
        val op = words[0]
        val a = words.drop(1).mapNotNull { w -> w.indexOf('=').takeIf { it > 0 }?.let { w.substring(0, it) to w.substring(it + 1) } }.toMap()
        val e = expect?.firstOrNull()
        when (op) {
            "slot" -> slots += EntitlementCrypto.Slot(
                words[1].toInt(), a.getValue("from").toLong(), a.getValue("until").let { if (it == "open") 0L else it.toLong() }, onion(a.getValue("onion")),
            )
            "boundary" -> assertEquals(e == "yes", RedeemPlanner.nearBoundary(time(a.getValue("t"))))
            "slotsfor" -> assertEquals(e, show(RedeemPlanner.slotsFor(summary(), onion(a.getValue("relay")), a.getValue("week").toLong())))
            "plan" -> plan(a, checkNotNull(expect))
            "estimate" -> when (words[1]) {
                "reset" -> estimate = ClockEstimate()
                "record" -> estimate.record(
                    RelayId(a.getValue("relay").toLong()), a.getValue("relay_minute").toLong(), a.getValue("period").toLong(), time(a.getValue("local")),
                    a.getValue("wrong") == "yes",
                )
                "now" -> sameTime(checkNotNull(e), estimate.now(time(a.getValue("wall"))))
                "week" -> assertEquals(checkNotNull(e).toLong(), estimate.week(RelayId(a.getValue("relay").toLong()), time(a.getValue("wall"))))
                else -> error("unknown estimate ${words[1]}")
            }
            "eligible" -> {
                val uniforms = a.getValue("uniforms").let { if (it == "none") emptyList() else it.split(',').map(String::toDouble) }
                val draws = Draws(0.0, uniforms)
                val mode = if (a.getValue("mode") == "high") PrivacyMode.HIGH else PrivacyMode.STANDARD
                val t = time(a.getValue("finalized"))
                val got = if (a.getValue("batch") == "pack") Slots.packEligibleMinute(t, draws, mode) else Slots.trialEligibleMinute(t, draws, mode)
                sameTime(checkNotNull(e), got)
                assertTrue("every listed uniform is consumed", draws.queue.isEmpty())
            }
            "attempt" -> sameTime(checkNotNull(e), RetryPolicy.blindSignDueMinute(Bytes.unhex(a.getValue("seed")), time(a.getValue("receipt")), a.getValue("k").toInt()))
            "retry" -> {
                val u = a.getValue("uniform").toDouble()
                sameTime(checkNotNull(e), RetryPolicy.nextDueAfterSend(a.getValue("attempt").toInt(), optionalTime(a.getValue("current")), time(a.getValue("now"))) { u })
            }
            "classify" -> assertEquals(e, RetryPolicy.classify(words[1]).name.lowercase())
            "work" -> work(a, checkNotNull(e))
            "cover" -> cover(a, checkNotNull(e))
            else -> error("unknown operation $op")
        }
        return op
    }

    private fun plan(a: Map<String, String>, expect: List<String>) {
        val kind = if (a.getValue("kind") == "write") CapabilityKind.WRITE else CapabilityKind.READ
        val reason = CapabilityNeed.Reason.valueOf(a.getValue("reason").uppercase())
        val need = CapabilityNeed(RelayId(1), NamespaceId(ByteArray(32) { 7 }), kind, reason)
        val relay = SyncTables.Relay(RelayId(1), onion(a.getValue("relay")), ByteArray(16), true)
        val planner = RedeemPlanner(Draws(a.getValue("prf").toDouble(), emptyList()))
        val d = planner.plan(
            need, relay, summary(), time(a.getValue("now")), a.getValue("week").toLong(), a.getValue("trusted") == "yes", time(a.getValue("first")),
            optionalTime(a.getValue("write_expiry")),
        )
        val got = when (d) {
            is RedeemPlanner.Decision.Redeem -> "redeem week=${d.week} slots=${show(d.slots)} due=${showTime(d.dueSeconds)}"
            RedeemPlanner.Decision.Deferred -> "deferred"
            RedeemPlanner.Decision.NoSlot -> "no_slot"
            RedeemPlanner.Decision.Skip -> "skip"
        }
        if (expect[0] == "redeem") {
            val f = expect.drop(1).associate { it.substringBefore('=') to it.substringAfter('=') }
            val r = d as? RedeemPlanner.Decision.Redeem ?: error("expected a redemption, got $got")
            assertEquals("week", f.getValue("week").toLong(), r.week)
            assertEquals("slots", f.getValue("slots"), show(r.slots))
            assertEquals("due ($got)", time(f.getValue("due")), r.dueSeconds)
        } else {
            assertEquals(expect.joinToString(" "), got)
        }
    }

    private fun work(a: Map<String, String>, expect: String) {
        val now = time(a.getValue("now"))
        val id = ByteArray(16)
        val items = a.getValue("items").let { spec ->
            if (spec == "none") {
                emptyList()
            } else {
                spec.split(',').map { item ->
                    val due = time(item.substringAfter('@'))
                    when (item.substringBefore('@')) {
                        "request" -> QuietRunWork.Item.Request(id, due)
                        "sign" -> QuietRunWork.Item.Sign(id, due)
                        "refresh" -> QuietRunWork.Item.Refresh(id, due)
                        "revocation" -> QuietRunWork.Item.Revocation(id, due)
                        "claim" -> QuietRunWork.Item.Claim(id, due)
                        "renewal" -> QuietRunWork.Item.Renewal(due)
                        else -> error("unknown item $item")
                    }
                }
            }
        }
        val picked = QuietRunWork.pick(items, now)
        assertEquals(expect, picked?.let { p -> items.indexOfFirst { it === p }.toString() } ?: "none")
    }

    private fun cover(a: Map<String, String>, expect: String) {
        val prices = a.getValue("prices").split(',').associate { it.substringBefore(':').toLong() to it.substringAfter(':').toLong() }
        val credits = a.getValue("credits").split(',').mapIndexed { i, epoch ->
            TokenRow(Bytes.u64(i.toLong()) + ByteArray(24), "credit", epoch.toLong(), null, ByteArray(354), "fresh", 0, null, null, null, null, null)
        }
        val chosen = Pricing.coveringSet(summary(prices), credits, a.getValue("base").toLong(), a.getValue("now").toLong())
        val got = chosen?.joinToString(",") { row -> credits.indexOfFirst { it.nullifier().contentEquals(row.nullifier()) }.toString() } ?: "none"
        assertEquals(expect, got)
    }

    @Test
    fun theEngineMatchesTheSharedPolicyVectors() {
        val file = File(VECTORS)
        assertTrue("vector file missing: ${file.absolutePath}", file.isFile)
        val seen = sortedSetOf<String>()
        var outcomes = 0
        file.readLines().forEachIndexed { index, raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            val (opPart, expectPart) = if ("->" in line) Pair(line.substringBefore("->"), line.substringAfter("->")) else Pair(line, null)
            val words = opPart.trim().split(Regex("\\s+"))
            val expect = expectPart?.trim()?.split(Regex("\\s+"))
            try {
                seen += run(words, expect)
            } catch (e: Throwable) {
                throw AssertionError("entitlement_policy.txt:${index + 1}: `${line.take(140)}`: ${e.message}", e)
            }
            if (expect != null) outcomes++
        }
        assertEquals(sortedSetOf("slot", "boundary", "slotsfor", "plan", "estimate", "eligible", "attempt", "retry", "classify", "work", "cover"), seen)
        assertTrue("only $outcomes outcomes", outcomes >= 70)
    }

    companion object {
        /** Test working directory is the module directory (ghost/android/entitlement). */
        const val VECTORS = "../../protocol/test-vectors/entitlement_policy.txt"
    }
}
