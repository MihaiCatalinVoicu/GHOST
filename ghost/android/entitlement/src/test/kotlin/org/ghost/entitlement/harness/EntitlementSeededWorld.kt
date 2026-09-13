package org.ghost.entitlement.harness

import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.api.PayWith
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Fault
import org.ghost.sync.harness.FaultPlan
import org.ghost.sync.harness.OpRecord
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs
import java.util.SplittableRandom

/**
 * The `:entitlement` liveness world (Phase 8 design §11.9, §13.2), seeded: the real entitlement
 * engine feeds the real sync engine through the model redeem relays and the model issuer. Either an
 * invitee activating an invite in the foreground (trial tokens) or a genesis identity buying a pack
 * in XMR (quiet-run `RequestInvoice` and `BlindSign`, payment when the instructions show, tokens at
 * the next activation slot); STANDARD or HIGH mode; 1–2 namespaces over the three ES slot relays,
 * listened or not; ops and other writers' blobs at random times; periodic jobs every 15 minutes with
 * the production quiet-run decision, random foreground windows; a crash budget and network faults
 * (sync calls, and transient ones on redemptions and issuer calls), issuer unavailability in some
 * worlds. Every Phase 7 invariant holds with the real redeem lane, and the liveness premise holds: no
 * need waits while an eligible token exists (the quiescence check). Everything derives from the seed.
 */
internal class EntitlementSeededWorld(val seed: Long) : EntScenario("ent-seed $seed") {
    private val rnd = SplittableRandom(seed)
    private var crashBudget = 0
    private var pCrash = 0.0
    private var pNetwork = 0.0
    private var pIssuer = 0.0
    private var disturbed = false
    val description = StringBuilder()

    private val categories = listOf(
        "timeout", "transport", "relay_unavailable", "internal", "malformed_response", "not_stored", "closed", "not_bootstrapped", "tor_bootstrap",
        "tor_bootstrap_timeout", "no_such_category",
    )
    private val afterSend = listOf("timeout", "relay_unavailable", "internal", "closed", "no_such_category")
    private val transient = listOf("timeout", "transport", "relay_unavailable", "internal", "closed", "not_bootstrapped", "tor_bootstrap", "no_such_category")
    private val callBefore = listOf("timeout", "transport", "relay_unavailable", "closed")
    private val callAfter = listOf("timeout", "relay_unavailable", "closed")

    override fun config(): EntConfig {
        val issuerSeed = seed
        return configured(
            EntConfig(
                issuerSeed = issuerSeed,
                issuerUnavailable = { i -> pIssuer > 0 && (Bytes.sha256(Bytes.ascii("unavailable|$issuerSeed|$i"))[0].toInt() and 0xff) < pIssuer * 256 },
            ),
        )
    }

    override fun build(w: World) {
        pIssuer = if (rnd.nextInt(3) == 0) 0.02 else 0.0
        val mode = if (rnd.nextInt(4) == 0) PrivacyMode.HIGH else PrivacyMode.STANDARD
        val invitee = rnd.nextBoolean()
        val e = standard(w, mode, genesis = !invitee)
        val relays = w.relays.take(3)
        // A and C share an operator: a namespace spans B and one of them, or all three.
        val sets = listOf(listOf(0, 1), listOf(1, 2), listOf(0, 1, 2))
        val nsCount = 1 + rnd.nextInt(2)
        val namespaces = ArrayList<Pair<NamespaceId, List<Int>>>()
        for (n in 0 until nsCount) {
            val set = sets[rnd.nextInt(sets.size)]
            val listen = n == 0 || rnd.nextBoolean()
            namespaces += e.c.namespace("ns$n", set.map { relays[it] }, listen) to set
        }
        val end: Long
        if (invitee) {
            val (text, _) = inviteText(ent, "seed|$seed")
            w.foreground(e.c, 0, 20 * MINUTE)
            w.at(MINUTE, "activate") { e.e().activate(text) }
            for (t in listOf(40 * MINUTE, 3 * HOUR)) {
                w.foreground(e.c, t, t + 15 * MINUTE)
                w.at(t + MINUTE, "the user activates again if nothing started") { if (e.e().activationState() == ActivationState.NONE) e.e().activate(text) }
            }
            end = (6 + rnd.nextInt(24)) * HOUR
            // An invitee whose trial is unusable (its HIGH-mode tokens eligible only after their
            // weeks) buys a pack in XMR when the app shows it uncovered.
            w.keepBuying(6 * HOUR, PayWith.XMR)
            w.keepPaying(6 * HOUR)
            // HIGH-mode trial tokens wait for an activation slot and its Geometric(1/2) extra days.
            if (mode == PrivacyMode.HIGH) disturbed = true
        } else {
            w.purchase(0, PayWith.XMR, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
            w.keepBuying(4 * HOUR, PayWith.XMR)
            if (rnd.nextInt(10) == 0) w.payAt(listOf(2 * HOUR), fraction = 0.5)
            w.keepPaying(3 * HOUR)
            end = (30 + rnd.nextInt(42)) * HOUR
        }
        if (pIssuer > 0) disturbed = true
        w.jobs(e.c, MINUTE, end)
        repeat(rnd.nextInt(4)) {
            val from = rnd.nextLong(0, end)
            w.foreground(e.c, from, from + (5 + rnd.nextInt(30)) * MINUTE)
        }
        val opCount = rnd.nextInt(7)
        for (i in 0 until opCount) {
            val (ns, _) = namespaces[rnd.nextInt(namespaces.size)]
            val ttl = if (rnd.nextInt(4) == 0) TtlBucket.DAY_1 else TtlBucket.DAYS_7
            w.at(rnd.nextLong(0, end), "enqueue op$i") { if (e.identity.exists) e.c.enqueue("op$i", ns, ttl) }
        }
        val listened = namespaces.filter { it.first in e.c.listening }
        val inbound = if (listened.isEmpty()) 0 else rnd.nextInt(11)
        for (i in 0 until inbound) {
            val (ns, set) = listened[rnd.nextInt(listened.size)]
            val node = relays[set[rnd.nextInt(set.size)]]
            w.at(rnd.nextLong(0, end), "inbound $i") { w.otherWrite(node, ns, "in$i") }
        }
        crashBudget = rnd.nextInt(4)
        pCrash = if (crashBudget == 0) 0.0 else 1.0 / (200 + rnd.nextInt(800))
        pNetwork = rnd.nextInt(10) / 100.0
        w.endMillis = end
        description.append("invitee=$invitee mode=$mode ns=$nsCount ops=$opCount inbound=$inbound end=${end / HOUR}h crashes<=$crashBudget pCrash=$pCrash pNet=$pNetwork pIssuer=$pIssuer")
    }

    /** Faults until the scripted end; the quiescence tail is fault-free. Redemptions and issuer calls fail only transiently. */
    fun plan(w: World): FaultPlan = FaultPlan { e ->
        if (w.clock.millis >= w.endMillis) return@FaultPlan null
        if (crashBudget > 0 && rnd.nextDouble() < pCrash) {
            crashBudget--
            return@FaultPlan Fault.Crash
        }
        val call = e.call ?: return@FaultPlan null
        if (!e.kind.relay || rnd.nextDouble() >= pNetwork) return@FaultPlan null
        val before = e.kind == EventKind.RELAY_BEFORE_SEND
        val pool = when {
            call.kind == CallKind.ISSUER || call.kind == CallKind.REDEEM -> if (before) callBefore else callAfter
            !before -> afterSend
            call.kind == CallKind.GET -> transient
            else -> categories
        }
        Fault.Network(pool[rnd.nextInt(pool.size)])
    }

    override fun allowed(op: OpRecord, w: World): Set<Outcome> = if (disturbed) Outcome.entries.toSet() else setOf(Outcome.SENT)

    override fun toString(): String = "EntitlementSeededWorld($seed)"
}
