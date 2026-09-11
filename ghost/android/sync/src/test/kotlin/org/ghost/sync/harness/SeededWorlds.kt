package org.ghost.sync.harness

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.harness.World.Companion.DAY
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.store.StoreLimits
import java.util.SplittableRandom

/**
 * A seeded random world (design §8.5): 2–4 relays over 2–3 operators (at least two honest
 * operators in every namespace's set), at most one hostile relay per set, 1–3 namespaces, either
 * privacy mode, 0–20 ops, 0–50 inbound blobs, error rates and a crash probability per event,
 * offline windows from hours to 60 days, clock steps (backward within 1 h, forward within 2 d,
 * large jumps only while offline), capability expiry and renewal, relay-set changes and
 * retirements, and interleaved consumer, capability, topology actions at relay events. Everything
 * derives from the seed; a failure names it.
 */
internal class SeededWorld(val seed: Long) : Scenario("seed $seed") {
    private val rnd = SplittableRandom(seed)
    private val categories = listOf(
        "timeout", "transport", "relay_unavailable", "internal", "malformed_response", "not_stored", "unauthorized", "quota",
        "closed", "not_bootstrapped", "tor_bootstrap", "tor_bootstrap_timeout", "no_such_category",
    )
    private val storeOnly = listOf("rejected", "invalid_argument", "not_bucket_sized", "not_onion")

    /** Ops whose outcome the script may legitimately change (deadline, removals, permanent refusals, long outages). */
    private val disturbed = HashSet<String>()
    private var disturbedAll = false
    private var crashBudget = 0
    private var pCrash = 0.0
    private var pNetwork = 0.0
    private var pStoreOnly = 0.0
    val description = StringBuilder()

    override val maxTailRounds: Int = 400

    override fun build(w: World) {
        val relayCount = 2 + rnd.nextInt(3)
        val operators = listOf(1, 2) + List(relayCount - 2) { 1 + rnd.nextInt(3) }
        val hostileIndex = if (relayCount >= 3 && rnd.nextInt(10) < 4) relayCount - 1 else -1
        val longOffline = rnd.nextInt(20) == 0
        val span = if (longOffline) 0L else (1 + rnd.nextInt(6)) * HOUR
        var hostileMode: Hostile? = null
        val relays = (0 until relayCount).map { i ->
            val hostile = if (i == hostileIndex) {
                val modes = Hostile.entries.filter { it != Hostile.SHORT_EXPIRY || !longOffline }
                modes[rnd.nextInt(modes.size)].also { hostileMode = it }
            } else {
                null
            }
            w.relay("R$i", operators[i], hostile = hostile, skewSeconds = if (hostile == null) rnd.nextLong(-3_600, 3_601) else 0)
        }
        val honest = relays.filter { it.honest }
        val mode = if (rnd.nextBoolean()) PrivacyMode.STANDARD else PrivacyMode.HIGH
        val consumer = ConsumerPolicy(deferOnce = { rnd.nextInt(8) == 0 && it.toByteArray()[1].toInt() and 7 == 0 }, deferSeconds = 60 + rnd.nextInt(600))
        val c = subject(w, "subject", mode = mode, consumer = consumer)
        c.directory(*relays.toTypedArray())
        val nsCount = 1 + rnd.nextInt(3)
        val namespaces = ArrayList<NamespaceId>()
        for (n in 0 until nsCount) {
            val set = (honest.take(2) + relays.drop(2).filter { rnd.nextBoolean() }).distinct()
            val listen = n == 0 || rnd.nextBoolean()
            val ns = c.namespace("ns$n", set, listen)
            namespaces += ns
            for (r in set) {
                val shortLived = rnd.nextInt(6) == 0
                val quota = if (rnd.nextInt(8) == 0) 4L * 1024 else 64L * 1024 * 1024
                c.capability(r, ns, CapabilityKind.WRITE, quota = quota, validSeconds = if (shortLived) 2 * 3_600 else 200L * 86_400)
                if (listen && rnd.nextInt(4) == 0) c.capability(r, ns, CapabilityKind.READ)
            }
        }
        val end = if (longOffline) 0L else span
        // Sessions: background jobs every 15 minutes, and foreground windows.
        if (!longOffline) {
            w.jobs(c, MINUTE, end)
            repeat(rnd.nextInt(3)) {
                val from = rnd.nextLong(0, maxOf(1, end))
                w.foreground(c, from, from + (5 + rnd.nextInt(30)) * MINUTE)
            }
        }
        // Ops and inbound blobs.
        val opCount = rnd.nextInt(21)
        val horizon = if (longOffline) 30 * MINUTE else maxOf(MINUTE, end)
        for (i in 0 until opCount) {
            val ns = namespaces[rnd.nextInt(namespaces.size)]
            val ttl = TtlBucket.entries[rnd.nextInt(TtlBucket.entries.size)]
            val deadline = if (rnd.nextInt(10) == 0) (1 + rnd.nextInt(48)) * 3_600L else null
            val label = "op$i"
            if (deadline != null) disturbed += label
            val size = if (rnd.nextInt(10) == 0) 4096 else 1024
            w.at(rnd.nextLong(0, horizon), "enqueue $label") { c.enqueue(label, ns, ttl, size, deadline) }
        }
        val listened = namespaces.filter { it in c.listening }
        val inboundCount = if (listened.isEmpty()) 0 else rnd.nextInt(51)
        for (i in 0 until inboundCount) {
            val ns = listened[rnd.nextInt(listened.size)]
            val node = relays[rnd.nextInt(relays.size)]
            val ttl = if (rnd.nextInt(5) == 0) TtlBucket.DAY_1 else TtlBucket.DAYS_7
            w.at(rnd.nextLong(0, horizon), "inbound $i") { w.otherWrite(node, ns, "in$i", ttl) }
        }
        // Outages.
        if (longOffline) {
            val days = 3 + rnd.nextInt(58)
            disturbedAll = true
            val from = 20 * MINUTE
            c.offlineWindows += from until from + days * DAY
            w.jobs(c, MINUTE, 16 * MINUTE)
            w.jobs(c, 12 * HOUR, (days + 1) * DAY, every = 12 * HOUR)
            if (rnd.nextBoolean()) {
                val jump = (10L + rnd.nextInt(30)) * 86_400
                w.at(from + MINUTE, "clock jump forward while offline") { w.clock.deviceOffsetSeconds += jump }
                w.at(from + days * DAY - HOUR, "clock back") { w.clock.deviceOffsetSeconds -= jump }
                w.foreground(c, from + 2 * MINUTE, from + 3 * HOUR)
            }
            w.endMillis = (days + 1) * DAY
        } else {
            if (rnd.nextInt(5) == 0) {
                val from = rnd.nextLong(0, end)
                c.offlineWindows += from until from + (1 + rnd.nextInt(6)) * HOUR
            }
            if (rnd.nextInt(5) == 0) {
                val node = honest[rnd.nextInt(honest.size)]
                val from = rnd.nextLong(0, end)
                val category = listOf("transport", "timeout", "relay_unavailable")[rnd.nextInt(3)]
                w.at(from, "unreachable ${node.name}") {
                    node.reachable = false
                    node.unreachableCategory = category
                }
                w.at(from + (10 + rnd.nextInt(110)) * MINUTE, "reachable ${node.name}") { node.reachable = true }
            }
            w.endMillis = end
        }
        // Clock steps within tolerance (the device clock stays within σ while the transport is READY).
        if (rnd.nextInt(5) == 0) {
            val delta = if (rnd.nextBoolean()) -rnd.nextLong(60, 3_601) else rnd.nextLong(60, 2 * 86_400 + 1)
            w.at(rnd.nextLong(0, maxOf(1, w.endMillis)), "clock step") { w.clock.deviceOffsetSeconds += delta }
            if (delta > 86_400) disturbedAll = true
        }
        // Topology: a removal or retirement of a non-guaranteed relay, sometimes re-added.
        val extras = relays.drop(2)
        if (extras.isNotEmpty() && rnd.nextInt(6) == 0) {
            val node = extras[rnd.nextInt(extras.size)]
            val at = rnd.nextLong(0, maxOf(1, w.endMillis))
            if (rnd.nextBoolean()) {
                w.at(at, "retire ${node.name}") { c.tx { c.stores.relayDirectory.retire(it, c.id(node)) } }
                if (rnd.nextBoolean()) w.at(at + 20 * MINUTE, "re-add ${node.name}") { c.directory(node) }
            } else {
                val ns = namespaces[rnd.nextInt(namespaces.size)]
                w.at(at, "remove ${node.name} from a set") {
                    c.tx { tx ->
                        val keep = HashSet<org.ghost.sync.api.RelayId>()
                        tx.sql.query("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?1", listOf(ns.toByteArray())) { keep += org.ghost.sync.api.RelayId(it.long(0)) }
                        keep -= c.id(node)
                        c.stores.namespaces.setRelays(tx, ns, keep)
                    }
                }
            }
            disturbedAll = true
        }
        // Interleavings between events (design §8.5): at relay calls (outside any transaction) and
        // before lane items, a consumer transaction, a capability put (Phase 8), a relay-set change or
        // a retirement / re-add of a relay beyond the two guaranteed honest operators.
        val pInterleave = rnd.nextInt(10) / 100.0
        fun interleave(info: CallInfo?) {
            w.scriptState++
            when (rnd.nextInt(4)) {
                0 -> c.oracle.step()
                1 -> {
                    val node = info?.let { i -> w.relays.first { it.name == i.relay } } ?: relays[rnd.nextInt(relays.size)]
                    val ns = info?.let { i -> c.namespaces.values.firstOrNull { it.toByteArray().hex() == i.namespace } } ?: namespaces[rnd.nextInt(namespaces.size)]
                    var inSet = false
                    c.jdbc.query("SELECT 1 FROM namespace_relay WHERE namespace_id = ?1 AND relay_id = ?2", listOf(ns.toByteArray(), c.id(node).value)) { inSet = true }
                    if (inSet) c.capability(node, ns, CapabilityKind.WRITE)
                }
                2 -> if (extras.isNotEmpty()) {
                    val node = extras[rnd.nextInt(extras.size)]
                    val ns = namespaces[rnd.nextInt(namespaces.size)]
                    c.tx { tx ->
                        val set = HashSet<org.ghost.sync.api.RelayId>()
                        tx.sql.query("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?1", listOf(ns.toByteArray())) { set += org.ghost.sync.api.RelayId(it.long(0)) }
                        if (!set.remove(c.id(node))) set += c.id(node)
                        c.stores.namespaces.setRelays(tx, ns, set)
                    }
                    disturbedAll = true
                }
                else -> if (extras.isNotEmpty()) {
                    val node = extras[rnd.nextInt(extras.size)]
                    var active = false
                    c.jdbc.query("SELECT 1 FROM relay_directory WHERE relay_id = ?1 AND state = 'active'", listOf(c.id(node).value)) { active = true }
                    if (active) c.tx { c.stores.relayDirectory.retire(it, c.id(node)) } else c.directory(node)
                    disturbedAll = true
                }
            }
        }
        w.relayHook = { client, _, info ->
            if (client === c && rnd.nextDouble() < pInterleave) interleave(info)
            null
        }
        w.driver.beforeItem = { client, _ -> if (client === c && rnd.nextDouble() < pInterleave) interleave(null) }
        crashBudget = rnd.nextInt(5)
        pCrash = if (crashBudget == 0) 0.0 else 1.0 / (100 + rnd.nextInt(900))
        pNetwork = rnd.nextInt(20) / 100.0
        pStoreOnly = if (rnd.nextInt(4) == 0) 0.02 else 0.0
        description.append("relays=$relayCount hostile=$hostileMode mode=$mode ns=$nsCount ops=$opCount inbound=$inboundCount ")
            .append("longOffline=$longOffline end=${w.endMillis / MINUTE}min crashes<=$crashBudget pCrash=$pCrash pNet=$pNetwork")
    }

    /** Faults until the scripted end; the quiescence tail is fault-free. */
    fun plan(w: World): FaultPlan = FaultPlan { e ->
        if (w.clock.millis >= w.endMillis) return@FaultPlan null
        if (crashBudget > 0 && rnd.nextDouble() < pCrash) {
            crashBudget--
            return@FaultPlan Fault.Crash
        }
        val call = e.call ?: return@FaultPlan null
        if (!e.kind.relay) return@FaultPlan null
        if (call.kind == CallKind.STORE && e.kind == EventKind.RELAY_BEFORE_SEND && rnd.nextDouble() < pStoreOnly) {
            w.ops.values.filter { op -> op.hash.toByteArray().hex() in call.hashes }.forEach { disturbed += it.label }
            return@FaultPlan Fault.Network(storeOnly[rnd.nextInt(storeOnly.size)])
        }
        if (rnd.nextDouble() >= pNetwork) return@FaultPlan null
        // An honest relay serves what it lists: a get fails only in transit (a corrupt or empty answer
        // from an honest relay does not exist; the hostile relays model those).
        // Once the request may have reached the relay, only the categories that do not prove
        // "not applied" can occur (design §3.6: `transport` means no stream was opened; refusals
        // are answers of a relay that applied nothing).
        val pool = when {
            e.kind != EventKind.RELAY_BEFORE_SEND -> afterSend
            call.kind == CallKind.GET -> transient
            else -> categories
        }
        Fault.Network(pool[rnd.nextInt(pool.size)])
    }

    private val afterSend = listOf("timeout", "relay_unavailable", "internal", "closed", "no_such_category")

    private val transient = listOf(
        "timeout", "transport", "relay_unavailable", "internal", "closed", "not_bootstrapped", "tor_bootstrap", "tor_bootstrap_timeout", "no_such_category",
    )

    override fun allowed(op: OpRecord, w: World): Set<Outcome> =
        if (disturbedAll || op.label in disturbed) Outcome.entries.toSet() else setOf(Outcome.SENT)

    /** Design §8.5: the hostile relay costs its pairs' slots only, and its rows stay bounded. */
    override fun finalChecks(w: World) {
        val c = w.subject
        val hostile = w.relays.firstOrNull { !it.honest } ?: return
        val policy = c.spec.policy
        for (call in c.port.calls.filter { it.relay == hostile.name }) {
            if (call.kind == CallKind.LIST && (call.page ?: 1) > policy.standardPagesPerEvent) violation("more than ${policy.standardPagesPerEvent} list pages in one event")
        }
        val perItem = w.records.callsPerItem.filterKeys { it[0] == c.name && it[1] == hostile.name }
        for ((k, n) in perItem) {
            when (k[3]) {
                CallKind.GET -> if (n > policy.backgroundFetchesPerEvent) violation("$n gets to the hostile relay in one event")
                CallKind.CHECK -> if (n > 1 + 2 * policy.storesPerPairEvent) violation("$n checks to the hostile relay in one event")
                else -> Unit
            }
        }
        var rows = 0L
        c.jdbc.query(
            "SELECT count(*) FROM inbox_blob b WHERE b.state IN ('listed', 'unavailable') AND NOT EXISTS (SELECT 1 FROM inbox_source s " +
                "WHERE s.namespace_id = b.namespace_id AND s.blob_hash = b.blob_hash AND s.relay_id <> ?1)",
            listOf(c.id(hostile).value),
        ) { rows = it.long(0) }
        val bound = (policy.backlogCap + policy.listLimit).toLong() * c.namespaces.size
        if (rows > bound) violation("$rows rows attributable to the hostile relay (bound $bound)")
        check(StoreLimits.BACKLOG_CAP >= policy.backlogCap)
    }
}
