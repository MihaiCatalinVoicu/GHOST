package org.ghost.sync.harness

import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.Outcome
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.engine.TrafficPolicy
import org.ghost.sync.harness.World.Companion.DAY
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.World.Companion.SECOND
import org.ghost.sync.store.RetentionPolicy
import java.security.MessageDigest

/**
 * S-A outbox (design §8.3): 3 ops, 3 relays over 3 operators, 1 listening namespace; relay C's
 * maximum TTL is 7 days, so it rejects the 30-day op3 (that delivery fails; op3 is still sent by
 * A and B). Background jobs every 15 minutes.
 */
internal class ScenarioA : Scenario("S-A") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 3, maxTtl = TtlBucket.DAYS_7.seconds.toLong())
        val alice = subject(w, "alice")
        val ns = alice.namespace("inbox", listOf(a, b, c), listen = true)
        listOf(a, b, c).forEach { alice.capability(it, ns) }
        w.at(0, "enqueue op1") { alice.enqueue("op1", ns) }
        w.at(0, "enqueue op2") { alice.enqueue("op2", ns) }
        w.at(2 * MINUTE, "enqueue op3") { alice.enqueue("op3", ns, TtlBucket.DAYS_30) }
        w.jobs(alice, MINUTE, 16 * MINUTE)
        w.endMillis = 30 * MINUTE
    }
}

/**
 * S-B inbox (design §8.3): relays A and B with overlapping sets of 9 hashes (h8 only on B, h9 only
 * on A with a one-day TTL, which then expires). A starts with exactly LIST_LIMIT blobs and B with
 * LIST_LIMIT + 1; three more arrive on both during a foreground window. STANDARD reads several pages
 * per event, HIGH exactly one. A job after h9 expired re-lists over the expired entry.
 */
internal class ScenarioB(private val mode: PrivacyMode) : Scenario("S-B/${mode.name}") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val bob = subject(w, "bob", mode = mode)
        val ns = bob.namespace("inbox", listOf(a, b), listen = true)
        bob.capability(a, ns, CapabilityKind.READ)
        bob.capability(b, ns, CapabilityKind.READ)
        // h8 (only on B) comes first on B, so B's first page carries a hash no other relay lists.
        w.otherWrite(b, ns, "h8")
        for (i in 1..4) {
            w.otherWrite(a, ns, "h$i")
            w.otherWrite(b, ns, "h$i")
        }
        w.foreground(bob, 0, 2 * MINUTE)
        w.at(90 * SECOND, "others write h5..h7, h9") {
            for (i in 5..7) {
                w.otherWrite(a, ns, "h$i")
                w.otherWrite(b, ns, "h$i")
            }
            w.otherWrite(a, ns, "h9", TtlBucket.DAY_1)
        }
        w.jobs(bob, 16 * MINUTE, 46 * MINUTE)
        w.jobs(bob, 25 * HOUR, 25 * HOUR)
        w.endMillis = 25 * HOUR + 15 * MINUTE
    }

    override fun finalChecks(w: World) {
        val lists = w.subject.port.calls.filter { it.kind == CallKind.LIST }
        if (mode == PrivacyMode.HIGH && lists.any { it.page != 1 }) violation("HIGH mode read a further page")
        if (mode == PrivacyMode.STANDARD && w.bus.injected.isEmpty() && lists.none { (it.page ?: 1) > 1 }) {
            violation("S-B STANDARD never read a further page")
        }
    }
}

/**
 * S-C mixed (design §8.3): S-A and S-B together, with the consumer (claim, markConsumed, defer,
 * release) acting between every two lane items and at every relay call's apply point.
 */
internal class ScenarioC : Scenario("S-C") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 3, maxTtl = TtlBucket.DAYS_7.seconds.toLong())
        val carol = subject(w, "carol", consumer = ConsumerPolicy(deferOnce = { (it.toByteArray()[0].toInt() and 3) == 0 }, deferSeconds = 60))
        val out = carol.namespace("out", listOf(a, b, c), listen = true)
        listOf(a, b, c).forEach { carol.capability(it, out) }
        val inbox = carol.namespace("in", listOf(a, b), listen = true)
        carol.capability(a, inbox, CapabilityKind.READ)
        carol.capability(b, inbox, CapabilityKind.READ)
        for (i in 1..4) {
            w.otherWrite(a, inbox, "h$i")
            w.otherWrite(b, inbox, "h$i")
        }
        w.otherWrite(b, inbox, "h8")
        w.driver.beforeItem = { client, _ -> if (client === carol) carol.oracle.step() }
        w.relayHook = { client, kind, _ -> if (client === carol && kind == EventKind.RELAY_AFTER_APPLY) carol.oracle.step(); null }
        w.at(0, "enqueue op1") { carol.enqueue("op1", out) }
        w.at(0, "enqueue op2") { carol.enqueue("op2", out) }
        w.foreground(carol, 0, 2 * MINUTE)
        w.at(90 * SECOND, "others write h5..h7") {
            for (i in 5..7) {
                w.otherWrite(a, inbox, "h$i")
                w.otherWrite(b, inbox, "h$i")
            }
        }
        w.at(100 * SECOND, "enqueue op3") { carol.enqueue("op3", out, TtlBucket.DAYS_30) }
        w.jobs(carol, 16 * MINUTE, 31 * MINUTE)
        w.endMillis = 45 * MINUTE
    }
}

/**
 * S-D capability (design §8.3): relay A rotates its key while a store with generation 1 is in
 * flight and Phase 8 installs generation 2 mid-call, so the call answers `unauthorized` for a
 * token that is no longer the current one (the generation guard keeps generation 2 usable). Relay
 * B's token has a one-blob quota: op2 meets `quota`, the check finds it absent, the delivery waits
 * for a capability until Phase 8 installs a new token two hours later. The job after the first is
 * two hours later, so a crash in the first job's store window is resolved after the relay's
 * no-op hour (check before restore verifies instead of a charged re-store).
 */
internal class ScenarioD : Scenario("S-D") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 3)
        val alice = subject(w, "alice")
        val ns = alice.namespace("dm", listOf(a, b, c), listen = false)
        alice.capability(a, ns)
        alice.capability(b, ns, quota = 1024)
        alice.capability(c, ns)
        var raced = false
        w.relayHook = { client, kind, info ->
            if (!raced && client === alice && info.kind == CallKind.STORE && info.relay == "A" && kind == EventKind.RELAY_BEFORE_SEND) {
                raced = true
                w.scriptState++
                a.model.rotateKey(MessageDigest.getInstance("SHA-256").digest("rotated|${w.seed}".toByteArray()))
                alice.capability(a, ns)
            }
            null
        }
        w.at(0, "enqueue op1") { alice.enqueue("op1", ns) }
        w.at(3 * MINUTE, "enqueue op2") { alice.enqueue("op2", ns) }
        w.jobs(alice, MINUTE, MINUTE)
        w.at(2 * HOUR + 5 * MINUTE, "phase 8 renews B") { alice.capability(b, ns) }
        w.jobs(alice, 2 * HOUR, 2 * HOUR + 45 * MINUTE)
        w.endMillis = 3 * HOUR
    }

    override val renewCapabilitiesInTail: Boolean = true
}

/**
 * S-E topology (design §8.3): relay C leaves the send set while its store is in flight (relay D
 * joins); relay A is retired while deliveries to it are pending or acked, then re-added; the
 * listening namespace is unsubscribed while a list is in flight and subscribed again.
 */
internal class ScenarioE : Scenario("S-E") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 3)
        val d = w.relay("D", 4)
        val dave = subject(w, "dave")
        val inbox = dave.namespace("in", listOf(a, b, c), listen = true)
        listOf(a, b, c).forEach { dave.capability(it, inbox, CapabilityKind.READ) }
        val out = dave.namespace("out", listOf(a, b, c), listen = false)
        dave.directory(d)
        listOf(a, b, c, d).forEach { dave.capability(it, out) }
        for (i in 1..3) w.otherWrite(listOf(a, b, c)[i - 1], inbox, "h$i")
        w.otherWrite(a, inbox, "h4")
        w.otherWrite(b, inbox, "h4")
        var moved = false
        var raced = false
        w.relayHook = { client, kind, info ->
            if (client === dave && !moved && info.kind == CallKind.STORE && info.relay == "C" && kind == EventKind.RELAY_BEFORE_SEND) {
                moved = true
                w.scriptState++
                dave.tx { dave.stores.namespaces.setRelays(it, out, setOf(dave.id(a), dave.id(b), dave.id(d))) }
            }
            if (client === dave && !raced && info.kind == CallKind.LIST && kind == EventKind.RELAY_AFTER_APPLY) {
                raced = true
                w.scriptState++
                dave.tx { dave.stores.namespaces.setListening(it, inbox, false) }
            }
            null
        }
        w.at(0, "enqueue op1") { dave.enqueue("op1", out) }
        w.at(0, "enqueue op2") { dave.enqueue("op2", out) }
        w.jobs(dave, MINUTE, MINUTE)
        w.at(10 * MINUTE, "retire A") { dave.tx { dave.stores.relayDirectory.retire(it, dave.id(a)) } }
        w.jobs(dave, 16 * MINUTE, 31 * MINUTE)
        w.at(20 * MINUTE, "subscribe again") { dave.tx { dave.stores.namespaces.setListening(it, inbox, true) } }
        w.at(40 * MINUTE, "re-add A") { dave.directory(a) }
        w.jobs(dave, 46 * MINUTE, 61 * MINUTE)
        w.endMillis = 75 * MINUTE
    }
}

/**
 * S-F window (design §8.3): the op's first store attempt is ambiguous (a timeout after the relay
 * applied it, or before it arrived), then the sender is offline for [offlineDays]. A recipient
 * with GC runs throughout. The outcome is INDETERMINATE only in the documented case: an ambiguous
 * attempt and no relay reachable for longer than max(H, TTL − σ); otherwise resolution settles it
 * (and an absence proven in time reopens the window).
 */
internal class ScenarioF(private val applied: Boolean, private val offlineDays: Int, private val ttl: TtlBucket) :
    Scenario("S-F/${if (applied) "applied" else "lost"}/${offlineDays}d/${ttl.days}d") {

    override val maxTailRounds: Int = 64

    override fun build(w: World) {
        val relays = listOf(w.relay("A", 1), w.relay("B", 2), w.relay("C", 3))
        val alice = subject(w, "alice")
        val bob = w.client(ClientSpec("bob", armed = false))
        val ns = alice.namespace("bob-dm", relays, listen = false)
        relays.forEach { alice.capability(it, ns) }
        bob.namespace("bob-dm", relays, listen = true)
        relays.forEach { bob.capability(it, ns, CapabilityKind.READ, validSeconds = 400L * 86_400) }
        var first = true
        w.relayHook = { client, kind, info ->
            val target = if (applied) EventKind.RELAY_AFTER_APPLY else EventKind.RELAY_BEFORE_SEND
            if (first && client === alice && info.kind == CallKind.STORE && kind == target) {
                first = false
                w.scriptState++
                val now = w.clock.millis
                alice.offlineWindows += now until now + offlineDays * DAY
                "timeout"
            } else {
                null
            }
        }
        w.at(0, "enqueue op") { alice.enqueue("op", ns, ttl) }
        w.jobs(alice, MINUTE, MINUTE)
        w.jobs(alice, 12 * HOUR, (offlineDays + 3) * DAY, every = 12 * HOUR)
        w.jobs(bob, 10 * MINUTE, (offlineDays + 40) * DAY, every = DAY)
        w.endMillis = (offlineDays + 40) * DAY
    }

    /**
     * The rules of design §3.5 for this variant, exactly in the fault-free run. With injected
     * crashes the first attempts may happen in another order (a delivery can be stored before the
     * ambiguous one), so SENT and DEGRADED are also accepted (their truth is checked structurally);
     * INDETERMINATE stays confined to the documented case.
     */
    override fun allowed(op: OpRecord, w: World): Set<Outcome> {
        val sigma = RetentionPolicy.SKEW_SECONDS / 86_400
        val resolvable = offlineDays < ttl.days - sigma
        val windowOpen = offlineDays < RetentionPolicy.STORE_WINDOW_SECONDS / 86_400
        val exact = when {
            windowOpen && resolvable -> setOf(Outcome.SENT)
            resolvable -> if (applied) setOf(Outcome.DEGRADED) else setOf(Outcome.SENT)
            else -> setOf(Outcome.INDETERMINATE)
        }
        if (!w.bus.faulted) return exact
        val documented = !resolvable && !windowOpen
        return if (documented) setOf(Outcome.SENT, Outcome.DEGRADED, Outcome.INDETERMINATE) else setOf(Outcome.SENT, Outcome.DEGRADED)
    }
}

/**
 * S-G verification (design §8.3): relay B acknowledges stores and drops them (repair, then failed
 * at the second strike); relay D answers the first store of each hash `malformed_response`
 * without storing. op1 (A, B, C, D) ends SENT; op2 (A, B) can only be verified on A: DEGRADED.
 */
internal class ScenarioG : Scenario("S-G") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2, hostile = Hostile.ACK_AND_DROP)
        val c = w.relay("C", 3)
        val d = w.relay("D", 4, hostile = Hostile.MALFORMED_STORE)
        val erin = subject(w, "erin")
        val ns1 = erin.namespace("dm1", listOf(a, b, c, d), listen = false)
        listOf(a, b, c, d).forEach { erin.capability(it, ns1) }
        val ns2 = erin.namespace("dm2", listOf(a, b), listen = false)
        listOf(a, b).forEach { erin.capability(it, ns2) }
        w.at(0, "enqueue op1") { erin.enqueue("op1", ns1) }
        w.at(0, "enqueue op2") { erin.enqueue("op2", ns2) }
        w.jobs(erin, MINUTE, 61 * MINUTE)
        w.endMillis = 75 * MINUTE
    }

    override fun allowed(op: OpRecord, w: World): Set<Outcome> = if (op.label == "op2") setOf(Outcome.DEGRADED) else setOf(Outcome.SENT)
}

/**
 * S-H backlog (design §11.2 #1): the consumer is paused for two days, longer than relay A's
 * one-day TTL; the backlog exceeds both caps (scaled to FETCHED_CAP 4 and BACKLOG_CAP 8 so it stays
 * enumerable). Once the consumer resumes nothing that was fetched before its relay expiry is lost,
 * and every live blob is consumed.
 */
internal class ScenarioH : Scenario("S-H") {
    override val maxTailRounds: Int = 64

    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val policy = TrafficPolicy(listLimit = 4, fetchedCap = 4, backlogCap = 8)
        val frank = subject(w, "frank", policy = policy, consumer = ConsumerPolicy(paused = { it.clock.millis < 2 * DAY }))
        val ns = frank.namespace("inbox", listOf(a, b), listen = true)
        frank.capability(a, ns, CapabilityKind.READ)
        frank.capability(b, ns, CapabilityKind.READ)
        for (i in 1..10) {
            w.otherWrite(a, ns, "a$i", TtlBucket.DAY_1)
            w.otherWrite(b, ns, "b$i", TtlBucket.DAYS_7)
        }
        w.jobs(frank, MINUTE, 3 * DAY, every = 6 * HOUR)
        w.endMillis = 3 * DAY
    }
}

/**
 * Cross-namespace dedup (mutant M6's detection, design §8.8): the same ciphertext is written into
 * two namespaces the client listens to; each namespace must deliver it once.
 */
internal class ScenarioCrossNamespace : Scenario("S-M6/cross-namespace") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val gina = subject(w, "gina")
        val ns1 = gina.namespace("one", listOf(a, b), listen = true)
        val ns2 = gina.namespace("two", listOf(a, b), listen = true)
        listOf(ns1, ns2).forEach { ns -> listOf(a, b).forEach { gina.capability(it, ns, CapabilityKind.READ) } }
        for (ns in listOf(ns1, ns2)) {
            w.otherWrite(a, ns, "shared")
            w.otherWrite(b, ns, "shared")
        }
        w.otherWrite(a, ns1, "only-one")
        w.otherWrite(b, ns2, "only-two")
        w.jobs(gina, MINUTE, 31 * MINUTE)
        w.endMillis = 45 * MINUTE
    }
}

/**
 * A relay that lies about expiry (mutant M7's detection, design §8.8): relay A declares a one-hour
 * expiry on every get, so tombstones of blobs fetched from it end early. The real engine keeps its
 * cursor past them (sticky tail) and never lists them again; the tail it re-lists was fetched from
 * honest relay B first. Listing from the beginning after a caught-up page re-lists them after their
 * tombstones are gone, and the consumer receives them twice.
 */
internal class ScenarioLyingExpiry : Scenario("S-M7/lying-expiry") {
    override val maxTailRounds: Int = 8

    override fun build(w: World) {
        val a = w.relay("A", 1, hostile = Hostile.SHORT_EXPIRY)
        val b = w.relay("B", 2)
        val hana = subject(w, "hana")
        val ns = hana.namespace("inbox", listOf(b), listen = true)
        hana.directory(a)
        hana.capability(a, ns, CapabilityKind.READ)
        hana.capability(b, ns, CapabilityKind.READ)
        for (label in listOf("x", "z1", "z2", "z3")) w.otherWrite(a, ns, label, TtlBucket.DAYS_30)
        for (label in listOf("t1", "t2")) {
            w.otherWrite(b, ns, label, TtlBucket.DAYS_30)
            w.otherWrite(a, ns, label, TtlBucket.DAYS_30)
        }
        w.jobs(hana, MINUTE, MINUTE)
        w.at(10 * MINUTE, "A joins the set") { hana.tx { hana.stores.namespaces.setRelays(it, ns, setOf(hana.id(a), hana.id(b))) } }
        w.jobs(hana, 16 * MINUTE, HOUR)
        w.jobs(hana, DAY, 29 * DAY + 12 * HOUR, every = DAY / 2)
        w.endMillis = 29 * DAY + 20 * HOUR
    }
}

/**
 * A 90-day blob (mutant M8's detection, design §8.8): its tombstone must outlive every relay's copy;
 * daily jobs with garbage collection run for forty days.
 */
internal class ScenarioLongTtl : Scenario("S-M8/long-ttl") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val ivan = subject(w, "ivan")
        val ns = ivan.namespace("inbox", listOf(a, b), listen = true)
        ivan.capability(a, ns, CapabilityKind.READ)
        ivan.capability(b, ns, CapabilityKind.READ)
        w.otherWrite(a, ns, "long", TtlBucket.DAYS_90)
        w.otherWrite(b, ns, "short", TtlBucket.DAY_1)
        w.jobs(ivan, MINUTE, 40 * DAY, every = DAY)
        w.endMillis = 40 * DAY + HOUR
    }
}
