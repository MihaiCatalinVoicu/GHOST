package org.ghost.sync.harness

import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
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
 * S-F with the short TTL buckets (Phase 9 design §10.4, §13.3 item 1): the same ambiguous first
 * store attempt and offline window as [ScenarioF], with a 1-hour or 1-day TTL and, in half the
 * variants, the DM deadline `author + min(bucket, 7 d)` of §21.10 point 1.
 *
 * §10.4's re-derivation for these buckets: resolution never applies (`now < copy_hour + ttl − σ` is
 * never true, since every bucket is shorter than σ = 3 d), so no identical resend happens and an
 * op whose only possible copy is ambiguous ends INDETERMINATE instead of being resolved. The safety
 * invariants do not use σ and are unchanged, which the structural checks of every run assert.
 */
internal class ScenarioShortTtl(
    private val applied: Boolean,
    private val offlineMillis: Long,
    private val ttl: TtlBucket,
    private val withDeadline: Boolean,
) : Scenario(
    "S-F/short/${if (applied) "applied" else "lost"}/${offlineMillis / MINUTE}m/${ttl.seconds}s/${if (withDeadline) "deadline" else "open"}",
) {
    override val maxTailRounds: Int = 64

    /** The DM deadline of §21.10 point 1: `author + min(bucket, 7 d)`, in seconds from the enqueue. */
    private val deadlineInSeconds: Long? = if (withDeadline) minOf(ttl.seconds.toLong(), 7 * 86_400L) else null

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
                // The window ends at a fixed moment, not one the attempt's time sets: a crash that
                // delays the attempt must not push alice's return past her jobs (it leaves her
                // online instead, which `allowed` accepts for a faulted run).
                val now = w.clock.millis
                alice.offlineWindows += now until maxOf(now, offlineMillis)
                "timeout"
            } else {
                null
            }
        }
        w.at(0, "enqueue op") { alice.enqueue("op", ns, ttl, deadlineInSeconds = deadlineInSeconds) }
        w.jobs(alice, MINUTE, MINUTE)
        // The offline window starts at the ambiguous attempt, a little after the first job, so alice
        // returns a few minutes after it ends; her jobs are then close enough for a store and its
        // verification to fit inside a one-hour deadline. Bob polls sparsely while she is away and
        // closely around the stores, so a one-hour blob is fetched inside its life.
        w.jobs(alice, offlineMillis + 3 * MINUTE, offlineMillis + 45 * MINUTE, every = 5 * MINUTE)
        w.jobs(bob, 10 * MINUTE, offlineMillis, every = 12 * HOUR)
        w.jobs(bob, offlineMillis + 5 * MINUTE, offlineMillis + 2 * HOUR, every = 20 * MINUTE)
        w.endMillis = offlineMillis + 3 * HOUR
    }

    /**
     * The op reaches every relay once alice is back, unless its deadline passed while she was away:
     * then the deliveries close undecided and, because resolution never applies to these buckets
     * (§10.4 point 1), D2 answers INDETERMINATE from the one possible copy — the ambiguous attempt
     * leaves a `copy_hour` whether or not the relay applied it.
     */
    override fun allowed(op: OpRecord, w: World): Set<Outcome> {
        val deadlinePassed = deadlineInSeconds != null && deadlineInSeconds * 1_000 <= offlineMillis
        val exact = if (deadlinePassed) setOf(Outcome.INDETERMINATE) else setOf(Outcome.SENT)
        if (!w.bus.faulted) return exact
        // With a crash the first attempt, and so the offline window, can start later or not at all;
        // an op whose deadline then passes before any attempt fails, and one stored before it is sent.
        return if (deadlinePassed) {
            setOf(Outcome.SENT, Outcome.DEGRADED, Outcome.INDETERMINATE, Outcome.FAILED)
        } else {
            setOf(Outcome.SENT, Outcome.DEGRADED, Outcome.INDETERMINATE)
        }
    }
}

/**
 * The consumer takes its blobs with `Inbox.peek` and `Inbox.claimOne` instead of `Inbox.claim`
 * (Phase 9 design §13.3 item 10; V-11): the exactly-once argument of Phase 7 is unchanged, so the
 * same invariants hold with a consumer that orders its batch before claiming any of it.
 */
internal class ScenarioPeekClaimOne : Scenario("S-P/peek-claim-one") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val pia = subject(w, "pia", consumer = ConsumerPolicy(claimStyle = ClaimStyle.PEEK_ONE, deferOnce = { (it.toByteArray()[0].toInt() and 3) == 0 }))
        val inbox = pia.namespace("in", listOf(a, b), listen = true)
        pia.capability(a, inbox, CapabilityKind.READ)
        pia.capability(b, inbox, CapabilityKind.READ)
        val out = pia.namespace("out", listOf(a, b), listen = true)
        listOf(a, b).forEach { pia.capability(it, out) }
        for (i in 1..4) {
            w.otherWrite(a, inbox, "h$i")
            w.otherWrite(b, inbox, "h$i")
        }
        w.otherWrite(b, inbox, "h5", TtlBucket.HOUR_1)
        w.at(0, "enqueue op1") { pia.enqueue("op1", out) }
        w.at(90 * SECOND, "others write h6, h7") {
            w.otherWrite(a, inbox, "h6")
            w.otherWrite(b, inbox, "h7", TtlBucket.HOUR_1)
        }
        w.jobs(pia, MINUTE, 61 * MINUTE)
        w.endMillis = 75 * MINUTE
    }
}

/**
 * S-P/reoffer-deferred (Phase 10 design §7.5 item 6, slice S1a): the consumer is a channel actor.
 * A message it cannot open before the channel is settled is deferred for three days
 * (`Inbox.defer`); the key message, consumed in one transaction with `Inbox.reofferDeferred`, brings
 * every deferred row back at once. Without the re-offer the deferred rows would stay fetched for
 * three days and the run would not reach quiescence; with it, every message is consumed exactly
 * once, however a crash cuts the claim, the deferral or the settling transaction, and the key
 * arrives before some messages, with others, and after others.
 */
internal class ScenarioReofferDeferred : Scenario("S-P/reoffer-deferred") {
    private fun labelOf(w: World, hash: BlobHash): String? = w.otherBlobs.entries.firstOrNull { it.value.second == hash }?.key

    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val settle = SettlePolicy(
            unopenable = { world, hash -> labelOf(world, hash)?.startsWith("msg") == true },
            settles = { world, hash -> labelOf(world, hash)?.startsWith("key") == true },
        )
        val ria = subject(w, "ria", consumer = ConsumerPolicy(settle = settle))
        val chan = ria.namespace("chan", listOf(a, b), listen = true, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        ria.capability(a, chan, CapabilityKind.READ)
        ria.capability(b, chan, CapabilityKind.READ)
        for (i in 1..3) {
            w.otherWrite(a, chan, "msg$i")
            w.otherWrite(b, chan, "msg$i")
        }
        w.otherWrite(b, chan, "msg4")
        w.at(8 * MINUTE, "the key arrives with a message") {
            w.otherWrite(a, chan, "key1")
            w.otherWrite(b, chan, "key1")
            w.otherWrite(a, chan, "msg5")
        }
        w.at(18 * MINUTE, "a message after the key") {
            w.otherWrite(a, chan, "msg6")
            w.otherWrite(b, chan, "msg6")
        }
        w.jobs(ria, MINUTE, 31 * MINUTE, every = 5 * MINUTE)
        w.endMillis = 45 * MINUTE
    }

    override fun finalChecks(w: World) {
        val sql = w.subject.jdbc
        var consumed = 0L
        sql.query("SELECT count(*) FROM oracle_consumed") { consumed = it.long(0) }
        if (consumed != w.otherBlobs.size.toLong()) violation("S-P/reoffer-deferred: $consumed of ${w.otherBlobs.size} blobs consumed")
        var deferred = 0L
        sql.query("SELECT count(*) FROM inbox_blob WHERE state = 'fetched'") { deferred = it.long(0) }
        if (deferred != 0L) violation("S-P/reoffer-deferred: $deferred deferred row(s) left after the namespace settled")
    }
}

/**
 * S-R/funded-channel (Phase 10 design §7.5 item 2, slice S1a): a funded CHANNEL namespace of source
 * LOCAL whose **write slot holds the shared bearer DEPOSIT credential**, with this week's member keys
 * (DEPOSIT and READ) to register at two relays. The registrations are served by the registration
 * capability alone: the credential at `RegisterKey` is a T21 violation the harness port refuses, which
 * would leave the rows pending for ever (no quiescence), mark the write slot rejected (the truth
 * invariant) and leave a relay without its record (the final check). The capability arrives from the
 * script (the planner's REGISTER MISSING need, played by Phase 8) or, when a crash lost that action, from
 * the quiescence tail, which installs what `Capabilities.needed()` reports. Crashes cut the lease, the
 * call and the result of every registration.
 */
internal class ScenarioFundedChannel : Scenario("S-R/funded-channel") {
    private val kinds = listOf(KeyKind.DEPOSIT, KeyKind.READ)
    private var ns: NamespaceId? = null
    private var week = 0L

    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val relays = listOf(a, b)
        val fay = subject(w, "fay")
        val chan = fay.namespace("chan", relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        ns = chan
        relays.forEach { fay.depositCredential(it, chan) }
        week = ModelRelay.week(w.relayNow(a))
        fay.tx { tx ->
            fay.stores.funding.set(tx, chan, true)
            for (node in relays) for (kind in kinds) fay.stores.registrations.request(tx, fay.id(node), chan, week, kind, fay.verifier(chan, kind))
        }
        w.at(2 * MINUTE, "phase 8 installs the registration capabilities") {
            relays.forEach { fay.capability(it, chan, CapabilityKind.REGISTER, validSeconds = thisWeekValidSeconds(w, it)) }
        }
        w.jobs(fay, MINUTE, 31 * MINUTE, every = 5 * MINUTE)
        w.endMillis = 45 * MINUTE
    }

    /**
     * A redeemed capability is valid to the end of its week plus an hour (`start(c + 1) + 1 h`), which is
     * where both the relay and the registration rule read the week from; the tail's renewal mints the same.
     */
    private fun thisWeekValidSeconds(w: World, node: RelayNode): Long = ModelRelay.weekStart(week + 1) + 3_600 - w.relayNow(node)

    override fun renewalValidSeconds(w: World, node: RelayNode, need: CapabilityNeed): Long =
        if (need.kind == CapabilityKind.REGISTER) thisWeekValidSeconds(w, node) else super.renewalValidSeconds(w, node, need)

    override fun extraQuiescence(w: World): List<String> {
        val out = ArrayList<String>()
        w.subject.jdbc.query("SELECT count(*) FROM relay_key_registration WHERE state <> 'done' OR inflight <> 0") {
            if (it.long(0) > 0) out += "${it.long(0)} registration(s) still pending or in flight"
        }
        return out
    }

    override fun finalChecks(w: World) {
        val chan = ns ?: violation("S-R: no namespace")
        val fay = w.subject
        for (node in w.relays) {
            for (kind in kinds) {
                val relayKind = if (kind == KeyKind.DEPOSIT) ModelRelay.KIND_DEPOSIT else ModelRelay.KIND_READ
                if (node.model.record(chan, week, relayKind, fay.verifier(chan, kind)) == null) {
                    violation("S-R: ${node.name} holds no $kind record for the channel")
                }
            }
        }
        fay.jdbc.query("SELECT kind, state FROM relay_capability") {
            if (it.string(1) != "usable") violation("S-R: the write slot ended ${it.string(1)}, the bearer credential was refused somewhere")
        }
        fay.jdbc.query("SELECT count(*) FROM relay_register_capability WHERE state = 'usable'") {
            if (it.long(0) != w.relays.size.toLong()) violation("S-R: ${it.long(0)} usable registration capabilities, one per relay expected")
        }
    }
}

/**
 * S-R/funding-flip (Phase 10 review of S1a, finding on the harness driver). A funder's background session
 * starts with its four registrations due (a funded channel, registration capabilities installed), each
 * pair's work waiting for its keyed offset in the job window. Seconds later the funding flag is taken off
 * from the script — a commit outside any lane item, as S6's renewal step will make — which the engine
 * answers by refreshing the pairs: the unfunded LOCAL channel has no capability that serves a registration
 * (its write slot holds the bearer credential), so the work the session waited for is gone, both lanes are
 * idle and no lane has a wake time. The production runner wakes on that change and ends the session; a driver
 * that takes an item only when a lane has a wake time never did, and left the session online for ever, so
 * that no later session started (seed 9 of a funded seeded world: "no quiescence"). The flag is put back at
 * minute 30 and later sessions register everything.
 */
internal class ScenarioFundingFlip : Scenario("S-R/funding-flip") {
    private val kinds = listOf(KeyKind.DEPOSIT, KeyKind.READ)
    private var ns: NamespaceId? = null
    private var week = 0L

    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val relays = listOf(a, b)
        // HIGH mode, where a registration is work of its pair's event (STANDARD runs them in the session's
        // first maintenance pass), and a five-minute window for the keyed offsets of the pairs' events.
        val fay = subject(w, "fay", mode = PrivacyMode.HIGH, policy = TrafficPolicy(listLimit = 4, backgroundWindowMillis = 5 * MINUTE))
        val chan = fay.namespace("chan", relays, listen = false, consumer = Consumer.CHANNEL, capabilitySource = CapabilitySource.LOCAL)
        ns = chan
        relays.forEach { fay.depositCredential(it, chan) }
        week = ModelRelay.week(w.relayNow(a))
        fay.tx { tx ->
            fay.stores.funding.set(tx, chan, true)
            for (node in relays) for (kind in kinds) fay.stores.registrations.request(tx, fay.id(node), chan, week, kind, fay.verifier(chan, kind))
        }
        relays.forEach { fay.capability(it, chan, CapabilityKind.REGISTER, validSeconds = thisWeekValidSeconds(w, it)) }
        // The background session starts at minute 1 and is online within seconds; the flag goes off ten
        // seconds in, before the pairs' events have fired their registrations.
        w.jobs(fay, MINUTE, MINUTE)
        w.at(MINUTE + 10 * SECOND, "funding off, outside any lane item") { fay.tx { tx -> fay.stores.funding.set(tx, chan, false) } }
        // Thirty seconds later the session the flip emptied has ended, on its own: nothing else has touched
        // it (the flag goes back on at minute 30, which would give it work to wake for).
        w.at(MINUTE + 40 * SECOND, "the emptied session has ended") {
            val s = fay.session
            if (s != null) violation("S-R/funding-flip: $s still runs 30 s after the funding flip took its work away (the driver never re-checked its end)")
        }
        w.at(30 * MINUTE, "funding on") { fay.tx { tx -> fay.stores.funding.set(tx, chan, true) } }
        w.jobs(fay, 31 * MINUTE, 41 * MINUTE, every = 5 * MINUTE)
        w.endMillis = 45 * MINUTE
    }

    private fun thisWeekValidSeconds(w: World, node: RelayNode): Long = ModelRelay.weekStart(week + 1) + 3_600 - w.relayNow(node)

    override fun renewalValidSeconds(w: World, node: RelayNode, need: CapabilityNeed): Long =
        if (need.kind == CapabilityKind.REGISTER) thisWeekValidSeconds(w, node) else super.renewalValidSeconds(w, node, need)

    override fun extraQuiescence(w: World): List<String> {
        val out = ArrayList<String>()
        w.subject.jdbc.query("SELECT count(*) FROM relay_key_registration WHERE state <> 'done' OR inflight <> 0") {
            if (it.long(0) > 0) out += "${it.long(0)} registration(s) still pending or in flight"
        }
        return out
    }

    override fun finalChecks(w: World) {
        val chan = ns ?: violation("S-R/funding-flip: no namespace")
        val fay = w.subject
        for (node in w.relays) {
            for (kind in kinds) {
                val relayKind = if (kind == KeyKind.DEPOSIT) ModelRelay.KIND_DEPOSIT else ModelRelay.KIND_READ
                if (node.model.record(chan, week, relayKind, fay.verifier(chan, kind)) == null) {
                    violation("S-R/funding-flip: ${node.name} holds no $kind record for the channel")
                }
            }
        }
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
        // MD-1 (2026-11-13): on a DM pair the receipt verifies at once and no check follows, so
        // the ack-and-drop strike path this scenario exercises runs on CHANNEL pairs.
        val ns1 = erin.namespace("dm1", listOf(a, b, c, d), listen = false, consumer = Consumer.CHANNEL)
        listOf(a, b, c, d).forEach { erin.capability(it, ns1) }
        val ns2 = erin.namespace("dm2", listOf(a, b), listen = false, consumer = Consumer.CHANNEL)
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

/**
 * Listening turned on later (S9 findings #1 and #4): the subject posts to a channel and to a DM
 * namespace it does not listen to, then subscribes to the channel (`setListening`) and registers the
 * DM namespace again with `listen = true`, while its ops still exist (the consumer is paused until
 * then, so nothing is released or collected before). Others write into both namespaces. The consumer
 * is never offered its own blobs (IN-2) and consumes every other blob once (IN-1). Mutant M14
 * NoOwnTombstone is detected here.
 */
internal class ScenarioListenLater : Scenario("S-L/listen-later") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 3)
        val lena = subject(w, "lena", consumer = ConsumerPolicy(paused = { it.clock.millis < 12 * MINUTE }))
        val chan = lena.namespace("chan", listOf(a, b, c), listen = false, consumer = org.ghost.sync.api.Consumer.CHANNEL)
        listOf(a, b, c).forEach { lena.capability(it, chan) }
        val dm = lena.namespace("dm", listOf(a, b), listen = false)
        listOf(a, b).forEach { lena.capability(it, dm) }
        w.otherWrite(a, chan, "c1")
        w.otherWrite(b, chan, "c1")
        w.otherWrite(c, chan, "c2")
        w.otherWrite(a, dm, "d1")
        w.otherWrite(b, dm, "d1")
        w.at(0, "enqueue op1") { lena.enqueue("op1", chan) }
        w.at(0, "enqueue op2") { lena.enqueue("op2", dm) }
        w.jobs(lena, MINUTE, MINUTE)
        w.at(10 * MINUTE, "subscribe to chan") {
            lena.tx { lena.stores.namespaces.setListening(it, chan, true) }
            lena.listening += chan
        }
        w.at(10 * MINUTE, "register dm listening") { lena.namespace("dm", listOf(a, b), listen = true) }
        w.at(12 * MINUTE, "enqueue op3") { lena.enqueue("op3", chan) }
        w.jobs(lena, 16 * MINUTE, 46 * MINUTE)
        w.endMillis = 60 * MINUTE
    }
}

/**
 * A forward clock step after READY, while offline (S9 finding #2): the foreground reaches READY,
 * fetches and consumes four blobs; at 20 minutes a transport fault (`closed`) takes it offline and
 * the network stays down until 3 h; at 25 minutes the device date jumps 120 days forward and is
 * corrected at 2 h, so the hourly GC comes due on the stepped clock while offline. GC must not trust
 * it: the tombstones it would delete are still live on both relays (retention check, IN-2).
 */
internal class ScenarioClockStepOffline : Scenario("S-K/clock-step-offline") {
    private var faulted = false

    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val kai = subject(w, "kai")
        val ns = kai.namespace("inbox", listOf(a, b), listen = true)
        kai.capability(a, ns, CapabilityKind.READ)
        kai.capability(b, ns, CapabilityKind.READ)
        for (i in 1..4) {
            w.otherWrite(a, ns, "h$i")
            w.otherWrite(b, ns, "h$i")
        }
        w.foreground(kai, 0, 4 * HOUR)
        var fault = false
        w.at(20 * MINUTE, "network down") {
            fault = true
            kai.offlineWindows += 20 * MINUTE until 3 * HOUR
        }
        w.relayHook = { client, kind, _ ->
            if (fault && client === kai && kind == EventKind.RELAY_BEFORE_SEND) {
                fault = false
                faulted = true
                w.scriptState++
                "closed"
            } else {
                null
            }
        }
        w.at(25 * MINUTE, "clock jumps 120 days forward") { w.clock.deviceOffsetSeconds += 120 * 86_400L }
        w.at(2 * HOUR, "clock corrected") { w.clock.deviceOffsetSeconds -= 120 * 86_400L }
        w.endMillis = 4 * HOUR + 15 * MINUTE
    }

    override fun finalChecks(w: World) {
        if (!faulted) violation("S-K: the transport fault never happened")
        if (w.otherBlobs.size != 4) violation("S-K: unexpected blobs")
    }
}

/**
 * S-M media (Phase 11 design §5.5 and §13.3: the sync-exit-gate's worlds gain a media consumer with
 * bursts of 17 and 129 blobs): a card holder floods the subject's media namespace `M` with a burst
 * of [burst] blobs — 17 is three fetch slices of 8, 129 exceeds a background event's media fetch
 * budget of 128, so the last blob resumes at the pair's next event — while the subject uploads a
 * media op of its own (media stores run after the pass's non-media stores). The media lane's
 * slicing, event budgets and store rounds run under the crash enumeration.
 */
internal class ScenarioMedia(private val burst: Int) : Scenario("S-M/$burst") {
    override fun build(w: World) {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val mia = subject(w, "mia")
        val media = mia.namespace("media", listOf(a, b), listen = true, consumer = Consumer.MEDIA)
        mia.capability(a, media, CapabilityKind.READ)
        mia.capability(b, media, CapabilityKind.READ)
        mia.capability(a, media)
        mia.capability(b, media)
        w.at(0, "a card holder deposits a burst of $burst") {
            for (i in 1..burst) w.otherWrite(if (i % 2 == 0) a else b, media, "m$i")
        }
        w.at(3 * MINUTE, "mia uploads a photo") { mia.enqueue("up1", media) }
        w.jobs(mia, MINUTE, 31 * MINUTE)
        w.endMillis = 45 * MINUTE
    }

    override fun finalChecks(w: World) {
        // Every blob of the burst reached the consumer exactly once (IN-1/IN-2 are the harness's).
        var consumed = 0L
        w.subject.jdbc.query(
            "SELECT count(*) FROM oracle_consumed WHERE namespace_id = ?1",
            listOf(w.subject.namespaces.getValue("media").toByteArray()),
        ) { consumed = it.long(0) }
        if (consumed != burst.toLong()) violation("S-M: $consumed of $burst burst blobs consumed")
    }
}
