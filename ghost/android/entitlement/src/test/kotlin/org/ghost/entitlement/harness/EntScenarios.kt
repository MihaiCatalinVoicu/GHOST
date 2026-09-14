package org.ghost.entitlement.harness

import org.ghost.entitlement.api.ActivationState
import org.ghost.entitlement.api.PayWith
import org.ghost.entitlement.engine.Grid
import org.ghost.entitlement.engine.RestoreScan
import org.ghost.identity.DropSeal
import org.ghost.identity.Invite
import org.ghost.identity.RootEntropy
import org.ghost.network.EntitlementCrypto
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.harness.CallKind
import org.ghost.sync.harness.EventKind
import org.ghost.sync.harness.Scenario
import org.ghost.sync.harness.World
import org.ghost.sync.harness.World.Companion.DAY
import org.ghost.sync.harness.World.Companion.HOUR
import org.ghost.sync.harness.World.Companion.MINUTE
import org.ghost.sync.harness.foreground
import org.ghost.sync.harness.jobs
import org.ghost.sync.store.Time
import java.security.SecureRandom
import org.ghost.sync.engine.SessionKind as SyncKind

/**
 * A scenario of the `:entitlement` harness (Phase 8 design §13.2): a Phase 7 scenario whose subject
 * carries the real entitlement engine. The quiescence tail does not play Phase 8 any more (§19.17
 * point 5): the engine's redeem lane fulfils the capability needs, and the tail's periodic jobs draw
 * their quiet runs from the production scheduler. Quiescence adds the engine's own conditions; the
 * end adds MS-6, the token accounting and the T3 canaries. The world starts on Friday of access week
 * 2975 at 08:00 UTC (invite epoch 743, credit and price epoch 228).
 */
internal abstract class EntScenario(name: String) : Scenario(name) {
    override val renewCapabilitiesInTail: Boolean get() = false

    /** A purchase recovering from a lost `BlindSign` waits for its next planned attempt (up to 22 days). */
    override val maxTailRounds: Int get() = 3_000

    lateinit var ent: EntWorld
    lateinit var alice: EntClient

    /** A mutant (design §13.5, test sources only): its SQL rewrites and its substitutions of [EntConfig]. */
    var mutant: EntMutant? = null
        set(value) {
            field = value
            mutation = value?.mutation
        }

    open fun config(): EntConfig = configured(EntConfig())

    /** [base] with this scenario's [mutant] applied; [namespaces] is the subject's namespace count (mutant M8). */
    protected fun configured(base: EntConfig, namespaces: Int = 0): EntConfig = mutant?.configure?.invoke(base, namespaces) ?: base

    /**
     * Relays A (operator 1, ES slot 0), B (operator 2, slot 1), C (operator 1, slot 2) and the armed
     * subject with its engine; the schedule is accepted before the armed phase.
     */
    protected fun standard(w: World, mode: PrivacyMode = PrivacyMode.STANDARD, genesis: Boolean = true): EntClient {
        val a = w.relay("A", 1)
        val b = w.relay("B", 2)
        val c = w.relay("C", 1)
        ent = EntWorld(w, listOf(a, b, c), config())
        val client = subject(w, "alice", mode = mode)
        client.directory(a, b, c)
        alice = ent.attach(client, genesis)
        alice.e().status()
        return alice
    }

    /** A scripted quiet run at [at] (a session start of the subject for the reboot logic). */
    protected fun World.quietRunAt(at: Long) =
        driver.scheduleSession(at, alice.c, "quiet:${alice.c.name}") { if (alice.c.session == null) alice.quietRun() }

    /** A scripted background session at [at]. */
    protected fun World.backgroundAt(at: Long) =
        driver.scheduleSession(at, alice.c, "job:${alice.c.name}") { if (alice.c.session == null) alice.c.startSession(SyncKind.BACKGROUND) }

    /** The user starts a purchase at [at] and, if none exists (a crash ended the first attempt), again at each of [retries]. */
    protected fun World.purchase(at: Long, payWith: PayWith, retries: List<Long>) {
        at(at, "startPurchase") { alice.e().startPurchase(payWith) }
        for (t in retries) at(t, "the user retries a purchase that never started") { if (alice.purchaseStates().none { it.first == "pack" }) alice.e().startPurchase(payWith) }
    }

    /** The user pays what the payment instructions show, at each of [times] (nothing when nothing is due). */
    protected fun World.payAt(times: List<Long>, fraction: Double = 1.0) {
        for (t in times) at(t, "pay") { alice.payInvoiced(fraction = fraction) }
    }

    /**
     * From [from] on, every 2 hours for 30 days, the user pays the rest of an invoice the app shows
     * that their wallet has not paid in full: a crash inside a payment loses that payment, and a flow
     * that recovers later than the script (its invoice on the `RequestInvoice` retry, a day on) is
     * paid all the same while its payment window is open. A check with nothing due asks nothing of
     * the engine.
     */
    protected fun World.keepPaying(from: Long) {
        var t = from
        while (t <= from + KEEP_PAYING_DAYS * DAY) {
            at(t, "the user pays what is due") { if (alice.unpaidInvoice()) alice.payInvoiced() }
            t += KEEP_PAYING_EVERY
        }
    }

    /**
     * From [from] on, every 6 hours for 30 days, the user buys a pack when the app shows them
     * uncovered ([EntClient.uncovered]): a purchase that crashes left `failed` with its capped
     * attempts spent (J9), a trial that is spent or over, are followed by a new purchase, as the
     * app's `ENTITLEMENT_NEEDED` asks. Credits first when
     * [payWith] is CREDITS, and XMR when they no longer cover the price.
     */
    protected fun World.keepBuying(from: Long, payWith: PayWith) {
        var t = from
        while (t <= from + KEEP_PAYING_DAYS * DAY) {
            at(t, "the user buys again when uncovered") {
                if (alice.uncovered()) {
                    val started = alice.e().startPurchase(payWith)
                    if (started == null && payWith != PayWith.XMR) alice.e().startPurchase(PayWith.XMR)
                }
            }
            t += KEEP_BUYING_EVERY
        }
    }

    /** Setup: tokens of the current week for every slot, eligible an hour ago. */
    protected fun accessTokens(week: Long, perSlot: Int) {
        val eligible = Time.floorMinute(alice.w.clock.epochSeconds()) - 3_600
        for (slot in 0..2) alice.addTokens("access", week, slot, perSlot, eligible)
    }

    /** A test's checks of this scenario's outcome, run at the end while the world is still open. */
    var outcome: ((EntScenario) -> Unit)? = null

    override fun extraQuiescence(w: World): List<String> = ent.quiescenceProblems()

    override fun finalChecks(w: World) {
        ent.finalChecks()
        outcome?.invoke(this)
    }

    protected companion object {
        const val WEEK0 = 2975L
        const val KEEP_PAYING_DAYS = 30L
        const val KEEP_PAYING_EVERY = 2 * HOUR
        const val KEEP_BUYING_EVERY = 6 * HOUR

        /** E-G's scripted days: a received credit's refresh is due on day 12, its retry a day later. */
        const val REFRESH_DAYS = 17L

        /** A deterministic random stream (sealed blobs and invite nonces of a scenario's setup). */
        fun seeded(label: String): SecureRandom = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(Bytes.sha256(Bytes.ascii(label))) }
    }
}

/**
 * E-A pack paid in XMR, the happy path (design §13.2): startPurchase, `RequestInvoice` in a quiet
 * run, payment and 10 confirmations, `BlindSign` at its first planned attempt, finalization; the
 * tokens become eligible at the next activation slot, the user then writes in the app and the redeem
 * lane fulfils the write needs at A and B.
 */
internal open class ScenarioEA(private val writes: Boolean = true) : EntScenario(if (writes) "E-A" else "E-A/no-writes") {
    override fun build(w: World) {
        val e = standard(w)
        val ns = e.c.namespace("dm", listOf(w.relays[0], w.relays[1]), listen = false)
        w.purchase(0, PayWith.XMR, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
        w.quietRunAt(MINUTE)
        w.quietRunAt(45 * MINUTE)
        w.keepPaying(20 * MINUTE)
        w.keepBuying(HOUR, PayWith.XMR)
        w.quietRunAt(5 * HOUR + 30 * MINUTE)
        if (writes) {
            // The user writes in the app once the tokens are eligible (Saturday morning).
            w.foreground(e.c, 22 * HOUR + 30 * MINUTE, 22 * HOUR + 45 * MINUTE)
            w.at(22 * HOUR + 31 * MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        }
        w.endMillis = 23 * HOUR
    }
}

/**
 * E-B underpay, top-up, confirm: half of the amount first, so the first planned `BlindSign` answers
 * UNDERPAID (non-final, the outstanding amount is stored); the rest later; the second planned attempt
 * signs; the tokens (weeks 2975…2979) are used on Monday after the week boundary.
 */
internal open class ScenarioEB : EntScenario("E-B") {
    override fun build(w: World) {
        val e = standard(w)
        val ns = e.c.namespace("dm", listOf(w.relays[0], w.relays[1]), listen = false)
        w.purchase(0, PayWith.XMR, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
        w.quietRunAt(MINUTE)
        w.quietRunAt(45 * MINUTE)
        w.payAt(listOf(20 * MINUTE), fraction = 0.5)
        w.quietRunAt(5 * HOUR + 30 * MINUTE)
        w.payAt(listOf(6 * HOUR))
        w.keepPaying(8 * HOUR)
        w.quietRunAt(52 * HOUR + 30 * MINUTE)
        w.foreground(e.c, 71 * HOUR, 71 * HOUR + 15 * MINUTE)
        w.at(71 * HOUR + MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        w.endMillis = 72 * HOUR
    }
}

/**
 * E-C expiry: never paid, the wallet synced; the third planned attempt (after the grace window) finds
 * the invoice EXPIRED, and the purchase is `expired` with its secrets wiped.
 */
internal class ScenarioECExpired : EntScenario("E-C/expired") {
    override fun build(w: World) {
        standard(w)
        w.purchase(0, PayWith.XMR, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
        w.quietRunAt(MINUTE)
        w.quietRunAt(45 * MINUTE)
        w.quietRunAt(5 * HOUR + 30 * MINUTE)
        w.quietRunAt(52 * HOUR + 30 * MINUTE)
        w.at(60 * HOUR, "the grace window passes") { ent.mine(2_891) }
        w.quietRunAt(112 * HOUR + 30 * MINUTE)
        w.endMillis = 113 * HOUR
    }
}

/**
 * E-C lost: never paid and the issuer's wallet stops being synced, so no answer is ever final; after
 * the fifth attempt of the fixed plan (the last at receipt + 20–22 days) the purchase is `lost` (the
 * J9 cap of 5 `BlindSign` per invoice, whatever the issuer answers).
 */
internal class ScenarioECLost : EntScenario("E-C/lost") {
    override fun build(w: World) {
        standard(w)
        w.purchase(0, PayWith.XMR, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
        w.quietRunAt(MINUTE)
        w.quietRunAt(45 * MINUTE)
        w.at(50 * MINUTE, "the issuer's wallet falls behind") { ent.issuer.synced = false }
        w.quietRunAt(5 * HOUR + 30 * MINUTE)
        w.quietRunAt(52 * HOUR + 30 * MINUTE)
        w.quietRunAt(112 * HOUR + 30 * MINUTE)
        w.quietRunAt(8 * DAY + HOUR)
        w.quietRunAt(22 * DAY + HOUR)
        w.endMillis = 22 * DAY + 2 * HOUR
    }
}

/**
 * E-D pack paid with credits: ten own credits of epoch 228 (the smallest covering set) are reserved
 * with the first `RequestInvoice`, the invoice (amount 0) is CONFIRMED at once, the first planned
 * `BlindSign` signs and the finalizing transaction deletes the credits.
 */
internal open class ScenarioED : EntScenario("E-D") {
    override fun build(w: World) {
        val e = standard(w)
        e.addTokens("credit", Grid.creditEpoch(WEEK0), null, 10, Time.floorMinute(w.clock.epochSeconds()) - 3_600)
        val ns = e.c.namespace("dm", listOf(w.relays[0], w.relays[1]), listen = false)
        w.purchase(0, PayWith.CREDITS, listOf(10 * MINUTE, 40 * MINUTE, 3 * HOUR))
        // Credits spent by an invoice the client never learned of are bought again, in XMR if need be.
        w.keepBuying(HOUR, PayWith.CREDITS)
        w.keepPaying(HOUR)
        w.quietRunAt(MINUTE)
        w.quietRunAt(45 * MINUTE)
        w.quietRunAt(5 * HOUR + 30 * MINUTE)
        w.foreground(e.c, 22 * HOUR + 30 * MINUTE, 22 * HOUR + 45 * MINUTE)
        w.at(22 * HOUR + 31 * MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        w.endMillis = 23 * HOUR
    }
}

/** An invite of another identity (INVITER) whose token is an INVITE token of epoch 743, deterministic. */
internal fun inviteText(ent: EntWorld, label: String): Pair<String, ByteArray> {
    val token = ent.mint(EntitlementCrypto.KIND_INVITE, Grid.inviteEpoch(2975))
    val inviter = RootEntropy.fromRaw(Bytes.sha256(Bytes.ascii("inviter|$label")))
    val today = Grid.day(ent.w.clock.epochSeconds())
    val invite = Invite.create(token, Grid.inviteEpoch(2975), today + 14, listOf(0, 1, 2), inviter.inviteKeys(0), SecureRandom.getInstance("SHA1PRNG").apply { setSeed(Bytes.sha256(Bytes.ascii("invite|$label"))) })
    return invite.encode() to token
}

/**
 * E-E trial with activation: a new identity activates an invite in the foreground (the trial and the
 * drop target in one transaction, the identity created, `RedeemInvite` as a user call); the trial's
 * tokens are eligible at once in STANDARD and fund the identity's first writes. A crash anywhere
 * resumes the pending trial at the next foreground; an activation that never started is retried.
 */
internal class ScenarioETrial : EntScenario("E-E/trial") {
    override fun build(w: World) {
        val e = standard(w, genesis = false)
        val (text, _) = inviteText(ent, "trial|${w.seed}")
        val ns = e.c.namespace("dm", listOf(w.relays[0], w.relays[1]), listen = false)
        w.foreground(e.c, 0, 20 * MINUTE)
        w.at(MINUTE, "activate") { e.e().activate(text) }
        w.at(3 * MINUTE, "enqueue op1") { if (e.identity.exists) e.c.enqueue("op1", ns) }
        for (t in listOf(30 * MINUTE, 90 * MINUTE)) {
            w.foreground(e.c, t - 5 * MINUTE, t + 15 * MINUTE)
            w.at(t, "the user activates again if nothing started") { if (e.e().activationState() == ActivationState.NONE) e.e().activate(text) }
            w.at(t + MINUTE, "enqueue op1") { if (e.identity.exists && "op1" !in w.ops) e.c.enqueue("op1", ns) }
        }
        w.endMillis = 2 * HOUR
    }
}

/**
 * E-E trial refused: the invite token was already redeemed with another request, so `RedeemInvite`
 * answers REPLAYED; the identity is wiped before the failure is recorded ("revoked invite fails
 * closed", design §8.3), and nothing is left but a failed trial row.
 */
internal class ScenarioEWipe : EntScenario("E-E/wipe") {
    override fun build(w: World) {
        val e = standard(w, genesis = false)
        val (text, token) = inviteText(ent, "wipe|${w.seed}")
        val base = Grid.week(w.clock.epochSeconds())
        val positions = checkNotNull(ent.schedule.positions(EntitlementCrypto.PRODUCT_TRIAL, base))
        ent.issuer.redeemInvite(token, base, Batch.blind(ent.schedule, Bytes.sha256(Bytes.ascii("another device")), positions), ent.issuerNow())
        w.foreground(e.c, 0, 20 * MINUTE)
        w.at(MINUTE, "activate") { e.e().activate(text) }
        w.foreground(e.c, 25 * MINUTE, 45 * MINUTE)
        w.at(30 * MINUTE, "the user activates again if nothing started") {
            if (e.e().activationState() == ActivationState.NONE && e.purchaseStates().isEmpty()) e.e().activate(text)
        }
        w.endMillis = HOUR
    }
}

/**
 * E-F redeem needs across a week boundary with EXHAUSTED and REJECTED: tokens of weeks 2975 and 2976;
 * a listened namespace on A and B; on Sunday the first writes redeem, relay A answers `quota` and B
 * `unauthorized` to a store (the capabilities become exhausted and rejected, and new tokens are
 * redeemed), the week's capabilities are renewed with next week's tokens before the boundary, and on
 * Monday the writes use them.
 */
internal class ScenarioEF : EntScenario("E-F") {
    override fun build(w: World) {
        val e = standard(w)
        accessTokens(WEEK0, 3)
        accessTokens(WEEK0 + 1, 3)
        val (a, b) = w.relays[0] to w.relays[1]
        val ns = e.c.namespace("ch", listOf(a, b), listen = true)
        var quota = false
        var refused = false
        w.relayHook = { client, kind, info ->
            when {
                client !== e.c || kind != EventKind.RELAY_BEFORE_SEND || info.kind != CallKind.STORE -> null
                !quota && info.relay == "A" -> {
                    quota = true
                    w.scriptState++
                    "quota"
                }
                !refused && info.relay == "B" -> {
                    refused = true
                    w.scriptState++
                    "unauthorized"
                }
                else -> null
            }
        }
        w.foreground(e.c, 48 * HOUR, 48 * HOUR + 10 * MINUTE)
        w.at(48 * HOUR + MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        w.at(48 * HOUR + 2 * MINUTE, "enqueue op2") { e.c.enqueue("op2", ns) }
        w.backgroundAt(60 * HOUR)
        w.foreground(e.c, 65 * HOUR + 30 * MINUTE, 65 * HOUR + 40 * MINUTE)
        w.at(65 * HOUR + 31 * MINUTE, "enqueue op3") { e.c.enqueue("op3", ns) }
        w.endMillis = 66 * HOUR
    }
}

/**
 * E-G drop send and receive: as an invitee the subject writes its credit to its inviter's drop at the
 * pre-drawn drop minute (the namespace registered on the three drop relays, the blob sealed and
 * enqueued in one transaction, the namespace retired once the outcome is released); as an inviter
 * it lists the drop of an invite it created, opens the credit an invitee sealed to it, and refreshes
 * it with `RefreshCredit` in a quiet run days later (one scripted quiet run a day until day 17; the
 * received credit is never spent itself).
 */
internal class ScenarioEG : EntScenario("E-G") {
    override fun build(w: World) {
        val e = standard(w)
        val now = w.clock.epochSeconds()
        val minute = Time.floorMinute(now)
        val week = Grid.week(now)
        accessTokens(week, 4)
        e.addTokens("credit", Grid.creditEpoch(week), null, 1, minute - 3_600)
        val ctx = checkNotNull(e.e().context())
        val inviterKeys = RootEntropy.fromRaw(Bytes.sha256(Bytes.ascii("inviter|drop|${w.seed}"))).inviteKeys(0)
        val mine = e.identity.root.inviteKeys(0)
        val inviteToken = ent.mint(EntitlementCrypto.KIND_INVITE, Grid.inviteEpoch(week))
        val invite = Invite.create(inviteToken, Grid.inviteEpoch(week), Grid.day(now) + 14, listOf(0, 1, 2), mine, seeded("my invite|${w.seed}"))
        val relays = w.relays.take(3)
        // The invite row as `createInvite` leaves it, with its refresh times set inside the script
        // (the first on day 12, the second after the listening): the rule that draws them
        // (`RefreshPlan.times`, weeks after the invite) is pinned by the policy vectors and DropStepsTest.
        // Day 12 leaves a day for the retry and keeps the finalized row inside its 7 GC days at the end.
        val listenUntil = Grid.day(now) + 14 + 56
        e.c.tx { tx ->
            ctx.invites.insertDropTarget(tx, inviterKeys.dropNamespace, inviterKeys.drop.publicKey, listOf(0, 1, 2), minute + 3_600, Grid.day(now) + 60)
            ctx.invites.insert(tx, 0, invite.bytes(), mine.dropNamespace, listenUntil, minute + 12 * Grid.DAY, (listenUntil + 1) * Grid.DAY)
            ctx.state.takeInviteIndex(tx, 0)
            e.c.stores.namespaces.register(tx, NamespaceId(mine.dropNamespace), Consumer.IDENTITY, relays.map { e.c.id(it) }.toSet(), true)
        }
        w.at(3 * HOUR, "an invitee writes its drop") {
            val credit = ent.dropCredit(Grid.creditEpoch(week))
            val blob = DropSeal.sealCredit(credit, mine.drop.publicKey, mine.dropNamespace, seeded("drop blob|${w.seed}"))
            for (r in relays.take(2)) r.model.inject(NamespaceId(mine.dropNamespace), blob, TtlBucket.DAYS_30.seconds.toLong(), w.relayNow(r))
        }
        w.foreground(e.c, 2 * HOUR, 2 * HOUR + 15 * MINUTE)
        w.foreground(e.c, 9 * HOUR, 9 * HOUR + 15 * MINUTE)
        w.foreground(e.c, 26 * HOUR, 26 * HOUR + 15 * MINUTE)
        // The received credit is refreshed at its invite's first refresh time, day 12 (§19.26): a quiet
        // run each day until day 17, so the refresh (and the identical retry a crash may make it take
        // a day later) falls inside the script instead of a quiescence tail of background sessions.
        for (day in 2..REFRESH_DAYS) w.quietRunAt(day * DAY + 10 * MINUTE)
        w.endMillis = REFRESH_DAYS * DAY + HOUR
    }
}

/**
 * E-J restore scan (design §8.4, §19.26): the device restores its identity from the backup in the
 * foreground (the scan recorded as owed for the restored root, indices 0..7 reserved, the identity
 * stored), and the foreground session's next pass, under its trusted clock, fixes the scan's end and
 * records the drops of invites 0..7, registered as listened on the ES slot relays, in one transaction;
 * an invitee of invite 2, created before the restore, wrote its credit into that drop at relay A; the
 * redeem lane spends 8 of the device's tokens per slot on read capabilities of the 8 drops at A, B and
 * C (every need is met, so no lane step retries a reservation without a token), the read lane fetches
 * the blob, the engine turns the credit into a refresh flow due at the scanned drop's refresh time,
 * 1–14 days after the scan ends (`RefreshPlan.scanned`, §19.26), a quiet run after the fifth week ends
 * the scan (GC closes the drops and forgets it), the refresh runs in one of the quiet runs scripted
 * each day until day 50 (a crash may make it take its identical retry a day later), and a quiet run on
 * day 58 lets GC delete its terminal row. A crash inside the restore ends with the scan owed (a later trusted relay session
 * installs it) or with no identity (the user restores again). In every run, crash runs included, the
 * harness requires the credit refreshed ([EntWorld.dropCredit]) and holds quiescence until the owed
 * scan is installed and, past its end, forgotten ([EntWorld.quiescenceProblems]).
 */
internal class ScenarioEJ : EntScenario("E-J") {
    override fun build(w: World) {
        val e = standard(w, genesis = false)
        val now = w.clock.epochSeconds()
        val week = Grid.week(now)
        // Tokens are not restored (E11): the device bought again, 8 per slot for this week.
        accessTokens(week, 8)
        val mnemonic = e.identity.root.toMnemonic()
        val keys = e.identity.root.inviteKeys(2)
        // Short foregrounds: the read lane lists every one of the 24 listened pairs about every 35 s.
        w.foreground(e.c, 0, 4 * MINUTE)
        w.at(MINUTE, "restore") { e.e().restore(mnemonic) }
        w.foreground(e.c, 29 * MINUTE, 33 * MINUTE)
        w.at(30 * MINUTE, "the user restores again if no identity") { if (!e.identity.exists) e.e().restore(mnemonic) }
        w.at(HOUR, "an invitee of a pre-restore invite writes its drop") {
            val credit = ent.dropCredit(Grid.creditEpoch(week))
            val blob = DropSeal.sealCredit(credit, keys.drop.publicKey, keys.dropNamespace, seeded("restore drop|${w.seed}"))
            val a = w.relays[0]
            a.model.inject(NamespaceId(keys.dropNamespace), blob, TtlBucket.DAYS_30.seconds.toLong(), w.relayNow(a))
        }
        // The read needs are due within 6 h of their first sighting (§12.4): redeemed, listed and fetched at 7 h;
        // the session at 26 h consumes a blob a crash left fetched.
        w.foreground(e.c, 7 * HOUR, 7 * HOUR + 5 * MINUTE)
        w.foreground(e.c, 26 * HOUR, 26 * HOUR + 5 * MINUTE)
        // The first quiet run after the scan's end closes the drops; the refresh is due 1–14 days after
        // that end (a scanned drop's refresh time, §19.26), so one quiet run a day covers it and a retry.
        for (day in RestoreScan.SCAN_DAYS + 1..RestoreScan.SCAN_DAYS + 15) w.quietRunAt(day * DAY + 10 * MINUTE)
        w.quietRunAt((RestoreScan.SCAN_DAYS + 23) * DAY + 10 * MINUTE)
        w.endMillis = (RestoreScan.SCAN_DAYS + 23) * DAY + HOUR
    }
}

/**
 * E-H payout claim: ten own credits; the claim (address checked, credits reserved, due at a random
 * time within a day) runs alone in a quiet run and is QUEUED; the credits are deleted and the address
 * is remembered as used.
 */
internal open class ScenarioEH : EntScenario("E-H") {
    override fun build(w: World) {
        val e = standard(w)
        e.addTokens("credit", Grid.creditEpoch(WEEK0), null, 10, Time.floorMinute(w.clock.epochSeconds()) - 3_600)
        val address = HarnessAddresses.standard("payout|${w.seed}")
        w.at(MINUTE, "claimPayout") { e.e().claimPayout(address) }
        w.at(30 * MINUTE, "the user claims again if nothing started") { if (count(e, "SELECT count(*) FROM ent_claim") == 0L) e.e().claimPayout(address) }
        for (t in listOf(12 * HOUR, 25 * HOUR, 26 * HOUR, 50 * HOUR)) w.quietRunAt(t)
        w.endMillis = 51 * HOUR
    }

    private fun count(e: EntClient, sql: String): Long {
        var n = 0L
        e.c.jdbc.query(sql) { n = it.long(0) }
        return n
    }
}

/**
 * Q29 (design §17, §19.23 point 5) lapsed capabilities, background only: the subject's listened
 * namespace on A and B holds only write capabilities that expired three days ago, an op waits, and
 * eligible tokens of the week are held; nothing but periodic jobs runs (no foreground at all). A
 * background session then has no read pair and no write pair, and ends right after its first pass;
 * because it started with a pending write need it stays open until the redeem lane has run one step,
 * which redeems at A and B, and a later background session stores the op.
 */
internal class ScenarioLapsed : EntScenario("Q29/lapsed") {
    /** Without the hold no background session ever redeems: a short tail makes that a quick failure. */
    override val maxTailRounds: Int get() = 4

    override fun config(): EntConfig = configured(EntConfig(dailyForegroundJobs = 0))

    override fun build(w: World) {
        val e = standard(w)
        accessTokens(WEEK0, 2)
        val (a, b) = w.relays[0] to w.relays[1]
        val ns = e.c.namespace("dm", listOf(a, b), listen = true)
        for (node in listOf(a, b)) e.c.capability(node, ns, validSeconds = -3 * DAY / 1_000)
        w.at(MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        w.jobs(e.c, 2 * MINUTE, 3 * HOUR)
        w.endMillis = 3 * HOUR
    }
}

/**
 * E-I `WRONG_PERIOD` re-prepare: on Sunday evening the device clock runs 7 hours ahead (Monday), so the
 * base week of the first `RequestInvoice` is outside the issuer's ±4 h tolerance; the issuer records
 * nothing, the engine closes the flow as failed and prepares a new one in the same transaction. The new
 * flow is the first one's retry (§19.23 point 2): it keeps the attempt count and the retry time drawn
 * with the first send, 20–28 h later, so the quiet run half an hour on makes no call. The clock is
 * corrected meanwhile; at its retry time the new flow sends its unsent base week, is invoiced (its
 * `BlindSign` plan from the second window, E5), paid and signed; the user writes in the app once the
 * tokens are eligible (the activation slot after the 139 h finalization lies in [160 h, 166 h)).
 */
internal open class ScenarioEI : EntScenario("E-I") {
    override fun build(w: World) {
        val e = standard(w)
        val ns = e.c.namespace("dm", listOf(w.relays[0], w.relays[1]), listen = false)
        w.at(58 * HOUR, "the device clock runs 7 hours ahead") { w.clock.deviceOffsetSeconds = 7 * 3_600 }
        w.purchase(58 * HOUR + MINUTE, PayWith.XMR, listOf(58 * HOUR + 10 * MINUTE))
        w.quietRunAt(58 * HOUR + 5 * MINUTE)
        w.at(58 * HOUR + 30 * MINUTE, "the device clock is corrected") { w.clock.deviceOffsetSeconds = 0 }
        w.quietRunAt(59 * HOUR)
        // From the first moment an invoice can exist: a crash before the first send leaves the flow
        // unsent, so the quiet run at 59 h sends it with the corrected clock and it is invoiced then.
        w.keepPaying(59 * HOUR + 30 * MINUTE)
        w.quietRunAt(86 * HOUR + 30 * MINUTE)
        w.quietRunAt(139 * HOUR)
        w.foreground(e.c, 166 * HOUR + 30 * MINUTE, 166 * HOUR + 45 * MINUTE)
        w.at(166 * HOUR + 31 * MINUTE, "enqueue op1") { e.c.enqueue("op1", ns) }
        // The WRONG_PERIOD spent the flow's first attempt, so a crash that loses the successor's answer
        // ends the flow with its cap spent (J9, §19.23 point 2): the user then buys again, as in E-A.
        w.keepBuying(166 * HOUR + 32 * MINUTE, PayWith.XMR)
        w.endMillis = 167 * HOUR
    }
}
