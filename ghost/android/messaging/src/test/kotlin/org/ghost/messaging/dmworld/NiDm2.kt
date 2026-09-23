package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.Timer

/**
 * NI-DM2 (Phase 9 design §15.6): "message type and session state at equal body length (first vs
 * later, intro vs provisional vs pair, text vs TIMER_SET vs CONTROL, with and without pending PQ
 * TLVs)" — P-4's "no type, state or sender in sizes or bytes", as a twin.
 *
 * **The twins.** One world per [Variant] — a session state crossed with a message kind — and in
 * every world the same pairs of clients: pair `k` is A = `2k` and B = `2k + 1`, and it exists for
 * the body length `LENGTHS[k]`. Every twin runs the same seed, so a pair's cards, namespaces, relay
 * sets and deposit credentials are the same in every world; the worlds differ only in how pair `k`
 * reached the state in which A seals its one message **M** of `LENGTHS[k]` body bytes to B at `t0`,
 * and in what M is:
 *  - [State.INTRO]: A scans B's card at `t0` and M is its first message (intro mode);
 *  - [State.PROVISIONAL]: B scanned A's card six hours earlier and wrote; at `t0` A's user accepts
 *    the request and M is A's first reply (provisional mode, A's root riding);
 *  - [State.PAIR_OFFER]: the pair met in person a day earlier (A wrote, B accepted and answered with
 *    its root); M is A's first pair-mode message, **its own root offer pending** and riding;
 *  - [State.PAIR]: the same, and A wrote once more pair-sealed and B answered under A's root, which
 *    acknowledged A's offer; M is a pair-mode message with **no offer pending** ("first vs later");
 *  - [State.RESET]: an established pair, and M is the `reset` control A's user's reset sends — a
 *    CONTROL, sealed intro mode after the re-establishment.
 * The kinds are a TEXT, a TEXT **quoting** B's newest message, a TIMER_SET (7 d → 1 d, whose TTL is
 * the larger bucket, 7 d, like the text's: R-T3), a REACTION to B's newest message with a one-byte
 * grapheme (16 + 1 body bytes), and the CONTROL. A kind appears at the lengths it can have: a
 * TIMER_SET and a CONTROL have no body (length 0), a REACTION's is 17 bytes, a quoted text is any
 * length and an unquoted one any but 0 ([lengthsOf] says why).
 * The lengths are R-B1's two class boundaries (2 220 | 2 221 and 14 508 | 14 509, §21.11 point 3),
 * the bodies a text shares with a TIMER_SET, a CONTROL or a REACTION (0, 17), and 3 000 and 15 000,
 * inside the 16 and 64 KiB classes, where an intro envelope's 1 425 bytes of overhead and a pair
 * envelope's 54 would put a bare Olm output in different classes. **Measured under PM-4** (a bucket
 * from the Olm output's length): the twins differ at 2 221, 14 509 and 15 000 — mostly by the TLVs
 * that ride, not by the seal mode: a pending root offer (a 1 194-byte `seal_root_pq` where the
 * slack admits it) or a `pq_key` pushes one state's output over a class the others stay under,
 * which is the "with and without pending PQ TLVs" axis showing itself. At 3 000 every state's
 * output crossed 4 KiB under that mutant (intros by their overhead, the others by their TLVs).
 *
 * **What is compared.** At each length, A's stores **into B's inbox** from `t0` to `t0 + 20 min`, as
 * `(op, relay slot, namespace, size, TTL, credential scope)` ([Store]), must be the same multiset in
 * every gating twin that has that length. The **second** of each store, counted from `t0`, is
 * compared too among the twins whose state needs **no establishment** (provisional and both pair
 * states: 51 of the 60 messages), so a send delay that depends on the session state shows. It is
 * not compared for an intro or a reset: those are stored when `EST-READY` runs, a couple of minutes
 * after the bundle arrives, and when that is is the relay's choice and declared (§21.7 point 6,
 * L7-D6) — inbound and send timing across that choice is NI-DM6's variable. Nor is the rest of the
 * view: the bundle fetch before an intro is establishment traffic (declared, §1.2).
 *
 * **What makes it able to fail.** Each twin must **reach its variable**, by the ground truth the
 * ports recorded, not by what the world meant to do: exactly one distinct blob in the compared
 * stores (M; a second is an extra store the comparison must see), sealed in the state's mode, of the
 * variant's kind and body length, quoted exactly when the variant quotes, and — for the two pair
 * states — with a root offer riding exactly in [State.PAIR_OFFER]. A twin that did not reach its
 * state fails the check and is **not compared** (so a "no store" is never mistaken for a difference
 * a mutant made, and equal views can never come from twins that were secretly the same). The report
 * line prints which modes, kinds and TLVs M actually carried.
 *
 * **Declared open defects** ([OPEN_DEFECTS]) are the one exception to "every twin gates", and each is
 * declared as the exact difference it makes, never as "any difference" (see [OpenDefect]).
 */
internal object NiDm2 {

    /**
     * The session state M is sealed in, the seal mode it must produce, whether an offer rides, and
     * whether reaching it at `t0` takes an establishment (whose timing is the relay's).
     */
    enum class State(val mode: DmSeal.Mode, val offer: Boolean?, val establishes: Boolean) {
        INTRO(DmSeal.Mode.INTRO, null, true),
        PROVISIONAL(DmSeal.Mode.PROVISIONAL, null, false),
        PAIR_OFFER(DmSeal.Mode.PAIR, true, false),
        PAIR(DmSeal.Mode.PAIR, false, false),
        RESET(DmSeal.Mode.INTRO, null, true),
    }

    /** What M is. */
    enum class Kind(val wire: DmContent.Kind, val quoted: Boolean) {
        TEXT(DmContent.Kind.TEXT, false),
        QUOTED(DmContent.Kind.TEXT, true),
        TIMER_SET(DmContent.Kind.TIMER_SET, false),
        REACTION(DmContent.Kind.REACTION, false),
        CONTROL(DmContent.Kind.CONTROL, false),
    }

    class Variant(val state: State, val kind: Kind) {
        val name: String get() = "${state.name}/${kind.name}"

        override fun toString(): String = name
    }

    /** The body lengths, one pair of clients each (see the class comment). */
    val LENGTHS: List<Int> = listOf(0, 17, 2_220, 2_221, 3_000, 14_508, 14_509, 15_000)

    /** A REACTION's body: the 16-byte target and a one-byte grapheme. */
    private const val REACTION_BYTES = 17

    private const val GRAPHEME = "x"

    /**
     * The lengths each kind is sent at. An **unquoted empty text is not sent**: the codec accepts
     * one, but `dm_message.body_env`'s CHECK (`length BETWEEN 30 AND 61485`, §13.6) refuses the
     * 29-byte envelope of a one-byte flags field, so `Messaging.send(contact, "", null)` throws a
     * CHECK abort out of the facade — an engine finding of this slice (§22.20), not a privacy one.
     * A quoted empty text carries the 16-byte reference and is stored, so length 0 compares a
     * quoted text, a TIMER_SET and a CONTROL, all bodiless.
     */
    fun lengthsOf(kind: Kind): List<Int> = when (kind) {
        Kind.TEXT -> LENGTHS.filter { it > 0 }
        Kind.QUOTED -> LENGTHS
        Kind.TIMER_SET, Kind.CONTROL -> listOf(0)
        Kind.REACTION -> listOf(REACTION_BYTES)
    }

    /** Every twin: each state with each kind it can send (an intro quotes and reacts to nothing). */
    val VARIANTS: List<Variant> = buildList {
        add(Variant(State.INTRO, Kind.TEXT))
        add(Variant(State.INTRO, Kind.TIMER_SET))
        for (state in listOf(State.PROVISIONAL, State.PAIR_OFFER, State.PAIR)) {
            for (kind in listOf(Kind.TEXT, Kind.QUOTED, Kind.TIMER_SET, Kind.REACTION)) add(Variant(state, kind))
        }
        add(Variant(State.RESET, Kind.CONTROL))
    }

    /**
     * One of A's stores into B's inbox as the relay saw it; its second is kept apart ([Slot.seconds]).
     * The namespace is B's inbox by construction and printed short.
     */
    data class Store(val slot: Int, val namespace: String, val size: Int, val ttl: Long, val scope: String?) {
        override fun toString(): String = "slot $slot size=$size ttl=$ttl scope=$scope"
    }

    private val STORE_ORDER: Comparator<Store> =
        compareBy<Store>({ it.slot }, { it.namespace }, { it.size }, { it.ttl }, { it.scope })

    /**
     * An **open engine defect** a twin reproduces, declared as exactly the difference it makes: at
     * [length], the twin [variant]'s stores must equal the view every gating twin at that length agrees
     * on with **one** field changed — every store's TTL [reproducedTtl] where the others store
     * [gatedTtl] — and every other field (size, relay slot, namespace, credential scope, the number
     * of stores) equal. Everything else fails the check: the views equal (the defect was fixed and
     * the entry must go), another TTL (a partial fix, or a new bug on the same path), a difference
     * in any other field, the other twins no longer storing [gatedTtl], or the twin not having run or
     * not having reached its variable. So a declaration can neither turn into a silent pass nor
     * excuse a difference it does not name.
     */
    class OpenDefect(
        val variant: String,
        val length: Int,
        val gatedTtl: Long,
        val reproducedTtl: Long,
        val what: String,
    ) {
        /** The view the defect twin must store, given the gating twins' shared view. */
        fun expected(consensus: List<Store>): List<Store> = consensus.map { it.copy(ttl = reproducedTtl) }.sortedWith(STORE_ORDER)
    }

    /**
     * Twins that reproduce an open engine defect this check found and the S11b slice did not fix
     * (§22.20 item 2). They are compared apart from the rest, each against its exact declaration
     * ([OpenDefect]), and the report line prints what each reproduced.
     *
     * **INTRO/TIMER_SET**: a TIMER_SET sent before a session exists waits as a pending item, and
     * `SendStep`'s flush at `EST-READY` (and its FAILED retry) takes the TTL from the L0's timer
     * code — the **new** bucket — where the send path takes R-T3's larger of the old and the new
     * (`DmTimers.timerSetBucket`). A first-flight change from 7 d to 1 d is stored for a day, where
     * the same body as a text is stored for seven: the relay reads the kind off the TTL (P-4), and a
     * recipient offline for more than a day never learns of the change (R-T3). By the same code (read,
     * not run here), a new timer of 1 h makes the flush's deadline check fail the item as expired
     * once an establishment takes more than an hour, where R-T4 gives it seven days.
     */
    val OPEN_DEFECTS: List<OpenDefect> = listOf(
        OpenDefect(
            variant = "INTRO/TIMER_SET",
            length = 0,
            gatedTtl = 604_800,
            reproducedTtl = 86_400,
            what = "R-T3 on the pending path: SendStep's EST-READY flush takes the TTL of the new timer, " +
                "not the larger of the old and the new (§22.20)",
        ),
    )

    /** The compared window after `t0`: A's session, `EST-READY` and the flush all fall inside it. */
    private const val WINDOW: Long = 20 * DmWorld.MINUTE

    /** One pair of one twin: the stores compared, and what the ground truth says M was. */
    class Slot(
        val variant: Variant,
        val length: Int,
        val view: List<Store>,
        /** The second of each store of [view], counted from `t0`, sorted. */
        val seconds: List<Long>,
        val blobs: Int,
        val mode: DmSeal.Mode?,
        val content: GroundTruth.Content?,
        val action: String,
    ) {
        /** Null when the twin reached its variable; otherwise why not. */
        val unreached: String?
            get() = when {
                blobs != 1 -> "$blobs distinct blobs in B's inbox in the window, not 1 ($action)"
                content == null || mode == null -> "no recorded content or mode for M ($action)"
                mode != variant.state.mode -> "sealed ${mode.name}, not ${variant.state.mode.name}"
                content.kind != variant.kind.wire -> "kind ${content.kind}, not ${variant.kind.wire}"
                content.bodyLength != length -> "body ${content.bodyLength}, not $length"
                content.quoted != variant.kind.quoted -> "quoted ${content.quoted}, not ${variant.kind.quoted}"
                variant.state.offer != null && content.offer != variant.state.offer ->
                    "a root offer rode: ${content.offer}, the state needs ${variant.state.offer} (TLVs ${content.tlvs})"
                else -> null
            }
    }

    class Result(val slots: List<Slot>, private val declared: List<OpenDefect> = OPEN_DEFECTS) {
        private fun declaration(s: Slot): OpenDefect? = declared.firstOrNull { it.variant == s.variant.name && it.length == s.length }

        /** Twins that did not reach their variable: each makes the check fail. */
        val unreached: List<String>
            get() = slots.mapNotNull { s -> s.unreached?.let { "${s.variant} at ${s.length}: $it" } }

        /** The messages the comparison gates on: every one but a declared open defect's. */
        private val gating: List<Slot> get() = slots.filter { declaration(it) == null }

        /**
         * The gating messages actually compared: those whose twin reached its variable. A twin that
         * did not already fails the check through [unreached]; comparing its (empty or extra) stores
         * as well would let a twin that never got there pass for a difference in the view.
         */
        private val compared: List<Slot> get() = gating.filter { it.unreached == null }

        /** The compared messages whose state needs no establishment: their store seconds gate too. */
        private val timed: List<Slot> get() = compared.filter { !it.variant.state.establishes }

        /** Per length, the compared twins grouped by their view: more than one group is a difference. */
        val differences: List<String>
            get() = compared.groupBy { it.length }.toSortedMap().mapNotNull { (length, atLength) ->
                val groups = atLength.groupBy { it.view }
                if (groups.size <= 1) {
                    null
                } else {
                    "differ at body length $length: " + groups.entries.joinToString(" vs ") { (view, twins) ->
                        "${twins.joinToString(",") { it.variant.name }} -> ${summary(view)}"
                    }
                }
            }

        /** Per length, the timed twins grouped by the seconds of their stores after `t0`. */
        val timing: List<String>
            get() = timed.groupBy { it.length }.toSortedMap().mapNotNull { (length, atLength) ->
                val groups = atLength.groupBy { it.seconds }
                if (groups.size <= 1) {
                    null
                } else {
                    "store seconds after t0 differ at body length $length: " +
                        groups.entries.joinToString(" vs ") { (seconds, twins) ->
                            "${twins.joinToString(",") { it.variant.name }} -> $seconds"
                        }
                }
            }

        /**
         * Each declared open defect against its declaration: `true` with what it reproduced, or
         * `false` with why it is not the declared defect any more (see [OpenDefect]).
         */
        val defects: List<Pair<Boolean, String>>
            get() = declared.map { d ->
                val at = "${d.variant} at ${d.length}"
                val s = slots.singleOrNull { it.variant.name == d.variant && it.length == d.length }
                    ?: return@map false to "$at: declared, but no such twin ran"
                s.unreached?.let { return@map false to "$at: did not reach its variable ($it), so nothing was reproduced" }
                val consensus = compared.filter { it.length == d.length }.map { it.view }.distinct()
                if (consensus.size != 1) return@map false to "$at: no single view of the other twins to compare it with"
                val others = consensus.single()
                val expected = d.expected(others)
                when {
                    others.isEmpty() || others.any { it.ttl != d.gatedTtl } ->
                        false to "$at: the other twins store ${summary(others)}, not the declared ttl=${d.gatedTtl}: " +
                            "the declaration no longer describes the world"
                    s.view == others ->
                        false to "$at: the declared open defect no longer reproduces (its stores equal the other " +
                            "twins'): remove it from NiDm2.OPEN_DEFECTS"
                    s.view != expected ->
                        false to "$at differs from the other twins otherwise than declared: it stores ${summary(s.view)} " +
                            "where the declaration expects ${summary(expected)}"
                    else -> true to "$at stores ttl=${d.reproducedTtl} where the other twins store ttl=${d.gatedTtl}, " +
                        "every other field equal, at ${s.view.size} relays — ${d.what}"
                }
            }

        /** Comparisons made: at each length, every compared twin against the first. */
        val comparisons: Int get() = compared.groupBy { it.length }.values.sumOf { it.size - 1 }

        /** Comparisons of the store seconds: at each length, every timed twin against the first. */
        val timedComparisons: Int get() = timed.groupBy { it.length }.values.sumOf { it.size - 1 }

        val passed: Boolean
            get() = unreached.isEmpty() && differences.isEmpty() && timing.isEmpty() && defects.all { it.first } &&
                comparisons > 0 && timedComparisons > 0 && slots.all { it.view.isNotEmpty() }

        fun line(): String {
            val lengths = slots.map { it.length }.distinct().sorted()
            val modes = slots.mapNotNull { it.mode?.name }.groupingBy { it }.eachCount().toSortedMap()
            val kinds = slots.mapNotNull { s -> s.content?.let { if (it.quoted) "QUOTED" else it.kind.name } }
                .groupingBy { it }.eachCount().toSortedMap()
            val tlvs = slots.mapNotNull { it.content?.tlvs }.groupingBy { it }.eachCount().toSortedMap()
            val sizes = slots.groupBy { it.length }.toSortedMap()
                .mapValues { (_, s) -> s.flatMap { v -> v.view.map { it.size } }.toSortedSet().joinToString("/") }
            val twins = slots.map { it.variant.name }.distinct()
            val reproduced = defects.filter { it.first }.map { it.second }
            val broken = defects.filterNot { it.first }.map { it.second }
            return buildString {
                append("dm NI-DM2: ${if (passed) "PASS" else "FAIL"} ${twins.size} twins at ${lengths.size} body lengths ")
                append("(${lengths.joinToString(", ")}); ${gating.size} of their ${slots.size} messages gate: A's stores ")
                append("of M into B's inbox equal at each length over $comparisons comparisons, and at the same second ")
                append("after t0 over $timedComparisons comparisons among the ${timed.size} messages whose state needs no ")
                append("establishment (an intro's or a reset's store waits for the bundle, whose timing is the relay's, ")
                append("§21.7 point 6); M sealed $modes, kinds $kinds, TLVs that rode $tlvs; sizes by length $sizes")
                if (reproduced.isNotEmpty()) {
                    append("; ${reproduced.size} declared open defect${if (reproduced.size == 1) "" else "s"}, not gated, ")
                    append("reproduced exactly as declared: ${reproduced.joinToString("; ")}")
                }
                if (broken.isNotEmpty()) append("; declared open defect not reproduced as declared: ${broken.joinToString("; ")}")
                if (unreached.isNotEmpty()) append("; twins that did not reach their variable: ${unreached.joinToString("; ")}")
                if (differences.isNotEmpty()) append("; ${differences.joinToString("; ")}")
                if (timing.isNotEmpty()) append("; ${timing.joinToString("; ")}")
            }
        }

        /** A view, store by store (relay slot, size, TTL, credential scope). */
        private fun summary(view: List<Store>): String =
            if (view.isEmpty()) "no store" else view.joinToString(" | ") + " (${view.size} stores)"
    }

    fun run(seed: Long, mutant: PrivacyMutant? = null): Result =
        Result(VARIANTS.flatMap { twin(seed, it, mutant) })

    private fun a(k: Int): Int = 2 * k

    private fun b(k: Int): Int = 2 * k + 1

    fun twin(seed: Long, variant: Variant, mutant: PrivacyMutant?): List<Slot> {
        val slots = LENGTHS.indices.filter { LENGTHS[it] in lengthsOf(variant.kind) }
        val clients = 2 * (slots.max() + 1)
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        val t0 = start + DmWorld.DAY
        val met = variant.state in setOf(State.PAIR_OFFER, State.PAIR, State.RESET)
        // The in-person flow of every privacy world (§12.2): A scans B and writes, B accepts at its
        // first relay session that shows the request and answers with its root.
        val edges = if (met) {
            slots.map { k -> Plan.Edge(a(k), b(k), start + DmWorld.HOUR, reject = false, timer = Timer.DAYS_7, bursts = emptyList()) }
        } else {
            emptyList()
        }
        val plan = Plan.scripted(activation = LongArray(clients) { start }, edges = edges, seed = seed)
        val config = PrivacyWorldConfig(seed = seed, clients = clients, days = 2, mutant = mutant, plan = plan)
        PrivacyWorld(config).use { world ->
            val actions = HashMap<Int, String>()
            for (k in slots) {
                val a = a(k)
                val b = b(k)
                if (variant.state == State.PAIR || variant.state == State.RESET) {
                    // A's first pair message carries its root; B's answer under that root
                    // acknowledges it (R12), so A has no offer pending at t0.
                    world.schedule(t0 - 8 * DmWorld.HOUR) {
                        world.session(a, t0 - 8 * DmWorld.HOUR, 3, mapOf(0 to { world.userSend(a, b, 12) }))
                    }
                    world.schedule(t0 - 4 * DmWorld.HOUR) {
                        world.session(b, t0 - 4 * DmWorld.HOUR, 3, mapOf(0 to { world.userSend(b, a, 12) }))
                    }
                }
                if (variant.state == State.PROVISIONAL) {
                    world.schedule(t0 - 6 * DmWorld.HOUR) {
                        world.session(b, t0 - 6 * DmWorld.HOUR, 12, mapOf(0 to {
                            world.userAdd(b, a)
                            world.userSend(b, a, 12)
                        }))
                    }
                }
                world.schedule(t0) {
                    world.session(a, t0, 12, mapOf(0 to { actions[k] = act(world, variant, a, b, LENGTHS[k]) }))
                }
            }
            world.runUntil(t0 + WINDOW)
            return slots.map { k -> slot(world, variant, k, t0, actions[k] ?: "no action ran") }
        }
    }

    /** M: what A's user does at `t0`, after the session's first relay session read everything. */
    private fun act(world: PrivacyWorld, variant: Variant, a: Int, b: Int, length: Int): String {
        when (variant.state) {
            State.INTRO -> {
                val added = world.userAdd(a, b)
                if (added != AddContactResult.ADDED) return "the scan answered $added"
            }
            State.PROVISIONAL -> if (!world.userDecide(a, b, accept = true)) {
                return "no request from B to accept (trust ${world.trustOf(a, b)})"
            }
            else -> Unit
        }
        val contact = world.contactIdOf(a, b) ?: return "A holds no contact for B"
        val engine = world.clients[a].device.engine
        world.clients[a].sync()
        val result: SendResult? = when (variant.kind) {
            Kind.TEXT -> world.userSend(a, b, length)
            Kind.QUOTED -> world.userSend(a, b, length, newestIncoming(world, a, b) ?: return "nothing of B's to quote")
            Kind.TIMER_SET -> world.userSetTimer(a, b, Timer.DAY_1)
            Kind.REACTION -> engine.react(contact, newestIncoming(world, a, b) ?: return "nothing of B's to react to", GRAPHEME)
            Kind.CONTROL -> engine.resetSession(contact)
        }
        return "${variant.kind.name.lowercase()} answered $result"
    }

    private fun newestIncoming(world: PrivacyWorld, a: Int, b: Int): MessageId? {
        val contact = world.contactIdOf(a, b) ?: return null
        return world.clients[a].device.engine.conversation(contact, 50, null).firstOrNull { !it.outgoing }?.id
    }

    private fun slot(world: PrivacyWorld, variant: Variant, k: Int, t0: Long, action: String): Slot {
        val a = a(k)
        val inbox = world.truth.clients[b(k)]?.inboxNamespace
        val stores = world.relay.events.filter {
            it.op == ViewOp.STORE && it.client == a && it.second >= t0 && it.second <= t0 + WINDOW &&
                inbox != null && inbox.contentEquals(it.namespace)
        }
        val view = stores.map { e ->
            Store(
                slot = e.relaySlot,
                namespace = Joins.hex(e.namespace).take(16),
                size = e.bytes!!.size,
                ttl = e.ttlSeconds!!,
                scope = e.credential?.let { Joins.hex(Joins.sha256(it)).take(12) },
            )
        }.sortedWith(STORE_ORDER)
        val blobs = stores.map { GroundTruth.Key(it.blobHash!!) }.distinct()
        val m = blobs.singleOrNull()
        return Slot(
            variant = variant,
            length = LENGTHS[k],
            view = view,
            seconds = stores.map { it.second - t0 }.sorted(),
            blobs = blobs.size,
            mode = m?.let { world.truth.modeOfBlob[it] },
            content = m?.let { world.truth.contentOfBlob[it] },
            action = action,
        )
    }
}
