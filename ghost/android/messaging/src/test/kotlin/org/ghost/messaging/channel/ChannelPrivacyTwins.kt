package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * **The NI-CH twins of the channel privacy world** (Phase 10 design §12.7's NI-CH1 … NI-CH5; the
 * T40 row of §2.2 and §12.6): two worlds that differ only in what one client received (NI-CH1),
 * in a commit vs a post at the same minute (NI-CH2), in how many channels one funder funds at
 * fixed renewal times (NI-CH3), in a rotating vs a non-rotating received commit (NI-CH4, with the
 * declared LC-4 difference), or in one channel being password-protected and the other open
 * (NI-CH5, with the declared LC-4 rotation-rate difference) — give **identical relay views** of
 * every client except exactly where the design declares (LC-5/LC-6's pass outcomes, LC-3's count,
 * LC-4's rotation and namespace-switch effects).
 *
 * **The view** is S5c's trace (the twin harness) extended with the harness debts S11 paid
 * (§19.10): the register calls of the world's registration step, and the circuits of every serve
 * round with their open and close times. Aliases name the namespace shapes (the worlds' natively
 * drawn namespace bytes differ; §12.1 reads no native bytes).
 *
 * **F-S10-1's fork honesty for the twins** (§19.49's hand-off): NI-CH1's world-scale injection is
 * §12.1's fork-junk model — a blob sealed under the current epoch's key id that does not open,
 * which is exactly what honest cross-branch traffic looks like to the wrong branch (its hint
 * matches no key a member holds... rather: the recognition matches, the AEAD does not, the shape
 * F-S10-1 pins) — so the twin exercises the privacy world's fork-shaped noise without a fork.
 * NI-CH4's rotating twin models the rotation honestly: the draining namespace, the new
 * generation's namespace, and the removed member's unchanged listening are the declared LC-4
 * delta, not noise.
 */
internal object ChannelPrivacyTwins {

    /** One relay-visible act of a client (S5c's Act, extended with register and circuit kinds). */
    private class Act(val kind: String, val ns: String, val detail: String, val minute: Long) {
        override fun toString(): String = "$kind/$ns/$detail@$minute"
        override fun equals(other: Any?): Boolean = other is Act && toString() == other.toString()
        override fun hashCode(): Int = toString().hashCode()
    }

    private fun trace(
        w: ChannelWorld,
        client: ChannelClient,
        /** The world's recorded namespace map (generation per namespace, whatever client still rows it). */
        worldAliases: Map<String, Pair<ChannelId, Long>> = emptyMap(),
        channelIndex: Map<ChannelId, Int> = emptyMap(),
    ): List<Act> {
        val aliases = HashMap<String, String>()
        client.sql.query("SELECT hex(namespace_id), generation FROM ch_generation") {
            aliases[it.string(0).lowercase()] = "G${it.long(1)}"
        }
        client.sql.query("SELECT hex(ns) FROM ch_join WHERE ns IS NOT NULL") { aliases[it.string(0).lowercase()] = "JOIN" }
        var ext = 0
        // SQLite's hex() is uppercase on the host JDBC driver, ModelChannelRelay's hex is
        // lowercase: normalize both sides or every namespace aliases twice.
        fun alias(ns: String): String = aliases.getOrPut(ns.lowercase()) {
            val world = worldAliases[ns.lowercase()]
            if (world != null && channelIndex.containsKey(world.first)) {
                "X${channelIndex.getValue(world.first)}G${world.second}"
            } else {
                "EXT${ext++}#${ns.lowercase().take(10)}"
            }
        }
        val acts = ArrayList<Act>()
        for (s in w.relay.stored) {
            // Own-attributed stores, enqueued or injected (the staged-own pattern): a client
            // never sees an adversary's blob as one of its own acts.
            if (s.from != client.name) continue
            acts += Act("store", alias(ModelChannelRelay.hex(s.namespace)), "${s.purpose}:${s.ciphertext.size}", s.storedAt / DmWorld.MINUTE)
        }
        client.sql.query(
            "SELECT hex(namespace_id), kind, generation, state FROM relay_capability ORDER BY 1, 2, 3, 4",
        ) { acts += Act("capability", alias(it.string(0)), "${it.string(1)}:g${it.long(2)}:${it.string(3)}", 0) }
        client.sql.query(
            "SELECT hex(namespace_id), kind, period_id, state FROM relay_key_registration ORDER BY 1, 2, 3, 4",
        ) { acts += Act("registration", alias(it.string(0)), "${it.string(1)}:p${it.long(2)}:${it.string(3)}", 0) }
        client.sql.query("SELECT hex(namespace_id) FROM sync_namespace WHERE listening = 1 ORDER BY 1") {
            acts += Act("listening", alias(it.string(0)), "", 0)
        }
        for (e in w.relay.events) {
            when (e) {
                is ModelChannelRelay.RelayEvent.Register ->
                    if (e.client == client.name) acts += Act("register", alias(ModelChannelRelay.hex(e.namespace)), "${e.kind}:p${e.period}:${e.credentialKind}", e.at / DmWorld.MINUTE)
                is ModelChannelRelay.RelayEvent.Circuit ->
                    // The counter is the model's bookkeeping; the relay-visible truth is the
                    // circuit's open and close times.
                    if (e.client == client.name) acts += Act("circuit", "", "${e.openedAt}-${e.closedAt}", e.openedAt / DmWorld.MINUTE)
                else -> Unit
            }
        }
        return acts.sortedBy { it.toString() }
    }

    private fun assertSameView(what: String, a: List<Act>, b: List<Act>) {
        if (a == b) return
        val onlyA = a.toMutableList()
        for (x in b) onlyA.remove(x)
        val onlyB = b.toMutableList()
        for (x in a) onlyB.remove(x)
        throw AssertionError("$what: only-A=$onlyA only-B=$onlyB")
    }

    class TwinResult(val id: String, val passed: Boolean, val detail: String) {
        fun line(): String = "channel $id: ${if (passed) "PASS" else "FAIL"} $detail"
    }

    // --------------------------------------------------------------------------------------------- NI-CH1

    /**
     * NI-CH1 at the world scale (§12.7's header: the full 28-day, 60-client world is this slice's):
     * two runs of [ChannelPrivacyWorld] on one seed, twin B injecting a fork-junk blob (F-S10-1's
     * model) into one channel's namespace at day 14 — every client's view identical.
     */
    fun niCh1WorldScale(seed: Long): TwinResult {
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        var reportA: ChannelPrivacyWorld.Report? = null
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelPrivacyWorld(
                ChannelPrivacyWorld.Config(
                    seed = seed,
                    midRun = if (isB) ({ world ->
                        // Twin B only: a member-sized blob of the fork-junk shape in the big
                        // channel's namespace, sealed under the current epoch's key id — by a
                        // member still active at day 14 (the cast's earlier seats may be removal
                        // subjects by then).
                        val info = world.channels[0]
                        val carol = info.cast.first {
                            it.channel(info.id)?.state == ChannelState.ACTIVE && it !== info.owner
                        }
                        val junk = ByteArray(700) { (it * 7).toByte() }
                        world.world.relay.inject(
                            ChannelAdversary.namespace(carol, info.id),
                            ChannelAdversary.sealJunk(carol, info.id, junk), world.world.now, "ni-ch1-fork-junk",
                        )
                        // No pump here: the daily loop's own rounds serve the junk — an extra
                        // pump would add a serve round twin A has not, and the circuits (one per
                        // round) must stay pump-symmetric between the twins.
                    }) else null,
                )
            ).use { privacy ->
                val built = privacy.build()
                if (!isB) reportA = built.report
                // The trace reads the clients' databases: inside the world's lifetime. The
                // world's recorded namespace map backs the aliases — a namespace a client's own
                // rows lost to the drain sweep still aliases structurally (per channel and
                // generation), never by its natively drawn bytes.
                val index = built.channels.mapIndexed { i, info -> info.id to i }.toMap()
                for (c in built.clients) into[c.name] = trace(built.world, c, built.namespaces, index)
            }
        }
        var failures = 0
        for (name in tracesA.keys) {
            try {
                assertSameView("NI-CH1 world twin: the fork junk changes $name's view", tracesA.getValue(name), tracesB.getValue(name))
            } catch (e: AssertionError) {
                failures++
                if (failures == 1) throw e
            }
        }
        return TwinResult(
            "NI-CH1", failures == 0,
            "the 60-client, 28-day world twin (fork-junk injection in twin B, day 14): " +
                "${tracesA.size} clients' views identical; seed 0x${java.lang.Long.toHexString(seed)}",
        )
    }

    // --------------------------------------------------------------------------------------------- NI-CH2

    /**
     * NI-CH2: a committer stores a non-removing commit (twin B) vs a post of equal length (twin A)
     * at the same minute — identical views (§19.22: a non-removing own commit no longer holds the
     * committer's posts, so the comparison holds after the store too; both blobs seal to the class
     * floor, the relay cannot tell them apart).
     */
    fun niCh2(seed: Long): TwinResult {
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        var postSize = 0
        var equalSize = false
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val bob = w.client("bob")
                val carol = w.client("carol")
                val id = ChannelScenes.channelOf(w, owner, bob, carol)
                w.advance(8 * DmWorld.DAY)
                if (isB) {
                    // Twin B: the owner's PCS pass, its commit stored at minute m (the pass's time).
                    ChannelM20PcsDue.arm(owner, id, back = 8)
                    owner.sessionStart()
                    w.advance(6 * DmWorld.MINUTE)
                    owner.timePass()
                    w.pump()
                    w.quiesce()
                    w.pastSettleWindow()
                    w.quiesce()
                } else {
                    // Twin A: a post at the same minute m (STANDARD: stored in the same round) —
                    // the same 6-minute advance and the same settle-window shape the twin's
                    // session start + pass + settle took, with the owner's PCS clock re-armed to
                    // "not due" so the twin's settle passes store no commit: the twins differ in
                    // the one store only.
                    w.advance(6 * DmWorld.MINUTE)
                    ChannelScenes.post(owner, id, "aceeasi minut")
                    w.pump()
                    w.quiesce()
                    ChannelM20PcsDue.arm(owner, id, back = 0)
                    w.pastSettleWindow()
                    w.quiesce()
                }
                w.advance(DmWorld.DAY)
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
                for (c in listOf(owner, bob, carol)) into[c.name] = trace(w, c)
                // Equal length: both blobs seal to the class floor bucket — the relay cannot tell
                // a commit's blob from a post's (PC-3's counterfactual, measured here).
                if (isB) {
                    val commit = w.relay.stored.last { it.purpose == "commit" && !it.injected }
                    equalSize = commit.ciphertext.size == postSize
                } else {
                    postSize = w.relay.stored.last { it.purpose == "post" && !it.injected }.ciphertext.size
                }
            }
        }
        // The stores' purpose label is ground truth, not relay-visible (NI-CH2's whole point: a
        // commit and a post are the same relay view) — compare the stores with the label masked.
        fun masked(acts: List<Act>): List<Act> = acts.map {
            if (it.kind == "store") Act(it.kind, it.ns, "blob:" + it.detail.substringAfter(":"), it.minute) else it
        }
        for (name in listOf("owner", "bob", "carol")) {
            assertSameView(
                "NI-CH2: the commit vs the post changes $name's view",
                masked(tracesA.getValue(name)), masked(tracesB.getValue(name)),
            )
        }
        return TwinResult(
            "NI-CH2", equalSize,
            "a non-removing commit vs a post of equal length ($equalSize) at the same minute: " +
                "3 clients' views identical",
        )
    }

    // --------------------------------------------------------------------------------------------- NI-CH3

    /**
     * NI-CH3: [subject] funds 1 channel (twin A) vs 4 (twin B) at fixed renewal times — identical
     * per-namespace views; the count of funded namespaces is the declared LC-3 difference. G funds
     * the other three channels in twin A, so every namespace is registered in both twins; the
     * credentials are bearer tokens derived from the generation secret (JC-3's one scope), so the
     * relay cannot tell G's registration from [subject]'s.
     */
    fun niCh3(seed: Long): TwinResult {
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        val subject = "funder"
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val funder = w.client(subject)
                val other = w.client("other")
                // Four channels, the same two members in each (funders must name current members,
                // §5.3); the subject funds one of them in twin A and all four in twin B.
                val channels = (0 until 4).map { index ->
                    ChannelScenes.channelOf(w, owner, other, funder).let { id -> id to index }
                }
                channels.forEachIndexed { index, (id, _) ->
                    val funders = if (isB || index == 0) listOf(funder) else emptyList()
                    nameFunders(w, owner, id, funders)
                }
                // The renewal window: the week's last 23 h. Advance to it and run everyone's
                // time-triggered pass; the registrations are relay events.
                val weekStart = DmWorld.WEEK_ORIGIN + DmTime.week(w.now) * DmWorld.WEEK
                w.advance(weekStart + 6 * DmWorld.DAY + DmWorld.HOUR - w.now)
                for (c in w.clients) c.timePass()
                w.pump()
                w.quiesce()
                for (c in w.clients) into[c.name] = trace(w, c)
            }
        }
        // Every client's view is identical except the subject's own registration count (LC-3).
        for (name in tracesA.keys) {
            if (name == subject) continue
            assertSameView("NI-CH3: the funding count changes $name's view", tracesA.getValue(name), tracesB.getValue(name))
        }
        val subjectA = tracesA.getValue(subject)
        val subjectB = tracesB.getValue(subject)
        val registrationsA = subjectA.count { it.kind == "registration" || it.kind == "register" }
        val registrationsB = subjectB.count { it.kind == "registration" || it.kind == "register" }
        // The declared delta is exactly the subject's own register acts on the other channels;
        // everything else of the subject's view is unchanged.
        val delta = subjectB.toMutableList()
        for (x in subjectA) delta.remove(x)
        val nonRegisterDelta = delta.count { it.kind != "registration" && it.kind != "register" }
        assertTrue("NI-CH3: the subject's delta is register acts only (LC-3): $delta", nonRegisterDelta == 0)
        assertTrue("NI-CH3: twin B funds more namespaces (LC-3)", registrationsB > registrationsA)
        return TwinResult(
            "NI-CH3", true,
            "1 vs 4 funded namespaces: every non-subject view identical; the subject's delta is " +
                "exactly its $registrationsA → $registrationsB register rows (LC-3, declared)",
        )
    }

    /** A rank-0 context change naming [funders] the channel's funders (the makeCommitter pattern). */
    private fun nameFunders(w: ChannelWorld, owner: ChannelClient, id: ChannelId, funders: List<ChannelClient>) {
        val before = ChannelAdversary.policy(owner, id)
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            before.committers, funders.map { pseudonymOf(it, id) },
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == owner.name }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "funders")
        w.relay.holdAt = { _, _ -> false }
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (c in w.clients) if (c.channel(id)?.state == ChannelState.ACTIVE) c.timePass()
        w.quiesce()
    }

    // --------------------------------------------------------------------------------------------- NI-CH4

    /**
     * NI-CH4 (with LC-4's declared difference): twin B's clients receive a **rotating** commit
     * (a removal, committed by the owner at minute m); twin A's receive a **non-rotating** commit
     * of equal length at the same minute (a padded name change, staged like an own candidate).
     * Views are identical except: the rotating committer's funding of ns_{g+1}, every other
     * member's first list of ns_{g+1} at the switch hour, the registrations on ns_{g+1} — and the
     * removed member's listing stays on ns_g until the drain ends.
     */
    fun niCh4(seed: Long): TwinResult {
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        var removedName = "carol"
        var equalLength = false
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val bob = w.client("bob")
                val carol = w.client(removedName)
                val id = ChannelScenes.channelOf(w, owner, bob, carol)
                w.advance(2 * DmWorld.DAY)
                if (isB) {
                    // Twin B: the owner's user-action removal of carol (rotates, §6.5).
                    assertEquals(
                        org.ghost.messaging.channel.engine.ChannelEngine.RemoveResult.REMOVED,
                        owner.engine.remove(id, pseudonymOf(carol, id)),
                    )
                    owner.sessionStart()
                    w.advance(6 * DmWorld.MINUTE)
                    owner.timePass()
                    w.pump()
                    w.quiesce()
                    w.pastSettleWindow()
                    w.quiesce()
                } else {
                    // Twin A: a non-rotating context change (a name change padded toward the
                    // removal commit's size), staged like an own candidate and settled by the
                    // same choreography twin B's removal commit is: the same 6-minute advance
                    // the twin's session start + pass took, the same settle window after it.
                    w.advance(6 * DmWorld.MINUTE)
                    val before = ChannelAdversary.policy(owner, id)
                    val after = ChannelPolicy(
                        before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
                        before.flags, before.idleEvictDays, before.pwVersion, "salon-redenumit-cu-un-nume-lung".toByteArray(),
                        before.committers, before.funders,
                    )
                    val change = ChannelAdversary.commit(owner, id, after)
                    // The label is ground truth, not relay-visible: both twins' blobs read as a
                    // "commit" store (the relay sees two sealed 4 KiB blobs it cannot tell
                    // apart). The bytes are the owner's own op's: attributed to it like an
                    // enqueued store (the staged-own pattern), never served back to it.
                    w.relay.holdAt = { name, s -> s.purpose == "commit" && name == owner.name }
                    ChannelAdversary.stageOwn(owner, id, change, rank = 0)
                    w.relay.injectAs(owner, ChannelAdversary.namespace(owner, id), change.blob, w.now, "commit")
                    w.relay.holdAt = { _, _ -> false }
                    w.pump()
                    w.quiesce()
                    w.pastSettleWindow()
                    w.quiesce()
                    val a = w.relay.stored.last { it.purpose == "commit" }
                    equalLength = a.ciphertext.size == 4096
                }
                // The switch hour (twin B): everyone switches; the drain lives 14 days. Twin A
                // has no pending generation: the same passes run, the switch step finds nothing.
                w.advance(3 * DmWorld.HOUR)
                for (c in w.clients) if (c.channel(id)?.state == ChannelState.ACTIVE) c.sessionStart()
                w.advance(6 * DmWorld.MINUTE)
                for (c in w.clients) if (c.channel(id)?.state == ChannelState.ACTIVE) c.timePass()
                w.quiesce()
                w.pump()
                for (c in w.clients) if (c.channel(id)?.state == ChannelState.ACTIVE) c.hintPass()
                w.pastSettleWindow()
                w.quiesce()
                assertEquals(
                    "twin B rotated, twin A did not",
                    if (isB) 1L else 0L,
                    owner.channel(id)!!.generation,
                )
                for (c in listOf(owner, bob, carol)) into[c.name] = trace(w, c)
            }
        }
        // The declared LC-4 delta: exactly the new-generation (G1) acts in twin B, plus nothing
        // for the removed member (her listing of G0 stays until the drain ends). Circuits ride
        // the twins' pump choreography (B's engine pass and quiesce rounds are not pump-identical
        // to A's injection): compared at minute granularity — no circuit at a minute the other
        // twin had none.
        for (name in listOf("owner", "bob", removedName)) {
            val a = tracesA.getValue(name)
            val b = tracesB.getValue(name)
            if (name == removedName) {
                // The removed member: every non-circuit act identical (her listing stays on the
                // old namespace until the drain ends, LC-4); her circuits at minute-set
                // granularity like the others (her session choreography legitimately differs —
                // she is active in one twin and removed in the other — while no minute may carry
                // a circuit in one twin that the other had none of).
                val aStrict = a.filter { it.kind != "circuit" }
                val bStrict = b.filter { it.kind != "circuit" }
                assertSameView("NI-CH4: the removed member's acts stay on the old namespace (LC-4)", aStrict, bStrict)
                val aMinutes = a.filter { it.kind == "circuit" }.map { it.minute }.toSet()
                val extra = b.filter { it.kind == "circuit" }.map { it.minute }.filter { it !in aMinutes }
                assertTrue("NI-CH4: the removed member's circuits stay at the twins' session minutes: $extra", extra.isEmpty())
                continue
            }
            val delta = b.filter { it.kind != "circuit" }.toMutableList()
            for (x in a.filter { it.kind != "circuit" }) delta.remove(x)
            val nonG1 = delta.filter { it.ns != "G1" }
            assertTrue("NI-CH4: $name's delta is G1 acts only (LC-4): nonG1=$nonG1 fullDelta=$delta", nonG1.isEmpty())
            assertTrue("NI-CH4: $name lists the new generation (LC-4's declared difference)", delta.isNotEmpty())
            val aCircuitMinutes = a.filter { it.kind == "circuit" }.map { it.minute }.toSet()
            val extraCircuitMinutes = b.filter { it.kind == "circuit" }.map { it.minute }.filter { it !in aCircuitMinutes }
            assertTrue("NI-CH4: $name's circuits stay at the twins' session minutes: $extraCircuitMinutes", extraCircuitMinutes.isEmpty())
        }
        return TwinResult(
            "NI-CH4", equalLength,
            "rotating vs non-rotating commit of equal sealed length ($equalLength) at the same minute: " +
                "identical views except the G1 (ns_{g+1}) acts — the switch-hour lists, the registrations and the " +
                "rotating committer's funding — and the removed member's listing unchanged on G0 (LC-4)",
        )
    }

    // --------------------------------------------------------------------------------------------- NI-CH5

    /**
     * NI-CH5 (§19.29.3): twins where one channel is password-protected and the other open, the
     * same invites, joins and posts (the password channel's invites sealed, its joiners opening
     * them with the password). Identical relay views of every client — the twin proves a password
     * channel is not distinguishable at the relays (MM-PW4's second half). The declared LC-4
     * clause the row names: an invite that expires unconsumed (a sponsor's typo cannot be
     * detected — in a password channel no verifier exists to tell a wrong password from a lost
     * link, which is why such invites expire more often there) sets the rotation flag (§6.5,
     * Q28); the expiring invite rotates **both** twins here, and the rotation count is counted
     * and reported, not compared away.
     */
    fun niCh5(seed: Long, password: CharArray): TwinResult {
        val tracesP = HashMap<String, List<Act>>()
        val tracesO = HashMap<String, List<Act>>()
        var rotations = 0
        for ((passwordChannel, into) in listOf(true to tracesP, false to tracesO)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val bob = w.client("bob")
                val carol = w.client("carol")
                val id = ChannelAdmissionTest.create(owner, password = passwordChannel)
                // The same invitations: two consumed (the password twin's sealed, opened with the
                // password), a third left to expire unconsumed (the sponsor's typo shape).
                val link1 = ChannelAdmissionTest.invite(owner, id, if (passwordChannel) password else null)
                val link2 = ChannelAdmissionTest.invite(owner, id, if (passwordChannel) password else null)
                ChannelAdmissionTest.invite(owner, id, if (passwordChannel) password else null)
                assertEquals(AcceptResult.PENDING, bob.engine.accept(link1, if (passwordChannel) password else null))
                assertEquals(AcceptResult.PENDING, carol.engine.accept(link2, if (passwordChannel) password else null))
                w.quiesce()
                w.admissionPass(owner)
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
                assertEquals(ChannelState.ACTIVE, bob.channel(id)!!.state)
                assertEquals(ChannelState.ACTIVE, carol.channel(id)!!.state)
                // The same posts, day by day, past the third invite's 7-day expiry.
                for (d in 0 until 8) {
                    ChannelScenes.post(if (d % 2 == 0) bob else carol, id, "ziua $d")
                    w.quiesce()
                    w.advance(DmWorld.DAY)
                }
                // The expiry: the pass sees the expired unconsumed invite and sets the rotation
                // flag (Q28); the commit rotates the channel in both twins.
                owner.sessionStart()
                w.advance(6 * DmWorld.MINUTE)
                owner.timePass()
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
                owner.sessionStart()
                w.advance(6 * DmWorld.MINUTE)
                owner.timePass()
                w.quiesce()
                w.advance(3 * DmWorld.HOUR)
                for (c in listOf(owner, bob, carol)) if (c.channel(id)?.state == ChannelState.ACTIVE) c.sessionStart()
                w.advance(6 * DmWorld.MINUTE)
                for (c in listOf(owner, bob, carol)) if (c.channel(id)?.state == ChannelState.ACTIVE) c.timePass()
                w.quiesce()
                w.pump()
                for (c in listOf(owner, bob, carol)) if (c.channel(id)?.state == ChannelState.ACTIVE) c.hintPass()
                w.pastSettleWindow()
                w.quiesce()
                rotations = owner.count("ch_generation").toInt()
                for (c in listOf(owner, bob, carol)) into[c.name] = trace(w, c)
            }
        }
        // Identical views, both twins rotated (the declared LC-4 effect, counted and reported).
        for (name in listOf("owner", "bob", "carol")) {
            assertSameView("NI-CH5: the password channel is distinguishable at $name's relays", tracesO.getValue(name), tracesP.getValue(name))
        }
        assertTrue("NI-CH5: the expiring invite rotated the channel in both twins (LC-4)", rotations >= 2)
        return TwinResult(
            "NI-CH5", true,
            "password vs open channel, the same invitations, joins and posts: 3 clients' views identical; " +
                "both twins hold $rotations generations (the expiring invite's rotation, the declared LC-4 " +
                "leakage — counted, not compared away)",
        )
    }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym
}

/** The PCS-clock arming the NI-CH twins share (the M20 scenario's agePcsClock + duePass shape). */
internal object ChannelM20PcsDue {
    /** [back] days behind "now" as the last own-commit day: 8 makes the PCS cadence due, 0 keeps it away. */
    fun arm(client: ChannelClient, id: ChannelId, back: Long) {
        val day = DmTime.day(client.clock.now) - back
        client.database.transaction { tx ->
            val row = client.channelStores.channels.schedule(tx.sql, id.toByteArray()) ?: return@transaction
            client.channelStores.channels.putSchedule(tx, id.toByteArray(), row.nextSelfupdateDay, day, null)
        }
    }
}
