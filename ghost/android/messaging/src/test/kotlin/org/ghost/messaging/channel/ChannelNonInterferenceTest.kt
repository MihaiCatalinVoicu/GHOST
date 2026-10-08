package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * **NI-CH1 at the channel world's PR scale** (Phase 10 design §12.7's NI-CH1 row, §2.2 P-C6, T40;
 * slice S5c): twins that differ only in what one client received give **identical relay views of
 * that client** — the sequence of its stores (namespace, purpose, padded size, minute), its
 * capabilities, registrations and listened namespaces — except the declared LC differences (LC-6's
 * pass outcome: the pass a received request triggers, PC-5; LC-5's joiner listening). The full
 * 60-client, 28-day privacy world is S11's (§12.7, §19.10); this is the twin harness and the
 * NI-CH1 variants over the channel world at its own scale (three virtual days, one channel), each
 * report line naming what it compared (§19.10's rule until S11's harness debts land): stores,
 * capabilities, registrations, the listen set; session-close times and circuit timing are not
 * modeled in this world. A rejoin request is S6/S7's flow.
 */
class ChannelNonInterferenceTest {

    @Before
    fun native() {
        assumeTrue("ghost-dm-host is not loaded (-Dghost.dm.native)", ChannelWorld.nativeAvailable())
    }

    /** One relay-visible act of a client: a store or a sync row a relay sees of it. */
    private class Act(val kind: String, val ns: String, val detail: String, val minute: Long) {
        override fun toString(): String = "$kind/$ns/$detail@$minute"
        override fun equals(other: Any?): Boolean = other is Act && toString() == other.toString()
        override fun hashCode(): Int = toString().hashCode()
    }

    /**
     * The client's relay-visible view: its stores (shapes, not bytes — §12.1 reads no native
     * bytes) and its sync rows. Namespaces are ALIASED ("CH" the channel's current generation,
     * "JOIN" a pending-join namespace of this client): the worlds' natively drawn namespace
     * bytes differ (the seeded native stream is process-global, §19.10), and what T40 compares
     * is the view's structure — which namespace shape carried which act at which minute.
     */
    private fun trace(w: ChannelWorld, client: ChannelClient): List<Act> {
        val aliases = HashMap<String, String>()
        client.sql.query("SELECT hex(namespace_id) FROM ch_generation") { aliases[it.string(0)] = "CH" }
        client.sql.query("SELECT hex(ns) FROM ch_join WHERE ns IS NOT NULL") { aliases[it.string(0)] = "JOIN" }
        var ext = 0
        fun alias(ns: String): String = aliases.getOrPut(ns) { "EXT${ext++}" }
        val acts = ArrayList<Act>()
        for (s in w.relay.stored) {
            if (s.from != client.name || s.injected) continue
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
        return acts.sortedBy { it.toString() }
    }


    /** Asserts two views equal, printing only the differing acts (JUnit truncates long messages). */
    private fun assertSameView(what: String, a: List<Act>, b: List<Act>) {
        if (a == b) return
        val onlyA = a.toMutableList()
        for (x in b) onlyA.remove(x)
        val onlyB = b.toMutableList()
        for (x in a) onlyB.remove(x)
        throw AssertionError("$what: only-A=$onlyA only-B=$onlyB")
    }

    private class Clients(val owner: ChannelClient, val bob: ChannelClient, val carol: ChannelClient, val dave: ChannelClient) {
        fun byName(name: String): ChannelClient = when (name) {
            "owner" -> owner; "bob" -> bob; "carol" -> carol; else -> dave
        }
    }

    /**
     * Runs the shared three-day choreography in two twins. [early] is installed right after the
     * channel is up (before any post — a hold that must intercept a serve is installed there);
     * [late] runs at the day-1 mark. Each hook receives its world, the clients, the channel and
     * whether this is twin B (twin A runs the identical choreography with no hook).
     */
    private fun runTwin(
        early: ((w: ChannelWorld, cs: Clients, id: ChannelId, isB: Boolean) -> Unit)? = null,
        late: ((w: ChannelWorld, cs: Clients, id: ChannelId, isB: Boolean) -> Unit)? = null,
    ): Pair<Map<String, List<Act>>, Map<String, List<Act>>> {
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val bob = w.client("bob")
                val carol = w.client("carol")
                val dave = w.client("dave")
                val cs = Clients(owner, bob, carol, dave)
                val id = ChannelScenes.channelOf(w, owner, bob, carol, dave)
                if (early != null) early(w, cs, id, isB)
                // Day 0 midday: the first posts.
                w.advance(2 * DmWorld.HOUR)
                ChannelScenes.post(owner, id, "prima zi, owner")
                ChannelScenes.post(bob, id, "prima zi, bob")
                ChannelScenes.post(carol, id, "prima zi, carol")
                w.quiesce()
                // Day 1 midday: the variant's event.
                w.advance(1 * DmWorld.DAY)
                if (late != null) late(w, cs, id, isB)
                ChannelScenes.post(dave, id, "ziua doi, dave")
                w.quiesce()
                // Day 2: the last posts and a settle window of everyone.
                w.advance(1 * DmWorld.DAY)
                ChannelScenes.post(owner, id, "ziua trei, owner")
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
                for (name in listOf("owner", "bob", "carol", "dave")) into[name] = trace(w, cs.byName(name))
            }
        }
        return tracesA to tracesB
    }

    @Test
    fun aForgedBlobReceivedChangesNoOnesRelayView() {
        val (a, b) = runTwin(late = { w, cs, id, isB ->
            if (!isB) return@runTwin
            val junk = ByteArray(700) { (it * 7).toByte() }
            w.relay.inject(
                ChannelAdversary.namespace(cs.carol, id),
                ChannelAdversary.sealJunk(cs.carol, id, junk), w.now, "ni-forged",
            )
        })
        for (name in listOf("owner", "bob", "carol", "dave")) {
            assertSameView("the forged blob changes no one's relay view ($name)", a.getValue(name), b.getValue(name))
        }
    }

    @Test
    fun aReplayReceivedChangesNoOnesRelayView() {
        val (a, b) = runTwin(late = { w, cs, id, isB ->
            if (!isB) return@runTwin
            val post = ChannelScenes.postsOf(w, cs.carol).single()
            val replay = ChannelAdversary.reseal(cs.bob, id, post.ciphertext)
            w.relay.inject(ChannelAdversary.namespace(cs.bob, id), replay, w.now, "ni-replay")
        })
        for (name in listOf("owner", "bob", "carol", "dave")) {
            assertSameView("the replay changes no one's relay view ($name)", a.getValue(name), b.getValue(name))
        }
    }

    @Test
    fun aValidPostHeldInOneTwinChangesNoOnesRelayView() {
        // Carol's day-1 post is composed and stored in both twins; the relay holds it from bob in
        // A (the hold intercepts the serve — it is installed before the post exists, counting
        // carol's posts) and serves it in B: the twins differ only in what bob received.
        val (a, b) = runTwin(
            early = { w, cs, _, isB ->
                if (isB) return@runTwin
                var carolPosts = 0
                w.relay.holdAt = { name, s ->
                    if (s.from == "carol" && s.purpose == "post") {
                        carolPosts++
                        name == "bob" && carolPosts == 2
                    } else false
                }
            },
            late = { w, cs, id, _ ->
                // Both twins: carol's second post ("extra"). The day-0 post was the first.
                ChannelScenes.post(cs.carol, id, "extra a carei")
                w.pump()
            },
        )
        for (name in listOf("owner", "bob", "carol", "dave")) {
            assertSameView("the held/served post changes no one's relay view ($name)", a.getValue(name), b.getValue(name))
        }
    }

    @Test
    fun aCommitReceivedChangesNoOnesRelayView() {
        // An extra candidate built by the owner, served to everyone but its author (an own copy
        // would only count FORGE_OWN): receiving a commit causes no relay-visible act.
        val (a, b) = runTwin(late = { w, cs, id, isB ->
            if (!isB) return@runTwin
            val extra = ChannelAdversary.commit(cs.owner, id)
            w.relay.holdAt = { name, s -> s.purpose == "ni-commit" && name == "owner" }
            w.relay.inject(ChannelAdversary.namespace(cs.owner, id), extra.blob, w.now, "ni-commit")
        })
        for (name in listOf("owner", "bob", "carol", "dave")) {
            assertSameView("the received commit changes no one's relay view ($name)", a.getValue(name), b.getValue(name))
        }
    }

    @Test
    fun aJoinRequestToACommitterDiffersOnlyByThePassesItTriggers() {
        // Bob is a committer; dave's request is stored in both twins, served to bob in B and held
        // from him in A. The deltas are exactly the declared ones: LC-6 (bob's pass: the
        // admission commit and the Welcome) and LC-5 (dave's joiner listening).
        val tracesA = HashMap<String, List<Act>>()
        val tracesB = HashMap<String, List<Act>>()
        for ((isB, into) in listOf(false to tracesA, true to tracesB)) {
            ChannelWorld().use { w ->
                val owner = w.client("owner")
                val bob = w.client("bob")
                val id = ChannelScenes.channelOf(w, owner, bob)
                makeCommitter(w, owner, bob, id)
                val dave = w.client("dave")
                if (!isB) w.relay.holdAt = { name, s -> name == "bob" && s.purpose == "join" }
                assertEquals(AcceptResult.PENDING, dave.engine.accept(ChannelAdmissionTest.invite(owner, id), null))
                w.quiesce()
                // Two days age the request so rank 1's pass may take it (the work-age rule).
                w.advance(2 * DmWorld.DAY)
                w.admissionPass(bob)
                w.quiesce()
                // The owner's session in both twins: in B the work is already done (a no-op); in A
                // the owner's pass is what admits dave — the same flow, one twin later.
                w.admissionPass(owner)
                w.quiesce()
                w.pastSettleWindow()
                w.quiesce()
                into["owner"] = trace(w, owner)
                into["bob"] = trace(w, bob)
                into["dave"] = trace(w, dave)
            }
        }
        // The admission runs in both twins (dave joins either way), but on different committers:
        // in A the owner's pass takes the request (bob never saw it); in B bob's pass takes it
        // first and the owner's session finds the work done. The delta is exactly LC-6's declared
        // one — the pass outcome — on whichever committer ran it, and nothing else moves.
        val ownerA = tracesA.getValue("owner") - tracesB.getValue("owner").toSet()
        val ownerB = tracesB.getValue("owner") - tracesA.getValue("owner").toSet()
        val bobA = tracesA.getValue("bob") - tracesB.getValue("bob").toSet()
        val bobB = tracesB.getValue("bob") - tracesA.getValue("bob").toSet()
        fun passWork(d: List<Act>) = d.all { it.detail.startsWith("commit:") || it.detail.startsWith("welcome:") }
        assertTrue("the owner's delta is pass work only (LC-6): A=$ownerA B=$ownerB", passWork(ownerA) && passWork(ownerB))
        assertTrue("bob's delta is pass work only (LC-6): A=$bobA B=$bobB", passWork(bobA) && passWork(bobB))
        assertTrue("the owner admitted in A only: A=$ownerA B=$ownerB", ownerA.isNotEmpty() && ownerB.isEmpty())
        assertTrue("bob admitted in B only: A=$bobA B=$bobB", bobB.isNotEmpty() && bobA.isEmpty())
        assertEquals("dave joined in both twins: his view is identical", tracesA.getValue("dave"), tracesB.getValue("dave"))
    }

    // --------------------------------------------------------------------------------------------- helpers

    private fun makeCommitter(w: ChannelWorld, owner: ChannelClient, bob: ChannelClient, id: ChannelId) {
        val before = ChannelAdversary.policy(owner, id)
        val after = ChannelPolicy(
            before.channelId, before.sizeClass, before.timerCode, before.timerVersion, before.historyPolicy,
            before.flags, before.idleEvictDays, before.pwVersion, before.name,
            listOf(pseudonymOf(owner, id), pseudonymOf(bob, id)), before.funders,
        )
        val change = ChannelAdversary.commit(owner, id, after)
        w.relay.holdAt = { name, s -> s.purpose == "committers" && name == "owner" }
        ChannelAdversary.stageOwn(owner, id, change, rank = 0)
        ChannelAdversary.inject(w, owner, id, change, "committers")
        w.quiesce()
        w.advance(21 * DmWorld.MINUTE)
        w.pump()
        for (client in w.clients) client.timePass()
        w.quiesce()
    }

    private fun pseudonymOf(client: ChannelClient, id: ChannelId): ByteArray =
        client.contexts.open(id.toByteArray())!!.pseudonym
}
