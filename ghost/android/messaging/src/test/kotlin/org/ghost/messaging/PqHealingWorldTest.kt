package org.ghost.messaging

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.port.DmContext
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.messaging.port.NativeDmEnvelopes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * **PQ3, the PQ-C healing world** (Phase 9 design §15.5 PQ3, §9.4 "Healing argument", model
 * obligation M-6; slice S13), with a ground-truth compromise event.
 *
 * > PQ3 PQ-C healing world: both devices' state leaked at day t, the adversary given all classical
 * > secrets and no post-t ML-KEM secrets opens no pair envelope after the healing cycle and does
 * > before it (ground truth).
 *
 * **The world.** Two devices with the real cryptography converse every day for about twelve weeks:
 * each daily pass runs OWNER-WEEK (a new bundle generation each week, §5.4) and SWEEP, and each
 * side sends one message a day, delivered at once. At day [COMPROMISE_DAY] both devices' complete
 * state is **leaked** ([Leak]): every row of both databases the adversary could use, and both DM
 * contexts' secrets — a leaked context is a second native context opened over the device's
 * MESSAGING branch, `ghost1` seed and `session_state_key`, which is what a dump of the device lets
 * anyone call.
 *
 * **The adversary** has everything the statement gives it. It holds the leak; it is handed
 * **every L0 either device encodes after t** — all classical secrets, so it reads every Olm
 * message as if X25519 were broken, including every `root_rand`, every classical root and every
 * `pq_key` — and every blob either device stores (the relay archive). What it does **not** get is
 * any X-Wing seed of a generation created after t: those exist only in rows written after the leak.
 * With that, it derives every pair week key it can:
 *  1. the leaked **in** keys of both devices, ratcheted forward to the end of the world
 *     (`K_{w+1} = HKDF(K_w)`, §6.3) — the leak's whole future until a root is replaced;
 *  2. the leaked **unacknowledged offers**' roots, ratcheted the same way;
 *  3. every root that travels after t: a classical `seal_root` is in the L0, and a `seal_root_pq`
 *     opens exactly when the generation it names is one the leak contained (the real `pqRootOpen`,
 *     through the leaked context of the device that decapsulates). That branch runs only when such
 *     an offer exists: with the leak on day [COMPROMISE_DAY] none does (every later `seal_root_pq`
 *     targets a post-leak generation), so [pq3APqRootToALeakedGenerationDoesNotHeal] moves the
 *     leak to day [EARLY_COMPROMISE_DAY], just before a replacement, and asserts the branch ran.
 * It then tries **every** derived key on **every** pair envelope stored after t (recognition hint
 * first, then the real `openPair`), in both directions.
 *
 * **The ground truth** ([PqRecorder]) says, for every pair envelope, which root generation sealed
 * it and how that root was offered: classical, PQ-C to a generation the leak contained, or PQ-C to
 * a generation created **after** t. The last kind is a **healed** generation.
 *
 * **What is asserted**, per direction:
 *  - the adversary opens **no** envelope sealed under a healed generation, and **every** envelope
 *    sealed under any other generation (so a "0" is not the output of a broken attempt);
 *  - healing happens: the first envelope under a healed generation is sealed within
 *    [HEALING_BOUND_WEEKS] of t (§9.4 says "about 5–6 weeks of ordinary two-way use at the
 *    default cadence"), and every pair envelope after it is under a healed generation too;
 *  - before it, the adversary opens at least one envelope sealed after t ("and does before it").
 * The **control world** is the same world with every PQ-C offer answered `INVALID_KEY` at the port,
 * which SEND takes as §22.8.2 rule 4's classical fallback — a client that never heals, built from
 * the production path: there the adversary opens every pair envelope, including all of those sealed
 * after the honest world's healing bound. So the check can fail, and it fails on the property.
 */
class PqHealingWorldTest {

    private fun requireNative() {
        assumeTrue("set -Dghost.dm.native to the ghost-dm-host library", DmWorld.nativeAvailable())
    }

    @Test
    fun pq3AnAdversaryWithTheLeakOpensNoPairEnvelopeAfterTheHealingCycle() {
        requireNative()
        val honest = runWorld(forceClassical = false, compromiseDay = COMPROMISE_DAY)
        assertHealed(honest)

        // The control: the same world, never healing. The adversary opens everything, including
        // every envelope sealed after the honest world's bound.
        val control = runWorld(forceClassical = true, compromiseDay = COMPROMISE_DAY)
        val bound = control.compromiseAt + HEALING_BOUND_WEEKS * DmWorld.WEEK
        // That the control heals nothing is structural — its recorder refuses every PQ-C offer
        // before recording one — so what this line checks is that SEND **tried** PQ-C and fell
        // back each time, which is what makes it the production path and not a world without keys.
        assertTrue("the control refused PQ-C offers (${control.refusedPqOffers})", control.refusedPqOffers > 0)
        for (direction in control.directions) {
            val late = direction.all.filter { it.at >= bound }
            assertTrue("${direction.label}: the control has late envelopes", late.size >= FLOOR)
            assertEquals("${direction.label}: nothing healed in the control", 0, direction.healed.size)
            assertEquals(
                "${direction.label}: the adversary opens every late envelope of the control",
                late.size,
                late.count { it in direction.opened },
            )
        }
    }

    /**
     * **PQ3 with the leak just before a replacement** (the slice S13 review): on day
     * [EARLY_COMPROMISE_DAY] the next replacement in each direction is a `seal_root_pq` to the key
     * the peer announced **before** the leak — a generation the leak contains. That offer does not
     * heal: the adversary opens it with the real `pqRootOpen` through the leaked context and reads
     * every envelope under it, and healing waits for the replacement after it. This is the
     * engine-level counterpart of M-6's control `msgPqOld`, and what makes "a generation created
     * after the leak", not "any PQ root", the healing condition. The day-31 world never exercised
     * it: every `seal_root_pq` after that leak went to a post-leak generation.
     */
    @Test
    fun pq3APqRootToALeakedGenerationDoesNotHeal() {
        requireNative()
        val early = runWorld(forceClassical = false, compromiseDay = EARLY_COMPROMISE_DAY)
        assertHealed(early)
        for (direction in early.directions) {
            assertTrue(
                "${direction.label}: a PQ-C root to a leaked generation travelled after the leak",
                direction.pqLeaked.isNotEmpty(),
            )
            assertTrue(
                "${direction.label}: and the adversary opened it with pqRootOpen (${direction.pqOpened})",
                direction.pqOpened > 0,
            )
            val underLeaked = direction.all.filter { it.rootGen in direction.pqLeaked }
            assertTrue("${direction.label}: envelopes sealed under it", underLeaked.isNotEmpty())
            assertEquals(
                "${direction.label}: every one of them opened",
                underLeaked.size,
                underLeaked.count { it in direction.opened },
            )
        }
    }

    /** The per-direction assertions of PQ3 (see the class comment). */
    private fun assertHealed(honest: Outcome) {
        for (direction in honest.directions) {
            val label = direction.label
            assertTrue("$label: healed envelopes exist (${direction.healed.size})", direction.healed.size >= FLOOR)
            assertEquals(
                "$label: the adversary opened healed envelopes",
                0,
                direction.healed.count { it in direction.opened },
            )
            assertTrue(
                "$label: enough envelopes under leaked or classical roots (${direction.breakable.size})",
                direction.breakable.size >= FLOOR,
            )
            assertEquals(
                "$label: the adversary's control — every envelope it should open, it opens",
                direction.breakable.size,
                direction.breakable.count { it in direction.opened },
            )
            val healedAt = requireNotNull(direction.healingAt) { "$label never healed" }
            assertTrue(
                "$label: healed ${(healedAt - honest.compromiseAt) / DmWorld.DAY} days after the leak",
                healedAt - honest.compromiseAt <= HEALING_BOUND_WEEKS * DmWorld.WEEK,
            )
            assertTrue(
                "$label: after healing, every pair envelope is under a healed generation",
                direction.all.filter { it.at >= healedAt }.all { it in direction.healedSet },
            )
            assertTrue(
                "$label: and before it the adversary did open envelopes sealed after the leak",
                direction.all.any { it.at < healedAt && it in direction.opened },
            )
        }
    }

    // ---------------------------------------------------------------- the world

    @Suppress("LongParameterList")
    private class Direction(
        val label: String,
        val all: List<PqLog.PairBlob>,
        val healed: List<PqLog.PairBlob>,
        val breakable: List<PqLog.PairBlob>,
        val opened: Set<PqLog.PairBlob>,
        /** Generations offered after the leak as `seal_root_pq` to a generation the leak held. */
        val pqLeaked: Set<Int>,
        /** How many post-leak `seal_root_pq` the adversary opened with `pqRootOpen`. */
        val pqOpened: Int,
    ) {
        val healedSet: Set<PqLog.PairBlob> = healed.toSet()
        val healingAt: Long? = healed.minOfOrNull { it.at }
    }

    private class Outcome(val compromiseAt: Long, val directions: List<Direction>, val refusedPqOffers: Int)

    @Suppress("LongMethod")
    private fun runWorld(forceClassical: Boolean, compromiseDay: Int): Outcome {
        val log = PqLog()
        val world = DmWorld(decorate = { branch, inner -> PqRecorder(inner, branch, log, forceClassical) })
        log.now = { world.alice.clock.now }
        world.use {
            val alice = world.alice
            val bob = world.bob
            val (contactB, contactA) = establishBothWays(world)
            var leakA: Leak? = null
            var leakB: Leak? = null
            var compromiseAt = 0L
            for (day in 1..DAYS) {
                world.advanceTo(alice.clock.now + DmWorld.DAY)
                alice.timeTriggeredPass()
                bob.timeTriggeredPass()
                if (day == compromiseDay) {
                    compromiseAt = alice.clock.now
                    leakA = Leak.of(alice)
                    leakB = Leak.of(bob)
                }
                assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "a$day", null))
                world.deliver()
                bob.hintPass()
                assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "b$day", null))
                world.deliver()
                alice.hintPass()
            }
            // Nothing was lost: the only counter allowed to move is `root_not_newer`, which a
            // re-attached offer the peer already installed produces by design (§6.3).
            for (device in listOf(alice, bob)) {
                val drops = device.engine.status().drops.filterKeys { it != "root_not_newer" }
                assertEquals("no drop in the world: $drops", 0, drops.values.sum())
                // The sending side's PQ-C counts (the slice S13 review), for the report.
                println("dm PQ3 device ${device.branch} (leak day $compromiseDay): pq ${device.engine.status().pq}")
            }
            val finalWeek = DmTime.week(alice.clock.now)
            val a = requireNotNull(leakA)
            val b = requireNotNull(leakB)
            try {
                return Outcome(
                    compromiseAt = compromiseAt,
                    directions = listOf(
                        direction("A→B", log, from = a, to = b, alice, compromiseAt, finalWeek),
                        direction("B→A", log, from = b, to = a, bob, compromiseAt, finalWeek),
                    ),
                    refusedPqOffers = log.refusedPqOffers,
                )
            } finally {
                DmSessions.closeContext(a.handle)
                DmSessions.closeContext(b.handle)
            }
        }
    }

    /** One direction's ground truth and the adversary's attempt on it. */
    @Suppress("LongParameterList")
    private fun direction(
        label: String,
        log: PqLog,
        from: Leak,
        to: Leak,
        sender: DmDevice,
        compromiseAt: Long,
        finalWeek: Long,
    ): Direction {
        val blobs = log.pairBlobs.filter { it.branch == from.branch && it.at >= compromiseAt }
        // The offers of the recipient, which key the envelopes sent to it (§6.3).
        val offers = log.offers.filter { it.branch == to.branch }
        fun offerOf(rootGen: Int) = offers.lastOrNull { it.rootGen == rootGen }
        val healed = blobs.filter { blob ->
            val offer = offerOf(blob.rootGen)
            offer != null && offer.at >= compromiseAt && offer.peerGenId != null &&
                offer.peerGenId !in from.generationIds
        }
        val breakable = blobs - healed.toSet()
        // The generations the recipient offered after the leak as a PQ-C root to a generation of
        // the sender's that the leak held: PQ-C, and still not healed.
        val pqLeaked = offers.map { it.rootGen }.distinct().filter { gen ->
            val offer = offerOf(gen)
            offer != null && offer.at >= compromiseAt && offer.peerGenId != null &&
                offer.peerGenId in from.generationIds
        }.toSet()
        val adversary = Adversary(from, to, log, compromiseAt, finalWeek)
        val keys = adversary.keys()
        val namespaces = storedNamespaces(sender)
        val opened = LinkedHashSet<PqLog.PairBlob>()
        for (blob in blobs) {
            val namespace = namespaces[blob.blob.toList()] ?: error("$label: a pair envelope that was never stored")
            for (key in keys) {
                if (!key.envelopes.hintMatches(blob.blob, key.recognition)) continue
                val result = key.envelopes.openPair(
                    namespace = namespace,
                    blob = blob.blob,
                    openEnv = key.openEnv,
                    contactId = key.contactId,
                    rootGen = key.rootGen,
                    week = key.week,
                    // Each side's Olm identity is the one its peer pinned.
                    oiSender = to.peerOlmIdentity,
                    oiRecipient = from.peerOlmIdentity,
                )
                if (result is DmSeal.OuterSymmetric.Ok) {
                    opened += blob
                    break
                }
            }
        }
        val direction = Direction(label, blobs, healed, breakable, opened, pqLeaked, adversary.pqOpened)
        // The report line: what the run measured, whatever the assertions decide.
        println(
            "dm PQ3 $label (forced classical: ${offers.none { it.peerGenId != null }}): " +
                "${blobs.size} pair envelopes after the leak, ${healed.size} under healed generations " +
                "(opened ${healed.count { it in opened }}), ${breakable.size} under leaked or classical roots " +
                "(opened ${breakable.count { it in opened }}), ${keys.size} derived keys, " +
                "${adversary.pqOpened} post-leak PQ-C roots opened with pqRootOpen; roots offered: " +
                offers.joinToString { offer ->
                    val kind = when (offer.peerGenId) {
                        null -> "classical"
                        in from.generationIds -> "pq-leaked"
                        else -> "pq-fresh"
                    }
                    "g${offer.rootGen} at day ${(offer.at - compromiseAt) / DmWorld.DAY} $kind"
                } +
                "; healed ${direction.healingAt?.let { (it - compromiseAt) / DmWorld.DAY }} days after the leak",
        )
        return direction
    }

    /** `ciphertext → namespace` of every blob the device stored: the relay archive's index. */
    private fun storedNamespaces(device: DmDevice): Map<List<Byte>, ByteArray> {
        val out = HashMap<List<Byte>, ByteArray>()
        device.sql.query("SELECT namespace_id, ciphertext FROM outbox_op") {
            out[it.blob(1).toList()] = it.blob(0)
        }
        return out
    }

    // ---------------------------------------------------------------- the leak

    /**
     * One device's state at the compromise: the rows the adversary uses and a second native
     * context over the device's secrets. Nothing written after this moment reaches it.
     */
    private class Leak(
        val branch: Int,
        /** The leaked context: closed once the adversary is done. */
        val handle: Long,
        val envelopes: DmEnvelopes,
        /** This device's local id for its one contact. */
        val contactId: ByteArray,
        val peerOlmIdentity: ByteArray,
        val inKeys: List<InKey>,
        val offers: List<OfferRoot>,
        val generations: List<Generation>,
    ) {
        val generationIds: Set<Long> = generations.map { it.genId }.toSet()

        class InKey(val rootGen: Int, val week: Long, val openEnv: ByteArray)

        class OfferRoot(val rootGen: Int, val baseWeek: Long, val rootEnv: ByteArray)

        class Generation(val genId: Long, val fallbackPublic: ByteArray, val secretsEnv: ByteArray)

        companion object {
            fun of(device: DmDevice): Leak {
                val handle = requireNotNull(device.openLeakedContext()) { "a leaked context" }
                val context = object : DmContext {
                    override fun handleOrNull(): Long = handle

                    override fun stateKeyWrapped(): ByteArray? = null

                    override fun channelScheduleKey(): ByteArray? = null
                }
                var contactId: ByteArray? = null
                var peer: ByteArray? = null
                device.sql.query("SELECT contact_id, pinned_identity FROM dm_contact") {
                    contactId = it.blob(0)
                    peer = it.blob(1)
                }
                val inKeys = ArrayList<InKey>()
                device.sql.query(
                    "SELECT root_gen, week, open_env FROM dm_pair_key WHERE direction = 'in'",
                ) { inKeys += InKey(it.long(0).toInt(), it.long(1), it.blob(2)) }
                val offers = ArrayList<OfferRoot>()
                device.sql.query(
                    "SELECT root_gen, base_week, root_env FROM dm_pair_offer WHERE root_env IS NOT NULL",
                ) { offers += OfferRoot(it.long(0).toInt(), it.long(1), it.blob(2)) }
                val generations = ArrayList<Generation>()
                device.sql.query("SELECT gen_id, fallback_pub, secrets_env FROM olm_prekey_gen") {
                    generations += Generation(it.long(0), it.blob(1), it.blob(2))
                }
                return Leak(
                    branch = device.branch,
                    handle = handle,
                    envelopes = NativeDmEnvelopes(context),
                    contactId = requireNotNull(contactId),
                    peerOlmIdentity = requireNotNull(peer),
                    inKeys = inKeys,
                    offers = offers,
                    generations = generations,
                )
            }
        }
    }

    // ---------------------------------------------------------------- the adversary

    private class Key(
        val envelopes: DmEnvelopes,
        val contactId: ByteArray,
        val rootGen: Int,
        val week: Long,
        val openEnv: ByteArray,
        val recognition: ByteArray,
    )

    /**
     * Every pair week key the adversary can derive for envelopes `from → to` (the recipient's
     * **in** direction), from the leak and the post-leak L0s only.
     */
    private class Adversary(
        private val from: Leak,
        private val to: Leak,
        private val log: PqLog,
        private val compromiseAt: Long,
        private val finalWeek: Long,
    ) {
        /** Post-leak `seal_root_pq` offers this adversary opened with the real `pqRootOpen`. */
        var pqOpened: Int = 0
            private set

        fun keys(): List<Key> {
            val out = ArrayList<Key>()
            // 1. The recipient's leaked in keys, each generation ratcheted forward from its newest.
            for ((rootGen, rows) in to.inKeys.groupBy { it.rootGen }) {
                for (row in rows) out += key(to, rootGen, row.week, row.openEnv, derivedRecognition = null)
                val newest = rows.maxBy { it.week }
                if (newest.week < finalWeek) {
                    out += ratchet(to, rootGen, DmPairing.From.WEEK_KEY, newest.openEnv, newest.week, newest.week + 1)
                }
            }
            // 2. The recipient's leaked unacknowledged offers.
            for (offer in to.offers) {
                out += ratchet(to, offer.rootGen, DmPairing.From.ROOT, offer.rootEnv, offer.baseWeek, offer.baseWeek)
            }
            // 3. Every root the recipient sent after the leak, read from the L0 as the sender's
            //    leaked context decodes it (the sender is the one the root was offered to).
            for (encoded in log.encoded.filter { it.branch == to.branch && it.at >= compromiseAt }) {
                val decoded = from.envelopes.decodeContent(from.contactId, encoded.l0)
                val content = (decoded as? DmContent.DecodeResult.Ok)?.content ?: continue
                content.sealRoot?.let { root ->
                    out += ratchet(from, root.rootGen, DmPairing.From.ROOT, root.rootEnv, root.baseWeek, root.baseWeek)
                }
                content.sealRootPq?.let { root ->
                    // Only a generation the leak contained: the decapsulation needs its seed.
                    val generation = from.generations.firstOrNull { it.genId == root.peerGenId } ?: return@let
                    val opened = from.envelopes.pqRootOpen(
                        contactId = from.contactId,
                        rootGen = root.rootGen,
                        genId = generation.genId,
                        genSecretsEnv = generation.secretsEnv,
                        genFallbackPublic = generation.fallbackPublic,
                        tlv = root.tlv,
                        // The offerer is the recipient `to`, whose identity the sender pinned.
                        peerOlmIdentity = from.peerOlmIdentity,
                    )
                    if (opened is DmPairing.PqOpenResult.Ok) {
                        pqOpened += 1
                        out += ratchet(from, opened.rootGen, DmPairing.From.ROOT, opened.rootEnv, opened.baseWeek, opened.baseWeek)
                    }
                }
            }
            return out
        }

        /** The in-bound week keys `[fromWeek, finalWeek]` of one generation, under a leaked context. */
        @Suppress("LongParameterList")
        private fun ratchet(
            owner: Leak,
            rootGen: Int,
            kind: DmPairing.From,
            keyEnv: ByteArray,
            baseWeek: Long,
            fromWeek: Long,
        ): List<Key> {
            if (fromWeek > finalWeek) return emptyList()
            val keys = owner.envelopes.pairKeys(
                contactId = owner.contactId,
                direction = DmSeal.PairDirection.IN,
                rootGen = rootGen,
                from = kind,
                keyEnv = keyEnv,
                baseWeek = baseWeek,
                fromWeek = fromWeek,
                toWeek = finalWeek,
            )
            val weeks = (keys as? DmPairing.KeysResult.Ok)?.weeks
                ?: error("the adversary's ratchet failed: $keys")
            return weeks.map { key(owner, rootGen, it.week, it.openEnv, it.recognitionKey) }
        }

        @Suppress("LongParameterList")
        private fun key(
            owner: Leak,
            rootGen: Int,
            week: Long,
            openEnv: ByteArray,
            derivedRecognition: ByteArray?,
        ): Key {
            // A leaked row's recognition key is its own; re-deriving it through a one-week walk
            // from the row keeps the adversary on the real surface rather than on a column.
            val recognition = derivedRecognition ?: run {
                val one = owner.envelopes.pairKeys(
                    contactId = owner.contactId,
                    direction = DmSeal.PairDirection.IN,
                    rootGen = rootGen,
                    from = DmPairing.From.WEEK_KEY,
                    keyEnv = openEnv,
                    baseWeek = week,
                    fromWeek = week,
                    toWeek = week,
                )
                ((one as? DmPairing.KeysResult.Ok)?.weeks?.single() ?: error("re-derive: $one")).recognitionKey
            }
            return Key(owner.envelopes, owner.contactId, rootGen, week, openEnv, recognition)
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
        assertEquals(
            AddContactResult.ADDED,
            world.alice.engine.addContact(world.bob.card(), CardSource.QR_IN_PERSON),
        )
        val contactB = world.alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "hello", null))
        world.deliver()
        world.alice.timeTriggeredPass()
        world.advanceTo(world.alice.clock.now + 3 * DmWorld.MINUTE)
        world.alice.timeTriggeredPass()
        world.deliver()
        world.bob.hintPass()
        val contactA = world.bob.engine.contacts().single().id
        assertTrue(world.bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "hi back", null))
        world.deliver()
        world.alice.hintPass()
        assertEquals(SendResult.QUEUED, world.alice.engine.send(contactB, "pair now", null))
        world.deliver()
        world.bob.hintPass()
        return contactB to contactA
    }

    private companion object {
        /** About twelve weeks of daily two-way traffic. */
        const val DAYS = 84

        /**
         * The leak: in the fifth week, five days after both roots were replaced (rule c at four
         * weeks, on day 26), so the next replacement is about 23 days away and goes to a key
         * announced after the leak. It is **not** the worst case of the cadence, which is a leak
         * just after a replacement (§22.18 item 11 says so); the 6-week bound is asserted, not
         * stressed. (The comment this replaces called it "a full cycle away … the worst the cadence
         * gives", which the recorded offer days contradicted — the slice S13 review.)
         */
        const val COMPROMISE_DAY = 31

        /**
         * The leak one or two days before the day-26 replacement: that replacement then goes to a
         * key the peer announced before the leak, and healing waits for the next one
         * ([pq3APqRootToALeakedGenerationDoesNotHeal]).
         */
        const val EARLY_COMPROMISE_DAY = 24

        /** §9.4: "about 5–6 weeks of ordinary two-way use at the default cadence". */
        const val HEALING_BOUND_WEEKS = 6L

        /** No half of the check may pass on an empty sample. */
        const val FLOOR = 3
    }
}
