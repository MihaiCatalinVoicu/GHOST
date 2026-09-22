package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.DmDevice
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.Timer

/**
 * The T34 seizure scenario (Phase 9 design §15.6, §14.1 T34): "a separate world: 10 clients, 70
 * virtual days, daily conversations: at day 70 dump two clients' databases, state keys and seeds;
 * try every stored key, every derivation, … on every archived blob".
 *
 * **What is seized, and how it is tried.** The two clients with the most accepted conversations.
 * A seized client is its whole device — the database, the DM context that holds its seed-derived
 * keys and its `session_state_key` — so "try" is a call into that same context, which is exactly
 * what an adversary holding the dump can do. **Every stored key** is every 32-byte value (as a
 * recognition key) and every 60-byte value (as a key envelope: the size of every wrapped week key,
 * root and `reply_seed`) of **any column of any table** of the database, not only the rows that are
 * supposed to hold keys — so a copy of a week key, a root or a `reply_seed` kept anywhere is found.
 * The archive is every blob any relay ever stored ([ViewRelay.archive], AD-1's archive). Each check
 * is against the seized device's **last relay session**, the last time its SWEEP ran.
 *
 * **What is checked, per seized client** (each half has a floor, so an empty sample fails):
 *  1. **Pair mode** (§6.3 P-7): over the pair-mode blobs of the client's conversations sealed in a
 *     week `w` with `start(w + 1) + 45 d ≤` the seizure, no stored value recognises one (R-S6,
 *     PM-36) or opens one (PM-19), and no **derived** key recognises one: the seed's and every held
 *     card's recognition keys, and the week keys every stored value yields when taken as the root of
 *     each generation the client offered ("every derivation"; a root kept after its acknowledgement).
 *     Opening is tried on the blobs **to** the client only: `openPair` unwraps a key under the `in`
 *     binding (the bridge fixes the direction), so a sender's out key cannot open what it sent through
 *     the surface, and the blobs it sent are tried by recognition, which takes raw keys. The
 *     **controls**: every current-window pair blob to the client is recognised and opened, and every
 *     blob it sealed this week under the newest root its peer offered it (the one out key it keeps,
 *     §6.3) is recognised, by the same calls — so a "0" is not the output of a broken attempt, in
 *     either direction. The out-direction sample is floored over the seizure, not per client.
 *  2. **Intro mode** (§6.4 "Attribution of first contacts"): every intro blob to the client opens
 *     with a retained generation **exactly** when the generation it names is not yet due for erasure
 *     (`superseded_day + 91`, supersession being the recorder's next generation of the client); in a
 *     70-day world none is due, the line says how many were, and it is not an erasure test.
 *  3. **Provisional mode** (§6.7 as amended by §22.8.5): no session still holds `prov_env` 45 days
 *     after a pair envelope from its peer first opened, nor 119 days after its anchor (both from the
 *     recorder: an initiator's first decryption, a responder's first provisional seal); and every
 *     provisional blob of the client's conversations is **tried** with every stored value taken as
 *     the session's `reply_seed`: none of a session due for erasure opens. The control is the same
 *     attempt at day [CHECKPOINT_DAY], while every `prov_env` is still held: every provisional blob
 *     the client had by then opens.
 * **Not done here (§22.16):** Olm decryption with every retained session and the throwaway-account
 * session over every retained generation (`inbound`, §2.6 function 14) on the layers that do open,
 * X-Wing decapsulation separately from `openIntro`, the lossless variant, and MC-30's age case.
 */
internal object Seizure {

    /**
     * The day of the provisional control: after the last planned establishment (invitees activate by
     * day 7, their edges within a day and a half), and while every `prov_env` is still held (the
     * earliest erasure is 45 days after a pair envelope first opened).
     */
    const val CHECKPOINT_DAY: Long = 10

    /** Per client: provisional blobs it had at the checkpoint, and how many its stored values opened. */
    class Checkpoint(val blobs: Map<Int, Int>, val opened: Map<Int, Int>)

    class ClientResult(
        val client: Int,
        val candidates32: Int,
        val candidates60: Int,
        val oldPairBlobs: Int,
        val oldTriedForOpening: Int,
        val oldRecognised: Int,
        val oldOpened: Int,
        val oldRecognisedByDerivation: Int,
        val rootsTried: Int,
        val currentInBlobs: Int,
        val currentInOpened: Int,
        val currentOutBlobs: Int,
        val currentOutRecognised: Int,
        val introBlobs: Int,
        val introOpened: Int,
        val introExpected: Int,
        val introWrong: Int,
        val introDueGenerations: Int,
        val provRetained: Int,
        val provDue: Int,
        val provPastRule: Int,
        val provBlobs: Int,
        val provBlobsOfDue: Int,
        val provOpenedOfDue: Int,
        val controlProvBlobs: Int,
        val controlProvOpened: Int,
    )

    class Result(val day: Long, val clients: List<ClientResult>) {
        val violations: List<String>
            get() = clients.flatMap { c ->
                listOfNotNull(
                    "c${c.client}: ${c.oldOpened} old-week pair envelopes opened by retained keys".takeIf { c.oldOpened > 0 },
                    "c${c.client}: ${c.oldRecognised} old-week pair envelopes recognised by a retained recognition key"
                        .takeIf { c.oldRecognised > 0 },
                    "c${c.client}: ${c.oldRecognisedByDerivation} old-week pair envelopes recognised by a derived key"
                        .takeIf { c.oldRecognisedByDerivation > 0 },
                    "c${c.client}: ${c.provPastRule} sessions keep prov_env past §22.8.5's erase point"
                        .takeIf { c.provPastRule > 0 },
                    "c${c.client}: ${c.provOpenedOfDue} provisional blobs of sessions due for erasure opened"
                        .takeIf { c.provOpenedOfDue > 0 },
                    "c${c.client}: intro ${c.introOpened} opened, ${c.introExpected} expected (${c.introWrong} wrong)"
                        .takeIf { c.introWrong > 0 },
                )
            }

        val floorsMet: List<String>
            get() = clients.flatMap { c ->
                listOfNotNull(
                    "c${c.client}: only ${c.oldPairBlobs} expired-week pair blobs (floor $FLOOR_OLD)".takeIf { c.oldPairBlobs < FLOOR_OLD },
                    "c${c.client}: the in-direction control recognised and opened ${c.currentInOpened} of ${c.currentInBlobs}"
                        .takeIf { c.currentInBlobs == 0 || c.currentInOpened != c.currentInBlobs },
                    "c${c.client}: the out-direction control recognised ${c.currentOutRecognised} of ${c.currentOutBlobs}"
                        .takeIf { c.currentOutRecognised != c.currentOutBlobs },
                    "c${c.client}: the day-$CHECKPOINT_DAY provisional control opened ${c.controlProvOpened} of ${c.controlProvBlobs}"
                        .takeIf { c.controlProvBlobs == 0 || c.controlProvOpened != c.controlProvBlobs },
                    "c${c.client}: no intro blob to try".takeIf { c.introBlobs == 0 },
                ) + listOfNotNull(
                    // A seized client may not have written this week under the newest root its peer
                    // gave it; the seizure as a whole must have such a blob.
                    "no current-week out-direction pair blob to recognise".takeIf { clients.sumOf { it.currentOutBlobs } == 0 },
                    "no session anywhere was due to erase prov_env".takeIf { clients.sumOf { it.provDue } == 0 },
                    "no provisional blob of a due session to try".takeIf { clients.sumOf { it.provBlobsOfDue } == 0 },
                )
            }.distinct()

        val passed: Boolean get() = violations.isEmpty() && floorsMet.isEmpty()

        fun line(): String =
            "dm T34: ${if (passed) "PASS" else "FAIL"} seized ${clients.joinToString(", ") { "c${it.client}" }} at day $day; " +
                "expired-week pair blobs ${clients.sumOf { it.oldPairBlobs }}, " +
                "${clients.sumOf { it.oldRecognised }} recognised and ${clients.sumOf { it.oldOpened }} opened by retained keys " +
                "(every stored value: ${clients.sumOf { it.candidates32 }} of 32 bytes, ${clients.sumOf { it.candidates60 }} of 60; " +
                "opening tried on the ${clients.sumOf { it.oldTriedForOpening }} in-direction ones), " +
                "${clients.sumOf { it.oldRecognisedByDerivation }} recognised by derived keys " +
                "(seed, cards, ${clients.sumOf { it.rootsTried }} root derivations); " +
                "control ${clients.sumOf { it.currentInOpened }} of ${clients.sumOf { it.currentInBlobs }} current in-direction pair blobs " +
                "recognised and opened, ${clients.sumOf { it.currentOutRecognised }} of ${clients.sumOf { it.currentOutBlobs }} " +
                "current-week out-direction recognised; " +
                "intro ${clients.sumOf { it.introOpened }} of ${clients.sumOf { it.introBlobs }} opened, " +
                "${clients.sumOf { it.introExpected }} expected (${clients.sumOf { it.introDueGenerations }} generations due for erasure); " +
                "prov_env ${clients.sumOf { it.provRetained }} retained, ${clients.sumOf { it.provDue }} due erased, " +
                "${clients.sumOf { it.provPastRule }} past the rule; provisional blobs ${clients.sumOf { it.provBlobs }}, " +
                "${clients.sumOf { it.provOpenedOfDue }} of ${clients.sumOf { it.provBlobsOfDue }} of due sessions opened, " +
                "day-$CHECKPOINT_DAY control ${clients.sumOf { it.controlProvOpened }} of ${clients.sumOf { it.controlProvBlobs }} opened" +
                (if (violations.isEmpty()) "" else "; " + violations.joinToString("; ")) +
                (if (floorsMet.isEmpty()) "" else "; floors: " + floorsMet.joinToString("; "))
    }

    const val FLOOR_OLD: Int = 10
    const val FRESH: Long = 45 * DmWorld.DAY
    const val PROV_MAX: Long = 119 * DmWorld.DAY

    /** §15.6's seizure world: 10 clients, 70 days, daily conversations. */
    fun config(seed: Long, mutant: PrivacyMutant? = null, days: Int = 70): PrivacyWorldConfig =
        PrivacyWorldConfig(seed = seed, clients = 10, days = days, mutant = mutant, meanDegree = 3.0, burstsPerDay = 1.0)

    /** Runs the seizure world of [config]: the checkpoint at day [CHECKPOINT_DAY], then the seizure. */
    fun seize(config: PrivacyWorldConfig): Result = PrivacyWorld(config).use { world ->
        world.runUntil(config.startSeconds + CHECKPOINT_DAY * DmWorld.DAY)
        val checkpoint = checkpoint(world)
        world.run()
        run(world, checkpoint)
    }

    /** The provisional control, for every client (the seized ones are only known at the end). */
    fun checkpoint(world: PrivacyWorld): Checkpoint {
        val archive = world.relay.archive()
        val blobs = HashMap<Int, Int>()
        val opened = HashMap<Int, Int>()
        for (client in world.clients) {
            if (!client.activated) continue
            val stored = storedValues(client.device)
            val result = provisional(world, client.index, client.device, archive, stored.second, dueSessions = emptySet())
            blobs[client.index] = result.blobs
            opened[client.index] = result.opened
        }
        return Checkpoint(blobs, opened)
    }

    fun run(world: PrivacyWorld, checkpoint: Checkpoint): Result {
        val seized = world.acceptedEdges.flatMap { listOf(it.first, it.second) }
            .groupingBy { it }.eachCount().entries.sortedWith(compareBy({ -it.value }, { it.key }))
            .take(2).map { it.key }
        val archive = world.relay.archive()
        val day = Math.floorDiv(world.now - world.config.startSeconds, DmWorld.DAY)
        return Result(day, seized.map { seize(world, it, archive, checkpoint) })
    }

    // ------------------------------------------------------------------ the dump

    /** Every distinct BLOB value of every column of every table: (32-byte values, 60-byte values). */
    private fun storedValues(device: DmDevice): Pair<List<ByteArray>, List<ByteArray>> {
        val tables = ArrayList<String>()
        device.sql.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'") {
            tables += it.string(0)
        }
        val v32 = LinkedHashSet<GroundTruth.Key>()
        val v60 = LinkedHashSet<GroundTruth.Key>()
        for (table in tables) {
            val columns = ArrayList<String>()
            device.sql.query("SELECT name FROM pragma_table_info(?)", listOf(table)) { columns += it.string(0) }
            for (column in columns) {
                device.sql.query(
                    "SELECT \"$column\" FROM \"$table\" WHERE typeof(\"$column\") = 'blob' AND length(\"$column\") IN (32, 60)",
                ) { r ->
                    val bytes = r.blob(0)
                    if (bytes.size == 32) v32 += GroundTruth.Key(bytes) else v60 += GroundTruth.Key(bytes)
                }
            }
        }
        return v32.map { it.bytes } to v60.map { it.bytes }
    }

    /** The seized device's own contact id for [peer], or null. */
    private fun contactOf(world: PrivacyWorld, device: DmDevice, peer: Int): ByteArray? {
        val pk = world.truth.clients[peer]?.identityPk ?: return null
        var id: ByteArray? = null
        device.sql.query("SELECT contact_id FROM dm_contact WHERE identity_pk = ?", listOf(pk)) { id = it.blob(0) }
        return id
    }

    private class Provisional(val blobs: Int, val opened: Int, val blobsOfDue: Int, val openedOfDue: Int)

    /**
     * Every provisional blob of [s]'s conversations, tried with every stored 60-byte value taken as
     * its session's `reply_seed`, through [device]'s own `provisionalKeys` and `openProvisional`.
     */
    private fun provisional(
        world: PrivacyWorld,
        s: Int,
        device: DmDevice,
        archive: List<Triple<ByteArray, ByteArray, Long>>,
        candidates: List<ByteArray>,
        dueSessions: Set<GroundTruth.Key>,
    ): Provisional {
        val truth = world.truth
        val own = truth.clients[s] ?: return Provisional(0, 0, 0, 0)
        val ownInbox = own.inboxNamespace ?: return Provisional(0, 0, 0, 0)
        class Session(val contact: ByteArray, val stateEnv: ByteArray)
        val sessions = HashMap<GroundTruth.Key, Session>()
        device.sql.query("SELECT session_id, contact_id, state_env FROM olm_session") { r ->
            sessions[GroundTruth.Key(r.blob(0))] = Session(r.blob(1), r.blob(2))
        }
        val keys = HashMap<Pair<GroundTruth.Key, Int>, DmPairing.Provisional?>()
        var blobs = 0
        var opened = 0
        var blobsOfDue = 0
        var openedOfDue = 0
        for ((namespace, blob, _) in archive) {
            val key = GroundTruth.Key(GroundTruth.sha256(blob))
            if (truth.modeOfBlob[key] != DmSeal.Mode.PROVISIONAL) continue
            val sender = truth.senderOfBlob[key] ?: continue
            val incoming = namespace.contentEquals(ownInbox)
            if (!incoming && sender != s) continue
            val peer = if (incoming) sender else truth.ownerOfInbox(namespace) ?: continue
            val peerOi = truth.clients[peer]?.olmIdentity ?: continue
            val sessionId = truth.sessionOfBlob[key] ?: continue
            blobs++
            val due = sessionId in dueSessions
            if (due) blobsOfDue++
            val session = sessions[sessionId]
            var open = false
            if (session != null) {
                for ((i, candidate) in candidates.withIndex()) {
                    val derived = keys.getOrPut(sessionId to i) {
                        val result = device.envelopes.provisionalKeys(session.contact, sessionId.bytes, session.stateEnv, candidate, peerOi)
                        (result as? DmPairing.ProvisionalResult.Ok)?.keys
                    } ?: continue
                    val result = if (incoming) {
                        device.envelopes.openProvisional(
                            namespace, blob, derived.inEnv, derived.inDirection, sessionId.bytes, peerOi, own.olmIdentity!!,
                        )
                    } else {
                        device.envelopes.openProvisional(
                            namespace, blob, derived.outEnv, derived.outDirection, sessionId.bytes, own.olmIdentity!!, peerOi,
                        )
                    }
                    if (result is DmSeal.OuterSymmetric.Ok) {
                        open = true
                        break
                    }
                }
            }
            if (open) opened++
            if (open && due) openedOfDue++
        }
        return Provisional(blobs, opened, blobsOfDue, openedOfDue)
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod")
    private fun seize(
        world: PrivacyWorld,
        s: Int,
        archive: List<Triple<ByteArray, ByteArray, Long>>,
        checkpoint: Checkpoint,
    ): ClientResult {
        val device = world.clients[s].device
        val truth = world.truth
        val own = truth.clients.getValue(s)
        val ownInbox = own.inboxNamespace!!
        val ownOi = own.olmIdentity!!
        // The device's last SWEEP: a key that expired after it cannot have been erased yet.
        val now = world.lastWakeOf(s) ?: world.now
        val nowWeek = world.weekOf(now)
        val (v32, v60) = storedValues(device)

        // "Every derivation": the recognition keys the seed and the held cards give — the own card's
        // intro and bundle keys and every contact card's. None is a pair key by construction (§3.1:
        // roots are random), and the attempt is what shows it.
        val derived = ArrayList<ByteArray>()
        device.crypto.ownCard(0)?.let { derived += it.recognitionIntro; derived += it.recognitionBundle }
        val peers = HashSet<Int>()
        for ((u, v) in world.acceptedEdges) {
            when (s) {
                u -> peers += v
                v -> peers += u
            }
        }
        for (peer in peers) {
            val card = truth.clients[peer]?.card ?: continue
            val d = device.crypto.deriveCard(card, 0)
            if (d is org.ghost.crypto.bridge.DmCards.DeriveResult.Ok) {
                derived += d.values.recognitionIntro
                derived += d.values.recognitionBundle
                d.values.clearSecrets()
            }
        }
        // And the week keys of every root generation this client offered, taking every stored
        // 60-byte value as that root: a root kept after its acknowledgement derives every old key.
        var rootsTried = 0
        val rootDerived = HashMap<GroundTruth.Key, MutableList<ByteArray>>()
        for ((offer, baseWeek) in truth.offers) {
            if (offer.first != s) continue
            for (candidate in v60) {
                rootsTried++
                val keys = device.envelopes.pairKeys(
                    offer.second.bytes, DmSeal.PairDirection.IN, offer.third, DmPairing.From.ROOT, candidate,
                    baseWeek, baseWeek, minOf(baseWeek + DmPairing.MAX_WINDOW_WEEKS, nowWeek),
                )
                if (keys is DmPairing.KeysResult.Ok) {
                    rootDerived.getOrPut(offer.second) { ArrayList() } += keys.weeks.map { it.recognitionKey }
                }
            }
        }

        val contacts = HashMap<Int, ByteArray?>()
        var oldPair = 0
        var oldTriedForOpening = 0
        var oldRecognised = 0
        var oldOpened = 0
        var oldDerived = 0
        var inBlobs = 0
        var inOpened = 0
        var outBlobs = 0
        var outRecognised = 0
        var intro = 0
        var introOpened = 0
        var introExpected = 0
        var introWrong = 0
        val dueGenerations = HashSet<Int>()
        // The newest root generation each peer offered this client (the out control): the sender
        // keeps the week key of the newest generation it received only (§6.3), so a blob it sealed
        // under an older one is legitimately unrecognisable to it once the newer root arrived.
        val newestOut = HashMap<Int, Int>()
        for (peer in peers) {
            val atPeer = contactOf(world, world.clients[peer].device, s)?.let { GroundTruth.Key(it) } ?: continue
            truth.offers.keys.filter { it.first == peer && it.second == atPeer }.maxOfOrNull { it.third }
                ?.let { newestOut[peer] = it }
        }
        for ((namespace, blob, _) in archive) {
            val key = GroundTruth.Key(GroundTruth.sha256(blob))
            val mode = truth.modeOfBlob[key] ?: continue
            val sender = truth.senderOfBlob[key] ?: continue
            val incoming = namespace.contentEquals(ownInbox)
            if (!incoming && sender != s) continue
            when (mode) {
                DmSeal.Mode.PAIR -> {
                    val peer = if (incoming) sender else truth.ownerOfInbox(namespace) ?: continue
                    val week = truth.weekOfBlob[key] ?: continue
                    val rootGen = truth.rootGenOfBlob[key] ?: continue
                    val peerOi = truth.clients[peer]?.olmIdentity ?: continue
                    val contact = contacts.getOrPut(peer) { contactOf(world, device, peer) } ?: continue
                    val expired = weekStart(week + 1) + FRESH <= now
                    // Opening goes through `openPair`, which unwraps a key under the `in` binding
                    // only (the bridge fixes the direction): an out key cannot be tried on the
                    // blobs this client sent, through the surface or otherwise short of the state
                    // key itself. Those are tried by **recognition** (hints take raw keys).
                    fun opened(): Boolean = incoming && v60.any {
                        device.envelopes.openPair(namespace, blob, it, contact, rootGen, week, peerOi, ownOi) is
                            DmSeal.OuterSymmetric.Ok
                    }
                    fun recognised(): Boolean = v32.any { device.envelopes.hintMatches(blob, it) }
                    if (expired) {
                        oldPair++
                        if (incoming) oldTriedForOpening++
                        if (recognised()) oldRecognised++
                        if (opened()) oldOpened++
                        val fromRoots = rootDerived[GroundTruth.Key(contact)].orEmpty()
                        if ((derived + fromRoots).any { device.envelopes.hintMatches(blob, it) }) oldDerived++
                    } else if (incoming) {
                        inBlobs++
                        if (recognised() && opened()) inOpened++
                    } else if (week == nowWeek && rootGen == newestOut[peer]) {
                        outBlobs++
                        if (recognised()) outRecognised++
                    }
                }
                DmSeal.Mode.INTRO -> {
                    if (!incoming) continue
                    intro++
                    val dueGen = truth.introGenOfBlob[key]?.takeIf { generationDue(truth, s, it, now) }
                    val due = dueGen != null
                    dueGen?.let { dueGenerations += it }
                    if (!due) introExpected++
                    var opened = false
                    val outer = device.envelopes.openOuterIntro(0, namespace, blob)
                    if (outer is DmSeal.OuterIntro.Ok) {
                        var retained: Pair<ByteArray, ByteArray>? = null
                        device.sql.query(
                            "SELECT secrets_env, fallback_pub FROM olm_prekey_gen WHERE gen_id = ?",
                            listOf(outer.genId.toLong() and 0xffffffffL),
                        ) { r -> retained = r.blob(0) to r.blob(1) }
                        retained?.let { (secrets, fallback) ->
                            opened = device.envelopes.openIntro(0, namespace, outer.genId, secrets, fallback, blob) is
                                DmSeal.OpenedIntro.Ok
                        }
                    }
                    if (opened) introOpened++
                    if (opened == due) introWrong++
                }
                else -> Unit
            }
        }

        // Provisional: every session against §22.8.5's two erase points, from the recorder.
        var retained = 0
        var pastRule = 0
        var provDue = 0
        val dueSessions = HashSet<GroundTruth.Key>()
        device.sql.query(
            "SELECT contact_id, session_id, role, prov_env IS NOT NULL FROM olm_session",
        ) { r ->
            val contact = GroundTruth.Key(r.blob(0))
            val session = GroundTruth.Key(r.blob(1))
            val holds = r.long(3) == 1L
            val anchor = if (r.string(2) == "initiator") {
                truth.firstDecrypt[s to contact]
            } else {
                truth.firstProvisionalSeal[s to session]
            }
            val firstOpen = truth.firstPairOpen[s to contact]
            val due = (firstOpen != null && firstOpen + FRESH <= now) || (anchor != null && anchor + PROV_MAX <= now)
            if (due) {
                provDue++
                dueSessions += session
            }
            if (holds) {
                retained++
                if (due) pastRule++
            }
        }
        val prov = provisional(world, s, device, archive, v60, dueSessions)
        return ClientResult(
            client = s,
            candidates32 = v32.size,
            candidates60 = v60.size,
            oldPairBlobs = oldPair,
            oldTriedForOpening = oldTriedForOpening,
            oldRecognised = oldRecognised,
            oldOpened = oldOpened,
            oldRecognisedByDerivation = oldDerived,
            rootsTried = rootsTried,
            currentInBlobs = inBlobs,
            currentInOpened = inOpened,
            currentOutBlobs = outBlobs,
            currentOutRecognised = outRecognised,
            introBlobs = intro,
            introOpened = introOpened,
            introExpected = introExpected,
            introWrong = introWrong,
            introDueGenerations = dueGenerations.size,
            provRetained = retained,
            provDue = provDue,
            provPastRule = pastRule,
            provBlobs = prov.blobs,
            provBlobsOfDue = prov.blobsOfDue,
            provOpenedOfDue = prov.openedOfDue,
            controlProvBlobs = checkpoint.blobs[s] ?: 0,
            controlProvOpened = checkpoint.opened[s] ?: 0,
        )
    }

    /**
     * §5.4: generation [gen] of client [s] is erased at `superseded_day + 91`, supersession being
     * the creation of its next generation (the recorder's [GroundTruth.generations]).
     */
    private fun generationDue(truth: GroundTruth, s: Int, gen: Int, now: Long): Boolean {
        val created = truth.generations[s]?.entries?.toList() ?: return false
        val at = created.indexOfFirst { it.key == gen }
        if (at < 0 || at + 1 >= created.size) return false
        val superseded = Math.floorDiv(created[at + 1].value, DmWorld.DAY)
        return Math.floorDiv(now, DmWorld.DAY) >= superseded + 91
    }

    private fun weekStart(week: Long): Long = DmWorld.WEEK_ORIGIN + week * DmWorld.WEEK

    // ------------------------------------------------------------ one reply

    /**
     * §15.6's **one-reply variant** of T34 (§22.8.5 rule 8): "the peer never writes after receiving
     * my root; the world runs 130 virtual days and is dumped at day 125", and both devices must have
     * erased `prov_env` by `prov_anchor_minute + 119 d` (PM-39).
     *
     * Two clients: A scans B's card and writes (intro), B accepts and answers (provisional, carrying
     * B's root), A answers once more (pair-sealed under B's root, carrying A's) — and B never writes
     * again, so A never opens a pair envelope under **its own** root and never acknowledges it: only
     * the anchor bounds A's `prov_env`. The anchors are the recorder's (A's first decryption, B's
     * first provisional seal), the check is against each device's last relay session before day 125.
     */
    class OneReply(val sessions: List<String>, val kept: List<String>, val due: Int, val held: Int) {
        val passed: Boolean get() = kept.isEmpty() && due == 2 && held == 2

        fun line(): String =
            "dm T34 one-reply: ${if (passed) "PASS" else "FAIL"} dumped at day $ONE_REPLY_DUMP_DAY: $due of 2 sessions due " +
                "by prov_anchor_minute + 119 d, $held of 2 provably held prov_env, ${kept.size} keep it (${sessions.joinToString("; ")})" +
                (if (kept.isEmpty()) "" else "; " + kept.joinToString("; ")) +
                (if (due == 2 && held == 2) "" else "; floors: both sessions must have held prov_env and be due")
    }

    const val ONE_REPLY_DAYS: Int = 130
    const val ONE_REPLY_DUMP_DAY: Long = 125

    fun oneReply(seed: Long, mutant: PrivacyMutant? = null): OneReply {
        val start = DmWorld.WEEK_ORIGIN + 2_870 * DmWorld.WEEK + 2 * DmWorld.DAY
        val plan = Plan.scripted(
            activation = LongArray(2) { start },
            edges = listOf(
                Plan.Edge(
                    0, 1, start + DmWorld.HOUR, reject = false, timer = Timer.DAYS_7,
                    bursts = listOf(Plan.Burst(start + 3 * DmWorld.HOUR, listOf(Plan.Message(true, 0, 20)))),
                ),
            ),
            seed = seed,
        )
        val config = PrivacyWorldConfig(seed = seed, clients = 2, days = ONE_REPLY_DAYS, mutant = mutant, plan = plan)
        return PrivacyWorld(config).use { world ->
            world.runUntil(start + ONE_REPLY_DUMP_DAY * DmWorld.DAY)
            val truth = world.truth
            val sessions = ArrayList<String>()
            val kept = ArrayList<String>()
            var due = 0
            var held = 0
            for (c in 0..1) {
                val now = world.lastWakeOf(c) ?: world.now
                world.clients[c].device.sql.query(
                    "SELECT contact_id, session_id, role, prov_env IS NOT NULL FROM olm_session",
                ) { r ->
                    val contact = GroundTruth.Key(r.blob(0))
                    val session = GroundTruth.Key(r.blob(1))
                    val role = r.string(2)
                    val anchor = if (role == "initiator") truth.firstDecrypt[c to contact] else truth.firstProvisionalSeal[c to session]
                    // The session held a reply_seed: an initiator sealed its intro with one, a
                    // responder sealed provisional with it.
                    val provable = if (role == "initiator") {
                        truth.sessions.contains(c to (1 - c)) && anchor != null
                    } else {
                        truth.firstProvisionalSeal.containsKey(c to session)
                    }
                    if (provable) held++
                    val isDue = anchor != null && anchor + PROV_MAX <= now
                    if (isDue) due++
                    val holds = r.long(3) == 1L
                    val anchorDay = anchor?.let { Math.floorDiv(it - start, DmWorld.DAY) }
                    sessions += "c$c $role anchor day $anchorDay ${if (holds) "holds" else "erased"}"
                    if (holds && isDue) kept += "c$c keeps prov_env past prov_anchor_minute + 119 d"
                }
            }
            OneReply(sessions, kept, due, held)
        }
    }
}
