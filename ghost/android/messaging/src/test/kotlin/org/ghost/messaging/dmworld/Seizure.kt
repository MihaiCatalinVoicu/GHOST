package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.DmWorld

/**
 * The T34 seizure scenario (Phase 9 design §15.6, §14.1 T34): "a separate world: 10 clients, 70
 * virtual days, daily conversations: at day 70 dump two clients' databases, state keys and seeds;
 * try every stored key, every derivation, … on every archived blob".
 *
 * **What is seized, and how it is tried.** The two clients with the most accepted conversations.
 * A seized client is its whole device — the database, the DM context that holds its seed-derived
 * keys and its `session_state_key` — so "try every stored key" is a call into that same context with
 * each stored row, which is exactly what an adversary holding the dump can do. The archive is every
 * blob any relay ever stored ([ViewRelay.archive], AD-1's archive).
 *
 * **What is checked, per seized client** (each half has a floor, so an empty sample fails):
 *  1. **Pair mode** (§6.3 P-7): over the pair-mode blobs of the client's conversations sealed in a
 *     week `w` with `start(w + 1) + 45 d ≤ day 70`, every stored `dm_pair_key` row's recognition key
 *     recognises none (R-S6, PM-36) and its opening key opens none (PM-19); the seed-derived and
 *     card-derived recognition keys recognise none either ("every derivation"). The **control**:
 *     current-window pair blobs of the same conversations *are* recognised and opened by the same
 *     calls, so a "0" is not the output of a broken attempt.
 *  2. **Intro mode** (§6.4 "Attribution of first contacts"): every intro blob to the client opens
 *     with a retained generation exactly when its generation is not yet due for erasure
 *     (`superseded_day + 91`); in a 70-day world none is due, so the expectation is all of them, and
 *     the line says so rather than presenting it as an erasure test.
 *  3. **Provisional mode** (§6.7 as amended by §22.8.5): no session still holds `prov_env` 45 days
 *     after a pair envelope from its peer first opened, nor 119 days after its anchor; the number of
 *     sessions the rule required erased is reported and must be non-zero.
 * **Not done here (§22.16):** Olm decryption with every retained session and throwaway accounts over
 * every generation (the outer layers above never open for expired weeks, so there is nothing for
 * them to run on), X-Wing decapsulation separately from `openIntro`, and the one-reply 130-day
 * variant with its PM-39.
 */
internal object Seizure {

    class ClientResult(
        val client: Int,
        val oldPairBlobs: Int,
        val oldRecognised: Int,
        val oldOpened: Int,
        val oldRecognisedByDerivation: Int,
        val currentPairBlobs: Int,
        val currentOpened: Int,
        val introBlobs: Int,
        val introOpened: Int,
        val introExpected: Int,
        val provRetained: Int,
        val provDue: Int,
        val provPastRule: Int,
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
                    "c${c.client}: intro ${c.introOpened} opened, ${c.introExpected} expected"
                        .takeIf { c.introOpened != c.introExpected },
                )
            }

        val floorsMet: List<String>
            get() = clients.flatMap { c ->
                listOfNotNull(
                    "c${c.client}: only ${c.oldPairBlobs} expired-week pair blobs (floor $FLOOR_OLD)".takeIf { c.oldPairBlobs < FLOOR_OLD },
                    "c${c.client}: the control opened no current pair blob".takeIf { c.currentOpened == 0 },
                    "c${c.client}: no intro blob to try".takeIf { c.introBlobs == 0 },
                ) + listOfNotNull(
                    "no session anywhere was due to erase prov_env".takeIf { clients.sumOf { it.provDue } == 0 },
                )
            }.distinct()

        val passed: Boolean get() = violations.isEmpty() && floorsMet.isEmpty()

        fun line(): String =
            "dm T34: ${if (passed) "PASS" else "FAIL"} seized ${clients.joinToString(", ") { "c${it.client}" }} at day $day; " +
                "expired-week pair blobs ${clients.sumOf { it.oldPairBlobs }}, " +
                "${clients.sumOf { it.oldRecognised }} recognised and ${clients.sumOf { it.oldOpened }} opened by retained keys, " +
                "${clients.sumOf { it.oldRecognisedByDerivation }} recognised by derived keys; " +
                "control ${clients.sumOf { it.currentOpened }} of ${clients.sumOf { it.currentPairBlobs }} current pair blobs opened; " +
                "intro ${clients.sumOf { it.introOpened }} of ${clients.sumOf { it.introExpected }} expected opened " +
                "(no generation due for erasure before day 91); " +
                "prov_env ${clients.sumOf { it.provRetained }} retained, ${clients.sumOf { it.provDue }} due erased, " +
                "${clients.sumOf { it.provPastRule }} past the rule" +
                (if (violations.isEmpty()) "" else "; " + violations.joinToString("; ")) +
                (if (floorsMet.isEmpty()) "" else "; floors: " + floorsMet.joinToString("; "))
    }

    const val FLOOR_OLD: Int = 10
    const val FRESH: Long = 45 * DmWorld.DAY

    /** §15.6's seizure world: 10 clients, 70 days, daily conversations. */
    fun config(seed: Long, mutant: PrivacyMutant? = null, days: Int = 70): PrivacyWorldConfig =
        PrivacyWorldConfig(seed = seed, clients = 10, days = days, mutant = mutant, meanDegree = 3.0, burstsPerDay = 1.0)

    fun run(world: PrivacyWorld): Result {
        val seized = world.acceptedEdges.flatMap { listOf(it.first, it.second) }
            .groupingBy { it }.eachCount().entries.sortedWith(compareBy({ -it.value }, { it.key }))
            .take(2).map { it.key }
        val archive = world.relay.archive()
        val day = Math.floorDiv(world.now - world.config.startSeconds, DmWorld.DAY)
        return Result(day, seized.map { seize(world, it, archive) })
    }

    private class PairKeyRow(
        val contact: ByteArray,
        val direction: String,
        val rootGen: Int,
        val week: Long,
        val recognition: ByteArray,
        val open: ByteArray,
    )

    private fun seize(world: PrivacyWorld, s: Int, archive: List<Triple<ByteArray, ByteArray, Long>>): ClientResult {
        val device = world.clients[s].device
        val truth = world.truth
        val own = truth.clients.getValue(s)
        val ownInbox = own.inboxNamespace!!
        val now = world.now

        val keys = ArrayList<PairKeyRow>()
        device.sql.query(
            "SELECT contact_id, direction, root_gen, week, recog_key, open_env FROM dm_pair_key",
        ) { r -> keys += PairKeyRow(r.blob(0), r.string(1), r.long(2).toInt(), r.long(3), r.blob(4), r.blob(5)) }
        val pinned = HashMap<GroundTruth.Key, ByteArray>()
        val contactCards = ArrayList<ByteArray>()
        device.sql.query("SELECT contact_id, identity_pk, pinned_identity FROM dm_contact") { r ->
            if (!r.isNull(2)) pinned[GroundTruth.Key(r.blob(0))] = r.blob(2)
            val pk = r.blob(1)
            truth.clients.values.firstOrNull { it.identityPk?.contentEquals(pk) == true }?.card?.let { contactCards += it }
        }
        // "Every derivation": the recognition keys the seed and the held cards give — the own card's
        // intro and bundle keys and every contact card's. None is a pair key by construction (§3.1:
        // roots are random), and the attempt is what shows it.
        val derived = ArrayList<ByteArray>()
        device.crypto.ownCard(0)?.let { derived += it.recognitionIntro; derived += it.recognitionBundle }
        for (card in contactCards) {
            val d = device.crypto.deriveCard(card, 0)
            if (d is org.ghost.crypto.bridge.DmCards.DeriveResult.Ok) {
                derived += d.values.recognitionIntro
                derived += d.values.recognitionBundle
                d.values.clearSecrets()
            }
        }
        val contactInboxes = HashSet<GroundTruth.Key>()
        for ((u, v) in world.acceptedEdges) {
            val peer = when (s) { u -> v; v -> u; else -> continue }
            truth.clients[peer]?.inboxNamespace?.let { contactInboxes += GroundTruth.Key(it) }
        }

        var oldPair = 0
        var oldRecognised = 0
        var oldOpened = 0
        var oldDerived = 0
        var currentPair = 0
        var currentOpened = 0
        var intro = 0
        var introOpened = 0
        for ((namespace, blob, _) in archive) {
            val key = GroundTruth.Key(GroundTruth.sha256(blob))
            val mode = truth.modeOfBlob[key] ?: continue
            val mine = namespace.contentEquals(ownInbox) ||
                (truth.senderOfBlob[key] == s && GroundTruth.Key(namespace) in contactInboxes)
            if (!mine) continue
            when (mode) {
                DmSeal.Mode.PAIR -> {
                    val week = truth.weekOfBlob[key] ?: continue
                    val expired = weekStart(week + 1) + FRESH <= now
                    var recognised = false
                    var opened = false
                    for (row in keys) {
                        if (!device.envelopes.hintMatches(blob, row.recognition)) continue
                        recognised = true
                        val peerOi = pinned[GroundTruth.Key(row.contact)] ?: continue
                        val (sender, recipient) =
                            if (row.direction == "in") peerOi to own.olmIdentity!! else own.olmIdentity!! to peerOi
                        val result = device.envelopes.openPair(
                            namespace, blob, row.open, row.contact, row.rootGen, row.week, sender, recipient,
                        )
                        if (result is DmSeal.OuterSymmetric.Ok) opened = true
                    }
                    if (expired) {
                        oldPair++
                        if (recognised) oldRecognised++
                        if (opened) oldOpened++
                        if (derived.any { device.envelopes.hintMatches(blob, it) }) oldDerived++
                    } else if (namespace.contentEquals(ownInbox)) {
                        currentPair++
                        if (opened) currentOpened++
                    }
                }
                DmSeal.Mode.INTRO -> {
                    if (!namespace.contentEquals(ownInbox)) continue
                    intro++
                    val outer = device.envelopes.openOuterIntro(0, namespace, blob)
                    if (outer !is DmSeal.OuterIntro.Ok) continue
                    var secrets: ByteArray? = null
                    var fallback: ByteArray? = null
                    device.sql.query(
                        "SELECT secrets_env, fallback_pub FROM olm_prekey_gen WHERE gen_id = ?",
                        listOf(outer.genId.toLong() and 0xffffffffL),
                    ) { r ->
                        secrets = r.blob(0)
                        fallback = r.blob(1)
                    }
                    if (secrets == null) continue
                    val inner = device.envelopes.openIntro(0, namespace, outer.genId, secrets!!, fallback!!, blob)
                    if (inner is DmSeal.OpenedIntro.Ok) introOpened++
                }
                else -> Unit
            }
        }

        // Provisional: every retained prov_env against §22.8.5's two erase points.
        var retained = 0
        var pastRule = 0
        device.sql.query(
            "SELECT contact_id, prov_env IS NOT NULL, prov_anchor_minute FROM olm_session",
        ) { r ->
            val contact = GroundTruth.Key(r.blob(0))
            val holds = r.long(1) == 1L
            val anchor = if (r.isNull(2)) null else r.long(2)
            val firstOpen = truth.firstPairOpen[s to contact]
            val due = (firstOpen != null && firstOpen + FRESH <= now) ||
                (anchor != null && anchor + 119 * DmWorld.DAY <= now)
            if (holds) {
                retained++
                if (due) pastRule++
            }
        }
        var due = 0
        for ((key, first) in truth.firstPairOpen) {
            if (key.first == s && first + FRESH <= now) due++
        }
        return ClientResult(
            client = s,
            oldPairBlobs = oldPair,
            oldRecognised = oldRecognised,
            oldOpened = oldOpened,
            oldRecognisedByDerivation = oldDerived,
            currentPairBlobs = currentPair,
            currentOpened = currentOpened,
            introBlobs = intro,
            introOpened = introOpened,
            introExpected = intro,
            provRetained = retained,
            provDue = due,
            provPastRule = pastRule,
        )
    }

    private fun weekStart(week: Long): Long = DmWorld.WEEK_ORIGIN + week * DmWorld.WEEK
}
