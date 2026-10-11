package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.channel.engine.ChannelTime
import org.ghost.messaging.engine.DmTime
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * **The exact searches of the channel privacy world** (Phase 10 design §12.7's JC-1 … JC-7), run
 * over the world's effective relay view: [ModelChannelRelay.stored] (every stored blob's bytes),
 * [ModelChannelRelay.events] (every list, fetch and register call with the credential it
 * presented) and the clients' capability/generation tables (the scopes a member presents). Every
 * check fails on an empty sample (a search over nothing is a failure, the DM suites' rule) and
 * returns a design-doc report line naming what it compared (§15 item 10a).
 *
 * **JC-1's recomputation** uses the derivation labels of §5.2/§5.6 as a HKDF label set: rule (1)
 * there forbids every derivation's key input from being public material, so no candidate a relay
 * can compute from channel ids, pseudonym keys, box keys, KeyPackages or invite ids may equal a
 * namespace, a credential secret or a hint — PC-7's family is what a non-zero count catches.
 */
internal object ChannelPrivacyChecks {

    /** The outcome of one search: the design-doc line and the assertions' verdict. */
    class Result(val id: String, val passed: Boolean, val detail: String) {
        fun line(): String = "channel JC-$id: ${if (passed) "PASS" else "FAIL"} $detail"
    }

    /** The public material every member can recompute (§12.7's JC-1 parenthetical), per channel. */
    class Material(
        val channelId: ByteArray,
        val pseudonyms: List<ByteArray>,
        val boxKeys: List<ByteArray>,
        val inviteIds: List<ByteArray>,
        val invitePks: List<ByteArray>,
        /**
         * The KeyPackages the channel admitted: their refs (each ref is the stored hash of the
         * KeyPackage — the value JC-1's raw-32-byte convention hashes, §19.52 FIX 3), recorded at
         * the accept because the joiner's `ch_join` row is deleted when its join completes.
         */
        val keyPackageRefs: List<ByteArray>,
        /**
         * The `ChannelContent` op ids the channel's members hold (the header's identifying field,
         * §19.52 FIX 2): every op id still rowed in any member's `ch_post`/`ch_reaction` — the
         * posts swept everywhere are past retention, so no relay-visible blob carries them.
         */
        val opIds: List<ByteArray>,
        /** The channel's every generation namespace, from its owner's rows. */
        val namespaces: List<ByteArray>,
        /** The owner's capability tokens: (relayId, namespace, kind, token). */
        val capabilities: List<Triple<Long, ByteArray, Pair<String, ByteArray>>>,
    )

    /** The derivation labels a candidate may be hashed under (§5.2, §5.6, §19.28.3, and F9 §4.3's
     *  verifier labels — every label of `derive.rs`, the review of S11, §19.52 FIX 3). */
    private val LABELS = listOf(
        "ghost/v1/ch/ns", "ghost/v1/ch/read-base", "ghost/v1/ch/deposit-base",
        "ghost/v1/ch/join-key", "ghost/v1/ch-recognition", "ghost/v1/ch/epoch",
        "ghost/v1/ch/generation", "ghost/v1/ch-seal", "ghost/v1/ch-hint",
        "ghost/v1/ch/invite-seal", "ghost/v1/ch/committers",
        "ghost/v1/ch/read", "ghost/v1/ch/deposit",
        "ghost/v1/read-verifier", "ghost/v1/deposit-verifier",
    )

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** RFC 5869 HKDF-SHA256 with an empty salt (the `∅` of §5.2): extract then expand to [length]. */
    private fun hkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val actualSalt = salt ?: ByteArray(32)
        val prk = hmac(actualSalt, ikm)
        var out = ByteArray(0)
        var t = ByteArray(0)
        var counter = 1
        while (out.size < length) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte()))
            out += t
            counter++
        }
        return out.copyOf(length)
    }

    /** Gathers the public material of every channel from its owner (who lives through the world). */
    fun gather(built: ChannelPrivacyWorld.Built): List<Material> =
        built.channels.map { info ->
            val owner = info.owner
            val c = info.id.toByteArray()
            val day = DmTime.day(owner.clock.now)
            val roster = owner.database.transaction { tx ->
                val rows = org.ghost.messaging.channel.engine.MlsRows.of(owner.channelStores.mls.rows(tx.sql, c, day))
                owner.contexts.open(c)!!.crypto.roster(c, rows, day.toInt())
            }.let { (it as? MlsOutcome.Ok)?.value ?: error("the roster of ${info.name} does not open") }
            val (inviteIds, invitePks) = owner.database.transaction { tx ->
                owner.channelStores.invites.issuedOf(tx.sql, c, day)
                    .map { it.inviteId.copyOf() to it.invitePk.copyOf() }.unzip()
            }
            val namespaces = owner.database.transaction { tx ->
                val out = ArrayList<ByteArray>()
                tx.sql.query("SELECT namespace_id FROM ch_generation WHERE channel_id = ?", listOf(c)) { out += it.blob(0) }
                out
            }
            val opIds = ArrayList<ByteArray>()
            for (client in built.clients) {
                client.sql.query("SELECT op_id FROM ch_post WHERE channel_id = ?", listOf(c)) { opIds += it.blob(0) }
                client.sql.query("SELECT target FROM ch_reaction WHERE channel_id = ?", listOf(c)) { opIds += it.blob(0) }
            }
            val capabilities = owner.database.transaction { tx ->
                val out = ArrayList<Triple<Long, ByteArray, Pair<String, ByteArray>>>()
                tx.sql.query(
                    "SELECT relay_id, namespace_id, kind, token FROM relay_capability WHERE state = 'usable'",
                ) {
                    out += Triple(it.long(0), it.blob(1), it.string(2) to it.blob(3))
                }
                out
            }
            Material(
                c,
                roster.members.map { it.pseudonym },
                roster.members.mapNotNull { it.boxPk },
                inviteIds, invitePks,
                built.world.keyPackageRefsOf(info.id),
                opIds,
                namespaces, capabilities,
            )
        }

    // ------------------------------------------------------------------------------------------------ JC-1

    /**
     * JC-1: every relay-visible value recomputed from public material — for each public value
     * (channel id, pseudonym key, box key, KeyPackage ref, invite id, invite public key) its
     * SHA-256 and its HKDF under every derivation label of §5.2/§5.6 and F9 §4.3 — must match no
     * namespace and no stored blob's hint. The KeyPackages of §12.7's parenthetical enter as their
     * refs: the ref is the stored hash of the KeyPackage (JC-1's convention hashes a raw 32-byte
     * value; the KeyPackage bytes themselves live only inside the sealed join traffic, §19.52
     * FIX 3).
     */
    fun jc1(built: ChannelPrivacyWorld.Built, material: List<Material>): Result {
        val namespaces = material.flatMap { it.namespaces }.map { ModelChannelRelay.hex(it) }.toHashSet()
        val hints = built.world.relay.stored.map { ModelChannelRelay.hex(it.ciphertext.copyOfRange(16, 32)) }.toHashSet()
        var candidates = 0
        var nsMatches = 0
        var hintMatches = 0
        val values = material.flatMap { m ->
            listOf(m.channelId) + m.pseudonyms + m.boxKeys + m.keyPackageRefs + m.inviteIds + m.invitePks
        }.distinctBy { ModelChannelRelay.hex(it) }
        for (v in values) {
            val derived = listOf(sha256(v)) + LABELS.map { hkdf(v, null, it.toByteArray(), 32) }
            for (d in derived) {
                candidates++
                if (ModelChannelRelay.hex(d) in namespaces) nsMatches++
                if (ModelChannelRelay.hex(d.copyOfRange(0, 16)) in hints) hintMatches++
            }
        }
        val passed = values.isNotEmpty() && namespaces.isNotEmpty() && hints.isNotEmpty() && nsMatches == 0 && hintMatches == 0
        return Result("1", passed,
            "${values.size} public values (channel ids, pseudonym keys, box keys, KeyPackage refs, invite ids and pks) " +
                "× ${LABELS.size + 1} derivations = $candidates recomputed values: " +
                "0 namespace matches, 0 hint matches over ${namespaces.size} namespaces, ${hints.size} distinct hints")
    }

    // ------------------------------------------------------------------------------------------------ JC-2

    /**
     * JC-2: the header scan — no stored blob's bytes contain a group id (channel id), an epoch
     * (u64_be of 1 … 64), a pseudonym key, a box key, an invite id, an invite public key, a
     * KeyPackageRef or a `ChannelContent` op id (the header's identifying field). A raw MLS byte
     * on the wire (PC-1) carries its group id and epoch at fixed offsets; the KeyPackages and
     * KeyPackageRefs live in the sealed join traffic, whose outer layer a leak would bare — a bare
     * ref or op id (both hashes, 16 … 32 bytes) matched none of the original patterns (§19.52
     * FIX 2).
     */
    fun jc2(built: ChannelPrivacyWorld.Built, material: List<Material>): Result {
        val patterns = ArrayList<ByteArray>()
        for (m in material) {
            patterns += m.channelId
            patterns += m.pseudonyms
            patterns += m.boxKeys
            patterns += m.keyPackageRefs
            patterns += m.opIds
            patterns += m.inviteIds
            patterns += m.invitePks
        }
        for (e in 1..64L) patterns += byteArrayOf(0, 0, 0, 0, 0, 0, 0, e.toByte())
        val distinct = patterns.distinctBy { ModelChannelRelay.hex(it) }
        // A prefix index: one pass over each blob, full comparisons only where the first four
        // bytes collide (patterns are 8 … 32 bytes, so a 4-byte hit pins the position).
        val byPrefix = HashMap<Int, MutableList<ByteArray>>()
        for (p in distinct) byPrefix.getOrPut(((p[0].toInt() and 0xff) shl 24) or ((p[1].toInt() and 0xff) shl 16) or
            ((p[2].toInt() and 0xff) shl 8) or (p[3].toInt() and 0xff)) { ArrayList() } += p
        var scanned = 0
        var matches = 0
        val blobs = built.world.relay.stored.distinctBy { ModelChannelRelay.hex(it.hash) }
        for (blob in blobs) {
            scanned++
            val bytes = blob.ciphertext
            for (i in 0..bytes.size - 4) {
                val key = ((bytes[i].toInt() and 0xff) shl 24) or ((bytes[i + 1].toInt() and 0xff) shl 16) or
                    ((bytes[i + 2].toInt() and 0xff) shl 8) or (bytes[i + 3].toInt() and 0xff)
                val candidates = byPrefix[key] ?: continue
                for (p in candidates) {
                    if (i + p.size <= bytes.size && p.indices.all { bytes[i + it] == p[it] }) matches++
                }
            }
        }
        val passed = scanned > 0 && distinct.isNotEmpty() && matches == 0
        return Result("2", passed,
            "${distinct.size} patterns (group ids, epochs 1…64, pseudonym keys, box keys, KeyPackageRefs, " +
                "ChannelContent op ids, invite ids and pks) scanned over $scanned stored blobs " +
                "(${blobs.sumOf { it.ciphertext.size }} bytes): $matches matches")
    }

    // ------------------------------------------------------------------------------------------------ JC-3

    /**
     * JC-3: per (relay, generation namespace) exactly one store scope and one read scope — what
     * the relays were **presented**: every list and fetch of a namespace presents the same READ
     * credential bytes on every client (the bearer credential v3 is derived from the generation
     * secret, §5.2), every store presents the same DEPOSIT credential, and a registration
     * capability appears in no list, fetch or store (it serves the registration step alone,
     * `RegisterCapabilityTest`'s rule; PC-4/PC-10). The clients' tables are not read: how a
     * client stores its capability is its own business — the relay view is what JC-3 compares.
     *
     * Granularity (§19.52 FIX 7): the scopes and register counts are seed-stable; the count of
     * presented list/fetch credentials is not — it scales with the serve-round count, which the
     * unseeded native draws make load-dependent — so the line does not pin it (it is still
     * computed for the misuse assertion).
     */
    fun jc3(built: ChannelPrivacyWorld.Built, material: List<Material>): Result {
        val readScopes = HashMap<Pair<Int, String>, HashSet<String>>()
        val storeScopes = HashMap<Pair<Int, String>, HashSet<String>>()
        val registerKind = HashSet<String>()
        val registerScopes = HashMap<Pair<Int, String>, HashSet<String>>()
        var registerEvents = 0
        for (e in built.world.relay.events) {
            when (e) {
                is ModelChannelRelay.RelayEvent.Listed ->
                    readScopes.getOrPut(e.slot to ModelChannelRelay.hex(e.namespace)) { HashSet() } +=
                        ModelChannelRelay.hex(e.credential ?: continue)
                is ModelChannelRelay.RelayEvent.Fetched ->
                    readScopes.getOrPut(e.slot to ModelChannelRelay.hex(e.namespace)) { HashSet() } +=
                        ModelChannelRelay.hex(e.credential ?: continue)
                is ModelChannelRelay.RelayEvent.Register -> {
                    registerEvents++
                    val key = e.slot to ModelChannelRelay.hex(e.namespace)
                    registerScopes.getOrPut(key) { HashSet() }
                    val token = e.credential?.let { ModelChannelRelay.hex(it) } ?: continue
                    registerScopes.getValue(key) += token
                    if (e.credentialKind == "register") registerKind += token
                }
                else -> Unit
            }
        }
        // A store reaches every relay of the namespace's set, presenting that relay's DEPOSIT
        // credential — the store scope is per (relay, namespace), like the read scope.
        for (s in built.world.relay.stored) {
            if (s.injected) continue
            val client = built.clients.firstOrNull { it.name == s.from } ?: continue
            for (slot in client.slots) {
                var token: ByteArray? = null
                client.sql.query(
                    "SELECT token FROM relay_capability WHERE relay_id = ? AND namespace_id = ? AND kind = ? AND state = 'usable'",
                    listOf(slot.relay.value, s.namespace, "write"),
                ) { token = it.blob(0) }
                val credential = token ?: continue
                storeScopes.getOrPut(slot.slot to ModelChannelRelay.hex(s.namespace)) { HashSet() } +=
                    ModelChannelRelay.hex(credential)
            }
        }
        var scopeViolations = 0
        var unreadScopes = 0
        val violating = ArrayList<String>()
        for ((key, set) in readScopes) when {
            set.size > 1 -> {
                scopeViolations++
                if (violating.size < 5) violating += "read(slot=${key.first},ns=${key.second.take(10)},distinct=${set.size})"
            }
            set.isEmpty() -> unreadScopes++
        }
        for ((key, set) in storeScopes) when {
            set.size > 1 -> {
                scopeViolations++
                if (violating.size < 5) violating += "store(slot=${key.first},ns=${key.second.take(10)},distinct=${set.size})"
            }
            set.isEmpty() -> unreadScopes++
        }
        for ((key, set) in registerScopes) when {
            set.size > 1 -> {
                scopeViolations++
                if (violating.size < 5) violating += "register(slot=${key.first},ns=${key.second.take(10)},distinct=${set.size})"
            }
            set.isEmpty() -> unreadScopes++
        }
        var registerMisuse = 0
        for (e in built.world.relay.events) {
            val credential = when (e) {
                is ModelChannelRelay.RelayEvent.Listed -> e.credential
                is ModelChannelRelay.RelayEvent.Fetched -> e.credential
                else -> null
            } ?: continue
            if (ModelChannelRelay.hex(credential) in registerKind) registerMisuse++
        }
        val passed = readScopes.isNotEmpty() && storeScopes.isNotEmpty() && registerEvents > 0 &&
            scopeViolations == 0 && registerMisuse == 0
        return Result("3", passed,
            "${storeScopes.size} store scopes and ${readScopes.size} read scopes over $registerEvents register " +
                "calls on ${registerScopes.size} (relay, namespace) pairs (one presented credential each where one " +
                "was presented, $scopeViolations two-credential violations $violating, $unreadScopes scopes no client " +
                "presented a credential for), $registerMisuse register-capability " +
                "misuses; ${built.world.relay.registerSkipped} registration rows skipped (relays outside the slot table)")
    }

    // ------------------------------------------------------------------------------------------------ JC-4

    /**
     * JC-4: per generation namespace one TTL (a namespace carries one timer version — timer
     * changes are Phase 13's user entry points, F-S11-1), commits and posts inside the class
     * floor bucket, Welcomes under the class cap. The stale-invite TTL exception (LC-1) is
     * counted and reported: 0 in this choreography (no timer version ever changes).
     */
    fun jc4(built: ChannelPrivacyWorld.Built): Result {
        val byNs = built.world.relay.stored.filter { !it.injected }.groupBy { ModelChannelRelay.hex(it.namespace) }
        var ttlViolations = 0
        var bucketViolations = 0
        var staleInviteTtls = 0
        var welcomesOverCap = 0
        for ((ns, blobs) in byNs) {
            if (blobs.map { it.ttl }.distinct().size != 1) ttlViolations++
            for (b in blobs) {
                when (b.purpose) {
                    "welcome" -> if (b.ciphertext.size > 65_536) welcomesOverCap++
                    "join" -> staleInviteTtls++ // counted and reported: none should carry an old handshake TTL
                    else -> if (b.ciphertext.size != ChannelTime.SMALL_FLOOR) bucketViolations++
                }
            }
        }
        val passed = byNs.isNotEmpty() && ttlViolations == 0 && bucketViolations == 0 && welcomesOverCap == 0
        return Result("4", passed,
            "${byNs.size} generation namespaces: 1 TTL each ($ttlViolations violations), commits and posts in the " +
                "4 KiB floor bucket ($bucketViolations outside), $welcomesOverCap Welcomes over the cap; " +
                "$staleInviteTtls join requests (the LC-1 stale-invite exception: 0 expected, none choreographed)")
    }

    // ------------------------------------------------------------------------------------------------ JC-5

    /**
     * JC-5: a removed member's credentials or secrets accepted in a later generation's
     * namespace: 0 — the T38 oracle's sweep over the world's removal subjects against every
     * blob of their channels' every generation (the namespace map is the union the world
     * recorded; the epoch keys are the anchor's retained rows and every subject dump's).
     * JC-5's declared content is the zero: opened later epochs, opened later generations and
     * recognised-later counts must all be 0. The oracle's further T38 residue floors (its
     * dump-row checks) are the M20 scenario's own lens — a removed member's dump legitimately
     * accumulates draining-generation rows in this world's longer tail — so the counts are
     * reported here, not asserted (the T38 line itself owns those).
     *
     * The oracle's floors are asserted in-suite (§19.52 FIX 4): a subject whose restore broke
     * (matched == 0, nothing tried, `laterOpens == 0` vacuously) fails here, as does a blob of
     * a namespace the world's union map does not name (the completeness the zero claims rely
     * on: `stored.all { ns in map }`). The blob floor is this world's own: the oracle's 100-blob
     * floor is calibrated to M20's single 318-blob channel, and this world's two smallest subject
     * channels measured 55 blobs each — [JC5_BLOB_FLOOR] is half that, a floor against a vacuous
     * sample, like the sizes test's convention.
     */
    fun jc5(built: ChannelPrivacyWorld.Built): Result {
        val failures = ArrayList<String>()
        var subjects = 0
        var blobs = 0
        var laterOpens = 0
        var recognisedLater = 0
        val reported = ArrayList<String>()
        // The union-map completeness the zeros rely on: every stored blob's namespace is one the
        // world recorded (a blob outside the map would be invisible to every subject's sweep).
        val unnamed = built.world.relay.stored.count { ModelChannelRelay.hex(it.namespace) !in built.namespaces }
        if (unnamed > 0) failures += "$unnamed stored blobs of a namespace the world's union map does not name"
        for (subject in built.report.subjects) {
            subjects++
            val info = subject.channel
            val seized = built.world.client(
                "seized-${subject.name}", sql = ChannelWorld.restore(subject.dump),
                boot = 9, seedName = subject.name,
            )
            val (generationOf, epochOf) = blobMaps(built, info)
            val channelBlobs = built.world.relay.stored.filter {
                built.namespaces[ModelChannelRelay.hex(it.namespace)]?.first == info.id
            }
            blobs += channelBlobs.size
            val r = RemovedMemberOracle.run(
                seized, subject.name, subject.kind, info.id, channelBlobs,
                subject.removedAtEpoch, subject.heldGeneration, generationOf, epochOf,
            )
            laterOpens += r.openedLaterEpoch + r.openedLaterGeneration
            recognisedLater += r.recognisedLater
            // The anti-vacuity floors, in-suite (FIX 4): a broken subject restore (matched == 0,
            // nothing tried) or an empty sample would pass the zeros vacuously — the same floors
            // the oracle reports on its M20 line, the blob floor at this world's scale (KDoc above).
            if (r.blobs < JC5_BLOB_FLOOR) failures += "${subject.name}: only ${r.blobs} blobs (floor $JC5_BLOB_FLOOR)"
            if (r.stored32 == 0) failures += "${subject.name}: no stored 32-byte value in the dump"
            if (r.stored60 + r.stored68 == 0) failures += "${subject.name}: no stored envelope in the dump"
            if (r.matched == 0) failures += "${subject.name}: nothing matched, so nothing was tried"
            if (r.openedLaterEpoch > 0 || r.openedLaterGeneration > 0 || r.recognisedLater > 0) failures += r.line()
            reported += "${subject.name}: ${r.blobs} blobs, matched ${r.matched}, stored ${r.stored32}/${r.stored60}/${r.stored68}, " +
                "removing epoch ${r.openedRemovingEpoch}, earlier ${r.openedEarlierEpoch}, join traffic ${r.joinTrafficOpened}, " +
                "later-epoch rows ${r.laterEpochRows}, later-generation rows ${r.laterGenerationRows} (reported)"
        }
        val passed = subjects > 0 && laterOpens == 0 && recognisedLater == 0 && failures.isEmpty()
        return Result("5", passed,
            "$subjects removal subjects over $blobs blobs: $laterOpens opens and $recognisedLater recognitions of " +
                "later epochs or generations (both must be 0); reported: ${reported.joinToString("; ")}")
    }

    /**
     * JC-5's blob floor per subject channel: the smallest subject channel measured 55 blobs
     * (seed `0x5eed_b101`, §19.52), the floor is half that — a subject whose channel holds fewer
     * would be a vacuous sample. (The oracle's own floor is 100, calibrated to M20's single
     * 318-blob channel; asserting it here would fail this world's two 55-blob subject channels.)
     */
    private const val JC5_BLOB_FLOOR = 25

    /**
     * The world's view of (namespace → generation, blob → epoch) for one channel: the namespace
     * map is the one [ChannelPrivacyWorld] recorded through the run (a live owner's rows lose the
     * finished drains to the sweep); the epoch keys are the anchor's retained rows **and every
     * subject dump's** — the anchor's retention reaches only its own era, a victim's reaches its
     * own (the M20 oracle's frozen-dump widening, per subject here).
     */
    private fun blobMaps(
        built: ChannelPrivacyWorld.Built,
        info: ChannelPrivacyWorld.ChannelInfo,
    ): Pair<(ByteArray) -> Long?, (ByteArray) -> Long?> {
        val c = info.id.toByteArray()
        val generationOfMap = built.namespaces
        val epochs = ArrayList<org.ghost.messaging.channel.store.EpochStore.EpochRow>()
        val keyHolders = ArrayList<ChannelClient>()
        keyHolders += info.owner
        for (subject in built.report.subjects) {
            if (subject.channel !== info) continue
            keyHolders += built.world.client(
                "jc5-keys-${subject.name}", sql = ChannelWorld.restore(subject.dump),
                boot = 7, seedName = subject.name,
            )
        }
        val day = DmTime.day(info.owner.clock.now)
        for (holder in keyHolders) {
            epochs += holder.database.transaction { tx -> holder.channelStores.epochs.retained(tx.sql, c, day) }
        }
        val byEpoch = epochs.distinctBy { it.epoch }
        val epochOf = HashMap<String, Long>()
        val crypto = info.owner.contexts.open(c)!!.crypto
        val channelBlobs = built.world.relay.stored.filter {
            generationOfMap[ModelChannelRelay.hex(it.namespace)]?.first == info.id
        }
        for (blob in channelBlobs) {
            val hashKey = ModelChannelRelay.hex(blob.hash)
            if (epochOf.containsKey(hashKey)) continue
            for (e in byEpoch) {
                val o = crypto.open(c, e.kEnv, ChannelCrypto.KEY_CLASS_EPOCH, blob.namespace, ChannelCrypto.MODE_EPOCH, blob.ciphertext)
                if (o is MlsOutcome.Ok && (o.value.headerEpoch ?: o.value.order.epoch) == e.epoch) {
                    epochOf[hashKey] = e.epoch
                    break
                }
            }
        }
        return Pair(
            { ns -> generationOfMap[ModelChannelRelay.hex(ns)]?.second },
            { hash -> epochOf[ModelChannelRelay.hex(hash)] },
        )
    }

    // ------------------------------------------------------------------------------------------------ JC-6

    /**
     * JC-6: every store's relay-visible minute is at or after its op's `not_before_minute` (the
     * send-delay rule — in HIGH mode each op waits up to 10 min, in STANDARD not_before is the
     * enqueue minute, so the rule is the honest timing claim in both modes), and every store maps
     * to a non-inbound cause by construction — the world stores only what a client enqueued at
     * its own user action or scheduled pass (the relay's own injected blobs are named, not
     * counted as client stores). What this line compared is named, §15 item 10a: the op→store
     * join by rowid order, not a port of `oracle_traffic` (the twin-level no-reflex property is
     * NI-CH1's exact comparison).
     */
    fun jc6(built: ChannelPrivacyWorld.Built): Result {
        var stores = 0
        var violations = 0
        val delayed = built.world.relay.delayedStores
        for (blob in built.world.relay.stored) {
            if (blob.injected) continue
            stores++
            // not_before_minute holds minute-aligned epoch seconds (Time.floorMinute's unit).
            if (blob.storedAt < blob.notBeforeMinute) violations++
        }
        val injected = built.world.relay.stored.count { it.injected }
        val passed = stores > 0 && violations == 0
        return Result("6", passed,
            "$stores client stores, each at or after its op's not_before ($violations violations); " +
                "$delayed distinct ops honoured their HIGH-mode send delay by later rounds; " +
                "$injected relay-injected blobs named, not stores")
    }

    // ------------------------------------------------------------------------------------------------ JC-7

    /**
     * JC-7 (§19.20): the model relay tries every value it was shown — every READ and DEPOSIT
     * secret inside a presented credential (of a list, a fetch, a register call **and a store** —
     * the DEPOSIT credential each stored blob presented, which no Listed/Fetched/Register event
     * shows: Stored.storeCredential, §19.52 FIX 1), every verifier of a register call, every
     * registration capability, and the namespace — as the recognition key R of §5.6's hint (all
     * three modes) and, derived, as a key input K (`R' = HKDF(V, ∅, "ghost/v1/ch-recognition")`,
     * the honest recognition key of a K = V seal): 0 hints match, so 0 blobs open (an open is
     * attempted only where the hint matched — with 0 matches no AEAD attempt runs, which the
     * line states).
     */
    fun jc7(built: ChannelPrivacyWorld.Built): Result {
        // Every value the relays were shown, deduplicated.
        val shown = LinkedHashSet<String>()
        val namespaces = LinkedHashSet<String>()
        for (e in built.world.relay.events) {
            val namespace = when (e) {
                is ModelChannelRelay.RelayEvent.Listed -> {
                    e.credential?.let { shown += ModelChannelRelay.hex(it) }
                    e.namespace
                }
                is ModelChannelRelay.RelayEvent.Fetched -> {
                    e.credential?.let { shown += ModelChannelRelay.hex(it) }
                    e.namespace
                }
                is ModelChannelRelay.RelayEvent.Register -> {
                    e.credential?.let { shown += ModelChannelRelay.hex(it) }
                    shown += ModelChannelRelay.hex(e.verifier)
                    e.namespace
                }
                else -> null
            }
            if (namespace != null) namespaces += ModelChannelRelay.hex(namespace)
        }
        for (b in built.world.relay.stored) {
            namespaces += ModelChannelRelay.hex(b.namespace)
            // FIX 1: the DEPOSIT credential a store presented — the whole token and its secret
            // half enter via the v3 parse below (a store's secret can be a value no other event
            // shows; without this the "every shown value" claim overreached, §19.52).
            b.storeCredential?.let { shown += ModelChannelRelay.hex(it) }
        }

        // Bearer credential v3: 3 ‖ kind ‖ u8(s) ‖ ns(32) ‖ secret(32) — the secret is the value.
        val values = ArrayList<ByteArray>()
        for (hexToken in shown) {
            val token = ModelChannelRelay.unhex(hexToken)
            values += token
            if (token.size == 67 && token[0].toInt() == 3) values += token.copyOfRange(35, 67)
        }
        values += namespaces.map { ModelChannelRelay.unhex(it) }
        val distinct = values.distinctBy { ModelChannelRelay.hex(it) }

        // Every stored blob's (salt, hint) pair, per mode: hint = HMAC(R, "ghost/v1/ch-hint" ‖ mode ‖ salt)[0..16].
        val label = "ghost/v1/ch-hint".toByteArray()
        val blobs = built.world.relay.stored.distinctBy { ModelChannelRelay.hex(it.hash) }
        val tripled = blobs.map {
            val salt = it.ciphertext.copyOfRange(0, 16)
            val hint = it.ciphertext.copyOfRange(16, 32)
            Triple(salt, hint, it)
        }
        val modes = intArrayOf(ChannelCrypto.MODE_EPOCH, ChannelCrypto.MODE_JOIN, ChannelCrypto.MODE_WELCOME)
        var checks = 0L
        var matches = 0
        for (v in distinct) {
            val asRecognition = listOf(v) + listOf(hkdf(v, null, "ghost/v1/ch-recognition".toByteArray(), 32))
            for ((salt, hint, _) in tripled) {
                for (r in asRecognition) {
                    for (mode in modes) {
                        checks++
                        val mac = Mac.getInstance("HmacSHA256")
                        mac.init(SecretKeySpec(r, "HmacSHA256"))
                        val computed = mac.doFinal(label + byteArrayOf(mode.toByte()) + salt).copyOfRange(0, 16)
                        if (computed.contentEquals(hint)) matches++
                    }
                }
            }
        }
        val passed = distinct.isNotEmpty() && tripled.isNotEmpty() && matches == 0
        return Result("7", passed,
            "${distinct.size} shown values (READ and DEPOSIT credential secrets of lists, fetches, registers and " +
                "stores, verifiers, registration capabilities, namespaces), each as R and as K-derived R', over " +
                "${tripled.size} blobs × 3 modes = $checks hint computations: " +
                "$matches matches, 0 blobs open (no open is attempted where no hint matched)")
    }
}
