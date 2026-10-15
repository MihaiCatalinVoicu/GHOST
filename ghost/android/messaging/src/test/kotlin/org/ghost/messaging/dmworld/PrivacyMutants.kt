package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmBundles
import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.DmDevice
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.NamespaceId
import java.security.MessageDigest
import java.util.Collections
import java.util.WeakHashMap

/**
 * One privacy mutant of Phase 9 design §15.7 (the PM table), in the discipline S10's
 * `DmMutants` set: **a mutant is registered only when a named check kills it**, the kill is run
 * against a same-scale control world that must pass, and the killing failure's message must
 * contain the killer's `expect` — so "detected" means "the check the design names failed", not
 * "something broke".
 *
 * A privacy mutant is one of: a decorator on the envelope port ([envelopes]), a decorator on the
 * crypto port ([crypto]), a statement rewrite ([rewrite]), a device configuration ([configure]), or
 * a **reflex hook** ([afterWake], [afterAdd]) that makes the device do something relay-visible that
 * no user asked for — which is what PM-2, PM-6 and PM-8 are, and what the production engine is
 * forbidden to do (T28, T31).
 */
internal class PrivacyMutant(
    val id: String,
    /** The property §15.7 says this mutant defeats. */
    val defeats: String,
    /** §15.7's "Detected by" column, and which of those checks kill it here. */
    val detectedBy: String,
    /** The checks that kill it here, each with the substring its failure must contain. */
    val killers: List<Killer>,
    val envelopes: ((PrivacyWorld, Int, DmEnvelopes) -> DmEnvelopes)? = null,
    val crypto: ((PrivacyWorld, Int, DmCrypto) -> DmCrypto)? = null,
    val rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
    val configure: ((DmDevice) -> Unit)? = null,
    val afterWake: ((PrivacyWorld, Int) -> Unit)? = null,
    val afterAdd: ((PrivacyWorld, Int, Int) -> Unit)? = null,
    /**
     * What of §15.7's entry this mutant implements, when it is not all of it; printed on the
     * report's detection line, so a count of detected mutants never reads as more than was built.
     */
    val scope: String? = null,
    /**
     * The mutant's half in the **entitlement world** (`entworld/EntDmJd8.kt`, §22.26): a statement
     * rewrite on every client's shared executor or a decorator of the DM steps' sync ports. Only
     * the JD8 twin worlds read it; a privacy world never does.
     */
    val entWorld: org.ghost.messaging.entworld.EntMutation? = null,
) {
    /**
     * A named check, the substring its failure message must contain, and — where a failure can
     * also come from the world not reaching what the check needs — a substring it must **not**
     * contain ([refuse]): such a failure is the world's, not the mutant's, and is no kill.
     */
    class Killer(val check: PrivacyCheck, val expect: String, val refuse: String? = null)

    override fun toString(): String = id
}

/** The checks a privacy mutant can be killed by, each run on its own control world. */
internal enum class PrivacyCheck(val label: String) {
    JD1("JD1 (SMALL world)"),
    JD2("JD2 (SMALL world)"),
    JD4("JD4 (SMALL world)"),
    JD5("JD5 (SMALL world)"),
    JD6("JD6 (SMALL world)"),
    JD7("JD7 (SMALL world)"),
    JD7_WITHHOLD("JD7 WITHHOLD_ALL_BUNDLES (SMALL world)"),
    JD9("JD9 (SMALL world)"),
    NI_DM1("NI-DM1 (twin worlds)"),
    NI_DM2("NI-DM2 (twin worlds)"),
    NI_DM3("NI-DM3 (twin worlds)"),
    JD8("JD8 (entitlement twin worlds)"),
    S_DM3("S-DM3 (MEDIUM world, n >= 100)"),
    T34("T34 (seizure world)"),
    T34_ONE_REPLY("T34 one-reply variant (two clients, 130 days)"),
}

/**
 * The privacy mutants registered: ten of §15.7's forty from slice S11, PM-5 and PM-31 from the
 * S11b slice (with NI-DM2 as PM-4's second killer), and PM-1, PM-1b and PM-26 — killed by JD8 in the
 * entitlement world's twins (§22.26) — each with the checks that kill it. §22.16 lists what the
 * others need, §22.21 what S11b changed of that list, and §22.26 what JD8 changed of it.
 */
internal object PrivacyMutants {

    /** Per-world cursors of the reflex hooks, so a hook acts on each event once. */
    private val cursors: MutableMap<PrivacyWorld, IntArray> = Collections.synchronizedMap(WeakHashMap())

    private fun cursor(world: PrivacyWorld): IntArray = cursors.getOrPut(world) { IntArray(4) }

    const val RECEIPT: String = "✓"

    /**
     * **PM-2 — an automatic delivery receipt on decrypt.** After every relay session, for each
     * message the device decrypted in it, the device sends its contact a receipt — the reflex T28
     * forbids ("processing any inbound blob … enqueues nothing"). A receipt is not itself receipted,
     * or two devices would answer each other for ever.
     */
    val PM2 = PrivacyMutant(
        id = "PM-2",
        defeats = "T28: processing an inbound blob enqueues nothing",
        detectedBy = "JD6, NI-DM1 (§15.7); both here",
        killers = listOf(
            PrivacyMutant.Killer(PrivacyCheck.JD6, "maps to no user action"),
            PrivacyMutant.Killer(PrivacyCheck.NI_DM1, "only in VALID (ops {STORE="),
        ),
        // Every decrypt happens inside the decrypting client's own relay session, so the entries a
        // hook finds are that session's; each is answered from the device that decrypted it.
        afterWake = { world, _ ->
            val cursor = cursor(world)
            val decrypted = world.truth.decrypted
            while (cursor[0] < decrypted.size) {
                val (client, contact) = decrypted[cursor[0]++]
                val id = ContactId(contact)
                world.clients[client].sync()
                val engine = world.clients[client].device.engine
                val newest = engine.conversation(id, 1, null).firstOrNull()
                if (newest == null || newest.outgoing || newest.text == RECEIPT) continue
                engine.send(id, RECEIPT, null)
            }
        },
    )

    /**
     * **PM-3 — an inbox or bundle namespace = SHA-256(label ‖ `ghost1` hash).** Both namespaces of
     * every card become a public function of the identity key, on the owner's side (`ownCard`) and
     * on every card holder's (`deriveCard`), so the world still works: senders deposit where the
     * owner reads. The bundle blob is still sealed by Rust under the real `P`, so the fetcher's open
     * is handed the real namespace back — the mutation is of the addressing, not of the seal.
     */
    val PM3: PrivacyMutant = run {
        val realOf = Collections.synchronizedMap(HashMap<GroundTruth.Key, ByteArray>())
        fun public(label: String, identityPk: ByteArray): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(label.toByteArray(Charsets.US_ASCII))
            md.update(MessageDigest.getInstance("SHA-256").digest(identityPk))
            return md.digest()
        }
        PrivacyMutant(
            id = "PM-3",
            defeats = "T26: no relay-visible value is computable from public identity material",
            detectedBy = "JD1, S-DM3 (§15.7); both here",
            killers = listOf(
                PrivacyMutant.Killer(PrivacyCheck.JD1, "‖ghost1 hash) found in"),
                PrivacyMutant.Killer(PrivacyCheck.S_DM3, "dm S-DM3: FAIL"),
            ),
            crypto = { _, _, native ->
                object : DmCrypto by native {
                    override fun ownCard(cardIndex: Int): DmSessions.OwnCard? {
                        val real = native.ownCard(cardIndex) ?: return null
                        val pk = real.card.copyOfRange(3, 35)
                        val x = public("ghost/v1/card/inbox-ns", pk)
                        val p = public("ghost/v1/card/bundle-ns", pk)
                        realOf[GroundTruth.Key(p)] = real.bundleNamespace
                        return real.copy(inboxNamespace = x, bundleNamespace = p)
                    }

                    override fun deriveCard(card: ByteArray, slot: Int): DmCards.DeriveResult {
                        val real = native.deriveCard(card, slot)
                        if (real !is DmCards.DeriveResult.Ok) return real
                        val pk = card.copyOfRange(3, 35)
                        val p = public("ghost/v1/card/bundle-ns", pk)
                        realOf[GroundTruth.Key(p)] = real.values.bundleNamespace
                        val v = real.values
                        return DmCards.DeriveResult.Ok(
                            DmCards.Derived(
                                public("ghost/v1/card/inbox-ns", pk), p,
                                public("ghost/v1/card/media-ns", pk),
                                v.deposit, v.fetch, v.mediaDeposit,
                                v.recognitionIntro, v.recognitionBundle, v.introKeyEnv, v.bundleKeyEnv,
                            ),
                        )
                    }
                }
            },
            envelopes = { _, _, native ->
                object : DmEnvelopes by native {
                    override fun openBundle(
                        bundleKeyEnv: ByteArray,
                        bundleNamespace: ByteArray,
                        blob: ByteArray,
                        expectedIdentityPk: ByteArray,
                        expectedCardIndex: Int,
                    ): DmBundles.OpenResult = native.openBundle(
                        bundleKeyEnv,
                        realOf[GroundTruth.Key(bundleNamespace)] ?: bundleNamespace,
                        blob, expectedIdentityPk, expectedCardIndex,
                    )
                }
            },
        )
    }

    /**
     * **PM-4 — pad, session-encrypt, store the next bucket up.** The bucket is chosen from the
     * length of the Olm output instead of from the body length (R-B1), so it depends on the session
     * state and the message type: a body just over the 4 KiB class fits a 4 KiB pair envelope and
     * not a 4 KiB intro envelope. The recipient opens either, so the world still works.
     *
     * NI-DM2's kill counts only when **every** twin reached its variable: a twin that stored
     * nothing is a world that failed, not a size class the mutant chose. What NI-DM2 sees is the
     * size class the Olm output falls in, and that output's length depends on the TLVs the engine
     * attaches on its own (the world does not control them): it detects a TLV- and mode-driven
     * size class, not the state or the type directly.
     */
    val PM4 = PrivacyMutant(
        id = "PM-4",
        defeats = "T29 and R-B1: the bucket is a function of the body length only",
        detectedBy = "JD4, NI-DM2 (§15.7); both here (NI-DM2 since §22.21: at 2 221, 14 509 and 15 000 body " +
            "bytes the TLVs one state carries push its Olm output over a class the others stay under)",
        killers = listOf(
            PrivacyMutant.Killer(PrivacyCheck.JD4, "R-B1 says"),
            PrivacyMutant.Killer(PrivacyCheck.NI_DM2, "differ at body length", refuse = "did not reach their variable"),
        ),
        envelopes = { _, _, native ->
            fun after(l1: ByteArray, overhead: Int): Int = listOf(4096, 16384, 65536).first { l1.size + overhead <= it }
            object : DmEnvelopes by native {
                override fun sealIntro(
                    cardIndex: Int, namespace: ByteArray, bucket: Int, introKeyEnv: ByteArray,
                    peerIdentityPk: ByteArray, peerOlmIdentity: ByteArray, genId: Int, genPublic: ByteArray,
                    bindingMinute: Long, sessionId: ByteArray, replySeedEnv: ByteArray, l1: ByteArray,
                ): DmSeal.Sealed = native.sealIntro(
                    cardIndex, namespace, after(l1, INTRO_OVERHEAD), introKeyEnv, peerIdentityPk, peerOlmIdentity,
                    genId, genPublic, bindingMinute, sessionId, replySeedEnv, l1,
                )

                override fun sealPair(
                    namespace: ByteArray, bucket: Int, openEnv: ByteArray, contactId: ByteArray, rootGen: Int,
                    week: Long, oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                ): DmSeal.Sealed = native.sealPair(
                    namespace, after(l1, SYMMETRIC_OVERHEAD), openEnv, contactId, rootGen, week, oiSender, oiRecipient, l1,
                )

                override fun sealProvisional(
                    namespace: ByteArray, bucket: Int, openEnv: ByteArray, direction: Int, sessionId: ByteArray,
                    oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                ): DmSeal.Sealed = native.sealProvisional(
                    namespace, after(l1, SYMMETRIC_OVERHEAD), openEnv, direction, sessionId, oiSender, oiRecipient, l1,
                )
            }
        },
    )

    /** §6.4: everything of a 4 KiB intro envelope that is not L1 (1 189 outer + 236 inner). */
    private const val INTRO_OVERHEAD = 1_425

    /** §6.3, §6.7: salt, hint, tag, mode, kind and length. */
    private const val SYMMETRIC_OVERHEAD = 54

    /**
     * **PM-6 — an automatic session reset on an undecryptable blob.** A blob whose hint names a key
     * and whose AEAD fails makes the device reset the session with that contact: a store the
     * relay's forgery caused, which T28 forbids and which tells the forger its probe landed. A reset
     * restarts establishment, so the first thing the relays see is a bundle fetch of the peer's `P`
     * (a LIST the valid twin does not make), and then a first flight: NI-DM1 names the malformed
     * twin as the one with events of its own.
     */
    val PM6 = PrivacyMutant(
        id = "PM-6",
        defeats = "T28: an undecryptable blob causes no traffic",
        detectedBy = "NI-DM1 (§15.7); NI-DM1 here",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.NI_DM1, "only in MALFORMED (ops {")),
        afterWake = { world, _ ->
            val cursor = cursor(world)
            val failed = world.truth.undecryptable
            while (cursor[1] < failed.size) {
                val (client, contact) = failed[cursor[1]++]
                world.clients[client].sync()
                world.clients[client].device.engine.resetSession(ContactId(contact))
            }
            val failedSessions = world.truth.undecryptableSessions
            while (cursor[2] < failedSessions.size) {
                val (client, session) = failedSessions[cursor[2]++]
                var contact: ByteArray? = null
                world.clients[client].device.sql.query(
                    "SELECT contact_id FROM olm_session WHERE session_id = ?",
                    listOf(session),
                ) { contact = it.blob(0) }
                world.clients[client].sync()
                contact?.let { world.clients[client].device.engine.resetSession(ContactId(it)) }
            }
        },
    )

    /**
     * **PM-8 — contacts listen to a per-identity revocation namespace.** Adding a contact registers
     * a listening namespace derived from the contact's identity key, so every holder of that
     * identity's card reads the same namespace — the per-identity channel §8.5 rejects in favour of
     * revocation notices through the inbox (T31).
     */
    val PM8 = PrivacyMutant(
        id = "PM-8",
        defeats = "T31: a client reads only its own namespaces and one bundle fetch per establishment",
        detectedBy = "JD7, static check (§15.7); JD7 here, and NI-DM3, which §15.7 does not name: " +
            "the idle contacts of the k' world each add a listened namespace",
        killers = listOf(
            PrivacyMutant.Killer(PrivacyCheck.JD7, "not its own and not an open bundle fetch"),
            PrivacyMutant.Killer(PrivacyCheck.NI_DM3, "events only in k' (ops {LIST="),
        ),
        afterAdd = { world, c, peer ->
            val pk = requireNotNull(world.truth.clients[peer]?.identityPk)
            val md = MessageDigest.getInstance("SHA-256")
            md.update("ghost/v1/dm/revocation-ns".toByteArray(Charsets.US_ASCII))
            md.update(pk)
            val namespace = md.digest()
            val device = world.clients[c].device
            val set = Joins.relaySet(namespace)
            val relays = device.slots.filter { it.slot in set }.map { it.relay }.toSet()
            device.database.transaction { tx ->
                device.stores.namespaces.register(
                    tx, NamespaceId(namespace), Consumer.DM, relays, listen = true,
                    capabilitySource = CapabilitySource.LOCAL,
                )
            }
        },
    )

    /**
     * **PM-13 — a library-native sealed-sender format with cleartext recipient identifiers on the
     * wire.** Every DM envelope leaves with the recipient's Olm identity key in its first 32 bytes;
     * the library on the other side knows the format and restores what it overwrote (a table shared
     * by the world stands in for that knowledge), so every message still arrives.
     */
    val PM13: PrivacyMutant = run {
        val restore = Collections.synchronizedMap(HashMap<GroundTruth.Key, ByteArray>())
        fun wire(sealed: DmSeal.Sealed, recipient: ByteArray): DmSeal.Sealed {
            if (sealed !is DmSeal.Sealed.Ok) return sealed
            val out = sealed.blob.copyOf()
            System.arraycopy(recipient, 0, out, 0, 32)
            restore[GroundTruth.Key(out)] = sealed.blob
            return DmSeal.Sealed.Ok(out)
        }
        fun back(blob: ByteArray): ByteArray = restore[GroundTruth.Key(blob)] ?: blob
        PrivacyMutant(
            id = "PM-13",
            defeats = "T26: no Olm header byte string appears outside the seal",
            detectedBy = "JD1, JD2 (§15.7); both here",
            killers = listOf(
                PrivacyMutant.Killer(PrivacyCheck.JD2, "OI of c"),
                PrivacyMutant.Killer(PrivacyCheck.JD1, "Olm identity key found"),
            ),
            envelopes = { _, _, native ->
                object : DmEnvelopes by native {
                    override fun sealIntro(
                        cardIndex: Int, namespace: ByteArray, bucket: Int, introKeyEnv: ByteArray,
                        peerIdentityPk: ByteArray, peerOlmIdentity: ByteArray, genId: Int, genPublic: ByteArray,
                        bindingMinute: Long, sessionId: ByteArray, replySeedEnv: ByteArray, l1: ByteArray,
                    ): DmSeal.Sealed = wire(
                        native.sealIntro(
                            cardIndex, namespace, bucket, introKeyEnv, peerIdentityPk, peerOlmIdentity, genId,
                            genPublic, bindingMinute, sessionId, replySeedEnv, l1,
                        ),
                        peerOlmIdentity,
                    )

                    override fun sealPair(
                        namespace: ByteArray, bucket: Int, openEnv: ByteArray, contactId: ByteArray, rootGen: Int,
                        week: Long, oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                    ): DmSeal.Sealed = wire(
                        native.sealPair(namespace, bucket, openEnv, contactId, rootGen, week, oiSender, oiRecipient, l1),
                        oiRecipient,
                    )

                    override fun sealProvisional(
                        namespace: ByteArray, bucket: Int, openEnv: ByteArray, direction: Int, sessionId: ByteArray,
                        oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                    ): DmSeal.Sealed = wire(
                        native.sealProvisional(namespace, bucket, openEnv, direction, sessionId, oiSender, oiRecipient, l1),
                        oiRecipient,
                    )

                    override fun hintMatches(blob: ByteArray, recognitionKey: ByteArray): Boolean =
                        native.hintMatches(back(blob), recognitionKey)

                    override fun openOuterIntro(cardIndex: Int, namespace: ByteArray, blob: ByteArray): DmSeal.OuterIntro =
                        native.openOuterIntro(cardIndex, namespace, back(blob))

                    override fun openIntro(
                        cardIndex: Int, namespace: ByteArray, genId: Int, genSecretsEnv: ByteArray,
                        genFallbackPublic: ByteArray, blob: ByteArray,
                    ): DmSeal.OpenedIntro = native.openIntro(cardIndex, namespace, genId, genSecretsEnv, genFallbackPublic, back(blob))

                    override fun openPair(
                        namespace: ByteArray, blob: ByteArray, openEnv: ByteArray, contactId: ByteArray, rootGen: Int,
                        week: Long, oiSender: ByteArray, oiRecipient: ByteArray,
                    ): DmSeal.OuterSymmetric =
                        native.openPair(namespace, back(blob), openEnv, contactId, rootGen, week, oiSender, oiRecipient)

                    override fun openProvisional(
                        namespace: ByteArray, blob: ByteArray, openEnv: ByteArray, direction: Int, sessionId: ByteArray,
                        oiSender: ByteArray, oiRecipient: ByteArray,
                    ): DmSeal.OuterSymmetric =
                        native.openProvisional(namespace, back(blob), openEnv, direction, sessionId, oiSender, oiRecipient)
                }
            },
        )
    }

    /** The one statement that erases a week key (`ContactStore.deletePairKey`). */
    private const val ERASE_WEEK_KEY =
        "DELETE FROM dm_pair_key WHERE contact_id = ? AND direction = ? AND root_gen = ? AND week = ?"

    /**
     * **PM-19 — pair week keys kept beyond the FRESH window.** SWEEP's erasure of a week key does
     * nothing, so a seized device still holds the opening keys of expired weeks (P-7, T34).
     */
    val PM19 = PrivacyMutant(
        id = "PM-19",
        defeats = "T34 and P-7: no stored key opens a pair envelope of an expired week",
        detectedBy = "T34 seizure scenario, erasure tests (§15.7); T34 here",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.T34, "old-week pair envelopes opened by retained keys")),
        rewrite = { sql, args -> if (sql == ERASE_WEEK_KEY) "$sql AND 0" to args else sql to args },
    )

    /**
     * **PM-36 — recognition keys not erased with their opening keys.** SWEEP destroys the opening
     * key of an expired week and keeps its recognition key, so the seized device can no longer open
     * those envelopes and can still tell which conversation each belonged to (R-S6).
     */
    val PM36 = PrivacyMutant(
        id = "PM-36",
        defeats = "R-S6 and T34: a recognition key follows the erasure schedule of its opening key",
        detectedBy = "T34 world (§15.7); T34 here",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.T34, "recognised by a retained recognition key")),
        rewrite = { sql, args ->
            if (sql == ERASE_WEEK_KEY) {
                "UPDATE dm_pair_key SET open_env = zeroblob(60) " +
                    "WHERE contact_id = ? AND direction = ? AND root_gen = ? AND week = ?" to args
            } else {
                sql to args
            }
        },
    )

    /**
     * **PM-24 — the relay set chosen by the client (E-15).** Every client keeps its namespaces on the
     * three slots it prefers — slots 0, 1 and 2 of the four — instead of `set(ns, w)`. It is the
     * uniform version of the mutant: §15.7's fingerprint needs a per-client choice carried in the
     * card, which the world cannot express without a card change (§22.16); what JD9 checks, a relay
     * set that is not `set(ns, w)`, is the same.
     */
    val PM24 = PrivacyMutant(
        id = "PM-24",
        defeats = "§5.2, JD9: every DM namespace's relay set is set(ns, w)",
        detectedBy = "JD9 (§15.7); JD9 here",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.JD9, "set(ns) =")),
        configure = { device -> device.slots = device.slots.filter { it.slot != 3 } },
    )

    /** `SessionStore.boundProvisionalErase`: the anchor's 119-day bound on `prov_erase_minute`. */
    private const val BOUND_PROVISIONAL_ERASE =
        "UPDATE olm_session SET prov_erase_minute = prov_anchor_minute + ? " +
            "WHERE contact_id = ? AND slot = ? AND prov_env IS NOT NULL " +
            "AND prov_anchor_minute IS NOT NULL " +
            "AND (prov_erase_minute IS NULL OR prov_erase_minute > prov_anchor_minute + ?)"

    /**
     * **PM-39 — `prov_env` kept past `prov_anchor_minute + 119 d` (§22.8.5).** The anchor no longer
     * bounds the erase minute, so only a pair envelope under the device's own root schedules it —
     * which is exactly the engine before slice S11's review: a side whose peer never wrote after
     * receiving its root keeps its `reply_seed` for as long as the session lives.
     */
    val PM39 = PrivacyMutant(
        id = "PM-39",
        defeats = "§22.8.5 rule 4, P-7: each side erases prov_env by prov_anchor_minute + 119 d",
        detectedBy = "T34 one-reply variant (§15.7); here",
        killers = listOf(
            PrivacyMutant.Killer(PrivacyCheck.T34_ONE_REPLY, "keeps prov_env past prov_anchor_minute + 119 d"),
        ),
        rewrite = { sql, args -> if (sql == BOUND_PROVISIONAL_ERASE) "$sql AND 0" to args else sql to args },
    )

    /** `OutboxStore.enqueue`'s insert: the TTL is its fifth argument (`blob.ttl.seconds`). */
    private const val ENQUEUE_OP = "INSERT INTO outbox_op(operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, "

    /**
     * **PM-5 — "1 h through day rounding" (§15.7).** Every op's TTL is written as the whole days of
     * its bucket (`TtlBucket.days × 86 400`, the rounding §10.2 row 7 keeps for day-granular fields
     * and that the `ttl_bucket_days` relay field applied before D15), so a 5-minute or a 1-hour
     * conversation's blobs are kept for a day. It is a bucket, so `outbox_op`'s CHECK and a relay
     * that accepts exact buckets both take it; only a check that knows the timer the users set sees
     * it. **Only this half is built.** §15.7's other half — "TTL = exact timer seconds" — is refused
     * by that CHECK before any relay could see it (a crash, not a leak); its killers, the relay's
     * `rejected_ttl` and the capture check, are outside this world, so it is **not** run and not
     * counted: the report's PM-5 line says which half was detected (§22.21 item 8 lists the other
     * with the deferred mutants).
     */
    val PM5 = PrivacyMutant(
        id = "PM-5",
        defeats = "R-T1, T30: the relay TTL is §10.1's table of the timer, 5 min and 1 h at 1 h",
        detectedBy = "relay rejected_ttl, capture-check, JD5 (§15.7); JD5 here, on the day-rounding half",
        scope = "the day-rounding half only; the exact-seconds half is not built",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.JD5, "stored with TTL 86400; the timer the users set (code")),
        rewrite = { sql, args ->
            if (sql.startsWith(ENQUEUE_OP) && (args[4] as Number).toLong() == 3_600L) {
                sql to args.toMutableList().also { it[4] = 86_400 }
            } else {
                sql to args
            }
        },
    )

    /** `ContactStore.setEstablishment`: the one statement that writes `fetch_attempts` forward. */
    private const val SET_ESTABLISHMENT =
        "UPDATE dm_contact SET establishment = ?, fetch_attempts = ?, fetch_listen_until_minute = ? WHERE contact_id = ?"

    /**
     * **PM-31 — unbounded bundle fetch attempts (§21.7).** The attempt counter is written as at most
     * one, so `EST-START`'s "three attempts" and `EST-END`'s "after the third, unreachable" never
     * bind: an establishment whose bundle never arrives keeps opening a 15-minute window at every
     * relay session six hours after the last — the unbounded co-occurrence of `P_c` with session
     * starts L7-D6 declares bounded at three. Only a world in which the bound is reached shows it:
     * the JD7 variant under WITHHOLD_ALL_BUNDLES (§21.7 point 6), where no bundle ever arrives.
     */
    val PM31 = PrivacyMutant(
        id = "PM-31",
        defeats = "§21.7 point 5, L7-D6: at most three attempt windows per establishment",
        detectedBy = "JD7 variant with WITHHOLD_ALL_BUNDLES (§15.7); here",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.JD7_WITHHOLD, "outside every attempt window")),
        rewrite = { sql, args ->
            if (sql == SET_ESTABLISHMENT) {
                sql.replace("fetch_attempts = ?", "fetch_attempts = min(?, 1)") to args
            } else {
                sql to args
            }
        },
    )

    // ------------------------------------------------------------------ the entitlement world (§22.26)

    /**
     * A JD8 kill: extra calls in the active twin (the twin with the DM activity), refused when the
     * twins did not reach their variable — a world that stopped, a text never delivered, an idle
     * twin with DM traffic — since JD8 then compared nothing the mutant decided.
     */
    private val JD8_KILL = PrivacyMutant.Killer(PrivacyCheck.JD8, "calls only in the active twin", refuse = "did not reach their variable")

    /**
     * **PM-1 — a per-sender token-bought write capability for a contact inbox (Annex B literal).**
     * The sender no longer writes to a contact's inbox with the DEPOSIT credential its card yields
     * (§4.3, §21.2): the DM steps register the contact's inbox as a namespace whose write access is
     * **redeemed** (`CapabilitySource.REDEEM`, not `LOCAL`) and install no DEPOSIT credential, so the
     * inbox has outbox work and no write token, the planner redeems one of the sender's own ACCESS
     * tokens for it at every relay of its set, and the deposits go out under that capability — which
     * the relay accepts, so every message still arrives. It lives on the DM steps' sync ports
     * (`DmDevice.HarnessOverride.decorateNamespaces`/`decorateCapabilities`): the owner's own
     * namespaces and the engines' stores are untouched.
     */
    val PM1 = PrivacyMutant(
        id = "PM-1",
        defeats = "P-2, T27: no honest client redeems for a namespace it does not own; a sender deposits with the card's credential",
        detectedBy = "JD3, JD8, NI-DM3 (§15.7); JD8 here — the privacy world, where JD3 and NI-DM3 run, has no redeem lane (§22.26)",
        killers = listOf(JD8_KILL),
        entWorld = org.ghost.messaging.entworld.EntMutation(
            decorateNamespaces = { real ->
                object : org.ghost.sync.api.Namespaces by real {
                    override fun register(
                        tx: org.ghost.sync.api.SyncTransaction,
                        namespace: NamespaceId,
                        consumer: Consumer,
                        relays: Set<org.ghost.sync.api.RelayId>,
                        listen: Boolean,
                        sendDelay: org.ghost.sync.api.SendDelay,
                        capabilitySource: CapabilitySource,
                    ) {
                        // A contact's inbox: registered write-only, by SEND S7 and the contact KEEPER.
                        val contactInbox = consumer == Consumer.DM && !listen && capabilitySource == CapabilitySource.LOCAL
                        real.register(tx, namespace, consumer, relays, listen, sendDelay, if (contactInbox) CapabilitySource.REDEEM else capabilitySource)
                    }
                }
            },
            decorateCapabilities = { real ->
                object : org.ghost.sync.api.Capabilities by real {
                    override fun put(
                        tx: org.ghost.sync.api.SyncTransaction,
                        relay: org.ghost.sync.api.RelayId,
                        namespace: NamespaceId,
                        kind: org.ghost.sync.api.CapabilityKind,
                        token: ByteArray,
                        expiresAtEpochSeconds: Long?,
                    ) {
                        val deposit = org.ghost.sync.harness.ModelRelay.credential(token)?.kind == org.ghost.sync.harness.ModelRelay.KIND_DEPOSIT
                        if (kind == org.ghost.sync.api.CapabilityKind.WRITE && deposit) return
                        real.put(tx, relay, namespace, kind, token, expiresAtEpochSeconds)
                    }
                }
            },
        ),
    )

    /** The four statements of `CapabilityStore.needed` select the need's source as this column. */
    private const val NEED_SOURCE = "n.capability_source FROM"

    /**
     * **PM-1b — the planner redeems a LOCAL need.** Every need reaches the redeem planner as a
     * REDEEM one: the source column of the four statements `Capabilities.needed()` runs is read as
     * `'redeem'`. In production code the planner's LOCAL line (`RedeemPlanner.plan`: "a LOCAL need
     * is decided before anything else") is the only reader of a need's source, so this is that
     * line deleted, reached through the planner's input because the engine has no seam in its code.
     * A LOCAL need exists where a card holder's own credential is refused: alice's FETCH credential
     * for the bundle of dave, who holds no token and registered nothing (`Jd8Twin`), so the planner
     * redeems alice's own tokens for dave's bundle namespace. The entitlement world's every-commit
     * check catches that capability at its commit too ("a redeemed capability on a LOCAL
     * namespace"), which is why JD8's mutated worlds run with that check off (`Jd8Twin`).
     */
    val PM1B = PrivacyMutant(
        id = "PM-1b",
        defeats = "§13.4, T27: the planner never redeems a LOCAL need (DM breadth costs no token)",
        detectedBy = "JD8, planner test (§15.7); JD8 here — `RedeemPlannerTest` hands the planner a LOCAL need directly, " +
            "so the mutation of the needs it reads is JD8's alone",
        killers = listOf(JD8_KILL),
        entWorld = org.ghost.messaging.entworld.EntMutation(
            rewrite = { _ ->
                { sql, args -> if (sql.startsWith("SELECT") && NEED_SOURCE in sql) sql.replace(NEED_SOURCE, "'redeem' FROM") to args else sql to args }
            },
        ),
    )

    /** `RegistrationStore.keep`'s look-up of the row it would insert. */
    private const val KEEP_LOOKUP =
        "SELECT verifier, inflight FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 AND period_id = ?3 AND kind = ?4"

    /**
     * **PM-26 — owner registrations created on the first inbound deposit instead of from the
     * capabilities and the week.** REGROWS inserts a row of a period **after the current week** —
     * the `c + 1` rows of §4.8, and `c` when the capability was redeemed early — only once a deposit
     * has reached the owner's own inbox (an `inbox_blob` row of it): `keep`'s look-up answers "a row
     * with its call in flight" until then, so `keep` inserts nothing. The current week's rows are
     * left alone, which is the half built: a mutant that waited for a deposit before those too would
     * deliver nothing at all, since the relay stores no deposit into an inbox with no DEPOSIT
     * registration (§4.5), and would never see a first deposit.
     */
    val PM26 = PrivacyMutant(
        id = "PM-26",
        defeats = "§4.8, T27: the owner's registrations follow its capabilities and the week, never its inbound traffic",
        detectedBy = "JD8, NI-DM1 (§15.7); JD8 here",
        scope = "the rows of later weeks only; a mutant that also held back the current week's rows would deliver nothing",
        killers = listOf(JD8_KILL),
        entWorld = org.ghost.messaging.entworld.EntMutation(
            rewrite = { w ->
                { sql, args ->
                    val later = sql == KEEP_LOOKUP && (args[2] as Number).toLong() > org.ghost.sync.harness.ModelRelay.week(w.clock.epochSeconds())
                    if (later) {
                        "$sql UNION ALL SELECT zeroblob(32), 1 WHERE NOT EXISTS ($sql) AND NOT EXISTS (SELECT 1 FROM inbox_blob b " +
                            "JOIN dm_own_namespace d ON d.namespace_id = b.namespace_id WHERE d.role = 'inbox')" to args
                    } else {
                        sql to args
                    }
                }
            },
        ),
    )

    fun all(): List<PrivacyMutant> = listOf(PM1, PM1B, PM2, PM3, PM4, PM5, PM6, PM8, PM13, PM19, PM24, PM26, PM31, PM36, PM39)
}
