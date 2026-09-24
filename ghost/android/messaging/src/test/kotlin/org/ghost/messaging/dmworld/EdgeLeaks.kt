package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.port.DmEnvelopes
import java.security.MessageDigest
import java.util.Collections

/**
 * The **statistics controls** of S-DM1 and S-DM2 (Phase 9 design §15.6 "Statistics", R-17:
 * "mutants that must move the statistics"): leaks built to be **edge-linking**, each run on a world
 * of the scale its statistic needs, so that a statistic which stays green over them is shown to be
 * blind, not the engine to be clean. They reuse the privacy mutants' plumbing ([PrivacyMutant]) but
 * are **not** §15.7 entries and are not in [PrivacyMutants.all] — the `dm privacy mutants` count is
 * §15.7's — and the report's `dm S-DM1 controls` line says what each one moved (§22.30).
 *
 * Existing §15.7 mutants are used where one creates an edge signal: **PM-2** (an automatic receipt,
 * a store into the sender's inbox at the recipient's fetch) is inside LD's categories — a store into
 * an inbox — so it can only move the LD attacker, which is S-DM2's to measure, and S-DM1 must **not**
 * flag it. **PM-6** (an automatic reset on an undecryptable blob) is a reflex store of the same kind,
 * but it acts only on a blob that fails to open, and the controls line counts how many the unmutated
 * world holds (none at the seed measured: only NI-DM1's MALFORMED twin injects one), so it has
 * nothing to act on here. The others of the fifteen registered are not edge leaks: PM-3 and PM-13
 * map namespaces to identities (S-DM3's and JD1/JD2's), PM-4 and PM-5 change a size or a TTL inside
 * LD's own fields, PM-8's per-identity namespace is read by a contact's **contacts** (their common
 * neighbours, not the edge), PM-24 moves relay sets, PM-31 acts only under WITHHOLD_ALL_BUNDLES,
 * PM-19, PM-36 and PM-39 act on the seizure worlds, and PM-1, PM-1b and PM-26 on the entitlement
 * world.
 */
internal object EdgeLeaks {

    /** `DirectoryStore.setListening`: the one statement that opens and closes a namespace's listening. */
    private const val SET_LISTENING = "UPDATE sync_namespace SET listening = ?1 WHERE namespace_id = ?2"

    /**
     * **The fetch window left open** (§21.7 point 2, L7-D6). The statement that closes a bundle
     * namespace's listening — `EST-READY`'s, `EST-END`'s and a block's — keeps every `prekeys`
     * namespace listening, so a reader that fetched a contact's bundle once lists that bundle
     * namespace at every relay session for as long as the world runs: the "periodic refetch" the
     * review of S11 measured against JD7 (§22.16 item 21), and the defect `abandonFetch`'s note
     * describes. Every such list is a read of `P_c` outside an attempt window — outside LD — at the
     * reader's session second, beside its own inbox list: an edge, with no message on it, in every
     * window the reader is online. S-DM1's comparison must flag it, and JD7 must fail on the same
     * world — the controls test runs JD7 on it, since this control is no §15.7 entry and the mutant
     * test never runs its [PrivacyMutant.killers].
     */
    val OPEN_FETCH_WINDOW = PrivacyMutant(
        id = "open fetch window",
        defeats = "§21.7 point 2, L7-D6: a card's bundle namespace is read only inside an attempt window",
        detectedBy = "JD7 (exact), S-DM1 (statistical)",
        killers = listOf(PrivacyMutant.Killer(PrivacyCheck.JD7, "not its own and not an open bundle fetch")),
        rewrite = { sql, args ->
            if (sql == SET_LISTENING) {
                "UPDATE sync_namespace SET listening = CASE WHEN consumer = 'prekeys' THEN 1 ELSE ?1 END WHERE namespace_id = ?2" to args
            } else {
                sql to args
            }
        },
    )

    /** Where [CONVERSATION_TAG] writes its tag, and how long it is. */
    const val TAG_OFFSET: Int = 5
    const val TAG_LENGTH: Int = 8

    /**
     * **A conversation tag in the envelope bytes.** Every envelope leaves with [TAG_LENGTH] bytes at
     * offset [TAG_OFFSET] replaced by SHA-256(the two Olm identities, sorted)'s first [TAG_LENGTH] —
     * the same in both directions of a conversation and in no other — and the receiving library
     * restores what it overwrote (a table shared by the world, as PM-13's), so every message still
     * arrives. It links the two inboxes of a conversation through **bytes only**: no event is added,
     * no time moves, and no identity value appears (the tag is a hash of two, which no dictionary of
     * JD1 or JD2 holds; the controls test runs every join on its world and reports which fail). It is
     * the control for S-DM1's exact half — the cross-namespace structure of the fields only the full
     * view has — at the shortest run that half guarantees to see (8 bytes) and at an offset the first
     * version's every-16th-offset windows never read (§22.30 item 12: a 16-byte tag at offset 4
     * passed it); and it is the measurement of what S-DM1's AUC comparison cannot see in this world:
     * LD's declared session co-occurrence already names the sender of every message here, so a leak
     * that needs a message to link adds nothing an attacker's AUC can show (§22.30).
     */
    val CONVERSATION_TAG: PrivacyMutant = run {
        val restore = Collections.synchronizedMap(HashMap<GroundTruth.Key, ByteArray>())
        fun tag(a: ByteArray, b: ByteArray): ByteArray {
            val (lo, hi) = if (java.util.Arrays.compareUnsigned(a, b) <= 0) a to b else b to a
            val md = MessageDigest.getInstance("SHA-256")
            md.update("ghost/test/conversation-tag".toByteArray(Charsets.US_ASCII))
            md.update(lo)
            md.update(hi)
            return md.digest().copyOf(TAG_LENGTH)
        }
        fun wire(sealed: DmSeal.Sealed, a: ByteArray?, b: ByteArray?): DmSeal.Sealed {
            if (sealed !is DmSeal.Sealed.Ok || a == null || b == null) return sealed
            val out = sealed.blob.copyOf()
            System.arraycopy(tag(a, b), 0, out, TAG_OFFSET, TAG_LENGTH)
            restore[GroundTruth.Key(out)] = sealed.blob
            return DmSeal.Sealed.Ok(out)
        }
        fun back(blob: ByteArray): ByteArray = restore[GroundTruth.Key(blob)] ?: blob
        PrivacyMutant(
            id = "conversation tag",
            defeats = "T26, P-2: no relay-visible byte links the two inboxes of a conversation",
            detectedBy = "S-DM1's exact half (the cross-namespace structure of the full view's fields)",
            killers = emptyList(),
            envelopes = { world, index, native ->
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
                        world.truth.clients[index]?.olmIdentity, peerOlmIdentity,
                    )

                    override fun sealPair(
                        namespace: ByteArray, bucket: Int, openEnv: ByteArray, contactId: ByteArray, rootGen: Int,
                        week: Long, oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                    ): DmSeal.Sealed = wire(
                        native.sealPair(namespace, bucket, openEnv, contactId, rootGen, week, oiSender, oiRecipient, l1),
                        oiSender, oiRecipient,
                    )

                    override fun sealProvisional(
                        namespace: ByteArray, bucket: Int, openEnv: ByteArray, direction: Int, sessionId: ByteArray,
                        oiSender: ByteArray, oiRecipient: ByteArray, l1: ByteArray,
                    ): DmSeal.Sealed = wire(
                        native.sealProvisional(namespace, bucket, openEnv, direction, sessionId, oiSender, oiRecipient, l1),
                        oiSender, oiRecipient,
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
}
