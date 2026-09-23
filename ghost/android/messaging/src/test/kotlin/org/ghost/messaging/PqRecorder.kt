package org.ghost.messaging

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.messaging.port.DmEnvelopes

/**
 * The ground truth of the PQ-C worlds (Phase 9 design §9.4, §15.5 PQ3, PQ4, PQ6; slice S13),
 * recorded at the envelope port and never re-derived from the engine's own rows: every L0 the
 * engine encoded with the TLVs that rode, every root offer it minted and in which form, and every
 * pair envelope it sealed with the (generation, week) key that sealed it.
 *
 * One log serves every device of a world; each record names its device by MESSAGING branch.
 */
internal class PqLog {
    /** The world's clock, set once the world exists (every device shares it). */
    var now: () -> Long = { 0L }

    class Encoded(
        val branch: Int,
        val at: Long,
        val contactId: ByteArray,
        val kind: DmContent.Kind,
        val bodyLength: Int,
        val l0: ByteArray,
        val bucket: Int,
        val sealRootRode: Boolean,
        val sealRootPqRode: Boolean,
        val pqKeyRode: Boolean,
        /** Whether a `pq_key` candidate was offered to the codec at all. */
        val pqKeyOffered: Boolean,
        /** The `bundle_week` of the generation the candidate named, if one was offered. */
        val pqKeyWeek: Long?,
        /** Whether R-C5's order put the announcement ahead of the offer. */
        val pqKeyFirst: Boolean,
        /** The length of the offer envelope handed in: 0, 70 (classical) or 1 194 (PQ-C). */
        val offerEnvLength: Int,
    )

    class Offer(
        val branch: Int,
        val at: Long,
        val contactId: ByteArray,
        val rootGen: Int,
        /** Null for a classical `seal_root`; the peer's generation for a `seal_root_pq`. */
        val peerGenId: Long?,
    )

    class PairBlob(
        val branch: Int,
        val at: Long,
        val contactId: ByteArray,
        val rootGen: Int,
        val week: Long,
        val blob: ByteArray,
    )

    val encoded = ArrayList<Encoded>()
    val offers = ArrayList<Offer>()
    val pairBlobs = ArrayList<PairBlob>()

    /** Every blob any seal of a device returned, with its size: T29's bucket half. */
    val sealedSizes = ArrayList<Pair<Int, Int>>()
}

/**
 * The recording decorator. [forceClassical] is the control mutant of PQ3: every PQ-C offer is
 * answered `INVALID_KEY`, which SEND takes as §22.8.2 rule 4's fallback to the classical
 * `seal_root` — a client that never heals, built from the production code path.
 */
internal class PqRecorder(
    private val inner: DmEnvelopes,
    private val branch: Int,
    private val log: PqLog,
    private val forceClassical: Boolean = false,
    /** PQ4's twin: no `pq_key` candidate ever reaches the codec, so no PQ-C TLV rides at all. */
    private val stripPqKey: Boolean = false,
) : DmEnvelopes by inner {

    override fun encodeContent(
        kind: DmContent.Kind,
        messageId: ByteArray,
        authorMinute: Long,
        minuteIndex: Int,
        timerCode: Int,
        timerVersion: Long,
        quoteRef: ByteArray?,
        body: ByteArray,
        contactId: ByteArray,
        offerRootGen: Int,
        offerEnv: ByteArray,
        revocation: ByteArray,
        sessionReset: Boolean,
        pqKey: DmContent.PqKeyCandidate?,
        pqKeyFirst: Boolean,
    ): DmContent.Encoded {
        val candidate = if (stripPqKey) null else pqKey
        val encoded = inner.encodeContent(
            kind, messageId, authorMinute, minuteIndex, timerCode, timerVersion, quoteRef, body,
            contactId, offerRootGen, offerEnv, revocation, sessionReset, candidate, pqKeyFirst,
        )
        if (encoded is DmContent.Encoded.Ok) {
            log.encoded += PqLog.Encoded(
                branch = branch,
                at = log.now(),
                contactId = contactId.copyOf(),
                kind = kind,
                bodyLength = body.size,
                l0 = encoded.l0.copyOf(),
                bucket = encoded.bucket,
                sealRootRode = encoded.sealRootRode,
                sealRootPqRode = encoded.sealRootPqRode,
                pqKeyRode = encoded.pqKeyRode,
                pqKeyOffered = candidate != null,
                pqKeyWeek = candidate?.bundleWeek,
                pqKeyFirst = pqKeyFirst,
                offerEnvLength = offerEnv.size,
            )
        }
        return encoded
    }

    override fun pairOffer(contactId: ByteArray, rootGen: Int, baseWeek: Long): DmPairing.OfferResult {
        val offer = inner.pairOffer(contactId, rootGen, baseWeek)
        if (offer is DmPairing.OfferResult.Ok) {
            log.offers += PqLog.Offer(branch, log.now(), contactId.copyOf(), rootGen, null)
        }
        return offer
    }

    @Suppress("LongParameterList")
    override fun pqRootSeal(
        contactId: ByteArray,
        rootGen: Int,
        baseWeek: Long,
        peerOlmIdentity: ByteArray,
        peerGenId: Long,
        peerXwingPublic: ByteArray,
    ): DmPairing.PqOfferResult {
        if (forceClassical) return DmPairing.PqOfferResult.InvalidKey
        val offer = inner.pqRootSeal(contactId, rootGen, baseWeek, peerOlmIdentity, peerGenId, peerXwingPublic)
        if (offer is DmPairing.PqOfferResult.Ok) {
            log.offers += PqLog.Offer(branch, log.now(), contactId.copyOf(), rootGen, peerGenId)
        }
        return offer
    }

    @Suppress("LongParameterList")
    override fun sealPair(
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): DmSeal.Sealed {
        val sealed = inner.sealPair(namespace, bucket, openEnv, contactId, rootGen, week, oiSender, oiRecipient, l1)
        if (sealed is DmSeal.Sealed.Ok) {
            log.pairBlobs += PqLog.PairBlob(branch, log.now(), contactId.copyOf(), rootGen, week, sealed.blob.copyOf())
            log.sealedSizes += bucket to sealed.blob.size
        }
        return sealed
    }

    @Suppress("LongParameterList")
    override fun sealProvisional(
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): DmSeal.Sealed {
        val sealed = inner.sealProvisional(namespace, bucket, openEnv, direction, sessionId, oiSender, oiRecipient, l1)
        if (sealed is DmSeal.Sealed.Ok) log.sealedSizes += bucket to sealed.blob.size
        return sealed
    }

    @Suppress("LongParameterList")
    override fun sealIntro(
        cardIndex: Int,
        namespace: ByteArray,
        bucket: Int,
        introKeyEnv: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlmIdentity: ByteArray,
        genId: Int,
        genPublic: ByteArray,
        bindingMinute: Long,
        sessionId: ByteArray,
        replySeedEnv: ByteArray,
        l1: ByteArray,
    ): DmSeal.Sealed {
        val sealed = inner.sealIntro(
            cardIndex, namespace, bucket, introKeyEnv, peerIdentityPk, peerOlmIdentity, genId, genPublic,
            bindingMinute, sessionId, replySeedEnv, l1,
        )
        if (sealed is DmSeal.Sealed.Ok) log.sealedSizes += bucket to sealed.blob.size
        return sealed
    }

    override fun toString(): String = "PqRecorder($branch)"
}
