package org.ghost.messaging.port

import org.ghost.crypto.bridge.DmBundles
import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmPairing
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.crypto.bridge.Recognition

/**
 * Everything the send and receive steps of Phase 9 design §7 call into the cryptography for: the
 * seal of §6, the Olm sessions of §8.1, the pair and provisional keys of §6.3 and §6.7, and the
 * L0 codec of §7.1.
 *
 * **Why a port with one implementation.** §13.1 makes `:crypto-bridge` the only module that
 * touches the JNI surface, and [NativeDmEnvelopes] is the whole of the coupling. What the port
 * buys is a seam the engine is written against, so a step reads as transactions and guards rather
 * than as handles — and so a test can count calls (the one-attempt spy of rule R-S5, the
 * recording `DmNative.encrypt` counter of §15.1) without reaching into the bridge.
 *
 * **It is not faked.** Unlike [DmCrypto], whose calls are derivations a deterministic fake can
 * stand in for, every call here is a ratchet step, an AEAD or a KEM: a fake would prove its own
 * arithmetic and hide exactly the mistakes this layer can make (a wrong wrap binding, a wrong
 * direction byte, a peer that cannot open what we sealed). The engine's JVM tests therefore run
 * the real library through `ghost-dm-host`, as §15.1 requires, and skip where it is absent.
 *
 * **Value semantics (§7.9).** Every call takes stored envelopes and returns new ones. The caller
 * writes what came back inside its own transaction and only on a success outcome.
 */
interface DmEnvelopes {

    /** True while a DM context is open; false maps to `CRYPTO_UNAVAILABLE` at the facade. */
    fun isAvailable(): Boolean

    // ------------------------------------------------------------------ bundles

    /** §2.6 function 6: opens and verifies a contact's bundle v2 (§5.5). */
    fun openBundle(
        bundleKeyEnv: ByteArray,
        bundleNamespace: ByteArray,
        blob: ByteArray,
        expectedIdentityPk: ByteArray,
        expectedCardIndex: Int,
    ): DmBundles.OpenResult

    // -------------------------------------------------------------------- seals

    /** §2.6 function 9: intro mode (§6.4). */
    @Suppress("LongParameterList")
    fun sealIntro(
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
    ): DmSeal.Sealed

    /** §2.6 function 10 in pair mode (§6.3). */
    @Suppress("LongParameterList")
    fun sealPair(
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): DmSeal.Sealed

    /** §2.6 function 10 in provisional mode (§6.7). */
    @Suppress("LongParameterList")
    fun sealProvisional(
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): DmSeal.Sealed

    /** §2.6 function 11 in intro mode: the generation an envelope is addressed to. */
    fun openOuterIntro(cardIndex: Int, namespace: ByteArray, blob: ByteArray): DmSeal.OuterIntro

    /** §2.6 function 11 in pair mode. */
    @Suppress("LongParameterList")
    fun openPair(
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmSeal.OuterSymmetric

    /** §2.6 function 11 in provisional mode. */
    @Suppress("LongParameterList")
    fun openProvisional(
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmSeal.OuterSymmetric

    /** §2.6 function 12: the X-Wing-keyed inner layer, binding v3 verified (§6.4, §6.5 step 4). */
    @Suppress("LongParameterList")
    fun openIntro(
        cardIndex: Int,
        namespace: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        blob: ByteArray,
    ): DmSeal.OpenedIntro

    // ----------------------------------------------------------- pair and provisional

    /** §2.6 function 15: the week keys of a window, ratcheted from the base week (§6.3). */
    @Suppress("LongParameterList")
    fun pairKeys(
        contactId: ByteArray,
        direction: DmSeal.PairDirection,
        rootGen: Int,
        from: DmPairing.From,
        keyEnv: ByteArray,
        baseWeek: Long,
        fromWeek: Long,
        toWeek: Long,
    ): DmPairing.KeysResult

    /** Function 22: the random root this device offers a contact for `c → me` (§6.3). */
    fun pairOffer(contactId: ByteArray, rootGen: Int, baseWeek: Long): DmPairing.OfferResult

    /** Function 21: the two provisional keys of one session (§6.7). */
    fun provisionalKeys(
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        replySeedEnv: ByteArray,
        peerOlmIdentity: ByteArray,
    ): DmPairing.ProvisionalResult

    // ------------------------------------------------------------------ sessions

    /** §2.6 function 7: a new initiator session toward a contact's published keys (§8.1). */
    fun outbound(
        contactId: ByteArray,
        peerOlmIdentity: ByteArray,
        peerFallbackKey: ByteArray,
        today: Int,
    ): DmSessions.Outbound

    /** §2.6 function 8: one ratchet step on the `current` slot. */
    fun encrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot,
        l0: ByteArray,
        today: Int,
    ): DmSessions.Encrypted

    /** §2.6 function 13: the two-slot trial of §7.6. */
    @Suppress("LongParameterList")
    fun decrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot?,
        previous: DmSessions.StoredSlot?,
        l1: ByteArray,
        isPreKey: Boolean,
        today: Int,
    ): DmSessions.Decrypted

    /** §2.6 function 14: a new responder session from a first flight (§8.1). */
    @Suppress("LongParameterList")
    fun inbound(
        contactId: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        expectedPeerIdentity: ByteArray,
        l1: ByteArray,
        today: Int,
    ): DmSessions.Inbound

    /**
     * §2.6 function 19: the gap hold's expected index, read from the stored state during peek
     * (§7.7 point 2). It writes nothing and sends nothing (T28).
     */
    fun chainPosition(
        contactId: ByteArray,
        slot: DmSessions.StoredSlot,
        ratchetKey: ByteArray,
    ): DmSessions.ChainPosition

    // ------------------------------------------------------------------- content

    /** §2.6 function 18: the canonical L0 of §7.1, with the bucket R-B1 chose (§6.6). */
    @Suppress("LongParameterList")
    fun encodeContent(
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
    ): DmContent.Encoded

    /** §2.6 function 18: the fail-closed decode of §7.1 (R-C4). */
    fun decodeContent(contactId: ByteArray, l0: ByteArray): DmContent.DecodeResult

    // --------------------------------------------------------------- recognition

    /**
     * Rule R-S5: whether a blob's hint is the one a recognition key produces.
     *
     * Matching is Kotlin's (§2.4), and it is on this port so the one-attempt property can be
     * counted: a test wraps the port and asserts that at most one open follows per blob, whatever
     * the number of candidates (mutant PM-18).
     */
    fun hintMatches(blob: ByteArray, recognitionKey: ByteArray): Boolean
}

/**
 * [DmEnvelopes] over the real JNI surface.
 *
 * It holds the [DmContext] rather than a handle, so a context closed between two calls — a lock,
 * a wipe — is the routine `CRYPTO_UNAVAILABLE` of §2.7 and never a call on a stale handle. Every
 * function answers the facade's `Unavailable` outcome in that case, which each step turns into a
 * result and never into a crash loop (§13.2).
 */
class NativeDmEnvelopes(private val context: DmContext) : DmEnvelopes {

    override fun isAvailable(): Boolean = context.handleOrNull() != null

    override fun openBundle(
        bundleKeyEnv: ByteArray,
        bundleNamespace: ByteArray,
        blob: ByteArray,
        expectedIdentityPk: ByteArray,
        expectedCardIndex: Int,
    ): DmBundles.OpenResult {
        val handle = context.handleOrNull() ?: return DmBundles.OpenResult.Unavailable
        return DmBundles.open(
            handle,
            bundleKeyEnv,
            bundleNamespace,
            blob,
            expectedIdentityPk,
            expectedCardIndex,
        )
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
        val handle = context.handleOrNull() ?: return DmSeal.Sealed.Unavailable
        return DmSeal.sealIntro(
            handle,
            cardIndex,
            namespace,
            bucket,
            introKeyEnv,
            peerIdentityPk,
            peerOlmIdentity,
            genId,
            genPublic,
            bindingMinute,
            sessionId,
            replySeedEnv,
            l1,
        )
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
        val handle = context.handleOrNull() ?: return DmSeal.Sealed.Unavailable
        return DmSeal.sealPair(
            handle,
            namespace,
            bucket,
            openEnv,
            contactId,
            rootGen,
            week,
            oiSender,
            oiRecipient,
            l1,
        )
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
        val handle = context.handleOrNull() ?: return DmSeal.Sealed.Unavailable
        return DmSeal.sealProvisional(
            handle,
            namespace,
            bucket,
            openEnv,
            direction,
            sessionId,
            oiSender,
            oiRecipient,
            l1,
        )
    }

    override fun openOuterIntro(
        cardIndex: Int,
        namespace: ByteArray,
        blob: ByteArray,
    ): DmSeal.OuterIntro {
        val handle = context.handleOrNull() ?: return DmSeal.OuterIntro.Unavailable
        return DmSeal.openOuterIntro(handle, cardIndex, namespace, blob)
    }

    @Suppress("LongParameterList")
    override fun openPair(
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmSeal.OuterSymmetric {
        val handle = context.handleOrNull() ?: return DmSeal.OuterSymmetric.Unavailable
        return DmSeal.openPair(
            handle,
            namespace,
            blob,
            openEnv,
            contactId,
            rootGen,
            week,
            oiSender,
            oiRecipient,
        )
    }

    @Suppress("LongParameterList")
    override fun openProvisional(
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmSeal.OuterSymmetric {
        val handle = context.handleOrNull() ?: return DmSeal.OuterSymmetric.Unavailable
        return DmSeal.openProvisional(
            handle,
            namespace,
            blob,
            openEnv,
            direction,
            sessionId,
            oiSender,
            oiRecipient,
        )
    }

    @Suppress("LongParameterList")
    override fun openIntro(
        cardIndex: Int,
        namespace: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        blob: ByteArray,
    ): DmSeal.OpenedIntro {
        val handle = context.handleOrNull() ?: return DmSeal.OpenedIntro.Unavailable
        return DmSeal.openIntro(
            handle,
            cardIndex,
            namespace,
            genId,
            genSecretsEnv,
            genFallbackPublic,
            blob,
        )
    }

    @Suppress("LongParameterList")
    override fun pairKeys(
        contactId: ByteArray,
        direction: DmSeal.PairDirection,
        rootGen: Int,
        from: DmPairing.From,
        keyEnv: ByteArray,
        baseWeek: Long,
        fromWeek: Long,
        toWeek: Long,
    ): DmPairing.KeysResult {
        val handle = context.handleOrNull() ?: return DmPairing.KeysResult.Unavailable
        return DmPairing.keys(
            handle,
            contactId,
            direction,
            rootGen,
            from,
            keyEnv,
            baseWeek,
            fromWeek,
            toWeek,
        )
    }

    override fun pairOffer(
        contactId: ByteArray,
        rootGen: Int,
        baseWeek: Long,
    ): DmPairing.OfferResult {
        val handle = context.handleOrNull() ?: return DmPairing.OfferResult.Unavailable
        return DmPairing.offer(handle, contactId, rootGen, baseWeek)
    }

    override fun provisionalKeys(
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        replySeedEnv: ByteArray,
        peerOlmIdentity: ByteArray,
    ): DmPairing.ProvisionalResult {
        val handle = context.handleOrNull() ?: return DmPairing.ProvisionalResult.Unavailable
        return DmPairing.provisional(
            handle,
            contactId,
            sessionId,
            stateEnv,
            replySeedEnv,
            peerOlmIdentity,
        )
    }

    override fun outbound(
        contactId: ByteArray,
        peerOlmIdentity: ByteArray,
        peerFallbackKey: ByteArray,
        today: Int,
    ): DmSessions.Outbound {
        val handle = context.handleOrNull() ?: return DmSessions.Outbound.Unavailable
        return DmSessions.outbound(handle, contactId, peerOlmIdentity, peerFallbackKey, today)
    }

    override fun encrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot,
        l0: ByteArray,
        today: Int,
    ): DmSessions.Encrypted {
        val handle = context.handleOrNull() ?: return DmSessions.Encrypted.Unavailable
        return DmSessions.encrypt(handle, contactId, current, l0, today)
    }

    @Suppress("LongParameterList")
    override fun decrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot?,
        previous: DmSessions.StoredSlot?,
        l1: ByteArray,
        isPreKey: Boolean,
        today: Int,
    ): DmSessions.Decrypted {
        val handle = context.handleOrNull() ?: return DmSessions.Decrypted.Unavailable
        return DmSessions.decrypt(handle, contactId, current, previous, l1, isPreKey, today)
    }

    @Suppress("LongParameterList")
    override fun inbound(
        contactId: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        expectedPeerIdentity: ByteArray,
        l1: ByteArray,
        today: Int,
    ): DmSessions.Inbound {
        val handle = context.handleOrNull() ?: return DmSessions.Inbound.Unavailable
        return DmSessions.inbound(
            handle,
            contactId,
            genId,
            genSecretsEnv,
            genFallbackPublic,
            expectedPeerIdentity,
            l1,
            today,
        )
    }

    override fun chainPosition(
        contactId: ByteArray,
        slot: DmSessions.StoredSlot,
        ratchetKey: ByteArray,
    ): DmSessions.ChainPosition {
        val handle = context.handleOrNull() ?: return DmSessions.ChainPosition.Unavailable
        return DmSessions.chainPosition(handle, contactId, slot, ratchetKey)
    }

    @Suppress("LongParameterList")
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
    ): DmContent.Encoded {
        val handle = context.handleOrNull() ?: return DmContent.Encoded.Unavailable
        return DmContent.encode(
            handle,
            kind,
            messageId,
            authorMinute,
            minuteIndex,
            timerCode,
            timerVersion,
            quoteRef,
            body,
            contactId,
            offerRootGen,
            offerEnv,
            revocation,
            sessionReset,
        )
    }

    override fun decodeContent(contactId: ByteArray, l0: ByteArray): DmContent.DecodeResult {
        val handle = context.handleOrNull() ?: return DmContent.DecodeResult.Unavailable
        return DmContent.decode(handle, contactId, l0)
    }

    override fun hintMatches(blob: ByteArray, recognitionKey: ByteArray): Boolean =
        Recognition.matches(blob, recognitionKey)

    override fun toString(): String = "NativeDmEnvelopes"
}
