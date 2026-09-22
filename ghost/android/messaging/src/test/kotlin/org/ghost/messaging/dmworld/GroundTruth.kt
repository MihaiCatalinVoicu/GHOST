package org.ghost.messaging.dmworld

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmSeal
import org.ghost.crypto.bridge.DmSessions
import org.ghost.crypto.bridge.L1
import org.ghost.messaging.port.DmCrypto
import org.ghost.messaging.port.DmEnvelopes
import java.security.MessageDigest

/**
 * The ground truth of a privacy world (Phase 9 design §15.6: "Ground truth: identities, cards,
 * namespaces, sessions, edges, the user action behind each store, timers"), recorded **from the
 * real engine's own calls** into the closed DM surface.
 *
 * **Why a recorder on the two ports and not a second derivation.** Every value a join searches for
 * — an Olm identity key, a base key, a ratchet key, a fallback key, a body length — is produced by
 * `ghost-dm-host` inside a call the engine makes. Re-deriving them in the test would prove that the
 * test derives what the test derives; recording them at the port proves what the running system
 * actually held. The decorators forward every call unchanged and only look at what came back.
 *
 * The recorder is world-wide and single-threaded, like the world that drives it.
 */
internal class GroundTruth {

    /** Everything the dictionaries of JD1 and JD2 are built from, per client. */
    class Client(val index: Int) {
        var card: ByteArray? = null
        var identityPk: ByteArray? = null
        var olmIdentity: ByteArray? = null
        var inboxNamespace: ByteArray? = null
        var bundleNamespace: ByteArray? = null
    }

    val clients = HashMap<Int, Client>()

    fun client(index: Int): Client = clients.getOrPut(index) { Client(index) }

    /** Bundle namespace hex → its owner's identity key, as each own card is first read. */
    val bundleOwners = HashMap<String, ByteArray>()

    /** JD2: every Olm header string the running sessions produced (base, ratchet, identity keys). */
    val olmHeaderKeys = LinkedHashSet<Key>()

    /** JD2: every published fallback key and the 32-byte prefix of every published X-Wing key. */
    val bundleKeys = LinkedHashSet<Key>()

    /** Every `gen_id` a bundle was created with, by owner: the seizure world's generation truth. */
    val generations = ArrayList<Pair<Int, Int>>()

    /** JD4: the body length behind every sealed blob, keyed by the blob's SHA-256. */
    val bodyLengthOfBlob = HashMap<Key, Int>()

    /** The seal mode behind every sealed blob (intro, provisional, pair), keyed like the above. */
    val modeOfBlob = HashMap<Key, DmSeal.Mode>()

    /** Every bundle blob a client created, keyed by hash: JD4 expects them at 4 KiB. */
    val bundleBlobs = HashSet<Key>()

    /** The pair week a pair-mode blob was sealed under (T34's "pair-mode envelopes of week w"). */
    val weekOfBlob = HashMap<Key, Long>()

    /** The generation an intro blob was sealed to, and the client that sealed it. */
    val genOfBlob = HashMap<Key, Int>()

    private val bodyLengthOfL0 = HashMap<Key, Int>()
    private val bodyLengthOfL1 = HashMap<Key, Int>()

    /** How many seals of each mode the world performed (T35's denominator). */
    val seals = HashMap<String, Int>()

    /** Successful decrypts per (recipient client, contact id hex), for the PM-2 hook. */
    val decrypted = ArrayList<Pair<Int, ByteArray>>()

    /** Opens that failed after a hint matched, per (recipient client, contact id): the PM-6 hook. */
    val undecryptable = ArrayList<Pair<Int, ByteArray>>()

    /** The same for provisional envelopes, which name a session rather than a contact. */
    val undecryptableSessions = ArrayList<Pair<Int, ByteArray>>()

    /** The first minute a pair envelope from a contact opened on a client: T34's prov truth. */
    val firstPairOpen = HashMap<Pair<Int, Key>, Long>()

    /** A byte string with value semantics, for sets and maps. */
    class Key(bytes: ByteArray) {
        val bytes: ByteArray = bytes.copyOf()
        private val hash = bytes.contentHashCode()

        override fun equals(other: Any?): Boolean = other is Key && other.bytes.contentEquals(bytes)

        override fun hashCode(): Int = hash

        override fun toString(): String = hex(bytes.copyOf(minOf(8, bytes.size)))
    }

    fun recordL0(l0: ByteArray, bodyLength: Int) {
        bodyLengthOfL0[Key(sha256(l0))] = bodyLength
    }

    fun recordL1(l0: ByteArray, l1: ByteArray) {
        bodyLengthOfL0[Key(sha256(l0))]?.let { bodyLengthOfL1[Key(sha256(l1))] = it }
    }

    /** The client that sealed each blob. */
    val senderOfBlob = HashMap<Key, Int>()

    fun recordSeal(mode: DmSeal.Mode, l1: ByteArray, sealed: DmSeal.Sealed, sender: Int) {
        seals.merge(mode.name, 1, Int::plus)
        if (sealed !is DmSeal.Sealed.Ok) return
        val blobKey = Key(sha256(sealed.blob))
        modeOfBlob[blobKey] = mode
        senderOfBlob[blobKey] = sender
        bodyLengthOfL1[Key(sha256(l1))]?.let { bodyLengthOfBlob[blobKey] = it }
    }

    fun recordHeader(header: L1) {
        when (header) {
            is L1.PreKey -> {
                olmHeaderKeys += Key(header.olmIdentity)
                olmHeaderKeys += Key(header.baseKey)
                olmHeaderKeys += Key(header.fallbackKey)
                olmHeaderKeys += Key(header.ratchetKey)
            }
            is L1.Normal -> olmHeaderKeys += Key(header.ratchetKey)
            else -> Unit
        }
    }

    /**
     * The world's clock, read by the recorder when it stamps a first pair open. Set by the world.
     */
    var now: () -> Long = { 0L }

    companion object {
        fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Records what the engine asked of the DM crypto port and what it got back (§2.6 functions 2–5 and
 * 17): the own card and its namespaces, and every generation's published keys.
 */
internal class RecordingCrypto(
    private val inner: DmCrypto,
    private val client: Int,
    private val truth: GroundTruth,
) : DmCrypto by inner {

    override fun ownCard(cardIndex: Int): DmSessions.OwnCard? {
        val card = inner.ownCard(cardIndex) ?: return null
        val record = truth.client(client)
        record.card = card.card
        record.identityPk = card.card.copyOfRange(3, 35)
        record.olmIdentity = card.olmIdentity
        record.inboxNamespace = card.inboxNamespace
        record.bundleNamespace = card.bundleNamespace
        truth.bundleOwners[GroundTruth.hex(card.bundleNamespace)] = card.card.copyOfRange(3, 35)
        return card
    }

    override fun bundleCreate(
        cardIndex: Int,
        bundleWeek: Long,
        bundleRank: Int,
        genId: Int,
    ): DmSessions.BundleGeneration? {
        val generation = inner.bundleCreate(cardIndex, bundleWeek, bundleRank, genId) ?: return null
        truth.bundleKeys += GroundTruth.Key(generation.fallbackPublic)
        truth.bundleKeys += GroundTruth.Key(generation.xwingPublic.copyOf(32))
        truth.bundleBlobs += GroundTruth.Key(GroundTruth.sha256(generation.blob))
        truth.generations += client to genId
        return generation
    }

    override fun toString(): String = "RecordingCrypto($inner)"
}

/**
 * Records what the engine asked of the envelope port: the body length behind every L0, the L1 an
 * L0 became, the blob an L1 was sealed into, every Olm header, and every open's outcome.
 */
internal class RecordingEnvelopes(
    private val inner: DmEnvelopes,
    private val client: Int,
    private val truth: GroundTruth,
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
    ): DmContent.Encoded {
        val encoded = inner.encodeContent(
            kind, messageId, authorMinute, minuteIndex, timerCode, timerVersion, quoteRef, body,
            contactId, offerRootGen, offerEnv, revocation, sessionReset,
        )
        if (encoded is DmContent.Encoded.Ok) truth.recordL0(encoded.l0, body.size)
        return encoded
    }

    override fun encrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot,
        l0: ByteArray,
        today: Int,
    ): DmSessions.Encrypted {
        val encrypted = inner.encrypt(contactId, current, l0, today)
        if (encrypted is DmSessions.Encrypted.Ok) {
            truth.recordL1(l0, encrypted.l1)
            truth.recordHeader(inner.parseL1(encrypted.l1, encrypted.isPreKey))
        }
        return encrypted
    }

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
        truth.olmHeaderKeys += GroundTruth.Key(peerOlmIdentity)
        val sealed = inner.sealIntro(
            cardIndex, namespace, bucket, introKeyEnv, peerIdentityPk, peerOlmIdentity, genId,
            genPublic, bindingMinute, sessionId, replySeedEnv, l1,
        )
        truth.recordSeal(DmSeal.Mode.INTRO, l1, sealed, client)
        if (sealed is DmSeal.Sealed.Ok) truth.genOfBlob[GroundTruth.Key(GroundTruth.sha256(sealed.blob))] = genId
        return sealed
    }

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
        truth.recordSeal(DmSeal.Mode.PAIR, l1, sealed, client)
        if (sealed is DmSeal.Sealed.Ok) truth.weekOfBlob[GroundTruth.Key(GroundTruth.sha256(sealed.blob))] = week
        return sealed
    }

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
        truth.recordSeal(DmSeal.Mode.PROVISIONAL, l1, sealed, client)
        return sealed
    }

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
        val opened = inner.openPair(namespace, blob, openEnv, contactId, rootGen, week, oiSender, oiRecipient)
        when (opened) {
            is DmSeal.OuterSymmetric.Ok -> {
                truth.olmHeaderKeys += GroundTruth.Key(opened.ratchetKey)
                truth.firstPairOpen.putIfAbsent(client to GroundTruth.Key(contactId), truth.now())
            }
            DmSeal.OuterSymmetric.NotOpen, DmSeal.OuterSymmetric.NonCanonical ->
                truth.undecryptable += client to contactId.copyOf()
            else -> Unit
        }
        return opened
    }

    override fun openProvisional(
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmSeal.OuterSymmetric {
        val opened = inner.openProvisional(namespace, blob, openEnv, direction, sessionId, oiSender, oiRecipient)
        when (opened) {
            is DmSeal.OuterSymmetric.Ok -> truth.olmHeaderKeys += GroundTruth.Key(opened.ratchetKey)
            DmSeal.OuterSymmetric.NotOpen, DmSeal.OuterSymmetric.NonCanonical ->
                truth.undecryptableSessions += client to sessionId.copyOf()
            else -> Unit
        }
        return opened
    }

    override fun openIntro(
        cardIndex: Int,
        namespace: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        blob: ByteArray,
    ): DmSeal.OpenedIntro {
        val opened = inner.openIntro(cardIndex, namespace, genId, genSecretsEnv, genFallbackPublic, blob)
        if (opened is DmSeal.OpenedIntro.Ok) {
            truth.olmHeaderKeys += GroundTruth.Key(opened.intro.olmIdentity)
            truth.olmHeaderKeys += GroundTruth.Key(opened.intro.baseKey)
            truth.olmHeaderKeys += GroundTruth.Key(opened.intro.oneTimeKey)
            truth.olmHeaderKeys += GroundTruth.Key(opened.intro.ratchetKey)
        }
        return opened
    }

    override fun decrypt(
        contactId: ByteArray,
        current: DmSessions.StoredSlot?,
        previous: DmSessions.StoredSlot?,
        l1: ByteArray,
        isPreKey: Boolean,
        today: Int,
    ): DmSessions.Decrypted {
        val decrypted = inner.decrypt(contactId, current, previous, l1, isPreKey, today)
        if (decrypted is DmSessions.Decrypted.Ok) truth.decrypted += client to contactId.copyOf()
        return decrypted
    }

    override fun inbound(
        contactId: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        expectedPeerIdentity: ByteArray,
        l1: ByteArray,
        today: Int,
    ): DmSessions.Inbound {
        val made = inner.inbound(contactId, genId, genSecretsEnv, genFallbackPublic, expectedPeerIdentity, l1, today)
        if (made is DmSessions.Inbound.Ok) truth.decrypted += client to contactId.copyOf()
        return made
    }

    override fun toString(): String = "RecordingEnvelopes($inner)"
}
