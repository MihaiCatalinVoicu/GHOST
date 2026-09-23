package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The S7 half of the surface against the **real** native library (Phase 9 design §15.1): cards,
 * bundles, the four seal modes, pair and provisional keys, and the L0 codec.
 *
 * It walks the one-scan flow of §12.2 end to end between two contexts in one process —
 * A scans B's card, fetches and verifies B's bundle, seals an intro envelope, B opens it and
 * answers in provisional mode, both offer roots and both switch to pair mode — because that is
 * the flow every later slice rests on and the one place a wrong wrap binding, a wrong direction
 * byte or a wrong transcript input shows up as "the peer cannot open it" rather than as a
 * compile error.
 *
 * Skipped without `-Dghost.dm.native`, like [DmSessionsNativeTest]; once the property is set, a
 * library that does not load is a failure of the job, not a skip.
 */
class DmEnvelopeNativeTest {

    private val cardIndex = 0
    private val slot = 7
    private val today = 100
    private val bundleWeek = 2_870L
    private val bucket = 4096

    private fun requireNative() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        assertTrue(
            "the host library must load from $path: ${DmNative.loadFailure()}",
            DmNative.isAvailable(),
        )
    }

    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    private fun context(branch: Int): Long {
        val handle = DmSessions.openContext(
            messagingBranch = bytes(branch, 32),
            identitySeed = bytes(branch + 1, 32),
            sessionStateKey = bytes(branch + 2, 32),
        )
        assertNotNull("ctxOpen", handle)
        return handle!!
    }

    private fun ownCard(handle: Long): DmSessions.OwnCard =
        requireNotNull(DmSessions.ownCard(handle, cardIndex)) { "ownCard" }

    private fun derived(handle: Long, card: ByteArray): DmCards.Derived {
        val result = DmCards.derive(handle, card, slot)
        assertTrue("cardDerive: $result", result is DmCards.DeriveResult.Ok)
        return (result as DmCards.DeriveResult.Ok).values
    }

    private fun blob(sealed: DmSeal.Sealed): ByteArray {
        assertTrue("seal: $sealed", sealed is DmSeal.Sealed.Ok)
        return (sealed as DmSeal.Sealed.Ok).blob
    }

    // ---------------------------------------------------------------- cards

    /**
     * §3.3: a card parses into the two fields a contact row is keyed by, and a card that is not
     * one is refused rather than half-accepted. The own-card refusal is a comparison the caller
     * makes, so it is asserted here as the comparison it is.
     */
    @Test
    fun aCardParsesAndAMalformedOneIsRefused() {
        requireNative()
        val alice = context(0x41)
        try {
            val card = ownCard(alice).card
            assertEquals(131, card.size)
            val parsed = DmCards.parse(card)
            assertTrue("parse: $parsed", parsed is DmCards.ParseResult.Ok)
            assertEquals(cardIndex, (parsed as DmCards.ParseResult.Ok).card.cardIndex)

            // Every single-byte mutation of a card is refused by the crate's own test; here the
            // point is that the facade turns the refusal into an outcome and not an exception.
            val flipped = card.copyOf()
            flipped[40] = (flipped[40].toInt() xor 0x01).toByte()
            assertEquals(DmCards.ParseResult.InvalidCard, DmCards.parse(flipped))
            assertEquals(DmCards.ParseResult.InvalidCard, DmCards.parse(ByteArray(0)))
            assertEquals(
                DmCards.DeriveResult.InvalidCard,
                DmCards.derive(alice, flipped, slot),
            )
        } finally {
            DmSessions.closeContext(alice)
        }
    }

    /**
     * §3.2, P-2: two devices holding the same card derive the **same** namespaces and the same
     * bearer secrets, so every depositor of an inbox presents one credential and one scope. The
     * two opening keys come back wrapped, never in clear (rule R-S6).
     */
    @Test
    fun everyHolderOfOneCardDerivesTheSameValues() {
        requireNative()
        val owner = context(0x41)
        val holderA = context(0x51)
        val holderB = context(0x61)
        try {
            val card = ownCard(owner).card
            val a = derived(holderA, card)
            val b = derived(holderB, card)
            assertArrayEquals(a.inboxNamespace, b.inboxNamespace)
            assertArrayEquals(a.bundleNamespace, b.bundleNamespace)
            assertArrayEquals(a.deposit, b.deposit)
            assertArrayEquals(a.fetch, b.fetch)
            assertArrayEquals(a.recognitionIntro, b.recognitionIntro)
            assertArrayEquals(a.recognitionBundle, b.recognitionBundle)

            // The card's own namespaces are the owner's own (§5.1): what `ownCard` returns.
            val own = ownCard(owner)
            assertArrayEquals(own.inboxNamespace, a.inboxNamespace)
            assertArrayEquals(own.bundleNamespace, a.bundleNamespace)
            assertArrayEquals(own.recognitionIntro, a.recognitionIntro)
            assertArrayEquals(own.recognitionBundle, a.recognitionBundle)

            // A different slot is a different bearer secret and the same namespaces (§21.2).
            val otherSlot = DmCards.derive(holderA, card, slot + 1)
            assertTrue(otherSlot is DmCards.DeriveResult.Ok)
            val other = (otherSlot as DmCards.DeriveResult.Ok).values
            assertArrayEquals(a.inboxNamespace, other.inboxNamespace)
            assertFalse(a.deposit.contentEquals(other.deposit))
            assertFalse(a.fetch.contentEquals(other.fetch))

            // The opening keys are envelopes, not keys: 32 bytes of key plus 28 of overhead.
            assertEquals(60, a.introKeyEnv.size)
            assertEquals(60, a.bundleKeyEnv.size)
            // And they are **the holder's** envelopes: another context cannot open them.
            val bundle = requireNotNull(
                DmSessions.bundleCreate(owner, cardIndex, bundleWeek, 0, 0x11_22_33_44),
            ) { "bundleCreate" }
            assertEquals(
                DmBundles.OpenResult.StateCorrupt,
                DmBundles.open(
                    handle = holderB,
                    bundleKeyEnv = a.bundleKeyEnv,
                    bundleNamespace = a.bundleNamespace,
                    blob = bundle.blob,
                    expectedIdentityPk = DmCards.parseOrThrow(card).identityPk,
                    expectedCardIndex = cardIndex,
                ),
            )
        } finally {
            DmSessions.closeContext(owner)
            DmSessions.closeContext(holderA)
            DmSessions.closeContext(holderB)
        }
    }

    // --------------------------------------------------------------- bundles

    /**
     * §5.5: a card holder opens the owner's bundle, and every check that needs no clock holds —
     * the namespace, the card index, the identity key and the signature. A blob of another card,
     * a truncated one and a flipped byte are each a typed refusal.
     */
    @Test
    fun aBundleOpensForACardHolderAndIsRefusedOtherwise() {
        requireNative()
        val owner = context(0x41)
        val holder = context(0x51)
        val stranger = context(0x71)
        try {
            val card = ownCard(owner).card
            val identityPk = DmCards.parseOrThrow(card).identityPk
            val keys = derived(holder, card)
            val generation = requireNotNull(
                DmSessions.bundleCreate(owner, cardIndex, bundleWeek, 3, 0x0a_0b_0c_0d),
            ) { "bundleCreate" }
            assertEquals(4096, generation.blob.size)

            val opened = DmBundles.open(
                handle = holder,
                bundleKeyEnv = keys.bundleKeyEnv,
                bundleNamespace = keys.bundleNamespace,
                blob = generation.blob,
                expectedIdentityPk = identityPk,
                expectedCardIndex = cardIndex,
            )
            assertTrue("bundleOpen: $opened", opened is DmBundles.OpenResult.Ok)
            val verified = (opened as DmBundles.OpenResult.Ok).bundle
            assertEquals(bundleWeek, verified.bundleWeek)
            assertEquals(3, verified.bundleRank)
            assertEquals(0x0a_0b_0c_0d, verified.genId)
            assertArrayEquals(ownCard(owner).olmIdentity, verified.olmIdentity)
            assertArrayEquals(generation.fallbackPublic, verified.fallbackKey)
            assertArrayEquals(generation.xwingPublic, verified.xwingPublic)
            assertEquals(1216, verified.xwingPublic.size)

            // A stranger's card opens nothing: the seal key is card-derived (§5.3, P-1).
            val strangerKeys = derived(holder, ownCard(stranger).card)
            assertEquals(
                DmBundles.OpenResult.NotOpen,
                DmBundles.open(
                    holder,
                    strangerKeys.bundleKeyEnv,
                    strangerKeys.bundleNamespace,
                    generation.blob,
                    DmCards.parseOrThrow(ownCard(stranger).card).identityPk,
                    cardIndex,
                ),
            )
            // A flipped ciphertext byte does not open; a truncated blob is not a bucket.
            val flipped = generation.blob.copyOf()
            flipped[100] = (flipped[100].toInt() xor 0x01).toByte()
            assertEquals(
                DmBundles.OpenResult.NotOpen,
                DmBundles.open(
                    holder, keys.bundleKeyEnv, keys.bundleNamespace, flipped, identityPk, cardIndex,
                ),
            )
            assertEquals(
                DmBundles.OpenResult.NotOpen,
                DmBundles.open(
                    handle = holder,
                    bundleKeyEnv = keys.bundleKeyEnv,
                    bundleNamespace = keys.bundleNamespace,
                    blob = generation.blob.copyOf(2048),
                    expectedIdentityPk = identityPk,
                    expectedCardIndex = cardIndex,
                ),
            )
            // The right key envelope with the **wrong** expected identity does not even reach
            // the signature: the transient `KB_c` envelope is bound to the card's `identity_pk`
            // (§22.8.3), so it cannot be re-pointed at another identity, and that is the stronger
            // of the two refusals. `BAD_SIGNATURE` is what a card holder forging a bundle under
            // the shared `KB_c` would get, which the crate's own `one_signature_binds_every_field`
            // covers — it needs a sealer that is not `bundleCreate`, which the closed surface has
            // no export for.
            assertEquals(
                DmBundles.OpenResult.StateCorrupt,
                DmBundles.open(
                    holder, keys.bundleKeyEnv, keys.bundleNamespace, generation.blob,
                    DmCards.parseOrThrow(ownCard(stranger).card).identityPk, cardIndex,
                ),
            )
        } finally {
            DmSessions.closeContext(owner)
            DmSessions.closeContext(holder)
            DmSessions.closeContext(stranger)
        }
    }

    // -------------------------------------------------------- the one-scan flow

    /**
     * §12.2 end to end: A's intro envelope, B's provisional reply, and pair mode in both
     * directions once the roots are acknowledged. Every envelope is opened by the side that is
     * supposed to open it, and by nobody else.
     */
    @Test
    @Suppress("LongMethod")
    fun theOneScanFlowRunsThroughIntroProvisionalAndPairModes() {
        requireNative()
        val alice = context(0x41)
        val bob = context(0x51)
        try {
            val aliceCard = ownCard(alice)
            val bobCard = ownCard(bob)
            val aliceOi = aliceCard.olmIdentity
            val bobOi = bobCard.olmIdentity
            val aliceId = DmCards.parseOrThrow(aliceCard.card).identityPk
            val bobId = DmCards.parseOrThrow(bobCard.card).identityPk
            // Local contact ids; §8.1: Olm receives no address, only this random 16-byte key.
            val bobAtAlice = bytes(0x31, 16)
            val aliceAtBob = bytes(0x32, 16)

            // 1. A scans B's card and derives everything it needs to reach B.
            val bobKeys = derived(alice, bobCard.card)
            val aliceKeys = derived(bob, aliceCard.card)

            // 2. A fetches and verifies B's bundle (§5.5).
            val generation = requireNotNull(
                DmSessions.bundleCreate(bob, cardIndex, bundleWeek, 0, 0x71_72_73_74),
            ) { "bundleCreate" }
            val verified = DmBundles.open(
                alice, bobKeys.bundleKeyEnv, bobKeys.bundleNamespace, generation.blob, bobId,
                cardIndex,
            )
            assertTrue("bundleOpen: $verified", verified is DmBundles.OpenResult.Ok)
            val bundle = (verified as DmBundles.OpenResult.Ok).bundle

            // 3. `EST-READY`: A builds the initiator session and seals the first flight in intro
            //    mode (§6.4). The first message carries no root: it is a PreKey message (§21.3).
            val outbound = DmSessions.outbound(
                alice, bobAtAlice, bundle.olmIdentity, bundle.fallbackKey, today,
            )
            assertTrue("outbound: $outbound", outbound is DmSessions.Outbound.Ok)
            outbound as DmSessions.Outbound.Ok
            val firstL0 = encode(alice, "first flight")
            val first = DmSessions.encrypt(
                alice, bobAtAlice,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv), firstL0, today,
            )
            assertTrue("encrypt: $first", first is DmSessions.Encrypted.Ok)
            first as DmSessions.Encrypted.Ok
            assertTrue(first.isPreKey)

            val introBlob = blob(
                DmSeal.sealIntro(
                    handle = alice,
                    cardIndex = cardIndex,
                    namespace = bobKeys.inboxNamespace,
                    bucket = bucket,
                    introKeyEnv = bobKeys.introKeyEnv,
                    peerIdentityPk = bobId,
                    peerOlmIdentity = bundle.olmIdentity,
                    genId = bundle.genId,
                    genPublic = bundle.xwingPublic,
                    bindingMinute = 29_000_000L,
                    sessionId = outbound.sessionId,
                    replySeedEnv = outbound.replySeedEnv,
                    l1 = first.l1,
                ),
            )
            assertEquals(bucket, introBlob.size)

            // 4. B recognises the envelope by its own `KIO` hint and nothing else (rule R-S5).
            assertTrue(Recognition.matches(introBlob, bobCard.recognitionIntro))
            assertFalse(Recognition.matches(introBlob, aliceCard.recognitionIntro))
            assertFalse(Recognition.matches(introBlob, bobCard.recognitionBundle))

            val outer = DmSeal.openOuterIntro(bob, cardIndex, bobKeys.inboxNamespace, introBlob)
            assertTrue("openOuter: $outer", outer is DmSeal.OuterIntro.Ok)
            assertEquals(bundle.genId, (outer as DmSeal.OuterIntro.Ok).genId)

            val opened = DmSeal.openIntro(
                handle = bob,
                cardIndex = cardIndex,
                namespace = bobKeys.inboxNamespace,
                genId = 0x71_72_73_74,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                blob = introBlob,
            )
            assertTrue("openIntro: $opened", opened is DmSeal.OpenedIntro.Ok)
            val intro = (opened as DmSeal.OpenedIntro.Ok).intro
            assertArrayEquals(aliceCard.card, intro.senderCard)
            assertEquals(29_000_000L, intro.bindingMinute)
            assertArrayEquals(aliceOi, intro.olmIdentity)
            assertArrayEquals(generation.fallbackPublic, intro.oneTimeKey)
            assertArrayEquals(outbound.sessionId, intro.sessionId)

            // A's own card cannot open an envelope addressed to B, whatever it is given.
            assertEquals(
                DmSeal.OuterIntro.NotOpen,
                DmSeal.openOuterIntro(alice, cardIndex, bobKeys.inboxNamespace, introBlob),
            )

            // 5. B creates the responder session from the first flight.
            val inbound = DmSessions.inbound(
                bob, aliceAtBob, 0x71_72_73_74, generation.secretsEnv,
                generation.fallbackPublic, aliceOi, intro.l1, today,
            )
            assertTrue("inbound: $inbound", inbound is DmSessions.Inbound.Ok)
            inbound as DmSessions.Inbound.Ok
            assertArrayEquals(firstL0, inbound.plaintext)

            // 6. B answers in **provisional** mode (§6.7): a normal message, no bundle fetch, and
            //    B's own root rides inside it.
            val bobOffer = offer(bob, aliceAtBob, rootGen = 0, baseWeek = bundleWeek)
            val replyL0 = encode(
                bob, "reply", contactId = aliceAtBob, offerRootGen = 0,
                offerEnv = bobOffer.offerEnv,
            )
            val reply = DmSessions.encrypt(
                bob, aliceAtBob,
                DmSessions.StoredSlot(inbound.sessionId, inbound.stateEnv), replyL0, today,
            )
            assertTrue("reply: $reply", reply is DmSessions.Encrypted.Ok)
            reply as DmSessions.Encrypted.Ok
            assertFalse("a responder's reply is a normal message", reply.isPreKey)

            val bobProvisional = provisional(
                bob, aliceAtBob, inbound.sessionId, inbound.stateEnv, intro.replySeedEnv, aliceOi,
            )
            val provisionalBlob = blob(
                DmSeal.sealProvisional(
                    handle = bob,
                    namespace = aliceKeys.inboxNamespace,
                    bucket = bucket,
                    openEnv = bobProvisional.outEnv,
                    direction = bobProvisional.outDirection,
                    sessionId = inbound.sessionId,
                    oiSender = bobOi,
                    oiRecipient = aliceOi,
                    l1 = reply.l1,
                ),
            )

            // 7. A recognises it by the incoming provisional key of the same session.
            val aliceProvisional = provisional(
                alice, bobAtAlice, outbound.sessionId, first.stateEnv, outbound.replySeedEnv, bobOi,
            )
            assertArrayEquals(
                "each side seals with the key the other opens with",
                bobProvisional.recognitionOut,
                aliceProvisional.recognitionIn,
            )
            assertTrue(Recognition.matches(provisionalBlob, aliceProvisional.recognitionIn))
            assertFalse(Recognition.matches(provisionalBlob, aliceProvisional.recognitionOut))

            val openedReply = DmSeal.openProvisional(
                handle = alice,
                namespace = aliceKeys.inboxNamespace,
                blob = provisionalBlob,
                openEnv = aliceProvisional.inEnv,
                direction = aliceProvisional.inDirection,
                sessionId = outbound.sessionId,
                oiSender = bobOi,
                oiRecipient = aliceOi,
            )
            assertTrue("openProvisional: $openedReply", openedReply is DmSeal.OuterSymmetric.Ok)
            openedReply as DmSeal.OuterSymmetric.Ok
            assertArrayEquals(reply.l1, openedReply.l1)

            val read = DmSessions.decrypt(
                alice, bobAtAlice,
                DmSessions.StoredSlot(outbound.sessionId, first.stateEnv), null,
                openedReply.l1, isPreKey = false, today = today,
            )
            assertTrue("decrypt: $read", read is DmSessions.Decrypted.Ok)
            read as DmSessions.Decrypted.Ok
            assertTrue("the session is acknowledged now", read.acknowledged)

            // 8. A reads B's root out of the reply and turns it into its **out** pair key.
            val decoded = DmContent.decode(alice, bobAtAlice, read.plaintext)
            assertTrue("decode: $decoded", decoded is DmContent.DecodeResult.Ok)
            val content = (decoded as DmContent.DecodeResult.Ok).content
            assertArrayEquals("reply".toByteArray(), content.body)
            val root = requireNotNull(content.sealRoot) { "the reply carries B's root" }
            assertEquals(0, root.rootGen)
            assertEquals(bundleWeek, root.baseWeek)

            val outKeys = DmPairing.keys(
                alice, bobAtAlice, DmSeal.PairDirection.OUT, root.rootGen, DmPairing.From.ROOT, root.rootEnv,
                root.baseWeek, bundleWeek, bundleWeek,
            )
            assertTrue("pairKeys: $outKeys", outKeys is DmPairing.KeysResult.Ok)
            val outKey = (outKeys as DmPairing.KeysResult.Ok).weeks.single()
            assertEquals(bundleWeek, outKey.week)

            // B holds the same generation's **in** key from its own offer.
            val inKeys = DmPairing.keys(
                bob, aliceAtBob, DmSeal.PairDirection.IN, 0, DmPairing.From.ROOT, bobOffer.rootEnv, bundleWeek,
                bundleWeek, bundleWeek,
            )
            assertTrue("pairKeys: $inKeys", inKeys is DmPairing.KeysResult.Ok)
            val inKey = (inKeys as DmPairing.KeysResult.Ok).weeks.single()
            assertArrayEquals(
                "the two sides ratchet one root to one week key",
                outKey.recognitionKey,
                inKey.recognitionKey,
            )

            // 9. A's next message is **pair**-sealed under B's root.
            val secondL0 = encode(alice, "pair mode")
            val second = DmSessions.encrypt(
                alice, bobAtAlice,
                DmSessions.StoredSlot(outbound.sessionId, read.stateEnv), secondL0, today,
            )
            assertTrue(second is DmSessions.Encrypted.Ok)
            second as DmSessions.Encrypted.Ok
            val pairBlob = blob(
                DmSeal.sealPair(
                    handle = alice,
                    namespace = bobKeys.inboxNamespace,
                    bucket = bucket,
                    openEnv = outKey.openEnv,
                    contactId = bobAtAlice,
                    rootGen = 0,
                    week = bundleWeek,
                    oiSender = aliceOi,
                    oiRecipient = bobOi,
                    l1 = second.l1,
                ),
            )
            assertTrue(Recognition.matches(pairBlob, inKey.recognitionKey))
            val openedPair = DmSeal.openPair(
                handle = bob,
                namespace = bobKeys.inboxNamespace,
                blob = pairBlob,
                openEnv = inKey.openEnv,
                contactId = aliceAtBob,
                rootGen = 0,
                week = bundleWeek,
                oiSender = aliceOi,
                oiRecipient = bobOi,
            )
            assertTrue("openPair: $openedPair", openedPair is DmSeal.OuterSymmetric.Ok)
            openedPair as DmSeal.OuterSymmetric.Ok
            assertArrayEquals(second.l1, openedPair.l1)
            assertEquals(32, openedPair.ratchetKey.size)

            val settled = DmSessions.decrypt(
                bob, aliceAtBob,
                DmSessions.StoredSlot(inbound.sessionId, reply.stateEnv), null,
                openedPair.l1, isPreKey = false, today = today,
            )
            assertTrue("decrypt: $settled", settled is DmSessions.Decrypted.Ok)
            assertArrayEquals(secondL0, (settled as DmSessions.Decrypted.Ok).plaintext)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    /**
     * §6.3: a week key is reachable only by ratcheting forward from the base week, and the
     * window a caller asks for is the window it gets — so `dm_pair_key` rows of a FRESH window
     * (§6.3 "the recipient keeps `K_w` for every week `w` with `now < start(w + 1) + FRESH`")
     * can be rebuilt in one call after a sweep ratcheted forward.
     */
    @Test
    fun pairKeysRatchetForwardAndCoverExactlyTheWindowAsked() {
        requireNative()
        val device = context(0x41)
        try {
            val contact = bytes(0x33, 16)
            val offer = offer(device, contact, rootGen = 4, baseWeek = 2_900L)
            val window = DmPairing.keys(
                device, contact, DmSeal.PairDirection.IN, 4, DmPairing.From.ROOT, offer.rootEnv, 2_900L, 2_900L, 2_908L,
            )
            assertTrue("pairKeys: $window", window is DmPairing.KeysResult.Ok)
            val weeks = (window as DmPairing.KeysResult.Ok).weeks
            assertEquals(9, weeks.size)
            assertEquals((2_900L..2_908L).toList(), weeks.map { it.week })
            assertEquals(9, weeks.map { it.recognitionKey.toList() }.toSet().size)
            for (key in weeks) {
                assertEquals(60, key.openEnv.size)
                assertEquals(32, key.recognitionKey.size)
            }
            // A later sub-window is the same keys: the ratchet is a function of the base week.
            val later = DmPairing.keys(
                device, contact, DmSeal.PairDirection.IN, 4, DmPairing.From.ROOT, offer.rootEnv, 2_900L, 2_905L, 2_906L,
            )
            assertTrue(later is DmPairing.KeysResult.Ok)
            assertArrayEquals(
                weeks[5].recognitionKey,
                (later as DmPairing.KeysResult.Ok).weeks.first().recognitionKey,
            )
            // A window that is not one, and one wider than the longest live one, are refused.
            assertEquals(
                DmPairing.KeysResult.NonCanonical,
                DmPairing.keys(
                    device, contact, DmSeal.PairDirection.IN, 4, DmPairing.From.ROOT, offer.rootEnv, 2_900L, 2_899L,
                    2_905L,
                ),
            )
            assertEquals(
                DmPairing.KeysResult.NonCanonical,
                DmPairing.keys(
                    device, contact, DmSeal.PairDirection.IN, 4, DmPairing.From.ROOT, offer.rootEnv, 2_900L, 2_900L,
                    2_999L,
                ),
            )
            // The root envelope is bound to its (contact, generation): another one is corrupt.
            assertEquals(
                DmPairing.KeysResult.StateCorrupt,
                DmPairing.keys(
                    device, contact, DmSeal.PairDirection.IN, 5, DmPairing.From.ROOT, offer.rootEnv, 2_900L, 2_900L,
                    2_900L,
                ),
            )
        } finally {
            DmSessions.closeContext(device)
        }
    }

    /**
     * §7.1: the L0 codec round-trips every field the engine stores, and a `seal_root` goes in
     * wrapped and comes out wrapped — Kotlin never holds the root.
     */
    @Test
    fun theContentCodecRoundTripsItsFieldsAndKeepsTheRootWrapped() {
        requireNative()
        val device = context(0x41)
        try {
            val contact = bytes(0x34, 16)
            val offer = offer(device, contact, rootGen = 2, baseWeek = 2_880L)
            val messageId = bytes(0x44, 16)
            val quote = bytes(0x45, 16)
            val encoded = DmContent.encode(
                handle = device,
                kind = DmContent.Kind.TEXT,
                messageId = messageId,
                authorMinute = 29_010_000L,
                minuteIndex = 3,
                timerCode = 4,
                timerVersion = 7,
                quoteRef = quote,
                body = "hello".toByteArray(),
                contactId = contact,
                offerRootGen = 2,
                offerEnv = offer.offerEnv,
            )
            assertTrue("encode: $encoded", encoded is DmContent.Encoded.Ok)
            val l0 = (encoded as DmContent.Encoded.Ok).l0
            assertEquals(bucket, encoded.bucket)

            val decoded = DmContent.decode(device, contact, l0)
            assertTrue("decode: $decoded", decoded is DmContent.DecodeResult.Ok)
            val content = (decoded as DmContent.DecodeResult.Ok).content
            assertEquals(DmContent.Kind.TEXT, content.kind)
            assertArrayEquals(messageId, content.messageId)
            assertEquals(29_010_000L, content.authorMinute)
            assertEquals(3, content.minuteIndex)
            assertEquals(4, content.timerCode)
            assertEquals(7L, content.timerVersion)
            assertArrayEquals(quote, content.quoteRef)
            assertArrayEquals("hello".toByteArray(), content.body)
            assertFalse(content.sessionReset)
            assertNull(content.revocation)
            assertFalse(content.pqIgnored)
            assertNull(content.sealRootPq)
            assertNull(content.pqKey)
            val root = requireNotNull(content.sealRoot)
            assertEquals(2, root.rootGen)
            assertEquals(2_880L, root.baseWeek)
            assertEquals(60, root.rootEnv.size)

            // The root that came back opens the same week keys the offer does: the TLV carried
            // the offered root and nothing else.
            val fromOffer = DmPairing.keys(
                device, contact, DmSeal.PairDirection.IN, 2, DmPairing.From.ROOT, offer.rootEnv, 2_880L, 2_880L, 2_880L,
            ) as DmPairing.KeysResult.Ok
            val fromTlv = DmPairing.keys(
                device, contact, DmSeal.PairDirection.OUT, 2, DmPairing.From.ROOT, root.rootEnv, 2_880L, 2_880L, 2_880L,
            ) as DmPairing.KeysResult.Ok
            assertArrayEquals(
                fromOffer.weeks.single().recognitionKey,
                fromTlv.weeks.single().recognitionKey,
            )

            // A control message with the reconnect notice, and one with no TLV at all.
            val control = DmContent.encode(
                handle = device,
                kind = DmContent.Kind.CONTROL,
                messageId = bytes(0x46, 16),
                authorMinute = 29_010_001L,
                minuteIndex = 0,
                timerCode = 4,
                timerVersion = 7,
                quoteRef = null,
                body = ByteArray(0),
                sessionReset = true,
            )
            assertTrue(control is DmContent.Encoded.Ok)
            val controlContent = (
                DmContent.decode(device, contact, (control as DmContent.Encoded.Ok).l0)
                    as DmContent.DecodeResult.Ok
                ).content
            assertEquals(DmContent.Kind.CONTROL, controlContent.kind)
            assertTrue(controlContent.sessionReset)
            assertNull(controlContent.sealRoot)
            assertNull(controlContent.quoteRef)

            // Garbage does not decode. A body over the API cap `MAX_BODY_BYTES = 61 440` is
            // `OVERSIZE`: R-B1 has no bucket for it, and that is decided from the body length
            // before the record is built. §13.2's `TOO_LARGE` is the engine's own guard at SEND
            // S2, which runs earlier still and is what a user sees.
            assertEquals(
                DmContent.DecodeResult.NonCanonical,
                DmContent.decode(device, contact, ByteArray(3)),
            )
            assertEquals(
                DmContent.Encoded.Oversize,
                DmContent.encode(
                    handle = device,
                    kind = DmContent.Kind.TEXT,
                    messageId = messageId,
                    authorMinute = 29_010_000L,
                    minuteIndex = 0,
                    timerCode = 0,
                    timerVersion = 0,
                    quoteRef = null,
                    body = ByteArray(70_000),
                ),
            )
            // A timer code outside 0..5 is refused too (§7.1).
            assertEquals(
                DmContent.Encoded.NonCanonical,
                DmContent.encode(
                    handle = device,
                    kind = DmContent.Kind.TEXT,
                    messageId = messageId,
                    authorMinute = 29_010_000L,
                    minuteIndex = 0,
                    timerCode = 9,
                    timerVersion = 0,
                    quoteRef = null,
                    body = "x".toByteArray(),
                ),
            )
        } finally {
            DmSessions.closeContext(device)
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun encode(
        handle: Long,
        text: String,
        contactId: ByteArray = DM_NO_CONTACT,
        offerRootGen: Int = 0,
        offerEnv: ByteArray = DM_NO_BYTES,
    ): ByteArray {
        val encoded = DmContent.encode(
            handle = handle,
            kind = DmContent.Kind.TEXT,
            messageId = bytes(text.length, 16),
            authorMinute = 29_000_001L,
            minuteIndex = 0,
            timerCode = 4,
            timerVersion = 0,
            quoteRef = null,
            body = text.toByteArray(),
            contactId = contactId,
            offerRootGen = offerRootGen,
            offerEnv = offerEnv,
        )
        assertTrue("encode: $encoded", encoded is DmContent.Encoded.Ok)
        return (encoded as DmContent.Encoded.Ok).l0
    }

    private fun offer(
        handle: Long,
        contactId: ByteArray,
        rootGen: Int,
        baseWeek: Long,
    ): DmPairing.Offer {
        val result = DmPairing.offer(handle, contactId, rootGen, baseWeek)
        assertTrue("pairOffer: $result", result is DmPairing.OfferResult.Ok)
        return (result as DmPairing.OfferResult.Ok).offer
    }

    private fun provisional(
        handle: Long,
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        replySeedEnv: ByteArray,
        peerOlmIdentity: ByteArray,
    ): DmPairing.Provisional {
        val result = DmPairing.provisional(
            handle, contactId, sessionId, stateEnv, replySeedEnv, peerOlmIdentity,
        )
        assertTrue("provisionalKeys: $result", result is DmPairing.ProvisionalResult.Ok)
        return (result as DmPairing.ProvisionalResult.Ok).keys
    }
}

/** `DmCards.parse` where a failure is a test bug rather than an outcome. */
internal fun DmCards.parseOrThrow(card: ByteArray): DmCards.Parsed =
    when (val result = DmCards.parse(card)) {
        is DmCards.ParseResult.Ok -> result.card
        else -> throw IllegalStateException("cardParse: $result")
    }
