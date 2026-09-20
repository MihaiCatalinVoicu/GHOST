package org.ghost.crypto.bridge

/**
 * The GHOST seal of Phase 9 design §6, as the typed facade exposes it (§2.6 functions 9–12).
 *
 * Four modes, one shape on the wire (`salt ‖ hint ‖ AEAD`, rule R-S1): **intro** for every PreKey
 * message, **provisional** for a session's normal messages before a pair root exists,
 * **pair** for answered conversations, and **bundle**, which [DmBundles] owns.
 *
 * **What this facade does not decide.** Which mode a send uses is §6.8's rule, which is
 * `:messaging`'s; which key opens an inbound blob is decided by [Recognition] before any AEAD is
 * attempted (rule R-S5: at most one attempt per blob, never trial decryption).
 */
object DmSeal {

    /** The mode byte of §6.2. */
    enum class Mode(val wire: Int) {
        /** Pair mode: the week key of `week(author_minute)` (§6.3). */
        PAIR(0x01),

        /** Intro mode: the card-keyed outer layer and the X-Wing inner layer (§6.4). */
        INTRO(0x02),

        /** Provisional mode: `K_prov(dir)` from the session's `reply_seed` (§6.7). */
        PROVISIONAL(0x04),
    }

    /** Which pair-key row a `sealSym`/`openOuter` call names (`dm_pair_key.direction`). */
    enum class PairDirection(val wire: Int) {
        /** `in`: a key this device accepts envelopes under. */
        IN(0x01),

        /** `out`: the key this device seals with. */
        OUT(0x02),
    }

    /** The outcome of a seal call. */
    sealed interface Sealed {
        /** The blob, exactly one bucket. */
        data class Ok(val blob: ByteArray) : Sealed

        /**
         * The content does not fit the bucket the caller chose, or the caller named a bucket that
         * is not one of the three. R-B1 computes the bucket from the body length before
         * encryption and asserts the fit afterwards, so this is a **bug**, never a peer's doing
         * (§6.6): SEND rolls back and throws.
         */
        data object NoFit : Sealed

        /** A malformed argument: a key, a namespace or a message of the wrong shape. */
        data object NonCanonical : Sealed

        /** The contact's published key is malformed or non-contributory (§22.8.2). */
        data object InvalidKey : Sealed

        /** A stored envelope does not open under its binding (§22.8.3). */
        data object StateCorrupt : Sealed

        /** The card inside an intro envelope does not parse: the own card is malformed. */
        data object InvalidCard : Sealed

        /** The native library is missing or the context is closed. */
        data object Unavailable : Sealed
    }

    /** What the outer layer of an intro envelope shows: the generation it is addressed to. */
    sealed interface OuterIntro {
        /** The blob opened under this device's own `KIO_i`. */
        data class Ok(val genId: Int) : OuterIntro

        /** It does not open under that key: a forgery or another card's envelope. */
        data object NotOpen : OuterIntro

        /** It opened but does not parse exactly (rule R-S2). */
        data object NonCanonical : OuterIntro

        /** A stored envelope does not open under its binding. */
        data object StateCorrupt : OuterIntro

        /** The native library is missing or the context is closed. */
        data object Unavailable : OuterIntro
    }

    /** What a pair or provisional envelope shows once opened: the Olm message and its header. */
    sealed interface OuterSymmetric {
        /** The Olm normal message and the two header fields the peek order reads (§7.7). */
        data class Ok(
            /** The Olm message. */
            val l1: ByteArray,
            /** Its receiver-chain ratchet key. */
            val ratchetKey: ByteArray,
            /** Its index inside that chain. */
            val chainIndex: Long,
        ) : OuterSymmetric

        /** It does not open under the key the hint named: a forgery, counted (rule R-S5). */
        data object NotOpen : OuterSymmetric

        /**
         * It opened but does not parse exactly: a PreKey message inside a pair or provisional
         * envelope, non-zero padding, a bad length (rule R-S2, §6.5 step 5).
         */
        data object NonCanonical : OuterSymmetric

        /** A stored envelope does not open under its binding. */
        data object StateCorrupt : OuterSymmetric

        /** The native library is missing or the context is closed. */
        data object Unavailable : OuterSymmetric
    }

    /** The inner layer of an intro envelope, with everything §6.5 step 4 verified (§6.4). */
    class Intro(
        /** The sender's card v2, as it arrived; Kotlin parses it again at `RECV` R5. */
        val senderCard: ByteArray,
        /** The sealing minute binding v3 covers; freshness is the caller's R5 (§21.4 point 2). */
        val bindingMinute: Long,
        /** The **wrapped** `reply_seed`, for `olm_session.prov_env` (§6.7). */
        val replySeedEnv: ByteArray,
        /** The Olm PreKey message. */
        val l1: ByteArray,
        /** `PreKey.identity_key`, which binding v3 names as `OI_A` (§3.4). */
        val olmIdentity: ByteArray,
        /** `PreKey.base_key`, which binding v3 signs. */
        val baseKey: ByteArray,
        /** `PreKey.one_time_key`, already checked to be the generation's `F_g`. */
        val oneTimeKey: ByteArray,
        /** The raw session id, matched against the two stored slots (D2b, §7.6). */
        val sessionId: ByteArray,
        /** The inner ratchet key, for the peek order. */
        val ratchetKey: ByteArray,
        /** The inner chain index, for the gap hold (§7.7 point 2). */
        val chainIndex: Long,
    ) {
        override fun toString(): String = "Intro(redacted)"
    }

    /** The outcome of [openIntro]. */
    sealed interface OpenedIntro {
        /** The inner layer opened, binding v3 verified and §6.5 step 4 held. */
        data class Ok(val intro: Intro) : OpenedIntro

        /**
         * The outer layer, the KEM or the inner AEAD did not open, or the envelope names another
         * generation. Every decapsulation error lands here (§22.8.2 rule 4).
         */
        data object NotOpen : OpenedIntro

        /**
         * It opened but does not parse exactly, the message inside is not a PreKey message, or
         * one of §6.5 step 4's three equalities failed: `drop(non_canonical)`, no state change.
         */
        data object NonCanonical : OpenedIntro

        /** Binding v3 does not verify under the sender card's key: `drop(bad_binding)` (E-1). */
        data object BadSignature : OpenedIntro

        /** A key inside the first flight is non-contributory (§22.8.2 rule 1). */
        data object InvalidKey : OpenedIntro

        /** The generation's secrets do not open under their binding. */
        data object StateCorrupt : OpenedIntro

        /** The native library is missing or the context is closed. */
        data object Unavailable : OpenedIntro
    }

    /**
     * §2.6 function 9: intro mode (§6.4).
     *
     * [introKeyEnv] is the **peer's** wrapped `KIO_c` from [DmCards.derive]; [genId] and
     * [genPublic] are the generation this envelope is addressed to, from the peer's bundle;
     * [bindingMinute] is `floor_minute(now)` at sealing, not the compose minute (§21.4 point 1).
     */
    @Suppress("LongParameterList")
    fun sealIntro(
        handle: Long,
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
    ): Sealed {
        if (!DmNative.isAvailable()) return Sealed.Unavailable
        val result = dmCall {
            DmNative.sealIntro(
                handle,
                cardIndex,
                namespace,
                bucket,
                introKeyEnv,
                peerIdentityPk,
                peerOlmIdentity,
                genId,
                genPublic,
                Math.toIntExact(bindingMinute),
                sessionId,
                replySeedEnv,
                l1,
            )
        }
        return when (result.code) {
            DmCode.OK -> Sealed.Ok(result.bytes(DmField.BLOB))
            DmCode.NO_FIT -> Sealed.NoFit
            DmCode.NON_CANONICAL -> Sealed.NonCanonical
            DmCode.INVALID_KEY -> Sealed.InvalidKey
            DmCode.INVALID_CARD -> Sealed.InvalidCard
            DmCode.STATE_CORRUPT -> Sealed.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Sealed.Unavailable
            else -> unexpected(result.code, "sealIntro")
        }
    }

    /** §2.6 function 10 in pair mode: the week key of `week(author_minute)` (§6.3). */
    @Suppress("LongParameterList")
    fun sealPair(
        handle: Long,
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): Sealed = sealSym(
        handle,
        Mode.PAIR,
        namespace,
        bucket,
        openEnv,
        contactId,
        PairDirection.OUT.wire,
        rootGen,
        week,
        DM_NO_KEY,
        oiSender,
        oiRecipient,
        l1,
    )

    /**
     * §2.6 function 10 in provisional mode (§6.7). [openEnv] is the outgoing envelope
     * [DmPairing.provisional] returned, and [direction] the byte it named.
     */
    @Suppress("LongParameterList")
    fun sealProvisional(
        handle: Long,
        namespace: ByteArray,
        bucket: Int,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): Sealed = sealSym(
        handle,
        Mode.PROVISIONAL,
        namespace,
        bucket,
        openEnv,
        DM_NO_CONTACT,
        direction,
        0,
        0L,
        sessionId,
        oiSender,
        oiRecipient,
        l1,
    )

    @Suppress("LongParameterList")
    private fun sealSym(
        handle: Long,
        mode: Mode,
        namespace: ByteArray,
        bucket: Int,
        keyEnv: ByteArray,
        contactId: ByteArray,
        direction: Int,
        rootGen: Int,
        week: Long,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
        l1: ByteArray,
    ): Sealed {
        if (!DmNative.isAvailable()) return Sealed.Unavailable
        val result = dmCall {
            DmNative.sealSym(
                handle,
                mode.wire,
                namespace,
                bucket,
                keyEnv,
                contactId,
                direction,
                rootGen,
                week,
                sessionId,
                oiSender,
                oiRecipient,
                l1,
            )
        }
        return when (result.code) {
            DmCode.OK -> Sealed.Ok(result.bytes(DmField.BLOB))
            DmCode.NO_FIT -> Sealed.NoFit
            DmCode.NON_CANONICAL -> Sealed.NonCanonical
            DmCode.STATE_CORRUPT -> Sealed.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Sealed.Unavailable
            else -> unexpected(result.code, "sealSym")
        }
    }

    /** §2.6 function 11 in intro mode: the `gen_id` of an envelope addressed to this device. */
    fun openOuterIntro(
        handle: Long,
        cardIndex: Int,
        namespace: ByteArray,
        blob: ByteArray,
    ): OuterIntro {
        if (!DmNative.isAvailable()) return OuterIntro.Unavailable
        val result = openOuter(
            handle,
            Mode.INTRO,
            blob,
            namespace,
            cardIndex,
            DM_NO_BYTES,
            DM_NO_CONTACT,
            0,
            0,
            0L,
            DM_NO_KEY,
            DM_NO_KEY,
            DM_NO_KEY,
        )
        return when (result.code) {
            DmCode.OK -> OuterIntro.Ok(result.u32(DmField.GEN_ID).toInt())
            DmCode.NOT_OPEN -> OuterIntro.NotOpen
            DmCode.NON_CANONICAL -> OuterIntro.NonCanonical
            DmCode.STATE_CORRUPT -> OuterIntro.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> OuterIntro.Unavailable
            else -> unexpected(result.code, "openOuter")
        }
    }

    /** §2.6 function 11 in pair mode. */
    @Suppress("LongParameterList")
    fun openPair(
        handle: Long,
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        week: Long,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): OuterSymmetric = symmetric(
        openOuter(
            handle,
            Mode.PAIR,
            blob,
            namespace,
            0,
            openEnv,
            contactId,
            PairDirection.IN.wire,
            rootGen,
            week,
            DM_NO_KEY,
            oiSender,
            oiRecipient,
        ),
    )

    /** §2.6 function 11 in provisional mode. */
    @Suppress("LongParameterList")
    fun openProvisional(
        handle: Long,
        namespace: ByteArray,
        blob: ByteArray,
        openEnv: ByteArray,
        direction: Int,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): OuterSymmetric = symmetric(
        openOuter(
            handle,
            Mode.PROVISIONAL,
            blob,
            namespace,
            0,
            openEnv,
            DM_NO_CONTACT,
            direction,
            0,
            0L,
            sessionId,
            oiSender,
            oiRecipient,
        ),
    )

    private fun symmetric(result: DmResult): OuterSymmetric = when (result.code) {
        DmCode.OK -> OuterSymmetric.Ok(
            l1 = result.bytes(DmField.L1),
            ratchetKey = result.bytes(DmField.RATCHET_KEY),
            chainIndex = result.i64(DmField.CHAIN_INDEX),
        )
        DmCode.NOT_OPEN -> OuterSymmetric.NotOpen
        DmCode.NON_CANONICAL -> OuterSymmetric.NonCanonical
        DmCode.STATE_CORRUPT -> OuterSymmetric.StateCorrupt
        DmCode.CRYPTO_UNAVAILABLE -> OuterSymmetric.Unavailable
        else -> unexpected(result.code, "openOuter")
    }

    @Suppress("LongParameterList")
    private fun openOuter(
        handle: Long,
        mode: Mode,
        blob: ByteArray,
        namespace: ByteArray,
        cardIndex: Int,
        keyEnv: ByteArray,
        contactId: ByteArray,
        direction: Int,
        rootGen: Int,
        week: Long,
        sessionId: ByteArray,
        oiSender: ByteArray,
        oiRecipient: ByteArray,
    ): DmResult = if (!DmNative.isAvailable()) {
        DmResult.unavailable()
    } else {
        dmCall {
            DmNative.openOuter(
                handle,
                mode.wire,
                blob,
                namespace,
                cardIndex,
                keyEnv,
                contactId,
                direction,
                rootGen,
                week,
                sessionId,
                oiSender,
                oiRecipient,
            )
        }
    }

    /**
     * §2.6 function 12: the X-Wing-keyed inner layer (§6.4), with binding v3 verified and the
     * three equalities of §6.5 step 4 enforced.
     *
     * It takes the **whole blob**, not the outer layer's parts: the transcript `T_in` covers the
     * ciphertext and both recipient identities, so every one of them has to come from one
     * envelope, and shuttling them through Kotlin as opaque arrays would make a mismatched set a
     * caller's mistake instead of an impossibility.
     */
    @Suppress("LongParameterList")
    fun openIntro(
        handle: Long,
        cardIndex: Int,
        namespace: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        blob: ByteArray,
    ): OpenedIntro {
        if (!DmNative.isAvailable()) return OpenedIntro.Unavailable
        val result = dmCall {
            DmNative.openIntro(
                handle,
                cardIndex,
                namespace,
                genId,
                genSecretsEnv,
                genFallbackPublic,
                blob,
            )
        }
        return when (result.code) {
            DmCode.OK -> OpenedIntro.Ok(
                Intro(
                    senderCard = result.bytes(DmField.CARD),
                    bindingMinute = result.u32(DmField.BINDING_MINUTE),
                    replySeedEnv = result.bytes(DmField.REPLY_SEED),
                    l1 = result.bytes(DmField.L1),
                    olmIdentity = result.bytes(DmField.OLM_IDENTITY),
                    baseKey = result.bytes(DmField.BASE_KEY),
                    oneTimeKey = result.bytes(DmField.ONE_TIME_KEY),
                    sessionId = result.bytes(DmField.SESSION_ID),
                    ratchetKey = result.bytes(DmField.RATCHET_KEY),
                    chainIndex = result.i64(DmField.CHAIN_INDEX),
                ),
            )
            DmCode.NOT_OPEN -> OpenedIntro.NotOpen
            DmCode.NON_CANONICAL -> OpenedIntro.NonCanonical
            DmCode.BAD_SIGNATURE -> OpenedIntro.BadSignature
            DmCode.INVALID_KEY -> OpenedIntro.InvalidKey
            DmCode.STATE_CORRUPT -> OpenedIntro.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> OpenedIntro.Unavailable
            else -> unexpected(result.code, "openIntro")
        }
    }
}
