package org.ghost.crypto.bridge

/**
 * The closed JNI surface of the DM cryptography (Phase 9 design `docs/design/faza9-dm.md` §2.6,
 * gate G-R6). **This is the only class in GHOST that declares a DM native method**, and
 * `:messaging` references no type of it: everything outside `:crypto-bridge` goes through the
 * typed facade ([DmSessions]).
 *
 * Every function is `static native`, takes byte arrays and ints, and returns **one** byte array
 * `code(1) || TLV fields`, which [DmResult] decodes. No function performs I/O, reads a clock,
 * logs, or keeps state between calls other than the context handle, and none throws: a Rust panic
 * is caught on the native side and comes back as [DmCode.INTERNAL], which the facade turns into
 * `IllegalStateException` (rollback, crash, poison guard).
 *
 * Time is always an argument (`today`, a day index): the native crate reads no clock, which is
 * what keeps T13 and T33 executable and what makes the host/Android equivalence fixture of §15.9
 * item 7 deterministic.
 *
 * **Loading** (§2.7, G-14). On a device the code is inside `libghost_client_net.so`, which already
 * loads lazily; JVM tests load the host build `ghost-dm-host` from the path in
 * `-Dghost.dm.native`. A missing or unloadable library is [DmCode.CRYPTO_UNAVAILABLE], never a
 * crash loop.
 *
 * **Visibility.** Every declaration is `internal`, like every other native declaration in GHOST
 * (`EntitlementCrypto`, `TorRelayTransport`, `TorIssuerTransport`): a module that depends on
 * `:crypto-bridge` reaches the ratchet through [DmSessions] or not at all, which is what makes the
 * typed facade the only place an unexpected code becomes an `IllegalStateException`. Kotlin
 * **mangles** an internal member's JVM name (`ctxClose` would become `ctxClose$crypto_bridge`, a
 * name no JNI symbol matches), so each one carries an explicit `@JvmName`; G-R6 checks both halves,
 * because dropping the annotation would be an `UnsatisfiedLinkError` on a device and nothing at
 * compile time.
 */
object DmNative {

    /** System property naming the host build, set by the `android` CI job (§2.7, §15.1). */
    const val HOST_LIBRARY_PROPERTY: String = "ghost.dm.native"

    /** Name of the shipped library the DM surface is exported from (§2.3). */
    const val ANDROID_LIBRARY: String = "ghost_client_net"

    @Volatile
    private var loadFailure: Throwable? = null

    private val loaded: Boolean by lazy {
        try {
            val hostPath = System.getProperty(HOST_LIBRARY_PROPERTY)
            if (hostPath.isNullOrEmpty()) {
                System.loadLibrary(ANDROID_LIBRARY)
            } else {
                System.load(hostPath)
            }
            true
        } catch (e: UnsatisfiedLinkError) {
            loadFailure = e
            false
        } catch (e: SecurityException) {
            loadFailure = e
            false
        }
    }

    /**
     * Whether the native library is available. The facade maps `false` to
     * [DmCode.CRYPTO_UNAVAILABLE] instead of letting an `UnsatisfiedLinkError` escape.
     */
    fun isAvailable(): Boolean = loaded

    /** Why the library did not load, for a diagnostic the caller may show; never logged here. */
    fun loadFailure(): Throwable? = loadFailure

    // §2.6 function 1.
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(
        messagingBranch: ByteArray,
        identitySeed: ByteArray,
        sessionStateKey: ByteArray,
    ): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?

    // §2.6 function 2.
    @JvmStatic
    @JvmName("ownCard")
    internal external fun ownCard(handle: Long, cardIndex: Int): ByteArray?

    // §2.6 function 4.
    @JvmStatic
    @JvmName("ownReadSecret")
    internal external fun ownReadSecret(handle: Long, cardIndex: Int, slot: Int): ByteArray?

    // §2.6 function 5.
    @JvmStatic
    @JvmName("bundleCreate")
    internal external fun bundleCreate(
        handle: Long,
        cardIndex: Int,
        bundleWeek: Long,
        bundleRank: Int,
        genId: Int,
    ): ByteArray?

    // §2.6 function 7.
    @JvmStatic
    @JvmName("sessionOutbound")
    internal external fun sessionOutbound(
        handle: Long,
        contactId: ByteArray,
        peerOlmIdentity: ByteArray,
        peerFallback: ByteArray,
        today: Int,
    ): ByteArray?

    // §2.6 function 8.
    @JvmStatic
    @JvmName("encrypt")
    internal external fun encrypt(
        handle: Long,
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        l0: ByteArray,
        today: Int,
    ): ByteArray?

    // §2.6 function 13. An absent slot is an empty session id and an empty envelope.
    @JvmStatic
    @JvmName("decrypt")
    internal external fun decrypt(
        handle: Long,
        contactId: ByteArray,
        currentSessionId: ByteArray,
        currentStateEnv: ByteArray,
        previousSessionId: ByteArray,
        previousStateEnv: ByteArray,
        l1: ByteArray,
        isPreKey: Int,
        today: Int,
    ): ByteArray?

    // §2.6 function 14.
    @JvmStatic
    @JvmName("sessionInbound")
    internal external fun sessionInbound(
        handle: Long,
        contactId: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        expectedPeerIdentity: ByteArray,
        l1: ByteArray,
        today: Int,
    ): ByteArray?

    // §2.6 function 17.
    @JvmStatic
    @JvmName("safetyNumber")
    internal external fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): ByteArray?

    // §2.6 function 19.
    @JvmStatic
    @JvmName("chainPosition")
    internal external fun chainPosition(
        handle: Long,
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        ratchetKey: ByteArray,
    ): ByteArray?

    // §2.6 function 20.
    @JvmStatic
    @JvmName("sessionPrune")
    internal external fun sessionPrune(
        handle: Long,
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        today: Int,
    ): ByteArray?

    // ------------------------------------------------------------------ slice S7

    // §2.6 function 3. Stateless: the parse of §3.3 needs no key material, and the own-card
    // refusal is a comparison Kotlin makes against what `ownCard` already returned.
    @JvmStatic
    @JvmName("cardParse")
    internal external fun cardParse(card: ByteArray): ByteArray?

    // §2.6 function 3.
    @JvmStatic
    @JvmName("cardDerive")
    internal external fun cardDerive(handle: Long, card: ByteArray, slot: Int): ByteArray?

    // §2.6 function 6.
    @JvmStatic
    @JvmName("bundleOpen")
    internal external fun bundleOpen(
        handle: Long,
        bundleKeyEnv: ByteArray,
        bundleNamespace: ByteArray,
        blob: ByteArray,
        expectedIdentityPk: ByteArray,
        expectedCardIndex: Int,
    ): ByteArray?

    // §2.6 function 9. `cardIndex` instead of the own card bytes, and no base key: both are read
    // where they cannot disagree with the signing seed or with the message (see the crate).
    @JvmStatic
    @JvmName("sealIntro")
    @Suppress("LongParameterList")
    internal external fun sealIntro(
        handle: Long,
        cardIndex: Int,
        namespace: ByteArray,
        bucket: Int,
        introKeyEnv: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlmIdentity: ByteArray,
        genId: Int,
        genPublic: ByteArray,
        bindingMinute: Int,
        sessionId: ByteArray,
        replySeedEnv: ByteArray,
        l1: ByteArray,
    ): ByteArray?

    // §2.6 function 10. The key binding is the one its mode fixes (§22.8.3): pair keys name the
    // contact, direction, root generation and week; provisional keys name the session and the
    // direction. The unused half is an empty array or a zero.
    @JvmStatic
    @JvmName("sealSym")
    @Suppress("LongParameterList")
    internal external fun sealSym(
        handle: Long,
        mode: Int,
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
    ): ByteArray?

    // §2.6 function 11.
    @JvmStatic
    @JvmName("openOuter")
    @Suppress("LongParameterList")
    internal external fun openOuter(
        handle: Long,
        mode: Int,
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
    ): ByteArray?

    // §2.6 function 12.
    @JvmStatic
    @JvmName("openIntro")
    @Suppress("LongParameterList")
    internal external fun openIntro(
        handle: Long,
        cardIndex: Int,
        namespace: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        blob: ByteArray,
    ): ByteArray?

    // §2.6 function 15.
    @JvmStatic
    @JvmName("pairKeys")
    @Suppress("LongParameterList")
    internal external fun pairKeys(
        handle: Long,
        contactId: ByteArray,
        direction: Int,
        rootGen: Int,
        fromKind: Int,
        keyEnv: ByteArray,
        baseWeek: Long,
        fromWeek: Long,
        toWeek: Long,
    ): ByteArray?

    // Function 22, added by S7: the random root a recipient offers (§6.3).
    @JvmStatic
    @JvmName("pairOffer")
    internal external fun pairOffer(
        handle: Long,
        contactId: ByteArray,
        rootGen: Int,
        baseWeek: Long,
    ): ByteArray?

    // Function 21, added by S7: the two provisional keys of one session (§6.7).
    @JvmStatic
    @JvmName("provisionalKeys")
    internal external fun provisionalKeys(
        handle: Long,
        contactId: ByteArray,
        sessionId: ByteArray,
        stateEnv: ByteArray,
        replySeedEnv: ByteArray,
        peerOlmIdentity: ByteArray,
    ): ByteArray?

    // §2.6 function 18.
    @JvmStatic
    @JvmName("l0Encode")
    @Suppress("LongParameterList")
    internal external fun l0Encode(
        handle: Long,
        kind: Int,
        messageId: ByteArray,
        authorMinute: Int,
        minuteIndex: Int,
        timerCode: Int,
        timerVersion: Int,
        quoteRef: ByteArray,
        body: ByteArray,
        contactId: ByteArray,
        rootGen: Int,
        offerEnv: ByteArray,
        revocation: ByteArray,
        sessionReset: Int,
    ): ByteArray?

    // §2.6 function 18.
    @JvmStatic
    @JvmName("l0Decode")
    internal external fun l0Decode(handle: Long, contactId: ByteArray, l0: ByteArray): ByteArray?
}
