package org.ghost.crypto.bridge

/**
 * The closed JNI surface of the channel cryptography (Phase 10 design
 * `docs/design/faza10-forum.md` §10.2, gate G-M6; slice S2b). **This is the only class in GHOST
 * that declares a channel native method**, and nothing outside `:crypto-bridge` references it:
 * every caller goes through the typed facade [ChannelCrypto].
 *
 * Every function is `static native`, takes byte arrays, ints and longs, and returns **one** byte
 * array `code(1) || fields`, which [MlsReply] decodes. No function performs I/O, reads a clock
 * (a `day` or a minute is always an argument), logs, or keeps state between calls other than the
 * context handle and the channels opened on it; none throws: a Rust panic is caught on the native
 * side and comes back as [MlsCode.INTERNAL], which the facade turns into
 * `IllegalStateException`.
 *
 * Function 16 (`revealSeal`, `revealOpen`, the reveal of §6.9) is slice S9's: it is on the
 * native closed list as reserved and is **not** declared here, so a library that exported it
 * early would fail G-M6 rather than be called.
 *
 * **Loading.** On a device the code is inside `libghost_client_net.so`, the library the DM surface
 * and the network module load too; JVM tests load the host build `ghost-dm-host` from the path in
 * `-Dghost.dm.native` (the DM tests' property: one host library carries both surfaces). A missing
 * or unloadable library is [MlsCode.CRYPTO_UNAVAILABLE], never a crash loop.
 *
 * **Visibility.** Every declaration is `internal` with an explicit `@JvmName` (Kotlin mangles an
 * internal member's JVM name, which no JNI symbol matches); G-M6 checks both halves.
 */
object MlsNative {

    /** System property naming the host build (the DM surface's, §2.7 of Phase 9). */
    const val HOST_LIBRARY_PROPERTY: String = DmNative.HOST_LIBRARY_PROPERTY

    /** Name of the shipped library the channel surface is exported from (§10.1). */
    const val ANDROID_LIBRARY: String = DmNative.ANDROID_LIBRARY

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
     * [MlsCode.CRYPTO_UNAVAILABLE] instead of letting an `UnsatisfiedLinkError` escape.
     */
    fun isAvailable(): Boolean = loaded

    /** Why the library did not load, for a diagnostic the caller may show; never logged here. */
    fun loadFailure(): Throwable? = loadFailure

    // §10.2 function 1.
    @JvmStatic
    @JvmName("ctxOpen")
    internal external fun ctxOpen(stateKey: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("ctxClose")
    internal external fun ctxClose(handle: Long): ByteArray?

    // Function 2.
    @JvmStatic
    @JvmName("channelOpen")
    internal external fun channelOpen(
        handle: Long,
        channelId: ByteArray,
        pseudonymSeed: ByteArray,
    ): ByteArray?

    @JvmStatic
    @JvmName("channelClose")
    internal external fun channelClose(handle: Long, channelId: ByteArray): ByteArray?

    // Function 3: `policy` is a CONTEXT record (the TLS encoding of §5.3 stays native).
    @JvmStatic
    @JvmName("groupCreate")
    internal external fun groupCreate(
        handle: Long,
        channelId: ByteArray,
        policy: ByteArray,
        day: Int,
    ): ByteArray?

    // Function 4.
    @JvmStatic
    @JvmName("keyPackage")
    internal external fun keyPackage(
        handle: Long,
        channelId: ByteArray,
        purpose: Int,
        day: Int,
    ): ByteArray?

    // Function 5: `anchorKind` 1 (join, restore: the invite's committers digest) or 2 (rejoin: the
    // last committers, 32 bytes each).
    @JvmStatic
    @JvmName("welcomeJoin")
    internal external fun welcomeJoin(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        welcomeBlob: ByteArray,
        day: Int,
        expectedGeneration: Int,
        expectedNs: ByteArray,
        anchorKind: Int,
        anchor: ByteArray,
    ): ByteArray?

    // Function 6: `messages` is a list of MESSAGE fields, at most 32 (S0-17).
    @JvmStatic
    @JvmName("receive")
    internal external fun receive(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        epoch: Long,
        messages: ByteArray,
        day: Int,
    ): ByteArray?

    // Function 7: `winnerKind` 1 another member's commit, 2 the own pending commit.
    @JvmStatic
    @JvmName("settle")
    internal external fun settle(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        winnerKind: Int,
        winner: ByteArray,
        generation: Int,
        day: Int,
    ): ByteArray?

    // Function 8.
    @JvmStatic
    @JvmName("clearOwn")
    internal external fun clearOwn(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        day: Int,
    ): ByteArray?

    // Function 9: `request` is one record (adds, removes, swaps, context, rotate, minute, floor,
    // and the generation the Welcome bootstraps).
    @JvmStatic
    @JvmName("commit")
    internal external fun commit(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        request: ByteArray,
        day: Int,
    ): ByteArray?

    // Function 10: `content` is `contentEncode`'s output.
    @JvmStatic
    @JvmName("encrypt")
    internal external fun encrypt(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        content: ByteArray,
        seq: Int,
        day: Int,
    ): ByteArray?

    // Function 11: `keyClass` 1 (`K_ep`, mode 0x11), 3 (`JK_g`, modes 0x12 and 0x13) or 6 (an
    // invite's `JK_g`: it seals mode 0x12 and, in `open`, opens mode 0x13 only).
    @JvmStatic
    @JvmName("seal")
    internal external fun seal(
        handle: Long,
        channelId: ByteArray,
        keyEnv: ByteArray,
        keyClass: Int,
        ns: ByteArray,
        bucket: Int,
        mode: Int,
        orderEpoch: Long,
        orderLeaf: Int,
        orderSeq: Int,
        body: ByteArray,
    ): ByteArray?

    // Function 12.
    @JvmStatic
    @JvmName("open")
    internal external fun open(
        handle: Long,
        channelId: ByteArray,
        keyEnv: ByteArray,
        keyClass: Int,
        ns: ByteArray,
        mode: Int,
        blob: ByteArray,
    ): ByteArray?

    // Function 13: `slots` one byte per relay slot.
    @JvmStatic
    @JvmName("generation")
    internal external fun generation(
        handle: Long,
        channelId: ByteArray,
        gEnv: ByteArray,
        generation: Int,
        openEpoch: Long,
        slots: ByteArray,
    ): ByteArray?

    // Function 14: `password` is null for an open invite, else the NFKD UTF-8 bytes of what the
    // user typed (§19.29.3), zeroed by the facade after the call.
    @JvmStatic
    @JvmName("inviteBuild")
    internal external fun inviteBuild(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        gEnv: ByteArray,
        generation: Int,
        expiryDay: Int,
        kdfCode: Int,
        password: ByteArray?,
        carryName: Int,
        day: Int,
    ): ByteArray?

    @JvmStatic
    @JvmName("inviteParse")
    internal external fun inviteParse(
        handle: Long,
        invite: ByteArray,
        password: ByteArray?,
        slots: ByteArray,
    ): ByteArray?

    // Function 15.
    @JvmStatic
    @JvmName("joinRequest")
    internal external fun joinRequest(
        handle: Long,
        channelId: ByteArray,
        inviteId: ByteArray,
        inviteSeedEnv: ByteArray,
        keyPackage: ByteArray,
    ): ByteArray?

    @JvmStatic
    @JvmName("rejoinRequest")
    internal external fun rejoinRequest(
        handle: Long,
        channelId: ByteArray,
        generation: Int,
        day: Int,
        lastEpoch: Long,
        lastHash: ByteArray,
        keyPackage: ByteArray,
    ): ByteArray?

    // `invitePk` for a join or restore, `member` for a rejoin: empty when absent.
    @JvmStatic
    @JvmName("joinVerify")
    internal external fun joinVerify(
        handle: Long,
        channelId: ByteArray,
        body: ByteArray,
        invitePk: ByteArray,
        member: ByteArray,
        generation: Int,
    ): ByteArray?

    // Function 17.
    @JvmStatic
    @JvmName("contentEncode")
    internal external fun contentEncode(fields: ByteArray): ByteArray?

    @JvmStatic
    @JvmName("contentDecode")
    internal external fun contentDecode(content: ByteArray): ByteArray?

    // Function 18.
    @JvmStatic
    @JvmName("roster")
    internal external fun roster(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        day: Int,
    ): ByteArray?

    // Function 19.
    @JvmStatic
    @JvmName("sweepPast")
    internal external fun sweepPast(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        keepCount: Int,
        day: Int,
    ): ByteArray?

    // Function 20: `held` is a list of HELD records (namespace, blob), at most 32 (S0-17).
    @JvmStatic
    @JvmName("trialCount")
    internal external fun trialCount(
        handle: Long,
        channelId: ByteArray,
        rows: ByteArray,
        candidateKind: Int,
        candidate: ByteArray,
        held: ByteArray,
        day: Int,
    ): ByteArray?
}
