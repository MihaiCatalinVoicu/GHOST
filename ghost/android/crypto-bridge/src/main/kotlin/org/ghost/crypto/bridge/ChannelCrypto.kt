package org.ghost.crypto.bridge

/**
 * Calls the channel surface and decodes the reply: [MlsCode.CRYPTO_UNAVAILABLE] when the library is
 * not loadable, or disappeared between the check and the call (never an `Error` escaping into
 * `:messaging`, the DM facade's rule, Phase 9 §2.7).
 */
internal inline fun mlsCall(body: () -> ByteArray?): MlsReply {
    if (!MlsNative.isAvailable()) return MlsReply.unavailable()
    return try {
        MlsReply.decode(body())
    } catch (e: UnsatisfiedLinkError) {
        MlsReply.unavailable()
    }
}

/**
 * A code the surface cannot produce for this function: `INTERNAL` (a caught Rust panic) or a
 * disagreement between the facade and the library, which `MlsResultCodesTest` fails the build on.
 * The caller rolls back its transaction (§10.4).
 */
internal fun mlsUnexpected(code: MlsCode, function: String): Nothing =
    throw IllegalStateException("channel native $function returned ${code.name}")

/** A refused call: its code and, where the native side names one, the reason or the index. */
class MlsRefusal(
    /** The code. */
    val code: MlsCode,
    /** An `INVALID_COMMIT`'s reason. */
    val reason: MlsCommitReason?,
    /** An `INVALID_KEYPACKAGE` or `INVALID_EVIDENCE` index. */
    val index: Int?,
) {
    override fun toString(): String = "MlsRefusal($code${reason?.let { ", $it" } ?: ""}${index?.let { ", #$it" } ?: ""})"

    internal companion object {
        fun of(reply: MlsReply): MlsRefusal = MlsRefusal(reply.code, reply.reason, reply.index)
    }
}

/** The outcome of a facade call: a value, or a refusal with one of the function's codes. */
sealed class MlsOutcome<out T> {
    /** The call succeeded. */
    class Ok<out T>(
        /** Its value. */
        val value: T,
    ) : MlsOutcome<T>() {
        override fun toString(): String = "Ok($value)"
    }

    /** The call was refused with a code the function declares. */
    class Refused(
        /** The code and its detail. */
        val refusal: MlsRefusal,
    ) : MlsOutcome<Nothing>() {
        override fun toString(): String = "Refused($refusal)"
    }

    /** The value, or `null` when refused. */
    fun valueOrNull(): T? = (this as? Ok)?.value

    /** The refusal's code, or [MlsCode.OK]. */
    val code: MlsCode get() = (this as? Refused)?.refusal?.code ?: MlsCode.OK
}

private fun refused(reply: MlsReply): MlsOutcome.Refused = MlsOutcome.Refused(MlsRefusal.of(reply))

/** A typed password with an unpaired surrogate: no UTF-8 encoding, so no native call (`NON_CANONICAL`). */
private fun unencodablePassword(): MlsOutcome.Refused =
    MlsOutcome.Refused(MlsRefusal(MlsCode.NON_CANONICAL, null, null))

/**
 * The typed channel facade (Phase 10 design §10.1, §10.2; slice S2b): the only caller of
 * [MlsNative], one context handle per instance. Every method maps the native reply to an
 * [MlsOutcome] — each code the native function can return is an arm (the crate's `FUNCTION_CODES`,
 * which `MlsResultCodesTest` compares with these arms in both directions), and a code it cannot
 * return is [mlsUnexpected], which throws: that is `INTERNAL`, the one outcome the facade throws on.
 *
 * **Value semantics (§3.4).** Every call takes the channel's stored rows ([MlsRow]) and returns a
 * change-set ([MlsChange]); the caller applies it in the same transaction, and only on `Ok`.
 * Nothing is cached across calls. The `day` and minute arguments come from the trusted clock.
 *
 * **No protocol logic here (ADR-19).** The facade encodes arguments and decodes replies; parsing,
 * sealing, derivations and every MLS operation are native. The transactions of §10.4 that use it
 * are `:messaging`'s (slice S4).
 */
class ChannelCrypto private constructor(private val handle: Long) {

    /** `ctxClose`: zeroises the context and every channel opened on it (natively, in place). */
    fun close(): MlsOutcome<Unit> {
        val reply = mlsCall { MlsNative.ctxClose(handle) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(Unit)
            MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "ctxClose")
        }
    }

    /** `channelOpen`: `P`, which the caller compares with `:identity`'s value (fn 2). */
    fun openChannel(channelId: ByteArray, pseudonymSeed: ByteArray): MlsOutcome<ByteArray> {
        val reply = mlsCall { MlsNative.channelOpen(handle, channelId, pseudonymSeed) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(reply.fields.bytes(MlsField.PSEUDONYM))
            MlsCode.NON_CANONICAL, MlsCode.INVALID_KEY, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "channelOpen")
        }
    }

    /** `channelClose`. */
    fun closeChannel(channelId: ByteArray): MlsOutcome<Unit> {
        val reply = mlsCall { MlsNative.channelClose(handle, channelId) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(Unit)
            MlsCode.NON_CANONICAL, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "channelClose")
        }
    }

    /** What `groupCreate` returns (fn 3). */
    class Created(
        /** The change-set. */
        val changes: List<MlsChange>,
        /** Epoch 0's keys. */
        val epoch: EpochKeys,
        /** Generation 0. */
        val generation: GenerationValues,
        /** The creator's box key. */
        val boxPk: ByteArray,
        /** Its secret half, wrapped. */
        val boxEnv: ByteArray,
    ) {
        override fun toString(): String = "Created($epoch, $generation)"
    }

    /** `groupCreate` (fn 3, §6.1). */
    fun groupCreate(channelId: ByteArray, policy: ChannelPolicy, day: Int): MlsOutcome<Created> {
        val args = policy.toRecord()
        val reply = try {
            mlsCall { MlsNative.groupCreate(handle, channelId, args.toByteArray(), day) }
        } finally {
            args.erase()
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Created(
                        MlsChange.all(it),
                        EpochKeys.of(it),
                        GenerationValues.of(it),
                        it.bytes(MlsField.BOX_PK),
                        it.bytes(MlsField.BOX_ENV),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_POLICY, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "groupCreate")
        }
    }

    /** What `keyPackage` returns (fn 4). */
    class KeyPackageMade(
        /** The canonical KeyPackage (395 bytes). */
        val keyPackage: ByteArray,
        /** Its reference. */
        val kpRef: ByteArray,
        /** The global rows (its private keys). */
        val changes: List<MlsChange>,
        /** The fresh box key. */
        val boxPk: ByteArray,
        /** Its secret half, wrapped. */
        val boxEnv: ByteArray,
    ) {
        override fun toString(): String = "KeyPackageMade(${keyPackage.size} bytes)"
    }

    /** `keyPackage` (fn 4): [purpose] 1 join, 2 rejoin, 3 restore. */
    fun keyPackage(channelId: ByteArray, purpose: Int, day: Int): MlsOutcome<KeyPackageMade> {
        val reply = mlsCall { MlsNative.keyPackage(handle, channelId, purpose, day) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    KeyPackageMade(
                        it.bytes(MlsField.KEY_PACKAGE),
                        it.bytes(MlsField.KP_REF),
                        MlsChange.all(it),
                        it.bytes(MlsField.BOX_PK),
                        it.bytes(MlsField.BOX_ENV),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "keyPackage")
        }
    }

    /** The joiner's anchor (§6.2.5, S0-15, §19.29.2). */
    sealed class Anchor {
        internal abstract val kind: Int
        internal abstract val bytes: ByteArray

        /** A join or restore: the invite's `committers_digest`. */
        class Invite(
            /** 32 bytes. */
            val committersDigest: ByteArray,
        ) : Anchor() {
            override val kind: Int get() = 1
            override val bytes: ByteArray get() = committersDigest
        }

        /** A rejoin: the committers of the member's last final epoch. */
        class Rejoin(
            /** 32 bytes each. */
            val lastCommitters: List<ByteArray>,
        ) : Anchor() {
            override val kind: Int get() = 2
            override val bytes: ByteArray
                get() = lastCommitters.fold(ByteArray(0)) { all, key -> all + key }
        }
    }

    /** What `welcomeJoin` returns (fn 5). */
    class Joined(
        /** The change-set. */
        val changes: List<MlsChange>,
        /** The joined context. */
        val context: ChannelPolicy,
        /** The roster. */
        val roster: List<RosterMember>,
        /** The own leaf. */
        val leaf: Long,
        /** The joined epoch's keys. */
        val epoch: EpochKeys,
        /** The bootstrap's generation. */
        val generation: GenerationValues,
    ) {
        override fun toString(): String = "Joined($epoch, $generation, members=${roster.size})"
    }

    /** `welcomeJoin` (fn 5): [expectedGeneration] and [expectedNs] are the invite's. */
    fun welcomeJoin(
        channelId: ByteArray,
        rows: List<MlsRow>,
        welcomeBlob: ByteArray,
        day: Int,
        expectedGeneration: Int,
        expectedNs: ByteArray,
        anchor: Anchor,
    ): MlsOutcome<Joined> {
        val reply = mlsCall {
            MlsNative.welcomeJoin(
                handle,
                channelId,
                MlsRow.encode(rows),
                welcomeBlob,
                day,
                expectedGeneration,
                expectedNs,
                anchor.kind,
                anchor.bytes,
            )
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Joined(
                        MlsChange.all(it),
                        ChannelPolicy.of(it.record(MlsField.CONTEXT)),
                        RosterMember.all(it),
                        it.u32(MlsField.LEAF),
                        EpochKeys.of(it),
                        GenerationValues.of(it),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.NOT_FOR_ME, MlsCode.INVALID_WELCOME,
            MlsCode.INVALID_BOOTSTRAP, MlsCode.INVALID_POLICY, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "welcomeJoin")
        }
    }

    /** One message's result in a `receive` batch (fn 6). */
    sealed class Item {
        /** An application message: its content, its author as OpenMLS verified it, its order. */
        class App(
            /** The content. */
            val content: ChannelContentFields,
            /** The author's `P`. */
            val sender: ByteArray,
            /** `ChannelOrder.sender_leaf`. */
            val senderLeaf: Long,
            /** `ChannelOrder.seq`. */
            val seq: Long,
        ) : Item() {
            override fun toString(): String = "App(leaf=$senderLeaf, seq=$seq)"
        }

        /** A commit's validation summary (no change-set). */
        class Commit(
            /** The summary. */
            val summary: CommitSummary,
        ) : Item() {
            override fun toString(): String = "Commit($summary)"
        }

        /** A proposal, dropped unprocessed. */
        object Proposal : Item()

        /** An `OwnPrivateMessage` result: evidence of nothing. */
        object Own : Item()

        /** A message that failed, rolled back inside the batch. */
        class Failed(
            /** Its refusal. */
            val refusal: MlsRefusal,
        ) : Item() {
            override fun toString(): String = "Failed($refusal)"
        }

        internal companion object {
            fun of(r: MlsRecord): Item = when (r.byte(MlsField.ITEM_KIND)) {
                1 -> App(
                    ChannelContentFields.of(r.record(MlsField.CONTENT)),
                    r.bytes(MlsField.SENDER),
                    r.u32(MlsField.SENDER_LEAF),
                    r.u32(MlsField.SEQ),
                )
                2 -> Commit(CommitSummary.of(r.record(MlsField.SUMMARY)))
                3 -> Proposal
                4 -> Own
                5 -> Failed(
                    MlsRefusal(
                        MlsCode.fromWire(r.byte(MlsField.ERROR_CODE))
                            ?: throw IllegalStateException("unknown item code"),
                        if (r.has(MlsField.REASON)) {
                            MlsCommitReason.fromWire(r.byte(MlsField.REASON))
                                ?: throw IllegalStateException("unknown reason")
                        } else {
                            null
                        },
                        r.u16OrNull(MlsField.INDEX),
                    ),
                )
                else -> throw IllegalStateException("unknown item kind")
            }
        }
    }

    /** What `receive` returns: one item per message, in order, and the batch's change-set. */
    class Received(
        /** The items. */
        val items: List<Item>,
        /** The net change-set of the successful items. */
        val changes: List<MlsChange>,
    ) {
        override fun toString(): String = "Received(${items.size} items)"
    }

    /** `receive` (fn 6, S0-17): up to 32 messages of one epoch in peek order, or one commit. */
    fun receive(
        channelId: ByteArray,
        rows: List<MlsRow>,
        epoch: Long,
        messages: List<ByteArray>,
        day: Int,
    ): MlsOutcome<Received> {
        val list = MlsTlv()
        for (m in messages) list.put(MlsField.MESSAGE, m)
        val reply = try {
            mlsCall { MlsNative.receive(handle, channelId, MlsRow.encode(rows), epoch, list.toByteArray(), day) }
        } finally {
            list.erase()
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                Received(reply.fields.records(MlsField.ITEM).map(Item::of), MlsChange.all(reply.fields)),
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_POLICY, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "receive")
        }
    }

    /** The commit `settle` and `trialCount` take: another member's, or the own pending one. */
    sealed class Winner {
        internal abstract val kind: Int

        /** Its bytes. */
        abstract val bytes: ByteArray

        /** Another member's commit. */
        class Foreign(override val bytes: ByteArray) : Winner() {
            override val kind: Int get() = 1
        }

        /** The own pending commit. */
        class Own(override val bytes: ByteArray) : Winner() {
            override val kind: Int get() = 2
        }
    }

    /** What `settle` returns (fn 7). */
    class Settled(
        /** The change-set. */
        val changes: List<MlsChange>,
        /** 1 member, 2 removed, 3 replaced (§6.6). */
        val standing: Int,
        /** The new epoch's keys; `null` when the member left. */
        val epoch: EpochKeys?,
        /** The commit's minute. */
        val commitMinute: Long,
        /** Whether the commit rotates. */
        val rotates: Boolean,
        /** The next generation when it rotates and the member stays. */
        val rotated: GenerationValues?,
        /** The pseudonyms the commit added. */
        val added: List<ByteArray>,
        /** The pseudonyms it removed. */
        val removed: List<ByteArray>,
    ) {
        override fun toString(): String = "Settled(standing=$standing, $epoch, rotates=$rotates)"
    }

    /** `settle` (fn 7). */
    fun settle(
        channelId: ByteArray,
        rows: List<MlsRow>,
        winner: Winner,
        generation: Int,
        day: Int,
    ): MlsOutcome<Settled> {
        val reply = mlsCall {
            MlsNative.settle(handle, channelId, MlsRow.encode(rows), winner.kind, winner.bytes, generation, day)
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Settled(
                        MlsChange.all(it),
                        it.byte(MlsField.STANDING),
                        EpochKeys.orNull(it),
                        it.u32(MlsField.COMMIT_MINUTE),
                        it.flag(MlsField.ROTATES),
                        GenerationValues.orNull(it),
                        it.all(MlsField.ADDED),
                        it.all(MlsField.REMOVED),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_COMMIT, MlsCode.INVALID_POLICY, MlsCode.WRONG_EPOCH,
            MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "settle")
        }
    }

    /** `clearOwn` (fn 8): the change-set that drops the own pending commit. */
    fun clearOwn(channelId: ByteArray, rows: List<MlsRow>, day: Int): MlsOutcome<List<MlsChange>> {
        val reply = mlsCall { MlsNative.clearOwn(handle, channelId, MlsRow.encode(rows), day) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(MlsChange.all(reply.fields))
            MlsCode.NON_CANONICAL, MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "clearOwn")
        }
    }

    /** What `commit` returns (fn 9). */
    class Committed(
        /** The commit's bytes. */
        val commit: ByteArray,
        /** One `WelcomeBlob` body per joiner, in [joiners]' order: kept until the commit wins, then sealed per joiner in mode 0x13. */
        val welcomes: List<ByteArray>,
        /** The joiners' references, in the Welcome's order. */
        val joiners: List<ByteArray>,
        /** The indices of the requested Adds the commit carries. */
        val keptAdds: List<Long>,
        /** The indices of the requested swaps it carries. */
        val keptSwaps: List<Long>,
        /** The indices of the requested Removes it carries. */
        val keptRemoves: List<Long>,
        /** 0 not requested, 1 full, 2 the drops of removed keys only. */
        val contextKept: Int,
        /** Whether it rotates. */
        val rotates: Boolean,
        /** The update path's fresh box key. */
        val boxPk: ByteArray,
        /** Its secret half, wrapped. */
        val boxEnv: ByteArray,
        /** The change-set (the pending commit). */
        val changes: List<MlsChange>,
        /** The committer's own CO-2 validation. */
        val summary: CommitSummary,
    ) {
        override fun toString(): String = "Committed(${commit.size} bytes, $summary)"
    }

    /** `commit` (fn 9). */
    fun commit(
        channelId: ByteArray,
        rows: List<MlsRow>,
        request: CommitRequest,
        day: Int,
    ): MlsOutcome<Committed> {
        val args = request.toRecord()
        val reply = try {
            mlsCall { MlsNative.commit(handle, channelId, MlsRow.encode(rows), args.toByteArray(), day) }
        } finally {
            args.erase()
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Committed(
                        it.bytes(MlsField.MLS),
                        it.all(MlsField.WELCOME),
                        it.all(MlsField.JOINER),
                        it.allU32(MlsField.KEPT_ADD),
                        it.allU32(MlsField.KEPT_SWAP),
                        it.allU32(MlsField.KEPT_REMOVE),
                        it.byte(MlsField.CONTEXT_KEPT),
                        it.flag(MlsField.ROTATES),
                        it.bytes(MlsField.BOX_PK),
                        it.bytes(MlsField.BOX_ENV),
                        MlsChange.all(it),
                        CommitSummary.of(it.record(MlsField.SUMMARY)),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.NO_FIT, MlsCode.INVALID_KEYPACKAGE, MlsCode.INVALID_EVIDENCE,
            MlsCode.INVALID_POLICY, MlsCode.INVALID_COMMIT, MlsCode.PENDING_COMMIT, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "commit")
        }
    }

    /** What `encrypt` returns (fn 10). */
    class Encrypted(
        /** The MLS application message. */
        val mls: ByteArray,
        /** Its epoch. */
        val epoch: Long,
        /** The own leaf. */
        val senderLeaf: Long,
        /** The change-set. */
        val changes: List<MlsChange>,
    ) {
        override fun toString(): String = "Encrypted(epoch=$epoch, leaf=$senderLeaf)"
    }

    /** `encrypt` (fn 10): [content] is `contentEncode`'s output; [seq] is `ch_epoch.own_seq`. */
    fun encrypt(
        channelId: ByteArray,
        rows: List<MlsRow>,
        content: ByteArray,
        seq: Int,
        day: Int,
    ): MlsOutcome<Encrypted> {
        val reply = mlsCall { MlsNative.encrypt(handle, channelId, MlsRow.encode(rows), content, seq, day) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Encrypted(
                        it.bytes(MlsField.MLS),
                        it.i64(MlsField.EPOCH),
                        it.u32(MlsField.SENDER_LEAF),
                        MlsChange.all(it),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.PENDING_COMMIT, MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE ->
                refused(reply)
            else -> mlsUnexpected(reply.code, "encrypt")
        }
    }

    /** The seal's `order` (§5.6): zero outside mode 0x11. */
    class SealOrder(
        /** The epoch. */
        val epoch: Long,
        /** The sender leaf (zero for a commit). */
        val senderLeaf: Int,
        /** The sequence number (zero for a commit). */
        val seq: Int,
    ) {
        override fun toString(): String = "SealOrder($epoch, $senderLeaf, $seq)"

        companion object {
            /** The order of modes 0x12 and 0x13. */
            val NONE: SealOrder = SealOrder(0, 0, 0)
        }
    }

    /** `seal` (fn 11): [keyClass] [KEY_CLASS_EPOCH] with mode 0x11, [KEY_CLASS_JOIN] with 0x12, 0x13. */
    fun seal(
        channelId: ByteArray,
        keyEnv: ByteArray,
        keyClass: Int,
        ns: ByteArray,
        bucket: Int,
        mode: Int,
        order: SealOrder,
        body: ByteArray,
    ): MlsOutcome<ByteArray> {
        val reply = mlsCall {
            MlsNative.seal(
                handle, channelId, keyEnv, keyClass, ns, bucket, mode, order.epoch, order.senderLeaf, order.seq, body,
            )
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(reply.fields.bytes(MlsField.BLOB))
            MlsCode.NON_CANONICAL, MlsCode.NO_FIT, MlsCode.INVALID_POLICY, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "seal")
        }
    }

    /** What `open` returns (fn 12). */
    class OpenedBlob(
        /** The seal's order. */
        val order: SealOrder,
        /** The body. */
        val body: ByteArray,
        /** Mode 0x11: the PrivateMessage header's epoch. */
        val headerEpoch: Long?,
        /** Mode 0x11: 1 application, 2 commit, 3 proposal. */
        val contentType: Int?,
        /** Mode 0x11, an application message: its `ChannelOrder` leaf. */
        val aadLeaf: Long?,
        /** Mode 0x11, an application message: its `ChannelOrder` seq. */
        val aadSeq: Long?,
    ) {
        override fun toString(): String = "OpenedBlob($order, type=$contentType)"
    }

    /** `open` (fn 12). */
    fun open(
        channelId: ByteArray,
        keyEnv: ByteArray,
        keyClass: Int,
        ns: ByteArray,
        mode: Int,
        blob: ByteArray,
    ): MlsOutcome<OpenedBlob> {
        val reply = mlsCall { MlsNative.open(handle, channelId, keyEnv, keyClass, ns, mode, blob) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    OpenedBlob(
                        SealOrder(it.i64(MlsField.ORDER_EPOCH), it.u32(MlsField.ORDER_LEAF).toInt(), it.u32(MlsField.ORDER_SEQ).toInt()),
                        it.bytes(MlsField.BODY),
                        it.i64OrNull(MlsField.HEADER_EPOCH),
                        if (it.has(MlsField.CONTENT_TYPE)) it.byte(MlsField.CONTENT_TYPE) else null,
                        it.u32OrNull(MlsField.AAD_LEAF),
                        it.u32OrNull(MlsField.AAD_SEQ),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.NOT_OPEN, MlsCode.INVALID_POLICY, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "open")
        }
    }

    /** What `generation` returns (fn 13). */
    class GenerationOut(
        /** The generation's values. */
        val values: GenerationValues,
        /** The credentials of the requested slots. */
        val slots: List<SlotCredentials>,
    ) {
        override fun toString(): String = "GenerationOut($values, slots=${slots.size})"
    }

    /** `generation` (fn 13). */
    fun generation(
        channelId: ByteArray,
        gEnv: ByteArray,
        generation: Int,
        openEpoch: Long,
        slots: ByteArray,
    ): MlsOutcome<GenerationOut> {
        val reply = mlsCall { MlsNative.generation(handle, channelId, gEnv, generation, openEpoch, slots) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                GenerationOut(GenerationValues.of(reply.fields), SlotCredentials.all(reply.fields)),
            )
            MlsCode.NON_CANONICAL, MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "generation")
        }
    }

    /** What `inviteBuild` returns (fn 14): the invite and the `INVITE_ISSUED` fields. */
    class InviteBuilt(
        /** `ChannelInviteV2`, 335 bytes (a bearer secret: the link). */
        val invite: ByteArray,
        /** 0 open, 1 password. */
        val kdfCode: Int,
        /** The `INVITE_ISSUED` record's fields. */
        val inviteId: ByteArray,
        /** The invite key's public half. */
        val invitePk: ByteArray,
        /** The expiry day. */
        val expiryDay: Long,
        /** The sponsor's signature. */
        val sponsorSig: ByteArray,
        /** The committers digest. */
        val committersDigest: ByteArray,
        /** The context's `pw_version`, in a password channel only. */
        val pwVersion: Int?,
    ) {
        override fun toString(): String = "InviteBuilt(kdfCode=$kdfCode, expiryDay=$expiryDay)"
    }

    /**
     * `inviteBuild` (fn 14, §19.29.3): [password] `null` for an open invite (`kdf_code` 0), else the
     * characters the user typed (`kdf_code` 1); the facade builds the NFKD UTF-8 bytes, hands them
     * to the native side and zeroes its copy after the call. [password] itself stays the caller's.
     */
    fun inviteBuild(
        channelId: ByteArray,
        rows: List<MlsRow>,
        gEnv: ByteArray,
        generation: Int,
        expiryDay: Int,
        password: CharArray?,
        carryName: Boolean,
        day: Int,
    ): MlsOutcome<InviteBuilt> {
        val bytes = password?.let { ChannelPassword.nfkdUtf8(it) ?: return unencodablePassword() }
        val kdfCode = if (password == null) 0 else ChannelInvite.KDF_ARGON2ID_P0
        val reply = try {
            mlsCall {
                MlsNative.inviteBuild(
                    handle, channelId, MlsRow.encode(rows), gEnv, generation, expiryDay, kdfCode, bytes,
                    if (carryName) 1 else 0, day,
                )
            }
        } finally {
            bytes?.fill(0)
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    InviteBuilt(
                        it.bytes(MlsField.INVITE),
                        it.byte(MlsField.KDF_CODE),
                        it.bytes(MlsField.INVITE_ID),
                        it.bytes(MlsField.INVITE_PK),
                        it.u32(MlsField.EXPIRY_DAY),
                        it.bytes(MlsField.SPONSOR_SIG),
                        it.bytes(MlsField.COMMITTERS_DIGEST),
                        it.u16OrNull(MlsField.PW_VERSION),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_POLICY, MlsCode.PASSWORD_REQUIRED, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "inviteBuild")
        }
    }

    /** What `inviteParse` returns (fn 14 as slice S2b maps it, §19.32). */
    class InviteParsed(
        /** 0 open, 1 password. */
        val kdfCode: Int,
        /** The suite (0x0003). */
        val suite: Int,
        /** The channel's size class. */
        val sizeClass: Int,
        /** The handshake TTL code. */
        val handshakeTtlCode: Int,
        /** The channel id. */
        val channelId: ByteArray,
        /** The generation. */
        val generation: Long,
        /** `ns_g`. */
        val ns: ByteArray,
        /** The invite's id. */
        val inviteId: ByteArray,
        /** The invite key's public half. */
        val invitePk: ByteArray,
        /** The committers digest (the join anchor). */
        val committersDigest: ByteArray,
        /** The expiry day. */
        val expiryDay: Long,
        /** The name (empty unless the sponsor carried it). */
        val name: ByteArray,
        /** `JK_g` wrapped under this context, bound to the invite's channel. */
        val jkEnv: ByteArray,
        /** `R_join(g)`. */
        val rJoin: ByteArray,
        /** The invite seed wrapped, for `joinRequest`. */
        val inviteSeedEnv: ByteArray,
        /** The credentials of the requested slots. */
        val slots: List<SlotCredentials>,
    ) {
        override fun toString(): String = "InviteParsed(kdfCode=$kdfCode, generation=$generation, expiryDay=$expiryDay)"
    }

    /**
     * `inviteParse` (fn 14): without [password] a password invite is `PASSWORD_REQUIRED` and no
     * Argon2id runs; with one, the facade builds the NFKD UTF-8 bytes and zeroes them after the call.
     */
    fun inviteParse(invite: ByteArray, password: CharArray?, slots: ByteArray): MlsOutcome<InviteParsed> {
        val bytes = password?.let { ChannelPassword.nfkdUtf8(it) ?: return unencodablePassword() }
        val reply = try {
            mlsCall { MlsNative.inviteParse(handle, invite, bytes, slots) }
        } finally {
            bytes?.fill(0)
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    InviteParsed(
                        it.byte(MlsField.KDF_CODE),
                        it.u16(MlsField.SUITE),
                        it.byte(MlsField.SIZE_CLASS),
                        it.byte(MlsField.HANDSHAKE_TTL_CODE),
                        it.bytes(MlsField.CHANNEL_ID),
                        it.u32(MlsField.GENERATION),
                        it.bytes(MlsField.NS),
                        it.bytes(MlsField.INVITE_ID),
                        it.bytes(MlsField.INVITE_PK),
                        it.bytes(MlsField.COMMITTERS_DIGEST),
                        it.u32(MlsField.EXPIRY_DAY),
                        it.bytes(MlsField.NAME),
                        it.bytes(MlsField.JK_ENV),
                        it.bytes(MlsField.R_JOIN),
                        it.bytes(MlsField.INVITE_SEED_ENV),
                        SlotCredentials.all(it),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.UNSUPPORTED_SUITE, MlsCode.PASSWORD_REQUIRED, MlsCode.WRONG_PASSWORD,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "inviteParse")
        }
    }

    /** `joinRequest` (fn 15): the join or restore request body. */
    fun joinRequest(
        channelId: ByteArray,
        inviteId: ByteArray,
        inviteSeedEnv: ByteArray,
        keyPackage: ByteArray,
    ): MlsOutcome<ByteArray> {
        val reply = mlsCall { MlsNative.joinRequest(handle, channelId, inviteId, inviteSeedEnv, keyPackage) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(reply.fields.bytes(MlsField.BODY))
            MlsCode.NON_CANONICAL, MlsCode.INVALID_KEYPACKAGE, MlsCode.WRONG_PURPOSE, MlsCode.STATE_CORRUPT,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "joinRequest")
        }
    }

    /** `rejoinRequest` (fn 15, §19.3): signed with the channel's pseudonym key. */
    fun rejoinRequest(
        channelId: ByteArray,
        generation: Int,
        day: Int,
        lastEpoch: Long,
        lastHash: ByteArray,
        keyPackage: ByteArray,
    ): MlsOutcome<ByteArray> {
        val reply = mlsCall {
            MlsNative.rejoinRequest(handle, channelId, generation, day, lastEpoch, lastHash, keyPackage)
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(reply.fields.bytes(MlsField.BODY))
            MlsCode.NON_CANONICAL, MlsCode.INVALID_KEYPACKAGE, MlsCode.WRONG_PURPOSE, MlsCode.CRYPTO_UNAVAILABLE ->
                refused(reply)
            else -> mlsUnexpected(reply.code, "rejoinRequest")
        }
    }

    /** What `joinVerify` returns (fn 15). */
    class JoinVerified(
        /** 1 join, 2 rejoin, 3 restore. */
        val requestType: Int,
        /** The canonical KeyPackage. */
        val keyPackage: ByteArray,
        /** Its reference. */
        val kpRef: ByteArray,
        /** Its pseudonym. */
        val pseudonym: ByteArray,
        /** Its box key. */
        val boxPk: ByteArray,
        /** Its `GhostKpBind`: `CHANNEL_ID`, `PURPOSE`, `DAY`. */
        val kpBind: MlsRecord,
        /** The authorization: `INVITE_ID`, `INVITE_SIG`, or `DAY`, `LAST_EPOCH`, `LAST_HASH`, `REJOIN_SIG`. */
        val auth: MlsRecord,
    ) {
        override fun toString(): String = "JoinVerified(type=$requestType)"
    }

    /** `joinVerify` (fn 15): [invitePk] for a join or restore, [member] for a rejoin. */
    fun joinVerify(
        channelId: ByteArray,
        body: ByteArray,
        invitePk: ByteArray?,
        member: ByteArray?,
        generation: Int,
    ): MlsOutcome<JoinVerified> {
        val reply = mlsCall {
            MlsNative.joinVerify(handle, channelId, body, invitePk ?: NO_BYTES, member ?: NO_BYTES, generation)
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    JoinVerified(
                        it.byte(MlsField.REQUEST_TYPE),
                        it.bytes(MlsField.KEY_PACKAGE),
                        it.bytes(MlsField.KP_REF),
                        it.bytes(MlsField.PSEUDONYM),
                        it.bytes(MlsField.BOX_PK),
                        it.record(MlsField.KP_BIND),
                        it,
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_KEYPACKAGE, MlsCode.WRONG_PURPOSE, MlsCode.BAD_SIGNATURE,
            MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "joinVerify")
        }
    }

    /** What `roster` returns (fn 18). */
    class Roster(
        /** The members. */
        val members: List<RosterMember>,
        /** The epoch. */
        val epoch: Long,
        /** Its `epoch_authenticator` (CO-12's fingerprint input). */
        val epochAuthenticator: ByteArray,
        /** The tree hash. */
        val treeHash: ByteArray,
        /** The context. */
        val context: ChannelPolicy,
        /** The own leaf. */
        val ownLeaf: Long,
    ) {
        override fun toString(): String = "Roster(epoch=$epoch, members=${members.size})"
    }

    /** `roster` (fn 18). */
    fun roster(channelId: ByteArray, rows: List<MlsRow>, day: Int): MlsOutcome<Roster> {
        val reply = mlsCall { MlsNative.roster(handle, channelId, MlsRow.encode(rows), day) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                reply.fields.let {
                    Roster(
                        RosterMember.all(it),
                        it.i64(MlsField.EPOCH),
                        it.bytes(MlsField.EPOCH_AUTHENTICATOR),
                        it.bytes(MlsField.TREE_HASH),
                        ChannelPolicy.of(it.record(MlsField.CONTEXT)),
                        it.u32(MlsField.LEAF),
                    )
                },
            )
            MlsCode.NON_CANONICAL, MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "roster")
        }
    }

    /** `sweepPast` (fn 19, §8.3). */
    fun sweepPast(channelId: ByteArray, rows: List<MlsRow>, keepCount: Int, day: Int): MlsOutcome<List<MlsChange>> {
        val reply = mlsCall { MlsNative.sweepPast(handle, channelId, MlsRow.encode(rows), keepCount, day) }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(MlsChange.all(reply.fields))
            MlsCode.NON_CANONICAL, MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
            else -> mlsUnexpected(reply.code, "sweepPast")
        }
    }

    /** What `trialCount` returns (fn 20, CO-3): the candidate's committer and the successors. */
    class Trial(
        /** The candidate's committer. */
        val committer: ByteArray,
        /** The distinct authenticated senders under the trial state. */
        val senders: List<ByteArray>,
    ) {
        override fun toString(): String = "Trial(senders=${senders.size})"
    }

    /** `trialCount` (fn 20, S0-17): writes nothing. */
    fun trialCount(
        channelId: ByteArray,
        rows: List<MlsRow>,
        candidate: Winner,
        held: List<HeldBlob>,
        day: Int,
    ): MlsOutcome<Trial> {
        val list = MlsTlv()
        for (h in held) list.record(MlsField.HELD, MlsTlv().put(MlsField.NS, h.ns).put(MlsField.BLOB, h.blob))
        val reply = try {
            mlsCall {
                MlsNative.trialCount(
                    handle, channelId, MlsRow.encode(rows), candidate.kind, candidate.bytes, list.toByteArray(), day,
                )
            }
        } finally {
            list.erase()
        }
        return when (reply.code) {
            MlsCode.OK -> MlsOutcome.Ok(
                Trial(reply.fields.bytes(MlsField.CANDIDATE), reply.fields.all(MlsField.TRIAL_SENDER)),
            )
            MlsCode.NON_CANONICAL, MlsCode.INVALID_COMMIT, MlsCode.INVALID_POLICY, MlsCode.WRONG_EPOCH,
            MlsCode.STATE_CORRUPT, MlsCode.CRYPTO_UNAVAILABLE,
            -> refused(reply)
            else -> mlsUnexpected(reply.code, "trialCount")
        }
    }

    override fun toString(): String = "ChannelCrypto(redacted)"

    companion object {
        /** `keyClass` of `K_ep` (mode 0x11). */
        const val KEY_CLASS_EPOCH: Int = 1

        /** `keyClass` of `JK_g` (modes 0x12, 0x13). */
        const val KEY_CLASS_JOIN: Int = 3

        /** The seal modes of §5.6. */
        const val MODE_EPOCH: Int = 0x11

        /** A join request. */
        const val MODE_JOIN: Int = 0x12

        /** A Welcome blob. */
        const val MODE_WELCOME: Int = 0x13

        private val NO_BYTES = ByteArray(0)

        /** `ctxOpen` (fn 1): a context over the 32-byte channel state key. */
        fun open(stateKey: ByteArray): MlsOutcome<ChannelCrypto> {
            val reply = mlsCall { MlsNative.ctxOpen(stateKey) }
            return when (reply.code) {
                MlsCode.OK -> MlsOutcome.Ok(ChannelCrypto(reply.fields.i64(MlsField.HANDLE)))
                MlsCode.INVALID_KEY, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
                else -> mlsUnexpected(reply.code, "ctxOpen")
            }
        }

        /** `contentEncode` (fn 17): the canonical `ChannelContent`. */
        fun contentEncode(content: ChannelContentFields): MlsOutcome<ByteArray> {
            val args = content.toRecord()
            val reply = try {
                mlsCall { MlsNative.contentEncode(args.toByteArray()) }
            } finally {
                args.erase()
            }
            return when (reply.code) {
                MlsCode.OK -> MlsOutcome.Ok(reply.fields.bytes(MlsField.ENCODED))
                MlsCode.NON_CANONICAL, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
                else -> mlsUnexpected(reply.code, "contentEncode")
            }
        }

        /** `contentDecode` (fn 17): a strict decode. */
        fun contentDecode(content: ByteArray): MlsOutcome<ChannelContentFields> {
            val reply = mlsCall { MlsNative.contentDecode(content) }
            return when (reply.code) {
                MlsCode.OK -> MlsOutcome.Ok(ChannelContentFields.of(reply.fields))
                MlsCode.NON_CANONICAL, MlsCode.CRYPTO_UNAVAILABLE -> refused(reply)
                else -> mlsUnexpected(reply.code, "contentDecode")
            }
        }
    }
}
