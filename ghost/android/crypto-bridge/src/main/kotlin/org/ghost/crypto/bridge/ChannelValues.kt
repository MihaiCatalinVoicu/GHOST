package org.ghost.crypto.bridge

/*
 * The value types of the channel facade (Phase 10 design §10.1: ":crypto-bridge — its types are
 * byte arrays and its own value types"). Each is built from a decoded reply ([MlsRecord]) or
 * encodes itself as an argument record ([MlsTlv]); none parses protocol bytes — the TLS formats of
 * §5 stay native (ADR-19) — and every type that holds a secret renders without it.
 */

/** A stored row (§3.4 point 2): `mls_kv` ([SCOPE_GROUP]) or `mls_global_kv` ([SCOPE_GLOBAL]). */
class MlsRow(
    /** [SCOPE_GROUP] or [SCOPE_GLOBAL]. */
    val scope: Int,
    /** The storage key. */
    val key: ByteArray,
    /** The wrapped value. */
    val env: ByteArray,
) {
    override fun toString(): String = "MlsRow(scope=$scope, ${key.size} + ${env.size} bytes)"

    companion object {
        /** `mls_kv`, the group-scoped rows of one channel. */
        const val SCOPE_GROUP: Int = 1

        /** `mls_global_kv`, tagged by Kotlin with the channel of the call. */
        const val SCOPE_GLOBAL: Int = 2

        /** The TLV array a call takes (`rows`). */
        fun encode(rows: List<MlsRow>): ByteArray {
            val list = MlsTlv()
            for (row in rows) {
                list.record(
                    MlsField.ROW,
                    MlsTlv().u8(MlsField.SCOPE, row.scope).put(MlsField.KEY, row.key).put(MlsField.ENV, row.env),
                )
            }
            return list.toByteArray().also { list.erase() }
        }
    }
}

/** One change of a change-set (§3.4 point 3): a put ([env] set) or a delete ([env] null). */
class MlsChange(
    /** [MlsRow.SCOPE_GROUP] or [MlsRow.SCOPE_GLOBAL]. */
    val scope: Int,
    /** The storage key. */
    val key: ByteArray,
    /** The new wrapped value, or `null` for a delete. */
    val env: ByteArray?,
) {
    /** Whether this change deletes its row. */
    val isDelete: Boolean get() = env == null

    override fun toString(): String = "MlsChange(scope=$scope, ${if (env == null) "delete" else "put"})"

    internal companion object {
        fun all(record: MlsRecord): List<MlsChange> = record.records(MlsField.CHANGE).map {
            MlsChange(it.byte(MlsField.SCOPE), it.bytes(MlsField.KEY), it.bytesOrNull(MlsField.ENV))
        }
    }
}

/** An epoch's keys as Kotlin stores them (§9 `ch_epoch`): `K_ep` wrapped, `R_ep` in clear (CS-S6). */
class EpochKeys(
    /** The epoch. */
    val epoch: Long,
    /** `K_ep(e)` wrapped with its epoch (68 bytes). */
    val kEnv: ByteArray,
    /** `R_ep(e)`, the recognition key. */
    val rEp: ByteArray,
    /** The epoch's `epoch_authenticator`. */
    val epochAuthenticator: ByteArray,
) {
    override fun toString(): String = "EpochKeys(epoch=$epoch)"

    internal companion object {
        fun of(r: MlsRecord): EpochKeys = EpochKeys(
            r.i64(MlsField.EPOCH),
            r.bytes(MlsField.K_ENV),
            r.bytes(MlsField.R_EP),
            r.bytes(MlsField.EPOCH_AUTHENTICATOR),
        )

        fun orNull(r: MlsRecord): EpochKeys? = if (r.has(MlsField.EPOCH)) of(r) else null
    }
}

/** A generation's values (§5.2): `G_g` and `JK_g` wrapped, `ns_g` and `R_join` in clear. */
class GenerationValues(
    /** The generation number. */
    val generation: Long,
    /** The epoch whose commit opened it. */
    val openEpoch: Long,
    /** `G_g` wrapped. */
    val gEnv: ByteArray,
    /** `ns_g`. */
    val ns: ByteArray,
    /** `JK_g` wrapped. */
    val jkEnv: ByteArray,
    /** `R_join(g)`. */
    val rJoin: ByteArray,
) {
    override fun toString(): String = "GenerationValues(generation=$generation, openEpoch=$openEpoch)"

    internal companion object {
        fun of(r: MlsRecord): GenerationValues = GenerationValues(
            r.u32(MlsField.GENERATION),
            r.i64(MlsField.OPEN_EPOCH),
            r.bytes(MlsField.G_ENV),
            r.bytes(MlsField.NS),
            r.bytes(MlsField.JK_ENV),
            r.bytes(MlsField.R_JOIN),
        )

        fun orNull(r: MlsRecord): GenerationValues? = if (r.has(MlsField.G_ENV)) of(r) else null
    }
}

/** One relay slot's READ and DEPOSIT credentials v3 and their verifiers (§5.2). */
class SlotCredentials(
    /** The relay slot. */
    val slot: Int,
    /** The READ credential, a bearer secret presented to the slot's relay. */
    val readCredential: ByteArray,
    /** Its verifier, registered with the relay. */
    val readVerifier: ByteArray,
    /** The DEPOSIT credential. */
    val depositCredential: ByteArray,
    /** Its verifier. */
    val depositVerifier: ByteArray,
) {
    override fun toString(): String = "SlotCredentials(slot=$slot)"

    internal companion object {
        fun all(r: MlsRecord): List<SlotCredentials> = r.records(MlsField.SLOT).map {
            SlotCredentials(
                it.byte(MlsField.SLOT_INDEX),
                it.bytes(MlsField.READ_CREDENTIAL),
                it.bytes(MlsField.READ_VERIFIER),
                it.bytes(MlsField.DEPOSIT_CREDENTIAL),
                it.bytes(MlsField.DEPOSIT_VERIFIER),
            )
        }
    }
}

/**
 * A `GhostChannelContext` as fields (§5.3): what `groupCreate` takes as its policy, a commit's
 * context change, and what `welcomeJoin`, `roster` and a commit summary report. Its TLS encoding
 * and validity are native.
 */
class ChannelPolicy(
    /** The channel id (the MLS group id). */
    val channelId: ByteArray,
    /** 0 small, 1 large (§5.7). */
    val sizeClass: Int,
    /** The ephemeral timer (§8.1). */
    val timerCode: Int,
    /** Its version. */
    val timerVersion: Int,
    /** 0 in P0. */
    val historyPolicy: Int,
    /** Bit 0 members may invite, bit 2 password (§5.3, §19.28). */
    val flags: Int,
    /** 35 … 70. */
    val idleEvictDays: Int,
    /** ≥ 1 in a password channel. */
    val pwVersion: Int,
    /** The name, UTF-8, ≤ 48 bytes. */
    val name: ByteArray,
    /** The committers, in rank order. */
    val committers: List<ByteArray>,
    /** The funders. */
    val funders: List<ByteArray>,
) {
    /** The argument record. */
    fun toRecord(): MlsTlv {
        val r = MlsTlv()
            .put(MlsField.CHANNEL_ID, channelId)
            .u8(MlsField.SIZE_CLASS, sizeClass)
            .u8(MlsField.TIMER_CODE, timerCode)
            .u16(MlsField.TIMER_VERSION, timerVersion)
            .u8(MlsField.HISTORY_POLICY, historyPolicy)
            .u8(MlsField.FLAGS, flags)
            .u16(MlsField.IDLE_EVICT_DAYS, idleEvictDays)
            .u16(MlsField.PW_VERSION, pwVersion)
            .put(MlsField.NAME, name)
        for (c in committers) r.put(MlsField.COMMITTER, c)
        for (f in funders) r.put(MlsField.FUNDER, f)
        return r
    }

    override fun toString(): String =
        "ChannelPolicy(class=$sizeClass, timer=$timerCode, flags=$flags, committers=${committers.size})"

    internal companion object {
        fun of(r: MlsRecord): ChannelPolicy = ChannelPolicy(
            r.bytes(MlsField.CHANNEL_ID),
            r.byte(MlsField.SIZE_CLASS),
            r.byte(MlsField.TIMER_CODE),
            r.u16(MlsField.TIMER_VERSION),
            r.byte(MlsField.HISTORY_POLICY),
            r.byte(MlsField.FLAGS),
            r.u16(MlsField.IDLE_EVICT_DAYS),
            r.u16(MlsField.PW_VERSION),
            r.bytes(MlsField.NAME),
            r.all(MlsField.COMMITTER),
            r.all(MlsField.FUNDER),
        )
    }
}

/** A member of the roster (fn 18): its pseudonym, leaf, box key and `refresh_epoch`. */
class RosterMember(
    /** `P`. */
    val pseudonym: ByteArray,
    /** The leaf index. */
    val leaf: Long,
    /** `GhostLeaf.box_pk`, when the leaf carries one. */
    val boxPk: ByteArray?,
    /** `GhostLeaf.refresh_epoch`, when the leaf carries one. */
    val refreshEpoch: Long?,
) {
    override fun toString(): String = "RosterMember(leaf=$leaf)"

    internal companion object {
        fun all(r: MlsRecord): List<RosterMember> = r.records(MlsField.MEMBER).map {
            RosterMember(
                it.bytes(MlsField.PSEUDONYM),
                it.u32(MlsField.LEAF),
                it.bytesOrNull(MlsField.BOX_PK),
                it.i64OrNull(MlsField.REFRESH_EPOCH),
            )
        }
    }
}

/**
 * A `ChannelContent` as fields (§5.5): the header and the body fields of its [kind]. What
 * `contentEncode` takes and `contentDecode` and a received post return; the canonical encoding
 * and every rule on it are native.
 */
class ChannelContentFields(
    /** 1 post, 2 reaction, 3 invite issued, 4 leave, 5 reveal. */
    val kind: Int,
    /** 16 bytes. */
    val opId: ByteArray,
    /** The author's minute. */
    val authorMinute: Long,
    /** The timer code. */
    val timerCode: Int,
    /** A post's text (UTF-8). */
    val text: ByteArray? = null,
    /** A post's `reply_to`. */
    val replyTo: ByteArray? = null,
    /** A reaction's target. */
    val target: ByteArray? = null,
    /** A reaction's grapheme (UTF-8; empty withdraws it). */
    val grapheme: ByteArray? = null,
    /** An `INVITE_ISSUED`'s fields. */
    val inviteId: ByteArray? = null,
    /** An `INVITE_ISSUED`'s `invite_pk`. */
    val invitePk: ByteArray? = null,
    /** An `INVITE_ISSUED`'s expiry day. */
    val expiryDay: Long? = null,
    /** An `INVITE_ISSUED`'s `sponsor_sig`. */
    val sponsorSig: ByteArray? = null,
    /** An `INVITE_ISSUED`'s committers digest. */
    val committersDigest: ByteArray? = null,
    /** An `INVITE_ISSUED`'s `pw_version`, present exactly in a password channel. */
    val pwVersion: Int? = null,
    /** A reveal's `hpke_enc`. */
    val hpkeEnc: ByteArray? = null,
    /** A reveal's ciphertext. */
    val ciphertext: ByteArray? = null,
) {
    /** The argument record of `contentEncode`. */
    fun toRecord(): MlsTlv {
        val r = MlsTlv()
            .u8(MlsField.KIND, kind)
            .put(MlsField.OP_ID, opId)
            .u32(MlsField.AUTHOR_MINUTE, authorMinute)
            .u8(MlsField.TIMER_CODE, timerCode)
        text?.let { r.put(MlsField.TEXT, it) }
        replyTo?.let { r.put(MlsField.REPLY_TO, it) }
        target?.let { r.put(MlsField.TARGET, it) }
        grapheme?.let { r.put(MlsField.GRAPHEME, it) }
        inviteId?.let { r.put(MlsField.INVITE_ID, it) }
        invitePk?.let { r.put(MlsField.INVITE_PK, it) }
        expiryDay?.let { r.u32(MlsField.EXPIRY_DAY, it) }
        sponsorSig?.let { r.put(MlsField.SPONSOR_SIG, it) }
        committersDigest?.let { r.put(MlsField.COMMITTERS_DIGEST, it) }
        pwVersion?.let { r.u16(MlsField.PW_VERSION, it) }
        hpkeEnc?.let { r.put(MlsField.HPKE_ENC, it) }
        ciphertext?.let { r.put(MlsField.CIPHERTEXT, it) }
        return r
    }

    /** Never shows a post's text (T3). */
    override fun toString(): String = "ChannelContentFields(kind=$kind)"

    internal companion object {
        fun of(r: MlsRecord): ChannelContentFields = ChannelContentFields(
            kind = r.byte(MlsField.KIND),
            opId = r.bytes(MlsField.OP_ID),
            authorMinute = r.u32(MlsField.AUTHOR_MINUTE),
            timerCode = r.byte(MlsField.TIMER_CODE),
            text = r.bytesOrNull(MlsField.TEXT),
            replyTo = r.bytesOrNull(MlsField.REPLY_TO),
            target = r.bytesOrNull(MlsField.TARGET),
            grapheme = r.bytesOrNull(MlsField.GRAPHEME),
            inviteId = r.bytesOrNull(MlsField.INVITE_ID),
            invitePk = r.bytesOrNull(MlsField.INVITE_PK),
            expiryDay = r.u32OrNull(MlsField.EXPIRY_DAY),
            sponsorSig = r.bytesOrNull(MlsField.SPONSOR_SIG),
            committersDigest = r.bytesOrNull(MlsField.COMMITTERS_DIGEST),
            pwVersion = r.u16OrNull(MlsField.PW_VERSION),
            hpkeEnc = r.bytesOrNull(MlsField.HPKE_ENC),
            ciphertext = r.bytesOrNull(MlsField.CIPHERTEXT),
        )
    }
}

/** `AdmitEvidence` (§19.2): what a committer puts in the commit's AAD for an Add. */
class AdmitEvidence(
    /** The KeyPackage's reference. */
    val kpRef: ByteArray,
    /** The invite's id. */
    val inviteId: ByteArray,
    /** The invite's public key. */
    val invitePk: ByteArray,
    /** The invite's expiry day. */
    val expiryDay: Long,
    /** The sponsor's pseudonym. */
    val sponsor: ByteArray,
    /** The sponsor's signature of the invite. */
    val sponsorSig: ByteArray,
    /** The invitee's signature with the invite key. */
    val inviteSig: ByteArray,
) {
    /** The argument record. */
    fun toRecord(): MlsTlv = MlsTlv()
        .put(MlsField.KP_REF, kpRef)
        .put(MlsField.INVITE_ID, inviteId)
        .put(MlsField.INVITE_PK, invitePk)
        .u32(MlsField.EXPIRY_DAY, expiryDay)
        .put(MlsField.SPONSOR, sponsor)
        .put(MlsField.SPONSOR_SIG, sponsorSig)
        .put(MlsField.INVITE_SIG, inviteSig)

    override fun toString(): String = "AdmitEvidence(expiryDay=$expiryDay)"

    internal companion object {
        fun of(r: MlsRecord): AdmitEvidence = AdmitEvidence(
            r.bytes(MlsField.KP_REF),
            r.bytes(MlsField.INVITE_ID),
            r.bytes(MlsField.INVITE_PK),
            r.u32(MlsField.EXPIRY_DAY),
            r.bytes(MlsField.SPONSOR),
            r.bytes(MlsField.SPONSOR_SIG),
            r.bytes(MlsField.INVITE_SIG),
        )
    }
}

/** `SwapEvidence` (§19.2): a rejoin's own signature, or a restore's invite evidence. */
sealed class SwapEvidence {
    /** The argument record. */
    abstract fun toRecord(): MlsTlv

    /** A rejoin (§19.3), signed with the member's pseudonym key. */
    class Rejoin(
        /** The KeyPackage's reference. */
        val kpRef: ByteArray,
        /** The generation of the namespace the request came from. */
        val generation: Long,
        /** The requester's day. */
        val day: Long,
        /** The requester's last final epoch. */
        val lastEpoch: Long,
        /** Its winner hash. */
        val lastHash: ByteArray,
        /** The signature. */
        val rejoinSig: ByteArray,
    ) : SwapEvidence() {
        override fun toRecord(): MlsTlv = MlsTlv()
            .u8(MlsField.SWAP_KIND, 1)
            .put(MlsField.KP_REF, kpRef)
            .u32(MlsField.GENERATION, generation)
            .u32(MlsField.DAY, day)
            .u64(MlsField.LAST_EPOCH, lastEpoch)
            .put(MlsField.LAST_HASH, lastHash)
            .put(MlsField.REJOIN_SIG, rejoinSig)

        override fun toString(): String = "SwapEvidence.Rejoin(generation=$generation)"
    }

    /** A restore, authorized by an invite. */
    class Restore(
        /** The invite evidence (its `kpRef` is the swap's). */
        val evidence: AdmitEvidence,
    ) : SwapEvidence() {
        override fun toRecord(): MlsTlv =
            MlsTlv().u8(MlsField.SWAP_KIND, 2).record(MlsField.EVIDENCE, evidence.toRecord())

        override fun toString(): String = "SwapEvidence.Restore"
    }

    internal companion object {
        fun of(r: MlsRecord): SwapEvidence = when (r.byte(MlsField.SWAP_KIND)) {
            1 -> Rejoin(
                r.bytes(MlsField.KP_REF),
                r.u32(MlsField.GENERATION),
                r.u32(MlsField.DAY),
                r.i64(MlsField.LAST_EPOCH),
                r.bytes(MlsField.LAST_HASH),
                r.bytes(MlsField.REJOIN_SIG),
            )
            2 -> Restore(AdmitEvidence.of(r.record(MlsField.EVIDENCE)))
            else -> throw IllegalStateException("unknown swap kind")
        }
    }
}

/** What a commit carries (fn 9; §10.2's argument list as one record). */
class CommitRequest(
    /** Adds: a canonical KeyPackage and its evidence. */
    val adds: List<Pair<ByteArray, AdmitEvidence>> = emptyList(),
    /** Removes, by pseudonym. */
    val removes: List<ByteArray> = emptyList(),
    /** Swaps: the pseudonym, the new KeyPackage and the evidence. */
    val swaps: List<Triple<ByteArray, ByteArray, SwapEvidence>> = emptyList(),
    /** A context change, or `null`. */
    val context: ChannelPolicy? = null,
    /** The rotation flag (committers only). */
    val rotate: Boolean = false,
    /** The commit's minute. */
    val commitMinute: Long,
    /** The class floor bucket (§5.7). */
    val floor: Long,
    /** The current generation (the Welcome's bootstrap, §5.4). */
    val generation: Long,
    /** The epoch that opened it. */
    val openEpoch: Long,
    /** Its `G_g` wrapped. */
    val gEnv: ByteArray,
) {
    /** The argument record. */
    fun toRecord(): MlsTlv {
        val r = MlsTlv()
        for ((kp, evidence) in adds) {
            r.record(MlsField.ADD, MlsTlv().put(MlsField.KEY_PACKAGE, kp).record(MlsField.EVIDENCE, evidence.toRecord()))
        }
        for (p in removes) r.record(MlsField.REMOVE, MlsTlv().put(MlsField.PSEUDONYM, p))
        for ((p, kp, evidence) in swaps) {
            r.record(
                MlsField.SWAP,
                MlsTlv().put(MlsField.PSEUDONYM, p).put(MlsField.KEY_PACKAGE, kp)
                    .record(MlsField.SWAP_EVIDENCE, evidence.toRecord()),
            )
        }
        context?.let { r.record(MlsField.CONTEXT, it.toRecord()) }
        r.flag(MlsField.ROTATE, rotate)
        r.u32(MlsField.COMMIT_MINUTE, commitMinute)
        r.u32(MlsField.FLOOR, floor)
        r.u32(MlsField.GENERATION, generation)
        r.u64(MlsField.OPEN_EPOCH, openEpoch)
        r.put(MlsField.G_ENV, gEnv)
        return r
    }

    override fun toString(): String =
        "CommitRequest(adds=${adds.size}, removes=${removes.size}, swaps=${swaps.size}, rotate=$rotate)"
}

/** A commit's `GhostCommitAad` as a summary reports it (§19.2). */
class CommitAadView(
    /** `commit_minute`. */
    val commitMinute: Long,
    /** The rotation flag. */
    val rotate: Boolean,
    /** The admissions' evidence. */
    val admits: List<AdmitEvidence>,
    /** The swaps' evidence. */
    val swaps: List<SwapEvidence>,
) {
    override fun toString(): String = "CommitAadView(admits=${admits.size}, swaps=${swaps.size})"

    internal companion object {
        fun of(r: MlsRecord): CommitAadView = CommitAadView(
            r.u32(MlsField.COMMIT_MINUTE),
            r.flag(MlsField.ROTATE),
            r.records(MlsField.EVIDENCE).map(AdmitEvidence::of),
            r.records(MlsField.SWAP_EVIDENCE).map(SwapEvidence::of),
        )
    }
}

/**
 * A commit's validation summary (fn 6's COMMIT output; §6.4 CO-2): everything CO-1 … CO-14 read,
 * and the native verdict ([invalidReason] `null` when CO-2 holds).
 */
class CommitSummary(
    /** SHA-256 of the commit's bytes. */
    val hash: ByteArray,
    /** Its size. */
    val size: Long,
    /** The epoch the commit leaves. */
    val epoch: Long,
    /** The sender's leaf. */
    val senderLeaf: Long,
    /** The sender's pseudonym. */
    val sender: ByteArray,
    /** The sender's rank (255 for a non-committer). */
    val rank: Int,
    /** The parsed AAD, when it parsed. */
    val aad: CommitAadView?,
    /** The joins: `KP_REF`, `PSEUDONYM`, `KP_BIND`, `BOX_PK`, `CONSTANT_LIFETIME`, `CANONICAL`. */
    val adds: List<MlsRecord>,
    /** The removes: `LEAF`, `PSEUDONYM`. */
    val removes: List<MlsRecord>,
    /** The swaps: `LEAF`, `PSEUDONYM`, `SWAP_KIND`. */
    val swaps: List<MlsRecord>,
    /** The new context, when the commit changes it. */
    val context: ChannelPolicy?,
    /** Whether the commit rotates. */
    val rotates: Boolean,
    /** The update-path leaf's facts: `SIGNATURE_KEY`, `BOX_PK`, `REFRESH_EPOCH`. */
    val updateLeaf: MlsRecord?,
    /** The sender leaf's `refresh_epoch` before the commit (CO-14). */
    val senderRefreshEpoch: Long?,
    /** The member count before the commit. */
    val memberCount: Long,
    /** The staged `epoch_authenticator`. */
    val epochAuthenticator: ByteArray?,
    /** `null` when CO-2 holds, else the rule it breaks. */
    val invalidReason: MlsCommitReason?,
) {
    /** Whether CO-2 holds. */
    val isValid: Boolean get() = invalidReason == null

    override fun toString(): String = "CommitSummary(epoch=$epoch, rank=$rank, valid=$isValid)"

    internal companion object {
        fun of(r: MlsRecord): CommitSummary {
            val verdict = r.byte(MlsField.VERDICT)
            return CommitSummary(
                hash = r.bytes(MlsField.HASH),
                size = r.u32(MlsField.SIZE),
                epoch = r.i64(MlsField.EPOCH),
                senderLeaf = r.u32(MlsField.SENDER_LEAF),
                sender = r.bytes(MlsField.SENDER),
                rank = r.byte(MlsField.RANK),
                aad = r.recordOrNull(MlsField.AAD)?.let(CommitAadView::of),
                adds = r.records(MlsField.ADD),
                removes = r.records(MlsField.REMOVE),
                swaps = r.records(MlsField.SWAP),
                context = r.recordOrNull(MlsField.CONTEXT)?.let(ChannelPolicy::of),
                rotates = r.flag(MlsField.ROTATES),
                updateLeaf = r.recordOrNull(MlsField.UPDATE_LEAF),
                senderRefreshEpoch = r.i64OrNull(MlsField.SENDER_REFRESH_EPOCH),
                memberCount = r.u32(MlsField.MEMBER_COUNT),
                epochAuthenticator = r.bytesOrNull(MlsField.EPOCH_AUTHENTICATOR),
                invalidReason = if (verdict == 0) {
                    null
                } else {
                    MlsCommitReason.fromWire(verdict) ?: throw IllegalStateException("unknown verdict")
                },
            )
        }
    }
}

/** A held blob of `trialCount` and the namespace it came from (CO-3). */
class HeldBlob(
    /** The namespace. */
    val ns: ByteArray,
    /** The blob. */
    val blob: ByteArray,
) {
    override fun toString(): String = "HeldBlob(${blob.size} bytes)"
}
