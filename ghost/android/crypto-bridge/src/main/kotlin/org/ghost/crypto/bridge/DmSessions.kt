package org.ghost.crypto.bridge

/**
 * The GHOST-typed session facade of Phase 9 design §2.6 ("Typed facade", §21.6 point 6).
 *
 * `:messaging` calls this and never [DmNative]: every library error already has a typed code here,
 * and the three signals libsignal gave only implicitly are explicit —
 * output kind ([Encrypted.isPreKey]), acknowledgement ([Encrypted.acknowledged]) and which slot
 * decrypted ([Decrypted.slot]). `INTERNAL` is only a caught Rust panic and is the one outcome that
 * throws, because the caller must roll back its transaction and count the blob against the poison
 * guard (§7.4 R2, §7.8).
 *
 * **Value semantics (§7.9).** Every call takes stored envelopes and returns new envelopes; nothing
 * is cached across calls or transactions. The caller writes returned state **only inside the
 * calling transaction and only on `Ok`** — which is what makes a failed decrypt leave the stored
 * envelope byte-identical, the property V-10 proved and mutant MC-29 detects.
 *
 * **Recorded deviation from §2.6's signatures.** The design writes `DmSessions.decrypt(tx, contact,
 * l1)`. `:crypto-bridge` has no dependency on `:storage` or `:messaging` and must not gain one
 * (§13.1: it is the JNI wrapper and the typed facade, nothing else), so the functions here take
 * the **row values** the caller has already read inside its transaction — the contact id, the two
 * slots' session ids and wrapped envelopes — and return the new envelope for the caller to write.
 * The `tx`/`contact` shape of §2.6 is the `:messaging` wrapper that S7 builds on top of this, and
 * the transaction rule is unchanged: the write happens in the caller's transaction, on `Ok` only.
 *
 * For the same reason §2.6's `created` and `renewed` are not outputs here: both are **GHOST
 * decisions under R-SS1** ("an explicit GHOST decision rather than a library side effect", §8.2),
 * taken by the layer that owns the two `olm_session` slots. What the library can tell us — which
 * slot decrypted, whether the session is acknowledged, whether the output was a PreKey message —
 * is what this facade returns.
 *
 * **One outcome per code the function can produce.** The `when` arms below are the code set of the
 * native function, `DmNative`'s `FUNCTION_CODES` table, which `DmResultCodesTest` compares with
 * these arms in both directions — a code with no arm would throw where the design asks for an
 * outcome, and an arm for a code the function cannot return is a stale surface. Review round 2
 * found the first kind: a first flight past Olm's 2 000-message gap reached `sessionInbound` as
 * `GAP_TOO_BIG`, which no arm named, so an ordinary inbound blob threw (fixed in the crate: every
 * inner decryption failure of a session **creation** is `UNDECRYPTABLE`, §2.6 function 14's own
 * code). `INTERNAL` — a caught Rust panic — is therefore the one outcome that throws, as §2.6
 * states it, and [unexpected] otherwise fires only on a disagreement between this class and the
 * library.
 *
 * `OVERSIZE` belongs to function 8 alone, so [Encrypted] carries it and [Decrypted], [Inbound],
 * [Outbound] and [Pruned] do not: the native side reports a state that does not fit as
 * `STATE_CORRUPT` on those paths (`olm::session`'s `stored_state`). `NON_CANONICAL` is the native
 * side's answer to a row value or a published key whose **length** is not the one the surface
 * takes; it joins `STATE_CORRUPT` wherever it can appear, because the caller's move is the same —
 * the row it holds cannot be used and must not be retried.
 */
object DmSessions {

    /** A stored session row, as the two-slot trial of §7.6 needs it. */
    data class StoredSlot(
        /** `olm_session.session_id`, 32 raw bytes. */
        val sessionId: ByteArray,
        /** `olm_session.state_env`, the wrapped state. */
        val stateEnv: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is StoredSlot &&
                sessionId.contentEquals(other.sessionId) &&
                stateEnv.contentEquals(other.stateEnv)

        override fun hashCode(): Int = 31 * sessionId.contentHashCode() + stateEnv.contentHashCode()
    }

    /** Which stored slot a message decrypted on (§8.2). */
    enum class Slot {
        /** `current`: the slot every send uses. */
        CURRENT,

        /** `previous`: receive only, with a `retire_day`. */
        PREVIOUS,
        ;

        internal companion object {
            fun fromWire(value: Int): Slot? = when (value) {
                0 -> CURRENT
                1 -> PREVIOUS
                else -> null
            }
        }
    }

    /** The outcome of [outbound] (§2.6 function 7). */
    sealed interface Outbound {
        /** A new initiator session. The caller inserts the row and wraps nothing itself. */
        data class Ok(
            /** `olm_session.state_env`. */
            val stateEnv: ByteArray,
            /** `olm_session.session_id`. */
            val sessionId: ByteArray,
            /** `olm_session.prov_env`: the wrapped `reply_seed` provisional mode is keyed from. */
            val replySeedEnv: ByteArray,
        ) : Outbound

        /** The contact's published key is malformed or non-contributory (§22.8.2 rule 1). */
        data object InvalidKey : Outbound

        /**
         * The row values this call was given are not the shapes the surface takes, or the state
         * the fresh session encodes to does not fit `SESSION_STATE_MAX` (`olm::session`'s
         * `stored_state`). Recorded against §2.6 function 7, whose code column names `INVALID_KEY`
         * alone: the native function can produce both codes and an outcome is what the facade owes
         * the caller (review round 2, S4B2-03/R2-01).
         */
        data object StateCorrupt : Outbound

        /** The native library is missing or the context is closed (§2.5). */
        data object Unavailable : Outbound
    }

    /** The outcome of [encrypt] (§2.6 function 8). */
    sealed interface Encrypted {
        /** One ratchet step. The caller writes [stateEnv] in the same transaction. */
        data class Ok(
            /** The Olm message. */
            val l1: ByteArray,
            /** Whether the library produced a PreKey message. */
            val isPreKey: Boolean,
            /** Whether the peer has answered this session. */
            val acknowledged: Boolean,
            /** The new `olm_session.state_env`. */
            val stateEnv: ByteArray,
        ) : Encrypted

        /** A library encryption error (§22.8.2 rule 2). */
        data object InvalidSession : Encrypted

        /**
         * The state does not open under its binding or does not parse (§22.8.3), or a row value
         * this call was given is not the shape the surface takes (`NON_CANONICAL`).
         */
        data object StateCorrupt : Encrypted

        /** The state grew past `SESSION_STATE_MAX`: a bug or a format change (§7.9 point 4). */
        data object Oversize : Encrypted

        /** The native library is missing or the context is closed. */
        data object Unavailable : Encrypted
    }

    /** The outcome of [decrypt] (§2.6 function 13). */
    sealed interface Decrypted {
        /** The message decrypted on [slot]. The caller writes [stateEnv] for that slot. */
        data class Ok(
            /** The L0 content. */
            val plaintext: ByteArray,
            /** Which stored slot decrypted. */
            val slot: Slot,
            /** Whether that session is now acknowledged. */
            val acknowledged: Boolean,
            /** The new `olm_session.state_env` of that slot. */
            val stateEnv: ByteArray,
        ) : Decrypted

        /** The message key is gone: used, evicted or never stored. A replay, not a forgery. */
        data object Duplicate : Decrypted

        /** A forward gap beyond Olm's 2 000 (§7.7 point 3). */
        data object GapTooBig : Decrypted

        /** A MAC, padding or format failure: consumed silently (T28). */
        data object Undecryptable : Decrypted

        /** The state does not open under its binding or does not parse. */
        data object StateCorrupt : Decrypted

        /** The native library is missing or the context is closed. */
        data object Unavailable : Decrypted
    }

    /** The outcome of [inbound] (§2.6 function 14). */
    sealed interface Inbound {
        /** A new responder session and the first flight's content. */
        data class Ok(
            /** The L0 content of the first flight. */
            val plaintext: ByteArray,
            /** `olm_session.state_env`. */
            val stateEnv: ByteArray,
            /** `olm_session.session_id`. */
            val sessionId: ByteArray,
        ) : Inbound

        /** The PreKey message names a fallback key this generation does not hold (§2.2). */
        data object MissingKey : Inbound

        /**
         * The PreKey message's identity is not the pinned one. **Never a key change on its own**
         * (§8.3): a drop, counted `untrusted`, with no state change.
         */
        data object IdentityMismatch : Inbound

        /** A non-contributory key in the first flight (§22.8.2). */
        data object InvalidKey : Inbound

        /**
         * A MAC, padding, format or session-config failure (S0′ V-2), and every other way the
         * first flight's inner message fails to decrypt — an inner chain index past Olm's
         * 2 000-message gap included, which vodozemac reports before the MAC and which any holder
         * of the card can author (review round 2, S4B2-01/R2-01).
         */
        data object Undecryptable : Inbound

        /** The generation secrets do not open under their binding. */
        data object StateCorrupt : Inbound

        /** The native library is missing or the context is closed. */
        data object Unavailable : Inbound
    }

    /** The outcome of [chainPosition] (§2.6 function 19). */
    sealed interface ChainPosition {
        /** The named chain exists; this is the next index the gap hold compares against. */
        data class Index(val nextIndex: Long) : ChainPosition

        /** The chains are readable and none matches — the hold reads this as position 0. */
        data object NewChain : ChainPosition

        /**
         * The stored state, or vodozemac's pickle layout, drifted (§2.1 rule 2), or a row value
         * this call was given is not the shape the surface takes (`NON_CANONICAL`).
         */
        data object StateCorrupt : ChainPosition

        /** The native library is missing or the context is closed. */
        data object Unavailable : ChainPosition
    }

    /** The outcome of [prune] (§2.6 function 20). */
    sealed interface Pruned {
        /** The new state and how many skipped keys the age bound removed. */
        data class Ok(val stateEnv: ByteArray, val removed: Long) : Pruned

        /**
         * The stored state, or vodozemac's pickle layout, drifted, or a row value this call was
         * given is not the shape the surface takes (`NON_CANONICAL`).
         */
        data object StateCorrupt : Pruned

        /** The native library is missing or the context is closed. */
        data object Unavailable : Pruned
    }

    /**
     * Opens a DM context (§2.5). The three arrays are **zeroised here** after the call, which is
     * the "the Kotlin caller zeroises its arrays after the call (best effort)" of §2.5: best
     * effort because the JVM may have copied them during GC, which is exactly why the derived
     * secrets live in native memory from here on and the JVM heap never holds a ratchet, KEM or
     * seal opening key. The native side holds them until [closeContext].
     */
    fun openContext(
        messagingBranch: ByteArray,
        identitySeed: ByteArray,
        sessionStateKey: ByteArray,
    ): Long? = try {
        // The availability check is **inside** the `try`: a missing or unloadable library is the
        // routine `CRYPTO_UNAVAILABLE` of §2.7, and it is the one path where the three arrays are
        // not consumed natively, so it is the one path that must not hand them back populated.
        if (!DmNative.isAvailable()) {
            null
        } else {
            val result = call { DmNative.ctxOpen(messagingBranch, identitySeed, sessionStateKey) }
            if (result.isOk) result.i64(DmField.HANDLE) else null
        }
    } finally {
        messagingBranch.fill(0)
        identitySeed.fill(0)
        sessionStateKey.fill(0)
    }

    /** Closes a DM context; a second close is a no-op from the caller's point of view. */
    fun closeContext(handle: Long) {
        if (!DmNative.isAvailable()) return
        call { DmNative.ctxClose(handle) }
    }

    /**
     * The own card and the values derived from it (§2.6 function 2, §3.2). Kotlin holds the
     * **recognition** keys in clear and never the opening keys `KIO_i` and `KB_i` themselves
     * (rule R-S6).
     */
    data class OwnCard(
        /** The 131-byte contact card v2. */
        val card: ByteArray,
        /** The inbox namespace `X_i`. */
        val inboxNamespace: ByteArray,
        /** The bundle namespace `P_i`. */
        val bundleNamespace: ByteArray,
        /** The recognition key of the intro outer key. */
        val recognitionIntro: ByteArray,
        /** The recognition key of the bundle seal key. */
        val recognitionBundle: ByteArray,
        /** The own Olm identity public key, which every contact pins. */
        val olmIdentity: ByteArray,
        /**
         * `t_pub(w) − start(w)` in seconds: the fixed weekly offset at which the owner
         * republishes its bundle (§5.4). **Added by S6** to §2.6 function 2's outputs, because the
         * scheduler that wakes at `t_pub(w)` is in `:messaging` while the schedule key `S_i` it
         * comes from must not leave the native context — it is not one of the three things §3.2
         * lets Kotlin hold.
         */
        val publicationOffsetSeconds: Long,
    )

    /** A freshly created bundle generation (§2.6 function 5, §5.3). */
    data class BundleGeneration(
        /** The sealed 4 KiB bundle blob, ready for the bundle namespace. */
        val blob: ByteArray,
        /** `olm_prekey_gen.fallback_pub`. */
        val fallbackPublic: ByteArray,
        /** The generation's X-Wing public key `Q_g`. */
        val xwingPublic: ByteArray,
        /** `olm_prekey_gen.secrets_env`: the wrapped fallback secret and X-Wing seed. */
        val secretsEnv: ByteArray,
    )

    /** §2.6 function 2. */
    fun ownCard(handle: Long, cardIndex: Int): OwnCard? {
        if (!DmNative.isAvailable()) return null
        val result = call { DmNative.ownCard(handle, cardIndex) }
        if (!result.isOk) return null
        return OwnCard(
            card = result.bytes(DmField.CARD),
            inboxNamespace = result.bytes(DmField.INBOX_NAMESPACE),
            bundleNamespace = result.bytes(DmField.BUNDLE_NAMESPACE),
            recognitionIntro = result.bytes(DmField.RECOGNITION_INTRO),
            recognitionBundle = result.bytes(DmField.RECOGNITION_BUNDLE),
            olmIdentity = result.bytes(DmField.OLM_IDENTITY),
            publicationOffsetSeconds = result.u32(DmField.PUBLICATION_OFFSET),
        )
    }

    /**
     * The own bearer secrets of one relay slot (§2.6 function 4 as S6 extends it; §3.1, §3.2,
     * §4.8). These are the DM secrets the design lets Kotlin hold **unwrapped**, because they are
     * exactly the secrets that go on the wire: the owner puts each into a 67-byte [CredentialV3]
     * and the relay only ever stores a [CredentialV3.verifier] of it.
     *
     * Callers zeroise the arrays once the credential or the verifier is built; they are the
     * caller's arrays, so this facade cannot do it for them the way [openContext] does for its own
     * inputs.
     */
    class OwnSecrets(
        /** `RX_{i,s}`: seed-derived, the D11 key no card holder can compute (§3.1). */
        val read: ByteArray,
        /** `D_{i,s}`: card-derived, what every holder of the card presents to deposit (§3.2). */
        val deposit: ByteArray,
        /** `RP_{i,s}`: card-derived, the bundle fetch secret, registered as kind FETCH. */
        val fetch: ByteArray,
    ) {
        /** Zeroises all three. */
        fun clear() {
            read.fill(0)
            deposit.fill(0)
            fetch.fill(0)
        }

        override fun toString(): String = "OwnSecrets(redacted)"
    }

    /** §2.6 function 4. Null when the library is missing or the call failed. */
    fun ownSecrets(handle: Long, cardIndex: Int, slot: Int): OwnSecrets? {
        if (!DmNative.isAvailable()) return null
        val result = call { DmNative.ownReadSecret(handle, cardIndex, slot) }
        if (!result.isOk) return null
        return OwnSecrets(
            read = result.bytes(DmField.READ_SECRET),
            deposit = result.bytes(DmField.DEPOSIT_SECRET),
            fetch = result.bytes(DmField.FETCH_SECRET),
        )
    }

    /** §2.6 function 5: a fresh generation, signed into a bundle v2 and sealed under `KB_i`. */
    fun bundleCreate(
        handle: Long,
        cardIndex: Int,
        bundleWeek: Long,
        bundleRank: Int,
        genId: Int,
    ): BundleGeneration? {
        if (!DmNative.isAvailable()) return null
        val result = call { DmNative.bundleCreate(handle, cardIndex, bundleWeek, bundleRank, genId) }
        if (!result.isOk) return null
        return BundleGeneration(
            blob = result.bytes(DmField.BLOB),
            fallbackPublic = result.bytes(DmField.FALLBACK_PUBLIC),
            xwingPublic = result.bytes(DmField.XWING_PUBLIC),
            secretsEnv = result.bytes(DmField.GENERATION_SECRETS),
        )
    }

    /** §2.6 function 7: a new initiator session toward a contact's published bundle keys. */
    fun outbound(
        handle: Long,
        contactId: ByteArray,
        peerOlmIdentity: ByteArray,
        peerFallbackKey: ByteArray,
        today: Int,
    ): Outbound {
        if (!DmNative.isAvailable()) return Outbound.Unavailable
        val result = call {
            DmNative.sessionOutbound(handle, contactId, peerOlmIdentity, peerFallbackKey, today)
        }
        return when (result.code) {
            DmCode.OK -> Outbound.Ok(
                stateEnv = result.bytes(DmField.STATE),
                sessionId = result.bytes(DmField.SESSION_ID),
                replySeedEnv = result.bytes(DmField.REPLY_SEED),
            )
            DmCode.INVALID_KEY -> Outbound.InvalidKey
            DmCode.STATE_CORRUPT, DmCode.NON_CANONICAL -> Outbound.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Outbound.Unavailable
            else -> unexpected(result.code, "sessionOutbound")
        }
    }

    /** §2.6 function 8: one ratchet step on the `current` slot. */
    fun encrypt(
        handle: Long,
        contactId: ByteArray,
        current: StoredSlot,
        l0: ByteArray,
        today: Int,
    ): Encrypted {
        if (!DmNative.isAvailable()) return Encrypted.Unavailable
        val result = call {
            DmNative.encrypt(handle, contactId, current.sessionId, current.stateEnv, l0, today)
        }
        return when (result.code) {
            DmCode.OK -> {
                val flags = result.byte(DmField.FLAGS)
                Encrypted.Ok(
                    l1 = result.bytes(DmField.L1),
                    isPreKey = flags and DM_FLAG_PRE_KEY != 0,
                    acknowledged = flags and DM_FLAG_ACKNOWLEDGED != 0,
                    stateEnv = result.bytes(DmField.STATE),
                )
            }
            DmCode.INVALID_SESSION -> Encrypted.InvalidSession
            DmCode.STATE_CORRUPT, DmCode.NON_CANONICAL -> Encrypted.StateCorrupt
            DmCode.OVERSIZE -> Encrypted.Oversize
            DmCode.CRYPTO_UNAVAILABLE -> Encrypted.Unavailable
            else -> unexpected(result.code, "encrypt")
        }
    }

    /**
     * §2.6 function 13: the two-slot trial of §7.6. A missing message key on one slot and a MAC
     * failure on the other is [Decrypted.Duplicate] — a replay must not be counted as a forgery.
     */
    fun decrypt(
        handle: Long,
        contactId: ByteArray,
        current: StoredSlot?,
        previous: StoredSlot?,
        l1: ByteArray,
        isPreKey: Boolean,
        today: Int,
    ): Decrypted {
        if (!DmNative.isAvailable()) return Decrypted.Unavailable
        if (current == null && previous == null) return Decrypted.Undecryptable
        val result = call {
            DmNative.decrypt(
                handle,
                contactId,
                current?.sessionId ?: EMPTY,
                current?.stateEnv ?: EMPTY,
                previous?.sessionId ?: EMPTY,
                previous?.stateEnv ?: EMPTY,
                l1,
                if (isPreKey) 1 else 0,
                today,
            )
        }
        return when (result.code) {
            DmCode.OK -> {
                val slot = Slot.fromWire(result.byte(DmField.SLOT_USED))
                    ?: throw IllegalStateException("DM reply names an unknown slot")
                Decrypted.Ok(
                    plaintext = result.bytes(DmField.L0),
                    slot = slot,
                    acknowledged = result.byte(DmField.FLAGS) and DM_FLAG_ACKNOWLEDGED != 0,
                    stateEnv = result.bytes(DmField.STATE),
                )
            }
            DmCode.DUPLICATE_OR_LOST -> Decrypted.Duplicate
            DmCode.GAP_TOO_BIG -> Decrypted.GapTooBig
            DmCode.UNDECRYPTABLE, DmCode.NON_CANONICAL -> Decrypted.Undecryptable
            DmCode.STATE_CORRUPT -> Decrypted.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Decrypted.Unavailable
            else -> unexpected(result.code, "decrypt")
        }
    }

    /** §2.6 function 14: a new responder session from a first flight on generation [genId]. */
    @Suppress("LongParameterList")
    fun inbound(
        handle: Long,
        contactId: ByteArray,
        genId: Int,
        genSecretsEnv: ByteArray,
        genFallbackPublic: ByteArray,
        expectedPeerIdentity: ByteArray,
        l1: ByteArray,
        today: Int,
    ): Inbound {
        if (!DmNative.isAvailable()) return Inbound.Unavailable
        val result = call {
            DmNative.sessionInbound(
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
        return when (result.code) {
            DmCode.OK -> Inbound.Ok(
                plaintext = result.bytes(DmField.L0),
                stateEnv = result.bytes(DmField.STATE),
                sessionId = result.bytes(DmField.SESSION_ID),
            )
            DmCode.MISSING_KEY -> Inbound.MissingKey
            DmCode.IDENTITY_MISMATCH -> Inbound.IdentityMismatch
            DmCode.INVALID_KEY -> Inbound.InvalidKey
            DmCode.UNDECRYPTABLE, DmCode.NON_CANONICAL -> Inbound.Undecryptable
            DmCode.STATE_CORRUPT -> Inbound.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Inbound.Unavailable
            else -> unexpected(result.code, "sessionInbound")
        }
    }

    /**
     * §2.6 function 19: the gap hold's expected index, read from the stored state during **peek**.
     * It writes nothing and sends nothing (T28), and it runs outside any transaction.
     */
    fun chainPosition(
        handle: Long,
        contactId: ByteArray,
        slot: StoredSlot,
        ratchetKey: ByteArray,
    ): ChainPosition {
        if (!DmNative.isAvailable()) return ChainPosition.Unavailable
        val result = call {
            DmNative.chainPosition(handle, contactId, slot.sessionId, slot.stateEnv, ratchetKey)
        }
        return when (result.code) {
            DmCode.OK -> ChainPosition.Index(result.i64(DmField.CHAIN_INDEX))
            DmCode.NEW_CHAIN -> ChainPosition.NewChain
            DmCode.STATE_CORRUPT, DmCode.NON_CANONICAL -> ChainPosition.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> ChainPosition.Unavailable
            else -> unexpected(result.code, "chainPosition")
        }
    }

    /** §2.6 function 20: SWEEP's age bound on the skipped keys of a live session (§7.7 point 4). */
    fun prune(handle: Long, contactId: ByteArray, slot: StoredSlot, today: Int): Pruned {
        if (!DmNative.isAvailable()) return Pruned.Unavailable
        val result = call {
            DmNative.sessionPrune(handle, contactId, slot.sessionId, slot.stateEnv, today)
        }
        return when (result.code) {
            DmCode.OK -> Pruned.Ok(
                stateEnv = result.bytes(DmField.STATE),
                removed = result.u32(DmField.PRUNED),
            )
            DmCode.STATE_CORRUPT, DmCode.NON_CANONICAL -> Pruned.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> Pruned.Unavailable
            else -> unexpected(result.code, "sessionPrune")
        }
    }

    /** §2.6 function 17: safety number v1. Stateless and free of network I/O (T31). */
    fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): SafetyNumber? {
        if (!DmNative.isAvailable()) return null
        val result = call { DmNative.safetyNumber(ownIdentityPk, ownOlm, peerIdentityPk, peerOlm) }
        if (!result.isOk) return null
        return SafetyNumber(result.text(DmField.DIGITS), result.bytes(DmField.SCANNABLE))
    }

    /** A computed safety number: the 60 digits and the 65-byte scannable form (§8.4). */
    data class SafetyNumber(val digits: String, val scannable: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is SafetyNumber && digits == other.digits &&
                scannable.contentEquals(other.scannable)

        override fun hashCode(): Int = 31 * digits.hashCode() + scannable.contentHashCode()
    }

    private val EMPTY = ByteArray(0)

    /** The shared decoder of [dmCall]; see `DmFacade.kt` for why it lives beside the facades. */
    private inline fun call(body: () -> ByteArray?): DmResult = dmCall(body)
}
