package org.ghost.crypto.bridge

/**
 * The contact-card half of the typed facade (Phase 9 design §2.6 function 3, §3.2, §3.3).
 *
 * [parse] is the fail-closed parse of §3.3 and needs no context: it is what `addContact` runs on
 * bytes a QR scan or a `ghost://contact/` link produced, before anything is stored (rule R-E2).
 * [derive] is every card-level value of §3.2 for one contact and one relay slot.
 *
 * **What Kotlin may hold.** §3.2's closing sentence lets Kotlin hold three things unwrapped: the
 * **recognition** keys, the contacts' **bearer** secrets (which go on the wire inside a credential
 * v3) and the credentials themselves. The two **opening** keys `KIO_c` and `KB_c` are not among
 * them, so [Derived] carries them only as transient envelopes, which [DmSeal] and [DmBundles] hand
 * straight back to the native side (rule R-S6).
 */
object DmCards {

    /** The fields of a parsed card v2 (§3.3). The card itself stays the caller's bytes. */
    data class Parsed(
        /** The card index; 0 in Phase 9. */
        val cardIndex: Int,
        /** The owner's Ed25519 identity key, which `dm_contact.identity_pk` keys the row by. */
        val identityPk: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Parsed && cardIndex == other.cardIndex &&
                identityPk.contentEquals(other.identityPk)

        override fun hashCode(): Int = 31 * cardIndex + identityPk.contentHashCode()
    }

    /** Everything one card opens for one relay slot (§3.2). */
    class Derived(
        /** The contact's inbox namespace `X_c`, where this device deposits. */
        val inboxNamespace: ByteArray,
        /** The contact's bundle namespace `P_c`, which establishment fetches from. */
        val bundleNamespace: ByteArray,
        /**
         * The contact's media namespace `M_c` (Phase 11 design §5.1): registered at a media send,
         * orphaned once every upload of c is over. **Added by S4-owner** — the native side has
         * returned it since S2.
         */
        val mediaNamespace: ByteArray,
        /** `D_{c,s}`: the deposit secret, a bearer value for the credential v3 of that slot. */
        val deposit: ByteArray,
        /** `RP_{c,s}`: the bundle fetch secret, registered and presented as kind FETCH. */
        val fetch: ByteArray,
        /**
         * `MD_{c,s}`: the media deposit secret (Phase 11 design §5.1), a bearer value for the media
         * deposit credential v3 of that slot. **Added by S4-owner**.
         */
        val mediaDeposit: ByteArray,
        /** The recognition key of `KIO_c`: what an intro envelope **to that contact** hints. */
        val recognitionIntro: ByteArray,
        /** The recognition key of `KB_c`: what that contact's bundle hints. */
        val recognitionBundle: ByteArray,
        /** The **wrapped** intro outer key `KIO_c`, for [DmSeal.sealIntro]. */
        val introKeyEnv: ByteArray,
        /** The **wrapped** bundle seal key `KB_c`, for [DmBundles.open]. */
        val bundleKeyEnv: ByteArray,
    ) {
        /** Zeroises the three bearer secrets; the envelopes and recognition keys are not secrets. */
        fun clearSecrets() {
            deposit.fill(0)
            fetch.fill(0)
            mediaDeposit.fill(0)
        }

        override fun toString(): String = "Derived(redacted)"
    }

    /** The outcome of [parse]. */
    sealed interface ParseResult {
        /** A well-formed card v2 with a valid signature. */
        data class Ok(val card: Parsed) : ParseResult

        /**
         * Not a card v2 of this version: the wrong length, an unsupported version or card index,
         * or a signature that does not verify (§3.3 "Parse order (fail closed)").
         */
        data object InvalidCard : ParseResult

        /** The native library is missing (§2.7). */
        data object Unavailable : ParseResult
    }

    /** The outcome of [derive]. */
    sealed interface DeriveResult {
        /** The card-level values of §3.2. */
        data class Ok(val values: Derived) : DeriveResult

        /** The card does not parse (§3.3). */
        data object InvalidCard : DeriveResult

        /** The state key could not wrap the two opening keys (§22.8.3). */
        data object StateCorrupt : DeriveResult

        /** The native library is missing or the context is closed (§2.5). */
        data object Unavailable : DeriveResult
    }

    /** §2.6 function 3: `cardParse(bytes)`. */
    fun parse(card: ByteArray): ParseResult {
        if (!DmNative.isAvailable()) return ParseResult.Unavailable
        val result = dmCall { DmNative.cardParse(card) }
        return when (result.code) {
            DmCode.OK -> ParseResult.Ok(
                Parsed(
                    cardIndex = result.u32(DmField.CARD_INDEX).toInt(),
                    identityPk = result.bytes(DmField.IDENTITY_PK),
                ),
            )
            DmCode.INVALID_CARD, DmCode.NON_CANONICAL -> ParseResult.InvalidCard
            DmCode.CRYPTO_UNAVAILABLE -> ParseResult.Unavailable
            else -> unexpected(result.code, "cardParse")
        }
    }

    /** §2.6 function 3: `cardDerive(h, card, slot)`. [slot] is the relay's ES slot number. */
    fun derive(handle: Long, card: ByteArray, slot: Int): DeriveResult {
        if (!DmNative.isAvailable()) return DeriveResult.Unavailable
        val result = dmCall { DmNative.cardDerive(handle, card, slot) }
        return when (result.code) {
            DmCode.OK -> DeriveResult.Ok(
                Derived(
                    inboxNamespace = result.bytes(DmField.INBOX_NAMESPACE),
                    bundleNamespace = result.bytes(DmField.BUNDLE_NAMESPACE),
                    mediaNamespace = result.bytes(DmField.MEDIA_NAMESPACE),
                    deposit = result.bytes(DmField.DEPOSIT_SECRET),
                    fetch = result.bytes(DmField.FETCH_SECRET),
                    mediaDeposit = result.bytes(DmField.MEDIA_DEPOSIT_SECRET),
                    recognitionIntro = result.bytes(DmField.RECOGNITION_INTRO),
                    recognitionBundle = result.bytes(DmField.RECOGNITION_BUNDLE),
                    introKeyEnv = result.bytes(DmField.INTRO_KEY),
                    bundleKeyEnv = result.bytes(DmField.BUNDLE_KEY),
                ),
            )
            DmCode.INVALID_CARD, DmCode.NON_CANONICAL -> DeriveResult.InvalidCard
            DmCode.STATE_CORRUPT -> DeriveResult.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> DeriveResult.Unavailable
            else -> unexpected(result.code, "cardDerive")
        }
    }
}
