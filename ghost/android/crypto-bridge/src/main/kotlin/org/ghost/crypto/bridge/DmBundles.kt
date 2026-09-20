package org.ghost.crypto.bridge

/**
 * The bundle half of the typed facade (Phase 9 design §2.6 function 6, §5.3, §5.5).
 *
 * [open] is every check of §5.5 that needs **no clock**: the blob opens under `KB_c` in the
 * contact's own bundle namespace, the version, card index and `identity_pk` are the card's, the
 * Ed25519 signature verifies under it, and the X-Wing key is validated whole (§22.8.2 rule 3).
 *
 * What stays with the caller, because it needs a clock or pinned state: validity
 * (`now < start(bundle_week + 2)` and `bundle_week ≤ week(now) + 1`), the
 * `(bundle_week, bundle_rank)` rollback rule against `dm_contact.bundle_week_seen`, and the
 * key-change classification of §8.3 when the bundle names an Olm identity other than the pinned
 * one under a signature that verifies.
 */
object DmBundles {

    /** A verified bundle v2 (§5.3). */
    class Verified(
        /** The card index the bundle belongs to; the caller's card's. */
        val cardIndex: Int,
        /** The ISO week the bundle is valid for, and in the next. */
        val bundleWeek: Long,
        /** 0 for the weekly publication, higher for an activation or restore (§5.3). */
        val bundleRank: Int,
        /** The generation this bundle publishes. */
        val genId: Int,
        /** The Olm identity key a first session pins. */
        val olmIdentity: ByteArray,
        /** The Olm fallback key `F_g` the 3DH of §8.1 runs against. */
        val fallbackKey: ByteArray,
        /** The X-Wing encapsulation key `Q_g`, 1 216 bytes, already validated whole. */
        val xwingPublic: ByteArray,
    ) {
        override fun toString(): String = "Verified(week=$bundleWeek, rank=$bundleRank)"
    }

    /** The outcome of [open]. */
    sealed interface OpenResult {
        /** The bundle opened and every signature-level check passed. */
        data class Ok(val bundle: Verified) : OpenResult

        /** The blob does not open under this card's bundle key: not this contact's bundle. */
        data object NotOpen : OpenResult

        /** It opened but does not parse exactly, or is not 4 KiB (rule R-S2). */
        data object NonCanonical : OpenResult

        /**
         * The signature does not verify under the card's `identity_pk`, or the bundle names
         * another identity or card index: a forgery, dropped with a counter (§5.5).
         */
        data object BadSignature : OpenResult

        /** The published X-Wing key is malformed or non-contributory (§22.8.2 rule 3). */
        data object InvalidKey : OpenResult

        /** The transient `KB_c` envelope does not open under its binding (§22.8.3). */
        data object StateCorrupt : OpenResult

        /** The native library is missing or the context is closed. */
        data object Unavailable : OpenResult
    }

    /** §2.6 function 6: `bundleOpen(h, kbEnv, bundleNamespace, blob, identityPk, cardIndex)`. */
    fun open(
        handle: Long,
        bundleKeyEnv: ByteArray,
        bundleNamespace: ByteArray,
        blob: ByteArray,
        expectedIdentityPk: ByteArray,
        expectedCardIndex: Int,
    ): OpenResult {
        if (!DmNative.isAvailable()) return OpenResult.Unavailable
        val result = dmCall {
            DmNative.bundleOpen(
                handle,
                bundleKeyEnv,
                bundleNamespace,
                blob,
                expectedIdentityPk,
                expectedCardIndex,
            )
        }
        return when (result.code) {
            DmCode.OK -> OpenResult.Ok(
                Verified(
                    cardIndex = result.u32(DmField.CARD_INDEX).toInt(),
                    bundleWeek = result.i64(DmField.BUNDLE_WEEK),
                    bundleRank = result.u32(DmField.BUNDLE_RANK).toInt(),
                    genId = result.u32(DmField.GEN_ID).toInt(),
                    olmIdentity = result.bytes(DmField.OLM_IDENTITY),
                    fallbackKey = result.bytes(DmField.FALLBACK_PUBLIC),
                    xwingPublic = result.bytes(DmField.XWING_PUBLIC),
                ),
            )
            DmCode.NOT_OPEN -> OpenResult.NotOpen
            DmCode.NON_CANONICAL -> OpenResult.NonCanonical
            DmCode.BAD_SIGNATURE -> OpenResult.BadSignature
            DmCode.INVALID_KEY -> OpenResult.InvalidKey
            DmCode.STATE_CORRUPT -> OpenResult.StateCorrupt
            DmCode.CRYPTO_UNAVAILABLE -> OpenResult.Unavailable
            else -> unexpected(result.code, "bundleOpen")
        }
    }
}
