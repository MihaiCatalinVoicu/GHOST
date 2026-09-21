package org.ghost.crypto.bridge

/**
 * The revocation certificate v2 of Phase 9 design §8.5, as function 23 of the closed surface
 * (added by slice S8).
 *
 * **Both halves are in Rust, and that is the rule rather than a preference** (X-21, §2.4 as
 * corrected by S0′ V-14). Issuing needs the `ghost1` Ed25519 seed, which lives inside the DM
 * context and is not one of the three things §3.2 lets Kotlin hold; verifying needs
 * `ed25519-dalek`'s `verify_strict`, which refuses mixed-order keys and nonces that BouncyCastle's
 * cofactored equation accepts — so a Kotlin verifier would accept certificates the crate refuses,
 * and "strict in both" is not reachable through BouncyCastle's public API.
 *
 * A certificate **only blocks**: it moves a contact to the terminal `revoked` state. A thief
 * holding the seed gains nothing by forging one, which is why there is no freshness rule here
 * beyond the signature and the pinned-identity check.
 */
object DmRevocations {

    /** Why an identity was revoked (the Phase 3 code set, kept by v2). */
    enum class Reason(val code: Int) {
        DEVICE_LOST(1),
        DEVICE_COMPROMISED(2),
        KEY_ROTATION(3),
        ;

        internal companion object {
            fun ofCode(code: Int): Reason? = entries.firstOrNull { it.code == code }
        }
    }

    /** What [issue] produced. */
    sealed interface Issued {
        /** The 102 certificate bytes, ready to ride in an L0's `revocation` TLV (§7.1). */
        class Ok(val certificate: ByteArray) : Issued {
            override fun toString(): String = "Issued.Ok(${certificate.size} bytes)"
        }

        /** A reason code outside §8.5's set. */
        data object NonCanonical : Issued

        /** The DM context is closed or the library is missing (§2.7). */
        data object Unavailable : Issued
    }

    /** What [verify] found. */
    sealed interface Verified {
        /** A certificate that parses and verifies under the identity it names. */
        class Ok(val identityPk: ByteArray, val issuedMinute: Long, val reason: Reason?) : Verified {
            /** Never shows the identity (T3). */
            override fun toString(): String = "Verified.Ok(reason=$reason)"
        }

        /** Wrong length, wrong version, or a reason code this version does not define. */
        data object NonCanonical : Verified

        /** It names an identity other than this contact's pinned one (§8.3). */
        data object WrongIdentity : Verified

        /** The signature does not verify strictly under the key the certificate carries. */
        data object BadSignature : Verified

        /** The library is missing (§2.7). */
        data object Unavailable : Verified
    }

    /**
     * §8.5 `issueRevocation`: a certificate for the identity this context holds the seed of.
     *
     * [issuedMinute] is **minutes since the Unix epoch**, supplied by the caller because nothing in
     * the crate reads a clock (G-R8), and the certificate carries no finer unit (T13).
     */
    fun issue(handle: Long, issuedMinute: Long, reason: Reason): Issued {
        if (!DmNative.isAvailable()) return Issued.Unavailable
        val result = call { DmNative.revocationIssue(handle, issuedMinute.toInt(), reason.code) }
        return when (result.code) {
            DmCode.OK -> Issued.Ok(result.bytes(DmField.REVOCATION))
            DmCode.NON_CANONICAL -> Issued.NonCanonical
            DmCode.CRYPTO_UNAVAILABLE -> Issued.Unavailable
            else -> unexpected(result.code, "revocationIssue")
        }
    }

    /**
     * §8.5: parses and verifies a certificate that arrived in an L0's `revocation` TLV.
     *
     * [expectedIdentityPk] is the contact's **pinned** `identity_pk`. GHOST never links two
     * Ed25519 identities, so a certificate that verifies under its own key but names another
     * identity is [Verified.WrongIdentity] and is never applied to the row it arrived on.
     */
    fun verify(certificate: ByteArray, expectedIdentityPk: ByteArray): Verified {
        if (!DmNative.isAvailable()) return Verified.Unavailable
        val result = call { DmNative.revocationVerify(certificate, expectedIdentityPk) }
        return when (result.code) {
            DmCode.OK -> Verified.Ok(
                identityPk = result.bytes(DmField.IDENTITY_PK),
                issuedMinute = result.u32(DmField.ISSUED_MINUTE),
                reason = Reason.ofCode(result.byte(DmField.REVOCATION_REASON)),
            )
            DmCode.NON_CANONICAL -> Verified.NonCanonical
            DmCode.INVALID_CARD -> Verified.WrongIdentity
            DmCode.BAD_SIGNATURE -> Verified.BadSignature
            DmCode.CRYPTO_UNAVAILABLE -> Verified.Unavailable
            else -> unexpected(result.code, "revocationVerify")
        }
    }

    /** The shared decoder of [dmCall]; see `DmFacade.kt` for why it lives beside the facades. */
    private inline fun call(body: () -> ByteArray?): DmResult = dmCall(body)
}
