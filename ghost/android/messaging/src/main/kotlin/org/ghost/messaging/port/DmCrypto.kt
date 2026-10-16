package org.ghost.messaging.port

import org.ghost.crypto.bridge.DmCards
import org.ghost.crypto.bridge.DmRevocations
import org.ghost.crypto.bridge.DmSessions

/**
 * The DM **derivation** calls of §2.6 behind one port: the owner's own card, secrets and
 * generations (functions 2, 4 and 5), and, since S7, a contact's card (function 3).
 *
 * Why a port and not `DmSessions` directly. §13.1 makes `:crypto-bridge` the only module that
 * touches the JNI surface, and it already is: [NativeDmCrypto] below is the whole of the coupling.
 * What the port buys is that the **owner steps** of §7.2 — which are about transactions, guards
 * and idempotence, not about cryptography — can be driven over a real migrated v5 database without
 * a Rust toolchain in the loop, while the same steps run against the real ratchet wherever
 * `ghost-dm-host` is on the test classpath (§2.7, §15.1). Both halves are exercised: the fake
 * proves the transaction behaviour on every machine, the native one proves this wiring.
 *
 * It exposes no session call and no seal: those are [DmEnvelopes], whose only implementation is
 * the native one. The split is by **fakeability**, and that is the honest line — a derivation is
 * a deterministic function of its inputs and a fake of it proves what the owner steps are about,
 * while a fake ratchet or a fake seal would prove only its own arithmetic (§15.1).
 */
interface DmCrypto {

    /** True while a DM context is open; false maps to `CRYPTO_UNAVAILABLE` at the facade (§13.2). */
    fun isAvailable(): Boolean

    /**
     * M1 `sealBegin` for the sender pipeline (Phase 11 design §3.7): the media worker's sealer,
     * over this context's handle. `K_f` never crosses this boundary; a null handle (a locked or
     * missing context) answers [MediaSealerFactory.Begun.Unavailable].
     */
    fun beginMediaSealer(
        destId: ByteArray,
        kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        viewOnce: Boolean,
        maxClass: Int,
    ): org.ghost.media.send.MediaSealerFactory.Begun

    /** §2.6 function 2: the own card, its two namespaces, and the publication offset of §5.4. */
    fun ownCard(cardIndex: Int): DmSessions.OwnCard?

    /** §2.6 function 4: the own bearer secrets of one ES slot (`RX`, `D`, `RP`). */
    fun ownSecrets(cardIndex: Int, slot: Int): DmSessions.OwnSecrets?

    /** §2.6 function 5: a fresh generation, signed into a bundle v2 and sealed under `KB_i`. */
    fun bundleCreate(cardIndex: Int, bundleWeek: Long, bundleRank: Int, genId: Int): DmSessions.BundleGeneration?

    /** The wrapped `session_state_key` of the open context, for `dm_self` at ACTIVATE (§2.5). */
    fun stateKeyWrapped(): ByteArray?

    /** §2.6 function 3: the fail-closed parse of a contact card v2 (§3.3). Added by S7. */
    fun parseCard(card: ByteArray): DmCards.ParseResult

    /**
     * §2.6 function 3: a contact's card-level values for one ES slot (§3.2). Added by S7, and
     * needed by KEEPER as well as by establishment: a contact's deposit and fetch credentials are
     * card-derived (§7.2's KEEPER row, §22.11 item 7).
     */
    fun deriveCard(card: ByteArray, slot: Int): DmCards.DeriveResult

    /**
     * §2.6 function 17: safety number v1 (§8.4). Added by S8.
     *
     * A deterministic function of four public keys, with no clock and no network I/O (T31), which
     * is why it is on this port and not on [DmEnvelopes]: it is exactly the shape a fake can stand
     * in for, and the digits themselves are pinned by `dm_safety_number.txt` in the crate and by
     * the independent JDK implementation §8.4 requires.
     */
    fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): DmSessions.SafetyNumber?

    /** Function 23: a revocation certificate v2 for this identity (§8.5). Added by S8. */
    fun issueRevocation(issuedMinute: Long, reason: DmRevocations.Reason): DmRevocations.Issued

    /** Function 23: parse and verify one, against a contact's pinned key (§8.5). Added by S8. */
    fun verifyRevocation(certificate: ByteArray, expectedIdentityPk: ByteArray): DmRevocations.Verified
}

/**
 * [DmCrypto] over the real JNI surface. It holds the [DmContext] rather than a handle, so a
 * context closed between two calls — a lock, a wipe — is the routine `CRYPTO_UNAVAILABLE` of §2.7
 * and never a call on a stale handle.
 */
class NativeDmCrypto(private val context: DmContext) : DmCrypto {

    override fun isAvailable(): Boolean = context.handleOrNull() != null

    override fun beginMediaSealer(
        destId: ByteArray,
        kind: org.ghost.crypto.bridge.MediaCrypto.Kind,
        viewOnce: Boolean,
        maxClass: Int,
    ): org.ghost.media.send.MediaSealerFactory.Begun {
        val handle = context.handleOrNull() ?: return org.ghost.media.send.MediaSealerFactory.Begun.Unavailable
        return when (val begun = org.ghost.media.send.NativeStreamSealer.begin(handle, destId, kind, viewOnce, maxClass)) {
            is org.ghost.media.send.NativeStreamSealer.Companion.Begun.Ok ->
                org.ghost.media.send.MediaSealerFactory.Begun.Ok(begun.sealer, begun.sealer.objectId)
            org.ghost.media.send.NativeStreamSealer.Companion.Begun.Limited ->
                org.ghost.media.send.MediaSealerFactory.Begun.Limited
            // A kind the surface refuses is this caller's own bug, unreachable from the engine's
            // two kinds; surfaced as Unavailable rather than a third shape at the port.
            org.ghost.media.send.NativeStreamSealer.Companion.Begun.NonCanonical,
            org.ghost.media.send.NativeStreamSealer.Companion.Begun.Unavailable,
            -> org.ghost.media.send.MediaSealerFactory.Begun.Unavailable
        }
    }

    override fun ownCard(cardIndex: Int): DmSessions.OwnCard? {
        val handle = context.handleOrNull() ?: return null
        return DmSessions.ownCard(handle, cardIndex)
    }

    override fun ownSecrets(cardIndex: Int, slot: Int): DmSessions.OwnSecrets? {
        val handle = context.handleOrNull() ?: return null
        return DmSessions.ownSecrets(handle, cardIndex, slot)
    }

    override fun bundleCreate(
        cardIndex: Int,
        bundleWeek: Long,
        bundleRank: Int,
        genId: Int,
    ): DmSessions.BundleGeneration? {
        val handle = context.handleOrNull() ?: return null
        return DmSessions.bundleCreate(handle, cardIndex, bundleWeek, bundleRank, genId)
    }

    override fun stateKeyWrapped(): ByteArray? = context.stateKeyWrapped()

    override fun parseCard(card: ByteArray): DmCards.ParseResult = DmCards.parse(card)

    override fun deriveCard(card: ByteArray, slot: Int): DmCards.DeriveResult {
        val handle = context.handleOrNull() ?: return DmCards.DeriveResult.Unavailable
        return DmCards.derive(handle, card, slot)
    }

    override fun safetyNumber(
        ownIdentityPk: ByteArray,
        ownOlm: ByteArray,
        peerIdentityPk: ByteArray,
        peerOlm: ByteArray,
    ): DmSessions.SafetyNumber? =
        DmSessions.safetyNumber(ownIdentityPk, ownOlm, peerIdentityPk, peerOlm)

    override fun issueRevocation(
        issuedMinute: Long,
        reason: DmRevocations.Reason,
    ): DmRevocations.Issued {
        val handle = context.handleOrNull() ?: return DmRevocations.Issued.Unavailable
        return DmRevocations.issue(handle, issuedMinute, reason)
    }

    override fun verifyRevocation(
        certificate: ByteArray,
        expectedIdentityPk: ByteArray,
    ): DmRevocations.Verified = DmRevocations.verify(certificate, expectedIdentityPk)

    override fun toString(): String = "NativeDmCrypto"
}
