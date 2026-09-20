package org.ghost.messaging.port

import org.ghost.crypto.bridge.DmSessions

/**
 * The three DM cryptographic calls the **owner** side needs (Phase 9 design §2.6 functions 2, 4
 * and 5), behind one port.
 *
 * Why a port and not `DmSessions` directly. §13.1 makes `:crypto-bridge` the only module that
 * touches the JNI surface, and it already is: [NativeDmCrypto] below is the whole of the coupling.
 * What the port buys is that the **owner steps** of §7.2 — which are about transactions, guards
 * and idempotence, not about cryptography — can be driven over a real migrated v5 database without
 * a Rust toolchain in the loop, while the same steps run against the real ratchet wherever
 * `ghost-dm-host` is on the test classpath (§2.7, §15.1). Both halves are exercised: the fake
 * proves the transaction behaviour on every machine, the native one proves this wiring.
 *
 * It exposes no session call. Sessions are S7's, and a port that could start one would be a place
 * for S7 material to leak into this slice.
 */
interface DmCrypto {

    /** True while a DM context is open; false maps to `CRYPTO_UNAVAILABLE` at the facade (§13.2). */
    fun isAvailable(): Boolean

    /** §2.6 function 2: the own card, its two namespaces, and the publication offset of §5.4. */
    fun ownCard(cardIndex: Int): DmSessions.OwnCard?

    /** §2.6 function 4: the own bearer secrets of one ES slot (`RX`, `D`, `RP`). */
    fun ownSecrets(cardIndex: Int, slot: Int): DmSessions.OwnSecrets?

    /** §2.6 function 5: a fresh generation, signed into a bundle v2 and sealed under `KB_i`. */
    fun bundleCreate(cardIndex: Int, bundleWeek: Long, bundleRank: Int, genId: Int): DmSessions.BundleGeneration?

    /** The wrapped `session_state_key` of the open context, for `dm_self` at ACTIVATE (§2.5). */
    fun stateKeyWrapped(): ByteArray?
}

/**
 * [DmCrypto] over the real JNI surface. It holds the [DmContext] rather than a handle, so a
 * context closed between two calls — a lock, a wipe — is the routine `CRYPTO_UNAVAILABLE` of §2.7
 * and never a call on a stale handle.
 */
class NativeDmCrypto(private val context: DmContext) : DmCrypto {

    override fun isAvailable(): Boolean = context.handleOrNull() != null

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

    override fun toString(): String = "NativeDmCrypto"
}
