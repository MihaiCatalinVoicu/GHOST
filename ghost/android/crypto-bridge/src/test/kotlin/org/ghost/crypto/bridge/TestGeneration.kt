package org.ghost.crypto.bridge

/**
 * The fixtures the session tests need, built **through the real surface** rather than hand-rolled:
 * a device's Olm identity comes from `ownCard` and its bundle generation from `bundleCreate`,
 * exactly as the owner side will build them in slice S6.
 *
 * Nothing here reimplements a derivation or a wrapping: if a test could produce a generation
 * envelope by itself, it would be testing its own arithmetic instead of the native code.
 */
internal class TestGeneration(
    val genId: Int,
    val olmIdentity: ByteArray,
    val fallbackPublic: ByteArray,
    val xwingPublic: ByteArray,
    val secretsEnv: ByteArray,
    val blob: ByteArray,
) {
    companion object {
        private const val CARD_INDEX = 0
        private const val BUNDLE_WEEK = 2_870L
        private const val BUNDLE_RANK = 0

        /** The Olm identity a peer pins for this context. */
        fun olmIdentityOf(handle: Long): ByteArray =
            requireNotNull(DmSessions.ownCard(handle, CARD_INDEX)) { "ownCard" }.olmIdentity

        /** A fresh generation of this context, as `OWNER-WEEK` would publish it. */
        fun of(handle: Long, genId: Int = 0x51_4f_00_01): TestGeneration {
            val card = requireNotNull(DmSessions.ownCard(handle, CARD_INDEX)) { "ownCard" }
            val bundle = requireNotNull(
                DmSessions.bundleCreate(handle, CARD_INDEX, BUNDLE_WEEK, BUNDLE_RANK, genId),
            ) { "bundleCreate" }
            return TestGeneration(
                genId = genId,
                olmIdentity = card.olmIdentity,
                fallbackPublic = bundle.fallbackPublic,
                xwingPublic = bundle.xwingPublic,
                secretsEnv = bundle.secretsEnv,
                blob = bundle.blob,
            )
        }
    }
}
