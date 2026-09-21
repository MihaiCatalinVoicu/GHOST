package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Function 23 (`revocationIssue`/`revocationVerify`) and function 24 (`l1Parse`) of the closed
 * surface, through the **real** library (Phase 9 design §2.6, §8.5, §22.8.1; added by slice S8).
 *
 * Both are new entry points, and both are on the closed list for a reason the facade cannot state
 * on its own:
 *
 *  - a revocation certificate v2 is signed with the `ghost1` seed, which lives inside the DM
 *    context, and verified with `verify_strict`, which S0′ V-14 showed BouncyCastle cannot
 *    reproduce — so a Kotlin verifier would accept certificates the crate refuses (X-21);
 *  - `l1Parse` is the one caller that holds bare L1 bytes and no envelope, the HELD replay, and a
 *    Kotlin protobuf reader over attacker-supplied bytes is what ADR-19 forbids.
 */
class DmRevocationNativeTest {

    private fun requireNative() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        assertTrue(
            "the host library must load from $path: ${DmNative.loadFailure()}",
            DmNative.isAvailable(),
        )
    }

    private fun context(branch: Int): Long {
        val handle = DmSessions.openContext(
            messagingBranch = ByteArray(32) { branch.toByte() },
            identitySeed = ByteArray(32) { (branch + 1).toByte() },
            sessionStateKey = ByteArray(32) { (branch + 2).toByte() },
        )
        assertNotNull("ctxOpen", handle)
        return handle!!
    }

    /**
     * §8.5: a certificate names the identity that signed it, carries a minute and not a second
     * (T13), and verifies under the pinned key of the contact it arrived for.
     */
    @Test
    fun aCertificateNamesItsOwnIdentityAndVerifiesUnderIt() {
        requireNative()
        val handle = context(0x91)
        try {
            val own = requireNotNull(DmSessions.ownCard(handle, 0))
            val identityPk = own.card.copyOfRange(3, 35)

            val issued = DmRevocations.issue(handle, 29_000_000, DmRevocations.Reason.DEVICE_LOST)
            val certificate = (issued as DmRevocations.Issued.Ok).certificate
            assertEquals(102, certificate.size)
            assertEquals("version 2 (§8.5)", 2, certificate[0].toInt())

            val verified = DmRevocations.verify(certificate, identityPk)
            assertTrue("it verifies under the key it names", verified is DmRevocations.Verified.Ok)
            verified as DmRevocations.Verified.Ok
            assertArrayEquals(identityPk, verified.identityPk)
            assertEquals(29_000_000L, verified.issuedMinute)
            assertEquals(DmRevocations.Reason.DEVICE_LOST, verified.reason)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    /**
     * §8.3: GHOST never links two Ed25519 identities, so a certificate that verifies under its own
     * key but names another identity is `WrongIdentity` and is never applied to the row it arrived
     * on. Every other corruption is refused too, which is what makes a forged certificate a
     * non-event rather than a denial of service any card holder could mount.
     */
    @Test
    fun aCertificateOfAnotherIdentityOrWithABrokenByteIsRefused() {
        requireNative()
        val mine = context(0x92)
        val theirs = context(0x93)
        try {
            val other = requireNotNull(DmSessions.ownCard(theirs, 0)).card.copyOfRange(3, 35)
            val certificate =
                (DmRevocations.issue(mine, 1, DmRevocations.Reason.KEY_ROTATION) as DmRevocations.Issued.Ok)
                    .certificate
            assertEquals(DmRevocations.Verified.WrongIdentity, DmRevocations.verify(certificate, other))

            val mineIdentity = requireNotNull(DmSessions.ownCard(mine, 0)).card.copyOfRange(3, 35)
            // Every byte is inside the transcript: flipping one refuses, by one code or another.
            for (i in certificate.indices) {
                val broken = certificate.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
                assertTrue(
                    "byte $i is outside the transcript",
                    DmRevocations.verify(broken, mineIdentity) !is DmRevocations.Verified.Ok,
                )
            }
            assertEquals(
                DmRevocations.Verified.NonCanonical,
                DmRevocations.verify(ByteArray(101), mineIdentity),
            )
        } finally {
            DmSessions.closeContext(mine)
            DmSessions.closeContext(theirs)
        }
    }

    /**
     * §22.8.1 rule 1: `L1.parse` reads a stored PreKey message's `session_id` and inner chain
     * index, which is what HELD groups and orders by.
     *
     * The bytes come from a real `sessionOutbound` and `encrypt`, so this is the shape a
     * `dm_held.l1_env` really carries — a header this parse got wrong would reorder a replay
     * silently.
     */
    @Test
    fun theHeldReplayReadsASessionIdAndAChainIndexOutOfStoredL1Bytes() {
        requireNative()
        val alice = context(0x94)
        val bob = context(0x95)
        try {
            val generation = requireNotNull(DmSessions.bundleCreate(bob, 0, 2_870, 0, 7))
            val bobIdentity = requireNotNull(DmSessions.ownCard(bob, 0)).olmIdentity
            val outbound = DmSessions.outbound(
                alice,
                ByteArray(16) { 1 },
                bobIdentity,
                generation.fallbackPublic,
                100,
            )
            outbound as DmSessions.Outbound.Ok
            var state = outbound.stateEnv
            val indices = ArrayList<Long>()
            for (i in 0 until 3) {
                val encrypted = DmSessions.encrypt(
                    alice,
                    ByteArray(16) { 1 },
                    DmSessions.StoredSlot(outbound.sessionId, state),
                    ByteArray(32) { i.toByte() },
                    100,
                )
                encrypted as DmSessions.Encrypted.Ok
                state = encrypted.stateEnv
                assertTrue("an unanswered session keeps sending PreKey messages", encrypted.isPreKey)
                val header = L1.parse(encrypted.l1, isPreKey = true)
                assertTrue(header is L1.PreKey)
                header as L1.PreKey
                assertArrayEquals(
                    "the header names the session the rows are grouped by",
                    outbound.sessionId,
                    header.sessionId,
                )
                assertArrayEquals(
                    "and the generation's fallback key, which §6.5 step 4 checks",
                    generation.fallbackPublic,
                    header.fallbackKey,
                )
                indices += header.chainIndex
            }
            assertEquals("and the index the group is ordered by", listOf(0L, 1L, 2L), indices)

            // The `Invalid` arm: bytes that are not an L1, and an L1 of the other kind.
            assertEquals(L1.Invalid, L1.parse(ByteArray(0), isPreKey = true))
            assertEquals(L1.Invalid, L1.parse(ByteArray(64) { 0xEE.toByte() }, isPreKey = true))
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }
}
