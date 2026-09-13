package org.ghost.entitlement.port

import org.ghost.entitlement.TestBytes
import org.ghost.entitlement.TestCrypto
import org.ghost.network.EntitlementCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The production randomness (per-process PRF key, CSPRNG) and the invite token check over the schedule. */
class PortsTest {

    @Test
    fun theProductionRandomIsUniformAndItsPrfIsKeyedPerProcess() {
        val a = SecureEntitlementRandom()
        val b = SecureEntitlementRandom()
        assertEquals(32, a.bytes(32).size)
        assertFalse(a.bytes(32).contentEquals(a.bytes(32)))
        repeat(1000) {
            val u = a.uniform()
            assertTrue(u >= 0.0 && u < 1.0)
        }
        val input = TestBytes.of(40, 1)
        assertEquals(a.prf(EntitlementRandom.DOMAIN_REDEEM, input), a.prf(EntitlementRandom.DOMAIN_REDEEM, input), 0.0)
        assertNotEquals(a.prf(EntitlementRandom.DOMAIN_REDEEM, input), a.prf(EntitlementRandom.DOMAIN_NEED_SURFACE, input), 0.0)
        assertNotEquals(a.prf(EntitlementRandom.DOMAIN_REDEEM, input), a.prf(EntitlementRandom.DOMAIN_REDEEM, TestBytes.of(40, 2)), 0.0)
        assertNotEquals("a fresh key per process", a.prf(EntitlementRandom.DOMAIN_REDEEM, input), b.prf(EntitlementRandom.DOMAIN_REDEEM, input), 0.0)
        assertEquals("SecureEntitlementRandom(redacted)", a.toString())
    }

    @Test
    fun theInviteTokenCheckAnswersTheEpochOfInviteTokensOnly() {
        val crypto = TestCrypto()
        val invite = TestBytes.token(1)
        val access = TestBytes.token(2)
        crypto.register(invite, EntitlementCrypto.KIND_INVITE, 739)
        crypto.register(access, EntitlementCrypto.KIND_ACCESS, 2958, 1)
        val check = InviteTokenCheck(crypto)
        assertEquals(739L, check.inviteEpoch(invite))
        assertNull(check.inviteEpoch(access))
        assertNull(check.inviteEpoch(TestBytes.token(3)))
    }
}
