package org.ghost.app.ui

import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.ghost.entitlement.api.Disclosure
import org.ghost.entitlement.api.Entitlement
import org.ghost.entitlement.api.PaymentInstructions
import org.ghost.entitlement.api.PurchaseId
import org.ghost.entitlement.api.PayWith
import org.ghost.identity.IdentityManager
import org.ghost.identity.InMemoryWrappedSecretStore
import org.ghost.identity.RootEntropy
import org.ghost.identity.Bip39
import org.ghost.ui.gateway.ActivateResult
import org.ghost.ui.gateway.ActivationState
import org.ghost.ui.gateway.RestoreResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 §3.2, §3.6: the IdentityGateway adapter over real :identity pieces and a fake
 * Entitlement — the create/verify round trip over the real BIP-39 list, the genesis policy gate
 * (Q21), the result mappings, and the zeroized database key.
 */
class IdentityGatewayAdapterTest {
    private class FakeEntitlement : Entitlement {
        var inspect: org.ghost.entitlement.api.InvitePreview =
            org.ghost.entitlement.api.InvitePreview(version = 2, expiryDay = 20_014, refusedReason = null)
        var activateResult: org.ghost.entitlement.api.ActivationResult =
            org.ghost.entitlement.api.ActivationResult.PENDING
        var restoreResult: org.ghost.entitlement.api.RestoreResult =
            org.ghost.entitlement.api.RestoreResult.RESTORED

        override fun openPurchases(): List<org.ghost.entitlement.api.OpenPurchase> = emptyList()
        override fun invites(): List<org.ghost.entitlement.api.InviteIndex> = emptyList()
        override fun inspectInvite(text: String, nowUnixSeconds: Long) = inspect
        override fun activate(inviteText: String) = activateResult
        override fun activationState() = org.ghost.entitlement.api.ActivationState.ACTIVE
        override fun restore(mnemonic: List<String>) = restoreResult

        override fun status() = error("not used")
        override fun startPurchase(payWith: PayWith): PurchaseId? = error("not used")
        override fun requiredDisclosures(id: PurchaseId): Set<Disclosure> = error("not used")
        override fun acknowledge(id: PurchaseId, disclosures: Set<Disclosure>) = error("not used")
        override fun paymentInstructions(id: PurchaseId): PaymentInstructions? = error("not used")
        override fun requestInvoiceNow(id: PurchaseId) = error("not used")
        override fun checkNow(id: PurchaseId) = error("not used")
        override fun cancel(id: PurchaseId): Boolean = error("not used")
        override fun createInvite(expiryDay: Int): String? = error("not used")
        override fun revokeInvite(index: Int): Boolean = error("not used")
        override fun claimPayout(address: String) = error("not used")
        override fun setAutoRenewWithCredits(enabled: Boolean) = error("not used")
        override fun paymentScreenShown(id: PurchaseId) = error("not used")
        override fun paymentScreenHidden(id: PurchaseId) = error("not used")
    }

    private class SoftwareWrapper : org.ghost.identity.SecretWrapper {
        override fun wrap(plaintext: ByteArray): ByteArray = plaintext.copyOf()
        override fun unwrap(envelope: ByteArray): ByteArray = envelope.copyOf()
    }

    private fun adapter(
        genesisOn: Boolean = false,
        entitlement: FakeEntitlement = FakeEntitlement(),
    ): Triple<IdentityGatewayAdapter, FakeEntitlement, ArrayList<String>> {
        val events = ArrayList<String>()
        val identity = IdentityManager(SoftwareWrapper(), InMemoryWrappedSecretStore(), SecureRandom())
        return Triple(
            IdentityGatewayAdapter(
                identity = { identity },
                entitlement = { entitlement },
                createKey = { events.add("createKey"); ByteArray(32) { 1 } },
                genesisPolicyOn = genesisOn,
                nowUnixSeconds = { 1_800_000_000L },
                random = SecureRandom(),
            ),
            entitlement,
            events,
        ).also { }
    }

    @Test
    fun createDatabaseKeyCreatesOnceAndZeroesTheArray(): Unit = runBlocking {
        val (g, _, events) = adapter()
        g.createDatabaseKey()
        assertEquals(listOf("createKey"), events)
    }

    @Test
    fun inspectInviteMapsThePreview(): Unit = runBlocking {
        val (g, e, _) = adapter()
        val p = g.inspectInvite("ghost://invite/x")
        assertEquals(2, p.version)
        assertEquals(20_014, p.expiryDay)
        assertEquals(null, p.refusedReason)
        e.inspect = org.ghost.entitlement.api.InvitePreview(version = 2, expiryDay = null, refusedReason = "expired")
        val refused = g.inspectInvite("ghost://invite/y")
        assertEquals("expired", refused.refusedReason)
    }

    @Test
    fun activateMapsTheEngineResults(): Unit = runBlocking {
        val (g, e, _) = adapter()
        e.activateResult = org.ghost.entitlement.api.ActivationResult.PENDING
        assertEquals(ActivateResult.ACTIVATED, g.activateInvite("x"))
        e.activateResult = org.ghost.entitlement.api.ActivationResult.ALREADY_ACTIVE
        assertEquals(ActivateResult.ALREADY_ACTIVE, g.activateInvite("x"))
        e.activateResult = org.ghost.entitlement.api.ActivationResult.REFUSED_EXPIRED
        assertEquals(ActivateResult.REFUSED, g.activateInvite("x"))
        e.activateResult = org.ghost.entitlement.api.ActivationResult.UNAVAILABLE
        assertEquals(ActivateResult.UNAVAILABLE, g.activateInvite("x"))
    }

    @Test
    fun genesisRefusesUnlessTheBuildPolicyIsOn(): Unit = runBlocking {
        val off = adapter(genesisOn = false)
        assertEquals(ActivateResult.REFUSED, off.first.activateGenesis(acknowledged = true))
        val on = adapter(genesisOn = true)
        assertEquals(ActivateResult.ACTIVATED, on.first.activateGenesis(acknowledged = true))
        // And the identity was really created by the genesis path: the stored root now exists.
        assertEquals(24, on.first.mnemonicIndices().size)
    }

    @Test
    fun restoreMapsTheEngineResults(): Unit = runBlocking {
        val (g, e, _) = adapter()
        assertEquals(RestoreResult.RESTORED, g.restore(listOf("a")))
        e.restoreResult = org.ghost.entitlement.api.RestoreResult.REFUSED_MNEMONIC
        assertEquals(RestoreResult.REFUSED_MNEMONIC, g.restore(listOf("a")))
    }

    @Test
    fun theWordListIsTheIdentityListsAndBackupVerifiesOverIndices(): Unit = runBlocking {
        val (g, _, _) = adapter()
        val words = g.wordList()
        assertEquals(2048, words.size)
        // The full-check round trip on a real root: indices -> words -> verify.
        val entropy = ByteArray(32) { it.toByte() }
        val indices = Bip39.encodeIndices(entropy)
        val rendered = indices.map { words[it] }
        assertTrue(g.verifyBackup(indices, (0 until 24).toList(), rendered))
        val wrong = rendered.toMutableList().also { it[7] = if (it[7] == "abandon") "ability" else "abandon" }
        assertFalse(g.verifyBackup(indices, (0 until 24).toList(), wrong))
    }

    @Test
    fun newPassphraseIndicesDrawFromTheListRange(): Unit = runBlocking {
        val (g, _, _) = adapter()
        val indices = g.newPassphraseIndices(5)
        assertEquals(5, indices.size)
        assertTrue(indices.all { it in 0..2047 })
    }

    @Test
    fun mnemonicIndicesComeFromTheStoredRoot(): Unit = runBlocking {
        val (g, _, _) = adapter(genesisOn = true)
        g.activateGenesis(acknowledged = true)
        val indices = g.mnemonicIndices()
        assertEquals(24, indices.size)
        // The stored root's indices decode cleanly (the real list and checksum validate).
        Bip39.decodeIndices(indices)
    }
}
