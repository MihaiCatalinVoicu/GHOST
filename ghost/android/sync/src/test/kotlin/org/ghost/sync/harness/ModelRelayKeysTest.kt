package org.ghost.sync.harness

import org.ghost.sync.api.NamespaceId
import org.ghost.sync.store.RetentionPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The model relay's Phase 9 key registrations and the hostile modes S2 adds to it (design §4.3–§4.6,
 * §15.1). `register.txt` pins the semantics against the real relay; what is checked here is what a
 * world does with them: a lost `keys.redb` (LOSE_KEYS), a card holder registering its own verifier
 * (ATTACKER_REGISTERS, SC-1), a relay refusing one sender's deposits (REFUSE_ONE_SENDER, §21.2
 * point 10) and one promising to keep a blob longer than asked (LONG_EXPIRY, T30).
 */
class ModelRelayKeysTest {
    private val key = ByteArray(32) { (it * 7 + 3).toByte() }
    private val inbox = namespace("inbox")
    private val now = ModelRelay.weekStart(2959) + 86_400
    private val ownerSecret = secret("owner-deposit")

    private fun namespace(name: String): NamespaceId =
        NamespaceId(MessageDigest.getInstance("SHA-256").digest(name.toByteArray(Charsets.US_ASCII)))

    private fun secret(label: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(label.toByteArray(Charsets.US_ASCII))

    /** A redeemed write capability (v2) of `inbox` for week 2959 with its own serial. */
    private fun capability(serial: Int, quota: Long = 1L shl 28, week: Long = 2959): ByteArray {
        val body = ByteBuffer.allocate(ModelRelay.BODY_V2_BYTES)
            .put(ModelRelay.VERSION_2).put(ModelRelay.KIND_WRITE.toByte()).put(inbox.toByteArray())
            .putLong(quota).putLong(ModelRelay.weekStart(week + 1) + 3_600)
            .put(ByteArray(16) { serial.toByte() }).array()
        return body + Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(body)
    }

    private fun relay(): ModelRelay = ModelRelay("r", key).also { it.slot = 1 }

    private fun deposit(secret: ByteArray): ByteArray =
        ModelRelay.credentialBytes(ModelRelay.KIND_DEPOSIT, 1, inbox, secret)

    private fun verifier(secret: ByteArray): ByteArray =
        ModelRelay.verifierOf(ModelRelay.Credential(ModelRelay.KIND_DEPOSIT, 1, inbox, secret))

    private fun register(relay: ModelRelay, capability: ByteArray, secret: ByteArray, request: Int): ModelRelay.RegisterAnswer {
        val reply = relay.registerKey(
            inbox.toByteArray(), 2959, ModelRelay.KIND_DEPOSIT, verifier(secret), capability,
            ByteArray(16) { request.toByte() }, now,
        )
        check(reply is ModelRelay.Reply.Ok) { "registration refused: $reply" }
        return reply.value
    }

    private fun blob(label: String): ByteArray = label.toByteArray(Charsets.US_ASCII).copyOf(1024)

    private fun store(relay: ModelRelay, credential: ByteArray, label: String): ModelRelay.Reply<ModelRelay.Receipt> =
        relay.store(inbox, blob(label), credential, 604_800, now)

    /** LOSE_KEYS: the registrations are gone, the blobs are not, and the owner heals it. */
    @Test
    fun aLostKeyStoreRefusesEveryCredentialUntilTheOwnerRegistersAgain() {
        val relay = relay()
        val credential = deposit(ownerSecret)
        assertTrue("nothing registered yet", store(relay, credential, "early") is ModelRelay.Reply.Err)
        register(relay, capability(1), ownerSecret, 1)
        val stored = store(relay, credential, "first")
        assertTrue("the registration authorizes the deposit", stored is ModelRelay.Reply.Ok)

        relay.loseKeys()
        assertNull("no registration survives", relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(ownerSecret)))
        assertEquals("the deposit ledger restarts empty", 0, relay.depositLedgerSize())
        val refused = store(relay, credential, "second")
        assertEquals("unauthorized", (refused as ModelRelay.Reply.Err).category)
        // The blobs are untouched: the owner still reads them with its capability.
        val held = relay.get(ModelRelay.sha256(blob("first")), capability(1), now)
        assertTrue("blobs survive a lost keys.redb", held is ModelRelay.Reply.Ok)

        register(relay, capability(1), ownerSecret, 2)
        assertTrue("the owner heals it", store(relay, credential, "second") is ModelRelay.Reply.Ok)
    }

    /**
     * ATTACKER_REGISTERS (SC-1): a card holder that redeemed its own token for the owner's inbox
     * can add its own verifier, never replace the owner's; one capability registers at most one
     * verifier, and both credentials deposit against their own record.
     */
    @Test
    fun aCardHoldersRegistrationAccumulatesAndNeverReplacesTheOwners() {
        val relay = relay()
        val ownerCap = capability(1)
        register(relay, ownerCap, ownerSecret, 1)
        val ownerRecord = relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(ownerSecret))
        assertNotNull(ownerRecord)

        val attackerSecret = secret("attacker-deposit")
        val attackerCap = capability(2)
        register(relay, attackerCap, attackerSecret, 2)
        assertNotNull("the card holder's own verifier is recorded", relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(attackerSecret)))
        val after = relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(ownerSecret))
        assertEquals("the owner's record is untouched", ownerRecord!!.quotaBytes, after!!.quotaBytes)
        assertEquals(1, after.serials.size)
        assertTrue("the owner still deposits", store(relay, deposit(ownerSecret), "owner") is ModelRelay.Reply.Ok)
        assertTrue("so does the card holder, on its own allowance", store(relay, deposit(attackerSecret), "holder") is ModelRelay.Reply.Ok)

        // A second verifier from the same capability is refused and records nothing.
        val second = secret("attacker-second")
        val conflict = relay.registerKey(
            inbox.toByteArray(), 2959, ModelRelay.KIND_DEPOSIT, verifier(second), attackerCap, ByteArray(16) { 9 }, now,
        )
        assertEquals("unauthorized", (conflict as ModelRelay.Reply.Err).category)
        assertNull(relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(second)))
        // A fourth and fifth capability: at most four credits, the record's verifier unchanged.
        val quota = after.quotaBytes
        register(relay, capability(3), ownerSecret, 3)
        register(relay, capability(4), ownerSecret, 4)
        register(relay, capability(5), ownerSecret, 5)
        register(relay, capability(6), ownerSecret, 6)
        val credited = relay.record(inbox, 2959, ModelRelay.KIND_DEPOSIT, verifier(ownerSecret))!!
        assertEquals("at most four credits", ModelRelay.MAX_SERIALS, credited.serials.size)
        assertEquals("three more capabilities credited it", quota * 4, credited.quotaBytes)
    }

    /**
     * REFUSE_ONE_SENDER: every depositor presents the same credential bytes, so a refused sender
     * is not distinguishable by what it sends — and its next store presents exactly the same bytes
     * (no fallback, §21.2 point 7, P-2).
     */
    @Test
    fun aRefusedSenderPresentsTheSameCredentialAgain() {
        val relay = relay()
        register(relay, capability(1), ownerSecret, 1)
        val first = deposit(ownerSecret)
        val second = deposit(ownerSecret)
        assertTrue("every depositor sends identical bytes", first.contentEquals(second))
        assertEquals(
            "one deposit scope per (relay, namespace)",
            ModelRelay.sha256(first),
            ModelRelay.sha256(second),
        )
        relay.refusedStores += ModelRelay.sha256(blob("cut-off"))
        val refused = store(relay, first, "cut-off")
        assertEquals("unauthorized", (refused as ModelRelay.Reply.Err).category)
        assertTrue("the sender's next store is the same credential", store(relay, first, "next") is ModelRelay.Reply.Ok)
        assertEquals(
            "the refused store charged nothing, the next one 1024 bytes",
            1024L,
            relay.depositsUsed(inbox, 2959, verifier(ownerSecret)),
        )
    }

    /** LONG_EXPIRY: the receipt promises more than the TTL, which the client's bound refuses (T30). */
    @Test
    fun aReceiptBeyondTheRequestedTtlIsOutsideTheClientBound() {
        val relay = relay()
        register(relay, capability(1), ownerSecret, 1)
        val ttl = 604_800L
        val honest = store(relay, deposit(ownerSecret), "honest")
        val bound = ModelRelay.ceilHour(now + ttl) + RetentionPolicy.SKEW_SECONDS
        assertTrue("an honest receipt is inside the bound", (honest as ModelRelay.Reply.Ok).value.expiry <= bound)

        relay.longExpirySeconds = RetentionPolicy.SKEW_SECONDS + 3_600
        val lying = store(relay, deposit(ownerSecret), "lying")
        assertTrue("the lie is outside it", (lying as ModelRelay.Reply.Ok).value.expiry > bound)
    }

    /** The rights matrix and the week-coarse times a credential sees (§4.3, §21.9 point 4, §22.8.7). */
    @Test
    fun theRightsMatrixAndCoarseTimes() {
        val ops = ModelRelay.Companion.Op.entries
        fun allowed(kind: Int) = ops.filter { ModelRelay.allows(kind, it) }
        assertEquals(listOf(ModelRelay.Companion.Op.GET, ModelRelay.Companion.Op.CHECK, ModelRelay.Companion.Op.LIST), allowed(ModelRelay.KIND_READ))
        assertEquals(listOf(ModelRelay.Companion.Op.STORE, ModelRelay.Companion.Op.CHECK), allowed(ModelRelay.KIND_DEPOSIT))
        assertEquals(listOf(ModelRelay.Companion.Op.GET, ModelRelay.Companion.Op.LIST), allowed(ModelRelay.KIND_FETCH))
        assertEquals("2 is Write, never a bearer kind", emptyList<ModelRelay.Companion.Op>(), allowed(ModelRelay.KIND_WRITE))

        val start = ModelRelay.weekStart(2959)
        val next = ModelRelay.weekStart(2960)
        assertEquals(start, ModelRelay.weekFloor(start))
        assertEquals(start, ModelRelay.weekFloor(start + 1))
        assertEquals(start, ModelRelay.weekFloor(next - 60))
        assertEquals(start, ModelRelay.weekCeil(start))
        assertEquals(next, ModelRelay.weekCeil(start + 1))
        assertEquals(next, ModelRelay.weekCeil(next - 1))
        assertEquals(5, ModelRelay.week(ModelRelay.weekStart(5) + 604_799))
    }

    /** A relay without a slot refuses every credential v3; its capabilities keep working (§21.2). */
    @Test
    fun aRelayWithoutASlotRefusesEveryCredential() {
        val relay = ModelRelay("no-slot", key)
        val answer = register(relay, capability(1), ownerSecret, 1)
        assertEquals(ModelRelay.RESULT_OK, answer.result)
        val refused = store(relay, deposit(ownerSecret), "blob")
        assertEquals("unauthorized", (refused as ModelRelay.Reply.Err).category)
        assertTrue("a capability still stores", store(relay, capability(1), "blob") is ModelRelay.Reply.Ok)
        // With the slot configured, the same credential is accepted; another slot is not.
        relay.slot = 1
        assertTrue(store(relay, deposit(ownerSecret), "blob2") is ModelRelay.Reply.Ok)
        val otherSlot = ModelRelay.credentialBytes(ModelRelay.KIND_DEPOSIT, 2, inbox, ownerSecret)
        assertEquals("unauthorized", (store(relay, otherSlot, "blob3") as ModelRelay.Reply.Err).category)
    }
}
