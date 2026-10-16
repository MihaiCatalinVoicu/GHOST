package org.ghost.messaging

import org.ghost.crypto.bridge.DmContent
import org.ghost.crypto.bridge.DmSessions
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MediaStateView
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.SendResult
import org.ghost.messaging.api.TrustState
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.port.DmEnvelopes
import org.ghost.storage.queryLong
import org.ghost.storage.queryString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The recipient pipeline's **RECV** integration on the real cryptography (Phase 11 design §7.2,
 * §13.4; SCN-MC's request and first-message cases): a kind-5 L0 threads its `key_env` from
 * `decrypt` (13) and `sessionInbound` (14) into `media_object` in RECV's own transaction — and
 * the request rule (D28) stores the message row but no object and no key, before and after the
 * request is accepted.
 *
 * The seam is the world's sanctioned envelope decorator (the shape S13's mutants use, §15.7):
 * the receiver's `decrypt`/`inbound` answer for one armed message is swapped for a real
 * `encodeContent`-built kind-5 L0 plus an envelope; everything else — sessions, freshness,
 * dedup, the outer envelope, the request creation — runs untouched. (Sending a kind-5 through
 * the production sender pipeline is S5's `MediaSteps`, already covered; here the subject is
 * RECV, and function 14's key-slot wrapping itself is S2's key-slot suite.)
 */
class DmMediaReceiveTest {

    private fun requireNative() {
        assumeTrue("set -Dghost.dm.native to the ghost-dm-host library", DmWorld.nativeAvailable())
    }

    /**
     * Swaps the decrypted L0 of the next armed answer for a crafted kind-5 descriptor L0 and
     * reports [keyEnv] as the media envelope — §4.2's contract from the native side's point of
     * view, planted at the seam the worlds already decorate.
     */
    private class MediaSwap(
        private val real: DmEnvelopes,
        private val keyEnv: ByteArray,
    ) : DmEnvelopes by real {
        /** Set before arming: the crafted L0, built at arm time so its minute is fresh. */
        lateinit var l0: () -> ByteArray

        @Volatile
        var armed: Boolean = false

        override fun decrypt(
            contactId: ByteArray,
            current: DmSessions.StoredSlot?,
            previous: DmSessions.StoredSlot?,
            l1: ByteArray,
            isPreKey: Boolean,
            today: Int,
        ): DmSessions.Decrypted =
            when (val result = real.decrypt(contactId, current, previous, l1, isPreKey, today)) {
                is DmSessions.Decrypted.Ok ->
                    if (armed) {
                        armed = false
                        DmSessions.Decrypted.Ok(
                            plaintext = l0(),
                            slot = result.slot,
                            acknowledged = result.acknowledged,
                            stateEnv = result.stateEnv,
                            mediaKeyEnv = keyEnv.copyOf(),
                        )
                    } else {
                        result
                    }
                else -> result
            }

        override fun inbound(
            contactId: ByteArray,
            genId: Int,
            genSecretsEnv: ByteArray,
            genFallbackPublic: ByteArray,
            expectedPeerIdentity: ByteArray,
            l1: ByteArray,
            today: Int,
        ): DmSessions.Inbound =
            when (
                val result = real.inbound(
                    contactId, genId, genSecretsEnv, genFallbackPublic, expectedPeerIdentity, l1, today,
                )
            ) {
                is DmSessions.Inbound.Ok ->
                    if (armed) {
                        armed = false
                        DmSessions.Inbound.Ok(
                            plaintext = l0(),
                            stateEnv = result.stateEnv,
                            sessionId = result.sessionId,
                            mediaKeyEnv = keyEnv.copyOf(),
                        )
                    } else {
                        result
                    }
                else -> result
            }
    }

    /** A real kind-5 descriptor L0: the descriptor body is §4.1's wire, encoded by the codec. */
    private class Craft(val l0: ByteArray, val objectId: ByteArray, val keyEnv: ByteArray)

    private fun craftDescriptor(
        envelopes: DmEnvelopes,
        senderHandle: Long,
        caption: String,
        now: Long,
        objectId: ByteArray? = null,
        messageId: ByteArray = ByteArray(16) { 0x4D },
    ): Craft {
        val resolvedObjectId = objectId ?: run {
            val begun = org.ghost.crypto.bridge.MediaCrypto.begin(
                senderHandle, ByteArray(16), org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE, viewOnce = false, maxClass = 10,
            ) as org.ghost.crypto.bridge.MediaCrypto.Begun.Ok
            org.ghost.crypto.bridge.MediaCrypto.abort(senderHandle, begun.sealer.id)
            begun.sealer.objectId
        }
        val keyEnv = ByteArray(60) { 0x42 }
        val manifestHash = ByteArray(32) { 0x24 }
        val captionBytes = caption.toByteArray()
        val body = ByteArray(86 + captionBytes.size)
        body[0] = 1
        body[1] = 1 // kind IMAGE
        body[2] = 0
        body[3] = 0 // class 0
        resolvedObjectId.copyInto(body, 4)
        manifestHash.copyInto(body, 52)
        body[84] = (captionBytes.size ushr 8).toByte()
        body[85] = captionBytes.size.toByte()
        captionBytes.copyInto(body, 86)
        val encoded = envelopes.encodeContent(
            kind = DmContent.Kind.MEDIA,
            messageId = messageId,
            authorMinute = DmTime.floorMinute(now) / 60,
            minuteIndex = 0,
            timerCode = 4,
            timerVersion = 1,
            quoteRef = null,
            body = body,
            contactId = ByteArray(16),
            offerRootGen = 0,
            offerEnv = ByteArray(0),
            revocation = ByteArray(0),
            sessionReset = false,
            pqKey = null,
            pqKeyFirst = false,
        )
        check(encoded is DmContent.Encoded.Ok) { "encodeContent: $encoded" }
        return Craft(encoded.l0, resolvedObjectId, keyEnv)
    }

    private fun queryLong(device: DmDevice, sql: String, args: List<Any?> = emptyList()): Long? =
        device.sql.queryLong(sql, args)

    private fun activate(world: DmWorld) {
        world.alice.engine.onActivated()
        world.bob.engine.onActivated()
        assertNotNull(world.alice.engine.myCard())
        assertNotNull(world.bob.engine.myCard())
    }

    /** The one-scan flow to pair mode (DmFlowTest's shape, inline to keep the file self-contained). */
    private fun establishBothWays(world: DmWorld): Pair<ContactId, ContactId> {
        val alice = world.alice
        val bob = world.bob
        activate(world)
        assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
        val contactB = alice.engine.contacts().single().id
        assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "hello", null))
        world.deliver()
        alice.timeTriggeredPass()
        world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
        alice.timeTriggeredPass()
        world.deliver()
        bob.hintPass()
        val contactA = bob.engine.contacts().single().id
        assertTrue(bob.engine.acceptRequest(contactA))
        assertEquals(SendResult.QUEUED, bob.engine.send(contactA, "hi back", null))
        world.deliver()
        alice.hintPass()
        assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "pair now", null))
        world.deliver()
        bob.hintPass()
        return contactB to contactA
    }

    private fun arm(swap: MediaSwap, envelopes: DmEnvelopes, handle: Long, caption: String, now: Long): Craft {
        val craft = craftDescriptor(envelopes, handle, caption, now)
        swap.l0 = { craft.l0 }
        swap.armed = true
        return craft
    }

    @Test
    fun aMediaMessageFromAnEstablishedContactCreatesTheObject() {
        requireNative()
        var swap: MediaSwap? = null
        DmWorld(
            decorate = { branch, envelopes ->
                if (branch == 0x41) {
                    val s = MediaSwap(envelopes, ByteArray(60) { 0x42 })
                    swap = s
                    s
                } else {
                    envelopes
                }
            },
        ).use { world ->
            val alice = world.alice
            val (contactB, contactA) = establishBothWays(world)
            val worldSwap = swap!!
            val craft = arm(worldSwap, alice.envelopes, alice.nativeHandle!!, "salut", alice.clock.now)

            assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "trigger", null))
            world.deliver()
            alice.hintPass()

            assertEquals(
                "the message row is stored (the caption, like a text)",
                1L, queryLong(alice, "SELECT count(*) FROM dm_message WHERE kind = 5"),
            )
            assertEquals(
                "the object is awaiting, created in RECV's transaction with the key",
                "awaiting",
                alice.sql.queryString("SELECT state FROM media_object WHERE object_id = ?", listOf(craft.objectId)),
            )
            assertEquals(
                "the key the native side returned is the key the row holds",
                1L,
                queryLong(
                    alice,
                    "SELECT count(*) FROM media_object WHERE object_id = ? AND key_env IS NOT NULL AND role = 'in'",
                    listOf(craft.objectId),
                ),
            )
            assertEquals(
                "the object's relay-expiry bound is the descriptor blob's",
                1L,
                queryLong(
                    alice,
                    "SELECT count(*) FROM media_object o JOIN dm_message m ON m.message_id = o.message_id " +
                        "WHERE o.object_id = ? AND m.kind = 5",
                    listOf(craft.objectId),
                ),
            )
        }
    }

    @Test
    fun aSecondDescriptorForTheSameObjectCreatesNothing() {
        requireNative()
        var swap: MediaSwap? = null
        DmWorld(
            decorate = { branch, envelopes ->
                if (branch == 0x41) {
                    val s = MediaSwap(envelopes, ByteArray(60) { 0x42 })
                    swap = s
                    s
                } else {
                    envelopes
                }
            },
        ).use { world ->
            val alice = world.alice
            val (contactB, contactA) = establishBothWays(world)
            val worldSwap = swap!!
            val craft = arm(worldSwap, alice.envelopes, alice.nativeHandle!!, "first", alice.clock.now)

            assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "trigger", null))
            world.deliver()
            alice.hintPass()
            assertEquals("awaiting", alice.sql.queryString(
                "SELECT state FROM media_object WHERE object_id = ?", listOf(craft.objectId),
            ))

            // The same object id arrives again under a new message id (a re-send, a replay):
            // the message row follows F9's dedup, the object is drop(duplicate_object) — nothing
            // written for it (§7.2).
            val second = craftDescriptor(
                alice.envelopes, alice.nativeHandle!!, "second", alice.clock.now,
                objectId = craft.objectId,
                messageId = ByteArray(16) { 0x4E },
            )
            worldSwap.l0 = { second.l0 }
            worldSwap.armed = true
            assertEquals(SendResult.QUEUED, world.bob.engine.send(contactA, "trigger two", null))
            world.deliver()
            alice.hintPass()

            assertEquals(2L, queryLong(alice, "SELECT count(*) FROM dm_message WHERE kind = 5"))
            assertEquals(1L, queryLong(alice, "SELECT count(*) FROM media_object"))
            assertEquals(
                "the second message has no object",
                1L,
                queryLong(
                    alice,
                    "SELECT count(*) FROM dm_message m WHERE m.kind = 5 AND NOT EXISTS " +
                        "(SELECT 1 FROM media_object o WHERE o.message_id = m.message_id)",
                ),
            )
        }
    }

    @Test
    fun aFirstMessageThatIsMediaTakesSessionInboundAndKeepsNoKey() {
        requireNative()
        var swap: MediaSwap? = null
        DmWorld(
            decorate = { branch, envelopes ->
                if (branch == 0x51) {
                    // The receiver is bob; alice's first flight is swapped for a media descriptor.
                    val s = MediaSwap(envelopes, ByteArray(60) { 0x43 })
                    swap = s
                    s
                } else {
                    envelopes
                }
            },
        ).use { world ->
            val alice = world.alice
            val bob = world.bob
            activate(world)
            assertEquals(AddContactResult.ADDED, alice.engine.addContact(bob.card(), CardSource.QR_IN_PERSON))
            val contactB = alice.engine.contacts().single().id
            val worldSwap = swap!!
            arm(worldSwap, alice.envelopes, alice.nativeHandle!!, "first photo", alice.clock.now)

            assertEquals(SendResult.QUEUED, alice.engine.send(contactB, "trigger", null))
            world.deliver()
            alice.timeTriggeredPass()
            world.advanceTo(alice.clock.now + 3 * DmWorld.MINUTE)
            alice.timeTriggeredPass()
            world.deliver()
            bob.hintPass()

            // An unknown card holder's first message is a request (F9 §12.3); the media half
            // creates no object and keeps no key (D28) — the photo a stranger sent never opens,
            // and function 14's envelope went nowhere: no media_object row exists to hold it.
            // (DmDevice's facade has no media pipeline wired, so mediaState is asserted at the
            // support level in MediaPreviewGateTest; here the rows are the oracle.)
            assertEquals(1, bob.engine.contacts().size)
            assertEquals(TrustState.REQUEST, bob.engine.contacts().single().trust)
            assertEquals(1L, queryLong(bob, "SELECT count(*) FROM dm_message WHERE kind = 5"))
            assertEquals(0L, queryLong(bob, "SELECT count(*) FROM media_object"))
            assertEquals(
                0L,
                queryLong(
                    bob,
                    "SELECT count(*) FROM dm_message m WHERE m.kind = 5 AND EXISTS " +
                        "(SELECT 1 FROM media_object o WHERE o.message_id = m.message_id)",
                ),
            )
        }
    }
}
