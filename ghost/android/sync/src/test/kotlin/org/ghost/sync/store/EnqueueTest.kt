package org.ghost.sync.store

import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.InsufficientReplicasException
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.TtlBucket
import org.ghost.sync.store.SyncWorld.Companion.DAY
import org.ghost.sync.store.SyncWorld.Companion.HOUR
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Enqueue (design §3.1, §11.2 #6 and #15). */
class EnqueueTest {

    @Test
    fun enqueueWritesTheOpOneDeliveryPerActiveRelayAndTheOwnTombstone(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.clock.advance(37)
        val op = w.enqueue(1, ns)
        val h = w.hashOf(1)
        assertEquals("pending", w.outcome(op))
        assertTrue(w.hasPayload(op))
        assertEquals(h.toByteArray().toList(), w.sql.let { s ->
            var b: ByteArray? = null
            s.query("SELECT blob_hash FROM outbox_op") { b = it.blob(0) }
            b!!.toList()
        })
        assertEquals(Time.floorMinute(w.now), w.long("SELECT not_before_minute FROM outbox_op"))
        assertNull(w.long("SELECT deadline_hour FROM outbox_op"))
        assertEquals(2L, w.long("SELECT required_operators FROM outbox_op"))
        relays.forEach { r ->
            assertEquals("pending", w.state(op, r))
            assertEquals(Time.floorMinute(w.now), w.delivery(op, r, "next_attempt_minute"))
        }
        assertEquals("done", w.inboxState(ns, h))
        assertEquals(RetentionPolicy.ceil7(Time.day(w.now) + 7 + 8), w.retainDay(ns, h))
        assertEquals(0L, w.retainDay(ns, h)!! % 7)
    }

    @Test
    fun aRetiredRelayGetsNoDeliveryAndDoesNotCountAsAnOperator(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        w.tx { w.stores.relayDirectory.retire(it, relays[2]) }
        val op = w.enqueue(1, ns)
        assertEquals(2L, w.count("outbox_delivery"))
        assertNull(w.state(op, relays[2]))
        w.tx { w.stores.relayDirectory.retire(it, relays[1]) }
        assertThrows(InsufficientReplicasException::class.java) { w.enqueue(2, ns) }
    }

    @Test
    fun twoRelaysOfOneOperatorAreNotEnough(): Unit = SyncWorld().use { w ->
        val relays = w.relays(7, 7)
        val ns = w.namespace(1, relays)
        val e = assertThrows(InsufficientReplicasException::class.java) { w.enqueue(1, ns) }
        assertEquals("fewer than two distinct relay operators", e.message)
        assertEquals(0L, w.count("outbox_op"))
        assertEquals(0L, w.count("inbox_blob"))
    }

    @Test
    fun invalidInputIsRefused(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet()
        assertThrows(IllegalArgumentException::class.java) { w.blob(1, ns, size = 1000) }
        val unknown = TestBytes.namespace(99)
        val e = assertThrows(IllegalStateException::class.java) { w.tx { w.stores.outbox.enqueue(it, w.blob(1, unknown)) } }
        assertEquals("namespace is not registered", e.message)
        val past = assertThrows(IllegalArgumentException::class.java) {
            w.tx { w.stores.outbox.enqueue(it, w.blob(2, ns, deadline = w.now)) }
        }
        assertEquals("deadline is not in the future", past.message)
        assertEquals(0L, w.count("outbox_op"))
    }

    @Test
    fun sameIdSameBytesIsIdempotentOtherwiseAConflictRollsTheCallerBack(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet()
        w.enqueue(1, ns)
        assertEquals(EnqueueResult.AlreadyEnqueued, w.tx { w.stores.outbox.enqueue(it, w.blob(1, ns)) })
        // Same id, other bytes.
        val otherBytes = OutboundBlob(TestBytes.op(1), ns, TestBytes.ciphertext(2), TtlBucket.DAYS_7)
        val e1 = assertThrows(IllegalStateException::class.java) {
            w.tx { tx ->
                tx.sql.exec("CREATE TABLE IF NOT EXISTS caller_effect (x INTEGER)")
                tx.sql.exec("INSERT INTO caller_effect(x) VALUES (1)")
                w.stores.outbox.enqueue(tx, otherBytes)
            }
        }
        assertEquals("operation id is already used for other bytes", e1.message)
        assertEquals(0L, w.long("SELECT count(*) FROM sqlite_master WHERE name = 'caller_effect'"))
        // Same bytes under another live op.
        val sameBytes = OutboundBlob(TestBytes.op(3), ns, TestBytes.ciphertext(1), TtlBucket.DAYS_7)
        val e2 = assertThrows(IllegalStateException::class.java) { w.tx { w.stores.outbox.enqueue(it, sameBytes) } }
        assertEquals("these bytes are already queued under another operation", e2.message)
        assertEquals(1L, w.count("outbox_op"))
    }

    @Test
    fun writeOnlyNamespacesKeepNoInboxRow(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet(listen = false)
        w.enqueue(1, ns)
        assertEquals(0L, w.count("inbox_blob"))
    }

    @Test
    fun sendDelayFollowsTheModeAndTheNamespaceOverride(): Unit = SyncWorld().use { w ->
        val relays = w.relays(1, 2)
        val nsDefault = w.namespace(1, relays)
        val nsOn = w.namespace(2, relays, sendDelay = SendDelay.ON)
        val nsOff = w.namespace(3, relays, sendDelay = SendDelay.OFF)
        w.clock.advance(10)
        w.random.sendDelayValue = 0.25 // 150 s
        val expectedDelayed = Time.ceilMinute(w.now + 150)
        val floor = Time.floorMinute(w.now)
        w.enqueue(1, nsDefault)
        w.enqueue(2, nsOn)
        w.enqueue(3, nsOff)
        assertEquals(1, w.random.sendDelayDraws)
        w.mode = PrivacyMode.HIGH
        w.enqueue(4, nsDefault)
        w.enqueue(5, nsOff)
        assertEquals(2, w.random.sendDelayDraws)
        fun notBefore(seed: Int) = w.long("SELECT not_before_minute FROM outbox_op WHERE operation_id = ?", TestBytes.op(seed))
        assertEquals(floor, notBefore(1))
        assertEquals(expectedDelayed, notBefore(2))
        assertEquals(floor, notBefore(3))
        assertEquals(expectedDelayed, notBefore(4))
        assertEquals(floor, notBefore(5))
        // Deliveries wait for not_before as well.
        assertEquals(expectedDelayed, w.long("SELECT next_attempt_minute FROM outbox_delivery WHERE operation_id = ? LIMIT 1", TestBytes.op(4)))
        // The whole range stays within 10 minutes.
        w.random.sendDelayValue = 0.999_999
        w.enqueue(6, nsDefault)
        assertTrue(notBefore(6)!! <= w.now + 600 + 59)
    }

    @Test
    fun deadlinesAreCeiledToTheHourAndStayAfterNotBefore(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet()
        w.clock.advance(59 * 60 + 30) // 00:59:30 past T0
        w.enqueue(1, ns, deadline = w.now + 20)
        assertEquals(SyncWorld.T0 + HOUR, w.long("SELECT deadline_hour FROM outbox_op WHERE operation_id = ?", TestBytes.op(1)))
        // HIGH mode: the delay can pass the ceiled deadline hour; the deadline moves one hour past not_before.
        w.mode = PrivacyMode.HIGH
        w.random.sendDelayValue = 0.9 // 540 s
        w.enqueue(2, ns, deadline = w.now + 20)
        val notBefore = w.long("SELECT not_before_minute FROM outbox_op WHERE operation_id = ?", TestBytes.op(2))!!
        val deadline = w.long("SELECT deadline_hour FROM outbox_op WHERE operation_id = ?", TestBytes.op(2))!!
        assertTrue(deadline > notBefore)
        assertEquals(Time.floorHour(notBefore) + HOUR, deadline)
    }

    @Test
    fun anExistingOwnTombstoneIsRaisedAndBoundsTheResendOfIdenticalBytes(): Unit = SyncWorld().use { w ->
        val (ns, relays) = w.standardSet()
        val h = w.hashOf(1)
        val first = TestBytes.op(1)
        w.enqueue(1, ns, TtlBucket.DAYS_30)
        // A receipt raised the tombstone to ceil7(day(expiry) + 24); then the op ends and is released.
        val expiry = w.now + 30 * DAY
        w.tx { tx ->
            val lease = w.outbox.lease(tx, first, relays[0], w.now, 60)!!
            assertEquals(ReceiptResult.ACKED, w.outbox.recordReceipt(tx, lease.operationId, relays[0], expiry, w.now))
            relays.drop(1).forEach { w.outbox.failDelivery(tx, first, it, w.now) }
        }
        val raised = RetentionPolicy.expiryRetainDay(expiry)
        assertEquals(raised, w.retainDay(ns, h))
        // Still acked: a live delivery keeps the payload and the op undecided; the relay then lists it.
        w.tx { tx -> w.inbox.commitPage(tx, relays[0], ns, listOf(h), ByteArray(0), ByteArray(0), w.now) }
        assertEquals("degraded", w.outcome(first))
        assertFalse(w.hasPayload(first))
        assertTrue(w.tx { w.stores.outbox.release(it, first) })
        // Resend of identical bytes as a new op, while now < retain − TAIL: the old row is taken over.
        w.clock.advance(2 * DAY)
        val again = OutboundBlob(TestBytes.op(2), ns, TestBytes.ciphertext(1), TtlBucket.DAYS_30)
        assertEquals(EnqueueResult.Enqueued, w.tx { w.stores.outbox.enqueue(it, again) })
        assertEquals(1L, w.count("outbox_op"))
        assertEquals(null, w.outcome(first))
        assertTrue(w.retainDay(ns, h)!! >= RetentionPolicy.ownRetainDay(w.now, 30 * DAY))
        assertTrue(w.retainDay(ns, h)!! >= raised)
    }

    @Test
    fun resendIsRefusedOnceTheOwnTombstoneIsTooCloseToItsEnd(): Unit = SyncWorld().use { w ->
        val (ns, _) = w.standardSet()
        val h = w.hashOf(1)
        val retain = RetentionPolicy.ceil7(Time.day(w.now) + 30)
        w.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?)", ns, h, retain)
        w.clock.now = (retain - RetentionPolicy.TAIL_DAYS) * DAY - 1
        w.enqueue(1, ns)
        w.clock.now = (retain - RetentionPolicy.TAIL_DAYS) * DAY
        val e = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.outbox.enqueue(it, OutboundBlob(TestBytes.op(2), ns, TestBytes.ciphertext(1), TtlBucket.DAYS_7)) }
        }
        assertEquals("these bytes are already queued under another operation", e.message)
        val bytes2 = TestBytes.ciphertext(5)
        val h2 = TestBytes.sha256(bytes2)
        w.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'done', ?)", ns, h2, retain)
        val refused = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.outbox.enqueue(it, OutboundBlob(TestBytes.op(5), ns, bytes2, TtlBucket.DAYS_7)) }
        }
        assertEquals("identical bytes can no longer be resent", refused.message)
        // Bytes someone else's relay already delivered to us are refused too.
        val bytes3 = TestBytes.ciphertext(6)
        w.raw("INSERT INTO inbox_blob(namespace_id, blob_hash, state, retain_until_day) VALUES (?, ?, 'listed', ?)", ns, TestBytes.sha256(bytes3), retain)
        val received = assertThrows(IllegalStateException::class.java) {
            w.tx { w.stores.outbox.enqueue(it, OutboundBlob(TestBytes.op(6), ns, bytes3, TtlBucket.DAYS_7)) }
        }
        assertEquals("these bytes were received from a relay", received.message)
    }
}
