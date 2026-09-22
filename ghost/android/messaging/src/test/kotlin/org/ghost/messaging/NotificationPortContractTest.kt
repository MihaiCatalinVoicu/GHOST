package org.ghost.messaging

import org.ghost.messaging.api.MediaPort
import org.ghost.messaging.api.MessageId
import org.ghost.messaging.api.NotificationPort
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

/**
 * **The `NotificationPort` contract test** §10.7 (Q19) and §21.10 point 9 name as the *only* way
 * Phase 9 proves ADR-27's notification rules.
 *
 * > `NotificationPort` exposes only `onUnreadChanged(count: Int)`; the Phase 13 implementation
 * > posts one constant text with no sender, conversation id or content, **locked or not**
 * > (Android's notification history keeps what was posted for 24 h).
 *
 * > Phase 9 posts no notification (a no-op port; no `POST_NOTIFICATIONS`). ADR-27's notification
 * > rules are proven in Phase 9 only by the `NotificationPort` contract test; the
 * > `getActiveNotifications()` check, the notification-history check and the corresponding
 * > evidence are removed and move to Phase 13 with its permission ADR and device check.
 *
 * So the guarantee Phase 9 can make is about the **shape of the channel**, and the shape is worth
 * a test precisely because it is the whole guarantee: mutant **ME-13** ("a notification with
 * content") cannot be written against this signature at all — it can only be written by changing
 * the signature, and that is what this refuses.
 *
 * The same reflection covers [MediaPort], for the other half of §10.6's cascade: it takes the
 * transaction and the ids, so the attachments of an expired message go in the same commit as the
 * row, and it takes nothing that would let a Phase 11 implementation learn who wrote them.
 */
class NotificationPortContractTest {

    @Test
    fun theNotificationPortCarriesACountAndNothingElse() {
        val methods = NotificationPort::class.java.declaredMethods.filter { !it.isSynthetic }
        assertEquals("one method", 1, methods.size)
        val method = methods.single()
        assertEquals("onUnreadChanged", method.name)
        assertEquals(
            "one parameter, and it is an Int",
            listOf(Int::class.javaPrimitiveType),
            method.parameterTypes.toList(),
        )
        assertEquals("and nothing comes back", Void.TYPE, method.returnType)
        assertTrue(
            "no field could carry a sender or a body either",
            NotificationPort::class.java.declaredFields.none { !it.isSynthetic },
        )
    }

    /** A count, as the port receives it, is all a sink can ever record. */
    @Test
    fun aSinkSeesTheCountAndCanSeeNothingMore() {
        val seen = ArrayList<Int>()
        val port = NotificationPort { seen += it }
        port.onUnreadChanged(3)
        port.onUnreadChanged(0)
        assertEquals(listOf(3, 0), seen)
    }

    /**
     * §10.6's media row: `MediaPort.onMessagesDeleted(tx, ids)`, inside the deletion transaction.
     *
     * The transaction argument is the point — a port called after the commit would leave, after a
     * process death in between, a thumbnail of a message the user was told had disappeared and
     * that nothing would ever look at again.
     */
    @Test
    fun theMediaPortTakesTheTransactionAndTheIdsAndNothingElse() {
        val methods = MediaPort::class.java.declaredMethods
            .filter { !it.isSynthetic && Modifier.isAbstract(it.modifiers) }
        assertEquals(1, methods.size)
        val method = methods.single()
        assertEquals("onMessagesDeleted", method.name)
        assertEquals(
            listOf(org.ghost.sync.api.SyncTransaction::class.java, List::class.java),
            method.parameterTypes.toList(),
        )
        assertEquals(Void.TYPE, method.returnType)
    }

    /**
     * A value type of this API never renders what it holds (T3), and Phase 9's media port renders
     * what it is: a no-op, which is what §10.6 says Phase 9 ships (Phase 11 wires the real one).
     */
    @Test
    fun theIdTypeStaysRedacted() {
        assertEquals("MessageId(redacted)", MessageId(ByteArray(16) { 7 }).toString())
        assertEquals("MediaPort.NONE", MediaPort.NONE.toString())
    }
}
