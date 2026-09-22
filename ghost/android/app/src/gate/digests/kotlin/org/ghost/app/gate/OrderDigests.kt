package org.ghost.app.gate

import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageCursor
import org.ghost.messaging.api.MessageView
import org.ghost.messaging.api.Messaging
import java.security.MessageDigest

/**
 * **The debug-only order digest export** (Phase 9 design §15.10 steps 2 and 3; slice S12): what the
 * gate orchestrator compares across the two phones, which is **digests, never content**.
 *
 * - The **order digest** is SHA-256 over the rendered `message_id` sequence of one conversation,
 *   oldest first, exactly as `Messaging.conversation` renders it (R-O1: `(sort_minute,
 *   minute_index, message_id)`), so two phones agree on it iff they render one order (CS-4).
 * - The **multiset digest** is SHA-256 over the same ids sorted bytewise, with the number of ids and
 *   the number of ids seen more than once: equal on both phones and zero duplicates is "no duplicate
 *   and nothing missing" (step 3).
 *
 * The digest is over ids only: no text, author minute, state or quote enters it, and nothing here
 * is logged. Gate G-DM5 keeps this class out of every release source set.
 */
object OrderDigests {

    /** One conversation's digests, as the orchestrator records them. */
    class Digests(val order: String, val multiset: String, val count: Int, val duplicates: Int) {
        override fun toString(): String = "Digests(count=$count, duplicates=$duplicates)"
    }

    /** Every message of [contact]'s conversation, oldest first, through the facade's own pages. */
    fun rendered(messaging: Messaging, contact: ContactId): List<MessageView> {
        val newestFirst = ArrayList<MessageView>()
        var before: MessageCursor? = null
        while (true) {
            val page = messaging.conversation(contact, PAGE, before)
            newestFirst += page
            if (page.size < PAGE) break
            before = page.last().cursor
        }
        return newestFirst.asReversed()
    }

    fun of(messaging: Messaging, contact: ContactId): Digests = of(rendered(messaging, contact).map { it.id.toByteArray() })

    /** The digests of an id sequence given oldest first (the pure half, for the self-test). */
    fun of(ids: List<ByteArray>): Digests {
        val order = MessageDigest.getInstance("SHA-256")
        for (id in ids) order.update(id)
        val sorted = ids.map { it.toList() }.sortedWith(BYTEWISE)
        val multiset = MessageDigest.getInstance("SHA-256")
        for (id in sorted) multiset.update(id.toByteArray())
        val duplicates = sorted.size - sorted.distinct().size
        return Digests(hex(order.digest()), hex(multiset.digest()), ids.size, duplicates)
    }

    /** SHA-256 of a safety number's digits, so two phones compare them without printing them. */
    fun safetyDigest(digits: String): String =
        hex(MessageDigest.getInstance("SHA-256").digest(digits.toByteArray(Charsets.US_ASCII)))

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private const val PAGE = 200

    private val BYTEWISE = Comparator<List<Byte>> { a, b ->
        for (i in 0 until minOf(a.size, b.size)) {
            val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (c != 0) return@Comparator c
        }
        a.size - b.size
    }
}
