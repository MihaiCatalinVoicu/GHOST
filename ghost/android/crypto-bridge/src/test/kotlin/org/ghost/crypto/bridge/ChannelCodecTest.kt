package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.CharBuffer

/**
 * The Kotlin halves of the channel surface that need no native library (review of S2b): the
 * negatives a mutant of [ChannelRecognition] or [ChannelInvite] survived, and the erasure rules of
 * [ChannelPassword], [MlsTlv] and [MlsRecord] — each test fails if the rule it names is dropped.
 * A pure-JVM test.
 */
class ChannelCodecTest {

    private val key = ByteArray(32) { (it + 1).toByte() }
    private val salt = ByteArray(16) { (0x40 + it).toByte() }

    private fun blob(mode: Int): ByteArray =
        salt + ChannelRecognition.hint(key, mode, salt) + ByteArray(64) { 7 }

    /** All 16 bytes of the hint count: one flipped anywhere — the last above all — is no match. */
    @Test
    fun aHintMatchesOnAllSixteenBytes() {
        val good = blob(0x11)
        assertTrue(ChannelRecognition.matches(good, key, 0x11))
        val candidate = ChannelRecognition.Candidate(key, 0x11, "epoch")
        for (i in ChannelRecognition.SALT_BYTES until ChannelRecognition.HEADER_BYTES) {
            val bad = good.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertFalse("hint byte ${i - ChannelRecognition.SALT_BYTES}", ChannelRecognition.matches(bad, key, 0x11))
            assertNull(ChannelRecognition.matchFirst(bad, sequenceOf(candidate)))
        }
        // The salt is read from the blob, so a flipped salt byte is another hint too.
        val badSalt = good.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(ChannelRecognition.matches(badSalt, key, 0x11))
    }

    /** A blob shorter than salt and hint carries no hint: no match, whatever its bytes. */
    @Test
    fun aBlobShorterThanItsHeaderNeverMatches() {
        val good = blob(0x12)
        val candidate = ChannelRecognition.Candidate(key, 0x12, "join")
        for (length in 0 until ChannelRecognition.HEADER_BYTES) {
            val short = good.copyOf(length)
            assertFalse("length $length", ChannelRecognition.matches(short, key, 0x12))
            assertNull("length $length", ChannelRecognition.matchFirst(short, sequenceOf(candidate)))
        }
        assertTrue(ChannelRecognition.matches(good.copyOf(ChannelRecognition.HEADER_BYTES), key, 0x12))
    }

    /** A link is the exact prefix and the exact alphabet: a same-length link with any other prefix has no bytes. */
    @Test
    fun aLinkWithAnotherPrefixHasNoBytes() {
        val invite = ByteArray(ChannelInvite.INVITE_BYTES) { (it * 7).toByte() }
        val link = ChannelInvite.toLink(invite)
        assertEquals(ChannelInvite.LINK_CHARS, link.length)
        assertArrayEquals(invite, ChannelInvite.fromLink(link))
        val body = link.substring(ChannelInvite.LINK_PREFIX.length)
        for (prefix in listOf("ghost://chanel_/", "https://channel/", "ghost://Channel/", "aaaaaaaaaaaaaaaa")) {
            assertEquals(ChannelInvite.LINK_PREFIX.length, prefix.length)
            assertNull(prefix, ChannelInvite.fromLink(prefix + body))
        }
    }

    /**
     * The password bytes the facade hands the native side are zeroed once the call ends, returned
     * or thrown — and the caller's characters are never touched.
     */
    @Test
    fun thePasswordBytesAreZeroedAfterTheCall() {
        val typed = "pârolă șțî".toCharArray()
        var seen: ByteArray? = null
        val result = ChannelPassword.withNfkdUtf8(typed) { bytes ->
            seen = bytes
            assertArrayEquals(ChannelPassword.nfkdUtf8(typed), bytes)
            bytes.size
        }
        assertEquals(seen!!.size, result)
        assertTrue("zeroed after the call", seen.all { it.toInt() == 0 })
        try {
            ChannelPassword.withNfkdUtf8("cabin".toCharArray()) { bytes ->
                seen = bytes
                throw IllegalStateException("the native call failed")
            }
            fail("the call's exception is the caller's")
        } catch (e: IllegalStateException) {
            assertTrue("zeroed when the call throws", seen.all { it.toInt() == 0 })
        }
        assertEquals("pârolă șțî", String(typed))
        assertNull(ChannelPassword.withNfkdUtf8(charArrayOf('a', '\uD800')) { fail("no call for an unpaired surrogate") })
    }

    /**
     * UTF-8 goes through a buffer of three bytes per char, never grown, and zeroed afterwards;
     * one, two, three and four-byte sequences encode as the JDK's own encoder encodes them.
     */
    @Test
    fun theEncoderWritesIntoAZeroedWorstCaseBuffer() {
        val text = "aâș€👍"
        val scratch = ByteBuffer.allocate(3 * text.length)
        val out = ChannelPassword.encodeUtf8(CharBuffer.wrap(text.toCharArray()), scratch)
        assertArrayEquals(text.toByteArray(Charsets.UTF_8), out)
        assertTrue("the scratch is zeroed", scratch.array().all { it.toInt() == 0 })
        // Too small a buffer is a refusal, never a growth.
        val small = ByteBuffer.allocate(4)
        assertNull(ChannelPassword.encodeUtf8(CharBuffer.wrap(text.toCharArray()), small))
        assertTrue(small.array().all { it.toInt() == 0 })
        assertNull(ChannelPassword.encodeUtf8(CharBuffer.wrap(charArrayOf('\uDC00')), ByteBuffer.allocate(3)))
    }

    /** The argument encoder erases the array it outgrows. */
    @Test
    fun theArgumentEncoderErasesTheBufferItOutgrows() {
        val t = MlsTlv()
        val field = MlsTlv::class.java.getDeclaredField("buffer").apply { isAccessible = true }
        val first = field.get(t) as ByteArray
        t.put(MlsField.TEXT, ByteArray(40) { 0x5a })
        assertTrue(first.any { it.toInt() == 0x5a })
        t.put(MlsField.TEXT, ByteArray(200) { 0x5b })
        assertTrue("a larger buffer replaced the first", field.get(t) !== first)
        assertTrue("the outgrown buffer is erased", first.all { it.toInt() == 0 })
        t.erase()
    }

    /** The copy a native call reads and the list itself are erased once the call ends, returned or thrown. */
    @Test
    fun theCopyANativeCallReadsIsErased() {
        val t = MlsTlv().put(MlsField.TEXT, "o postare".toByteArray())
        var seen: ByteArray? = null
        assertEquals(14, t.consume { bytes -> seen = bytes; bytes.size })
        assertTrue(seen!!.all { it.toInt() == 0 })
        assertEquals(0, t.toByteArray().size)
        val u = MlsTlv().put(MlsField.TEXT, "alta".toByteArray())
        try {
            u.consume<Unit> { bytes -> seen = bytes; throw IllegalStateException("refused") }
            fail()
        } catch (e: IllegalStateException) {
            assertTrue(seen.all { it.toInt() == 0 })
            assertEquals(0, u.toByteArray().size)
        }
    }

    /**
     * A decoded reply holds each value once: a received post's text is in its `TEXT` field only, not
     * also in the bytes of the `CONTENT` and `ITEM` records around it, so the owner's erasure of the
     * text it was given leaves no copy in the reply; and a record field is read as a record.
     */
    @Test
    fun aDecodedReplyHoldsEachValueOnce() {
        val text = "secret post".toByteArray()
        val content = MlsTlv().u8(MlsField.KIND, 1).put(MlsField.TEXT, text)
        val item = MlsTlv().u8(MlsField.ITEM_KIND, 1).record(MlsField.CONTENT, content)
        val reply = byteArrayOf(0) + MlsTlv().record(MlsField.ITEM, item).toByteArray()
        val decoded = MlsReply.decode(reply)
        assertTrue(decoded.isOk)
        val owned = decoded.fields.records(MlsField.ITEM).single().record(MlsField.CONTENT).bytes(MlsField.TEXT)
        assertArrayEquals(text, owned)
        val marker = "secret".toByteArray()
        fun holds(b: ByteArray) = (0..b.size - marker.size).any { i -> marker.indices.all { b[i + it] == marker[it] } }
        assertEquals("the text is held once", 1, decoded.fields.values().count(::holds))
        owned.fill(0)
        assertFalse("no other copy", decoded.fields.values().any(::holds))
        for (read in listOf<() -> Unit>(
            { decoded.fields.bytes(MlsField.ITEM) },
            { decoded.fields.all(MlsField.ITEM) },
        )) {
            try {
                read()
                fail("a record field has no raw bytes")
            } catch (e: IllegalStateException) {
                assertTrue(e.message!!.contains("record"))
            }
        }
    }
}
