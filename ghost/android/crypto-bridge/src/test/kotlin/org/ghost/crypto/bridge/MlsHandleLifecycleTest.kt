package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.URLClassLoader

/**
 * The handle lifecycle of the channel surface (Phase 10 design §10.2; slice S2b): a closed or
 * foreign handle, and a channel not open on the handle, are `CRYPTO_UNAVAILABLE`; a second close
 * is `CRYPTO_UNAVAILABLE`, never a crash; rows of one channel do not open as another's
 * (`STATE_CORRUPT`); a channel's pseudonym cannot be swapped under an open handle (`INVALID_KEY`);
 * a panic inside a call is `INTERNAL` and leaves the handle usable (the registry recovers its
 * poisoned lock); a missing library is `CRYPTO_UNAVAILABLE`, not an error.
 */
class MlsHandleLifecycleTest {

    private val day = 20_725
    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    @Before
    fun setUp() {
        val path = System.getProperty(MlsNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "ghost-dm-host is not loaded (-Dghost.dm.native)",
            !path.isNullOrEmpty() && MlsNative.isAvailable(),
        )
    }

    private fun open(key: Int): Long {
        val reply = MlsReply.decode(MlsNative.ctxOpen(bytes(key, 32)))
        assertEquals(MlsCode.OK, reply.code)
        return reply.fields.i64(MlsField.HANDLE)
    }

    private fun code(reply: ByteArray?): MlsCode = MlsReply.decode(reply).code

    @Test
    fun aClosedHandleIsUnavailableAndASecondCloseToo() {
        val h = open(1)
        val channel = bytes(2, 32)
        assertEquals(MlsCode.OK, code(MlsNative.channelOpen(h, channel, bytes(3, 32))))
        assertEquals(MlsCode.OK, code(MlsNative.ctxClose(h)))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.ctxClose(h)))
        // Use after close: every function that takes the handle.
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.channelOpen(h, channel, bytes(3, 32))))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.keyPackage(h, channel, 1, day)))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.roster(h, channel, ByteArray(0), day)))
        assertEquals(
            MlsCode.CRYPTO_UNAVAILABLE,
            code(MlsNative.generation(h, channel, ByteArray(60), 0, 0, byteArrayOf(0))),
        )
        // A handle that never existed, and one of the DM surface's small numbers.
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.ctxClose(1L)))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.ctxClose(0L)))
        // The facade answers the same codes.
        val crypto = (ChannelCrypto.open(bytes(4, 32)) as MlsOutcome.Ok).value
        assertEquals(MlsCode.OK, crypto.close().code)
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, crypto.close().code)
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, crypto.openChannel(channel, bytes(3, 32)).code)
    }

    @Test
    fun aChannelNotOpenOnTheHandleIsUnavailable() {
        val a = open(5)
        val b = open(6)
        val channel = bytes(7, 32)
        val p = MlsReply.decode(MlsNative.channelOpen(a, channel, bytes(8, 32))).fields.bytes(MlsField.PSEUDONYM)
        // Open on a, not on b: the wrong handle.
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.keyPackage(b, channel, 1, day)))
        assertEquals(MlsCode.OK, code(MlsNative.keyPackage(a, channel, 1, day)))
        // The same seed again is a no-op with the same P; another seed is refused.
        assertArrayEquals(p, MlsReply.decode(MlsNative.channelOpen(a, channel, bytes(8, 32))).fields.bytes(MlsField.PSEUDONYM))
        assertEquals(MlsCode.INVALID_KEY, code(MlsNative.channelOpen(a, channel, bytes(9, 32))))
        // Close the channel: a second close, and every call on it, are unavailable.
        assertEquals(MlsCode.OK, code(MlsNative.channelClose(a, channel)))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.channelClose(a, channel)))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE, code(MlsNative.keyPackage(a, channel, 1, day)))
        // Reopened with another seed after the close: allowed.
        assertEquals(MlsCode.OK, code(MlsNative.channelOpen(a, channel, bytes(9, 32))))
        // Arguments of the wrong width.
        assertEquals(MlsCode.INVALID_KEY, code(MlsNative.ctxOpen(bytes(1, 31))))
        assertEquals(MlsCode.INVALID_KEY, code(MlsNative.channelOpen(a, channel, bytes(1, 33))))
        assertEquals(MlsCode.NON_CANONICAL, code(MlsNative.channelOpen(a, bytes(1, 31), bytes(1, 32))))
        assertEquals(MlsCode.NON_CANONICAL, code(MlsNative.keyPackage(a, channel, 4, day)))
        assertEquals(MlsCode.NON_CANONICAL, code(MlsNative.keyPackage(a, channel, 1, -1)))
        assertEquals(MlsCode.OK, code(MlsNative.ctxClose(a)))
        assertEquals(MlsCode.OK, code(MlsNative.ctxClose(b)))
    }

    /** Rows of channel X passed with channel Y's id, or under another state key, do not open. */
    @Test
    fun rowsOfAnotherChannelOrContextAreStateCorrupt() {
        val h = open(10)
        val x = bytes(11, 32)
        val y = bytes(12, 32)
        val p = MlsReply.decode(MlsNative.channelOpen(h, x, bytes(13, 32))).fields.bytes(MlsField.PSEUDONYM)
        MlsNative.channelOpen(h, y, bytes(13, 32))
        val policy = ChannelPolicy(x, 0, 4, 0, 0, 1, 63, 0, ByteArray(0), listOf(p), listOf(p))
        val created = MlsReply.decode(MlsNative.groupCreate(h, x, policy.toRecord().toByteArray(), day))
        assertEquals(MlsCode.OK, created.code)
        val rows = MlsChange.all(created.fields).map { MlsRow(it.scope, it.key, it.env!!) }
        assertEquals(MlsCode.OK, code(MlsNative.roster(h, x, MlsRow.encode(rows), day)))
        assertEquals(MlsCode.STATE_CORRUPT, code(MlsNative.roster(h, y, MlsRow.encode(rows), day)))
        val other = open(14)
        MlsNative.channelOpen(other, x, bytes(13, 32))
        assertEquals(MlsCode.STATE_CORRUPT, code(MlsNative.roster(other, x, MlsRow.encode(rows), day)))
        // A malformed row list is NON_CANONICAL, an empty one has no group.
        assertEquals(MlsCode.NON_CANONICAL, code(MlsNative.roster(h, x, byteArrayOf(0x04, 0, 0, 0), day)))
        assertEquals(MlsCode.STATE_CORRUPT, code(MlsNative.roster(h, x, ByteArray(0), day)))
        // A policy that is not this channel's (§5.3: the group id is the channel id).
        val wrong = ChannelPolicy(y, 0, 4, 0, 0, 1, 63, 0, ByteArray(0), listOf(p), listOf(p))
        assertEquals(MlsCode.INVALID_POLICY, code(MlsNative.groupCreate(h, x, wrong.toRecord().toByteArray(), day)))
        MlsNative.ctxClose(h)
        MlsNative.ctxClose(other)
    }

    /**
     * A panic inside a call (`MlsVectors` plants one while the context is held, as a library panic
     * would raise it) is `INTERNAL` under the silent hook, and the surface stays usable: the same
     * handle serves the next call and still closes.
     */
    @Test
    fun aPanicIsInternalAndTheHandleSurvivesIt() {
        val h = open(15)
        val channel = bytes(16, 32)
        assertEquals(MlsCode.OK, code(MlsNative.channelOpen(h, channel, bytes(17, 32))))
        val (panicked, _) = MlsVectors.raw(MlsVectors.PANIC_IN_CONTEXT, MlsVectors.u64(h))
        assertEquals(MlsCode.INTERNAL.wire, panicked)
        val (again, _) = MlsVectors.raw(MlsVectors.PANIC_IN_CONTEXT, MlsVectors.u64(h))
        assertEquals("a poisoned registry would make this a different failure", MlsCode.INTERNAL.wire, again)
        assertEquals(MlsCode.OK, code(MlsNative.keyPackage(h, channel, 1, day)))
        assertEquals(MlsCode.OK, code(MlsNative.ctxClose(h)))
        // On a closed handle nothing panics: the context is not there.
        val (closed, _) = MlsVectors.raw(MlsVectors.PANIC_IN_CONTEXT, MlsVectors.u64(h))
        assertEquals(MlsCode.CRYPTO_UNAVAILABLE.wire, closed)
        // The facade throws on INTERNAL, as §10.2 says.
        try {
            mlsUnexpected(MlsCode.INTERNAL, "ctxOpen")
            error("unreachable")
        } catch (e: IllegalStateException) {
            assertEquals("channel native ctxOpen returned INTERNAL", e.message)
        }
    }

    /** A missing library is an outcome (`CRYPTO_UNAVAILABLE`), not an error. */
    @Test
    fun aMissingNativeLibraryIsUnavailableNotAnError() {
        val classpath = System.getProperty("java.class.path").orEmpty()
            .split(File.pathSeparator)
            .filter { it.isNotEmpty() }
            .map { File(it).toURI().toURL() }
            .toTypedArray()
        val previous = System.getProperty(MlsNative.HOST_LIBRARY_PROPERTY)
        System.clearProperty(MlsNative.HOST_LIBRARY_PROPERTY)
        try {
            URLClassLoader(classpath, null).use { loader ->
                val companion = loader.loadClass("org.ghost.crypto.bridge.ChannelCrypto\$Companion")
                val instance = loader.loadClass("org.ghost.crypto.bridge.ChannelCrypto").getField("Companion").get(null)
                val outcome = companion.getMethod("open", ByteArray::class.java).invoke(instance, ByteArray(32))
                assertEquals("Refused", outcome!!.javaClass.simpleName)
                val code = outcome.javaClass.getMethod("getCode").invoke(outcome)
                assertEquals("CRYPTO_UNAVAILABLE", code?.toString())
            }
        } finally {
            if (previous != null) System.setProperty(MlsNative.HOST_LIBRARY_PROPERTY, previous)
        }
    }
}
