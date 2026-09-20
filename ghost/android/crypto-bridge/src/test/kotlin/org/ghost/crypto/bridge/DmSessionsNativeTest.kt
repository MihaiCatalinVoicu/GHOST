package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.URLClassLoader

/**
 * The JVM half of the exit-gate argument (Phase 9 design §15.1): `:crypto-bridge` drives the
 * **real ratchet** through the host build `ghost-dm-host`, not a stand-in.
 *
 * The `android` CI job builds `ghost-dm-host` before the Gradle tests and passes
 * `-Dghost.dm.native=<path>`; without it these tests are skipped (`assumeTrue`), so a developer
 * without the Rust toolchain still builds and tests the module, and the decoder tests of
 * `DmResultCodesTest` still run. When the property is set, a failure here is a real failure.
 */
class DmSessionsNativeTest {

    private fun requireNative() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        // Only the *absent* property is a skip: a developer without the Rust toolchain still
        // builds and tests the module.
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        // Once it is set, this is the CI `android` job of §2.7 and §15.1, which exists to run the
        // real ratchet: a library that does not load fails the job. Assuming it away would leave
        // the job green with every native test skipped, and ci.yml's "if `System.load` fails here,
        // the §17.1 re-plan applies" would never fire.
        assertTrue(
            "the host library must load from $path: ${DmNative.loadFailure()}",
            DmNative.isAvailable(),
        )
    }

    /**
     * The test classpath in a loader of its own, so `DmNative`'s `loaded` lazy is evaluated again
     * — with [DmNative.HOST_LIBRARY_PROPERTY] cleared, which is the unloadable-library path of
     * §2.7 even when the JVM under test was given a library.
     */
    private fun withoutTheLibrary(body: (ClassLoader) -> Unit) {
        val classpath = System.getProperty("java.class.path")
            .split(File.pathSeparator)
            .filter { it.isNotEmpty() }
            .map { File(it).toURI().toURL() }
            .toTypedArray()
        val previous = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        System.clearProperty(DmNative.HOST_LIBRARY_PROPERTY)
        try {
            // No parent but the bootstrap loader: this loader defines its own `DmNative`, so its
            // `loaded` lazy runs again and finds neither the property nor `ghost_client_net`.
            URLClassLoader(classpath, null).use(body)
        } finally {
            if (previous != null) System.setProperty(DmNative.HOST_LIBRARY_PROPERTY, previous)
        }
    }

    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    /** Two contexts with different MESSAGING branches: two devices, one process. */
    private fun context(branch: Int): Long {
        val handle = DmSessions.openContext(
            messagingBranch = bytes(branch, 32),
            identitySeed = bytes(branch + 1, 32),
            sessionStateKey = bytes(branch + 2, 32),
        )
        assertNotNull("ctxOpen", handle)
        return handle!!
    }

    private val today = 100

    @Test
    fun aFullRoundTripRunsThroughTheTypedFacade() {
        requireNative()
        val alice = context(0x11)
        val bob = context(0x21)
        try {
            // Bob's generation: the fallback secret and the X-Wing seed, wrapped by the owner side
            // in S6. Here the test reuses the pair the native side computes for a known secret by
            // asking Bob's own context to seal it, which is what `bundleCreate` will do in S6.
            val generation = TestGeneration.of(bob)
            val contact = bytes(0x31, 16)

            val outbound = DmSessions.outbound(
                handle = alice,
                contactId = contact,
                peerOlmIdentity = generation.olmIdentity,
                peerFallbackKey = generation.fallbackPublic,
                today = today,
            )
            assertTrue("outbound: $outbound", outbound is DmSessions.Outbound.Ok)
            outbound as DmSessions.Outbound.Ok
            assertEquals(32, outbound.sessionId.size)
            assertTrue("the reply seed is wrapped", outbound.replySeedEnv.size >= 32 + 28)

            val first = DmSessions.encrypt(
                handle = alice,
                contactId = contact,
                current = DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                l0 = "first flight".toByteArray(),
                today = today,
            )
            assertTrue("encrypt: $first", first is DmSessions.Encrypted.Ok)
            first as DmSessions.Encrypted.Ok
            assertTrue("the first message is a PreKey message", first.isPreKey)
            assertTrue("it is not acknowledged yet", !first.acknowledged)

            val inbound = DmSessions.inbound(
                handle = bob,
                contactId = contact,
                genId = generation.genId,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                expectedPeerIdentity = TestGeneration.olmIdentityOf(alice),
                l1 = first.l1,
                today = today,
            )
            assertTrue("inbound: $inbound", inbound is DmSessions.Inbound.Ok)
            inbound as DmSessions.Inbound.Ok
            assertArrayEquals("first flight".toByteArray(), inbound.plaintext)
            assertArrayEquals(outbound.sessionId, inbound.sessionId)

            val reply = DmSessions.encrypt(
                handle = bob,
                contactId = contact,
                current = DmSessions.StoredSlot(inbound.sessionId, inbound.stateEnv),
                l0 = "reply".toByteArray(),
                today = today,
            )
            assertTrue("reply: $reply", reply is DmSessions.Encrypted.Ok)
            reply as DmSessions.Encrypted.Ok
            assertTrue("a settled session sends normal messages", !reply.isPreKey)

            val read = DmSessions.decrypt(
                handle = alice,
                contactId = contact,
                current = DmSessions.StoredSlot(outbound.sessionId, first.stateEnv),
                previous = null,
                l1 = reply.l1,
                isPreKey = reply.isPreKey,
                today = today,
            )
            assertTrue("decrypt: $read", read is DmSessions.Decrypted.Ok)
            read as DmSessions.Decrypted.Ok
            assertArrayEquals("reply".toByteArray(), read.plaintext)
            assertEquals(DmSessions.Slot.CURRENT, read.slot)
            assertTrue("the session is acknowledged", read.acknowledged)

            // D2a: the same message twice is a replay, never a forgery.
            val again = DmSessions.decrypt(
                handle = alice,
                contactId = contact,
                current = DmSessions.StoredSlot(outbound.sessionId, read.stateEnv),
                previous = null,
                l1 = reply.l1,
                isPreKey = reply.isPreKey,
                today = today,
            )
            assertEquals(DmSessions.Decrypted.Duplicate, again)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    /**
     * §7.9 point 2 across the JNI boundary: a failed decrypt returns no state, so the caller has
     * nothing to write and the stored envelope stays byte-identical (V-10, mutant MC-29).
     */
    @Test
    fun aFailedDecryptReturnsNoStateToWrite() {
        requireNative()
        val alice = context(0x41)
        val bob = context(0x51)
        try {
            val generation = TestGeneration.of(bob)
            val contact = bytes(0x61, 16)
            val outbound = DmSessions.outbound(
                alice, contact, generation.olmIdentity, generation.fallbackPublic, today,
            ) as DmSessions.Outbound.Ok
            val first = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                "one".toByteArray(),
                today,
            ) as DmSessions.Encrypted.Ok
            val inbound = DmSessions.inbound(
                bob,
                contact,
                generation.genId,
                generation.secretsEnv,
                generation.fallbackPublic,
                TestGeneration.olmIdentityOf(alice),
                first.l1,
                today,
            ) as DmSessions.Inbound.Ok

            val genuine = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, first.stateEnv),
                "two".toByteArray(),
                today,
            ) as DmSessions.Encrypted.Ok
            val forged = genuine.l1.copyOf()
            forged[forged.size - 1] = (forged[forged.size - 1].toInt() xor 0xff).toByte()

            val stored = inbound.stateEnv.copyOf()
            val failed = DmSessions.decrypt(
                bob,
                contact,
                DmSessions.StoredSlot(inbound.sessionId, stored),
                null,
                forged,
                genuine.isPreKey,
                today,
            )
            assertTrue("a forged message must not decrypt", failed !is DmSessions.Decrypted.Ok)
            assertArrayEquals("the caller's envelope is untouched", inbound.stateEnv, stored)

            val ok = DmSessions.decrypt(
                bob,
                contact,
                DmSessions.StoredSlot(inbound.sessionId, stored),
                null,
                genuine.l1,
                genuine.isPreKey,
                today,
            )
            assertTrue("the next valid message still decrypts", ok is DmSessions.Decrypted.Ok)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    /** §2.5: the caller's seed arrays do not outlive the call on the JVM heap. */
    @Test
    fun openingAContextZeroisesTheCallersArrays() {
        requireNative()
        val branch = bytes(0xe1, 32)
        val seed = bytes(0xe2, 32)
        val stateKey = bytes(0xe3, 32)
        val handle = DmSessions.openContext(branch, seed, stateKey)
        assertNotNull(handle)
        try {
            assertArrayEquals(ByteArray(32), branch)
            assertArrayEquals(ByteArray(32), seed)
            assertArrayEquals(ByteArray(32), stateKey)
        } finally {
            DmSessions.closeContext(handle!!)
        }
    }

    /**
     * §2.5 on the path §2.7 calls routine: with no library to load, `openContext` returns no
     * handle **and** still zeroises the caller's arrays. This is the one path where the three
     * arrays are not consumed natively, so it is the one that could hand them back populated.
     */
    @Test
    fun openingAContextWithoutTheLibraryZeroisesTheCallersArrays() {
        val branch = bytes(0xf1, 32)
        val seed = bytes(0xf2, 32)
        val stateKey = bytes(0xf3, 32)
        withoutTheLibrary { loader ->
            val sessions = loader.loadClass("org.ghost.crypto.bridge.DmSessions")
            val instance = sessions.getField("INSTANCE").get(null)
            val openContext = sessions.getMethod(
                "openContext",
                ByteArray::class.java,
                ByteArray::class.java,
                ByteArray::class.java,
            )
            assertNull(
                "an unloadable library gives no context",
                openContext.invoke(instance, branch, seed, stateKey),
            )
        }
        assertArrayEquals(ByteArray(32), branch)
        assertArrayEquals(ByteArray(32), seed)
        assertArrayEquals(ByteArray(32), stateKey)
    }

    /** §2.5: a closed or foreign handle is `CRYPTO_UNAVAILABLE`, never a crash. */
    @Test
    fun aClosedOrForeignHandleIsUnavailable() {
        requireNative()
        val handle = context(0x71)
        DmSessions.closeContext(handle)
        val outcome = DmSessions.outbound(handle, bytes(1, 16), bytes(2, 32), bytes(3, 32), today)
        assertEquals(DmSessions.Outbound.Unavailable, outcome)
        assertEquals(
            DmSessions.Pruned.Unavailable,
            DmSessions.prune(handle, bytes(1, 16), DmSessions.StoredSlot(bytes(2, 32), bytes(3, 64)), today),
        )
    }

    /** §22.8.2 rule 1: a low-order peer key is refused, with a typed code. */
    @Test
    fun aNonContributoryPeerKeyIsInvalidKey() {
        requireNative()
        val handle = context(0x81)
        try {
            val outcome = DmSessions.outbound(
                handle, bytes(1, 16), ByteArray(32), bytes(3, 32), today,
            )
            assertEquals(DmSessions.Outbound.InvalidKey, outcome)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    /** §8.4: the safety number is computed natively, with no network I/O (T31). */
    @Test
    fun theSafetyNumberIsSixtyDigitsAndSymmetric() {
        requireNative()
        val a = bytes(0x91, 32)
        val aOlm = bytes(0x92, 32)
        val b = bytes(0x93, 32)
        val bOlm = bytes(0x94, 32)
        val mine = DmSessions.safetyNumber(a, aOlm, b, bOlm)
        val theirs = DmSessions.safetyNumber(b, bOlm, a, aOlm)
        assertNotNull(mine)
        assertNotNull(theirs)
        assertEquals(60, mine!!.digits.length)
        assertTrue(mine.digits.all { it.isDigit() })
        assertEquals("both parties display the same number", mine.digits, theirs!!.digits)
        assertEquals(65, mine.scannable.size)
    }

    /** §7.7 point 4: the age bound removes nothing from a session that has skipped nothing. */
    @Test
    fun pruningASessionWithoutSkippedKeysRemovesNothing() {
        requireNative()
        val alice = context(0xa1)
        val bob = context(0xb1)
        try {
            val generation = TestGeneration.of(bob)
            val contact = bytes(0xc1, 16)
            val outbound = DmSessions.outbound(
                alice, contact, generation.olmIdentity, generation.fallbackPublic, today,
            ) as DmSessions.Outbound.Ok
            val slot = DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv)
            val pruned = DmSessions.prune(alice, contact, slot, today + 51)
            assertTrue("prune: $pruned", pruned is DmSessions.Pruned.Ok)
            assertEquals(0L, (pruned as DmSessions.Pruned.Ok).removed)

            // The unanswered session has no receiver chain yet, so every key is a new chain.
            val position = DmSessions.chainPosition(alice, contact, slot, bytes(0xd1, 32))
            assertEquals(DmSessions.ChainPosition.NewChain, position)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    @Test
    fun aMissingNativeLibraryIsUnavailableNotAnError() {
        // Independent of the property: the facade must answer without the library too.
        if (DmNative.isAvailable()) return
        assertNull(DmSessions.openContext(bytes(1, 32), bytes(2, 32), bytes(3, 32)))
        assertEquals(
            DmSessions.Outbound.Unavailable,
            DmSessions.outbound(0L, bytes(1, 16), bytes(2, 32), bytes(3, 32), today),
        )
        assertNull(DmSessions.safetyNumber(bytes(1, 32), bytes(2, 32), bytes(3, 32), bytes(4, 32)))
    }
}
