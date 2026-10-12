package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * PQ1 on the JVM (Phase 9 design §15.5 PQ1, §22.20): "every intro open performs exactly one
 * decapsulation and `k_in` depends on `ss` (spy)".
 *
 * The spy is native. `ghost-dm-host` enables `ghost-client-dm`'s `pq-spy` feature, which wraps
 * every `openIntro` in `pq::spy::assert_intro_open`: the open that succeeds must have performed
 * exactly one X-Wing decapsulation and derived exactly one inner key, a refused one at most one of
 * each, and the same open run again with the decapsulated secret perturbed (every bit of it) must
 * be `NOT_OPEN`. A violation is a Rust panic, which the JNI guard returns as `INTERNAL` and the
 * facade throws on (`IllegalStateException`), so **every intro open of every JVM world run against
 * the host library is under PQ1** — `DmFlowTest`, the privacy worlds, the exit-gate worlds. Where
 * the exception surfaces depends on the world: one that calls the facade directly stops at the
 * first open that breaks PQ1; a crash-enumeration world (`DmCrashWorld`) records what its actor
 * swallowed and fails the run at its end. The panic message itself is not printed (the JNI guard
 * silences panics and the crate prints nothing): a failure reads "openIntro returned INTERNAL", and
 * the `PQ1:` message is what `cargo test -p ghost-client-dm --lib --features jni-bridge -- pq1_`
 * shows for the same shape.
 *
 * What this class adds is the two things only the JVM side can check: that the library the JVM
 * tests load **is** a spy build (a plain build would make every world's PQ1 vacuous), and that
 * intro opens through the real surface pass the assertion at every bucket, for flights of one
 * unacknowledged session and for a re-sent flight, with a refusal before the KEM beside them.
 *
 * **No negative control on the JVM.** No input an honest client can send makes the assertion fire,
 * and the library exports no symbol that could arm one, so nothing here shows a violation reaching
 * `INTERNAL`. The negative control is on the Rust side, over the same `openIntro` body the host
 * library runs (`pq_bump.rs`, `pq1_the_host_open_intro_body_panics_on_a_key_that_ignores_the_secret`,
 * and the `pq-mutants` gate's patches, each of which fails that body); the JVM half was shown once,
 * by hand, with a PM-32 patch built into the host library (design §22.20).
 *
 * Skipped without `-Dghost.dm.native`, like [DmEnvelopeNativeTest]; once the property is set, a
 * library that does not load, or does not carry the assertion, is a failure.
 */
class DmPqSpyNativeTest {

    private val cardIndex = 0
    private val slot = 7
    private val today = 100
    private val genId = 0x51_50_51_31

    /** The three DM buckets (§6.6; DMs never use 1 KiB, R-B2). */
    private val buckets = listOf(4096, 16_384, 65_536)

    private fun requireNative(): String {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        assertTrue(
            "the host library must load from $path: ${DmNative.loadFailure()}",
            DmNative.isAvailable(),
        )
        return path!!
    }

    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    private fun context(branch: Int): Long {
        val opened = DmSessions.openContext(
            messagingBranch = bytes(branch, 32),
            identitySeed = bytes(branch + 1, 32),
            sessionStateKey = bytes(branch + 2, 32),
        )
        assertNotNull("ctxOpen", opened)
        return opened!!.handle
    }

    /**
     * The loaded library carries PQ1's assertion: its panic messages are linked in only when
     * `pq::spy::assert_intro_open` is (the `pq-spy` feature; the shipped `libghost_client_net.so`
     * never enables it, G-R2). The same way `T35.provenanceBuild` recognises a provenance build.
     */
    @Test
    fun theHostLibraryCarriesThePq1Assertion() {
        val path = requireNative()
        val library = File(path).readBytes()
        for (message in listOf(
            "PQ1: an intro open that succeeded performed ",
            "PQ1: an intro open that succeeded derived ",
            "PQ1: a refused intro open performed ",
            "PQ1: a refused intro open derived ",
            "k_in does not depend on ss",
        )) {
            assertTrue(
                "$path does not carry PQ1's assertion ('$message'): build ghost-dm-host with its " +
                    "default features",
                contains(library, message.toByteArray()),
            )
        }
    }

    /**
     * Intro envelopes through the real `sealIntro` and `openIntro` at every bucket: the first flight,
     * the second flight of the same unacknowledged session, and the first flight re-sent in a new
     * envelope. Each opens — so each open passed the native assertion — and an envelope opened as
     * another generation is refused before the KEM, which the assertion allows.
     */
    @Test
    @Suppress("LongMethod")
    fun everyIntroOpenThroughTheSurfacePassesThePq1Assertion() {
        requireNative()
        val alice = context(0x61)
        val bob = context(0x71)
        try {
            val aliceCard = requireNotNull(DmSessions.ownCard(alice, cardIndex)) { "ownCard" }
            val bobCard = requireNotNull(DmSessions.ownCard(bob, cardIndex)) { "ownCard" }
            val bobId = DmCards.parseOrThrow(bobCard.card).identityPk
            val bobKeys = (DmCards.derive(alice, bobCard.card, slot) as DmCards.DeriveResult.Ok).values
            val generation = TestGeneration.of(bob, genId)
            val bobAtAlice = bytes(0x33, 16)

            val outbound = DmSessions.outbound(
                alice, bobAtAlice, bobCard.olmIdentity, generation.fallbackPublic, today,
            )
            assertTrue("outbound: $outbound", outbound is DmSessions.Outbound.Ok)
            outbound as DmSessions.Outbound.Ok

            var stateEnv = outbound.stateEnv
            val flights = mutableListOf<ByteArray>()
            for (index in 0 until 2) {
                val l0 = encode(alice, "flight $index", index)
                val encrypted = DmSessions.encrypt(
                    alice, bobAtAlice, DmSessions.StoredSlot(outbound.sessionId, stateEnv), l0, today,
                )
                assertTrue("encrypt: $encrypted", encrypted is DmSessions.Encrypted.Ok)
                encrypted as DmSessions.Encrypted.Ok
                assertTrue("an unacknowledged session sends PreKey messages", encrypted.isPreKey)
                stateEnv = encrypted.stateEnv
                flights += encrypted.l1
            }
            // Flight 0 at every bucket (the first send and two re-sends, each its own
            // encapsulation), flight 1 at 4 KiB.
            val sends = buckets.map { flights[0] to it } + listOf(flights[1] to buckets[0])

            var opened = 0
            for ((l1, bucket) in sends) {
                val sealed = DmSeal.sealIntro(
                    handle = alice,
                    cardIndex = cardIndex,
                    namespace = bobKeys.inboxNamespace,
                    bucket = bucket,
                    introKeyEnv = bobKeys.introKeyEnv,
                    peerIdentityPk = bobId,
                    peerOlmIdentity = bobCard.olmIdentity,
                    genId = genId,
                    genPublic = generation.xwingPublic,
                    bindingMinute = 29_000_000L,
                    sessionId = outbound.sessionId,
                    replySeedEnv = outbound.replySeedEnv,
                    l1 = l1,
                )
                assertTrue("sealIntro: $sealed", sealed is DmSeal.Sealed.Ok)
                val blob = (sealed as DmSeal.Sealed.Ok).blob
                assertEquals(bucket, blob.size)

                val intro = DmSeal.openIntro(
                    bob, cardIndex, bobKeys.inboxNamespace, genId, generation.secretsEnv,
                    generation.fallbackPublic, blob,
                )
                assertTrue("openIntro at $bucket: $intro", intro is DmSeal.OpenedIntro.Ok)
                intro as DmSeal.OpenedIntro.Ok
                assertArrayEquals(l1, intro.intro.l1)
                assertArrayEquals(aliceCard.card, intro.intro.senderCard)
                opened++

                // Another generation of Bob's: refused before any decapsulation, NOT_OPEN, and the
                // assertion lets a refusal through.
                assertEquals(
                    DmSeal.OpenedIntro.NotOpen,
                    DmSeal.openIntro(
                        bob, cardIndex, bobKeys.inboxNamespace, genId + 1, generation.secretsEnv,
                        generation.fallbackPublic, blob,
                    ),
                )
            }
            assertEquals(sends.size, opened)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    private fun encode(handle: Long, text: String, index: Int): ByteArray {
        val encoded = DmContent.encode(
            handle = handle,
            kind = DmContent.Kind.TEXT,
            messageId = bytes(index + 1, 16),
            authorMinute = 29_000_001L,
            minuteIndex = index,
            timerCode = 0,
            timerVersion = 0L,
            quoteRef = null,
            body = text.toByteArray(),
        )
        assertTrue("encode: $encoded", encoded is DmContent.Encoded.Ok)
        return (encoded as DmContent.Encoded.Ok).l0
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
