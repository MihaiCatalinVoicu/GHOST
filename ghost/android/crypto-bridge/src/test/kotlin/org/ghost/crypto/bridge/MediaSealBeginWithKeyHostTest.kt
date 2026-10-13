package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The **function-14 JVM test** of Phase 11 design §22.3's pending list: `testSealBeginWithKey`
 * and `testVectors` (§13.2's two host-only entries, §15.6's model-relay re-derivation) driven
 * through the host library `ghost-dm-host` over JNI — the same route the media privacy world
 * will take when the model relay re-derives a blob on `get`.
 *
 * The checks replay `protocol/test-vectors/media_object.txt`: the derivations oracle must
 * reproduce the file's `k_p`/`k_m`/`commit`, the `key_env` oracle the file's `[key_env]`
 * envelopes (the section exists precisely because S2's dev cycle back generates it through the
 * shipped wrap code), and a full re-seal of `[object image_class0]` through `testSealBeginWithKey`
 * → `sealAppend` → `sealFinish` must reproduce the object's `manifest_hash` and every fragment
 * hash — 16 fragments, the manifest and the `key_env` binding, byte for byte. Native randomness
 * is the OS's (§15.1), but every byte the media format fixes is deterministic given `(K_f,
 * object_id, content)`, so the re-seal has an exact expected answer.
 */
class MediaSealBeginWithKeyHostTest {

    private fun requireNative() {
        val path = System.getProperty(DmNative.HOST_LIBRARY_PROPERTY)
        assumeTrue(
            "set -D${DmNative.HOST_LIBRARY_PROPERTY} to the ghost-dm-host library",
            !path.isNullOrEmpty(),
        )
        assertTrue(
            "the host library must load from $path: ${MediaNative.loadFailure()}",
            MediaNative.isAvailable(),
        )
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

    @Test
    fun derivationsThroughTestVectorsMatchTheVectorFile() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val d = MediaHostVectors.derivations(v.kf, v.objectId)
        assertEquals("derivations: $d", MediaCode.OK, d.code)
        assertArrayEquals("k_p", v.kp, d.fields[0x14])
        assertArrayEquals("k_m", v.km, d.fields[0x15])
        assertArrayEquals("commit", v.commit, d.fields[0x16])
    }

    @Test
    fun opIdIsSixteenBytesAndDeterministic() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val first = MediaHostVectors.opId(v.objectId, ordinal = 3, retryGen = 1, resendCount = 2)
        assertEquals("op_id: $first", MediaCode.OK, first.code)
        assertEquals(16, first.fields[0x17]!!.size)
        val second = MediaHostVectors.opId(v.objectId, ordinal = 3, retryGen = 1, resendCount = 2)
        assertArrayEquals("op_id is deterministic", first.fields[0x17], second.fields[0x17])
        // `op_id` separates the resend counter (no two ops of one object share it).
        val resend = MediaHostVectors.opId(v.objectId, ordinal = 3, retryGen = 1, resendCount = 3)
        assertTrue(
            "a resend is another op",
            !first.fields[0x17]!!.contentEquals(resend.fields[0x17]),
        )
    }

    @Test
    fun keyEnvThroughTestVectorsMatchesTheVectorFile() {
        requireNative()
        val k = MediaHostVectors.keyEnvVector()
        val out = MediaHostVectors.keyEnv(
            k.stateKey, role = 1, k.destId, k.objectId, k.manifestHash, k.nonce, k.kf,
        )
        assertEquals("key_env(out): $out", MediaCode.OK, out.code)
        assertArrayEquals("the out envelope", k.out, out.fields[0x0c])
        val inEnv = MediaHostVectors.keyEnv(
            k.stateKey, role = 2, k.destId, k.objectId, k.manifestHash, k.nonce, k.kf,
        )
        assertEquals("key_env(in): $inEnv", MediaCode.OK, inEnv.code)
        assertArrayEquals("the in envelope", k.inEnv, inEnv.fields[0x0c])
    }

    @Test
    fun resealingTheVectorObjectThroughJniReproducesItsManifest() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val handle = context(0x71)
        try {
            val begun = MediaHostVectors.sealBeginWithKey(
                handle, v.kf, v.objectId, kind = v.kind, viewOnce = 0, maxClass = 0,
            )
            assertTrue("testSealBeginWithKey: $begun", begun.isOk)
            val sealerId = begun.i64(MediaField.SEALER_ID)
            assertArrayEquals("the object id echoes", v.objectId, begun.bytes(MediaField.OBJECT_ID))

            val appended = MediaCrypto.append(handle, sealerId, v.content)
            assertTrue("sealAppend: $appended", appended is MediaCrypto.Appended.Ok)
            val finished = MediaCrypto.finish(handle, sealerId, v.preview)
            assertTrue("sealFinish: $finished", finished is MediaCrypto.FinishedResult.Ok)
            val done = (finished as MediaCrypto.FinishedResult.Ok).finished

            // The whole sealed object, byte for byte, against the committed vector.
            assertArrayEquals("manifest_hash", v.manifestHash, done.manifestHash)
            assertEquals(65_536, done.manifestBlob.size)
            assertEquals("class", v.classCode, done.classCode)
            assertEquals("content_len", v.contentLen, done.contentLen)
            assertEquals("width", v.width, done.width)
            assertEquals("height", v.height, done.height)
            assertEquals("duration", v.durationMs, done.durationMs)
            assertTrue("key_env", done.keyEnv.size >= 32 + 28)
            assertTrue("the preview rides the manifest", done.preview.isNotEmpty())

            val sealed = ((appended as MediaCrypto.Appended.Ok).chunks + done.chunks)
                .sortedBy { it.index }
            assertEquals("chunks", v.chunks, sealed.size)
            sealed.forEachIndexed { i, chunk ->
                assertEquals("chunk $i", i, chunk.index)
                assertEquals("fragments of chunk $i", 4, chunk.fragments.size)
                chunk.fragments.forEachIndexed { j, _ ->
                    assertArrayEquals(
                        "fragment ${i * 4 + j}",
                        v.fragmentHashes[i * 4 + j],
                        chunk.hashes[j],
                    )
                }
            }

            // The sealer is gone at finish: its registry id is foreign again, so a further append
            // is UNAVAILABLE, never a seal. (A spent-but-live sealer — one the walker refused —
            // answers SEQUENCE instead; that is the next test.)
            val again = MediaCrypto.append(handle, sealerId, v.content)
            assertEquals(MediaCrypto.Appended.Unavailable, again)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    @Test
    fun aWalkerRefusalSpendsTheSealerAndARefusedIndexReuseIsARuleNotAHole() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val handle = context(0x74)
        try {
            val begun = MediaHostVectors.sealBeginWithKey(handle, v.kf, v.objectId, v.kind, 0, 0)
            assertTrue("testSealBeginWithKey: $begun", begun.isOk)
            val sealerId = begun.i64(MediaField.SEALER_ID)

            // The walked image ends at content_len; a non-zero byte after it inside chunk 0 breaks
            // the pad rule when the chunk completes, and the sealer is spent (NON_CANONICAL).
            val garbage = v.content + ByteArray(262_144) { 0x55 }
            val refused = MediaCrypto.append(handle, sealerId, garbage)
            assertEquals(MediaCrypto.Appended.NonCanonical, refused)

            // A spent sealer refuses every further call with SEQUENCE — the state machine, not
            // a hole the refused bytes could leak through.
            val after = MediaCrypto.append(handle, sealerId, garbage)
            assertEquals(MediaCrypto.Appended.Sequence, after)
            val finish = MediaCrypto.finish(handle, sealerId, v.preview)
            assertEquals(MediaCrypto.FinishedResult.Sequence, finish)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    @Test
    fun aThirdLiveSealerHitsTheRegistryCap() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val handle = context(0x72)
        try {
            val first = MediaHostVectors.sealBeginWithKey(
                handle, v.kf, v.objectId, v.kind, 0, 0,
            )
            val second = MediaHostVectors.sealBeginWithKey(
                handle, v.kf, v.objectId, v.kind, 0, 0,
            )
            assertTrue(first.isOk && second.isOk)
            val third = MediaHostVectors.sealBeginWithKey(
                handle, v.kf, v.objectId, v.kind, 0, 0,
            )
            assertEquals("two sealers live; the third is the cap", MediaCode.LIMIT, third.code)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    @Test
    fun malformedTestRequestsAreNonCanonical() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        // Wrong-sized arguments cross JNI: the native `fixed` checks refuse them. (The well-formed
        // wrappers assert shapes before calling; these requests are built by hand.)
        assertEquals(
            MediaCode.NON_CANONICAL,
            rawRequest(byteArrayOf(0x01) + v.kf.copyOf(31) + v.objectId),
        )
        assertEquals(
            MediaCode.NON_CANONICAL,
            rawRequest(byteArrayOf(0x01) + v.kf + v.objectId.copyOf(15)),
        )
        assertEquals("an unknown request byte", MediaCode.NON_CANONICAL, rawRequest(byteArrayOf(0x04)))
        val handle = context(0x73)
        try {
            val bad = MediaHostVectors.sealBeginWithKey(handle, v.kf, v.objectId.copyOf(15), v.kind, 0, 0)
            assertEquals(MediaCode.NON_CANONICAL, bad.code)
        } finally {
            DmSessions.closeContext(handle)
        }
    }

    /** A `testVectors` request built by hand, answered by its code alone. */
    private fun rawRequest(request: ByteArray): MediaCode {
        val reply = MediaNative.testVectors(0, request)
        return if (reply == null || reply.isEmpty()) MediaCode.INTERNAL
        else MediaCode.fromWire(reply[0].toInt()) ?: MediaCode.INTERNAL
    }
}
