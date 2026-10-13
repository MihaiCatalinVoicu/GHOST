package org.ghost.crypto.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * The **held-replay JVM test** of Phase 11 design §22.3's pending list (T45's key-slot tests
 * through functions 13 and 14 and the held replay): a kind-5 (MEDIA) L0 through the real session
 * surface, asserting §4.2's key-slot rule — `encrypt` (function 8) fills the descriptor's slot
 * with `K_f` before the session layer sees the L0; `sessionInbound` (function 14, the first
 * message **and** the held replay — the function `HeldReplay.kt` drives after a key change) and
 * `decrypt` (function 13) read it out, wrap it into a fresh `key_env` under the `in` binding and
 * re-zero the slot, so every L0 Kotlin sees has a zero slot and the only durable form of the key
 * is the envelope.
 *
 * The object itself is sealed through the host-only `testSealBeginWithKey` with the vector's
 * `(K_f, object_id)`, so the descriptor's `manifest_hash` is the vector's and a reader opened
 * with the taken `key_env` must open the very manifest `sealFinish` produced. The kind-5 L0 is
 * built through the shipped `l0Encode` (the descriptor layout is `descriptor.rs`'s normative
 * table); `DmContent.Kind` deliberately refuses MEDIA until S3's pipeline, so the test calls
 * `DmNative.l0Encode` directly with kind 5 — the same wire value S3's facade addition will send.
 */
class MediaHeldReplayHostTest {

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

    private val today = 100

    /** Seals the vector object through [handle]'s context: the finished object and every sealed chunk. */
    private fun seal(
        handle: Long,
        v: MediaHostVectors.ObjectVector,
    ): Pair<MediaCrypto.Finished, List<MediaCrypto.SealedChunk>> {
        val begun = MediaHostVectors.sealBeginWithKey(handle, v.kf, v.objectId, v.kind, 0, 0)
        assertTrue("testSealBeginWithKey: $begun", begun.isOk)
        val sealerId = begun.i64(MediaField.SEALER_ID)
        val appended = MediaCrypto.append(handle, sealerId, v.content)
        assertTrue("sealAppend: $appended", appended is MediaCrypto.Appended.Ok)
        val finished = MediaCrypto.finish(handle, sealerId, v.preview)
        assertTrue("sealFinish: $finished", finished is MediaCrypto.FinishedResult.Ok)
        val done = (finished as MediaCrypto.FinishedResult.Ok).finished
        val all = (appended as MediaCrypto.Appended.Ok).chunks + done.chunks
        return done to all
    }

    /** The kind-5 body: `descriptor.rs`'s 86 fixed bytes plus the caption, slot zero. */
    private fun descriptor(v: MediaHostVectors.ObjectVector): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x01) // d_version
        out.write(v.kind)
        out.write(if (v.viewOnce) 1 else 0)
        out.write(v.classCode)
        out.write(v.objectId)
        out.write(ByteArray(32)) // key_slot: zero in every L0 Kotlin builds (§4.2)
        out.write(v.manifestHash)
        out.write(v.caption.size shr 8)
        out.write(v.caption.size)
        out.write(v.caption)
        return out.toByteArray()
    }

    /** Encodes the L0 through the shipped codec; [DmContent] will not expose MEDIA until S3. */
    private fun encodeMediaL0(handle: Long, body: ByteArray): ByteArray {
        val result = DmResult.decode(
            DmNative.l0Encode(
                handle,
                0x05,
                bytes(0x5a, 16),
                0x10_00_00,
                0,
                0,
                0,
                DM_NO_BYTES,
                body,
                DM_NO_CONTACT,
                0,
                DM_NO_BYTES,
                DM_NO_BYTES,
                0,
                0,
                0L,
                DM_NO_BYTES,
                DM_NO_BYTES,
                0,
            ),
        )
        assertTrue("l0Encode: ${result.code}", result.isOk)
        return result.bytes(DmField.L0)
    }

    /** The key slot of an encoded L0: bytes [20..52) of the kind-5 body. */
    private fun keySlot(l0: ByteArray): ByteArray {
        // §7.1's fixed prefix is 30 bytes, then the u32 body length: the body starts at 34.
        return l0.copyOfRange(34 + 20, 34 + 52)
    }

    @Test
    fun function14TakesTheSlotOfAFirstFlightMediaMessage() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val alice = context(0x81)
        val bob = context(0x82)
        try {
            val contact = ByteArray(16) // testSealBeginWithKey binds its envelopes to dest 0^16.
            val (done, sealed) = seal(alice, v)
            val sealedByIndex = sealed.associateBy { it.index }
            val l0 = encodeMediaL0(alice, descriptor(v))
            assertTrue("the sender's L0 has a zero slot", keySlot(l0).all { it == 0.toByte() })

            val generation = TestGeneration.of(bob)
            val outbound = DmSessions.outbound(
                alice, contact, generation.olmIdentity, generation.fallbackPublic, today,
            )
            assertTrue("outbound: $outbound", outbound is DmSessions.Outbound.Ok)
            outbound as DmSessions.Outbound.Ok

            val encrypted = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                l0,
                today,
                mediaKeyEnv = done.keyEnv,
            )
            assertTrue("encrypt: $encrypted", encrypted is DmSessions.Encrypted.Ok)
            encrypted as DmSessions.Encrypted.Ok
            assertTrue("the first flight is a PreKey message", encrypted.isPreKey)

            // Function 14 — the first message and the held replay's driver.
            val inbound = DmSessions.inbound(
                bob,
                contact,
                generation.genId,
                generation.secretsEnv,
                generation.fallbackPublic,
                TestGeneration.olmIdentityOf(alice),
                encrypted.l1,
                today,
            )
            assertTrue("inbound: $inbound", inbound is DmSessions.Inbound.Ok)
            inbound as DmSessions.Inbound.Ok

            // §4.2: the key left as key_env; the L0 that reaches Kotlin is byte-identical to
            // the sender's, slot included — zero.
            val keyEnv = inbound.mediaKeyEnv
            assertNotNull("a media L0 lands its key_env", keyEnv)
            assertEquals(60, keyEnv!!.size)
            assertArrayEquals("every L0 Kotlin sees has a zero slot", l0, inbound.plaintext)
            assertTrue(keySlot(inbound.plaintext).all { it == 0.toByte() })

            // The taken envelope opens under the (in, contact, object_id, manifest_hash) binding:
            // proven natively by opening a reader on the manifest sealFinish produced.
            val opened = MediaCrypto.openReader(
                bob,
                keyEnv,
                MediaCrypto.Role.IN,
                contact,
                v.objectId,
                done.manifestHash,
                done.manifestBlob,
                MediaCrypto.Kind.IMAGE,
                viewOnce = false,
                classCode = v.classCode,
                readable = true,
            )
            assertTrue("readerOpen: $opened", opened is MediaCrypto.Opened.Ok)
            opened as MediaCrypto.Opened.Ok
            assertEquals("content_len", v.contentLen, opened.reader.contentLen)
            assertEquals("the manifest's fragment hashes", v.chunks * 4, opened.reader.hashes.size)

            // The validation pass walks every chunk in order and agrees with the manifest.
            for (i in 0 until v.chunks) {
                val packed = ByteArrayOutputStream()
                sealedByIndex.getValue(i).fragments.forEach { packed.write(it) }
                val validated = MediaCrypto.chunk(
                    bob, opened.reader.id, i, packed.toByteArray(), MediaCrypto.Mode.VALIDATE,
                )
                assertTrue("validate chunk $i: $validated", validated is MediaCrypto.Chunked.Ok)
            }
            assertEquals(
                MediaCrypto.Validated.Ok,
                MediaCrypto.validateFinish(bob, opened.reader.id),
            )

            // Read mode exposes exactly the content bytes the object carries (the zero padding of
            // the last content chunk is trimmed — "at most 262 128" is the bound, not the size).
            val packed0 = ByteArrayOutputStream()
            sealedByIndex.getValue(0).fragments.forEach { packed0.write(it) }
            val read = MediaCrypto.chunk(
                bob, opened.reader.id, 0, packed0.toByteArray(), MediaCrypto.Mode.READ,
            )
            assertTrue("read chunk 0: $read", read is MediaCrypto.Chunked.Ok)
            val content = (read as MediaCrypto.Chunked.Ok).content
            assertArrayEquals("the walked content, padding trimmed", v.content, content)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    @Test
    fun function13TakesTheSlotOfASettledSessionMediaMessage() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val alice = context(0x83)
        val bob = context(0x84)
        try {
            val contact = ByteArray(16)
            // Alice's first flight is plain text; Bob answers with a media message on the
            // settled session — function 13's slot take.
            val generation = TestGeneration.of(bob)
            val outbound = DmSessions.outbound(
                alice, contact, generation.olmIdentity, generation.fallbackPublic, today,
            ) as DmSessions.Outbound.Ok
            val firstL0 = DmResult.decode(
                DmNative.l0Encode(
                    alice, 0x01, bytes(0x5c, 16), 0x10_00_02, 0, 0, 0,
                    DM_NO_BYTES, "settle the session".toByteArray(), DM_NO_CONTACT,
                    0, DM_NO_BYTES, DM_NO_BYTES, 0, 0, 0L, DM_NO_BYTES, DM_NO_BYTES, 0,
                ),
            )
            assertTrue("text l0 encodes", firstL0.isOk)
            // encrypt strict-decodes the L0 for the key slot (§4.2): the bytes must be a real
            // record, not a raw string.
            val first = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                firstL0.bytes(DmField.L0),
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
            assertNull("a text L0 leaves no key_env", inbound.mediaKeyEnv)

            val (done, _) = seal(bob, v)
            val l0 = encodeMediaL0(bob, descriptor(v))
            val media = DmSessions.encrypt(
                bob,
                contact,
                DmSessions.StoredSlot(inbound.sessionId, inbound.stateEnv),
                l0,
                today,
                mediaKeyEnv = done.keyEnv,
            )
            assertTrue("encrypt: $media", media is DmSessions.Encrypted.Ok)
            media as DmSessions.Encrypted.Ok
            assertTrue("the settled session sends normal messages", !media.isPreKey)

            val read = DmSessions.decrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, first.stateEnv),
                null,
                media.l1,
                media.isPreKey,
                today,
            )
            assertTrue("decrypt: $read", read is DmSessions.Decrypted.Ok)
            read as DmSessions.Decrypted.Ok
            val keyEnv = read.mediaKeyEnv
            assertNotNull("a media L0 lands its key_env", keyEnv)
            assertEquals(60, keyEnv!!.size)
            assertArrayEquals("every L0 Kotlin sees has a zero slot", l0, read.plaintext)

            val opened = MediaCrypto.openReader(
                alice,
                keyEnv,
                MediaCrypto.Role.IN,
                contact,
                v.objectId,
                done.manifestHash,
                done.manifestBlob,
                MediaCrypto.Kind.IMAGE,
                viewOnce = false,
                classCode = v.classCode,
                readable = true,
            )
            assertTrue("readerOpen with the taken envelope: $opened", opened is MediaCrypto.Opened.Ok)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    @Test
    fun aMediaL0WithoutItsEnvelopeIsARefusedCallerBug() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val alice = context(0x85)
        val bob = context(0x86)
        try {
            val contact = ByteArray(16)
            val (done, _) = seal(alice, v)
            val l0 = encodeMediaL0(alice, descriptor(v))
            val generation = TestGeneration.of(bob)
            val outbound = DmSessions.outbound(
                alice, contact, generation.olmIdentity, generation.fallbackPublic, today,
            ) as DmSessions.Outbound.Ok

            // encrypt with an empty mediaKeyEnv: media_slot_fill refuses (NON_CANONICAL, mapped
            // to StateCorrupt by the facade) and nothing is encrypted.
            val missing = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                l0,
                today,
                mediaKeyEnv = ByteArray(0),
            )
            assertEquals(DmSessions.Encrypted.StateCorrupt, missing)

            // A text L0 with a media envelope is the opposite caller bug, same refusal.
            val text = DmResult.decode(
                DmNative.l0Encode(
                    alice, 0x01, bytes(0x5b, 16), 0x10_00_01, 0, 0, 0,
                    DM_NO_BYTES, "plain text".toByteArray(), DM_NO_CONTACT,
                    0, DM_NO_BYTES, DM_NO_BYTES, 0, 0, 0L, DM_NO_BYTES, DM_NO_BYTES, 0,
                ),
            )
            assertTrue("text l0 encodes", text.isOk)
            val mismatched = DmSessions.encrypt(
                alice,
                contact,
                DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv),
                text.bytes(DmField.L0),
                today,
                mediaKeyEnv = done.keyEnv,
            )
            assertEquals(DmSessions.Encrypted.StateCorrupt, mismatched)
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }

    @Test
    fun readModeRequiresTheReadableAttestationAndInRangeIndices() {
        requireNative()
        val v = MediaHostVectors.objectVector("image_class0")
        val handle = context(0x87)
        try {
            val contact = ByteArray(16)
            val (done, sealed) = seal(handle, v)
            // sealFinish's envelope is bound (out, 0^16, object_id, manifest_hash) — the binding
            // a sender's own reader opens with; the taken key_env is the same envelope under
            // (in, contact, …), proven in the round-trip tests above.
            val opened = MediaCrypto.openReader(
                handle,
                done.keyEnv,
                MediaCrypto.Role.OUT,
                contact,
                v.objectId,
                done.manifestHash,
                done.manifestBlob,
                MediaCrypto.Kind.IMAGE,
                viewOnce = false,
                classCode = v.classCode,
                readable = false,
            )
            assertTrue("readerOpen itself does not attest readability: $opened", opened is MediaCrypto.Opened.Ok)
            val reader = (opened as MediaCrypto.Opened.Ok).reader

            // Read mode is where the unreadable object is refused (§22.2 row 28a).
            val packed = ByteArrayOutputStream()
            sealed.sortedBy { it.index }[0].fragments.forEach { packed.write(it) }
            val read = MediaCrypto.chunk(
                handle, reader.id, 0, packed.toByteArray(), MediaCrypto.Mode.READ,
            )
            assertEquals(MediaCrypto.Chunked.Sequence, read)

            // The validation pass is not a read: it still walks the same chunk.
            val validate = MediaCrypto.chunk(
                handle, reader.id, 0, packed.toByteArray(), MediaCrypto.Mode.VALIDATE,
            )
            assertTrue("validate: $validate", validate is MediaCrypto.Chunked.Ok)

            // An index outside the object is INDEX_RANGE in either mode.
            val outside = MediaCrypto.chunk(
                handle, reader.id, v.chunks, packed.toByteArray(), MediaCrypto.Mode.VALIDATE,
            )
            assertEquals(MediaCrypto.Chunked.IndexRange, outside)
        } finally {
            DmSessions.closeContext(handle)
        }
    }
}
