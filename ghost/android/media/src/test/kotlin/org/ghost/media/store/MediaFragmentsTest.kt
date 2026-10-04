package org.ghost.media.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `MediaFragments` (Phase 11 design §6.4, §7.2, §13.6): the fragment rows of a sealed and of a received object, the binding of
 * an arriving blob to every object that waits for it, the feeder's `unsent` → `open` → final path with its limits and its
 * resends, and the releases of §7.2.
 */
class MediaFragmentsTest {

    private val now = 1_800_000_000L

    // ------------------------------------------------------------------ sealed objects

    @Test
    fun aSealedObjectHasItsManifestAndItsFragmentsBoundAndUnsentManifestFirst() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        val fragments = w.stores.fragments.fragments(w.db, objectId, now)
        assertEquals((-1..15).toList(), fragments.map { it.ordinal })
        val blobs = w.blobsOf(1)
        assertArrayEquals(blobs.manifest, fragments.first().blobHash)
        assertArrayEquals(blobs.fragments[5], fragments.first { it.ordinal == 5 }.blobHash)
        // the feeder takes the manifest first, then the lowest ordinals
        val unsent = w.stores.fragments.unsent(w.db, objectId, now, 3)
        assertEquals(listOf(-1, 0, 1), unsent.map { it.ordinal })
        assertEquals(17, w.stores.fragments.unsent(w.db, objectId, now, 100).size)
        assertNotNull(w.stores.fragments.fragment(w.db, objectId, 0, now))
        assertNull(w.stores.fragments.fragment(w.db, objectId, 16, now))
        expectStoreError(MediaStoreError.BAD_VALUE) { w.stores.fragments.fragment(w.db, objectId, 804, now) }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.stores.fragments.fragment(w.db, objectId, -2, now) }
    }

    @Test
    fun theNumberOfFragmentsIsTheClassAndTheSchemaWantsTheBlobRowsFirst() = MediaWorld().use { w ->
        w.dmMessage(id16(0x91))
        w.ensureNamespace(hash32(0x4D))
        val blobs = w.blobsOf(1)
        w.tx { tx ->
            w.stores.objects.insertOutgoing(
                tx,
                NewOutgoing(MediaDescriptor(id16(0xA1), MediaKind.VIDEO, false, 0, blobs.manifest), id16(0xD1), bytes(60, 1), id16(0x91), hash32(0x4D), 3600L, 3600L),
            )
        }
        // fifteen fragments for a class of sixteen
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.insertSealed(it, id16(0xA1), 0, blobs.manifest, blobs.fragments.take(15)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.insertSealed(it, id16(0xA1), 0, blobs.manifest, blobs.fragments + hash32(9)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.insertSealed(it, id16(0xA1), 11, blobs.manifest, blobs.fragments) } }
        // the right number, but no blob rows: the schema refuses a bound row naming a blob that is not there
        val e = assertThrows(java.sql.SQLException::class.java) { w.tx { w.stores.fragments.insertSealed(it, id16(0xA1), 0, blobs.manifest, blobs.fragments) } }
        assertTrue(e.message, e.message.orEmpty().contains("a fragment is bound exactly when its blob row exists"))
        assertEquals(0L, w.count("media_fragment"))
    }

    // ------------------------------------------------------------------ received objects

    @Test
    fun aReceivedObjectsFragmentsAreBoundWhereTheBlobIsThereAndExpectedWhereItIsNot() = MediaWorld().use { w ->
        val blobs = w.blobsOf(1)
        w.ingest(blobs.all.take(5)) // the manifest and four fragments are in the pool before the descriptor binds
        val objectId = w.receive(1, blobs = blobs)
        val fragments = w.stores.fragments.fragments(w.db, objectId, now)
        assertEquals(17, fragments.size)
        assertEquals(5, fragments.count { it.state == FragmentState.BOUND })
        assertEquals(12, fragments.count { it.state == FragmentState.EXPECTED })
        assertTrue(fragments.all { it.uploadState == null })
        assertEquals(12, w.stores.fragments.expectedCount(w.db, objectId))
        assertEquals(5, w.stores.fragments.boundCount(w.db, objectId))
        // the rest arrive one by one; the last one bound makes the object complete
        for ((i, hash) in blobs.all.drop(5).withIndex()) {
            val bound = w.ingest(listOf(hash))
            assertEquals(listOf(objectId.toList()), bound.toList())
            assertEquals(12 - (i + 1), w.stores.fragments.expectedCount(w.db, objectId))
        }
        assertEquals(17, w.stores.fragments.boundCount(w.db, objectId))
    }

    /** D25: ownership is decided by authentication, never by arrival order: two objects may name one hash, and one arrival binds both. */
    @Test
    fun oneArrivingBlobBindsTheExpectedRowsOfEveryObjectThatNamesIt() = MediaWorld().use { w ->
        val shared = w.blobsOf(1)
        val first = w.receive(1, blobs = shared)
        val second = w.receive(2, blobs = MediaWorld.Blobs(shared.manifest, shared.fragments.take(8) + w.blobsOf(2).fragments.drop(8)))
        assertEquals(setOf(first.toList(), second.toList()), w.stores.fragments.objectsExpecting(w.db, shared.manifest).map { it.toList() }.toSet())
        val bound = w.ingest(listOf(shared.manifest))
        assertEquals(setOf(first.toList(), second.toList()), bound)
        assertEquals(1, w.stores.fragments.boundCount(w.db, first))
        assertEquals(1, w.stores.fragments.boundCount(w.db, second))
        assertEquals(emptyList<List<Byte>>(), w.stores.fragments.objectsExpecting(w.db, shared.manifest).map { it.toList() })
        // a hash that only the second names binds only the second
        val boundSecond = w.ingest(listOf(w.blobsOf(2).fragments[10]))
        assertEquals(setOf(second.toList()), boundSecond)
        assertEquals(setOf(first.toList(), second.toList()), w.stores.fragments.objectsNaming(w.db, shared.manifest).map { it.toList() }.toSet())
    }

    @Test
    fun anArrivalThatNoObjectWaitsForIsPooled() = MediaWorld().use { w ->
        assertEquals(emptySet<List<Byte>>(), w.ingest(listOf(hashOfBlob(5))))
        assertEquals(1, w.stores.blobs.pooledCount(w.db))
        assertEquals(0, w.tx { w.stores.fragments.bindExpected(it, hashOfBlob(5)) })
    }

    // ------------------------------------------------------------------ the feeder

    private fun op(n: Int, objectId: ByteArray, ordinal: Int, gen: Int = 0, resend: Int = 0) = MediaOp(id16(n), objectId, ordinal, gen, resend)

    @Test
    fun anOrdinalIsFedOnceOpenedSettledAndNeverFedAgainInItsGeneration() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        w.tx { w.stores.fragments.enqueue(it, op(0x11, objectId, -1)) }
        assertEquals(UploadState.OPEN, w.stores.fragments.fragment(w.db, objectId, -1, now)!!.uploadState)
        assertEquals(UploadState.OPEN, w.stores.fragments.uploadStateOf(w.db, objectId, -1))
        assertEquals(1, w.stores.fragments.openCount(w.db, objectId))
        assertNotNull(w.stores.fragments.op(w.db, id16(0x11), now))
        assertEquals(-1, w.stores.fragments.op(w.db, id16(0x11), now)!!.ordinal)
        assertNull(w.stores.fragments.op(w.db, id16(0x99), now))
        // fed again: the ordinal is open, not unsent
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.enqueue(it, op(0x12, objectId, -1)) } }
        w.tx { w.stores.fragments.settle(it, objectId, -1, UploadState.DEGRADED) }
        assertEquals(0, w.stores.fragments.openCount(w.db, objectId))
        // an acknowledged ordinal is not an outcome again, and unsent/open are not outcomes
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.settle(it, objectId, -1, UploadState.SENT) } }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.settle(it, objectId, 0, UploadState.OPEN) } }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.settle(it, objectId, 0, UploadState.SENT) } } // unsent, not open
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.enqueue(it, op(0x13, objectId, -1)) } }
        assertEquals(16, w.stores.fragments.unsent(w.db, objectId, now, 100).size)
        // a refused enqueue left no operation behind
        assertEquals(1L, w.count("media_outbound_op"))
    }

    @Test
    fun atMostThirtyTwoOrdinalsOfAnObjectAndSixtyFourOfTheDeviceAreOpen() = MediaWorld().use { w ->
        // class 2 has 36 fragments + the manifest = 37 ordinals: more than 32
        val big = w.commitOutgoing(1, classCode = 2)
        var n = 1
        for (ordinal in -1 until 31) w.tx { w.stores.fragments.enqueue(it, op(n++, big, ordinal)) }
        assertEquals(32, w.stores.fragments.openCount(w.db, big))
        expectStoreError(MediaStoreError.LIMIT) { w.tx { w.stores.fragments.enqueue(it, op(n++, big, 31)) } }
        // a settled ordinal frees a place
        w.tx { w.stores.fragments.settle(it, big, -1, UploadState.SENT) }
        w.tx { w.stores.fragments.enqueue(it, op(n++, big, 31)) }
        // the device: two more objects fill 64
        val b = w.commitOutgoing(2, classCode = 2)
        for (ordinal in -1 until 30) w.tx { w.stores.fragments.enqueue(it, op(n++, b, ordinal)) }
        assertEquals(32 + 31 - 0, w.stores.fragments.openCountOfDevice(w.db))
        w.tx { w.stores.fragments.enqueue(it, op(n++, b, 30)) }
        assertEquals(64, w.stores.fragments.openCountOfDevice(w.db))
        val c = w.commitOutgoing(3)
        expectStoreError(MediaStoreError.LIMIT) { w.tx { w.stores.fragments.enqueue(it, op(n++, c, -1)) } }
        assertEquals("the refused enqueue left nothing", UploadState.UNSENT, w.stores.fragments.uploadStateOf(w.db, c, -1))
    }

    @Test
    fun anIndeterminateOutcomeIsResentAsANewOperationOfTheSameOrdinalAtMostTwiceAndTheOrdinalStaysOpen() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        w.tx { w.stores.fragments.enqueue(it, op(0x11, objectId, 0)) }
        w.tx { w.stores.fragments.insertResend(it, op(0x12, objectId, 0, resend = 1)) }
        w.tx { w.stores.fragments.insertResend(it, op(0x13, objectId, 0, resend = 2)) }
        assertEquals(UploadState.OPEN, w.stores.fragments.uploadStateOf(w.db, objectId, 0))
        assertEquals(1, w.stores.fragments.openCount(w.db, objectId))
        // a third resend is outside the schema's range; a resend of 0 is the first operation, not a resend
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.insertResend(it, op(0x14, objectId, 0, resend = 3)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.insertResend(it, op(0x15, objectId, 0, resend = 0)) } }
        // the same (object, ordinal, generation, resend) under another id is refused by the schema's unique tuple and guard
        assertThrows(java.sql.SQLException::class.java) { w.tx { w.stores.fragments.insertResend(it, op(0x16, objectId, 0, resend = 2)) } }
        // a resend of an ordinal that is not open is not a resend
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.insertResend(it, op(0x17, objectId, 1, resend = 1)) } }
        assertEquals(3L, w.count("media_outbound_op"))
        w.tx { w.stores.fragments.settle(it, objectId, 0, UploadState.INDETERMINATE) }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.fragments.insertResend(it, op(0x18, objectId, 0, resend = 1)) } }
        for (bad in listOf(op(0x19, objectId, 804), op(0x1A, objectId, -2), op(0x1B, objectId, 0, gen = 4), op(0x1C, objectId, 0, resend = -1))) {
            expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.enqueue(it, bad) } }
        }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.enqueue(it, MediaOp(id16(1).copyOf(15), objectId, 0, 0, 0)) } }
    }

    @Test
    fun theObjectIsReadyWhenEveryOrdinalIsFinalInTheAcknowledgedStates() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        assertFalse(w.stores.fragments.allAcknowledged(w.db, objectId))
        var n = 1
        for (ordinal in -1..15) {
            w.tx { w.stores.fragments.enqueue(it, op(n++, objectId, ordinal)) }
            assertFalse("ordinal $ordinal is open", w.stores.fragments.allAcknowledged(w.db, objectId))
        }
        val finals = listOf(UploadState.SENT, UploadState.DEGRADED, UploadState.INDETERMINATE)
        for (ordinal in -1..14) w.tx { w.stores.fragments.settle(it, objectId, ordinal, finals[(ordinal + 1) % 3]) }
        assertFalse(w.stores.fragments.allAcknowledged(w.db, objectId))
        w.tx { w.stores.fragments.settle(it, objectId, 15, UploadState.FAILED) }
        assertFalse("a failed ordinal blocks the descriptor (§6.4)", w.stores.fragments.allAcknowledged(w.db, objectId))
        assertFalse("an object that does not exist is not ready", w.stores.fragments.allAcknowledged(w.db, id16(0x01)))
    }

    @Test
    fun theOperationOfAnExpiredObjectIsReleasedAndIgnoredLikeARowThatIsGone() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1, messageDeleteAtMinute = 600L)
        w.tx { w.stores.fragments.enqueue(it, op(0x11, objectId, 0)) }
        assertNotNull(w.stores.fragments.op(w.db, id16(0x11), 599L))
        assertNull(w.stores.fragments.op(w.db, id16(0x11), 600L))
        // the bounds still count it: the operation is in flight at Phase 7 whether or not the message has expired
        assertEquals(1, w.stores.fragments.openCount(w.db, objectId))
        assertEquals(1, w.stores.fragments.openCountOfDevice(w.db))
    }

    // ------------------------------------------------------------------ releases

    @Test
    fun aReleaseDeletesTheFragmentsOfTheObjectsNamedAndOnlyTheBlobsTheyNamedThatNothingNamesAnyMore() = MediaWorld().use { w ->
        val a = w.commitOutgoing(1)
        val b = w.commitOutgoing(2)
        w.ingest(listOf(hashOfBlob(999_001)), retainUntilDay = 20_090L) // pooled, unrelated
        assertEquals(0, w.tx { w.stores.fragments.release(it, emptyList(), ReleasePolicy.ERASE) })
        // RELEASE deletes the sealed blobs of a (nothing else names them) and leaves the pooled one alone
        assertEquals(17, w.tx { w.stores.fragments.release(it, listOf(a), ReleasePolicy.RELEASE) })
        assertEquals(17L + 1L, w.count("media_blob"))
        assertEquals(17L, w.count("media_fragment"))
        assertEquals(1, w.stores.blobs.pooledCount(w.db))
        // ERASE of b: its blobs go whatever their origin, the unrelated pooled blob stays
        assertEquals(17, w.tx { w.stores.fragments.release(it, listOf(b), ReleasePolicy.ERASE) })
        assertEquals(1L, w.count("media_blob"))
        assertEquals(0L, w.count("media_fragment"))
        assertTrue(w.stores.blobs.exists(w.db, hashOfBlob(999_001)))
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.fragments.release(it, listOf(id16(1).copyOf(3)), ReleasePolicy.ERASE) } }
    }

    @Test
    fun theFragmentTypesShowNothing() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        val op = op(0x11, objectId, 0)
        assertRedacted(op.toString(), op.operationId, op.objectId)
        val fragment = w.stores.fragments.fragments(w.db, objectId, now).first()
        assertRedacted(fragment.toString(), fragment.blobHash, fragment.objectId)
        assertEquals("MediaFragment(ordinal=-1, state=BOUND, upload=UNSENT)", fragment.toString())
        assertRedacted(LostBlob(hash32(1), listOf(objectId)).toString(), hash32(1), objectId)
        assertRedacted(ReconcileReport(1, 2, 3, emptyList()).toString())
    }
}
