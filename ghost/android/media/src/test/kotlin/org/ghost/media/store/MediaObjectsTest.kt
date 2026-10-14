package org.ghost.media.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `MediaObjects` (Phase 11 design §6.3, §7.2, §7.6, §11): the creation of an outgoing and of an incoming object, the machines
 * of §7.6 as guarded writes with typed errors, the releases and erasures of §7.2 and §11, the deletion cascade of `SWEEP`,
 * the retry of §6.4 — and the expiry filter of §10.7 point 4 on every read (the lint of mutant ME-16, in `:storage`, proves
 * it on the whole registry; these are the cases a reader of the DAO wants to see).
 */
class MediaObjectsTest {

    private val now = 1_800_000_000L // an hour and a minute boundary, in seconds
    private val hourFromNow = now + 3_600L

    // ------------------------------------------------------------------ MEDIA-COMMIT

    @Test
    fun anOutgoingObjectIsCommittedWithItsUploadItsBlobsAndItsFragments() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1, ttl = 86_400L, deadlineHour = now + 7_200L)
        val o = w.stores.objects.byId(w.db, objectId, now)!!
        assertEquals(MediaRole.OUT, o.role)
        assertEquals(ObjectState.UPLOADING, o.state)
        assertEquals(MediaKind.VIDEO, o.kind)
        assertEquals(0, o.classCode)
        assertEquals(60, o.keyEnv!!.size)
        assertNull(o.incompleteAfterHour)
        assertArrayEquals(id16(0x91), o.messageId)
        val u = w.stores.objects.upload(w.db, objectId, now)!!
        assertEquals(86_400L, u.ttlSeconds)
        assertEquals(now + 7_200L, u.deadlineHour)
        assertEquals(0, u.retryGen)
        val fragments = w.stores.fragments.fragments(w.db, objectId, now)
        assertEquals(17, fragments.size)
        assertEquals(-1, fragments.first().ordinal)
        assertEquals((-1..15).toList(), fragments.map { it.ordinal })
        assertTrue(fragments.all { it.state == FragmentState.BOUND && it.uploadState == UploadState.UNSENT })
        assertEquals(17L, w.count("media_blob"))
        // the same object is found by its message
        assertArrayEquals(objectId, w.stores.objects.byMessage(w.db, id16(0x91), now)!!.objectId)
        assertEquals(listOf(objectId.toList()), w.stores.objects.activeUploads(w.db, now, 10).map { it.toList() })
    }

    @Test
    fun anObjectAMessageOrAHashThatExistsIsRefusedAsARowThatExists() = MediaWorld().use { w ->
        w.commitOutgoing(1)
        w.dmMessage(id16(0x92))
        // the same object id, and the same message, are rows that exist
        expectStoreError(MediaStoreError.ROW_EXISTS) {
            w.tx { tx ->
                w.stores.objects.insertOutgoing(
                    tx,
                    NewOutgoing(MediaDescriptor(id16(0xA1), MediaKind.IMAGE, false, 0, hash32(1)), id16(0xD1), bytes(60, 1), id16(0x92), hash32(0x4D), 3600L, 3600L),
                )
            }
        }
        // another object for a message that has one
        expectStoreError(MediaStoreError.ROW_EXISTS) {
            w.tx { tx ->
                w.stores.objects.insertOutgoing(
                    tx,
                    NewOutgoing(MediaDescriptor(id16(0xA2), MediaKind.IMAGE, false, 0, hash32(1)), id16(0xD1), bytes(60, 1), id16(0x91), hash32(0x4D), 3600L, 3600L),
                )
            }
        }
        assertEquals("the refused transactions rolled back", 1L, w.count("media_object"))
        // a blob hash that has a row
        expectStoreError(MediaStoreError.ROW_EXISTS) {
            w.tx { tx -> w.stores.blobs.insert(tx, MediaBlob(w.blobsOf(1).manifest, id16(9), BlobOrigin.SEALED, null)) }
        }
    }

    @Test
    fun valuesTheSchemaWouldRefuseAreRefusedBeforeTheStatementRuns() {
        val d = MediaDescriptor(id16(1), MediaKind.VIDEO, false, 3, hash32(1))
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaDescriptor(id16(1).copyOf(15), MediaKind.VIDEO, false, 0, hash32(1)) }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaDescriptor(id16(1), MediaKind.VIDEO, false, 11, hash32(1)) }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaDescriptor(id16(1), MediaKind.VIDEO, false, -1, hash32(1)) }
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaDescriptor(id16(1), MediaKind.IMAGE, false, 1, hash32(1)) } // an image is class 0
        expectStoreError(MediaStoreError.BAD_VALUE) { MediaDescriptor(id16(1), MediaKind.VIDEO, false, 0, hash32(1).copyOf(31)) }
        expectStoreError(MediaStoreError.BAD_VALUE) { NewOutgoing(d, id16(1), bytes(59, 1), id16(2), hash32(3), 3600L, 3600L) }
        expectStoreError(MediaStoreError.BAD_VALUE) { NewOutgoing(d, id16(1), bytes(60, 1), id16(2), hash32(3), 7200L, 3600L) }
        expectStoreError(MediaStoreError.BAD_VALUE) { NewOutgoing(d, id16(1), bytes(60, 1), id16(2), hash32(3), 3600L, 3601L) }
        expectStoreError(MediaStoreError.BAD_VALUE) { NewOutgoing(d, id16(1), bytes(60, 1), id16(2), hash32(3).copyOf(31), 3600L, 3600L) }
        MediaWorld().use { w ->
            w.dmMessage(id16(2))
            expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.objects.onDescriptor(it, id16(2), id16(0xD1), d, bytes(60, 1), 3_601L) } }
            expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.objects.onDescriptor(it, id16(2), id16(0xD1), d, bytes(61, 1), 3_600L) } }
            expectStoreError(MediaStoreError.BAD_VALUE) { w.stores.objects.byId(w.db, id16(1).copyOf(3), now) }
            assertEquals(0L, w.count("media_object"))
        }
    }

    // ------------------------------------------------------------------ RECV and the incoming machine

    @Test
    fun aDescriptorCreatesAnAwaitingObjectWithTheKeyOfDecryptAndASecondOneIsDropped() = MediaWorld().use { w ->
        val objectId = w.receive(1, bind = false, incompleteAfterHour = hourFromNow)
        val o = w.stores.objects.byId(w.db, objectId, now)!!
        assertEquals(MediaRole.IN, o.role)
        assertEquals(ObjectState.AWAITING, o.state)
        assertArrayEquals(bytes(60, 0x41), o.keyEnv)
        assertEquals(hourFromNow, o.incompleteAfterHour)
        assertArrayEquals(id16(0xD1), o.destId)
        // a second descriptor naming the same object is drop(duplicate_object): nothing written, whatever message carries it
        w.dmMessage(id16(0x99))
        val again = w.tx { tx ->
            w.stores.objects.onDescriptor(tx, id16(0x99), id16(0xD1), MediaDescriptor(objectId, MediaKind.VIDEO, false, 0, w.blobsOf(1).manifest), bytes(60, 0x55), hourFromNow)
        }
        assertEquals(DescriptorResult.DUPLICATE_OBJECT, again)
        assertEquals(1L, w.count("media_object"))
        assertArrayEquals("the first key is the one kept", bytes(60, 0x41), w.stores.objects.byId(w.db, objectId, now)!!.keyEnv)
        // the pending-download worklist sees it, until its deadline
        assertEquals(listOf(objectId.toList()), w.stores.objects.pendingDownloads(w.db, now, 10).map { it.toList() })
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.pendingDownloads(w.db, hourFromNow, 10).map { it.toList() })
    }

    @Test
    fun theIncomingMachineIsGuardedWritesWithTypedErrors() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        assertEquals(ObjectState.FETCHING, w.stores.objects.byId(w.db, objectId, now)!!.state)
        // a transition the machine does not have: complete -> fetching, verified before complete, a missing row
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markVerified(it, objectId) } }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markFetching(it, objectId) } }
        expectStoreError(MediaStoreError.MISSING_ROW) { w.tx { w.stores.objects.markFetching(it, id16(0x01)) } }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markUploaded(it, objectId) } } // an outgoing edge on an incoming row
        w.ingest(w.blobsOf(1).all) // every blob arrived: the last expected row was bound
        w.tx { w.stores.objects.markComplete(it, objectId) }
        assertEquals(listOf(objectId.toList()), w.stores.objects.toVerify(w.db, now, 10).map { it.toList() })
        w.tx { w.stores.objects.markVerified(it, objectId) }
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.toVerify(w.db, now, 10).map { it.toList() })
        // the decode-failure guard: two failures, a third is a limit, and the object becomes undecodable
        assertEquals(1, w.tx { w.stores.objects.recordDecodeFailure(it, objectId) })
        assertEquals(2, w.tx { w.stores.objects.recordDecodeFailure(it, objectId) })
        expectStoreError(MediaStoreError.LIMIT) { w.tx { w.stores.objects.recordDecodeFailure(it, objectId) } }
        w.tx { w.stores.objects.markUndecodable(it, objectId) }
        assertEquals(ObjectState.UNDECODABLE, w.stores.objects.byId(w.db, objectId, now)!!.state)
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.recordDecodeFailure(it, objectId) } }
        // nothing a refused write began is left
        assertEquals(2, w.stores.objects.byId(w.db, objectId, now)!!.decodeFailures)
    }

    /** SCN-MC: complete only with `F + 1` rows of the object's class, every one bound; the store says so, the schema has no trigger for it. */
    @Test
    fun anObjectIsCompleteOnlyWhenEveryRowOfItsClassIsBound() = MediaWorld().use { w ->
        // no fragment rows at all (a MEDIA-BIND that did not run): fetching, and not complete
        val bare = w.receive(1, bind = false)
        w.tx { w.stores.objects.markFetching(it, bare) }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markComplete(it, bare) } }
        assertEquals("fetching", w.rawState(bare))
        // class 1 has 24 fragments: 25 rows. 24 bound is not enough, and 25 is.
        val blobs = w.blobsOf(2, classCode = 1)
        val sized = w.receive(2, classCode = 1, blobs = blobs)
        w.ingest(blobs.all.take(24))
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markComplete(it, sized) } }
        assertEquals("a refused write left the object as it was", "fetching", w.rawState(sized))
        w.ingest(blobs.all.drop(24))
        w.tx { w.stores.objects.markComplete(it, sized) }
        assertEquals(ObjectState.COMPLETE, w.stores.objects.byId(w.db, sized, now)!!.state)
        // it moves once, from fetching; a row that is not there is a missing row
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markComplete(it, sized) } }
        expectStoreError(MediaStoreError.MISSING_ROW) { w.tx { w.stores.objects.markComplete(it, id16(0x01)) } }
        // an object with fewer rows than its class (a defective BIND) is not complete however bound they are
        val short = w.receive(3)
        w.ingest(w.blobsOf(3).all)
        w.db.exec("DELETE FROM media_fragment WHERE object_id = ? AND ordinal = 15", listOf(short))
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markComplete(it, short) } }
    }

    // ------------------------------------------------------------------ releases and erasures

    @Test
    fun anObjectThatTurnsCorruptReleasesItsReferencesAndItsKeyAndItsIngestedBlobsReturnToThePool() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        val blobs = w.blobsOf(1)
        // every blob of the object arrives and it is complete; another object (a squatter, D25) names the manifest too
        w.ingest(blobs.all, retainUntilDay = 20_100L)
        w.tx { w.stores.objects.markComplete(it, objectId) }
        val squatter = w.receive(2, blobs = Blobs2(blobs.manifest, w.blobsOf(2).fragments))
        assertEquals(17L, w.count("media_blob"))
        val released = w.tx { w.stores.objects.markCorrupt(it, objectId) }
        assertEquals("ingested blobs are not deleted by a release: they return to the pool", 0, released)
        val o = w.stores.objects.byId(w.db, objectId, now)!!
        assertEquals(ObjectState.CORRUPT, o.state)
        assertNull("the key goes with the references (T45)", o.keyEnv)
        assertEquals(emptyList<MediaFragment>(), w.stores.fragments.fragments(w.db, objectId, now))
        assertEquals(17L, w.count("media_blob"))
        // pooled blobs: the sixteen nothing names, not the manifest the squatter still names
        assertEquals(16, w.stores.blobs.pooledCount(w.db))
        assertTrue(w.stores.blobs.isNamed(w.db, blobs.manifest))
        assertEquals(ObjectState.FETCHING, w.stores.objects.byId(w.db, squatter, now)!!.state)
        // a corrupt object stays corrupt and cannot be released twice
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markCorrupt(it, objectId) } }
    }

    @Test
    fun aReleaseDeletesTheSealedBlobsOfAnObjectAndKeepsTheOnesAnotherObjectNames() = MediaWorld().use { w ->
        // the sealed rule is the sender's release path (an outgoing object released the same way is not in the machine), so it is
        // exercised through the policy directly; an incoming object that names one of the object's hashes (D25) keeps it
        val objectId = w.commitOutgoing(1)
        val hashes = w.stores.fragments.hashesOf(w.db, objectId)
        assertEquals(17, hashes.size)
        val shared = w.blobsOf(1).fragments[3]
        val squatter = w.receive(2, blobs = MediaWorld.Blobs(hashOfBlob(2000), listOf(shared) + w.blobsOf(2).fragments.drop(1)))
        val deletedRelease = w.tx { w.stores.fragments.release(it, listOf(objectId), ReleasePolicy.RELEASE) }
        assertEquals("sealed blobs are deleted by a release, but not the one another object names", 16, deletedRelease)
        assertTrue(w.stores.blobs.exists(w.db, shared))
        assertTrue(w.stores.blobs.isNamed(w.db, shared))
        assertEquals(1L, w.count("media_blob"))
        assertEquals(17L, w.count("media_fragment")) // the squatter's own rows
        assertEquals(ObjectState.FETCHING, w.stores.objects.byId(w.db, squatter, now)!!.state)
    }

    @Test
    fun anObjectNotCompleteByItsDeadlineIsIncompleteAndAReaderSeesItBeforeTheMaintenanceRuns() = MediaWorld().use { w ->
        val objectId = w.receive(1, incompleteAfterHour = hourFromNow)
        w.ingest(w.blobsOf(1).all.take(3))
        // before the deadline: fetching, with its key and its fragments
        val before = w.stores.objects.byId(w.db, objectId, hourFromNow - 3_600L)!!
        assertEquals(ObjectState.FETCHING, before.state)
        assertNotNull(before.keyEnv)
        assertEquals(17, w.stores.fragments.fragments(w.db, objectId, hourFromNow - 3_600L).size)
        // at the deadline (the boundary): declared loss to a reader, whatever the row says
        val at = w.stores.objects.byId(w.db, objectId, hourFromNow)!!
        assertEquals(ObjectState.INCOMPLETE, at.state)
        assertNull(at.keyEnv)
        assertEquals(emptyList<MediaFragment>(), w.stores.fragments.fragments(w.db, objectId, hourFromNow))
        assertEquals(emptyList<OrdinalFile>(), w.stores.blobs.files(w.db, objectId, hourFromNow))
        assertEquals("fetching", w.rawState(objectId))
        // MEDIA-GC names it, and declares it
        assertEquals(listOf(objectId.toList()), w.stores.objects.incompleteDue(w.db, hourFromNow, 10).map { it.toList() })
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.incompleteDue(w.db, hourFromNow - 3_600L, 10).map { it.toList() })
        val released = w.tx { w.stores.objects.markIncomplete(it, objectId) }
        assertEquals(0, released)
        assertEquals(ObjectState.INCOMPLETE, w.stores.objects.byId(w.db, objectId, hourFromNow)!!.state)
        assertEquals("and a reader sees the same thing the row now says", ObjectState.INCOMPLETE, ObjectState.of(w.rawState(objectId)!!))
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.incompleteDue(w.db, hourFromNow, 10).map { it.toList() })
        assertEquals(3, w.stores.blobs.pooledCount(w.db))
    }

    @Test
    fun aMessageThatHasExpiredHidesItsObjectBeforeTheSweepAndTheSweepDeletesIt() = MediaWorld().use { w ->
        // the message expires at minute 600 (delete_at_minute); a read at that minute no longer shows the object
        val gone = w.commitOutgoing(1, messageId = id16(0x91), messageDeleteAtMinute = 600L)
        assertNotNull(w.stores.objects.byId(w.db, gone, 599L))
        assertNull(w.stores.objects.byId(w.db, gone, 600L))
        assertNull(w.stores.objects.byMessage(w.db, id16(0x91), 600L))
        assertNull(w.stores.objects.upload(w.db, gone, 600L))
        assertEquals(emptyList<MediaFragment>(), w.stores.fragments.fragments(w.db, gone, 600L))
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.activeUploads(w.db, 600L, 10).map { it.toList() })
        // the sweep: the message ids go to MediaPort.onMessagesDeleted, which deletes the objects and the blobs nothing names
        val deleted = w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91))) }
        assertEquals(1, deleted)
        assertEquals(0L, w.count("media_object"))
        assertEquals(0L, w.count("media_upload"))
        assertEquals(0L, w.count("media_fragment"))
        assertEquals("the blobs nothing names are deleted, rows now and files by the reconcile", 0L, w.count("media_blob"))
    }

    @Test
    fun theSweepKeepsABlobAnotherLiveObjectStillNamesAndDeletesNoPooledBlobOfAnotherObject() = MediaWorld().use { w ->
        val shared = w.blobsOf(1)
        w.receive(1, messageId = id16(0x91), blobs = shared)
        w.receive(2, messageId = id16(0x92), blobs = Blobs2(shared.manifest, w.blobsOf(2).fragments))
        w.ingest(listOf(shared.manifest) + w.blobsOf(2).fragments.take(2) + shared.fragments.take(2))
        val pooledBefore = w.stores.blobs.pooledCount(w.db)
        w.ingest(listOf(hashOfBlob(777_000)), retainUntilDay = 20_050L) // an unmatched blob of nobody
        assertEquals(pooledBefore + 1, w.stores.blobs.pooledCount(w.db))
        // object 1's message is swept: its fragments go, the manifest stays (object 2 names it), the unmatched blob is not touched
        val deleted = w.tx { w.stores.objects.deleteObjectsOfMessages(it, listOf(id16(0x91))) }
        assertEquals(1, deleted)
        assertTrue(w.stores.blobs.exists(w.db, shared.manifest))
        assertTrue(w.stores.blobs.isNamed(w.db, shared.manifest))
        assertTrue("the unmatched blob of nobody is not collateral", w.stores.blobs.exists(w.db, hashOfBlob(777_000)))
        assertFalse("object 1's own fragment blobs are gone", w.stores.blobs.exists(w.db, shared.fragments[0]))
        assertEquals(1L, w.count("media_object"))
    }

    // ------------------------------------------------------------------ view-once

    @Test
    fun aViewOnceObjectIsOpenedOnceAndTheKeyIsGoneWhenTheHandleIsReturned() = MediaWorld().use { w ->
        val objectId = w.receive(1, viewOnce = true)
        w.ingest(w.blobsOf(1).all)
        w.tx { w.stores.objects.markComplete(it, objectId) }
        w.tx { w.stores.objects.markVerified(it, objectId) }
        val key = w.stores.objects.byId(w.db, objectId, now)!!.keyEnv!!
        assertEquals(60, key.size)
        // VIEW-ONCE-OPEN: state viewing, key NULL, in the same statement
        w.tx { w.stores.objects.openViewOnce(it, objectId) }
        val viewing = w.stores.objects.byId(w.db, objectId, now)!!
        assertEquals(ObjectState.VIEWING, viewing.state)
        assertNull(viewing.keyEnv)
        assertEquals(listOf(objectId.toList()), w.stores.objects.viewing(w.db, now, 10).map { it.toList() })
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.openViewOnce(it, objectId) } } // at most one display
        assertEquals(17, w.stores.fragments.fragments(w.db, objectId, now).size)
        // VIEW-ONCE-CLOSE: viewed, the fragment rows and every blob nothing names any more erased
        val erased = w.tx { w.stores.objects.closeViewOnce(it, objectId) }
        assertEquals(17, erased)
        assertEquals(ObjectState.VIEWED, w.stores.objects.byId(w.db, objectId, now)!!.state)
        assertEquals(0L, w.count("media_fragment"))
        assertEquals(0L, w.count("media_blob"))
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.viewing(w.db, now, 10).map { it.toList() })
        // a row that is not view-once cannot be opened this way
        val plain = w.receive(2)
        w.ingest(w.blobsOf(2).all)
        w.tx { w.stores.objects.markComplete(it, plain) }
        w.tx { w.stores.objects.markVerified(it, plain) }
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.openViewOnce(it, plain) } }
        expectStoreError(MediaStoreError.MISSING_ROW) { w.tx { w.stores.objects.openViewOnce(it, id16(0x01)) } }
    }

    @Test
    fun theSendersViewOnceCleanupErasesTheKeyTheFragmentsAndTheBlobsAndKeepsTheRow() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1, viewOnce = true)
        w.tx { w.stores.objects.markUploaded(it, objectId) }
        val erased = w.tx { w.stores.objects.eraseSenderCopy(it, objectId) }
        assertEquals(17, erased)
        val o = w.stores.objects.byId(w.db, objectId, now)!!
        assertEquals(ObjectState.UPLOADED, o.state)
        assertNull(o.keyEnv)
        assertEquals(0L, w.count("media_fragment"))
        assertEquals(0L, w.count("media_blob"))
        // a normal object's copy is not erased this way (it stays until the message expires, §11.1)
        val normal = w.commitOutgoing(2)
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.eraseSenderCopy(it, normal) } }
        expectStoreError(MediaStoreError.MISSING_ROW) { w.tx { w.stores.objects.eraseSenderCopy(it, id16(0x01)) } }
        assertEquals(17L, w.count("media_fragment"))
    }

    // ------------------------------------------------------------------ the outgoing machine and the retry

    @Test
    fun anUploadEndsReadyOrFailsAndAFailedOneIsRetriedAtMostThreeTimesBeforeItsDeadline() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1, deadlineHour = now + 7_200L)
        // feed two ordinals, one fails
        w.tx { tx ->
            w.stores.fragments.enqueue(tx, MediaOp(id16(0x11), objectId, -1, 0, 0))
            w.stores.fragments.enqueue(tx, MediaOp(id16(0x12), objectId, 0, 0, 0))
            w.stores.fragments.settle(tx, objectId, -1, UploadState.SENT)
            w.stores.fragments.settle(tx, objectId, 0, UploadState.FAILED)
            w.stores.objects.markFailed(tx, objectId)
        }
        assertEquals(ObjectState.FAILED, w.stores.objects.byId(w.db, objectId, now)!!.state)
        expectStoreError(MediaStoreError.ILLEGAL_TRANSITION) { w.tx { w.stores.objects.markUploaded(it, objectId) } }
        for (generation in 1..3) {
            assertEquals(RetryResult.RETRIED, w.tx { w.stores.objects.retryUpload(it, objectId, now) })
            assertEquals(generation, w.stores.objects.upload(w.db, objectId, now)!!.retryGen)
            assertEquals(ObjectState.UPLOADING, w.stores.objects.byId(w.db, objectId, now)!!.state)
            val fragments = w.stores.fragments.fragments(w.db, objectId, now)
            assertEquals("the acknowledged ordinal is not stored again", UploadState.SENT, fragments.first { it.ordinal == -1 }.uploadState)
            assertEquals("the failed ordinal goes back", UploadState.UNSENT, fragments.first { it.ordinal == 0 }.uploadState)
            w.tx { tx ->
                w.stores.fragments.enqueue(tx, MediaOp(id16(0x20 + generation), objectId, 0, generation, 0))
                w.stores.fragments.settle(tx, objectId, 0, UploadState.FAILED)
                w.stores.objects.markFailed(tx, objectId)
            }
        }
        assertEquals(RetryResult.RETRIES_EXHAUSTED, w.tx { w.stores.objects.retryUpload(it, objectId, now) })
        // the deadline: after it the user must pick the file again, and an object still uploading reads as failed
        val late = w.commitOutgoing(2, deadlineHour = now + 3_600L)
        w.tx { w.stores.objects.markFailed(it, late) }
        assertEquals(RetryResult.DEADLINE_PASSED, w.tx { w.stores.objects.retryUpload(it, late, now + 3_600L) })
        val third = w.commitOutgoing(3)
        assertEquals(RetryResult.NOT_FAILED, w.tx { w.stores.objects.retryUpload(it, third, now) })
        assertEquals(RetryResult.NO_SUCH_OBJECT, w.tx { w.stores.objects.retryUpload(it, id16(0x01), now) })
    }

    @Test
    fun anObjectStillUploadingPastItsDeadlineReadsAsFailedAndIsNamedByTheDeadlineSweep() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1, deadlineHour = now + 3_600L)
        assertEquals(ObjectState.UPLOADING, w.stores.objects.byId(w.db, objectId, now)!!.state)
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.pastDeadline(w.db, now, 10).map { it.toList() })
        // at the deadline's own hour: failed to a reader, named by the sweep, no longer offered to the feeder
        assertEquals(ObjectState.FAILED, w.stores.objects.byId(w.db, objectId, now + 3_600L)!!.state)
        assertEquals(listOf(objectId.toList()), w.stores.objects.pastDeadline(w.db, now + 3_600L, 10).map { it.toList() })
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.activeUploads(w.db, now + 3_600L, 10).map { it.toList() })
        w.tx { w.stores.objects.markFailed(it, objectId) }
        assertEquals(ObjectState.FAILED, w.stores.objects.byId(w.db, objectId, now + 3_600L)!!.state)
        assertEquals(emptyList<List<Byte>>(), w.stores.objects.pastDeadline(w.db, now + 3_600L, 10).map { it.toList() })
    }

    @Test
    fun theUploadRowIsDeletedWhenTheSendersUploadsAreOver() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        assertTrue(w.tx { w.stores.objects.deleteUpload(it, objectId) })
        assertFalse("a second delete finds nothing", w.tx { w.stores.objects.deleteUpload(it, objectId) })
        assertNull(w.stores.objects.upload(w.db, objectId, now))
        assertNotNull("the object stays", w.stores.objects.byId(w.db, objectId, now))
    }

    // ------------------------------------------------------------------ the types show nothing

    @Test
    fun noRowShowsAByteOfItsFields() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        val o = w.stores.objects.byId(w.db, objectId, now)!!
        assertRedacted(o.toString(), o.objectId, o.destId, o.manifestHash, o.keyEnv!!, o.messageId!!)
        val u = w.stores.objects.upload(w.db, objectId, now)!!
        assertRedacted(u.toString(), u.objectId, u.namespaceId)
        val f = w.stores.fragments.fragments(w.db, objectId, now).first()
        assertRedacted(f.toString(), f.objectId, f.blobHash)
        val b = w.stores.blobs.byHash(w.db, f.blobHash)!!
        assertRedacted(b.toString(), b.blobHash, b.fileName)
        val op = MediaOp(id16(0x11), objectId, 0, 0, 0)
        assertRedacted(op.toString(), op.operationId, op.objectId)
        val d = MediaDescriptor(objectId, MediaKind.VIDEO, false, 0, hash32(7))
        assertRedacted(d.toString(), d.objectId, d.manifestHash)
        assertRedacted(NewOutgoing(d, id16(0xD1), bytes(60, 9), id16(2), hash32(3), 3600L, 3600L).toString(), bytes(60, 9), hash32(3))
        assertRedacted(MediaStoreException(MediaStoreError.BAD_VALUE, "media_object.object_id").toString(), objectId)
        assertEquals("MediaStores", w.stores.toString())
        assertEquals("BlobFile", w.stores.blobs.fileNames(w.db).first().toString())
        assertEquals("OrdinalFile(ordinal=-1)", OrdinalFile(-1, id16(1)).toString())
    }
}

/** Blobs with the manifest of one object and the fragments of another: two objects that name one manifest blob (D25). */
@Suppress("FunctionName")
internal fun Blobs2(manifest: ByteArray, fragments: List<ByteArray>) = MediaWorld.Blobs(manifest, fragments)
