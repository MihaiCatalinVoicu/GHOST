package org.ghost.media.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `MediaBlobs` (Phase 11 design §7.2, §7.5, §13.6): the content-addressed store with references — one row per distinct hash,
 * any number of fragment rows naming it —, the pool of unmatched blobs with its retention, its garbage collection and its
 * cap enforced by local eviction, and the rule for what a blob's retention day is.
 */
class MediaBlobsTest {

    private val now = 1_800_000_000L
    private val today = MediaLimits.day(now) // 20 833

    @Test
    fun aBlobRowIsInsertedOnceAndAnythingTheSchemaWouldRefuseIsRefusedFirst() = MediaWorld().use { w ->
        val hash = hashOfBlob(1)
        w.tx { w.stores.blobs.insert(it, MediaBlob(hash, id16(1), BlobOrigin.SEALED, null)) }
        val row = w.stores.blobs.byHash(w.db, hash)!!
        assertArrayEquals(id16(1), row.fileName)
        assertEquals(BlobOrigin.SEALED, row.origin)
        assertNull(row.retainUntilDay)
        assertTrue(w.stores.blobs.exists(w.db, hash))
        assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(2)))
        assertNull(w.stores.blobs.byHash(w.db, hashOfBlob(2)))
        // the same hash again, or a file name another row holds
        expectStoreError(MediaStoreError.ROW_EXISTS) { w.tx { w.stores.blobs.insert(it, MediaBlob(hash, id16(2), BlobOrigin.SEALED, null)) } }
        // a sealed blob has no retention; an ingested one has; sizes are exact
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(3), id16(3), BlobOrigin.SEALED, 20_000L)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(3), id16(3), BlobOrigin.INGESTED, null)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(3), id16(3), BlobOrigin.INGESTED, -1L)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.blobs.insert(it, MediaBlob(hash32(3).copyOf(31), id16(3), BlobOrigin.SEALED, null)) } }
        expectStoreError(MediaStoreError.BAD_VALUE) { w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(3), id16(3).copyOf(15), BlobOrigin.SEALED, null)) } }
        assertEquals(1L, w.count("media_blob"))
        assertEquals(listOf(hash.toList()), w.stores.blobs.fileNames(w.db).map { it.blobHash.toList() })
    }

    @Test
    fun theRetentionDayIsTheEarlierOfTheRelayExpiryDayPlusOneAndTodayPlusEight() {
        val noon = 1_800_000_000L + 43_200L
        // E well in the future: the eight-day cap
        assertEquals(today + 8, MediaBlobs.retentionDay(noon + 30 * 86_400L, noon))
        // E tomorrow: the day after E's day
        assertEquals(today + 2, MediaBlobs.retentionDay(noon + 86_400L, noon))
        // E today: the next day (the blob is kept through the day after its relay expiry)
        assertEquals(today + 1, MediaBlobs.retentionDay(noon + 3_600L, noon))
        // E in the past: still the day after E's day, never earlier than day 0
        assertEquals(today, MediaBlobs.retentionDay(now - 86_400L, now))
        assertEquals(0L, MediaBlobs.retentionDay(-86_400L * 3, 0L))
        // the cap is eight days from today, whatever E
        assertEquals(today + 8, MediaBlobs.retentionDay(noon + 8 * 86_400L, noon))
        assertEquals(today + 8, MediaBlobs.retentionDay(noon + 100 * 86_400L, noon))
    }

    @Test
    fun anIngestInsertsTheIngestedRowAndReturnsTheObjectsItBound() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        val blobs = w.blobsOf(1)
        val bound = w.tx { w.stores.blobs.ingest(it, blobs.manifest, w.nameOf(blobs.manifest), 20_200L) }
        assertEquals(listOf(objectId.toList()), bound.map { it.toList() })
        val row = w.stores.blobs.byHash(w.db, blobs.manifest)!!
        assertEquals(BlobOrigin.INGESTED, row.origin)
        assertEquals(20_200L, row.retainUntilDay)
        assertEquals(1, w.stores.fragments.boundCount(w.db, objectId))
        // the same hash again is a row that exists (ingest checks byHash first and consumes a duplicate without a file)
        expectStoreError(MediaStoreError.ROW_EXISTS) { w.tx { w.stores.blobs.ingest(it, blobs.manifest, id16(0x66), 20_200L) } }
        assertEquals("a blob nobody waits for", emptyList<List<Byte>>(), w.tx { w.stores.blobs.ingest(it, hashOfBlob(55), id16(0x55), 20_200L) }.map { it.toList() })
    }

    // ------------------------------------------------------------------ the pool

    @Test
    fun aBlobIsPooledWhenNoFragmentNamesItAndTheBytesAreOneFragmentEach() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        val blobs = w.blobsOf(1)
        w.ingest(blobs.all.take(3) + listOf(hashOfBlob(500), hashOfBlob(501)))
        assertEquals("the object's three are named; the two strangers are pooled", 2, w.stores.blobs.pooledCount(w.db))
        assertEquals(2L * MediaLimits.FRAGMENT_BYTES, w.stores.blobs.pooledBytes(w.db))
        assertTrue(w.stores.blobs.isNamed(w.db, blobs.manifest))
        assertFalse(w.stores.blobs.isNamed(w.db, hashOfBlob(500)))
        // a sealed blob is never pooled, named or not
        w.tx { w.stores.blobs.insert(it, MediaBlob(hashOfBlob(600), id16(0x60), BlobOrigin.SEALED, null)) }
        assertEquals(2, w.stores.blobs.pooledCount(w.db))
        assertNotNull(objectId)
    }

    @Test
    fun theEvictionOrderIsTheEarliestRetentionFirstAndTiesByHash() = MediaWorld().use { w ->
        for ((n, day) in listOf(5 to 20_010L, 6 to 20_005L, 7 to 20_005L, 8 to 20_020L, 9 to 20_005L)) {
            w.tx { w.stores.blobs.ingest(it, hashOfBlob(n), w.nameOf(hashOfBlob(n)), day) }
        }
        val order = w.stores.blobs.evictionOrder(w.db, 10)
        assertEquals(listOf(6, 7, 9, 5, 8).map { hashOfBlob(it).toList() }, order.map { it.blobHash.toList() })
        assertEquals(2, w.stores.blobs.evictionOrder(w.db, 2).size)
    }

    @Test
    fun theCapIsEnforcedByDeletingTheEarliestAndNeverByStoppingAndNeverTouchesANamedBlob() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        val named = w.blobsOf(1).all.take(2)
        w.ingest(named, retainUntilDay = 19_000L) // the earliest retention of all, but named: never evicted
        for (n in 10..19) w.tx { w.stores.blobs.ingest(it, hashOfBlob(n), w.nameOf(hashOfBlob(n)), 20_000L + n) }
        assertEquals(10, w.stores.blobs.pooledCount(w.db))
        // under the cap nothing happens
        assertEquals(0, w.tx { w.stores.blobs.evictOverCap(it, capBytes = 10L * MediaLimits.FRAGMENT_BYTES) })
        // three over the cap: the three earliest pooled go (10, 11, 12), the named ones stay although their retention is earlier
        assertEquals(3, w.tx { w.stores.blobs.evictOverCap(it, capBytes = 7L * MediaLimits.FRAGMENT_BYTES) })
        assertEquals(7, w.stores.blobs.pooledCount(w.db))
        for (n in 10..12) assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(n)))
        for (n in 13..19) assertTrue(w.stores.blobs.exists(w.db, hashOfBlob(n)))
        for (hash in named) assertTrue(w.stores.blobs.exists(w.db, hash))
        // a cap of zero empties the pool and stops: the named blobs are not pooled
        assertEquals(7, w.tx { w.stores.blobs.evictOverCap(it, capBytes = 0L) })
        assertEquals(0, w.stores.blobs.pooledCount(w.db))
        assertEquals(2L, w.count("media_blob"))
        // the default cap is 512 MiB: eight thousand blobs, far more than a test world holds
        assertEquals(0, w.tx { w.stores.blobs.evictOverCap(it) })
        assertEquals(512L * 1024 * 1024, MediaLimits.POOL_CAP_BYTES)
        assertEquals(8192L, MediaLimits.POOL_CAP_BYTES / MediaLimits.FRAGMENT_BYTES)
        assertNotNull(objectId)
    }

    @Test
    fun aPooledBlobIsCollectedTheDayAfterItsLastDayAndNotBefore() = MediaWorld().use { w ->
        w.tx { w.stores.blobs.ingest(it, hashOfBlob(1), w.nameOf(hashOfBlob(1)), today - 1) }
        w.tx { w.stores.blobs.ingest(it, hashOfBlob(2), w.nameOf(hashOfBlob(2)), today) }
        w.tx { w.stores.blobs.ingest(it, hashOfBlob(3), w.nameOf(hashOfBlob(3)), today + 1) }
        // its last day is a live day: the blob with retain_until_day = today is kept at today's noon
        assertEquals(listOf(hashOfBlob(1).toList()), w.stores.blobs.expiredPooled(w.db, now, 10).map { it.blobHash.toList() })
        assertEquals(1, w.tx { w.stores.blobs.collectExpired(it, now, 10) })
        assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(1)))
        assertTrue(w.stores.blobs.exists(w.db, hashOfBlob(2)))
        // the next day it goes too
        val tomorrow = now + 86_400L
        assertEquals(1, w.tx { w.stores.blobs.collectExpired(it, tomorrow, 10) })
        assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(2)))
        assertEquals(0, w.tx { w.stores.blobs.collectExpired(it, tomorrow, 10) })
        assertEquals(1L, w.count("media_blob"))
    }

    @Test
    fun aBlobPastItsDayThatAnObjectNamesIsNotCollectedAndGoesBackToThePoolWhenItIsReleased() = MediaWorld().use { w ->
        val objectId = w.receive(1)
        val blobs = w.blobsOf(1)
        w.ingest(blobs.all, retainUntilDay = today - 3) // all past their day, and named
        assertEquals(0, w.stores.blobs.expiredPooled(w.db, now, 100).size)
        assertEquals(0, w.tx { w.stores.blobs.collectExpired(it, now, 100) })
        assertEquals(17L, w.count("media_blob"))
        // the object turns corrupt: the blobs return to the pool with their original (past) retention, and are collected
        w.tx { w.stores.objects.markComplete(it, objectId) }
        w.tx { w.stores.objects.markCorrupt(it, objectId) }
        assertEquals(17, w.stores.blobs.expiredPooled(w.db, now, 100).size)
        assertEquals(17, w.tx { w.stores.blobs.collectExpired(it, now, 100) })
        assertEquals(0L, w.count("media_blob"))
    }

    @Test
    fun deletingUnnamedRowsDeletesOnlyTheUnnamedOnes() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        val named = w.blobsOf(1).manifest
        w.ingest(listOf(hashOfBlob(700)))
        assertEquals(1, w.tx { w.stores.blobs.deleteUnnamed(it, listOf(named, hashOfBlob(700), hashOfBlob(701))) })
        assertTrue(w.stores.blobs.exists(w.db, named))
        assertFalse(w.stores.blobs.exists(w.db, hashOfBlob(700)))
        assertEquals(0, w.tx { w.stores.blobs.dropLostUnnamed(it, listOf(named)) })
        assertNotNull(objectId)
    }

    @Test
    fun theFilesOfALiveObjectAreItsBoundFragmentsInOrder() = MediaWorld().use { w ->
        val objectId = w.commitOutgoing(1)
        val files = w.stores.blobs.files(w.db, objectId, now)
        assertEquals((-1..15).toList(), files.map { it.ordinal })
        assertArrayEquals(w.nameOf(w.blobsOf(1).manifest), files.first().fileName)
        // an incoming object has files for the fragments that are bound, not for the ones still expected
        val incoming = w.receive(2)
        w.ingest(w.blobsOf(2).all.take(4))
        assertEquals(listOf(-1, 0, 1, 2), w.stores.blobs.files(w.db, incoming, now).map { it.ordinal })
        assertEquals(emptyList<OrdinalFile>(), w.stores.blobs.files(w.db, id16(0x01), now))
        assertRedacted(files.first().toString(), files.first().fileName)
    }
}
