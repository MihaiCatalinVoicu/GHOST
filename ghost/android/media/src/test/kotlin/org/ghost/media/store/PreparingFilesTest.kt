package org.ghost.media.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The reservation set of a sealer's file names (Phase 11 design §6.2, §10.4; §22.4 row 25): a name is in it from the moment it
 * is handed out until it is released, the snapshot is a copy, and many threads may reserve and release while another snapshots.
 * The protocol it serves is [MediaReconcileRaceTest]'s.
 */
class PreparingFilesTest {
    @get:Rule
    val temp = TemporaryFolder()

    private fun files(names: NameSource = SecureNameSource): CiphertextFiles =
        CiphertextFiles(File(temp.root, "m"), NioCiphertextFileSystem(), names)

    @Test
    fun aNameIsReservedFromTheMomentItIsHandedOutUntilItIsReleased() {
        val files = files()
        val preparing = PreparingFiles()
        assertTrue(preparing.isEmpty)
        val a = preparing.reserve(files)
        val b = preparing.reserve(files)
        assertEquals(16, a.size)
        assertFalse("two reservations are two names", a.contentEquals(b))
        assertEquals(setOf(hex(a), hex(b)), preparing.snapshot())
        preparing.release(a)
        assertEquals(setOf(hex(b)), preparing.snapshot())
        preparing.release(a) // releasing twice, or a name never reserved, is no error: an abort may release what a commit released
        preparing.release(ByteArray(16))
        assertEquals(setOf(hex(b)), preparing.snapshot())
        preparing.release(b)
        assertTrue(preparing.isEmpty)
        assertEquals(emptySet<String>(), preparing.snapshot())
    }

    @Test
    fun theSnapshotIsACopyAndNothingShowsAName() {
        val files = files(SequentialNames())
        val preparing = PreparingFiles()
        val name = preparing.reserve(files)
        // the name is the one the store's source produced, whole
        assertArrayEquals(ByteArray(16).also { it[0] = 0xAB.toByte(); it[15] = 1 }, name)
        val snapshot = preparing.snapshot()
        preparing.release(name)
        assertEquals("a snapshot taken before the release still holds the name", setOf(hex(name)), snapshot)
        assertTrue(preparing.snapshot().isEmpty())
        assertEquals("PreparingFiles", preparing.toString())
        assertRedacted(preparing.toString(), name)
    }

    @Test
    fun manyThreadsReserveAndReleaseWhileAnotherSnapshots() {
        val files = files()
        val preparing = PreparingFiles()
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val kept = ConcurrentLinkedQueue<ByteArray>()
        val done = (0 until 8).map {
            pool.submit {
                start.await()
                repeat(200) { n ->
                    val name = preparing.reserve(files)
                    if (n % 2 == 0) preparing.release(name) else kept += name
                    preparing.snapshot() // a reader at any moment sees a consistent set, never an exception
                }
            }
        }
        start.countDown()
        done.forEach { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()
        assertEquals("800 reserved and never released", 800, kept.size)
        assertEquals(kept.map { hex(it) }.toSet(), preparing.snapshot())
    }
}
