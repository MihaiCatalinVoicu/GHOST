package org.ghost.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 13 design §5.5, §12.2 (CS-U1, MC-U3, MC-U4): the wipe W2–W7 over an in-memory file
 * system and a software Keystore port. Every crash point (between the steps) leaves either an
 * intact app (before W3) or a state [WipeController.needsResumption] completes at the next
 * start — files deleted before the key aliases (MC-U3) or leftovers never finished (MC-U4)
 * cannot happen.
 */
class WipeCrashTest {
    private class MemFs : WipeController.Filesystem {
        val files = HashMap<String, Boolean>() // path -> isDirectory
        override fun exists(path: String): Boolean = files.containsKey(path)
        override fun delete(path: String): Boolean {
            files.remove(path)
            return true
        }

        override fun isDirectory(path: String): Boolean = files[path] == true
        override fun listRecursively(path: String): List<String> =
            files.keys.filter { it.startsWith("$path/") && files[it] == false }
                .map { it.removePrefix("$path/") }.sorted()
    }

    private class World(val crashAfter: Int = -1) {
        val fs = MemFs()
        val events = ArrayList<String>()
        var controller: WipeController = newController()
        var crashAt = 0

        fun newController() = WipeController(
            files = fs,
            stopStacks = { step("stop") },
            deleteEnvelopes = { step("envelopes") },
            deleteKeystoreAliases = { step("keystore") },
            cancelNotifications = { step("notif") },
            clearClipboard = { step("clip") },
            exitProcess = { step("exit") },
        )

        /** The CS-U1 resumption's tail: W5 then the W6 cleanups — never W3/W4 again. */
        fun finishResumption() {
            controller.deleteFiles()
            controller.resumptionCleanups()
        }

        private fun step(name: String) {
            events.add(name)
            // The real deleteEnvelopes removes the key envelope; the in-memory world does too,
            // or the resumption predicate can never turn false.
            if (name == "envelopes") fs.files.remove(WipeController.KEY_ENVELOPE)
            if (crashAfter >= 0 && ++crashAt == crashAfter) throw Kill()
        }

        fun seed() {
            fs.files[WipeController.KEY_ENVELOPE] = false
            fs.files[WipeController.DATABASE] = false
            fs.files[WipeController.DATABASE_WAL] = false
            fs.files[WipeController.NO_BACKUP] = true
            fs.files["${WipeController.NO_BACKUP}/secrets/root-entropy.v1"] = false
            fs.files["${WipeController.NO_BACKUP}/tor/state"] = false
            fs.files[WipeController.FILES] = true
            fs.files["${WipeController.FILES}/pt/installer.stamp"] = false
            fs.files[WipeController.CACHE] = true
        }
    }

    private class Kill : RuntimeException("simulated process kill")

    @Test
    fun aFullWipeRunsW2ToW7InOrderAndLeavesNothing() {
        val w = World()
        w.seed()
        w.controller.wipe()
        assertEquals(listOf("stop", "envelopes", "keystore", "notif", "clip", "exit"), w.events)
        assertFalse("no data file survives", w.fs.files.keys.any { it == WipeController.DATABASE || it.startsWith(WipeController.NO_BACKUP + "/") })
        assertFalse("the wipe never needs resumption after a complete run", w.controller.needsResumption())
    }

    @Test
    fun aCrashBeforeW3LeavesAnIntactApp() {
        // crashAfter = 1 (after "stop", before envelopes): the envelopes still name the keys,
        // so the app is intact and the next start must NOT run the resumption.
        val w = World(crashAfter = 1)
        w.seed()
        try {
            w.controller.wipe()
        } catch (e: Kill) {
            // the kill
        }
        assertEquals(listOf("stop"), w.events)
        assertTrue("the envelopes survived", w.fs.exists(WipeController.KEY_ENVELOPE))
        assertFalse("an intact app is not resumed", w.controller.needsResumption())
    }

    @Test
    fun anyCrashFromW3OnIsCompletedAtTheNextStart() {
        // crashAfter = 2..3: after envelopes/keystore, the next start sees no key envelope but
        // data (or leftovers) and the resumption predicate fires; running the tail completes.
        // (A kill in W6/W7 — notif/clip/exit — leaves no file state to resume: at most one
        // uncancelled notification, which T57's residue list already names; the file predicate
        // is the design's CS-U1 trigger.)
        for (crashAfter in 2..3) {
            val w = World(crashAfter = crashAfter)
            w.seed()
            try {
                w.controller.wipe()
            } catch (e: Kill) {
                // the kill at step $crashAfter
            }
            assertTrue("a kill at step $crashAfter demands resumption", w.controller.needsResumption())
            // The next start runs the resumption tail (W5–W6, never W3/W4 again).
            w.finishResumption()
            assertFalse("completed after the restart (kill at $crashAfter)", w.controller.needsResumption())
        }
    }

    @Test
    fun theResumptionRunsFilesAndCleanupsButNeverTheEnvelopesAgain() {
        // After a crash past W3 the resumption path calls deleteFiles + the W4-W6 cleanups —
        // modelled here by re-running the controller and asserting the envelope step never
        // re-runs: needsResumption() false after completion and the key material (aliases) was
        // shredded exactly once, which the events log shows as a single "keystore" entry.
        val w = World(crashAfter = 3) // crash after keystore
        w.seed()
        try {
            w.controller.wipe()
        } catch (e: Kill) {
        }
        assertEquals(1, w.events.count { it == "keystore" })
        w.finishResumption()
        assertEquals("the crypto-shred ran once", 1, w.events.count { it == "keystore" })
        assertFalse("completed after the resumption", w.controller.needsResumption())
    }
}
