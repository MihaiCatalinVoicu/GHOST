package org.ghost.update.harness

import org.ghost.update.Updates
import org.junit.Assert.assertArrayEquals
import java.io.File
import java.security.MessageDigest

/**
 * The recording installer port (Phase 14 design §11.2): keeps every byte written to an install
 * session; the world fails if they differ from the bytes the native check verified (the MC-D22
 * oracle). A session here is the whole `install()` call — the platform's own session mechanics
 * are out of the world's scope (the emulator drill covers the platform half, §11.4).
 */
internal class RecordingInstaller : Updates.Installer {

    /** One committed install session: every byte the installer streamed, and its SHA-256. */
    class Session(val bytes: ByteArray) {
        val sha256: ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }

    val sessions: MutableList<Session> = mutableListOf()

    override fun install(apk: File) {
        sessions += Session(apk.readBytes())
    }

    /** The last session's bytes must equal the verified APK's bytes, byte for byte. */
    fun assertLastEquals(verified: ByteArray) {
        check(sessions.isNotEmpty()) { "no install session was committed" }
        assertArrayEquals("the installer streamed other bytes than the verified APK", verified, sessions.last().bytes)
    }

    /** Every session of this world, against one expected byte image. */
    fun assertAllEqual(verified: ByteArray) {
        sessions.forEachIndexed { i, s ->
            assertArrayEquals("install session $i differs from the verified APK", verified, s.bytes)
        }
    }
}
