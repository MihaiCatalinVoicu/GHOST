package org.ghost.app

import android.content.Context
import org.ghost.network.NetworkException
import org.ghost.network.TorMirrorTransport
import org.ghost.network.UpdateNative
import org.ghost.sync.api.MirrorAccess
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * The `gate` build type's mirror override (Phase 14 design §11.4's emulator half, G-DM5's rules):
 * while the orchestrator's `update-loopback` command has named a model-mirror endpoint
 * (`host:port`, persisted in a flag file exactly like `DmBranch`'s switch, because every
 * instrumentation command is a new process), the `Update` session's [MirrorAccess] fetches the
 * natively built path from that endpoint over plain HTTP instead of the Tor mirror. The release
 * and debug twins always answer `null`; G-DM5 refuses this file's package in every release source
 * set and in R8's release mapping.
 *
 * What the loopback may name: the endpoint (a test input), the verb and the status codes of plain
 * HTTP. What it still may not name: the network segment, the file name and the chunk step — those
 * come from `UpdateNative.mirrorPath` / `UpdateNative.apkChunkStep`, built by the same native code
 * the Tor transport uses (PM-D9, PM-D10 hold even in the test double).
 */
internal object UpdateLoopback {
    private const val LOOPBACK_FILE = "gate-update-loopback"

    /** Turns the loopback on at [endpoint] ("host:port"), or off with null. */
    fun set(app: Context, endpoint: String?) {
        val file = File(app.noBackupFilesDir, LOOPBACK_FILE)
        if (endpoint == null) file.delete() else file.writeText(endpoint)
    }

    /** The override the sync runtime consults at every `Update` session creation. */
    fun mirror(app: Context): MirrorAccess? {
        val file = File(app.noBackupFilesDir, LOOPBACK_FILE)
        if (!file.isFile) return null
        return LoopbackMirror(file.readText())
    }

    private class LoopbackMirror(private val endpoint: String) : MirrorAccess {
        override fun fetchBundle(mirrorSet: Long, slot: Int, deadlineMillis: Int): ByteArray =
            get(mirrorSet, TorMirrorTransport.KIND_BUNDLE, 0, null, expectPartial = false, deadlineMillis)

        override fun fetchApkChunk(mirrorSet: Long, slot: Int, chunkIndex: Long, deadlineMillis: Int): ByteArray {
            val step = UpdateNative.apkChunkStep()
            val start = chunkIndex * step
            return get(
                mirrorSet, TorMirrorTransport.KIND_APK_CHUNK, chunkIndex,
                start..(start + step - 1), expectPartial = true, deadlineMillis,
            )
        }

        private fun get(
            mirrorSet: Long,
            kind: Int,
            chunkIndex: Long,
            range: LongRange?,
            expectPartial: Boolean,
            deadlineMillis: Int,
        ): ByteArray {
            val path = UpdateNative.mirrorPath(mirrorSet, kind, chunkIndex)
            val connection = try {
                (URL("http://$endpoint$path").openConnection() as HttpURLConnection).also {
                    it.connectTimeout = deadlineMillis
                    it.readTimeout = deadlineMillis
                    if (range != null) it.setRequestProperty("Range", "bytes=${range.first}-${range.last}")
                }
            } catch (e: java.io.IOException) {
                throw NetworkException("transport")
            }
            val code = try {
                connection.responseCode
            } catch (e: java.io.IOException) {
                connection.disconnect()
                throw NetworkException("transport")
            }
            val expected = if (expectPartial) 206 else 200
            if (code != expected) {
                connection.disconnect()
                throw NetworkException("malformed_response")
            }
            val body = try {
                connection.inputStream.use { it.readBytes() }
            } catch (e: java.io.IOException) {
                connection.disconnect()
                throw NetworkException("transport")
            }
            connection.disconnect()
            if (body.isEmpty()) throw NetworkException("malformed_response")
            return body
        }
    }
}
