package org.ghost.spike.media

import android.content.Context
import android.os.Build
import android.os.FileObserver
import java.io.File
import java.security.MessageDigest
import java.util.Collections

/** Report lines of the running probe (returned in the instrumentation result, see [SpikeRunner]). */
object Report {
    val lines: MutableList<String> = Collections.synchronizedList(ArrayList())
    fun line(s: String) {
        lines += s
    }
}

fun report(s: String) = Report.line(s)

fun sha256(b: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(b))

fun hex(b: ByteArray): String {
    val sb = StringBuilder(b.size * 2)
    for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
    return sb.toString()
}

/** `VmHWM` / `VmRSS` of this process, in kB, from /proc/self/status. */
fun procStatus(key: String): Long {
    return try {
        File("/proc/self/status").readLines().firstOrNull { it.startsWith("$key:") }
            ?.substringAfter(':')?.trim()?.substringBefore(' ')?.toLong() ?: -1
    } catch (e: Exception) {
        -1
    }
}

/**
 * Every directory an app process can write to without a permission (design §15.8 item 1's list):
 * the credential-encrypted data dir (files, cache, code_cache, no_backup, databases,
 * shared_prefs, app_*), the device-encrypted data dir, and the app's external dirs. The external
 * dirs are listed only if they exist: calling getExternalFilesDir would create them.
 */
fun appDirs(ctx: Context): List<File> {
    val out = ArrayList<File>()
    out += ctx.dataDir
    out += ctx.createDeviceProtectedStorageContext().dataDir
    for (p in listOf("/sdcard/Android/data/${ctx.packageName}", "/sdcard/Android/media/${ctx.packageName}", "/sdcard/Android/obb/${ctx.packageName}")) {
        val f = File(p)
        if (f.exists()) out += f
    }
    return out
}

/** Recursive listing: path -> "size mtime". */
fun inventory(ctx: Context): Map<String, String> {
    val m = java.util.TreeMap<String, String>()
    fun walk(f: File) {
        val kids = f.listFiles() ?: return
        for (k in kids) {
            if (k.isDirectory) {
                m[k.path + "/"] = "dir"
                walk(k)
            } else {
                m[k.path] = "${k.length()} ${k.lastModified()}"
            }
        }
    }
    for (d in appDirs(ctx)) walk(d)
    return m
}

fun inventoryDiff(before: Map<String, String>, after: Map<String, String>): List<String> {
    val out = ArrayList<String>()
    for ((k, v) in after) {
        val b = before[k]
        if (b == null) out += "NEW $k $v" else if (b != v) out += "CHANGED $k $b -> $v"
    }
    for (k in before.keys) if (!after.containsKey(k)) out += "GONE $k"
    return out
}

/**
 * FileObserver on every directory of [appDirs] (recursively; FileObserver itself is not recursive),
 * recording every create, write, move and delete event, plus opens for writing.
 */
class FsWatch(ctx: Context) {
    val events: MutableList<String> = Collections.synchronizedList(ArrayList())
    private val observers = ArrayList<FileObserver>()
    val watched = ArrayList<String>()

    init {
        val dirs = ArrayList<File>()
        fun walk(f: File) {
            if (!f.isDirectory) return
            dirs += f
            f.listFiles()?.forEach { walk(it) }
        }
        for (d in appDirs(ctx)) walk(d)
        val mask = FileObserver.CREATE or FileObserver.MODIFY or FileObserver.CLOSE_WRITE or
            FileObserver.MOVED_TO or FileObserver.MOVED_FROM or FileObserver.DELETE or FileObserver.ATTRIB
        for (d in dirs) {
            val o = object : FileObserver(d, mask) {
                override fun onEvent(event: Int, path: String?) {
                    events += "${eventName(event)} ${d.path}/${path ?: ""}"
                }
            }
            o.startWatching()
            observers += o
            watched += d.path
        }
    }

    fun stop(): List<String> {
        observers.forEach { it.stopWatching() }
        return ArrayList(events)
    }

    private fun eventName(e: Int): String {
        val names = ArrayList<String>()
        if (e and FileObserver.CREATE != 0) names += "CREATE"
        if (e and FileObserver.MODIFY != 0) names += "MODIFY"
        if (e and FileObserver.CLOSE_WRITE != 0) names += "CLOSE_WRITE"
        if (e and FileObserver.MOVED_TO != 0) names += "MOVED_TO"
        if (e and FileObserver.MOVED_FROM != 0) names += "MOVED_FROM"
        if (e and FileObserver.DELETE != 0) names += "DELETE"
        if (e and FileObserver.ATTRIB != 0) names += "ATTRIB"
        return if (names.isEmpty()) "0x" + Integer.toHexString(e) else names.joinToString("|")
    }
}

fun deviceLine(): String =
    "device: sdk=${Build.VERSION.SDK_INT} release=${Build.VERSION.RELEASE} fingerprint=${Build.FINGERPRINT} abi=${Build.SUPPORTED_ABIS.joinToString(",")}"
