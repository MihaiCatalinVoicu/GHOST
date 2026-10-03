package org.ghost.spike.media

import android.app.Service
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorSpace
import android.graphics.ImageDecoder
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SharedMemory
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.math.max
import kotlin.math.roundToInt

/** The Binder protocol of the isolated decoding service (design §9.2), spike version. */
object Iso {
    const val PING = 1
    const val DECODE = 2
    const val STRIP = 3
    const val CRASH = 4
    const val OPS = 5
}

/** JNI entry of `libghost_spike_crash.so` (rust/crashlib), V-M20 only. */
object NativeCrash {
    @JvmStatic external fun crashIn(buffer: ByteBuffer)
}

/**
 * `android:isolatedProcess="true"`, `android:process=":mdec"`, not exported (manifest). One
 * process instance per bind name ([IsoClient]); it only uses platform decoder APIs and never
 * touches files. Every reply carries the process's own `VmHWM` so the main process can record the
 * decoder's memory high-water mark.
 */
class IsoService : Service() {
    override fun onBind(intent: Intent?): IBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            val r = reply ?: return false
            when (code) {
                Iso.PING -> {
                    r.writeInt(Process.myPid())
                    r.writeInt(Process.myUid())
                    r.writeInt(if (Process.isIsolated()) 1 else 0)
                    r.writeString(SpikeApp.onCreateProcessName ?: android.app.Application.getProcessName())
                    r.writeInt(if (SpikeApp.ranInIsolatedProcess) 1 else 0)
                    r.writeInt(if (SourceProvider.created) 1 else 0)
                    r.writeLong(procStatus("VmHWM"))
                }
                Iso.OPS -> r.writeString(tryGhostAppOps())
                Iso.DECODE, Iso.STRIP -> {
                    r.writeNoException()
                    val start = r.dataPosition()
                    try {
                        if (code == Iso.DECODE) decode(data, r) else strip(data, r)
                    } catch (t: Throwable) {
                        // A decoder failure is a typed answer, not a Binder exception (§9.2).
                        r.setDataPosition(start)
                        r.writeInt(1)
                        r.writeString("${t.javaClass.simpleName}: ${t.message}")
                    }
                }
                Iso.CRASH -> crash(data.readInt(), data)
                else -> return super.onTransact(code, data, reply, flags)
            }
            return true
        }
    }

    /** Each GhostApp-like operation alone, caught, so the result says which one fails and how. */
    private fun tryGhostAppOps(): String {
        val out = ArrayList<String>()
        fun op(name: String, f: () -> Unit) {
            out += try {
                f(); "$name=ok"
            } catch (t: Throwable) {
                "$name=${t.javaClass.simpleName}(${t.message?.take(90)})"
            }
        }
        op("noBackupFilesDir") { noBackupFilesDir.path }
        op("writeNoBackupFile") { java.io.File(noBackupFilesDir, "x").writeBytes(byteArrayOf(1)) }
        op("readDataDir") { dataDir.listFiles()!!.size }
        op("keystore") { java.security.KeyStore.getInstance("AndroidKeyStore").load(null) }
        op("connectivity") { getSystemService(android.net.ConnectivityManager::class.java).activeNetwork }
        op("contentResolverQuery") {
            contentResolver.query(android.net.Uri.parse("content://org.ghost.spike.media.src/x"), null, null, null, null)?.close()
        }
        op("socket") { java.net.Socket().use { it.connect(java.net.InetSocketAddress("10.0.2.2", 9), 500) } }
        return out.joinToString(" ")
    }

    private fun decode(data: Parcel, r: Parcel) {
        val input = SharedMemory.CREATOR.createFromParcel(data)
        val len = data.readInt()
        val output = SharedMemory.CREATOR.createFromParcel(data)
        val maxW = data.readInt()
        val maxH = data.readInt()
        // 0: ImageDecoder over the mapped (direct) region; 1: BitmapFactory; 2: ImageDecoder over a
        // heap copy (tells an isolated-process limit apart from a direct-buffer one, V-M5).
        val mode = data.readInt()
        val t0 = SystemClock.elapsedRealtimeNanos()
        val inBuf = input.mapReadOnly()
        inBuf.limit(len)
        val info = StringBuilder("source=${if (mode == 2) "heapCopy" else "sharedMemory"} ")
        val bmp: Bitmap = if (mode == 1) {
            val bytes = ByteArray(len)
            inBuf.get(bytes)
            BitmapFactory.decodeByteArray(bytes, 0, len) ?: throw IllegalStateException("BitmapFactory returned null")
        } else {
            val src = if (mode == 2) ImageDecoder.createSource(java.nio.ByteBuffer.wrap(ByteArray(len).also { inBuf.get(it) })) else ImageDecoder.createSource(inBuf)
            ImageDecoder.decodeBitmap(src) { dec, i, _ ->
                info.append("mime=${i.mimeType} size=${i.size.width}x${i.size.height} animated=${i.isAnimated}")
                dec.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                // ImageDecoder returns immutable bitmaps unless asked: eraseColor(0) (design §10.5)
                // on an immutable bitmap throws "cannot erase immutable bitmaps" (seen on API 35).
                dec.isMutableRequired = true
                val w = i.size.width
                val h = i.size.height
                if (w > maxW || h > maxH) {
                    val s = minOf(maxW.toDouble() / w, maxH.toDouble() / h)
                    dec.setTargetSize(max(1, (w * s).roundToInt()), max(1, (h * s).roundToInt()))
                }
                dec.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB))
            }
        }
        val t1 = SystemClock.elapsedRealtimeNanos()
        if (Build.VERSION.SDK_INT >= 34) info.append(" hasGainmap=${bmp.hasGainmap()}")
        info.append(" config=${bmp.config} cs=${bmp.colorSpace?.name}")
        val out = output.mapReadWrite()
        val need = bmp.width * bmp.height * 4
        require(need <= out.capacity()) { "output region too small: $need > ${out.capacity()}" }
        bmp.copyPixelsToBuffer(out)
        SharedMemory.unmap(out)
        SharedMemory.unmap(inBuf)
        r.writeInt(0)
        r.writeInt(bmp.width)
        r.writeInt(bmp.height)
        r.writeLong(t1 - t0)
        r.writeString(info.toString())
        r.writeLong(procStatus("VmHWM"))
        bmp.eraseColor(0)
        bmp.recycle()
        input.close()
        output.close()
    }

    /** `STRIP_IMAGE` of design §8.2, as written, so its output can be checked (V-M4, V-M6, D29). */
    private fun strip(data: Parcel, r: Parcel) {
        val input = SharedMemory.CREATOR.createFromParcel(data)
        val len = data.readInt()
        val output = SharedMemory.CREATOR.createFromParcel(data)
        val maxBytes = data.readInt()
        val t0 = SystemClock.elapsedRealtimeNanos()
        val inBuf = input.mapReadOnly()
        inBuf.limit(len)
        val info = StringBuilder()
        var srcW = 0
        var srcH = 0
        val ladder = intArrayOf(2048, 1024, 512)
        var step = 0
        val decoded = ImageDecoder.decodeBitmap(ImageDecoder.createSource(inBuf)) { dec, i, _ ->
            srcW = i.size.width
            srcH = i.size.height
            info.append("src=${i.mimeType} ${srcW}x$srcH")
            require(srcW.toLong() * srcH <= 100_000_000L) { "over 100 MP" }
            dec.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            dec.isMutableRequired = true
            val long = max(srcW, srcH)
            step = ladder.indexOfFirst { it <= long }.let { if (it < 0) 2 else it }
            val (tw, th) = canonical(srcW, srcH, ladder[step])
            dec.setTargetSize(tw, th)
            dec.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB))
        }
        var bmp = decoded
        if (Build.VERSION.SDK_INT >= 34) {
            info.append(" gainmapBefore=${bmp.hasGainmap()}")
            bmp.gainmap = null
        }
        if (bmp.hasAlpha()) {
            val flat = Bitmap.createBitmap(bmp.width, bmp.height, Bitmap.Config.ARGB_8888)
            val c = Canvas(flat)
            c.drawColor(Color.WHITE)
            c.drawBitmap(bmp, 0f, 0f, null)
            bmp.eraseColor(0)
            bmp.recycle()
            bmp = flat
            info.append(" alphaComposited")
        }
        var bytes: ByteArray? = null
        var usedQ = -1
        while (bytes == null) {
            for (q in intArrayOf(85, 80, 75, 70, 65, 60)) {
                val bos = ByteArrayOutputStream()
                bmp.compress(Bitmap.CompressFormat.JPEG, q, bos)
                if (bos.size() <= maxBytes) {
                    bytes = bos.toByteArray()
                    usedQ = q
                    break
                }
            }
            if (bytes == null) {
                require(step < 2) { "does not fit at 512 px" }
                step++
                val (tw, th) = canonical(bmp.width, bmp.height, ladder[step])
                val smaller = Bitmap.createScaledBitmap(bmp, tw, th, true)
                bmp.eraseColor(0)
                bmp.recycle()
                bmp = smaller
            }
        }
        val out = output.mapReadWrite()
        out.put(bytes!!)
        SharedMemory.unmap(out)
        SharedMemory.unmap(inBuf)
        val t1 = SystemClock.elapsedRealtimeNanos()
        r.writeInt(0)
        r.writeInt(bytes.size)
        r.writeInt(bmp.width)
        r.writeInt(bmp.height)
        r.writeInt(usedQ)
        r.writeLong(t1 - t0)
        r.writeString(info.toString())
        r.writeLong(procStatus("VmHWM"))
        bmp.eraseColor(0)
        bmp.recycle()
        input.close()
        output.close()
    }

    private fun crash(mode: Int, data: Parcel) {
        val canary = "GHOST-S0-PLAINTEXT-CANARY-".toByteArray()
        val buf = ByteBuffer.allocateDirect(512 * 1024)
        while (buf.remaining() >= canary.size) buf.put(canary)
        buf.clear()
        when (mode) {
            1 -> {
                System.loadLibrary("ghost_spike_crash")
                NativeCrash.crashIn(buf)
            }
            2 -> Thread { throw IllegalStateException("S0 forced Java crash in :mdec") }.apply { start(); join() }
            3 -> Os.kill(Os.getpid(), OsConstants.SIGSEGV)
        }
    }

    companion object {
        /** D29: the long edge on the ladder, the short edge `max(16, 16·round(long·ratio/16))`. */
        fun canonical(w: Int, h: Int, longEdge: Int): Pair<Int, Int> {
            val landscape = w >= h
            val ratio = if (landscape) h.toDouble() / w else w.toDouble() / h
            val short = max(16, 16 * (longEdge * ratio / 16.0).roundToInt())
            return if (landscape) Pair(longEdge, short) else Pair(short, longEdge)
        }
    }
}
