package org.ghost.spike.media

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Parcel
import android.os.SharedMemory
import android.os.SystemClock
import android.system.OsConstants
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Main-process side of the sandbox (design §9.2): a **fresh isolated process per request**, bound
 * with `bindIsolatedService` and a new random instance name, unbound after the reply; the death of
 * the instance is observed through `linkToDeath`.
 */
class IsoClient(private val ctx: Context) {
    private val executor = Executors.newSingleThreadExecutor()
    /** Request threads (a timed-out transact keeps its thread until the instance dies). */
    private val calls = Executors.newCachedThreadPool()

    class Session(
        val instance: String,
        val binder: IBinder?,
        val bindMs: Double,
        val callback: String,
    )

    class Done(val pid: Int, val bindMs: Double, val callMs: Double, val deathMs: Double, val result: Any?, val callback: String)

    /** Binds a new instance, runs [call], unbinds, and waits up to 5 s for the process to die. */
    fun <T> oneShot(prefix: String, call: (IBinder) -> T, timeoutMs: Long = 20_000): Done {
        // ActivityManagerService.validateServiceInstanceName accepts only [a-zA-Z0-9_.]+ (a "-"
        // throws "Illegal instanceName", seen on API 35).
        val name = prefix + "_" + randomHex(8)
        val connected = CountDownLatch(1)
        val died = CountDownLatch(1)
        var binder: IBinder? = null
        var cb = "none"
        val conn = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName?, b: IBinder?) {
                binder = b
                cb = "connected"
                connected.countDown()
            }
            override fun onServiceDisconnected(n: ComponentName?) {
                cb += "+disconnected"
            }
            override fun onBindingDied(n: ComponentName?) {
                cb += "+bindingDied"
                connected.countDown()
            }
            override fun onNullBinding(n: ComponentName?) {
                cb += "+nullBinding"
                connected.countDown()
            }
        }
        val intent = Intent(ctx, IsoService::class.java)
        val t0 = SystemClock.elapsedRealtimeNanos()
        val ok = ctx.bindIsolatedService(intent, Context.BIND_AUTO_CREATE, name, executor, conn)
        if (!ok) return Done(-1, -1.0, -1.0, -1.0, null, "bindIsolatedService=false")
        val gotIt = connected.await(timeoutMs, TimeUnit.MILLISECONDS)
        val t1 = SystemClock.elapsedRealtimeNanos()
        val b = binder
        if (!gotIt || b == null) {
            ctx.unbindService(conn)
            return Done(-1, (t1 - t0) / 1e6, -1.0, -1.0, null, if (gotIt) cb else "timeout($cb)")
        }
        b.linkToDeath({ died.countDown() }, 0)
        val pid = ping(b).pid
        // The request runs on its own thread under the design's per-request timeout (§9.2: 10 s;
        // here [timeoutMs]): a Binder transact cannot be interrupted, and on the API 29 emulator a
        // HEIF decode inside the isolated process blocks forever waiting for `media.player`.
        // After the timeout the instance is unbound (the OS kills it), which makes the blocked
        // transact return DeadObjectException on its thread.
        val fut = calls.submit(java.util.concurrent.Callable<Any?> { call(b) })
        val result: Any? = try {
            fut.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (te: java.util.concurrent.TimeoutException) {
            "call timeout after $timeoutMs ms (instance unbound and killed)"
        } catch (ee: java.util.concurrent.ExecutionException) {
            "call failed: ${ee.cause?.javaClass?.simpleName} ${ee.cause?.message}"
        }
        val t2 = SystemClock.elapsedRealtimeNanos()
        ctx.unbindService(conn)
        val t3 = SystemClock.elapsedRealtimeNanos()
        val dead = died.await(5, TimeUnit.SECONDS)
        val t4 = SystemClock.elapsedRealtimeNanos()
        return Done(pid, (t1 - t0) / 1e6, (t2 - t1) / 1e6, if (dead) (t4 - t3) / 1e6 else -1.0, result, cb)
    }

    class Ping(val pid: Int, val uid: Int, val isolated: Boolean, val processName: String?, val appRan: Boolean, val providerCreated: Boolean, val hwmKb: Long)

    fun ping(b: IBinder): Ping {
        val d = Parcel.obtain()
        val r = Parcel.obtain()
        try {
            b.transact(Iso.PING, d, r, 0)
            return Ping(r.readInt(), r.readInt(), r.readInt() == 1, r.readString(), r.readInt() == 1, r.readInt() == 1, r.readLong())
        } finally {
            d.recycle(); r.recycle()
        }
    }

    fun ops(b: IBinder): String {
        val d = Parcel.obtain()
        val r = Parcel.obtain()
        try {
            b.transact(Iso.OPS, d, r, 0)
            return r.readString() ?: ""
        } finally {
            d.recycle(); r.recycle()
        }
    }

    class Decoded(val w: Int, val h: Int, val ns: Long, val info: String, val hwmKb: Long, val pixels: ByteArray)

    /** `DECODE_IMAGE`: input region read-only; the output copied **after** the instance is gone by the caller. */
    fun decode(b: IBinder, bytes: ByteArray, maxW: Int, maxH: Int, mode: Int = 0): Pair<Decoded?, SharedMemory> {
        val input = region("in", bytes)
        val output = SharedMemory.create("out", maxW * maxH * 4)
        val d = Parcel.obtain()
        val r = Parcel.obtain()
        try {
            input.writeToParcel(d, 0)
            d.writeInt(bytes.size)
            output.writeToParcel(d, 0)
            d.writeInt(maxW); d.writeInt(maxH); d.writeInt(mode)
            b.transact(Iso.DECODE, d, r, 0)
            r.readException()
            if (r.readInt() != 0) throw IllegalStateException("sandbox: " + r.readString())
            val w = r.readInt(); val h = r.readInt(); val ns = r.readLong(); val info = r.readString() ?: ""; val hwm = r.readLong()
            return Pair(Decoded(w, h, ns, info, hwm, ByteArray(0)), output)
        } finally {
            d.recycle(); r.recycle(); zeroAndClose(input)
        }
    }

    class Stripped(val len: Int, val w: Int, val h: Int, val q: Int, val ns: Long, val info: String, val hwmKb: Long)

    fun strip(b: IBinder, bytes: ByteArray, maxBytes: Int): Pair<Stripped?, SharedMemory> {
        val input = region("in", bytes)
        val output = SharedMemory.create("out", maxBytes)
        val d = Parcel.obtain()
        val r = Parcel.obtain()
        try {
            input.writeToParcel(d, 0)
            d.writeInt(bytes.size)
            output.writeToParcel(d, 0)
            d.writeInt(maxBytes)
            b.transact(Iso.STRIP, d, r, 0)
            r.readException()
            if (r.readInt() != 0) throw IllegalStateException("sandbox: " + r.readString())
            return Pair(Stripped(r.readInt(), r.readInt(), r.readInt(), r.readInt(), r.readLong(), r.readString() ?: "", r.readLong()), output)
        } finally {
            d.recycle(); r.recycle(); zeroAndClose(input)
        }
    }

    fun crash(b: IBinder, mode: Int) {
        val d = Parcel.obtain()
        val r = Parcel.obtain()
        try {
            d.writeInt(mode)
            b.transact(Iso.CRASH, d, r, 0)
        } finally {
            d.recycle(); r.recycle()
        }
    }

    companion object {
        private val rnd = SecureRandom()
        fun randomHex(n: Int): String {
            val b = ByteArray(n)
            rnd.nextBytes(b)
            return hex(b)
        }

        /** A region with [bytes], set read-only before it is passed (design §9.2). */
        fun region(name: String, bytes: ByteArray): SharedMemory {
            val s = SharedMemory.create(name, maxOf(1, bytes.size))
            val m = s.mapReadWrite()
            m.put(bytes)
            SharedMemory.unmap(m)
            s.setProtect(OsConstants.PROT_READ)
            return s
        }

        /** The caller's copy of an output region, then zero-filled and closed. */
        fun takeAndZero(s: SharedMemory, len: Int): ByteArray {
            val m = s.mapReadWrite()
            val out = ByteArray(len)
            m.get(out)
            m.clear()
            while (m.hasRemaining()) m.put(0)
            SharedMemory.unmap(m)
            s.close()
            return out
        }

        fun zeroAndClose(s: SharedMemory) {
            s.close()
        }
    }
}
