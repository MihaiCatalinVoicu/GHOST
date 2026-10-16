package org.ghost.media.sandbox

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Build
import android.os.DeadObjectException
import android.os.IBinder
import android.os.SharedMemory
import java.security.SecureRandom
import android.os.Parcel
import org.ghost.media.send.MediaSendLimits
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The main-process half of the sandbox protocol (§9.2): one **fresh isolated process instance per
 * request** — bind with a random instance name, hand the request over `SharedMemory`, unbind, and
 * the instance dies with its decoded plaintext. At most [MediaSendLimits.MAX_DECODER_PROCESSES]
 * instances live at once; a request waits for a permit, and a permit is held for the whole bind.
 *
 * The main process **checks every answer on its own copy, taken after the instance is unbound**:
 * the bytes it checks are the bytes it seals or shows, and no live sandbox can change them
 * afterwards (§6.2, §9.2). Every `SharedMemory` region is zero-filled before it is unmapped and
 * closed, on both sides. A timeout ([MediaSendLimits.SANDBOX_TIMEOUT_MS]), a crashed instance
 * (`DeadObjectException`) or a malformed reply is a typed [Failure]; the caller counts two
 * failures per object towards `undecodable` (CS-M8).
 */
class MediaSandbox(
    private val context: Context,
    private val random: SecureRandom = SecureRandom(),
) {
    /** A sandbox answer: the output region's bytes, copied out after the instance died. */
    sealed class Result {
        class Ok(val bytes: ByteArray, val width: Int, val height: Int) : Result()
        class Failure(val reason: Reason) : Result() {
            enum class Reason {
                /** The bind did not connect, the call did not return, or the answer was malformed. */
                TIMEOUT,

                /** The instance died mid-request (a decoder crash — §9.2's typed failure). */
                CRASHED,

                /** The service answered a refusal (over 100 MP, would not fit, decode error). */
                REFUSED,
            }
        }
    }

    private val permits = Semaphore(MAX_LIVE)

    /**
     * `STRIP_IMAGE` (§8.2): [source] is the picked image's encoded bytes (sniffed to JPEG, PNG or
     * static WebP in the main process before any byte reaches the sandbox). The service derives
     * the D29 geometry from the source's own header (the main process never parses image
     * headers); [preview] asks for the 320-px preview instead of the object image. The answer is
     * the re-encoded JPEG, checked by the caller **after the instance died** — `jpegCanonicalize`
     * in Rust on its own copy, so the bytes it seals are the bytes it checked (§6.2).
     */
    fun stripImage(source: ByteArray, preview: Boolean, maxBytes: Int): Result =
        request(OP_STRIP, source, listOf(if (preview) 1 else 0, maxBytes))

    /**
     * `DECODE_IMAGE`: a canonical JPEG (already validated) decoded to ARGB pixels within
     * [maxW] × [maxH]; the answer's `bytes` are `w × h × 4`. The recipient-side preview path (§7.4).
     */
    fun decodeImage(jpeg: ByteArray, maxW: Int, maxH: Int): Result =
        request(OP_DECODE, jpeg, listOf(maxW, maxH))

    // ---------------------------------------------------------------- internals

    private fun request(op: Int, input: ByteArray, params: List<Int>): Result {
        if (!permits.tryAcquire()) return Result.Failure(Result.Failure.Reason.TIMEOUT)
        val inputRegion = try {
            SharedMemory.create("ghost-in", input.size).apply {
                mapReadWrite().apply {
                    put(input)
                    // Zeroed after the copy, before the read-only protect: a PROT_READ region
                    // cannot be mapped read-write again (EPERM), so the section 9.2 zeroing
                    // hygiene happens here, not in the teardown (the S5 device smoke, 2026-10-16).
                    while (hasRemaining()) put(0)
                    SharedMemory.unmap(this)
                }
                // Read-only for the sandbox.
                setProtect(android.system.OsConstants.PROT_READ)
            }
        } catch (e: IllegalArgumentException) {
            permits.release()
            return Result.Failure(Result.Failure.Reason.REFUSED)
        }
        val outSize = if (op == OP_DECODE) {
            // Pixels: the bounds the caller computed from the canonical geometry.
            params[0] * params[1] * 4
        } else {
            // JPEG: never above the image content bound.
            MediaSendLimits.IMAGE_MAX_CONTENT
        }
        val outputRegion = try {
            SharedMemory.create("ghost-out", outSize)
        } catch (e: IllegalArgumentException) {
            inputRegion.close()
            permits.release()
            return Result.Failure(Result.Failure.Reason.REFUSED)
        }
        val binderRef = AtomicReference<IBinder?>()
        val connected = CountDownLatch(1)
        // Hex, never a sign: the instance name becomes a process-name suffix, where '-' is
        // illegal — a negative draw made bindIsolatedService throw and every bind fail (found
        // by the S5 device smoke, 2026-10-16).
        val instance = "m" + java.lang.Long.toHexString(random.nextLong())
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                binderRef.set(service)
                connected.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                connected.countDown()
            }

            override fun onBindingDied(name: ComponentName?) {
                connected.countDown()
            }

            override fun onNullBinding(name: ComponentName?) {
                connected.countDown()
            }
        }
        val intent = Intent(context, MediaDecodeService::class.java)
        val bound = try {
            if (Build.VERSION.SDK_INT >= 29) {
                context.bindIsolatedService(
                    intent,
                    Context.BIND_AUTO_CREATE,
                    instance,
                    Executor { it.run() },
                    connection,
                )
            } else {
                false
            }
        } catch (e: SecurityException) {
            false
        } catch (e: IllegalArgumentException) {
            false
        }
        if (!bound) {
            inputRegion.close()
            outputRegion.close()
            permits.release()
            return Result.Failure(Result.Failure.Reason.TIMEOUT)
        }
        var result: Result
        try {
            if (!connected.await(MediaSendLimits.SANDBOX_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                result = Result.Failure(Result.Failure.Reason.TIMEOUT)
            } else {
                val binder = binderRef.get()
                result = if (binder == null) {
                    Result.Failure(Result.Failure.Reason.TIMEOUT)
                } else {
                    transact(binder, op, inputRegion, input.size, outputRegion, params)
                }
            }
        } finally {
            try {
                context.unbindService(connection)
            } catch (e: IllegalArgumentException) {
                // Never bound (a refused bind above): nothing to unbind.
            }
            // The instance dies with the unbind (§9.2); the answer is copied out already.
            // The input was zeroed before its read-only protect; only the output is zeroed here.
            zeroAndClose(outputRegion)
            inputRegion.close()
            permits.release()
        }
        return result
    }

    private fun transact(
        binder: IBinder,
        op: Int,
        inputRegion: SharedMemory,
        inputLen: Int,
        outputRegion: SharedMemory,
        params: List<Int>,
    ): Result {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            inputRegion.writeToParcel(data, 0)
            data.writeInt(inputLen)
            outputRegion.writeToParcel(data, 0)
            for (p in params) data.writeInt(p)
            binder.transact(op, data, reply, 0)
            reply.readException()
            when (reply.readInt()) {
                0 -> {
                    val size = reply.readInt()
                    val width = reply.readInt()
                    val height = reply.readInt()
                    if (size < 0 || size > outputRegion.size) {
                        Result.Failure(Result.Failure.Reason.TIMEOUT)
                    } else {
                        val copy = outputRegion.mapReadOnly().let { buf ->
                            try {
                                buf.limit(size)
                                val b = ByteArray(size)
                                buf.get(b)
                                b
                            } finally {
                                SharedMemory.unmap(buf)
                            }
                        }
                        // §9.2's parcel discipline: exactly the three ints, nothing after.
                        if (reply.dataAvail() != 0) {
                            Result.Failure(Result.Failure.Reason.TIMEOUT)
                        } else {
                            Result.Ok(copy, width, height)
                        }
                    }
                }
                1 -> Result.Failure(
                    when (reply.readInt()) {
                        ERR_DECODE -> Result.Failure.Reason.REFUSED
                        else -> Result.Failure.Reason.TIMEOUT
                    },
                )
                else -> Result.Failure(Result.Failure.Reason.TIMEOUT)
            }
        } catch (e: DeadObjectException) {
            Result.Failure(Result.Failure.Reason.CRASHED)
        } catch (e: android.os.RemoteException) {
            // The transaction itself failed (a malformed reply, a transport refusal): typed.
            Result.Failure(Result.Failure.Reason.TIMEOUT)
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    private fun zeroAndClose(region: SharedMemory) {
        try {
            val buf = region.mapReadWrite()
            try {
                while (buf.hasRemaining()) buf.put(0)
            } finally {
                SharedMemory.unmap(buf)
            }
        } catch (e: IllegalStateException) {
            // Already unmapped/closed: the zeroing hygiene ran where it could.
        }
        region.close()
    }

    companion object {
        /** The two operations (§9.2); the parcels carry SharedMemory handles and ints only. */
        const val OP_STRIP: Int = 1
        const val OP_DECODE: Int = 2

        /** The service's typed refusal code (a decode error or a bound check). */
        const val ERR_DECODE: Int = 1

        /** Live instances at once (§9.2, Q25's bound). */
        const val MAX_LIVE: Int = org.ghost.media.send.MediaSendLimits.MAX_DECODER_PROCESSES
    }
}
