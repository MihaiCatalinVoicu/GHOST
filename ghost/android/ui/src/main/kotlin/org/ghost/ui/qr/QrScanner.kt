package org.ghost.ui.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.view.Surface
import android.view.TextureView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors

/**
 * Phase 13 design §4.7 (Q12, ADR-57): in-app QR scanning — Camera2 preview on a `TextureView`
 * inside the secure window (the camera permission is the screen's, requested at first use);
 * YUV frames from an [ImageReader] decoded by zxing `QRCodeReader` (TRY_HARDER) on the single
 * `ghost-qr` thread. Frames are never stored; the camera closes at leave, hide and lock (the
 * composition's disposal). Each screen states which payload it expects ([expected]); anything
 * else is refused with [onRefused], never decoded further.
 *
 * A device without a camera (`android.hardware.camera` not required, G-U11) never composes
 * this — the paste fallback stands alone on those screens.
 */
@Composable
fun QrScanner(
    context: Context,
    expected: ExpectedPayload,
    onDecoded: (String) -> Unit,
    onRefused: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val executor = remember { Executors.newSingleThreadExecutor { r -> Thread(r, "ghost-qr") } }
    val state = remember { ScannerState(executor, expected, onDecoded, onRefused) }

    DisposableEffect(Unit) {
        onDispose {
            state.close()
            executor.shutdown()
        }
    }

    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            TextureView(ctx).also { view ->
                view.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                    override fun onSurfaceTextureAvailable(surface: android.graphics.SurfaceTexture, width: Int, height: Int) {
                        state.start(ctx, view, Surface(surface), width, height)
                    }

                    override fun onSurfaceTextureSizeChanged(surface: android.graphics.SurfaceTexture, width: Int, height: Int) = Unit

                    override fun onSurfaceTextureDestroyed(surface: android.graphics.SurfaceTexture): Boolean {
                        state.close()
                        return true
                    }

                    override fun onSurfaceTextureUpdated(surface: android.graphics.SurfaceTexture) = Unit
                }
            }
        },
    )
}

/** The payload kinds a screen may expect (§4.7); anything else is refused. */
enum class ExpectedPayload { INVITE, CONTACT_CARD_OR_LINK, CHANNEL_LINK, SAFETY_NUMBER }

private class ScannerState(
    private val executor: java.util.concurrent.ExecutorService,
    private val expected: ExpectedPayload,
    private val onDecoded: (String) -> Unit,
    private val onRefused: () -> Unit,
) {
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private val handlerThread = android.os.HandlerThread("ghost-qr").apply { start() }
    private val handler = android.os.Handler(handlerThread.looper)
    private var busy = false

    fun start(context: Context, view: TextureView, previewSurface: Surface, width: Int, height: Int) {
        if (context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            onRefused()
            return
        }
        val manager = context.getSystemService(CameraManager::class.java)
        val id = manager.cameraIdList.firstOrNull { cid ->
            manager.getCameraCharacteristics(cid)
                .get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
        } ?: manager.cameraIdList.firstOrNull() ?: run {
            onRefused()
            return
        }
        val imgReader = ImageReader.newInstance(width, height, ImageFormat.YUV_420_888, 2)
        reader = imgReader
        imgReader.setOnImageAvailableListener({ r ->
            val image = r.acquireNextImage() ?: return@setOnImageAvailableListener
            if (busy) {
                image.close()
                return@setOnImageAvailableListener
            }
            busy = true
            try {
                decode(image)
            } finally {
                image.close()
                busy = false
            }
        }, handler)
        manager.openCamera(id, executor, object : CameraDevice.StateCallback() {
            override fun onOpened(device: CameraDevice) {
                camera = device
                val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
                request.addTarget(previewSurface)
                request.addTarget(imgReader.surface)
                device.createCaptureSession(
                    listOf(previewSurface, imgReader.surface),
                    object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(s: CameraCaptureSession) {
                            session = s
                            s.setRepeatingRequest(request.build(), null, null)
                        }

                        override fun onConfigureFailed(session: CameraCaptureSession) {
                            onRefused()
                        }
                    },
                    handler,
                )
            }

            override fun onDisconnected(device: CameraDevice) = close()

            override fun onError(device: CameraDevice, error: Int) = close()
        })
    }

    private fun decode(image: android.media.Image) {
        val planes = image.planes
        val yPlane = planes[0]
        val source = PlanarYUVLuminanceSource(
            yPlane.buffer.array().copyOf(yPlane.buffer.remaining()),
            yPlane.rowStride,
            image.height,
            0,
            0,
            image.width,
            image.height,
            false,
        )
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val text = try {
            QRCodeReader().decode(bitmap, mapOf(DecodeHintType.TRY_HARDER to true)).text
        } catch (e: Exception) {
            null
        }
        if (text != null && accepted(text)) {
            handler.post { onDecoded(text) }
        }
    }

    /** The screen's expectation (§4.7): a payload of another kind is refused, never acted on. */
    private fun accepted(text: String): Boolean = when (expected) {
        ExpectedPayload.INVITE -> text.startsWith("ghost://invite/")
        ExpectedPayload.CONTACT_CARD_OR_LINK -> text.startsWith("GHOST1") || text.startsWith("ghost://contact/")
        ExpectedPayload.CHANNEL_LINK -> text.startsWith("ghost://channel/")
        ExpectedPayload.SAFETY_NUMBER -> text.startsWith("GHOST-SN-") || text.length in 60..200
    }

    fun close() {
        handlerThread.quitSafely()
        session?.close()
        session = null
        camera?.close()
        camera = null
        reader?.close()
        reader = null
    }
}
