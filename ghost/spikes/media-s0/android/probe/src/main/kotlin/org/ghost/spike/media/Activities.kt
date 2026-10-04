package org.ghost.spike.media

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.view.WindowManager
import android.widget.ImageView
import java.util.concurrent.CountDownLatch

/**
 * V-M20: a full-screen pattern of distinctive colours (magenta and lime stripes with a cyan
 * square). Extras: `secure` sets FLAG_SECURE, `noRecents` calls `setRecentsScreenshotEnabled(false)`
 * (API 33+). The host sends the task to the background and reads the task snapshot directory.
 */
class ViewerActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val secure = intent.getBooleanExtra("secure", false)
        val noRecents = intent.getBooleanExtra("noRecents", false)
        if (secure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (noRecents && Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        val b = Bitmap.createBitmap(540, 960, Bitmap.Config.ARGB_8888)
        val c = Canvas(b)
        val p = Paint()
        for (i in 0 until 12) {
            p.color = if (i % 2 == 0) Color.rgb(255, 0, 255) else Color.rgb(0, 255, 0)
            c.drawRect(0f, i * 80f, 540f, (i + 1) * 80f, p)
        }
        p.color = Color.rgb(0, 255, 255)
        c.drawRect(170f, 380f, 370f, 580f, p)
        val v = ImageView(this)
        v.setImageBitmap(b)
        v.scaleType = ImageView.ScaleType.FIT_XY
        setContentView(v)
    }
}

/**
 * V-M21 / V-M11: opens the system picker the way the design does (§6.1): the photo picker
 * (`MediaStore.ACTION_PICK_IMAGES`, what `PickVisualMedia` uses where the picker exists) on API 33+,
 * `ACTION_OPEN_DOCUMENT` (DocumentsUI, `PickVisualMedia`'s API 29 fallback) otherwise. The returned
 * stream is read straight into memory with no app-side copy while [watch] observes the app dirs.
 */
class PickActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val i = if (Build.VERSION.SDK_INT >= 33) {
            Intent(MediaStore.ACTION_PICK_IMAGES).setType("image/*")
        } else {
            Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("image/*")
        }
        result = "intent=${i.action}"
        startActivityForResult(i, 1)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        result = if (uri == null) {
            "$result resultCode=$resultCode no uri"
        } else {
            try {
                val bytes = contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                picked = bytes
                "$result resultCode=$resultCode uri=$uri bytes=${bytes.size} sha256=${sha256(bytes)} flags=0x${Integer.toHexString(data.flags)}"
            } catch (t: Throwable) {
                "$result uri=$uri read failed ${t.javaClass.simpleName}: ${t.message}"
            }
        }
        done?.countDown()
        finish()
    }

    companion object {
        @Volatile var result: String? = null
        /** The bytes read, kept in memory; written out by the probe only after the watch stopped. */
        @Volatile var picked: ByteArray? = null
        @Volatile var done: CountDownLatch? = null
        @Volatile var watch: FsWatch? = null
    }
}
