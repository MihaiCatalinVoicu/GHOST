package org.ghost.spike.media

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileNotFoundException

/**
 * Serves `filesDir/src/<name>` read-only as `content://org.ghost.spike.media.src/<name>`, so Media3
 * reads every source through `ContentDataSource` as design §6.1 prescribes for picked videos (the
 * picker's own URIs are exercised by V-M21). [created] is V-M19's probe: it is set in whichever
 * process installs this provider, and the isolated service reports it.
 */
class SourceProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        created = true
        return true
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("read-only")
        val name = uri.lastPathSegment ?: throw FileNotFoundException("no name")
        val f = File(File(context!!.filesDir, "src"), name)
        if (!f.isFile || f.parentFile?.name != "src") throw FileNotFoundException(name)
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String? = when {
        uri.path?.endsWith(".mp4") == true -> "video/mp4"
        uri.path?.endsWith(".jpg") == true -> "image/jpeg"
        else -> null
    }

    override fun query(uri: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<out String>?): Int = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<out String>?): Int = 0

    companion object {
        @Volatile var created = false
        fun uri(name: String): Uri = Uri.parse("content://org.ghost.spike.media.src/$name")
    }
}
