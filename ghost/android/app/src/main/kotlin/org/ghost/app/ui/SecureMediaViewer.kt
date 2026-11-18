package org.ghost.app.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.view.TextureView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.util.UnstableApi
import org.ghost.media.play.GhostPlayer
import org.ghost.media.store.MediaKind
import org.ghost.media.store.MediaLimits
import org.ghost.messaging.api.MediaHandle

/** Full-screen secure media: no save/share surface and no plaintext file or network cache. */
@UnstableApi
@Composable
internal fun SecureMediaViewer(handle: MediaHandle, onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().background(androidx.compose.ui.graphics.Color.Black)) {
        when (handle.kind) {
            MediaKind.IMAGE -> ImageViewer(handle, modifier = Modifier.weight(1f))
            MediaKind.VIDEO -> VideoViewer(handle, modifier = Modifier.weight(1f))
        }
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(text = stringResource(org.ghost.ui.R.string.media_close))
        }
    }
}

@Composable
private fun ImageViewer(handle: MediaHandle, modifier: Modifier = Modifier) {
    val bitmap = remember(handle) { decodeImage(handle) }
    DisposableEffect(bitmap) {
        onDispose { if (bitmap != null && !bitmap.isRecycled) bitmap.recycle() }
    }
    if (bitmap == null) {
        Text(text = stringResource(org.ghost.ui.R.string.media_unavailable), modifier = modifier)
    } else {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = stringResource(org.ghost.ui.R.string.media_open),
            contentScale = ContentScale.Fit,
            modifier = modifier.fillMaxWidth(),
        )
    }
}

@UnstableApi
@Composable
private fun VideoViewer(handle: MediaHandle, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val player = remember(handle) { GhostPlayer.create(context, handle.playable, "ghost://media/viewer") }
    var texture by remember { mutableStateOf<TextureView?>(null) }
    var playing by remember { mutableStateOf(false) }
    LaunchedEffect(texture) {
        texture?.let { view ->
            player.setVideoTextureView(view)
            player.prepare()
        }
    }
    DisposableEffect(handle) {
        onDispose { player.release() }
    }
    Column(modifier = modifier, verticalArrangement = Arrangement.Center) {
        AndroidView(
            factory = { ctx -> TextureView(ctx).also { texture = it } },
            modifier = Modifier.fillMaxWidth().weight(1f),
        )
        Button(
            onClick = {
                playing = !playing
                player.playWhenReady = playing
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = stringResource(if (playing) org.ghost.ui.R.string.media_pause else org.ghost.ui.R.string.media_play),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

private fun decodeImage(handle: MediaHandle): Bitmap? {
    require(handle.contentLength in 1..Int.MAX_VALUE.toLong()) { "image is too large" }
    val bytes = ByteArray(handle.contentLength.toInt())
    return try {
        val chunkSize = MediaLimits.CHUNK_PLAINTEXT
        val chunks = (bytes.size + chunkSize - 1) / chunkSize
        var offset = 0
        for (index in 0 until chunks) {
            val chunk = handle.playable.readChunk(index)
            try {
                chunk.copyInto(bytes, offset, endIndex = minOf(chunk.size, bytes.size - offset))
                offset += chunk.size
            } finally {
                chunk.fill(0)
            }
        }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    } finally {
        bytes.fill(0)
    }
}
