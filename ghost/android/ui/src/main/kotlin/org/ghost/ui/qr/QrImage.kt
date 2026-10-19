package org.ghost.ui.qr

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Phase 13 design §4.7 (Q12, ADR-57): a QR code drawn module by module on a Compose `Canvas` —
 * no `Bitmap`, no file. Encoding is zxing `QRCodeWriter` in byte mode with margin 4; the error
 * correction is L for invite links, contact cards and safety-number codes (M for channel links
 * is the caller's choice through [errorCorrection]). While a code is shown the screen raises
 * the window brightness (`screenBrightness = 1f`) — the caller does that for its own window.
 *
 * The rendered content is a link or a card the user is about to share in person; it is never
 * message content, and the composable takes the payload already encoded, so this file names no
 * clipboard, no file and no share primitive.
 */
@Composable
fun QrImage(
    payload: org.ghost.ui.protect.SensitiveText,
    modifier: Modifier = Modifier,
    size: Dp = 240.dp,
    errorCorrection: ErrorCorrectionLevel = ErrorCorrectionLevel.L,
) {
    // The sensitive overload consumes the value through the value class's single declared
    // consumption door (encodePixels); the matrix build holds the payload only for the encode.
    QrImage(payload.encodePixels { it }, modifier, size, errorCorrection)
}

@Composable
fun QrImage(
    payload: String,
    modifier: Modifier = Modifier,
    size: Dp = 240.dp,
    errorCorrection: ErrorCorrectionLevel = ErrorCorrectionLevel.L,
) {
    val matrix = QRCodeWriter().encode(
        payload,
        com.google.zxing.BarcodeFormat.QR_CODE,
        0,
        0,
        mapOf(
            EncodeHintType.ERROR_CORRECTION to errorCorrection,
            EncodeHintType.MARGIN to 4,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        ),
    )
    val moduleCount = matrix.width
    Canvas(modifier.size(size)) {
        val moduleSize = this.size.minDimension / moduleCount
        drawRect(Color.White)
        for (y in 0 until moduleCount) {
            for (x in 0 until moduleCount) {
                if (matrix.get(x, y)) {
                    drawRect(
                        color = Color.Black,
                        topLeft = Offset(x * moduleSize, y * moduleSize),
                        size = Size(moduleSize, moduleSize),
                    )
                }
            }
        }
    }
}
