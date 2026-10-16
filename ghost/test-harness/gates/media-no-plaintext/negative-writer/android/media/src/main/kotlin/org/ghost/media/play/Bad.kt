package org.ghost.media.play

import java.io.File
import java.io.FileOutputStream

/** A second file writer, unlisted: G-M1(b). */
class Bad(file: File) {
    val out = FileOutputStream(file)
}
