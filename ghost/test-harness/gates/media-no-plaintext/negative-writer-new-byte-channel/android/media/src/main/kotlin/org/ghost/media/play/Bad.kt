package org.ghost.media.play

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** An unlisted newByteChannel writer: G-M1(b), the F-S7 review's addition. */
class Bad(path: Path) {
    val channel = Files.newByteChannel(path, StandardOpenOption.WRITE)
}
