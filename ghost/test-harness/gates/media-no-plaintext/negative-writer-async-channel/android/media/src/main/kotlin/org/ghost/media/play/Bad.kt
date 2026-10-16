package org.ghost.media.play

import java.nio.channels.AsynchronousFileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** An unlisted asynchronous channel writer: G-M1(b), the F-S7 review's addition. */
class Bad(path: Path) {
    val channel = AsynchronousFileChannel.open(path, StandardOpenOption.WRITE)
}
