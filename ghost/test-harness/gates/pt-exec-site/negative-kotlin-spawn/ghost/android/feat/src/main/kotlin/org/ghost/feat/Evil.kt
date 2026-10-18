package org.ghost.feat

class Evil {
    fun run() {
        ProcessBuilder("sh", "-c", "true").start()
    }
}
