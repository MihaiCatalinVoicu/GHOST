package org.ghost.sync.bad

// Each function below swallows a JVM error; the sync-no-catch-all gate must reject every one.
object CatchAll {
    fun throwable(block: () -> Unit) {
        try { block() } catch (t: Throwable) { }
    }

    fun error(block: () -> Unit) {
        try { block() } catch (e: Error) { }
    }

    fun qualified(block: () -> Unit) {
        try { block() } catch (e: java.lang.Exception) { }
    }

    fun assertion(block: () -> Unit) {
        try { block() } catch (e: AssertionError) { }
    }

    fun runtime(block: () -> Unit) {
        try { block() } catch (_: RuntimeException) { }
    }

    fun result(block: () -> Unit) = runCatching { block() }.getOrElse { }

    fun handler() = Thread.setDefaultUncaughtExceptionHandler { _, _ -> }
}
