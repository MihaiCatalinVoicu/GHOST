package org.ghost.sync.bad;

// Java forms the sync-no-catch-all gate must reject.
final class CatchAllJava {
    static void multi(Runnable r) {
        try { r.run(); } catch (IllegalStateException | Error e) { }
    }

    static void plain(Runnable r) {
        try { r.run(); } catch (final Throwable t) { }
    }
}
