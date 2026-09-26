package org.ghost.messaging.evasion;

// A Java catch whose parameter name is on the next line. Expected: line 5.
final class SplitJava {
    static void run(Runnable r) { try { r.run(); } catch (Throwable
            t) { } }
}
