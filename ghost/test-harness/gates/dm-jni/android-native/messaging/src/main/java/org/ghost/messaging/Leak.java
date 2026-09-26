package org.ghost.messaging;

/** Fixture (Phase 9 review GATES-3): a Java native method in a production source set. */
final class Leak {
    // A comment that says native is not a declaration.
    static native byte[] open(long handle);
}
