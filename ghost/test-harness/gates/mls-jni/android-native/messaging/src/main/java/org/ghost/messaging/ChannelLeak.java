package org.ghost.messaging;

/** Fixture: a native method in another module. */
final class ChannelLeak {
    // static native byte[] commented();
    static native byte[] leak(long handle);
}
