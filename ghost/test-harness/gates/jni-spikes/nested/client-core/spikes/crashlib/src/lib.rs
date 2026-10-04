//! Fixture (Phase 11 S0, `ghost/spikes/media-s0/rust/crashlib`): a native crash probe that exports a
//! JNI symbol of a class no surface gate lists, on purpose, to prove a native crash is contained.

/// Writes through a null pointer.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_spike_media_NativeCrash_crashIn() {}
