//! Fixture: the one test entry point of the channel library (`MlsVectors.run`), which the MLS gate
//! requires its scan root to write, so the root is otherwise clean and only `spikes/` is in question.

/// The vector replay's entry.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsVectors_run() {}
