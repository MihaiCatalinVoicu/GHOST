//! Negative fixture (Phase 8 design §14.1): the logging-path ban covers client-core (line 3).
pub fn record() {
    tracing::debug!("client");
}
