//! Negative fixture (Phase 8 design §14.1): the logging-macro ban covers relay crates (line 3).
pub fn record() {
    trace!("relay");
}
