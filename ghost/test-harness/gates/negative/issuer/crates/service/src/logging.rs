//! Negative fixture (Phase 8 design §6.5, §14.1): the issuer keeps no logs at all, so logging
//! framework paths and bare logging macros are reported (lines 3 and 5 to 9).
use tracing::Level;
pub fn record(n: u64) {
    tracing::info!("n = {n}");
    log::warn!("n");
    info!("n");
    error!("n");
    event!(Level::INFO, n);
}
