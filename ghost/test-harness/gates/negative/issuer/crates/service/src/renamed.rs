//! Negative fixture (Phase 8 design §6.5, §14.1): a logging crate brought in under another name is
//! reported where it is brought in (lines 3, 4 and 5).
use tracing as t;
extern crate log as l;
pub use ::log as logger;
pub fn record(n: u64) {
    t::info!("n = {n}");
}
