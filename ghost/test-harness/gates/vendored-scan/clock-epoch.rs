//! G-M8 fixture (Phase 10 review of S2a, F5): a clock read through an imported constant and a clock
//! value's method, which `std::time` finds only at the import.
use std::time::UNIX_EPOCH;

pub fn clock_b() -> u64 {
    UNIX_EPOCH.elapsed().map(|d| d.as_secs()).unwrap_or(0)
}
