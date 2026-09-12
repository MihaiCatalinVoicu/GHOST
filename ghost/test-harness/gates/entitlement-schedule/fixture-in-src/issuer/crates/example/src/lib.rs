//! Negative fixture (entitlement-schedule.sh): production code embedding the test schedule.
pub const SCHEDULE: &[u8] = include_bytes!("../tests/fixtures/test_schedule.ghes");
