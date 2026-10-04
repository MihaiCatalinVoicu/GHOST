//! Negative fixture for the scopes of the source gates (Phase 10, slice S3): the crate of the channel
//! core is read by the hygiene gates like the rest of `client-core`.

pub fn epoch() -> u64 {
    // TODO: derive the epoch from the exporter
    println!("epoch");
    1
}
