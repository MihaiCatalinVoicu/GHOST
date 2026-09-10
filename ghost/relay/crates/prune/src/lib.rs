//! Deterministic removal of expired state (FR-5.5, ADR-11): blobs past their TTL, quota ledgers of
//! expired capabilities and nullifier periods that are no longer valid. Sweeps are idempotent and
//! their only output is a count, which is an allowed aggregate metric (§11.1).

use ghost_relay_capability::{NullifierSet, QuotaLedger};
use ghost_relay_storage::{BlobStore, StoreError};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub blobs_removed: usize,
    pub ledgers_removed: usize,
}

/// Runs one sweep at `now`. `keep_periods` are the nullifier periods still valid (current and
/// previous); everything else is dropped.
pub fn sweep(
    store: &BlobStore,
    ledger: &mut QuotaLedger,
    nullifiers: &mut NullifierSet,
    keep_periods: &[&[u8]],
    now_unix: u64,
) -> Result<SweepReport, StoreError> {
    let blobs_removed = store.prune_expired(now_unix)?;
    let ledgers_removed = ledger.prune(now_unix);
    nullifiers.retain_periods(keep_periods);
    Ok(SweepReport {
        blobs_removed,
        ledgers_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_relay_capability::{Capability, Kind, RelayKey};
    use ghost_relay_storage::sha256;

    #[test]
    fn sweep_removes_expired_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&dir.path().join("s.redb")).unwrap();
        let ns = [1u8; 32];
        let old = vec![1u8; 1024];
        let fresh = vec![2u8; 1024];
        store.put(&sha256(&old), &old, &ns, 10, 100).unwrap(); // expires 110
        store.put(&sha256(&fresh), &fresh, &ns, 1_000, 100).unwrap();

        let key = RelayKey::generate();
        let mut ledger = QuotaLedger::default();
        let expired_cap = Capability {
            kind: Kind::Write,
            namespace: ns,
            quota_bytes: 10,
            expiry_unix: 150,
        };
        let live_cap = Capability {
            kind: Kind::Write,
            namespace: ns,
            quota_bytes: 10,
            expiry_unix: 5_000,
        };
        ledger
            .charge(&key.mint(&expired_cap), &expired_cap, 1)
            .unwrap();
        ledger.charge(&key.mint(&live_cap), &live_cap, 1).unwrap();

        let mut nulls = NullifierSet::default();
        nulls.record_if_fresh(b"old", [0; 32]);
        nulls.record_if_fresh(b"cur", [0; 32]);

        let report = sweep(&store, &mut ledger, &mut nulls, &[b"cur"], 200).unwrap();
        assert_eq!(
            report,
            SweepReport {
                blobs_removed: 1,
                ledgers_removed: 1
            }
        );
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(nulls.len(), 1);
        // Idempotent.
        assert_eq!(
            sweep(&store, &mut ledger, &mut nulls, &[b"cur"], 200).unwrap(),
            SweepReport::default()
        );
    }
}
