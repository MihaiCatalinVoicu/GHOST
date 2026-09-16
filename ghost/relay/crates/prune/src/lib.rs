//! Deterministic removal of expired state (FR-5.5, ADR-11): blobs past their TTL, quota ledgers of
//! expired capabilities, redemption nullifiers of closed periods (Phase 8 design §10.4), and key
//! registrations past their validity with their deposit ledgers (Phase 9 design §4.5). Sweeps are
//! idempotent and their only output is a count, which is an allowed aggregate metric (§11.1).

use ghost_relay_capability::{DepositLedger, QuotaLedger};
use ghost_relay_storage::keys::KeyStore;
use ghost_relay_storage::nullifiers::NullifierStore;
use ghost_relay_storage::{BlobStore, StoreError};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub blobs_removed: usize,
    pub ledgers_removed: usize,
    /// Nullifier rows of closed periods removed (0 when redemption is disabled or the nullifier
    /// sweep did not run because the clock is below its high-water minute).
    pub nullifiers_removed: usize,
    /// `bearer_keys` records removed (0 when the key sweep did not run because the clock is below
    /// its high-water minute).
    pub key_records_removed: usize,
    /// `serial_use` rows removed.
    pub key_serials_removed: usize,
    /// Deposit ledger entries of registrations past their validity removed.
    pub deposit_ledgers_removed: usize,
}

/// The nullifier part of a sweep: the store and the last period whose acceptance window has
/// closed at the sweep's time (`None`: no period closed yet).
pub struct NullifierPeriods<'a> {
    pub store: &'a NullifierStore,
    pub closed_through: Option<u64>,
}

/// The key registration part of a sweep: `keys.redb` and the in-memory deposit ledger.
pub struct KeyRegistrations<'a> {
    pub store: &'a KeyStore,
    pub deposits: &'a mut DepositLedger,
}

/// Runs one sweep at `now_unix`: blobs, quota ledgers, nullifiers, then key registrations (last, so
/// closing a week is not delayed by the key store's commit).
pub fn sweep(
    store: &BlobStore,
    ledger: &mut QuotaLedger,
    keys: KeyRegistrations<'_>,
    nullifiers: Option<NullifierPeriods<'_>>,
    now_unix: u64,
) -> Result<SweepReport, StoreError> {
    let blobs_removed = store.prune_expired(now_unix)?;
    let ledgers_removed = ledger.prune(now_unix);
    let nullifiers_removed = match nullifiers {
        Some(n) => n.store.sweep(now_unix / 60, n.closed_through)?.removed,
        None => 0,
    };
    let key_sweep = keys.store.sweep(now_unix)?;
    let deposit_ledgers_removed = keys.deposits.prune(now_unix);
    Ok(SweepReport {
        blobs_removed,
        ledgers_removed,
        nullifiers_removed,
        key_records_removed: key_sweep.records_removed,
        key_serials_removed: key_sweep.serials_removed,
        deposit_ledgers_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_relay_capability::{Allowance, Capability, Kind, RelayKey};
    use ghost_relay_storage::keys::Registration;
    use ghost_relay_storage::nullifiers::NullifierStart;
    use ghost_relay_storage::sha256;

    #[test]
    fn sweep_removes_expired_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&dir.path().join("s.redb")).unwrap();
        let ns = [1u8; 32];
        let old = vec![1u8; 1024];
        let fresh = vec![2u8; 1024];
        store
            .put(&sha256(&old), &old, &ns, 10, 100, &mut || true)
            .unwrap(); // expires at 3_600 (expiries are rounded up to the hour)
        store
            .put(&sha256(&fresh), &fresh, &ns, 7_200, 100, &mut || true)
            .unwrap();

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

        let keys = KeyStore::open(&dir.path().join("k.redb")).unwrap();
        let mut deposits = DepositLedger::default();
        for (period, valid_until) in [(7u64, 3_600u64), (8, 7_200)] {
            keys.register(&Registration {
                namespace: ns,
                period,
                kind: 3,
                verifier: [5; 32],
                serial: [6; 16],
                quota_bytes: 10,
                valid_until,
            })
            .unwrap();
            deposits
                .charge(
                    &[Allowance {
                        record: (ns, period, [5; 32]),
                        quota_bytes: 10,
                        valid_until,
                    }],
                    1,
                )
                .unwrap();
        }

        let nulls =
            NullifierStore::open(&dir.path().join("n.redb"), NullifierStart::Create, &[0; 8])
                .unwrap();
        nulls.record_or_get(7, &[0; 32], &[1; 16]).unwrap();
        nulls.record_or_get(8, &[0; 32], &[1; 16]).unwrap();
        let periods = |closed| {
            Some(NullifierPeriods {
                store: &nulls,
                closed_through: closed,
            })
        };

        let report = sweep(
            &store,
            &mut ledger,
            KeyRegistrations {
                store: &keys,
                deposits: &mut deposits,
            },
            periods(Some(7)),
            3_600,
        )
        .unwrap();
        assert_eq!(
            report,
            SweepReport {
                blobs_removed: 1,
                ledgers_removed: 1,
                nullifiers_removed: 1,
                key_records_removed: 1,
                key_serials_removed: 1,
                deposit_ledgers_removed: 1,
            }
        );
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(nulls.count().unwrap(), 1);
        assert_eq!(keys.counts().unwrap(), (1, 1));
        assert_eq!(deposits.len(), 1);
        // Idempotent.
        assert_eq!(
            sweep(
                &store,
                &mut ledger,
                KeyRegistrations {
                    store: &keys,
                    deposits: &mut deposits,
                },
                periods(Some(7)),
                3_600
            )
            .unwrap(),
            SweepReport::default()
        );
        // Without a nullifier store the sweep still prunes blobs, ledgers and registrations.
        assert_eq!(
            sweep(
                &store,
                &mut ledger,
                KeyRegistrations {
                    store: &keys,
                    deposits: &mut deposits,
                },
                None,
                3_600
            )
            .unwrap(),
            SweepReport::default()
        );
    }
}
