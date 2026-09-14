//! `status.json` fixed vocabulary (Phase 8 design §6.5, G-11 "ops-status fixed vocabulary"): every
//! reachable status serialises to one JSON object whose keys are exactly `status::KEYS`, in order,
//! whose strings are codes of `status::CODES`, and whose other values are decimal integers or
//! booleans. No identifier, address, amount of one invoice or free text can appear.

mod common;

use common::world::World;
use ghost_issuer::rail::RailError;
use ghost_issuer::status::{
    write_status_file, PoolCode, ReconciliationCode, ScannerCode, StatusReport, CODES, KEYS,
};

#[derive(Debug)]
enum Value {
    Code(String),
    Number,
    Bool,
}

/// A strict reader of the one-line object `to_json` writes.
fn parse(json: &str) -> Vec<(String, Value)> {
    let body = json
        .strip_suffix('\n')
        .and_then(|s| s.strip_prefix('{'))
        .and_then(|s| s.strip_suffix('}'))
        .expect("one object on one line");
    body.split(',')
        .map(|field| {
            let (key, value) = field.split_once(':').expect("key:value");
            let key = key
                .strip_prefix('"')
                .and_then(|k| k.strip_suffix('"'))
                .expect("quoted key")
                .to_string();
            let value =
                if let Some(code) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                    Value::Code(code.to_string())
                } else if value == "true" || value == "false" {
                    Value::Bool
                } else {
                    assert!(
                        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                        "not a decimal integer: {value}"
                    );
                    Value::Number
                };
            (key, value)
        })
        .collect()
}

fn check(report: &StatusReport) {
    let json = report.to_json();
    let fields = parse(&json);
    let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, KEYS.to_vec(), "keys and their order are fixed");
    for (key, value) in &fields {
        if let Value::Code(code) = value {
            assert!(
                CODES.contains(&code.as_str()),
                "{key}: {code} outside the vocabulary"
            );
        }
    }
    assert!(json.is_ascii());
}

#[test]
fn every_reachable_status_uses_the_fixed_vocabulary() {
    let numbers = [0u64, 1, 99, 100, 2_960, u64::MAX];
    let mut count = 0;
    for scanner in ScannerCode::ALL {
        for pool in PoolCode::ALL {
            for reconciliation in ReconciliationCode::ALL {
                for &n in &numbers {
                    for flag in [false, true] {
                        check(&StatusReport {
                            scanner,
                            keys_ready_until_week: n,
                            es_horizon_weeks: n,
                            pool,
                            open_invoices: n / 100 * 100,
                            reconciliation,
                            reorg_after_issue: n,
                            confirmed_unissued: n,
                            pool_reconciled: n,
                            sign_fault: n,
                            keys_missing: n,
                            payout_batch_ready: flag,
                            payout_batches_open: n,
                            payout_oldest_batch_weeks: n,
                            payout_acks_refused: n,
                            refresh_refused: n,
                            halted: !flag,
                        });
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 5 * 3 * 2 * 6 * 2);
}

#[test]
fn the_vocabulary_is_closed_and_every_code_is_listed() {
    for list in [KEYS.as_slice(), CODES.as_slice()] {
        for (i, s) in list.iter().enumerate() {
            assert!(
                s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{s}"
            );
            assert!(!list[..i].contains(s), "{s} twice");
        }
    }
    for c in ScannerCode::ALL.map(ScannerCode::code) {
        assert!(CODES.contains(&c));
    }
    for c in PoolCode::ALL.map(PoolCode::code) {
        assert!(CODES.contains(&c));
    }
    for c in ReconciliationCode::ALL.map(ReconciliationCode::code) {
        assert!(CODES.contains(&c));
    }
    assert_eq!(PoolCode::of(0), PoolCode::Empty);
    assert_eq!(PoolCode::of(15), PoolCode::Low);
    assert_eq!(PoolCode::of(16), PoolCode::Ok);
}

#[test]
fn a_live_issuer_status_is_in_the_vocabulary_and_written_atomically() {
    let mut w = World::new(true);
    w.buy_pack("p");
    let now = w.now;
    let report = w.issuer().status_at(now).unwrap();
    assert_eq!(report.scanner, ScannerCode::Ok);
    assert_eq!(report.reconciliation, ReconciliationCode::Ok);
    assert_eq!(report.pool, PoolCode::Low);
    check(&report);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status.json");
    write_status_file(&path, &report).unwrap();
    write_status_file(&path, &report).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), report.to_json());
    assert!(!dir.path().join("status.json.tmp").exists());

    w.chain.set_failure(Some(RailError::Transport));
    w.tick();
    assert_eq!(
        w.issuer().status_at(now).unwrap().scanner,
        ScannerCode::WalletUnreachable
    );
    w.chain.set_failure(Some(RailError::ReorgDepth));
    w.tick();
    let report = w.issuer().status_at(now).unwrap();
    assert_eq!(report.scanner, ScannerCode::ReorgDepth);
    check(&report);
    w.chain.set_failure(None);
    w.tick();
    assert_eq!(
        w.issuer().status_at(now + 301).unwrap().scanner,
        ScannerCode::Stalled
    );
}
