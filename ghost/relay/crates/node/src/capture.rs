//! Privacy capture mode (invariant T1, ADR-09). When enabled, the relay writes one JSON object per
//! observable event containing *everything it knows about that event*. The object is validated in
//! CI against `test-harness/privacy/allowed-observables.json`: any field beyond that schema is a
//! privacy violation. Production relays run with capture disabled; the point is that the set of
//! fields this type can express is the set of things a relay is permitted to learn.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Serialize, Default, Debug, Clone)]
pub struct Event {
    pub op: &'static str,
    pub protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bucket: Option<usize>,
    pub time_bucket: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_bucket_days: Option<u32>,
    /// Redeem only: the token's nullifier (hex 64), once the nullifier store holds it: `ok` and
    /// `rejected_nullifier` events only (design §10.6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    /// Redeem only: the access week of the token's key (8-byte `epoch_id`, hex 16), once the key id
    /// names an ACCESS key of the Entitlement Schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_count: Option<u64>,
    pub result: &'static str,
}

pub struct Capture {
    file: Mutex<File>,
}

impl Capture {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Capture {
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, event: &Event) {
        if let Ok(line) = serde_json::to_string(event) {
            if let Ok(mut f) = self.file.lock() {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

pub fn hex_or_none(bytes: &[u8], expected_len: usize) -> Option<String> {
    if bytes.len() == expected_len {
        Some(hex::encode(bytes))
    } else {
        None
    }
}
