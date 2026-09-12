//! Reader for `protocol/test-vectors/blind_rsa_pp2.txt` (format in the file header).
#![allow(dead_code)]

use std::collections::BTreeMap;

pub mod fixture;

pub const FILE: &str = include_str!("../../../../../protocol/test-vectors/blind_rsa_pp2.txt");

pub struct Vector {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl Vector {
    pub fn get(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("vector {}: missing field {key}", self.id))
    }

    pub fn hex(&self, key: &str) -> Vec<u8> {
        hex::decode(self.get(key))
            .unwrap_or_else(|e| panic!("vector {}: field {key}: {e}", self.id))
    }
}

/// The vectors of one `[section]`, in file order.
pub fn section(name: &str) -> Vec<Vector> {
    let mut current = None::<String>;
    let mut out: Vec<Vector> = Vec::new();
    for line in FILE.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = Some(s.to_string());
            continue;
        }
        if current.as_deref() != Some(name) {
            continue;
        }
        if let Some(rest) = line.strip_prefix("vector ") {
            let id = rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            out.push(Vector {
                id,
                fields: BTreeMap::new(),
            });
            continue;
        }
        let (key, value) = line
            .split_once(" =")
            .unwrap_or_else(|| panic!("malformed line: {line}"));
        let vector = out
            .last_mut()
            .unwrap_or_else(|| panic!("field before any vector: {line}"));
        let previous = vector
            .fields
            .insert(key.to_string(), value.trim().to_string());
        assert!(
            previous.is_none(),
            "duplicate field {key} in vector {}",
            vector.id
        );
    }
    out
}
