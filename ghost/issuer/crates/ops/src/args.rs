//! Strict flag parsing: `--name value` pairs from a closed list per command. A refused command line
//! is reported by the flag's static name, never by echoing what was typed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ghost_entitlement::Kind;

use crate::Failure;

pub struct Flags {
    values: BTreeMap<&'static str, String>,
}

impl Flags {
    pub fn parse(argv: &[String], allowed: &[&'static str]) -> Result<Self, Failure> {
        let mut values = BTreeMap::new();
        let mut it = argv.iter();
        while let Some(arg) = it.next() {
            let Some(name) = arg.strip_prefix("--") else {
                return Err(Failure::usage("unexpected-argument", None));
            };
            let Some(&flag) = allowed.iter().find(|f| **f == name) else {
                return Err(Failure::usage("unknown-flag", None));
            };
            let value = match it.next() {
                Some(v) if !v.starts_with("--") => v.clone(),
                _ => return Err(Failure::usage("missing-value", Some(flag))),
            };
            if values.insert(flag, value).is_some() {
                return Err(Failure::usage("repeated-flag", Some(flag)));
            }
        }
        Ok(Self { values })
    }

    pub fn has(&self, flag: &str) -> bool {
        self.values.contains_key(flag)
    }

    /// Refuses every present flag outside `flags` (a mode of a command takes only its own).
    pub fn only(&self, flags: &[&'static str]) -> Result<(), Failure> {
        match self.values.keys().find(|f| !flags.contains(f)) {
            Some(&extra) => Err(Failure::usage("conflicting-flags", Some(extra))),
            None => Ok(()),
        }
    }

    pub fn text(&self, flag: &'static str) -> Result<&str, Failure> {
        self.values
            .get(flag)
            .map(String::as_str)
            .ok_or(Failure::usage("missing-flag", Some(flag)))
    }

    pub fn path(&self, flag: &'static str) -> Result<PathBuf, Failure> {
        self.text(flag).map(PathBuf::from)
    }

    pub fn opt_path(&self, flag: &'static str) -> Option<PathBuf> {
        self.values.get(flag).map(PathBuf::from)
    }

    pub fn u64(&self, flag: &'static str) -> Result<u64, Failure> {
        parse_u64(self.text(flag)?).ok_or(Failure::usage("bad-value", Some(flag)))
    }

    pub fn kind(&self, flag: &'static str) -> Result<Kind, Failure> {
        parse_kind(self.text(flag)?).ok_or(Failure::usage("bad-value", Some(flag)))
    }

    /// A 32-byte value in lowercase hex (a schedule public key).
    pub fn hex32(&self, flag: &'static str) -> Result<[u8; 32], Failure> {
        crate::hexfmt::decode(self.text(flag)?)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(Failure::usage("bad-value", Some(flag)))
    }
}

/// Canonical decimal: digits only, no sign, no leading zero (except "0" itself).
pub fn parse_u64(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

pub fn parse_kind(text: &str) -> Option<Kind> {
    Kind::ALL
        .into_iter()
        .find(|k| ghost_issuer::custody::kind_name(*k) == text)
}
