//! A fixture crate. Comments may name std::time, std::fs, unsafe and jni freely.
#![forbid(unsafe_code)]

#[cfg(feature = "nonce-registry")]
mod registry;

/// A string is not code: "std::fs::read", "Instant::now()", "rand::random".
pub const NOTE: &str = "std::time::SystemTime and extern \"C\"";

/// core::time::Duration is a type, not a clock.
pub fn span(ms: u64) -> core::time::Duration {
    core::time::Duration::from_millis(ms)
}

/// Near misses of the rules the review of S1 added: a `'static` lifetime is not a static item, a
/// `use std` that names no I/O, clock or thread module, and a comment that names
/// `#[path = "x.rs"]`, `include!`, `std::path`, `fs::read` and `extern crate`.
pub fn label() -> &'static str {
    "static X: u32 = 0; fs::read(\"x\"); std::path::Path"
}
use std::collections::BTreeMap;
pub fn empty() -> BTreeMap<u8, u8> {
    BTreeMap::new()
}

use std::{fmt::{self, Display}, io};
pub fn ask() -> String { let mut s = String::new(); let _ = io::stdin().read_line(&mut s); s }
pub fn show(d: &dyn Display, f: &mut fmt::Formatter<'_>) -> fmt::Result { d.fmt(f) }
