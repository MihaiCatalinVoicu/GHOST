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
