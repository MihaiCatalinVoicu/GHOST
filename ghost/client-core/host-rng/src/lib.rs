//! `ghost-host-rng`: the process-global seeded randomness of host and test builds (Phase 10 design
//! `docs/design/faza10-forum.md` §12.1, §19.10; S0-7; slice S2a).
//!
//! OpenMLS draws HPKE randomness from `SysRng` on the `rayon` worker thread
//! (`treekem.rs:75`, `hpke-rs-libcrux/src/lib.rs:355-369`), so a per-actor-thread stream cannot
//! attribute those draws to a world. Built with `--cfg getrandom_backend="custom"`, this crate
//! defines the symbol getrandom 0.4's custom backend calls, `__getrandom_v03_custom`, and serves
//! every draw of every thread of the process — the libcrux provider's HMAC-DRBG seeding and
//! reseeding, the HPKE PRNG on the worker — from **one ChaCha20 stream keyed by the world seed**,
//! under one lock. [`serialized`] is the second lock of §12.1: every native call of a JVM runs
//! under it, so the draw order is the call order. With `rayon` at one worker and the `added_at`
//! day rewrite (the other two preconditions of S0-7), two runs of a scripted world are
//! byte-identical (`client-core/mls/examples/det_world.rs`, `scripts/ci/mls-determinism.sh`).
//!
//! **Never in a shipped build.** The crate refuses to compile for Android; `rust-feature-policy.sh`
//! (G-R2) fails if it reaches the graph of `ghost-client-net`, `ghost-client-mls` or
//! `ghost-client-dm`, if a shipped build configuration names the cfg, or if a host graph links a
//! second getrandom major (S0-7 (c): one custom symbol must cover every draw).
#![deny(unsafe_code)]

#[cfg(target_os = "android")]
compile_error!(
    "ghost-host-rng is for host and test builds only (design §12.1): a seeded stream must never \
     reach an Android build"
);

use std::sync::Mutex;

use rand_chacha::rand_core::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

struct Stream {
    rng: ChaCha20Rng,
    draws: u64,
    bytes: u64,
}

static STREAM: Mutex<Option<Stream>> = Mutex::new(None);
static NATIVE: Mutex<()> = Mutex::new(());

/// Whether this build serves getrandom from the seeded stream (`--cfg getrandom_backend="custom"`).
pub const ACTIVE: bool = cfg!(getrandom_backend = "custom");

/// Keys the stream with a world's seed and resets the draw counters. Until the first call the
/// stream is keyed with 32 zero bytes (a fixed default, never the OS generator).
pub fn seed(seed: [u8; 32]) {
    *STREAM.lock().unwrap_or_else(|e| e.into_inner()) = Some(Stream {
        rng: ChaCha20Rng::from_seed(seed),
        draws: 0,
        bytes: 0,
    });
}

/// `(draws, bytes)` served since the last [`seed`].
pub fn draws() -> (u64, u64) {
    STREAM
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or((0, 0), |s| (s.draws, s.bytes))
}

/// Fills `dest` from the stream (what the custom backend serves; also callable directly).
pub fn fill(dest: &mut [u8]) {
    let mut g = STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let s = g.get_or_insert_with(|| Stream {
        rng: ChaCha20Rng::from_seed([0u8; 32]),
        draws: 0,
        bytes: 0,
    });
    s.rng.fill_bytes(dest);
    s.draws += 1;
    s.bytes += dest.len() as u64;
}

/// Runs one native call under the process-wide lock (§12.1: every native call of a JVM is
/// serialised, so draws happen in call order). A panic inside `f` does not poison later calls: the
/// lock guards no data.
pub fn serialized<T>(f: impl FnOnce() -> T) -> T {
    let _guard = NATIVE.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

/// The custom backend of getrandom 0.4 (`getrandom-0.4.3/src/backends/custom.rs`).
///
/// # Safety
/// getrandom's contract: `dest` is valid for `len` writes of `u8`.
#[cfg(getrandom_backend = "custom")]
#[allow(unsafe_code)]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom passes a buffer valid for `len` writes; it is zero-filled before use, so
    // no uninitialised byte is read.
    unsafe {
        core::ptr::write_bytes(dest, 0, len);
        fill(core::slice::from_raw_parts_mut(dest, len));
    }
    Ok(())
}

/// Keeps `getrandom` a used dependency when the backend is not compiled in.
#[cfg(not(getrandom_backend = "custom"))]
#[allow(dead_code)]
fn _getrandom_error_type(e: getrandom::Error) -> getrandom::Error {
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_seed_one_stream() {
        seed([7; 32]);
        let mut a = [0u8; 64];
        fill(&mut a);
        seed([7; 32]);
        let mut b = [0u8; 64];
        fill(&mut b);
        assert_eq!(a, b);
        seed([8; 32]);
        let mut c = [0u8; 64];
        fill(&mut c);
        assert_ne!(a, c);
        assert_eq!(draws(), (1, 64));
    }

    #[test]
    fn serialized_calls_do_not_interleave() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static INSIDE: AtomicUsize = AtomicUsize::new(0);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..200 {
                        serialized(|| {
                            assert_eq!(INSIDE.fetch_add(1, Ordering::SeqCst), 0);
                            std::hint::spin_loop();
                            INSIDE.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }
}
