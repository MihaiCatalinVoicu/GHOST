//! V10-6 probe: the process-global seeded stream of design §12.1 / §19.10, behind getrandom 0.4's
//! custom backend (`--cfg getrandom_backend="custom"`, host builds only). Every draw of every
//! thread of the process — the libcrux provider's HMAC-DRBG seeding and reseeding, and the HPKE
//! PRNG `hpke-rs-libcrux` seeds from `SysRng` on the `rayon` worker — comes from one ChaCha20
//! stream keyed by the world seed, under one lock. The draws are logged (thread, length) so the
//! probe can show which threads draw.

use std::sync::Mutex;
use std::thread::ThreadId;

use rand_chacha::rand_core::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

struct Stream {
    rng: ChaCha20Rng,
    log: Vec<(ThreadId, usize)>,
}

static STREAM: Mutex<Option<Stream>> = Mutex::new(None);

/// Keys the stream (a world's seed); clears the draw log.
pub fn seed(seed: [u8; 32]) {
    *STREAM.lock().unwrap() = Some(Stream {
        rng: ChaCha20Rng::from_seed(seed),
        log: Vec::new(),
    });
}

/// The draws since the last `seed`: `(thread, bytes)`.
pub fn draws() -> Vec<(ThreadId, usize)> {
    STREAM
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.log.clone())
        .unwrap_or_default()
}

/// # Safety
/// getrandom's contract: `dest` is valid for `len` writes.
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    let mut g = STREAM.lock().map_err(|_| getrandom::Error::UNSUPPORTED)?;
    let s = g.get_or_insert_with(|| Stream {
        rng: ChaCha20Rng::from_seed([0u8; 32]),
        log: Vec::new(),
    });
    core::ptr::write_bytes(dest, 0, len);
    let buf = core::slice::from_raw_parts_mut(dest, len);
    s.rng.fill_bytes(buf);
    s.log.push((std::thread::current().id(), len));
    Ok(())
}
