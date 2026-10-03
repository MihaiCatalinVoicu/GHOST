//! Plaintext left in freed heap memory (review M3 and ML2, design §19.31): a global allocator that
//! looks at every block when it is freed. (1) The Argon2id matrix of a password invite (64 MiB at
//! `kdf_code` 1) is freed all zero: `argon2` 0.6.0's own `hash_password_into` frees it unwiped, and
//! the freed matrix yields the key. (2) During a call, no freed or moved block holds a stored row's
//! plaintext (the member's `EpochSecrets` row, epoch secrets as JSON). Its own test binary, since
//! the allocator is the process's; the two tests take one lock, so neither sees the other's blocks.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::derive::{derive_invite_password_key, InvitePassword};
use ghost_client_mls::kv::{label_of, WrappedRows};
use support::*;

/// The Argon2id matrix at `kdf_code` 1: 65 536 blocks of 1 KiB.
const MATRIX: usize = 64 * 1024 * 1024;

static NEEDLE: OnceLock<Vec<u8>> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static MATRICES_FREED: AtomicUsize = AtomicUsize::new(0);
static MATRICES_DIRTY: AtomicUsize = AtomicUsize::new(0);
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Spy;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// Looks at a block about to be freed (or moved away by `realloc`).
fn inspect(block: &[u8]) {
    if block.len() == MATRIX {
        MATRICES_FREED.fetch_add(1, Ordering::SeqCst);
        if block.iter().any(|&b| b != 0) {
            MATRICES_DIRTY.fetch_add(1, Ordering::SeqCst);
        }
    }
    if ARMED.load(Ordering::SeqCst) {
        if let Some(n) = NEEDLE.get() {
            if contains(block, n) {
                HITS.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// SAFETY: every call is forwarded to the system allocator with its own arguments; the block is
// read only while it is still allocated (before `dealloc`, and before `realloc` may move it).
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        inspect(unsafe { std::slice::from_raw_parts(p, l.size()) });
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        inspect(unsafe { std::slice::from_raw_parts(p, l.size()) });
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Spy = Spy;

/// M3: the matrix is freed all zero.
#[test]
fn the_argon2id_matrix_is_freed_zeroized() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let freed = MATRICES_FREED.load(Ordering::SeqCst);
    let dirty = MATRICES_DIRTY.load(Ordering::SeqCst);
    let pw = InvitePassword::from_bytes(b"correct horse battery staple".to_vec());
    let key = derive_invite_password_key(&pw, &[7u8; 16], 1).unwrap();
    assert_ne!(key.as_bytes(), &[0u8; 32]);
    assert_eq!(
        MATRICES_FREED.load(Ordering::SeqCst) - freed,
        1,
        "one 64 MiB matrix per derivation"
    );
    assert_eq!(
        MATRICES_DIRTY.load(Ordering::SeqCst) - dirty,
        0,
        "the Argon2id matrix was freed with its contents (it yields the key)"
    );
}

/// ML2: no freed block holds the plaintext of a stored row while a call reads it.
#[test]
fn a_call_frees_no_row_plaintext() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut w = World::create(80, 0);
    w.admit(1);
    let b = &w.members[1];
    // The plaintext of the member's EpochSecrets row: a 96-byte window from its middle (secret
    // bytes written as JSON numbers).
    let row = {
        let kv = raw_storage(b, DAY);
        let rows = kv.rows();
        let row = rows
            .iter()
            .find(|((_, k), _)| label_of(k) == b"EpochSecrets")
            .map(|(_, v)| v)
            .expect("an EpochSecrets row");
        let mid = row.len() / 2;
        row[mid..mid + 96].to_vec()
    };
    NEEDLE.set(row).unwrap();
    let content = ChannelContent {
        kind: KIND_POST,
        op_id: [1; 16],
        author_minute: minute(DAY),
        timer_code: 4,
        body: Body::Post {
            text: "a post".into(),
            reply_to: None,
        },
    }
    .encode()
    .unwrap();
    let rows = b.wrapped();
    // A call that only reads (the roster) and one that writes (a post: the secret tree's rows).
    ARMED.store(true, Ordering::SeqCst);
    let r = b.ctx.roster(&b.ch, &WrappedRows(&rows), DAY);
    let post = b.ctx.encrypt(&b.ch, &WrappedRows(&rows), &content, 1, DAY);
    let ok = r.is_ok() && post.is_ok();
    drop((r, post));
    ARMED.store(false, Ordering::SeqCst);
    assert!(ok, "the calls succeed");
    assert_eq!(
        HITS.load(Ordering::SeqCst),
        0,
        "freed heap blocks held the EpochSecrets row's plaintext"
    );
}
