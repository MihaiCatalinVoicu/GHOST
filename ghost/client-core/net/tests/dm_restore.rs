//! The **self-test of the host re-store tool** (Phase 9 design §15.10 step 4, §21.13 point 4:
//! "a host re-store tool (a `client-core` test binary that stores captured blobs over Tor with a
//! deposit credential), each with a self-test"; slice S12).
//!
//! The tool's core (`examples/dm_restore/restore.rs`) runs here against a **real**
//! `ghost_relay_node::Relay` in-process — the test schedule's relay-b, a write capability redeemed
//! from a pinned token, and a deposit verifier registered with it, exactly as `register.rs` sets it
//! up — so what is proved is the tool against the relay's own rules, not against a stand-in. Only
//! the Tor hop is not here; `live-tor` is where Tor is exercised, and step 4 on the gate devices is
//! where the two meet.

mod common;
#[path = "../examples/dm_restore/restore.rs"]
mod restore;

use common::*;
use ghost_client_net::namespace_client::{redeem_with, register_with};
use ghost_relay_api::proto::{Capability, RegisterResult, StoreBlobRequest};
use ghost_relay_api::{BearerCredential, BearerKind, PROTOCOL_VERSION, REQUEST_ID_BYTES};
use restore::{parse_capture, report, restore_all, Capture, Depositor, REQUIRED_BLOBS};
use sha2::{Digest, Sha256};

const NS: [u8; 32] = [0xC3; 32];
const SLOT: u8 = 1;
const WEEK: u64 = 2959;
const TTL: u32 = 604_800;

fn secret(label: &str) -> [u8; 32] {
    Sha256::digest(format!("ghost/test/restore/{label}")).into()
}

fn deposit(label: &str) -> BearerCredential {
    BearerCredential {
        kind: BearerKind::Deposit,
        slot: SLOT,
        namespace: NS,
        secret: secret(label),
    }
}

fn verifier(c: &BearerCredential) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ghost/v1/deposit-verifier");
    h.update([c.slot]);
    h.update(c.namespace);
    h.update(c.secret);
    h.finalize().into()
}

/// Relay-b of the test schedule with `credential`'s verifier registered for [`NS`] in [`WEEK`].
async fn relay_with_deposit(
    dir: &std::path::Path,
    credential: &BearerCredential,
) -> InProcessRelay {
    let now = at(WEEK, 86_400);
    let mut relay = InProcessRelay::new(
        open_relay(dir, schedule().clone(), SLOT, "ghost/test/relay-b", now),
        now,
    );
    let addr = relay_address("ghost/test/relay-b", 443);
    let capability = redeem_with(
        &mut relay,
        schedule(),
        &addr,
        NS,
        &pinned("a1"),
        [1; 16],
        now,
    )
    .await
    .unwrap()
    .capability
    .expect("a capability");
    let ok = register_with(
        &mut relay,
        NS,
        capability,
        WEEK,
        BearerKind::Deposit,
        verifier(credential),
        [7; REQUEST_ID_BYTES],
        now,
    )
    .await
    .unwrap();
    assert_eq!(ok.result, RegisterResult::Ok);
    relay
}

/// The in-process relay behind the tool's seam: the same `StoreBlobRequest` the Tor client sends.
struct InProcess<'a>(&'a InProcessRelay);

impl Depositor for InProcess<'_> {
    async fn deposit(
        &mut self,
        credential: &[u8],
        blob: &[u8],
        ttl_seconds: u32,
    ) -> Result<[u8; 32], String> {
        let request = StoreBlobRequest {
            version: PROTOCOL_VERSION,
            blob_hash: Sha256::digest(blob).to_vec(),
            data: blob.to_vec(),
            capability: Some(Capability {
                token: credential.to_vec(),
            }),
            ttl_seconds,
            request_id: rand_request_id(),
            namespace_id: NS.to_vec(),
        };
        self.0
            .relay
            .store_at(request, self.0.now)
            .map(|answer| <[u8; 32]>::try_from(answer.stored_hash.as_slice()).unwrap_or([0; 32]))
            .map_err(|status| format!("refused: {:?}", status.code()))
    }
}

fn rand_request_id() -> Vec<u8> {
    use std::sync::atomic::{AtomicU8, Ordering};
    static NEXT: AtomicU8 = AtomicU8::new(1);
    vec![NEXT.fetch_add(1, Ordering::Relaxed); REQUEST_ID_BYTES]
}

fn blobs() -> Vec<Vec<u8>> {
    (0..REQUIRED_BLOBS as u8)
        .map(|i| vec![0x70 + i; 4096])
        .collect()
}

fn capture_text(credential: &BearerCredential, blobs: &[Vec<u8>]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut text = format!(
        "# exported by dm-gate.sh replay\nnamespace {}\ncredential {}\nttl {TTL}\n",
        hex(&NS),
        hex(&credential.encode())
    );
    for blob in blobs {
        text.push_str(&format!("blob {}\n", hex(blob)));
    }
    text
}

#[tokio::test]
async fn delivered_blobs_restore_as_identical_bytes_with_the_deposit_credential() {
    let dir = tempfile::tempdir().unwrap();
    let credential = deposit("sender");
    let relay = relay_with_deposit(dir.path(), &credential).await;
    let capture: Capture = parse_capture(&capture_text(&credential, &blobs())).unwrap();
    assert_eq!(
        capture.namespace, NS,
        "the capture names the inbox it re-stores into"
    );
    // The original delivery: the sender stored the five blobs once.
    let first = restore_all(&mut InProcess(&relay), &capture).await;
    assert!(first.iter().all(|o| o.result == "stored"), "{first:?}");
    // Step 4: the same bytes again, with the same credential. The relay acknowledges exactly these
    // bytes (D1 is the recipient's tombstone, not the relay's refusal), and the report says so.
    let again = restore_all(&mut InProcess(&relay), &capture).await;
    let text = report(&again);
    assert!(
        text.ends_with("dm-restore: 5 blobs, 5 stored identical bytes\n"),
        "{text}"
    );
    assert_eq!(first, again);
}

#[tokio::test]
async fn a_credential_the_relay_never_registered_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let relay = relay_with_deposit(dir.path(), &deposit("sender")).await;
    let capture = parse_capture(&capture_text(&deposit("guessed"), &blobs())).unwrap();
    let outcomes = restore_all(&mut InProcess(&relay), &capture).await;
    assert!(
        outcomes.iter().all(|o| o.result.starts_with("refused")),
        "{outcomes:?}"
    );
    assert!(report(&outcomes).ends_with("dm-restore: 5 blobs, 0 stored identical bytes\n"));
}

#[tokio::test]
async fn the_report_carries_digests_and_never_content() {
    let dir = tempfile::tempdir().unwrap();
    let credential = deposit("sender");
    let relay = relay_with_deposit(dir.path(), &credential).await;
    let capture = parse_capture(&capture_text(&credential, &blobs())).unwrap();
    let text = report(&restore_all(&mut InProcess(&relay), &capture).await);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert!(
        !text.contains(&hex(&credential.secret)),
        "the credential's secret is not printed"
    );
    assert!(!text.contains(&hex(&NS)), "the namespace is not printed");
    for blob in blobs() {
        assert!(
            !text.contains(&hex(&blob[..32])),
            "no ciphertext is printed"
        );
        let digest: [u8; 32] = Sha256::digest(&blob).into();
        assert!(
            text.contains(&hex(&digest[..8])),
            "each blob appears as its digest prefix"
        );
    }
    assert!(
        !format!("{capture:?}").contains(&hex(&credential.secret)),
        "Debug redacts the capture"
    );
}

#[test]
fn a_short_or_malformed_capture_is_refused_before_any_io() {
    let credential = deposit("sender");
    let four: Vec<Vec<u8>> = blobs().into_iter().take(4).collect();
    assert!(parse_capture(&capture_text(&credential, &four))
        .unwrap_err()
        .contains("re-stores 5"));
    let mut odd = blobs();
    odd[2] = vec![0x11; 4000];
    assert!(parse_capture(&capture_text(&credential, &odd))
        .unwrap_err()
        .contains("not a DM bucket"));
    let no_credential = capture_text(&credential, &blobs())
        .lines()
        .filter(|l| !l.starts_with("credential"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(parse_capture(&no_credential)
        .unwrap_err()
        .contains("no credential"));
    assert!(parse_capture("namespace 00\n").is_err());
}
