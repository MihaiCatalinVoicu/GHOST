//! The core of the **host re-store tool** (Phase 9 design §15.10 step 4, §21.13 point 4; slice S12):
//! re-store captured DM blobs, byte for byte, with a deposit credential — the relay's D1 view of a
//! replay ("identical-bytes re-stores"), which the receiving phone must then show nothing for.
//!
//! This file is shared: `main.rs` drives it over Tor against a staging relay, and the self-test
//! `client-core/net/tests/dm_restore.rs` drives it against a real `ghost_relay_node::Relay`
//! in-process, through the [`Depositor`] seam. Neither is shipped: the tool is an example of
//! `ghost-client-net`, never part of `libghost_client_net.so`.
//!
//! **What it prints is digests, never content** (§15.10: the orchestrator "records digests, never
//! content"): per blob, the first 8 bytes of its SHA-256 and the outcome. The credential is a
//! bearer secret and the blobs are ciphertext; neither is written anywhere by this code.

use sha2::{Digest, Sha256};
use std::future::Future;

/// The capture the gate phone exported: one inbox namespace, the deposit credential for it at
/// one relay, the store TTL, and the blobs to re-store.
pub struct Capture {
    /// The recipient's inbox namespace `X_c`.
    pub namespace: [u8; 32],
    /// The deposit credential v3 for `namespace` at the relay (a bearer secret).
    pub credential: Vec<u8>,
    /// The TTL bucket of the original stores, in seconds.
    pub ttl_seconds: u32,
    /// The captured ciphertexts, in capture order.
    pub blobs: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("blobs", &self.blobs.len())
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

/// The padding buckets of a DM envelope (design §6.6): nothing else was ever stored.
const BUCKETS: [usize; 3] = [4096, 16384, 65536];

/// How many blobs step 4 re-stores; the tool refuses a capture with fewer (§15.10: "5 delivered
/// blobs") so a short export cannot pass for the step.
pub const REQUIRED_BLOBS: usize = 5;

fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "not hex".to_string()))
        .collect()
}

/// Parses the capture file: `namespace <hex>`, `credential <hex>`, `ttl <seconds>`, then one
/// `blob <hex>` line per ciphertext; `#` lines and blank lines are skipped. Every blob must be
/// bucket-sized, and there must be at least [`REQUIRED_BLOBS`].
pub fn parse_capture(text: &str) -> Result<Capture, String> {
    let mut namespace = None;
    let mut credential = None;
    let mut ttl_seconds = None;
    let mut blobs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(' ')
            .ok_or("a capture line is `key value`")?;
        match key {
            "namespace" => {
                let bytes = hex_bytes(value)?;
                namespace = Some(
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| "a namespace is 32 bytes")?,
                );
            }
            "credential" => credential = Some(hex_bytes(value)?),
            "ttl" => ttl_seconds = Some(value.trim().parse::<u32>().map_err(|_| "ttl is seconds")?),
            "blob" => {
                let blob = hex_bytes(value)?;
                if !BUCKETS.contains(&blob.len()) {
                    return Err(format!(
                        "blob {} is {} bytes, not a DM bucket",
                        blobs.len(),
                        blob.len()
                    ));
                }
                blobs.push(blob);
            }
            _ => return Err(format!("unknown capture key `{key}`")),
        }
    }
    if blobs.len() < REQUIRED_BLOBS {
        return Err(format!(
            "the capture holds {} blobs; step 4 re-stores {REQUIRED_BLOBS}",
            blobs.len()
        ));
    }
    Ok(Capture {
        namespace: namespace.ok_or("the capture names no namespace")?,
        credential: credential.ok_or("the capture carries no credential")?,
        ttl_seconds: ttl_seconds.ok_or("the capture names no ttl")?,
        blobs,
    })
}

/// Where a blob is stored: the relay over Tor in the tool, an in-process relay in the self-test.
pub trait Depositor {
    /// Stores `blob` in the capture's namespace with `credential` and answers the hash the relay
    /// acknowledged, or the refusal's description (never the blob or the credential).
    fn deposit(
        &mut self,
        credential: &[u8],
        blob: &[u8],
        ttl_seconds: u32,
    ) -> impl Future<Output = Result<[u8; 32], String>>;
}

/// One blob's outcome, as the report prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The first 8 bytes of the blob's SHA-256, in hex.
    pub digest: String,
    /// `stored` when the relay acknowledged exactly these bytes, else the refusal.
    pub result: String,
}

/// Re-stores every blob of `capture`, in order. A receipt naming another hash is a failure: the
/// step is "identical bytes", and a relay that acknowledged something else did not store them.
pub async fn restore_all<D: Depositor>(depositor: &mut D, capture: &Capture) -> Vec<Outcome> {
    let mut out = Vec::with_capacity(capture.blobs.len());
    for blob in &capture.blobs {
        let hash: [u8; 32] = Sha256::digest(blob).into();
        let digest = hash[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let result = match depositor
            .deposit(&capture.credential, blob, capture.ttl_seconds)
            .await
        {
            Ok(acknowledged) if acknowledged == hash => "stored".to_string(),
            Ok(_) => "acknowledged-other-bytes".to_string(),
            Err(refusal) => refusal,
        };
        out.push(Outcome { digest, result });
    }
    out
}

/// The report: one line per blob, then `dm-restore: <n> blobs, <stored> stored identical bytes`.
pub fn report(outcomes: &[Outcome]) -> String {
    let mut text = String::new();
    for o in outcomes {
        text.push_str(&format!("blob {} {}\n", o.digest, o.result));
    }
    let stored = outcomes.iter().filter(|o| o.result == "stored").count();
    text.push_str(&format!(
        "dm-restore: {} blobs, {stored} stored identical bytes\n",
        outcomes.len()
    ));
    text
}
