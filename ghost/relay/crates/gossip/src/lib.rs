//! Inventory reconciliation between relays (FR-5.6, TB-3). A peer announces batches of blob
//! hashes; the receiver answers with the hashes it lacks. Only hashes cross the boundary — no
//! namespaces, capabilities or endpoint identities. Batches are bounded to keep memory and
//! bandwidth predictable (§11.2).

use ghost_relay_api::{HASH_BYTES, MAX_BATCH};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub enum GossipError {
    BatchTooLarge,
    BadHash,
    BadBatchId,
}

/// Validates an announced batch and computes which hashes are missing locally.
pub fn missing_from_batch<F>(
    hashes: &[Vec<u8>],
    batch_id: &[u8],
    have: F,
) -> Result<Vec<Vec<u8>>, GossipError>
where
    F: Fn(&[u8]) -> bool,
{
    if hashes.len() > MAX_BATCH {
        return Err(GossipError::BatchTooLarge);
    }
    if batch_id.len() != 16 {
        return Err(GossipError::BadBatchId);
    }
    let mut seen = HashSet::with_capacity(hashes.len());
    let mut missing = Vec::new();
    for h in hashes {
        if h.len() != HASH_BYTES {
            return Err(GossipError::BadHash);
        }
        if seen.insert(h.as_slice()) && !have(h) {
            missing.push(h.clone());
        }
    }
    Ok(missing)
}

/// Splits a local inventory into announceable batches.
pub fn batches(inventory: &[[u8; 32]]) -> impl Iterator<Item = Vec<Vec<u8>>> + '_ {
    inventory
        .chunks(MAX_BATCH)
        .map(|c| c.iter().map(|h| h.to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_missing_and_dedups() {
        let have = |h: &[u8]| h[0] == 1;
        let batch = vec![vec![1u8; 32], vec![2u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let missing = missing_from_batch(&batch, &[0u8; 16], have).unwrap();
        assert_eq!(missing, vec![vec![2u8; 32], vec![3u8; 32]]);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            missing_from_batch(&[vec![0u8; 31]], &[0u8; 16], |_| false),
            Err(GossipError::BadHash)
        );
        assert_eq!(
            missing_from_batch(&[], &[0u8; 3], |_| false),
            Err(GossipError::BadBatchId)
        );
        let big = vec![vec![0u8; 32]; MAX_BATCH + 1];
        assert_eq!(
            missing_from_batch(&big, &[0u8; 16], |_| false),
            Err(GossipError::BatchTooLarge)
        );
    }

    #[test]
    fn batching_respects_bound() {
        let inv = vec![[0u8; 32]; MAX_BATCH * 2 + 1];
        let sizes: Vec<usize> = batches(&inv).map(|b| b.len()).collect();
        assert_eq!(sizes, vec![MAX_BATCH, MAX_BATCH, 1]);
    }
}
