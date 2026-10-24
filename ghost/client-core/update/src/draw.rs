//! The mirror draw of one update run (§7.8). Pure: the caller passes the run's two uniform
//! draws from the process key (`RandomSources.updateRun`), never client state beyond the root
//! and the manifest's mirror set.

/// A `(onion, operator id)` mirror entry; the onion is the canonical `host.onion:port` spelling.
pub type Mirror = (Vec<u8>, [u8; 16]);

/// The two mirrors of one update run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorPick {
    /// Drawn uniformly from the trusted root's anchor mirrors.
    pub first: Mirror,
    /// Drawn from the anchor mirrors and the current fresh manifest's extra mirrors, without
    /// the first, preferring another operator id.
    pub second: Mirror,
}

/// §7.8: the first mirror from the anchor set; the second from anchors + extras (without the
/// first), restricted to a different operator id when one is available. `r0`/`r1` are the run's
/// two draws, `u64` each. `extras` is empty when the manifest is expired or not current, and on
/// `NO_CHANNEL` the caller passes the embedded root's anchors as the extras.
pub fn draw_mirrors(anchors: &[Mirror], extras: &[Mirror], r0: u64, r1: u64) -> Option<MirrorPick> {
    let first = anchors.get((r0 % anchors.len() as u64) as usize)?.clone();
    let mut candidates: Vec<&Mirror> = anchors
        .iter()
        .chain(extras.iter())
        .filter(|(onion, _)| *onion != first.0)
        .collect();
    let other_op: Vec<&&Mirror> = candidates
        .iter()
        .filter(|(_, op)| *op != first.1)
        .collect();
    if !other_op.is_empty() {
        candidates = other_op.into_iter().copied().collect();
    }
    let second = (*candidates.get((r1 % candidates.len() as u64) as usize)?).clone();
    Some(MirrorPick { first, second })
}
