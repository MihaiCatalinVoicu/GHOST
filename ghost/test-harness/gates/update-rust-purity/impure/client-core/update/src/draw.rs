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
    // MC-D19 (the `mutants` feature, host libraries only): one mirror per run — the second
    // pick repeats the first. The selector's default keeps the two-mirror draw.
    #[cfg(feature = "mutants")]
    if crate::mutants::active(crate::mutants::ONE_MIRROR_PER_RUN) {
        return Some(MirrorPick { first: first.clone(), second: first });
    }
    // MC-D24 (the `mutants` feature, host libraries only): both mirrors come from the
    // manifest's extras — no anchor mirror in the run. The selector's default keeps the
    // anchors in the draw.
    #[cfg(feature = "mutants")]
    let pool: Vec<&Mirror> = if crate::mutants::active(crate::mutants::NO_ANCHOR_MIRROR) {
        extras.iter().collect()
    } else {
        anchors.iter().chain(extras.iter()).collect()
    };
    #[cfg(not(feature = "mutants"))]
    let pool: Vec<&Mirror> = anchors.iter().chain(extras.iter()).collect();
    let mut candidates: Vec<&Mirror> = pool
        .into_iter()
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

/// The whole §7.8 draw as one call: anchors from the trusted root, extras from the stored
/// manifest when it is fresh and current, and — on `NO_CHANNEL` — the embedded chain's anchor
/// mirrors join the draw. `draw` is the run's 32 bytes from `RandomSources.updateRun`.
pub fn draw_for_run(
    state: &crate::state::StoredState,
    embedded: &ghost_client_release::chain::GHRC,
    no_channel: bool,
    today: u32,
    draw: &[u8; 32],
) -> Option<MirrorPick> {
    let r0 = u64::from_be_bytes(draw[..8].try_into().ok()?);
    let r1 = u64::from_be_bytes(draw[8..16].try_into().ok()?);
    let anchors: Vec<Mirror> = state
        .trusted_root()
        .body
        .anchor_mirrors
        .iter()
        .map(|a| (a.onion.clone(), a.operator_id))
        .collect();
    let mut extras: Vec<Mirror> = Vec::new();
    if let Some(m) = &state.manifest {
        let fresh_and_current = m.body.root_version == state.trusted_root().body.root_version
            && today <= m.body.not_after_day;
        if fresh_and_current {
            extras.extend(m.body.extra_mirrors.iter().map(|(o, op)| (o.clone(), *op)));
        }
    }
    if no_channel {
        let newest = embedded.roots.last()?;
        extras.extend(
            newest
                .body
                .anchor_mirrors
                .iter()
                .map(|a| (a.onion.clone(), a.operator_id)),
        );
    }
    draw_mirrors(&anchors, &extras, r0, r1)
}
