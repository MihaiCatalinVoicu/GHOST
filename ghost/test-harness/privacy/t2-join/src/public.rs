//! Z, the public context (Phase 8 design §1.2): the ES (keys, proofs, prices, constants, slot
//! table), the grid, slot boundaries, protocol constants and labels, and the values every client
//! derives from them alone (key ids, challenge digests, redemption contexts, capability expiries).
//! W, the set J1–J4 and T2b never count as joins, is Z with all substrings (`values::Public`).

use ghost_entitlement::challenge::redemption_context;
use ghost_entitlement::grid::{epoch_id, week_start, LATE_WINDOW_SECS};
use ghost_entitlement::onion::Onion;
use ghost_entitlement::{Kind, Schedule};

use crate::transforms::LABELS;
use crate::values::Public;

/// Z of `schedule`, plus `extra` (the signed schedule bytes and any constant a view carries).
pub fn public_context(schedule: &Schedule, extra: &[Vec<u8>]) -> Public {
    let mut z: Vec<Vec<u8>> = extra.to_vec();
    for key in schedule.keys() {
        z.push(key.public_key.to_spki());
        z.push(key.public_key.n_bytes().to_vec());
        z.push(key.public_key.e_bytes().to_vec());
        z.push(key.key_id.to_vec());
        z.push(redemption_context(key.kind, key.epoch).to_vec());
        z.push(epoch_id(key.epoch).to_vec());
        match key.kind {
            Kind::Access => {
                for slot in schedule.slots_in_week(key.epoch) {
                    if let Ok(d) = schedule.challenge_digest(key.kind, key.epoch, Some(slot)) {
                        z.push(d.to_vec());
                    }
                }
                let expiry = week_start(key.epoch + 1) + LATE_WINDOW_SECS;
                z.push(expiry.to_be_bytes().to_vec());
            }
            Kind::Invite | Kind::Credit => {
                if let Ok(d) = schedule.challenge_digest(key.kind, key.epoch, None) {
                    z.push(d.to_vec());
                }
            }
        }
    }
    let content = schedule.content();
    for s in &content.slots {
        z.push(s.onion.as_bytes().to_vec());
        if let Ok(o) = Onion::parse(&s.onion) {
            z.push(o.pubkey.to_vec());
        }
    }
    z.push(content.issuer_name.as_bytes().to_vec());
    z.push(content.issuer_onion.as_bytes().to_vec());
    for p in &content.prices {
        z.push(p.pack_price_atomic.to_be_bytes().to_vec());
        z.push((p.pack_price_atomic / 10).to_be_bytes().to_vec());
    }
    z.push(
        content
            .constants
            .capability_quota_bytes
            .to_be_bytes()
            .to_vec(),
    );
    for l in LABELS {
        z.push(l.as_bytes().to_vec());
    }
    z.retain(|v| !v.is_empty());
    Public::new(z)
}
