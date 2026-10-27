//! The offer decision (§7.4 step 8) and the staged-rollout bucket (§7.6).

use ghost_client_release::manifest::Release;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::state::{StoredState, Time};
use crate::UpdateError;

type HmacSha256 = Hmac<Sha256>;

/// The rollout bucket input label (§7.4 step 8, exact bytes).
const ROLLOUT_DOMAIN: &[u8] = b"ghost/v1/rollout";

/// A concrete update offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The release's index in the stored manifest.
    pub release_index: usize,
    pub version_code: u32,
    pub version_name: Vec<u8>,
    /// The release record (APK hash/length for the download).
    pub release: Release,
}

/// The offer run's result: an update to stage, or the exact reason there is none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferResult {
    Update(Offer),
    None(UpdateError),
}

/// §7.4 step 8. `rollout_key` is the client's stable per-epoch key for the bucket draw (an
/// input here; its derivation is `:update`'s), `sdk` the device's SDK, `installed_vc` the
/// installed `versionCode`. `today` comes from the same trusted clock as the acceptance.
pub fn offer(
    state: &StoredState,
    today: Time,
    installed_vc: u32,
    sdk: u8,
    rollout_key: &[u8; 32],
) -> OfferResult {
    let day = match today {
        Time::Trusted { day, .. } => day,
        Time::Untrusted => return OfferResult::None(UpdateError::ClockUntrusted),
    };
    let Some(manifest) = &state.manifest else {
        return OfferResult::None(UpdateError::NoManifest);
    };
    // Current means: its root is the trusted root. MC-D32 (the `mutants` feature, host
    // libraries only): the stored manifest stays current after a newer root — offers keep
    // coming from the old root's manifest. The selector's default keeps the shipped rule.
    #[cfg(feature = "mutants")]
    let currency_checked = !crate::mutants::active(crate::mutants::STORED_MANIFEST_STAYS);
    #[cfg(not(feature = "mutants"))]
    let currency_checked = true;
    if currency_checked && manifest.body.root_version != state.trusted_root().body.root_version {
        return OfferResult::None(UpdateError::NoManifest);
    }
    if day > manifest.body.not_after_day {
        return OfferResult::None(UpdateError::Stale);
    }
    if manifest.body.releases.first().is_some_and(|r| r.min_sdk > sdk) {
        return OfferResult::None(UpdateError::SdkUnsupported);
    }
    let flavor1: Vec<(usize, &Release)> = manifest
        .body
        .releases
        .iter()
        .enumerate()
        .filter(|(_, r)| r.flavor == 1)
        .collect();
    if installed_vc < state.floor.version_code {
        // Below the floor: the highest flavor-1 release >= floor, ignoring the rollout bucket.
        let pick = flavor1
            .iter()
            .filter(|(_, r)| r.version_code >= state.floor.version_code)
            .max_by_key(|(_, r)| r.version_code);
        return match pick {
            Some((i, r)) => OfferResult::Update(Offer {
                release_index: *i,
                version_code: r.version_code,
                version_name: r.version_name.clone(),
                release: (*r).clone(),
            }),
            None => OfferResult::None(UpdateError::Unsupported),
        };
    }
    // MC-D16 (the `mutants` feature, host libraries only): a release at the installed
    // versionCode is offered — `>=` replaces `>`. The selector's default keeps the shipped rule.
    #[cfg(feature = "mutants")]
    let above_installed: fn(u32, u32) -> bool = if crate::mutants::active(crate::mutants::OFFER_AT_OR_BELOW) {
        |vc: u32, installed: u32| vc >= installed
    } else {
        |vc: u32, installed: u32| vc > installed
    };
    #[cfg(not(feature = "mutants"))]
    let above_installed: fn(u32, u32) -> bool = |vc, installed| vc > installed;
    let pick = flavor1
        .iter()
        .filter(|(_, r)| {
            above_installed(r.version_code, installed_vc)
                && r.rollout_permille > 0
                && bucket(rollout_key, &r.apk_sha256, &r.rollout_salt) < r.rollout_permille
        })
        .max_by_key(|(_, r)| r.version_code);
    match pick {
        Some((i, r)) => OfferResult::Update(Offer {
            release_index: *i,
            version_code: r.version_code,
            version_name: r.version_name.clone(),
            release: (*r).clone(),
        }),
        None => OfferResult::None(UpdateError::UpToDate),
    }
}

/// `⌊1000 · BE64(HMAC-SHA256(rollout_key, "ghost/v1/rollout" ‖ apk_sha256 ‖ rollout_salt)[0..8]) / 2^64⌋`
/// (§7.4 step 8 — the APK's hash in the input makes the bucket per release even if a salt were
/// ever reused).
pub fn bucket(rollout_key: &[u8; 32], apk_sha256: &[u8; 32], rollout_salt: &[u8; 16]) -> u16 {
    let mut mac = HmacSha256::new_from_slice(rollout_key).expect("HMAC takes any key length");
    mac.update(ROLLOUT_DOMAIN);
    mac.update(apk_sha256);
    mac.update(rollout_salt);
    let out = mac.finalize().into_bytes();
    let be = u64::from_be_bytes(out[..8].try_into().expect("8 bytes"));
    ((1000u128 * be as u128) / (1u128 << 64)) as u16
}
