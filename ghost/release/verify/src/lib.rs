//! `ghost-verify` (Phase 14 design §9.1): the public verifier. The `apk` decision is exactly the
//! client's §7.4 run, offline: the bundle is accepted from the anchor root (the chain and the log
//! proof are verified, not trusted), the manifest's offer and attestation are checked, and the
//! APK itself passes the §7.4 steps 9–10 for each SDK class the caller names (29–32 and 33+ by
//! default). The vocabulary is fixed: `VERIFIED …` or `REFUSED <code>`.
//!
//! What the verifier deliberately is not: it does not check the rollout bucket (a per-device
//! draw, not a property of the APK), and it does not fetch anything (`fetch` lands later).

pub mod zip;

use ghost_client_release::manifest::ArtifactKind;
use ghost_client_release::root::GHRT;
use ghost_client_update::UpdateError;
use ghost_client_update::apk::check_apk;
use ghost_client_update::{Time, accept_bundle};
use sha2::{Digest, Sha256};

pub const SDK_CLASSES: [u8; 2] = [29, 33];

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The answer of one `apk` verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApkVerdict {
    /// The bundle accepted from the anchor, and the APK is the attested one for its release on
    /// every named SDK class.
    Verified {
        version_name: Vec<u8>,
        version_code: u32,
        manifest_seq: u64,
        log_origin: Vec<u8>,
        cosigned: usize,
        witnesses: usize,
        attested: usize,
        attest_threshold: usize,
        signer: [u8; 32],
        sdks: Vec<u8>,
    },
    /// The exact §7.4 code that refused it.
    Refused(UpdateError),
}

/// §7.4 offline against the anchor root. `day`/`now` pin the verification moment (an auditor
/// passes the manifest's own window). `sdks` empty = both classes (29 for the 29–32 class, 33
/// for 33+).
pub fn apk(
    bundle: &[u8],
    apk_file: &[u8],
    anchor: &GHRT,
    day: u32,
    now: u64,
    sdks: &[u8],
) -> ApkVerdict {
    let network = anchor.body.network as u8;
    // The verifier starts a fresh trust epoch at the anchor: stored chain = [anchor], no
    // manifest, pair (anchor.version, 0) — exactly a client's first start on this lineage.
    let state = ghost_client_update::start_epoch(
        1,
        vec![anchor.clone()],
        None,
    );
    let accepted = match accept_bundle(bundle, &state, network, Time::Trusted { day, now_secs: now }) {
        Ok(outcome) if outcome.refused.is_none() => outcome.state,
        Ok(outcome) => return ApkVerdict::Refused(outcome.refused.unwrap_or(UpdateError::Malformed)),
        Err(e) => return ApkVerdict::Refused(e),
    };
    let manifest = match &accepted.manifest {
        Some(m) => m.clone(),
        None => return ApkVerdict::Refused(UpdateError::NoManifest),
    };
    // The release this APK claims: its whole-file SHA-256 must name a release of the manifest.
    let claim = sha256(apk_file);
    let index = match manifest
        .body
        .releases
        .iter()
        .position(|r| r.apk_sha256 == claim)
    {
        Some(i) => i,
        None => return ApkVerdict::Refused(UpdateError::ApkHash),
    };
    let release = &manifest.body.releases[index];
    let trusted_root = accepted.trusted_root();
    let classes: Vec<u8> = if sdks.is_empty() { SDK_CLASSES.to_vec() } else { sdks.to_vec() };
    for sdk in &classes {
        if let Err(e) = check_apk(apk_file, &manifest, index, trusted_root, *sdk) {
            return ApkVerdict::Refused(e);
        }
    }
    let proof = match &accepted.manifest_proof {
        Some(p) => p,
        None => return ApkVerdict::Refused(UpdateError::LogProofInvalid),
    };
    let log_origin = trusted_root
        .body
        .logs
        .get(proof.log as usize)
        .map(|l| l.origin.clone())
        .unwrap_or_default();
    // The signer the platform uses on the newest class: the digest the client would pin.
    let signer = match ghost_client_update::apk::signer_digest_of(apk_file, *classes.last().unwrap_or(&33)) {
        Ok(d) => d,
        Err(e) => return ApkVerdict::Refused(e),
    };
    let attested = manifest
        .attestations
        .get(index)
        .map(|at| {
            at.entries
                .iter()
                .filter(|e| trusted_root.body.attest.keys.iter().any(|k| ghost_client_release::key_id(k) == e.key_id))
                .count()
        })
        .unwrap_or(0);
    ApkVerdict::Verified {
        version_name: release.version_name.clone(),
        version_code: release.version_code,
        manifest_seq: manifest.body.manifest_seq,
        log_origin,
        cosigned: proof.cosignatures.len(),
        witnesses: trusted_root.body.witnesses.len(),
        attested,
        attest_threshold: trusted_root.body.attest.threshold,
        signer,
        sdks: classes,
    }
}

/// The fixed vocabulary line (§9.1).
pub fn apk_line(v: &ApkVerdict) -> String {
    match v {
        ApkVerdict::Verified {
            version_name,
            version_code,
            manifest_seq,
            log_origin,
            cosigned,
            witnesses,
            attested,
            attest_threshold,
            signer,
            sdks,
        } => format!(
            "VERIFIED version={} version_code={} manifest_seq={} log={} cosigned={}/{} attested={}/{} signer={} sdk={}",
            String::from_utf8_lossy(version_name),
            version_code,
            manifest_seq,
            String::from_utf8_lossy(log_origin),
            cosigned,
            witnesses,
            attested,
            attest_threshold,
            hex::encode(signer),
            sdks.iter().map(u8::to_string).collect::<Vec<_>>().join(","),
        ),
        ApkVerdict::Refused(code) => format!("REFUSED {code}"),
    }
}

/// One native library of the APK, verified against the release's artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibLine {
    pub abi: String,
    pub name: String,
    pub sha256: [u8; 32],
    /// `VERIFIED` (the digest is the release's artifact of the ABI's kind), `MISMATCH` (an
    /// artifact of that kind exists but with another digest), `UNKNOWN` (the release lists no
    /// artifact for the ABI).
    pub status: &'static str,
}

/// `libs --apk`: the native libraries with their decompressed hashes against the release the APK
/// claims (found by its whole-file hash in the manifest, as in [apk]).
pub fn libs(bundle: &[u8], apk_file: &[u8], anchor: &GHRT, day: u32, now: u64) -> Result<Vec<LibLine>, UpdateError> {
    let accepted = match accept_bundle(bundle, &ghost_client_update::start_epoch(1, vec![anchor.clone()], None), anchor.body.network as u8, Time::Trusted { day, now_secs: now }) {
        Ok(outcome) if outcome.refused.is_none() => outcome.state,
        Ok(outcome) => return Err(outcome.refused.unwrap_or(UpdateError::Malformed)),
        Err(e) => return Err(e),
    };
    let manifest = accepted.manifest.ok_or(UpdateError::NoManifest)?;
    let claim = sha256(apk_file);
    let index = manifest.body.releases.iter().position(|r| r.apk_sha256 == claim).ok_or(UpdateError::ApkHash)?;
    let release = &manifest.body.releases[index];
    let entries = zip::entries(apk_file).map_err(|_| UpdateError::ApkLayout)?;
    let mut out = Vec::new();
    for e in &entries {
        if !e.name.starts_with(b"lib/") || !e.name.ends_with(b".so") {
            continue;
        }
        let name = String::from_utf8_lossy(&e.name).to_string();
        let abi = name.split('/').nth(1).unwrap_or("").to_string();
        let kind = match abi.as_str() {
            "arm64-v8a" => Some(ArtifactKind::NativeArm64),
            "x86_64" => Some(ArtifactKind::NativeX86_64),
            _ => None,
        };
        let data = zip::inflate(e).map_err(|_| UpdateError::ApkLayout)?;
        let digest = sha256(&data);
        let status = match kind {
            None => "UNKNOWN",
            Some(k) => match release.artifacts.iter().find(|(ak, _, _)| *ak == k) {
                None => "UNKNOWN",
                Some((_, sha, _)) if *sha == digest => "VERIFIED",
                Some(_) => "MISMATCH",
            },
        };
        out.push(LibLine { abi, name, sha256: digest, status });
    }
    Ok(out)
}

/// The `libs` vocabulary line.
pub fn libs_line(l: &LibLine) -> String {
    format!("LIB {} sha256={} status={}", l.name, hex::encode(l.sha256), l.status)
}

/// The `operator` verdict: an operator binary against the newest verified manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorVerdict {
    /// The binary's SHA-256 is the manifest's artifact of the named kind.
    Verified { kind: &'static str, sha256: [u8; 32] },
    /// The manifest lists the kind with another digest.
    Mismatch { kind: &'static str, sha256: [u8; 32] },
    /// The manifest lists no artifact of the kind.
    Unknown { kind: &'static str, sha256: [u8; 32] },
    /// The bundle did not verify: the exact code.
    Refused(UpdateError),
}

/// `operator --binary <file> --kind relay|issuer`: the binary's hash against the manifest's
/// artifact kinds 5 (`relay`) and 6 (`issuer`). The manifest comes from the verified bundle,
/// so the answer rides the same chain and log proof as everything else.
pub fn operator(bundle: &[u8], binary: &[u8], anchor: &GHRT, kind: &str, day: u32, now: u64) -> OperatorVerdict {
    let accepted = match accept_bundle(
        bundle,
        &ghost_client_update::start_epoch(1, vec![anchor.clone()], None),
        anchor.body.network as u8,
        Time::Trusted { day, now_secs: now },
    ) {
        Ok(outcome) if outcome.refused.is_none() => outcome.state,
        Ok(outcome) => return OperatorVerdict::Refused(outcome.refused.unwrap_or(UpdateError::Malformed)),
        Err(e) => return OperatorVerdict::Refused(e),
    };
    let manifest = match accepted.manifest {
        Some(m) => m,
        None => return OperatorVerdict::Refused(UpdateError::NoManifest),
    };
    let artifact = match kind {
        "relay" => Some(ArtifactKind::Relay),
        "issuer" => Some(ArtifactKind::Issuer),
        _ => None,
    };
    let digest = sha256(binary);
    let label: &'static str = match kind {
        "relay" => "relay",
        "issuer" => "issuer",
        _ => "unknown",
    };
    match artifact.and_then(|k| {
        manifest
            .body
            .releases
            .iter()
            .flat_map(|r| r.artifacts.iter())
            .find(|(ak, _, _)| *ak == k)
    }) {
        Some((_, sha, _)) if *sha == digest => OperatorVerdict::Verified { kind: label, sha256: digest },
        Some(_) => OperatorVerdict::Mismatch { kind: label, sha256: digest },
        None => OperatorVerdict::Unknown { kind: label, sha256: digest },
    }
}

pub fn operator_line(v: &OperatorVerdict) -> String {
    match v {
        OperatorVerdict::Verified { kind, sha256 } => format!("OPERATOR {kind} sha256={} VERIFIED", hex::encode(sha256)),
        OperatorVerdict::Mismatch { kind, sha256 } => format!("OPERATOR {kind} sha256={} MISMATCH", hex::encode(sha256)),
        OperatorVerdict::Unknown { kind, sha256 } => format!("OPERATOR {kind} sha256={} UNKNOWN", hex::encode(sha256)),
        OperatorVerdict::Refused(code) => format!("REFUSED {code}"),
    }
}
