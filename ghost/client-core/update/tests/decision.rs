//! Integration tests of the §7.4 decision: acceptance, refusals, epoch, offer and draw.
//! Fixtures come from `ghost-release-ops`' builders (software keys, synthetic single-leaf
//! proofs) — the same documents a stagenet mirror serves.

use std::path::{Path, PathBuf};

use ghost_client_update::offer::{bucket, offer, OfferResult};
use ghost_client_update::{
    ChannelStatus, Pair, StoredState, Time, UpdateError, accept_bundle, start_epoch,
};

const NOW: u64 = 1_900_000_000;
const DAY: u32 = (NOW / 86_400) as u32;

fn onion(seed: &str) -> String {
    use sha2::Digest as _;
    use sha3::Digest;
    let pk: [u8; 32] = sha2::Sha256::digest(seed.as_bytes()).into();
    let mut h = sha3::Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pk);
    h.update([3u8]);
    let sum = h.finalize();
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(&pk);
    raw.extend_from_slice(&sum[..2]);
    raw.push(3);
    const ALPH: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(56);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for b in &raw {
        acc = (acc << 8) | u32::from(*b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPH[((acc >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPH[((acc << (5 - nbits)) & 31) as usize] as char);
    }
    format!("{out}.onion:443")
}

fn hex16(byte: u8) -> String {
    hex::encode([byte; 16])
}

fn write(path: &Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Builds a whole stagenet world: keys, `n_roots` roots (versions 1..=n_roots, same root
/// keyset, so each verifies under its predecessor) and the chain.
struct World {
    dir: tempfile::TempDir,
    keys: PathBuf,
    roots: Vec<PathBuf>,
    chain: PathBuf,
}

impl World {
    fn new(n_roots: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        ghost_release_ops::build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:2")
            .unwrap();
        let oa = onion("anchor-a");
        let ob = onion("anchor-b");
        let (first, second) = if oa < ob { (oa, ob) } else { (ob, oa) };
        let mut roots = Vec::new();
        for v in 1..=n_roots {
            let cfg = dir.path().join(format!("root-{v}.toml"));
            write(
                &cfg,
                format!(
                    r#"network = 2
version = {v}
apk_signers = ["apk-1"]
witnesses = ["witness-1", "witness-2"]
quorum = 1
[root]
keys = ["root-1", "root-2"]
threshold = 2
[release]
keys = ["release-1"]
threshold = 1
[attest]
keys = ["attest-1"]
threshold = 1
[[logs]]
key = "log-1"
origin = "stg-log-1"
[[anchor_mirrors]]
onion = "{first}"
operator = "{}"
[[anchor_mirrors]]
onion = "{second}"
operator = "{}"
"#,
                    hex16(0x11),
                    hex16(0x22)
                ),
            );
            let out = dir.path().join(format!("root-{v}.ghrt"));
            ghost_release_ops::build::root_build(&cfg, &keys, &out).unwrap();
            roots.push(out);
        }
        let roots_dir = dir.path().join("roots");
        std::fs::create_dir_all(&roots_dir).unwrap();
        for r in &roots {
            std::fs::copy(r, roots_dir.join(r.file_name().unwrap())).unwrap();
        }
        let chain = dir.path().join("chain.ghrc");
        ghost_release_ops::build::chain_build(2, &roots_dir, &chain).unwrap();
        World { dir, keys, roots, chain }
    }

    /// Writes the release files and a manifest source for `version_code`/`seq` under
    /// `root_idx`, builds and signs it. `stale` makes it already expired.
    fn manifest(&self, version_code: u32, seq: u64, root_idx: usize, stale: bool) -> PathBuf {
        let rel = self.dir.path().join(format!("rel-{version_code}-{seq}"));
        std::fs::create_dir_all(&rel).unwrap();
        write(&rel.join("app.apk"), format!("signed-apk-v{version_code}-{seq}"));
        write(&rel.join("app-unsigned.apk"), format!("unsigned-core-v{version_code}-{seq}"));
        write(&rel.join("escrow.tar.gz"), format!("escrow-v{version_code}-{seq}"));
        write(&rel.join("es.json"), format!("es-v{version_code}-{seq}"));
        let (issued, not_after) = if stale {
            (DAY - 40, DAY - 10)
        } else {
            (DAY, DAY + 30)
        };
        let src = self.dir.path().join(format!("m-{version_code}-{seq}.toml"));
        write(
            &src,
            format!(
                r#"seq = {seq}
issued_day = {issued}
not_after_day = {not_after}
floor_version_code = 0
[[release]]
version_code = {version_code}
version_name = "0.9.0-stg{version_code}"
min_sdk = 29
anchor_root = 1
wire_changing = false
apk = "{apk}"
unsigned = "{unsigned}"
rollout_permille = 1000
rollout_salt = "{salt}"
commit = "{commit}"
es_seq = 2957
es_file = "{es}"
[[release.artifacts]]
kind = 16
file = "{escrow}"
"#,
                apk = rel.join("app.apk").display(),
                unsigned = rel.join("app-unsigned.apk").display(),
                salt = hex16(0x33),
                commit = "ab".repeat(20),
                es = rel.join("es.json").display(),
                escrow = rel.join("escrow.tar.gz").display(),
            ),
        );
        let m = self.dir.path().join(format!("m-{version_code}-{seq}.ghrm"));
        ghost_release_ops::build::manifest_build(
            &src,
            &self.roots[root_idx],
            &self.keys,
            &["attest-1".to_string()],
            None,
            &m,
        )
        .unwrap();
        m
    }

    fn proof(&self, file: &Path, name: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        ghost_release_ops::build::proof_build(
            file,
            0,
            "log-1",
            "release-1",
            &["witness-1".to_string(), "witness-2".to_string()],
            Some(NOW),
            &self.keys,
            &p,
        )
        .unwrap();
        p
    }

    /// Assembles a bundle over the whole chain: one proof per chain root after the first (the
    /// bundle grammar requires them even for roots the client already trusts; the walk only
    /// consumes those above its trusted version).
    fn bundle(&self, manifest: &Path) -> Vec<u8> {
        self.bundle_on(manifest, &self.chain)
    }

    /// A chain of only the first `n` roots (a bundle as an older client saw it).
    fn chain_upto(&self, n: usize) -> PathBuf {
        let dir = self.dir.path().join(format!("chain-dir-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        for r in &self.roots[..n] {
            std::fs::copy(r, dir.join(r.file_name().unwrap())).unwrap();
        }
        let chain = self.dir.path().join(format!("chain-{n}.ghrc"));
        ghost_release_ops::build::chain_build(2, &dir, &chain).unwrap();
        chain
    }

    /// Assembles a bundle over an explicit chain (one proof per chain root after the first).
    fn bundle_on(&self, manifest: &Path, chain: &Path) -> Vec<u8> {
        let nproofs = ghost_client_release::chain::GHRC::parse(&std::fs::read(chain).unwrap())
            .unwrap()
            .roots
            .len()
            - 1;
        let mp = self.proof(manifest, "bundle-manifest.ghrp");
        let mut proofs = Vec::new();
        for r in &self.roots[1..=nproofs] {
            proofs.push(self.proof(r, &format!("{}.ghrp", r.file_name().unwrap().to_string_lossy())));
        }
        let b = self.dir.path().join("bundle.ghrb");
        ghost_release_ops::build::bundle(chain, &proofs, manifest, &mp, &b).unwrap();
        std::fs::read(&b).unwrap()
    }
}

fn fresh_state(w: &World, installed_vc: u32) -> StoredState {
    let root = ghost_client_release::root::GHRT::parse(&std::fs::read(&w.roots[0]).unwrap()).unwrap();
    start_epoch(installed_vc, vec![root], None)
}

fn trusted() -> Time {
    Time::Trusted { day: DAY, now_secs: NOW }
}

#[test]
fn accept_offer_and_unchanged() {
    let w = World::new(1);
    let state = fresh_state(&w, 1);
    let m = w.manifest(2, 1, 0, false);
    let bundle = w.bundle(&m);
    let out = accept_bundle(&bundle, &state, 2, trusted()).unwrap();
    assert_eq!(out.refused, None);
    assert_eq!(out.status, ChannelStatus::Current);
    assert!(!out.changes.is_empty());
    assert_eq!(out.state.pair.manifest_seq, 1);

    // The offer: installed 1 < release 2 at permille 1000.
    match offer(&out.state, trusted(), 1, 29, &[7u8; 32]) {
        OfferResult::Update(o) => assert_eq!(o.version_code, 2),
        other => panic!("expected an offer, got {other:?}"),
    }
    assert_eq!(
        offer(&out.state, trusted(), 2, 29, &[7u8; 32]),
        OfferResult::None(UpdateError::UpToDate)
    );

    // Re-accepting the identical bundle is UNCHANGED and changes nothing.
    let out2 = accept_bundle(&bundle, &out.state, 2, trusted()).unwrap();
    assert_eq!(out2.refused, Some(UpdateError::Unchanged));
    assert_eq!(out2.state, out.state);
}

#[test]
fn rollback_conflict_and_stale() {
    let w = World::new(1);
    let state = fresh_state(&w, 1);
    let m2 = w.manifest(2, 2, 0, false);
    let out = accept_bundle(&w.bundle(&m2), &state, 2, trusted()).unwrap();
    assert_eq!(out.refused, None);
    let m1 = w.manifest(2, 1, 0, false);
    let out = accept_bundle(&w.bundle(&m1), &out.state, 2, trusted()).unwrap();
    assert_eq!(out.refused, Some(UpdateError::Rollback));

    // Same pair, different hash: CONFLICT, the flag is kept, nothing else changes.
    let w2 = World::new(1);
    let state2 = fresh_state(&w2, 1);
    let a = w2.manifest(2, 1, 0, false);
    let out_a = accept_bundle(&w2.bundle(&a), &state2, 2, trusted()).unwrap();
    let b = w2.manifest(3, 1, 0, false);
    let out_b = accept_bundle(&w2.bundle(&b), &out_a.state, 2, trusted()).unwrap();
    assert_eq!(out_b.refused, Some(UpdateError::Conflict));
    assert!(out_b.state.conflict);
    assert_eq!(out_b.state.manifest_sha256, out_a.state.manifest_sha256);

    // Expired manifest: accepted as a fact, STALE, no directory changes, no offer.
    let stale = w2.manifest(4, 999, 0, true);
    let out_s = accept_bundle(&w2.bundle(&stale), &out_a.state, 2, trusted()).unwrap();
    assert_eq!(out_s.refused, None);
    assert_eq!(out_s.status, ChannelStatus::Stale);
    assert!(out_s.changes.is_empty());
    assert_eq!(
        offer(&out_s.state, trusted(), 1, 29, &[7u8; 32]),
        OfferResult::None(UpdateError::Stale)
    );
}

#[test]
fn clock_network_floor_and_malformed() {
    let w = World::new(1);
    let state = fresh_state(&w, 1);
    let m = w.manifest(2, 1, 0, false);
    let bundle = w.bundle(&m);

    // Untrusted clock: nothing changes, CLOCK_UNTRUSTED before any parse.
    let err = accept_bundle(&bundle, &state, 2, Time::Untrusted).unwrap_err();
    assert_eq!(err, UpdateError::ClockUntrusted);

    // Wrong network.
    let err = accept_bundle(&bundle, &state, 1, trusted()).unwrap_err();
    assert_eq!(err, UpdateError::WrongNetwork);

    // Floor above every attested release: FLOOR_INVALID, the manifest is refused. The ops
    // builder refuses the naive fixture on its own, so this one is crafted at byte level: a
    // valid manifest whose only release has an EMPTY attestation block (sigblock_or_empty,
    // §4.5) and floor = its version_code. Parse accepts (floor <= lowest release); the client
    // computes the attested maximum over the empty block (attest threshold is 1) and refuses.
    let m_ok = w.manifest(2, 5, 0, false);
    let parsed = ghost_client_release::manifest::GHRM::parse(&std::fs::read(&m_ok).unwrap()).unwrap();
    let mut body = parsed.body.clone();
    body.floor_version_code = body.releases[0].version_code;
    let empty_at = ghost_client_release::SigBlock { entries: vec![] };
    let body_bytes = {
        let tmp = ghost_client_release::manifest::GHRM {
            body: body.clone(),
            attestations: vec![empty_at.clone()],
            block: ghost_client_release::SigBlock { entries: vec![] },
        };
        tmp.body_bytes()
    };
    let release_sk = {
        let seed = hex::decode(
            std::fs::read_to_string(w.keys.join("release-1.hex")).unwrap().trim(),
        )
        .unwrap();
        ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap())
    };
    let block = ghost_client_release::SigBlock {
        entries: vec![ghost_client_release::statement::sign_entry(
            &release_sk,
            ghost_client_release::StatementType::ReleaseManifest,
            2,
            &body_bytes,
        )],
    };
    let tampered = ghost_client_release::manifest::GHRM {
        body,
        attestations: vec![empty_at],
        block,
    };
    let mf = w.dir.path().join("m-floor.ghrm");
    std::fs::write(&mf, tampered.body_bytes_with_block()).unwrap();
    let out = accept_bundle(&w.bundle(&mf), &state, 2, trusted()).unwrap();
    assert_eq!(out.refused, Some(UpdateError::FloorInvalid));

    // An extra mirror equal to an anchor mirror: MALFORMED.
    let anchors: Vec<Vec<u8>> = {
        let doc = ghost_client_release::root::GHRT::parse(&std::fs::read(&w.roots[0]).unwrap()).unwrap();
        doc.body.anchor_mirrors.iter().map(|a| a.onion.clone()).collect()
    };
    let src2 = w.dir.path().join("m-mirror.toml");
    let mut text = std::fs::read_to_string(w.dir.path().join("m-2-1.toml")).unwrap();
    text.push_str(&format!(
        "[[mirror]]\nonion = \"{}\"\noperator = \"{}\"\n",
        String::from_utf8(anchors[0].clone()).unwrap(),
        hex16(0x44)
    ));
    std::fs::write(&src2, &text).unwrap();
    let mm = w.dir.path().join("m-mirror.ghrm");
    ghost_release_ops::build::manifest_build(&src2, &w.roots[0], &w.keys, &["attest-1".to_string()], None, &mm).unwrap();
    let out = accept_bundle(&w.bundle(&mm), &state, 2, trusted()).unwrap();
    assert_eq!(out.refused, Some(UpdateError::Malformed));
}

#[test]
fn epoch_rules() {
    let w = World::new(2);
    let root1 = ghost_client_release::root::GHRT::parse(&std::fs::read(&w.roots[0]).unwrap()).unwrap();
    let root2 = ghost_client_release::root::GHRT::parse(&std::fs::read(&w.roots[1]).unwrap()).unwrap();

    // Same installed version: the stored state passes through untouched.
    let s = start_epoch(7, vec![root1.clone()], None);
    let s2 = start_epoch(7, vec![root1.clone()], Some(s.clone()));
    assert_eq!(s, s2);

    // Newer embedded root, same lineage: the chain extends to it.
    let s3 = start_epoch(8, vec![root1.clone(), root2.clone()], Some(s.clone()));
    assert_eq!(s3.trusted_root().body.root_version, 2);

    // A chain with neither root in common: a recovery APK starts a new epoch.
    let w_other = World::new(1);
    let foreign = ghost_client_release::root::GHRT::parse(&std::fs::read(&w_other.roots[0]).unwrap()).unwrap();
    let s4 = start_epoch(9, vec![foreign.clone()], Some(s3.clone()));
    assert_eq!(s4.epoch.version_code, 9);
    assert_eq!(s4.chain.len(), 1);
    assert!(s4.manifest.is_none());
    assert_eq!(s4.floor.version_code, 0);
}

#[test]
fn root_adoption_and_not_current_manifest() {
    let w = World::new(2);
    let state = fresh_state(&w, 1);
    // Bundle whose manifest sits under root v2; the walk must adopt v2 through its proof.
    let m = w.manifest(2, 1, 1, false);
    let out = accept_bundle(&w.bundle(&m), &state, 2, trusted()).unwrap();
    assert_eq!(out.refused, None);
    assert_eq!(out.state.trusted_root().body.root_version, 2);
    assert_eq!(out.state.pair, Pair { root_version: 2, manifest_seq: 1 });

    // Adopt v2 through a bundle whose manifest still names v1: the root is persisted, the
    // manifest is refused with ROOT_MISMATCH, and the stored v1 manifest is not current.
    let w2 = World::new(2);
    let state2 = fresh_state(&w2, 1);
    let old = w2.manifest(2, 1, 0, false);
    // The first bundle is what an older client saw: only root v1 in the chain.
    let chain1 = w2.chain_upto(1);
    let out_old = accept_bundle(&w2.bundle_on(&old, &chain1), &state2, 2, trusted()).unwrap();
    assert_eq!(out_old.refused, None);
    assert_eq!(out_old.state.trusted_root().body.root_version, 1);
    let mixed_manifest = w2.manifest(3, 2, 0, false); // still under root v1
    let out_mixed = accept_bundle(&w2.bundle(&mixed_manifest), &out_old.state, 2, trusted()).unwrap();
    assert_eq!(out_mixed.refused, Some(UpdateError::RootMismatch));
    assert_eq!(out_mixed.state.trusted_root().body.root_version, 2);
    assert!(out_mixed.state.manifest.is_some()); // the stored v1 manifest stays stored…
    assert_eq!(
        offer(&out_mixed.state, trusted(), 1, 29, &[7u8; 32]),
        OfferResult::None(UpdateError::NoManifest) // …but it is not current
    );
}

#[test]
fn rollout_bucket_halt_and_draw() {
    // The bucket is deterministic and in range, and the input binds the APK hash.
    let key = [3u8; 32];
    let b1 = bucket(&key, &[1u8; 32], &[2u8; 16]);
    assert_eq!(b1, bucket(&key, &[1u8; 32], &[2u8; 16]));
    assert!(b1 < 1000);
    assert_ne!(b1, bucket(&key, &[9u8; 32], &[2u8; 16]));

    // A permille-0 release is a halt: no offer even when a newer version exists.
    let w = World::new(1);
    let state = fresh_state(&w, 1);
    let rel = w.dir.path().join("rel-halt");
    std::fs::create_dir_all(&rel).unwrap();
    write(&rel.join("app.apk"), "apk");
    write(&rel.join("app-unsigned.apk"), "core");
    write(&rel.join("escrow.tar.gz"), "escrow");
    write(&rel.join("es.json"), "es");
    let src = w.dir.path().join("halt.toml");
    write(
        &src,
        format!(
            r#"seq = 1
issued_day = {DAY}
not_after_day = {DAY_AFTER}
floor_version_code = 0
[[release]]
version_code = 5
version_name = "0.9.0-halt"
min_sdk = 29
anchor_root = 1
wire_changing = false
apk = "{apk}"
unsigned = "{unsigned}"
rollout_permille = 0
rollout_salt = "{salt}"
commit = "{commit}"
es_seq = 2957
es_file = "{es}"
[[release.artifacts]]
kind = 16
file = "{escrow}"
"#,
            DAY_AFTER = DAY + 30,
            apk = rel.join("app.apk").display(),
            unsigned = rel.join("app-unsigned.apk").display(),
            salt = hex16(0x33),
            commit = "ab".repeat(20),
            es = rel.join("es.json").display(),
            escrow = rel.join("escrow.tar.gz").display(),
        ),
    );
    let m = w.dir.path().join("halt.ghrm");
    ghost_release_ops::build::manifest_build(&src, &w.roots[0], &w.keys, &["attest-1".to_string()], None, &m).unwrap();
    let out = accept_bundle(&w.bundle(&m), &state, 2, trusted()).unwrap();
    assert_eq!(
        offer(&out.state, trusted(), 1, 29, &[7u8; 32]),
        OfferResult::None(UpdateError::UpToDate)
    );

    // The draw: first from the anchors; the second prefers another operator.
    let anchors = vec![
        (onion("m-a").into_bytes(), [1u8; 16]),
        (onion("m-b").into_bytes(), [2u8; 16]),
    ];
    let extras = vec![(onion("m-c").into_bytes(), [1u8; 16])];
    let pick = ghost_client_update::draw::draw_mirrors(&anchors, &extras, 0, 0).unwrap();
    assert_eq!(pick.first, anchors[0]);
    assert_ne!(pick.second.1, pick.first.1);
    assert_eq!(pick, ghost_client_update::draw::draw_mirrors(&anchors, &extras, 0, 0).unwrap());
}
