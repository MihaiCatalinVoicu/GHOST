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
        Self::new_signers(n_roots, &[[0x77u8; 32]])
    }

    /// `apk_digests` are the SHA-256 certificate digests of the root's `apk_signers` (§7.4
    /// step 10), so an APK fixture can carry a matching synthetic certificate.
    fn new_signers(n_roots: u32, apk_digests: &[[u8; 32]]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        ghost_release_ops::build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:2")
            .unwrap();
        let oa = onion("anchor-a");
        let ob = onion("anchor-b");
        let (first, second) = if oa < ob { (oa, ob) } else { (ob, oa) };
        let digests: Vec<String> = apk_digests.iter().map(hex::encode).collect();
        let digests_toml = digests
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut roots = Vec::new();
        for v in 1..=n_roots {
            let cfg = dir.path().join(format!("root-{v}.toml"));
            write(
                &cfg,
                format!(
                    r#"network = 2
version = {v}
apk_signers = [{digests_toml}]
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
        let name = format!("rel-{version_code}-{seq}");
        let rel = self.dir.path().join(&name);
        std::fs::create_dir_all(&rel).unwrap();
        write(&rel.join("app.apk"), format!("signed-apk-v{version_code}-{seq}"));
        write(&rel.join("app-unsigned.apk"), format!("unsigned-core-v{version_code}-{seq}"));
        write(&rel.join("escrow.tar.gz"), format!("escrow-v{version_code}-{seq}"));
        write(&rel.join("es.json"), format!("es-v{version_code}-{seq}"));
        self.manifest_for(
            version_code,
            seq,
            root_idx,
            stale,
            &rel.join("app.apk"),
            &rel.join("app-unsigned.apk"),
            &rel.join("escrow.tar.gz"),
            &rel.join("es.json"),
            &name,
        )
    }

    /// Builds a manifest whose release binds the given APK/unsigned files.
    #[allow(clippy::too_many_arguments)]
    fn manifest_for(
        &self,
        version_code: u32,
        seq: u64,
        root_idx: usize,
        stale: bool,
        apk: &Path,
        unsigned: &Path,
        escrow: &Path,
        es: &Path,
        name: &str,
    ) -> PathBuf {
        let (issued, not_after) = if stale {
            (DAY - 40, DAY - 10)
        } else {
            (DAY, DAY + 30)
        };
        let src = self.dir.path().join(format!("m-{name}.toml"));
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
                apk = apk.display(),
                unsigned = unsigned.display(),
                salt = hex16(0x33),
                commit = "ab".repeat(20),
                es = es.display(),
                escrow = escrow.display(),
            ),
        );
        let m = self.dir.path().join(format!("m-{name}.ghrm"));
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
    let mut text = std::fs::read_to_string(w.dir.path().join("m-rel-2-1.toml")).unwrap();
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

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The APK check (§7.4 steps 9–10) over synthetic signed APKs
// ---------------------------------------------------------------------------

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn lp32(data: &[u8]) -> Vec<u8> {
    let mut out = le32(data.len() as u32).to_vec();
    out.extend_from_slice(data);
    out
}

fn eocd(cd_offset: u32, cd_size: u32) -> Vec<u8> {
    let mut out = b"PK\x05\x06".to_vec();
    out.extend_from_slice(&le16(0)); // disk
    out.extend_from_slice(&le16(0)); // cd start disk
    out.extend_from_slice(&le16(1)); // entries this disk
    out.extend_from_slice(&le16(1)); // entries total
    out.extend_from_slice(&le32(cd_size));
    out.extend_from_slice(&le32(cd_offset));
    out.extend_from_slice(&le16(0)); // comment length 0
    out
}

/// One v3-layout signer value (min/max SDK present) with the given first certificate.
fn signer_v3(cert: &[u8], min_sdk: u32, max_sdk: u32) -> Vec<u8> {
    let mut signed = lp32(&lp32(b"digests"));
    signed.extend_from_slice(&lp32(&lp32(cert))); // certificates: one cert
    signed.extend_from_slice(&le32(min_sdk));
    signed.extend_from_slice(&le32(max_sdk));
    signed.extend_from_slice(&lp32(b"")); // additional attributes
    let mut signer = lp32(&signed);
    signer.extend_from_slice(&lp32(b"signatures"));
    signer.extend_from_slice(&lp32(b"public-key"));
    lp32(&signer)
}

/// A v2-layout signer (no SDK range).
fn signer_v2(cert: &[u8]) -> Vec<u8> {
    let mut signed = lp32(&lp32(b"digests"));
    signed.extend_from_slice(&lp32(&lp32(cert)));
    signed.extend_from_slice(&lp32(b""));
    let mut signer = lp32(&signed);
    signer.extend_from_slice(&lp32(b"signatures"));
    signer.extend_from_slice(&lp32(b"public-key"));
    lp32(&signer)
}

/// Builds a synthetic signed APK: `content_e` content bytes, a fake central directory, the
/// §6.5 zero padding and the signing block with the given id/value pairs. `pad_byte` taints
/// the padding. Returns (unsigned, signed).
fn build_apk(content_e: usize, cd: &[u8], pairs: &[(u32, Vec<u8>)], pad_byte: u8) -> (Vec<u8>, Vec<u8>) {
    let e = content_e;
    let mut unsigned = vec![0xA5u8; e];
    unsigned.extend_from_slice(cd);
    unsigned.extend_from_slice(&eocd(e as u32, cd.len() as u32));

    let pad = (4096 - (e % 4096)) % 4096;
    let b = (e + pad) as u64;
    let mut pairs_bytes = Vec::new();
    for (id, value) in pairs {
        pairs_bytes.extend_from_slice(&le64(value.len() as u64));
        pairs_bytes.extend_from_slice(&le32(*id));
        pairs_bytes.extend_from_slice(value);
    }
    let s = pairs_bytes.len() as u64 + 8 + 16;
    let mut signed = vec![0xA5u8; e];
    signed.extend(std::iter::repeat(pad_byte).take(pad));
    signed.extend_from_slice(&le64(s));
    signed.extend_from_slice(&pairs_bytes);
    signed.extend_from_slice(&le64(s));
    signed.extend_from_slice(b"APK Sig Block 42");
    assert_eq!(signed.len() as u64, b + 8 + s);
    signed.extend_from_slice(cd);
    signed.extend_from_slice(&eocd((b + 8 + s) as u32, cd.len() as u32));
    (unsigned, signed)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

struct ApkFixture {
    signed: Vec<u8>,
    manifest: ghost_client_release::manifest::GHRM,
    root: ghost_client_release::root::GHRT,
    #[allow(dead_code)]
    unsigned: Vec<u8>,
}

/// A world whose root lists `apk_digests` as apk_signers, plus a manifest bound to the
/// synthetic APK built from `pairs`.
fn apk_fixture(apk_digests: &[[u8; 32]], pairs: &[(u32, Vec<u8>)], pad_byte: u8) -> ApkFixture {
    let w = World::new_signers(1, apk_digests);
    let (unsigned, signed) = build_apk(900, b"fake-central-directory", pairs, pad_byte);
    let rel = w.dir.path().join("rel-apk");
    std::fs::create_dir_all(&rel).unwrap();
    write(&rel.join("app.apk"), &signed);
    write(&rel.join("app-unsigned.apk"), &unsigned);
    write(&rel.join("escrow.tar.gz"), "escrow");
    write(&rel.join("es.json"), "es");
    let m = w.manifest_for(
        2,
        1,
        0,
        false,
        &rel.join("app.apk"),
        &rel.join("app-unsigned.apk"),
        &rel.join("escrow.tar.gz"),
        &rel.join("es.json"),
        "apk",
    );
    ApkFixture {
        signed,
        manifest: ghost_client_release::manifest::GHRM::parse(&std::fs::read(&m).unwrap()).unwrap(),
        root: ghost_client_release::root::GHRT::parse(&std::fs::read(&w.roots[0]).unwrap()).unwrap(),
        unsigned,
    }
}

#[test]
fn apk_check_happy_path_and_refusals() {
    let cert = [0x11u8; 64];
    let f = apk_fixture(&[sha256(&cert)], &[(0xf053_68c0, signer_v3(&cert, 1, 0x7fff_ffff))], 0);
    ghost_client_update::apk::check_apk(&f.signed, &f.manifest, 0, &f.root, 29).unwrap();
    ghost_client_update::apk::check_apk(&f.signed, &f.manifest, 0, &f.root, 33).unwrap();

    // A content byte changed: APK_HASH (the layout still parses).
    let mut bad = f.signed.clone();
    bad[10] ^= 0x01;
    assert_eq!(
        ghost_client_update::apk::check_apk(&bad, &f.manifest, 0, &f.root, 29),
        Err(UpdateError::ApkHash)
    );
    // A self-consistent APK of a different length: APK_LENGTH (checked before the hash).
    // A longer certificate grows the signing block: B is unchanged, the total length is not.
    let (other_unsigned, other_signed) = build_apk(
        900,
        b"fake-central-directory",
        &[(0xf053_68c0, signer_v3(&[0x11u8; 300], 1, 0x7fff_ffff))],
        0,
    );
    let _ = other_unsigned;
    assert_eq!(
        ghost_client_update::apk::check_apk(&other_signed, &f.manifest, 0, &f.root, 29),
        Err(UpdateError::ApkLength)
    );
    // A truncated file fails the layout rule first (the EOCD is no longer at length − 22).
    let short = &f.signed[..f.signed.len() - 1];
    assert_eq!(
        ghost_client_update::apk::check_apk(short, &f.manifest, 0, &f.root, 29),
        Err(UpdateError::ApkLayout)
    );
    // An unknown certificate: APK_SIGNER — the file binds correctly (length, hash, layout),
    // but this fixture's root does not list the certificate's digest.
    let cert_f = [0x11u8; 64];
    let other = apk_fixture(&[sha256(&cert_f)], &[(0xf053_68c0, signer_v3(&[0xEEu8; 64], 1, 0x7fff_ffff))], 0);
    assert_eq!(
        ghost_client_update::apk::check_apk(&other.signed, &other.manifest, 0, &other.root, 29),
        Err(UpdateError::ApkSigner)
    );
}

#[test]
fn apk_signer_selection_by_sdk() {
    // v3.1 cert distinct from the v3 cert; v3.1 covers SDK 33+ only.
    let cert_v3 = [0x11u8; 64];
    let cert_v31 = [0x22u8; 64];
    let f = apk_fixture(
        &[sha256(&cert_v3)],
        &[
            (0xf053_68c0, signer_v3(&cert_v3, 1, 0x7fff_ffff)),
            (0x1b93_ad61, signer_v3(&cert_v31, 33, 0x7fff_ffff)),
        ],
        0,
    );
    // SDK 29: v3.1's range does not contain it → the v3 signer.
    ghost_client_update::apk::check_apk(&f.signed, &f.manifest, 0, &f.root, 29).unwrap();
    // SDK 33: v3.1 wins — its digest is not listed → APK_SIGNER.
    assert_eq!(
        ghost_client_update::apk::check_apk(&f.signed, &f.manifest, 0, &f.root, 33),
        Err(UpdateError::ApkSigner)
    );

    // v2-only signer and a v3 range that excludes the SDK: the v2 signer is selected.
    let cert_v2 = [0x33u8; 64];
    let f2 = apk_fixture(
        &[sha256(&cert_v2)],
        &[
            (0x7109_871a, signer_v2(&cert_v2)),
            (0xf053_68c0, signer_v3(&[0x44u8; 64], 28, 32)),
        ],
        0,
    );
    // SDK 33 is outside [28,32] → v2 signer, listed → OK; SDK 29 is inside → the unknown v3 cert.
    ghost_client_update::apk::check_apk(&f2.signed, &f2.manifest, 0, &f2.root, 33).unwrap();
    assert_eq!(
        ghost_client_update::apk::check_apk(&f2.signed, &f2.manifest, 0, &f2.root, 29),
        Err(UpdateError::ApkSigner)
    );
}

#[test]
fn apk_layout_refusals() {
    let cert = [0x55u8; 64];
    // The manifest binds this exact file, so the layout rule (not the hash) is what refuses.
    let f = apk_fixture(
        &[sha256(&cert)],
        &[(0xf053_68c0, signer_v3(&cert, 1, 0x7fff_ffff))],
        0x01, // non-zero padding byte
    );
    assert_eq!(
        ghost_client_update::apk::check_apk(&f.signed, &f.manifest, 0, &f.root, 29),
        Err(UpdateError::ApkLayout)
    );
}

#[test]
fn apk_streaming_check() {
    use ghost_client_update::apk::{ApkCheck, Need};
    let cert = [0x11u8; 64];
    let f = apk_fixture(&[sha256(&cert)], &[(0xf053_68c0, signer_v3(&cert, 1, 0x7fff_ffff))], 0);
    let n = f.signed.len();
    let body = &f.signed[..n - 22];

    let begin = || {
        let tail: [u8; 22] = f.signed[n - 22..].try_into().unwrap();
        ApkCheck::begin(
            0,
            f.manifest.body.releases[0].clone(),
            f.manifest.clone(),
            f.root.clone(),
            29,
            n as u64,
            &tail,
        )
            .unwrap()
    };
    // The named footer range is the 24 bytes before cd_offset.
    let (mut chk, need) = begin();
    let Need::Footer { offset } = need;
    let cd_offset = u32::from_le_bytes(f.signed[n - 6..n - 2].try_into().unwrap()) as u64;
    assert_eq!(offset, cd_offset - 24);
    chk.footer(f.signed[offset as usize..offset as usize + 24].try_into().unwrap())
        .unwrap();
    // Feed the body in 7-byte chunks, in order: OK.
    for (i, chunk) in body.chunks(7).enumerate() {
        chk.update((i * 7) as u64, chunk).unwrap();
    }
    chk.finish().unwrap();

    // A chunk out of order: OUT_OF_ORDER.
    let (mut chk2, need2) = begin();
    let Need::Footer { offset: o2 } = need2;
    chk2.footer(f.signed[o2 as usize..o2 as usize + 24].try_into().unwrap())
        .unwrap();
    assert_eq!(
        chk2.update(7, &body[7..14]),
        Err(UpdateError::OutOfOrder)
    );
    // update before footer: OUT_OF_ORDER.
    let (mut chk3, _) = begin();
    assert_eq!(chk3.update(0, &body[..1]), Err(UpdateError::OutOfOrder));
}

#[test]
fn stored_codec_roundtrip() {
    use ghost_client_update::codec::{decode_stored, encode_stored};
    let w = World::new(2);
    let state = fresh_state(&w, 1);
    let bytes = encode_stored(&state);
    assert_eq!(decode_stored(&bytes).unwrap(), state);

    // With an accepted manifest and an extended chain (exercises every codec branch).
    let m = w.manifest(2, 1, 1, false);
    let out = accept_bundle(&w.bundle(&m), &state, 2, trusted()).unwrap();
    let bytes = encode_stored(&out.state);
    assert_eq!(decode_stored(&bytes).unwrap(), out.state);

    // A tampered blob and a truncated one are MALFORMED, never a partial read. (Byte 0 is the
    // codec version; the epoch id is opaque and not re-derived here, so flipping an id byte
    // would legitimately decode.)
    let mut bad = bytes.clone();
    bad[0] ^= 0x01;
    assert_eq!(decode_stored(&bad), Err(UpdateError::Malformed));
    assert_eq!(
        decode_stored(&bytes[..bytes.len() - 1]),
        Err(UpdateError::Malformed)
    );
    // The manifest hash inside the blob is checked against the document: locate the GHRM
    // document and flip a byte of the 32-byte hash that follows it.
    let doc = out.state.manifest.as_ref().unwrap().body_bytes_with_block();
    let doc_at = bytes
        .windows(doc.len())
        .position(|w| w == doc.as_slice())
        .expect("manifest doc in blob");
    let mut bad_hash = bytes.clone();
    bad_hash[doc_at + doc.len() + 3] ^= 0x01;
    assert_eq!(decode_stored(&bad_hash), Err(UpdateError::Malformed));
}
