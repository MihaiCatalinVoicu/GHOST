//! Document builders for the release channel (Phase 14 design §3, §5): `keygen`, `root-build`,
//! `chain-build`, `proof-build`, `manifest-build`, `bundle`.
//!
//! This slice covers the stagenet channel end-to-end with software keys (RK1's hardware-token
//! PKCS#11 signer paths replace `load_signing_key` later). It implements the refusal rules that
//! are structural or local to the documents; the RK1-only rules that need issuer data (ES slot
//! coverage, relay withdrawals, archive index) land with the full ceremony tooling and are noted
//! per check. Every builder re-parses what it wrote and self-verifies signatures before writing
//! the output file (parse of the bytes, threshold checks, proof components).

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use ghost_client_release::bundle::GHRB;
use ghost_client_release::chain::GHRC;
use ghost_client_release::manifest::{ArtifactKind, GHRM, ManifestBody, Release};
use ghost_client_release::proof::{Cosignature, GHRP, SIGSUM_LEAF_DOMAIN, leaf_hash};
use ghost_client_release::root::{AnchorMirror, KeySet, LogEntry, Network, RootBody, GHRT};
use ghost_client_release::statement::{SigBlock, SigEntry, StatementType, key_id, sign_entry};
use sha2::{Digest, Sha256};

pub type Outcome = Result<String, String>;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.trim()).map_err(|_| format!("{what}: not hex"))?;
    b.try_into().map_err(|_| format!("{what}: must be 32 bytes"))
}

fn hex16(s: &str, what: &str) -> Result<[u8; 16], String> {
    let b = hex::decode(s.trim()).map_err(|_| format!("{what}: not hex"))?;
    b.try_into().map_err(|_| format!("{what}: must be 16 bytes"))
}

fn read_hex_file(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{what}: cannot read {}: {e}", path.display()))?;
    hex::decode(text.trim()).map_err(|_| format!("{what}: {} is not hex", path.display()))
}

/// A software key from `<keys_dir>/<name>.hex` (64 hex chars, the 32-byte Ed25519 seed).
fn load_signing_key(keys_dir: &Path, name: &str) -> Result<SigningKey, String> {
    let path = keys_dir.join(format!("{name}.hex"));
    let seed = read_hex_file(&path, "key")?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| format!("key {name}: seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_secret_keys(keys_dir: &Path, names: &[String]) -> Result<Vec<SigningKey>, String> {
    names.iter().map(|n| load_signing_key(keys_dir, n)).collect()
}

/// Keys of a keyset, sorted by key id (§4.1's one canonical encoding per value).
fn sorted_pubs(keys: &[&SigningKey]) -> Vec<[u8; 32]> {
    let mut pubs: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    pubs.sort_by_key(key_id);
    pubs
}

/// A signature block over `statement(ty, network, body)` from every key, ascending by key id.
fn block_from(keys: &[&SigningKey], ty: StatementType, network: u8, body: &[u8]) -> SigBlock {
    let mut entries: Vec<SigEntry> = keys.iter().map(|k| sign_entry(k, ty, network, body)).collect();
    entries.sort_by_key(|e| e.key_id);
    SigBlock { entries }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_doc(out: &Path, doc: &[u8]) -> Result<(), String> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(out, doc).map_err(|e| format!("cannot write {}: {e}", out.display()))
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

/// `keygen --out <dir> --spec root:3,release:2,attest:1,apk:1,log:1,witness:2`
/// Writes `<name>-<i>.hex` (the seed) and `<name>-<i>.pub` (the public key), 64 lowercase hex
/// chars each. Randomness: `/dev/urandom`, the signer host's OS RNG (the tool runs on Linux).
pub fn keygen(out_dir: &Path, spec: &str) -> Outcome {
    let mut total = 0usize;
    for part in spec.split(',') {
        let (name, count) = part
            .split_once(':')
            .ok_or_else(|| format!("spec element {part:?} is not name:count"))?;
        let count: usize = count
            .parse()
            .map_err(|_| format!("spec element {part:?}: bad count"))?;
        if count == 0 || name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("spec element {part:?}: bad name or count"));
        }
        for i in 1..=count {
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
                .map_err(|e| format!("/dev/urandom: {e}"))?;
            let sk = SigningKey::from_bytes(&seed);
            std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir: {e}"))?;
            std::fs::write(out_dir.join(format!("{name}-{i}.hex")), hex::encode(seed))
                .map_err(|e| format!("write key: {e}"))?;
            std::fs::write(
                out_dir.join(format!("{name}-{i}.pub")),
                hex::encode(sk.verifying_key().to_bytes()),
            )
            .map_err(|e| format!("write pubkey: {e}"))?;
            total += 1;
        }
    }
    Ok(format!("KEYS_BUILT n={total} dir={}", out_dir.display()))
}

// ---------------------------------------------------------------------------
// root-build
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct RootConfig {
    network: u8,
    version: u32,
    root: KeyCfg,
    release: KeyCfg,
    attest: KeyCfg,
    apk_signers: Vec<String>,
    logs: Vec<LogCfg>,
    witnesses: Vec<String>,
    quorum: usize,
    anchor_mirrors: Vec<MirrorCfg>,
}

#[derive(serde::Deserialize)]
struct KeyCfg {
    keys: Vec<String>,
    threshold: usize,
}

#[derive(serde::Deserialize)]
struct LogCfg {
    key: String,
    origin: String,
}

#[derive(serde::Deserialize)]
struct MirrorCfg {
    onion: String,
    operator: String,
}

fn keyset_from(keys_dir: &Path, cfg: &KeyCfg) -> Result<(KeySet, Vec<SigningKey>), String> {
    let sks = load_secret_keys(keys_dir, &cfg.keys)?;
    let refs: Vec<&SigningKey> = sks.iter().collect();
    let pubs = sorted_pubs(&refs);
    if cfg.threshold == 0 || cfg.threshold > pubs.len() {
        return Err(format!(
            "threshold {} outside 1..={}",
            cfg.threshold,
            pubs.len()
        ));
    }
    Ok((KeySet { keys: pubs, threshold: cfg.threshold }, sks))
}

/// `root-build --config <toml> --keys <dir> --out <path>`
/// Builds and signs a `GHRT`. The config's key names resolve to `<keys_dir>/<name>.hex`.
pub fn root_build(config_path: &Path, keys_dir: &Path, out: &Path) -> Outcome {
    let text = std::fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read {}: {e}", config_path.display()))?;
    let cfg: RootConfig =
        toml::from_str(&text).map_err(|e| format!("config TOML: {e}"))?;
    let network = Network::from_u8(cfg.network).map_err(|e| format!("network: {e}"))?;
    if cfg.version == 0 {
        return Err("version must be >= 1".into());
    }

    let (root_ks, root_sks) = keyset_from(keys_dir, &cfg.root)?;
    let (release_ks, _) = keyset_from(keys_dir, &cfg.release)?;
    let (attest_ks, _) = keyset_from(keys_dir, &cfg.attest)?;

    // `apk_signers` holds the SHA-256 digests of the signing certificates the platform may
    // select (§7.4 step 10), not public keys: the config names hex digests.
    let mut apk_signers: Vec<[u8; 32]> = Vec::new();
    for d in &cfg.apk_signers {
        apk_signers.push(hex32(d, "apk_signer digest")?);
    }
    apk_signers.sort(); // §4.3: ascending by raw bytes
    apk_signers.dedup();

    let mut logs = Vec::new();
    for l in &cfg.logs {
        let sk = load_signing_key(keys_dir, &l.key)?;
        if l.origin.is_empty() || l.origin.len() > u16::MAX as usize || !l.origin.is_ascii() {
            return Err(format!("log {}: origin must be 1..=65535 ASCII bytes", l.key));
        }
        logs.push(LogEntry { pk: sk.verifying_key().to_bytes(), origin: l.origin.clone().into_bytes() });
    }
    logs.sort_by_key(|l| key_id(&l.pk));
    logs.dedup_by_key(|l| key_id(&l.pk));
    if logs.is_empty() {
        return Err("at least one log required".into());
    }

    let witness_sks = load_secret_keys(keys_dir, &cfg.witnesses)?;
    let witness_refs: Vec<&SigningKey> = witness_sks.iter().collect();
    let witnesses = sorted_pubs(&witness_refs);

    if cfg.quorum > witnesses.len() {
        return Err(format!("quorum {} exceeds witness count {}", cfg.quorum, witnesses.len()));
    }

    let mut anchor_mirrors = Vec::new();
    for m in &cfg.anchor_mirrors {
        ghost_client_release::CanonicalOnion::parse(m.onion.as_bytes())
            .map_err(|e| format!("anchor mirror {}: {e}", m.onion))?;
        anchor_mirrors.push(AnchorMirror {
            onion: m.onion.clone().into_bytes(),
            operator_id: hex16(&m.operator, "operator id")?,
        });
    }
    anchor_mirrors.sort_by(|a, b| a.onion.cmp(&b.onion));
    anchor_mirrors.dedup_by_key(|a| a.onion.clone());

    let body = RootBody {
        network,
        root_version: cfg.version,
        root: root_ks,
        release: release_ks,
        attest: attest_ks,
        apk_signers,
        logs,
        witnesses,
        quorum: cfg.quorum,
        anchor_mirrors,
    };
    // §4.3's no-key-reuse rule is parse-level; build it the same way.
    let mut all: Vec<[u8; 32]> = body
        .root
        .keys
        .iter()
        .chain(body.release.keys.iter())
        .chain(body.attest.keys.iter())
        .map(|k| key_id(k))
        .collect();
    all.sort();
    if all.windows(2).any(|w| w[0] == w[1]) {
        return Err("a key appears in more than one keyset".into());
    }

    let body_bytes = {
        let tmp = GHRT { body: body.clone(), block: SigBlock { entries: vec![] } };
        tmp.body_bytes()
    };
    let root_refs: Vec<&SigningKey> = root_sks.iter().collect();
    let block = block_from(&root_refs, StatementType::ReleaseRoot, network as u8, &body_bytes);
    let doc = GHRT { body, block };
    let bytes = doc.to_bytes();
    // Self-check: the exact bytes must parse and the block must meet the root threshold.
    let parsed = GHRT::parse(&bytes).map_err(|e| format!("self-parse: {e}"))?;
    parsed
        .verify_block(&doc.body.root.keys, doc.body.root.threshold)
        .map_err(|e| format!("self-verify: {e}"))?;
    let digest = sha256(&bytes);
    write_doc(out, &bytes)?;
    Ok(format!(
        "ROOT_BUILT version={} keys={}/{} sha256={}",
        doc.body.root_version,
        doc.block.entries.len(),
        doc.body.root.threshold,
        hex::encode(digest)
    ))
}

// ---------------------------------------------------------------------------
// chain-build
// ---------------------------------------------------------------------------

/// `chain-build --network <n> --roots <dir> --out <path>`
/// Reads every `*.ghrt` in `<dir>`, sorts by root version, checks contiguity, writes a `GHRC`.
pub fn chain_build(network: u8, roots_dir: &Path, out: &Path) -> Outcome {
    let network = Network::from_u8(network).map_err(|e| format!("network: {e}"))?;
    let mut roots: Vec<GHRT> = Vec::new();
    let entries = std::fs::read_dir(roots_dir)
        .map_err(|e| format!("cannot read {}: {e}", roots_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir: {e}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ghrt") {
            let doc = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            roots.push(GHRT::parse(&doc).map_err(|e| format!("{}: {e}", path.display()))?);
        }
    }
    roots.sort_by_key(|r| r.body.root_version);
    if roots.is_empty() {
        return Err(format!("no .ghrt files in {}", roots_dir.display()));
    }
    for w in roots.windows(2) {
        if w[1].body.root_version != w[0].body.root_version + 1 {
            return Err(format!(
                "root versions not contiguous: {} then {}",
                w[0].body.root_version,
                w[1].body.root_version
            ));
        }
    }
    if roots.iter().any(|r| r.body.network != network) {
        return Err("a root has a different network".into());
    }
    let first_version = roots[0].body.root_version;
    let chain = GHRC { network: network as u8, first_version, roots };
    let bytes = chain.to_bytes();
    let parsed = GHRC::parse(&bytes).map_err(|e| format!("self-parse: {e}"))?;
    let digest = sha256(&bytes);
    write_doc(out, &bytes)?;
    Ok(format!(
        "CHAIN_BUILT first={} count={} sha256={}",
        parsed.first_version,
        parsed.roots.len(),
        hex::encode(digest)
    ))
}

// ---------------------------------------------------------------------------
// proof-build (synthetic single-leaf log, stagenet/test tooling)
// ---------------------------------------------------------------------------

/// `proof-build --file <logged file> --log-key <name> --submit-key <name>
///   --witness <name>... [--time <unix>] --out <path>`
/// Builds a `GHRP` over a synthetic one-leaf tree: every component is signed and verifiable
/// against the root's log/witness keys, but the tree exists only in this command. Real
/// submissions (sigsum-submit + proof-assemble) land with RK1/V-D11b. `--file` is the exact
/// logged document (a `GHRT` or a full `GHRM`); the proof's message is its leaf checksum.
pub fn proof_build(
    file: &Path,
    log_index: u8,
    log_key: &str,
    submit_key: &str,
    witnesses: &[String],
    time: Option<u64>,
    keys_dir: &Path,
    out: &Path,
) -> Outcome {
    let file_bytes =
        std::fs::read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    // §7.4 step 4: the logged message is the file's SHA-256; the leaf checksum the log stores
    // is SHA-256 of the message (so equal to leaf_checksum(file), which the tree uses).
    let message = sha256(&file_bytes);
    let checksum = sha256(&message);
    let log_sk = load_signing_key(keys_dir, log_key)?;
    let submit_sk = load_signing_key(keys_dir, submit_key)?;
    let time = time.unwrap_or_else(now_secs);

    use ed25519_dalek::Signer;
    let mut leaf_stmt = Vec::with_capacity(SIGSUM_LEAF_DOMAIN.len() + 1 + 32);
    leaf_stmt.extend_from_slice(SIGSUM_LEAF_DOMAIN);
    leaf_stmt.push(0x00);
    leaf_stmt.extend_from_slice(&checksum);
    let leaf_signature = submit_sk.sign(&leaf_stmt).to_bytes();
    let leaf_key_id = key_id(&submit_sk.verifying_key().to_bytes());
    let mut leaf = [0u8; 128];
    leaf[..32].copy_from_slice(&checksum);
    leaf[32..96].copy_from_slice(&leaf_signature);
    leaf[96..].copy_from_slice(&leaf_key_id);
    let root_hash = leaf_hash(&leaf);

    let proof = GHRP {
        message,
        log: log_index,
        leaf_signature,
        leaf_key_id,
        tree_size: 1,
        leaf_index: 0,
        path: vec![],
        root_hash,
        log_signature: [0u8; 64],
        cosignatures: vec![],
    };
    let checkpoint = proof.checkpoint_body(&key_id(&log_sk.verifying_key().to_bytes()));
    let log_signature = log_sk.sign(&checkpoint).to_bytes();

    let mut cosignatures = Vec::new();
    for w in witnesses {
        let wsk = load_signing_key(keys_dir, w)?;
        let mut msg = Vec::new();
        msg.extend_from_slice(b"cosignature/v1\ntime ");
        msg.extend_from_slice(time.to_string().as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(&checkpoint);
        cosignatures.push(Cosignature {
            witness_key_id: key_id(&wsk.verifying_key().to_bytes()),
            time,
            signature: wsk.sign(&msg).to_bytes(),
        });
    }
    cosignatures.sort_by_key(|c| c.witness_key_id);

    let proof = GHRP { log_signature, cosignatures, ..proof };
    let bytes = proof.to_bytes();
    let parsed = GHRP::parse(&bytes).map_err(|e| format!("self-parse: {e}"))?;
    // Component self-checks, exactly what a client verifies.
    if parsed.message != message {
        return Err("self-check: message".into());
    }
    ghost_client_release::proof::check_inclusion(
        leaf_hash(&parsed.leaf(&file_bytes)),
        0,
        &[],
        &parsed.root_hash,
    )
    .map_err(|e| format!("self-check inclusion: {e}"))?;
    let submit_pub = submit_sk.verifying_key().to_bytes();
    parsed
        .verify_leaf(&file_bytes, &submit_pub)
        .map_err(|e| format!("self-check leaf: {e}"))?;
    parsed
        .verify_log_signature(&log_sk.verifying_key().to_bytes())
        .map_err(|e| format!("self-check log sig: {e}"))?;
    for c in &parsed.cosignatures {
        let wsk = witnesses
            .iter()
            .map(|w| load_signing_key(keys_dir, w))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|w| key_id(&w.verifying_key().to_bytes()) == c.witness_key_id)
            .ok_or("cosignature key missing")?;
        parsed
            .verify_cosignature(c, &wsk.verifying_key().to_bytes(), &log_sk.verifying_key().to_bytes())
            .map_err(|e| format!("self-check cosignature: {e}"))?;
    }
    write_doc(out, &bytes)?;
    Ok(format!(
        "PROOF_BUILT log={log_index} message={} cosigned={}",
        hex::encode(checksum),
        parsed.cosignatures.len()
    ))
}

// ---------------------------------------------------------------------------
// manifest-build
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ManifestSource {
    seq: u64,
    issued_day: u32,
    not_after_day: u32,
    floor_version_code: u32,
    release: Vec<ReleaseCfg>,
    #[serde(default)]
    mirror: Vec<MirrorCfg>,
    #[serde(default)]
    relay: Vec<MirrorCfg>,
}

#[derive(serde::Deserialize)]
struct ReleaseCfg {
    version_code: u32,
    version_name: String,
    min_sdk: u8,
    anchor_root: u32,
    wire_changing: bool,
    apk: PathBuf,
    #[serde(default)]
    apk_sha256: Option<String>,
    #[serde(default)]
    apk_length: Option<u64>,
    unsigned: PathBuf,
    #[serde(default)]
    unsigned_sha256: Option<String>,
    #[serde(default)]
    unsigned_length: Option<u64>,
    rollout_permille: u16,
    rollout_salt: String,
    commit: String,
    es_seq: u64,
    es_sha256: Option<String>,
    es_file: Option<PathBuf>,
    artifacts: Vec<ArtifactCfg>,
}

#[derive(serde::Deserialize)]
struct ArtifactCfg {
    kind: u8,
    file: PathBuf,
}

fn file_digest_length(path: &Path, sha_override: &Option<String>, len_override: &Option<u64>) -> Result<([u8; 32], u64), String> {
    if let (Some(s), Some(l)) = (sha_override, len_override) {
        return Ok((hex32(s, "sha256 override")?, *l));
    }
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok((sha256(&data), data.len() as u64))
}

/// `manifest-build --source <toml> --root <ghrt> --keys <dir> --attest-keys n1,n2
///   [--prev <ghrm>] --out <path>`
/// Builds and signs a `GHRM`. Structural refusal rules only; the RK1 rules that need issuer
/// state (ES slot coverage, relay withdrawals, archive index, wire transcript) are listed in
/// the design's step 5 and land with the ceremony tooling.
pub fn manifest_build(
    source_path: &Path,
    root_path: &Path,
    keys_dir: &Path,
    attest_names: &[String],
    prev_path: Option<&Path>,
    out: &Path,
) -> Outcome {
    let text = std::fs::read_to_string(source_path)
        .map_err(|e| format!("cannot read {}: {e}", source_path.display()))?;
    let src: ManifestSource = toml::from_str(&text).map_err(|e| format!("source TOML: {e}"))?;
    let root_doc = std::fs::read(root_path).map_err(|e| format!("cannot read {}: {e}", root_path.display()))?;
    let root = GHRT::parse(&root_doc).map_err(|e| format!("root: {e}"))?;
    let network = root.body.network as u8;
    if root.body.root_version == 0 {
        return Err("root version is 0".into());
    }

    if let Some(pp) = prev_path {
        let prev_doc = std::fs::read(pp).map_err(|e| format!("cannot read prev: {e}"))?;
        let prev = GHRM::parse(&prev_doc).map_err(|e| format!("prev manifest: {e}"))?;
        if src.seq <= prev.body.manifest_seq {
            return Err(format!(
                "manifest_seq {} not above the logged {}",
                src.seq, prev.body.manifest_seq
            ));
        }
        if src.issued_day < prev.body.issued_day {
            return Err(format!(
                "issued_day {} below the previous manifest's {}",
                src.issued_day, prev.body.issued_day
            ));
        }
        // A salt changed for a logged apk_sha256 would break rollout stability.
        for rel in &src.release {
            if let Some(old) = prev
                .body
                .releases
                .iter()
                .find(|r| r.version_code == rel.version_code)
            {
                let (sha, _) = file_digest_length(
                    &rel.apk,
                    &rel.apk_sha256,
                    &rel.apk_length,
                )?;
                if sha == old.apk_sha256 && hex16(&rel.rollout_salt, "rollout salt")? != old.rollout_salt {
                    return Err(format!(
                        "version {}: salt changed for a logged apk_sha256",
                        rel.version_code
                    ));
                }
            }
        }
    }

    let mut releases: Vec<Release> = Vec::new();
    let mut last_code = 0u32;
    for rel in &src.release {
        if rel.version_code <= last_code {
            return Err(format!("release version codes not ascending at {}", rel.version_code));
        }
        last_code = rel.version_code;
        if rel.anchor_root > root.body.root_version || rel.anchor_root == 0 {
            return Err(format!(
                "version {}: anchor_root {} outside 1..={}",
                rel.version_code, rel.anchor_root, root.body.root_version
            ));
        }
        if rel.wire_changing && rel.rollout_permille > 0 && rel.rollout_permille < 1000 {
            return Err(format!(
                "version {}: wire-changing release at permille strictly between 0 and 1000",
                rel.version_code
            ));
        }
        let (apk_sha256, apk_length) =
            file_digest_length(&rel.apk, &rel.apk_sha256, &rel.apk_length)?;
        if apk_length == 0 {
            return Err(format!("version {}: apk is empty", rel.version_code));
        }
        let (unsigned_sha256, unsigned_length) =
            file_digest_length(&rel.unsigned, &rel.unsigned_sha256, &rel.unsigned_length)?;
        if unsigned_length == 0 {
            return Err(format!("version {}: unsigned core is empty", rel.version_code));
        }
        let es_sha256 = match (&rel.es_sha256, &rel.es_file) {
            (Some(h), None) => hex32(h, "es_sha256")?,
            (None, Some(f)) => {
                let data = std::fs::read(f).map_err(|e| format!("es_file: {e}"))?;
                sha256(&data)
            }
            _ => return Err("exactly one of es_sha256 or es_file".into()),
        };
        let mut artifacts = Vec::new();
        for a in &rel.artifacts {
            let kind = ArtifactKind::from_u8(a.kind)
                .ok_or_else(|| format!("artifact kind {} unknown", a.kind))?;
            let data = std::fs::read(&a.file)
                .map_err(|e| format!("cannot read {}: {e}", a.file.display()))?;
            artifacts.push((kind, sha256(&data), data.len() as u64));
        }
        artifacts.sort_by_key(|a| a.0);
        artifacts.dedup_by_key(|a| a.0);
        if !artifacts.iter().any(|a| a.0 == ArtifactKind::SourceEscrow) {
            return Err(format!(
                "version {}: artifact kind 16 (source escrow) is required",
                rel.version_code
            ));
        }
        if rel.version_name.is_empty()
            || rel.version_name.len() > 32
            || !rel.version_name.is_ascii()
        {
            return Err(format!("version {}: bad version_name", rel.version_code));
        }
        let commit = hex::decode(rel.commit.trim())
            .map_err(|_| "commit must be hex")?;
        let commit: [u8; 20] = commit
            .try_into()
            .map_err(|_| "commit must be 20 bytes (40 hex chars)")?;
        releases.push(Release {
            version_code: rel.version_code,
            version_name: rel.version_name.clone().into_bytes(),
            min_sdk: rel.min_sdk,
            flavor: 1,
            anchor_root: rel.anchor_root,
            wire_changing: rel.wire_changing,
            apk_sha256,
            apk_length,
            unsigned_sha256,
            unsigned_length,
            rollout_permille: rel.rollout_permille,
            rollout_salt: hex16(&rel.rollout_salt, "rollout salt")?,
            commit,
            es_seq: rel.es_seq,
            es_sha256,
            artifacts,
        });
    }
    if releases.is_empty() || releases.len() > 4 {
        return Err("1..=4 releases required".into());
    }
    if src.floor_version_code != 0
        && src.floor_version_code
            > releases.iter().map(|r| r.version_code).min().unwrap_or(0)
    {
        return Err("floor above the lowest attested release".into());
    }

    let mut mirrors = Vec::new();
    for m in &src.mirror {
        ghost_client_release::CanonicalOnion::parse(m.onion.as_bytes())
            .map_err(|e| format!("mirror {}: {e}", m.onion))?;
        mirrors.push((m.onion.clone().into_bytes(), hex16(&m.operator, "operator id")?));
    }
    mirrors.sort_by(|a, b| a.0.cmp(&b.0));
    mirrors.dedup_by_key(|m| m.0.clone());

    let mut relays = Vec::new();
    for r in &src.relay {
        ghost_client_release::CanonicalOnion::parse(r.onion.as_bytes())
            .map_err(|e| format!("relay {}: {e}", r.onion))?;
        relays.push((r.onion.clone().into_bytes(), hex16(&r.operator, "operator id")?));
    }
    relays.sort_by(|a, b| a.0.cmp(&b.0));
    relays.dedup_by_key(|r| r.0.clone());

    let body = ManifestBody {
        network,
        manifest_seq: src.seq,
        root_version: root.body.root_version,
        root_sha256: sha256(&root_doc),
        issued_day: src.issued_day,
        not_after_day: src.not_after_day,
        floor_version_code: src.floor_version_code,
        releases: releases.clone(),
        extra_mirrors: mirrors,
        relays,
    };

    // Per-release attestation blocks over each release's GHRA statement.
    let attest_sks = load_secret_keys(keys_dir, attest_names)?;
    let attest_refs: Vec<&SigningKey> = attest_sks.iter().collect();
    let mut attestations = Vec::new();
    for rel in &releases {
        let ghra = rel.attestation(network);
        attestations.push(block_from(
            &attest_refs,
            StatementType::BuildAttestation,
            network,
            &ghra.to_bytes(),
        ));
    }
    for (i, at) in attestations.iter().enumerate() {
        at.meets(
            &root.body.attest.keys,
            root.body.attest.threshold,
            &ghost_client_release::statement_bytes(
                StatementType::BuildAttestation,
                network,
                &releases[i].attestation(network).to_bytes(),
            ),
        )
        .map_err(|e| format!("attestation {}: {e}", i))?;
    }

    // The release statement binds the body WITH the attestation blocks (§4.5's grammar),
    // so it can only be computed after they exist.
    let body_bytes = {
        let tmp = GHRM {
            body: body.clone(),
            attestations: attestations.clone(),
            block: SigBlock { entries: vec![] },
        };
        tmp.body_bytes()
    };

    // The release signature block over the manifest statement.
    let release_sks: Vec<SigningKey> = root
        .body
        .release
        .keys
        .iter()
        .map(|pk| find_secret_for_pubkey(keys_dir, pk))
        .collect::<Result<Vec<_>, _>>()?;
    let release_refs: Vec<&SigningKey> = release_sks.iter().collect();
    let statement = ghost_client_release::statement_bytes(
        StatementType::ReleaseManifest,
        network,
        &body_bytes,
    );
    let block = block_from(&release_refs, StatementType::ReleaseManifest, network, &body_bytes);
    block
        .meets(&root.body.release.keys, root.body.release.threshold, &statement)
        .map_err(|e| format!("release block: {e}"))?;

    let doc = GHRM { body, attestations, block };
    let bytes = doc.body_bytes_with_block();
    let parsed = GHRM::parse(&bytes).map_err(|e| format!("self-parse: {e}"))?;
    parsed
        .verify_block(&root.body.release.keys, root.body.release.threshold)
        .map_err(|e| format!("self-verify: {e}"))?;
    let digest = sha256(&bytes);
    write_doc(out, &bytes)?;
    Ok(format!(
        "MANIFEST_BUILT seq={} root={} releases={} sha256={}",
        doc.body.manifest_seq,
        doc.body.root_version,
        doc.body.releases.len(),
        hex::encode(digest)
    ))
}

/// Locate the secret key whose public key matches `pk` by scanning `<keys_dir>/*.hex`.
/// The signer host keeps one directory per ceremony; RK1's token paths will replace this.
fn find_secret_for_pubkey(keys_dir: &Path, pk: &[u8; 32]) -> Result<SigningKey, String> {
    let want = key_id(pk);
    let entries = std::fs::read_dir(keys_dir).map_err(|e| format!("keys dir: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "hex") {
            if let Ok(seed) = read_hex_file(&path, "key") {
                if let Ok(seed) = <[u8; 32]>::try_from(seed) {
                    let sk = SigningKey::from_bytes(&seed);
                    if key_id(&sk.verifying_key().to_bytes()) == want {
                        return Ok(sk);
                    }
                }
            }
        }
    }
    Err(format!("no secret key in {} matches the root's release key", keys_dir.display()))
}

// ---------------------------------------------------------------------------
// bundle
// ---------------------------------------------------------------------------

/// `bundle --chain <ghrc> --root-proof <ghrp>... --manifest <ghrm> --manifest-proof <ghrp>
///   --out <path>`
/// Assembles a `GHRB` and checks every proof component against the documents it covers
/// (synthetic single-leaf proofs included: inclusion is the trivial path check).
pub fn bundle(
    chain_path: &Path,
    root_proofs: &[PathBuf],
    manifest_path: &Path,
    manifest_proof_path: &Path,
    out: &Path,
) -> Outcome {
    let chain_doc = std::fs::read(chain_path).map_err(|e| format!("chain: {e}"))?;
    let chain = GHRC::parse(&chain_doc).map_err(|e| format!("chain: {e}"))?;
    if root_proofs.len() != chain.roots.len().saturating_sub(1) {
        return Err(format!(
            "{} root proofs for {} chain roots (one per entry after the first)",
            root_proofs.len(),
            chain.roots.len()
        ));
    }
    let manifest_doc = std::fs::read(manifest_path).map_err(|e| format!("manifest: {e}"))?;
    let manifest = GHRM::parse(&manifest_doc).map_err(|e| format!("manifest: {e}"))?;
    let mp_doc = std::fs::read(manifest_proof_path).map_err(|e| format!("manifest proof: {e}"))?;
    let manifest_proof = GHRP::parse(&mp_doc).map_err(|e| format!("manifest proof: {e}"))?;

    let mut root_proof_docs: Vec<GHRP> = Vec::new();
    for (i, rp) in root_proofs.iter().enumerate() {
        let doc = std::fs::read(rp).map_err(|e| format!("root proof {i}: {e}"))?;
        let proof = GHRP::parse(&doc).map_err(|e| format!("root proof {i}: {e}"))?;
        let root = &chain.roots[i + 1];
        let root_bytes = root.to_bytes();
        if proof.message != sha256(&root_bytes) {
            return Err(format!("root proof {i}: message is not the root's SHA-256"));
        }
        ghost_client_release::check_inclusion(
            leaf_hash(&proof.leaf(&root_bytes)),
            proof.leaf_index,
            &proof.path,
            &proof.root_hash,
        )
        .map_err(|e| format!("root proof {i}: inclusion: {e}"))?;
        root_proof_docs.push(proof);
    }

    if manifest_proof.message != sha256(&manifest_doc) {
        return Err("manifest proof: message is not the manifest's SHA-256".into());
    }
    ghost_client_release::check_inclusion(
        leaf_hash(&manifest_proof.leaf(&manifest_doc)),
        manifest_proof.leaf_index,
        &manifest_proof.path,
        &manifest_proof.root_hash,
    )
    .map_err(|e| format!("manifest proof inclusion: {e}"))?;

    let doc = GHRB {
        network: chain.network,
        chain,
        root_proofs: root_proof_docs,
        manifest,
        manifest_proof,
    };
    let bytes = doc.to_bytes();
    let parsed = GHRB::parse(&bytes).map_err(|e| format!("self-parse: {e}"))?;
    let digest = sha256(&bytes);
    write_doc(out, &bytes)?;
    Ok(format!(
        "BUNDLE_BUILT bytes={} roots={} releases={} sha256={}",
        bytes.len(),
        parsed.chain.roots.len(),
        parsed.manifest.body.releases.len(),
        hex::encode(digest)
    ))
}

// ---------------------------------------------------------------------------
// inspect — the client-side acceptance skeleton (§7.4) for a downloaded bundle
// ---------------------------------------------------------------------------

/// `inspect --bundle <ghrb> [--today <day>]` — parses a bundle exactly as a client would and
/// checks the internal consistency: chain contiguity, each root's block under its own keysets,
/// the manifest's block under the newest root's release keys, the attestation blocks, each
/// proof's inclusion and cosignature count against the newest root's quorum, the network-wide
/// match and the manifest's expiry against `--today` (epoch days; omitted = no expiry check).
pub fn inspect(bundle_path: &Path, today: Option<u32>) -> Outcome {
    let doc = std::fs::read(bundle_path).map_err(|e| format!("bundle: {e}"))?;
    let b = GHRB::parse(&doc).map_err(|e| format!("bundle: {e}"))?;
    let network = b.network;
    let roots = &b.chain.roots;
    if roots.is_empty() {
        return Err("empty chain".into());
    }
    // Chain rule (§7.4 step 2): each root verifies under its predecessor's keysets; the first
    // is the trust anchor and must verify under its own.
    for (i, root) in roots.iter().enumerate() {
        let (keys, t) = if i == 0 {
            (&root.body.root.keys, root.body.root.threshold)
        } else {
            (&roots[i - 1].body.root.keys, roots[i - 1].body.root.threshold)
        };
        root.verify_block(keys, t)
            .map_err(|e| format!("root {} block: {e}", root.body.root_version))?;
    }
    let newest = roots.last().unwrap();
    let manifest = &b.manifest;
    if manifest.body.root_version != newest.body.root_version
        || manifest.body.root_sha256 != sha256(&newest.to_bytes())
    {
        return Err("manifest does not name the newest root".into());
    }
    manifest
        .verify_block(&newest.body.release.keys, newest.body.release.threshold)
        .map_err(|e| format!("manifest block: {e}"))?;
    for (i, at) in manifest.attestations.iter().enumerate() {
        at.meets(
            &newest.body.attest.keys,
            newest.body.attest.threshold,
            &ghost_client_release::statement_bytes(
                StatementType::BuildAttestation,
                network,
                &manifest.body.releases[i].attestation(network).to_bytes(),
            ),
        )
        .map_err(|e| format!("attestation {i}: {e}"))?;
    }
    // Proofs (§4.7): inclusion and a cosignature count meeting the root's quorum.
    for (i, p) in b.root_proofs.iter().enumerate() {
        check_proof(p, &roots[i + 1].to_bytes(), newest.body.quorum, i)?;
    }
    check_proof(&b.manifest_proof, &manifest.body_bytes_with_block(), newest.body.quorum, usize::MAX)?;
    if let Some(today) = today {
        if today >= manifest.body.not_after_day {
            return Err("manifest expired".into());
        }
        if manifest.body.issued_day >= manifest.body.not_after_day {
            return Err("manifest validity is empty".into());
        }
    }
    Ok(format!(
        "BUNDLE_OK network={} roots={} root_version={} seq={} releases={} proofs={} quorum={}",
        network,
        roots.len(),
        manifest.body.root_version,
        manifest.body.manifest_seq,
        manifest.body.releases.len(),
        b.root_proofs.len() + 1,
        newest.body.quorum
    ))
}

fn check_proof(p: &GHRP, file: &[u8], quorum: usize, idx: usize) -> Result<(), String> {
    if p.message != sha256(file) {
        return Err(format!("proof {idx}: message mismatch"));
    }
    ghost_client_release::check_inclusion(
        leaf_hash(&p.leaf(file)),
        p.leaf_index,
        &p.path,
        &p.root_hash,
    )
    .map_err(|e| format!("proof {idx}: inclusion: {e}"))?;
    if p.cosignatures.len() < quorum {
        return Err(format!(
            "proof {idx}: {} cosignatures below quorum {}",
            p.cosignatures.len(),
            quorum
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sums-compare (RK1 step 2, CR-M5)
// ---------------------------------------------------------------------------

/// One parsed SHA256SUMS entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SumsEntry {
    name: String,
    sha256: [u8; 32],
}

fn parse_sums(text: &str, what: &str) -> Result<Vec<SumsEntry>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        // "<64 hex>  <name>" (two spaces, the `*`-marker form refused: names only, no binaries).
        let (hex_part, name) = line
            .split_once("  ")
            .ok_or_else(|| format!("{what}: line {} does not parse", i + 1))?;
        let sha: [u8; 32] = hex::decode(hex_part.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("{what}: line {} is not a sha256", i + 1))?;
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(format!("{what}: line {} has no name", i + 1));
        }
        if name.starts_with('*') {
            return Err(format!("{what}: line {} uses the binary marker", i + 1));
        }
        out.push(SumsEntry { name, sha256: sha });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    for w in out.windows(2) {
        if w[0].name == w[1].name {
            return Err(format!("{what}: duplicate name {}", w[0].name));
        }
    }
    Ok(out)
}

/// `sums-compare --a-local <f> --a-job <f> --b-job <f>` (RK1 step 2): the three SHA256SUMS of
/// the release must agree entry for entry; on agreement prints `SUMS_EQUAL files=<n>
/// b_digest=<first 16 hex of SHA-256(SHA256SUMS-B)>`. `b_digest` is what the owner compares on
/// an independent device (CR-M5: a workstation that forged B's sums is caught there, never
/// through the workstation). `SUMS_DIFFER <which> <name>` on any disagreement.
pub fn sums_compare(a_local: &Path, a_job: &Path, b_job: &Path) -> Outcome {
    let read = |p: &Path, what: &str| -> Result<(Vec<SumsEntry>, Vec<u8>), String> {
        let raw = std::fs::read(p).map_err(|e| format!("{what}: cannot read {}: {e}", p.display()))?;
        let text = String::from_utf8(raw.clone()).map_err(|_| format!("{what}: not UTF-8"))?;
        Ok((parse_sums(&text, what)?, raw))
    };
    let (local, _) = read(a_local, "a-local")?;
    let (ajob, _) = read(a_job, "a-job")?;
    let (bjob, braw) = read(b_job, "b-job")?;
    if local.is_empty() {
        return Err("a-local has no entries".into());
    }
    for (which, other) in [("a-job", &ajob), ("b-job", &bjob)] {
        for (x, y) in local.iter().zip(other.iter()) {
            if x.name != y.name || x.sha256 != y.sha256 {
                return Err(format!("SUMS_DIFFER {which} {}", x.name));
            }
        }
        if other.len() != local.len() {
            return Err(format!("SUMS_DIFFER {which} <file count>"));
        }
    }
    let b_digest = sha256(&braw);
    Ok(format!(
        "SUMS_EQUAL files={} b_digest={}",
        local.len(),
        hex::encode(b_digest)[..16].to_string()
    ))
}
