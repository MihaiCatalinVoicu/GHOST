//! V10-12: the MLS WG passive-client vectors (as the openmls repository carries them at the tag
//! commit 3a3e35de…, fetched by scripts/v10-12-fetch-vectors.sh) replayed **through GhostKv under
//! value semantics** with the libcrux provider: every call loads the stored rows into a fresh
//! adapter, runs, and applies the change-set only on success; after every call the reload oracle
//! of design §3.4 point 6 compares the in-memory group with one reloaded from the rows (epoch,
//! epoch_authenticator, tree hash, own leaf, an exporter output).
//!
//! OpenMLS's own KAT switches off leaf-lifetime validation with a crate-internal flag; this
//! replay cannot. It joins with `JoinBuilder::skip_lifetime_validation()` (public) and reports, per
//! vector, how many epochs pass before the first refusal and why (received Adds' KeyPackage
//! lifetimes are checked against the host clock with no public switch, design C-15, §19.4).
//!
//! Run: `bash scripts/v10-12-fetch-vectors.sh && cargo test --release -p ghost-mls-spike-kat -- --nocapture`

use std::collections::BTreeMap;

use ghost_mls_spike::kv::{GhostKv, RowKey};
use ghost_mls_spike::provider::GhostProvider;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls::schedule::PreSharedKeyId;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider as _;
use openmls_traits::OpenMlsProvider;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
struct Vector {
    cipher_suite: u16,
    external_psks: Vec<Psk>,
    #[serde(with = "hex::serde")]
    key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    init_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    welcome: Vec<u8>,
    ratchet_tree: Option<HexBytes>,
    #[serde(with = "hex::serde")]
    initial_epoch_authenticator: Vec<u8>,
    epochs: Vec<Epoch>,
}

#[derive(Deserialize, Clone)]
struct HexBytes(#[serde(with = "hex::serde")] Vec<u8>);

#[derive(Deserialize, Clone)]
struct Psk {
    #[serde(with = "hex::serde")]
    psk_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    psk: Vec<u8>,
}

#[derive(Deserialize, Clone)]
struct Epoch {
    proposals: Vec<HexBytes>,
    #[serde(with = "hex::serde")]
    commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    epoch_authenticator: Vec<u8>,
}

/// One passive client: its crypto context and its committed rows.
struct Passive {
    crypto: CryptoProvider,
    group_id: Vec<u8>,
    rows: BTreeMap<RowKey, Vec<u8>>,
    reload_checks: usize,
}

impl Passive {
    fn call<T>(
        &mut self,
        f: impl FnOnce(&GhostProvider<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let provider = GhostProvider {
            crypto: &self.crypto,
            storage: GhostKv::for_group(&self.group_id, 0),
        };
        provider.storage.load_plain(self.rows.clone());
        let out = f(&provider)?;
        let (changes, _) = provider.storage.take_changes();
        for (k, v) in changes {
            match v {
                Some(v) => {
                    self.rows.insert(k, v);
                }
                None => {
                    self.rows.remove(&k);
                }
            }
        }
        Ok(out)
    }

    fn load(p: &GhostProvider<'_>, gid: &[u8]) -> Result<MlsGroup, String> {
        MlsGroup::load(p.storage(), &GroupId::from_slice(gid))
            .map_err(|e| format!("load: {e:?}"))?
            .ok_or_else(|| "no group".to_string())
    }

    /// The reload oracle: the group as the call left it in memory against the group reloaded from
    /// the rows the call's change-set produced.
    fn check_reload(
        &mut self,
        fingerprint: (u64, Vec<u8>, Vec<u8>, u32, Vec<u8>),
    ) -> Result<(), String> {
        let gid = self.group_id.clone();
        let reloaded = self.call(|p| {
            let g = Self::load(p, &gid)?;
            Ok(fingerprint_of(&g, p.crypto()))
        })?;
        self.reload_checks += 1;
        if reloaded != fingerprint {
            return Err("reload oracle: reloaded group differs from the in-memory group".into());
        }
        Ok(())
    }
}

fn fingerprint_of(
    g: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
) -> (u64, Vec<u8>, Vec<u8>, u32, Vec<u8>) {
    (
        g.epoch().as_u64(),
        g.epoch_authenticator().as_slice().to_vec(),
        g.tree_hash().to_vec(),
        g.own_leaf_index().u32(),
        g.export_secret(crypto, "ghost/v1/test/reload", b"", 32)
            .unwrap_or_default(),
    )
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .number_of_resumption_psks(16)
        .build()
}

/// Outcome of one vector: epochs verified (the initial one counts as 0), or where and why it stopped.
struct Outcome {
    suite: u16,
    epochs_total: usize,
    epochs_ok: usize,
    initial_ok: bool,
    stop: Option<String>,
    reloads: usize,
}

fn run(v: &Vector) -> Outcome {
    let mut o = Outcome {
        suite: v.cipher_suite,
        epochs_total: v.epochs.len(),
        epochs_ok: 0,
        initial_ok: false,
        stop: None,
        reloads: 0,
    };
    let crypto = CryptoProvider::new().unwrap();
    let Ok(suite) = Ciphersuite::try_from(v.cipher_suite) else {
        o.stop = Some("unknown suite".into());
        return o;
    };
    if crypto.supports(suite).is_err() {
        o.stop = Some("suite not supported by the libcrux provider".into());
        return o;
    }
    // The group id is known only from the Welcome; key injection happens under a placeholder id
    // (global rows only), then the passive client switches to the real one.
    let mut pc = Passive {
        crypto,
        group_id: vec![0u8],
        rows: BTreeMap::new(),
        reload_checks: 0,
    };
    let inject = pc.call(|p| {
        for psk in &v.external_psks {
            PreSharedKeyId::external(psk.psk_id.clone(), vec![])
                .store(p, &psk.psk)
                .map_err(|e| format!("psk: {e:?}"))?;
        }
        let kp_in = match MlsMessageIn::tls_deserialize_exact(&v.key_package)
            .map_err(|e| format!("{e:?}"))?
            .extract()
        {
            MlsMessageBodyIn::KeyPackage(k) => k,
            _ => return Err("not a KeyPackage".into()),
        };
        let kp: KeyPackage = kp_in.into();
        let bundle = KeyPackageBundle::new(
            kp.clone(),
            v.init_priv.clone().into(),
            v.encryption_priv.clone().into(),
        );
        let r = kp.hash_ref(p.crypto()).map_err(|e| format!("{e:?}"))?;
        p.storage()
            .write_key_package(&r, &bundle)
            .map_err(|e| format!("{e:?}"))
    });
    if let Err(e) = inject {
        o.stop = Some(format!("inject: {e}"));
        return o;
    }
    let welcome = match MlsMessageIn::tls_deserialize_exact(&v.welcome).map(|m| m.extract()) {
        Ok(MlsMessageBodyIn::Welcome(w)) => w,
        _ => {
            o.stop = Some("welcome does not parse".into());
            return o;
        }
    };
    let tree: Option<RatchetTreeIn> = v
        .ratchet_tree
        .as_ref()
        .map(|t| RatchetTreeIn::tls_deserialize_exact(&t.0).unwrap());
    // Learn the group id from the Welcome's GroupInfo, then join under it.
    let gid = {
        let p = GhostProvider {
            crypto: &pc.crypto,
            storage: GhostKv::for_group(&[0u8], 0),
        };
        p.storage.load_plain(pc.rows.clone());
        match ProcessedWelcome::new_from_welcome(&p, &join_config(), welcome.clone()) {
            Ok(pw) => pw.unverified_group_info().group_id().as_slice().to_vec(),
            Err(e) => {
                o.stop = Some(format!("welcome: {e:?}"));
                return o;
            }
        }
    };
    pc.group_id = gid.clone();
    // How the join fares without skip_lifetime_validation() (a trial on a copy of the rows).
    {
        let saved = pc.rows.clone();
        let w2 = welcome.clone();
        let t2 = tree.clone();
        let strict = pc.call(|p| {
            let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), w2)
                .map_err(|e| format!("{e:?}"))?;
            let mut jb = JoinBuilder::new(p, pw);
            if let Some(t) = t2 {
                jb = jb.with_ratchet_tree(t);
            }
            jb.build().map(|_| ()).map_err(|e| format!("{e:?}"))
        });
        pc.rows = saved;
        if let Err(e) = strict {
            println!(
                "V10-12 STRICT-JOIN refused without skip_lifetime_validation (suite 0x{:04x}): {}",
                v.cipher_suite,
                e.chars().take(160).collect::<String>()
            );
        } else {
            println!(
                "V10-12 STRICT-JOIN accepted (suite 0x{:04x})",
                v.cipher_suite
            );
        }
    }
    let joined = pc.call(|p| {
        let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), welcome)
            .map_err(|e| format!("{e:?}"))?;
        let mut jb = JoinBuilder::new(p, pw).skip_lifetime_validation();
        if let Some(t) = tree {
            jb = jb.with_ratchet_tree(t);
        }
        let g = jb
            .build()
            .map_err(|e| format!("join: {e:?}"))?
            .into_group(p)
            .map_err(|e| format!("into_group: {e:?}"))?;
        Ok(fingerprint_of(&g, p.crypto()))
    });
    let fp = match joined {
        Ok(fp) => fp,
        Err(e) => {
            o.stop = Some(e);
            return o;
        }
    };
    if let Err(e) = pc.check_reload(fp.clone()) {
        o.stop = Some(e);
        return o;
    }
    if fp.1 != v.initial_epoch_authenticator {
        o.stop = Some("initial epoch_authenticator differs".into());
        return o;
    }
    o.initial_ok = true;
    for (i, ep) in v.epochs.iter().enumerate() {
        for prop in &ep.proposals {
            let r = pc.call(|p| {
                let mut g = Passive::load(p, &gid)?;
                let m =
                    MlsMessageIn::tls_deserialize_exact(&prop.0).map_err(|e| format!("{e:?}"))?;
                let pm = m.into_protocol_message().ok_or("not a protocol message")?;
                let processed = g
                    .process_message(p, pm)
                    .map_err(|e| format!("proposal: {e:?}"))?;
                match processed.into_content() {
                    ProcessedMessageContent::ProposalMessage(q) => g
                        .store_pending_proposal(p.storage(), *q)
                        .map_err(|e| format!("{e:?}"))?,
                    _ => return Err("proposal message expected".into()),
                }
                Ok(fingerprint_of(&g, p.crypto()))
            });
            match r {
                Ok(fp) => {
                    if let Err(e) = pc.check_reload(fp) {
                        o.stop = Some(format!("epoch {}: {e}", i + 1));
                        o.reloads = pc.reload_checks;
                        return o;
                    }
                }
                Err(e) => {
                    o.stop = Some(format!("epoch {}: {e}", i + 1));
                    o.reloads = pc.reload_checks;
                    return o;
                }
            }
        }
        let r = pc.call(|p| {
            let mut g = Passive::load(p, &gid)?;
            let m =
                MlsMessageIn::tls_deserialize_exact(&ep.commit).map_err(|e| format!("{e:?}"))?;
            let pm = m.into_protocol_message().ok_or("not a protocol message")?;
            let processed = g
                .process_message(p, pm)
                .map_err(|e| format!("commit: {e:?}"))?;
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(sc) => {
                    for a in sc.add_proposals() {
                        let lt = a.add_proposal().key_package().life_time();
                        println!(
                            "V10-12 ADD-LIFETIME not_before {} not_after {}",
                            lt.not_before(),
                            lt.not_after()
                        );
                    }
                    g.merge_staged_commit(p, *sc)
                        .map_err(|e| format!("merge: {e:?}"))?
                }
                _ => return Err("commit expected".into()),
            }
            Ok(fingerprint_of(&g, p.crypto()))
        });
        match r {
            Ok(fp) => {
                if let Err(e) = pc.check_reload(fp.clone()) {
                    o.stop = Some(format!("epoch {}: {e}", i + 1));
                    break;
                }
                if fp.1 != ep.epoch_authenticator {
                    o.stop = Some(format!("epoch {}: epoch_authenticator differs", i + 1));
                    break;
                }
                o.epochs_ok += 1;
            }
            Err(e) => {
                o.stop = Some(format!("epoch {}: {e}", i + 1));
                break;
            }
        }
    }
    o.reloads = pc.reload_checks;
    o
}

#[test]
fn v10_12_passive_client_through_ghostkv() {
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    let mut total_vectors = 0;
    let mut grand_epochs = 0;
    let mut grand_ok = 0;
    for file in [
        "passive-client-welcome.json",
        "passive-client-handling-commit.json",
        "passive-client-random.json",
    ] {
        let path = dir.join(file);
        let Ok(text) = std::fs::read_to_string(&path) else {
            panic!(
                "{} missing: run scripts/v10-12-fetch-vectors.sh first",
                path.display()
            );
        };
        let vectors: Vec<Vector> = serde_json::from_str(&text).expect("vector file parses");
        let mut by_suite: BTreeMap<u16, (usize, usize, usize, usize, usize)> = BTreeMap::new();
        let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
        for (i, v) in vectors.iter().enumerate() {
            let o = run(v);
            let e = by_suite.entry(o.suite).or_default();
            e.0 += 1; // vectors
            if o.stop.is_none() {
                e.1 += 1; // fully replayed
            }
            if o.initial_ok {
                e.2 += 1; // joined with the right initial authenticator
            }
            e.3 += o.epochs_ok;
            e.4 += o.epochs_total;
            if let Some(s) = &o.stop {
                // Normalise the reason (drop numbers) for the summary.
                let key: String = s
                    .split(':')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(":")
                    .chars()
                    .take(140)
                    .collect();
                *reasons
                    .entry(if key.is_empty() { s.clone() } else { key })
                    .or_default() += 1;
                println!("V10-12 {file} #{i:>3} suite 0x{:04x}: {}/{} epochs, stopped: {s} (reload checks {})", o.suite, o.epochs_ok, o.epochs_total, o.reloads);
            } else {
                println!(
                    "V10-12 {file} #{i:>3} suite 0x{:04x}: all {} epochs match (reload checks {})",
                    o.suite, o.epochs_total, o.reloads
                );
            }
            if crate_supported(o.suite) {
                grand_epochs += o.epochs_total;
                grand_ok += o.epochs_ok;
            }
        }
        total_vectors += vectors.len();
        for (s, (n, full, init, ok, tot)) in &by_suite {
            println!("V10-12 SUMMARY {file} suite 0x{s:04x}: {n} vectors, {full} fully replayed, {init} joined, {ok}/{tot} epochs");
        }
        for (r, n) in &reasons {
            println!("V10-12 REASON {file} x{n}: {r}");
        }
    }
    println!("V10-12 TOTAL {total_vectors} vectors; epochs replayed on the libcrux suites: {grand_ok}/{grand_epochs}");
}

fn crate_supported(suite: u16) -> bool {
    matches!(suite, 1 | 3)
}
