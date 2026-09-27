//! V10-12: the MLS WG passive-client vectors (as the openmls repository carries them at the tag
//! commit 3a3e35de…, fetched by scripts/v10-12-fetch-vectors.sh) replayed **through GhostKv under
//! value semantics** with the libcrux provider: every call loads the stored rows into a fresh
//! adapter, runs, and applies the change-set only on success; after every call the reload oracle
//! compares the in-memory group with one reloaded from the rows (epoch, epoch_authenticator, tree
//! hash, own leaf, an exporter output). That is the **fingerprint half** of design §3.4 point 6
//! only: these vectors carry no application messages, so the behavioural half (a reloaded group
//! decrypts the next message and refuses a replay) cannot run on them; it runs in the spike's own
//! worlds (`core/tests/v10_05_adapter.rs`, `v10_05_split_matches_unsplit_on_late_posts`).
//!
//! What this replay is and is not (review finding I8): it exercises the adapter (`GhostKv`, value
//! semantics, the day rewrite, the optional split of past epochs) under OpenMLS's own processing of
//! independently produced commits. It joins through OpenMLS's `JoinBuilder` directly, with the
//! vectors' own configuration (mixed plaintext wire format, 16 resumption PSKs, day 0), **not**
//! through GHOST's `welcomeJoin`: the vectors' KeyPackages carry no `GhostLeaf` or `GhostKpBind`
//! and lifetimes of `[0, u64::MAX]`, which GHOST's join and CO-2 (A) refuse.
//!
//! Three configurations per vector: (A) OpenMLS's default join retention (no past epoch), the
//! first run's setting; (B) 16 retained past epochs; (C) the same with the past epochs split into
//! rows (S0-6). (B) and (C) are compared byte for byte on the reassembled `MessageSecretsStore`
//! after every call (the impact reviewer's R1, re-run).
//!
//! Run: `bash scripts/v10-12-fetch-vectors.sh && cargo test --release -p ghost-mls-spike-kat -- --nocapture`

use std::collections::BTreeMap;

use ghost_mls_spike::kv::{GhostKv, RowKey, Scope};
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

/// A replay configuration.
#[derive(Clone, Copy)]
struct Config {
    /// `max_past_epochs` of the join configuration (OpenMLS's default is 0).
    past: usize,
    /// `GhostKv`'s split of past epochs into rows (S0-6).
    split: bool,
}

/// One passive client: its crypto context and its committed rows.
struct Passive {
    crypto: CryptoProvider,
    group_id: Vec<u8>,
    rows: BTreeMap<RowKey, Vec<u8>>,
    reload_checks: usize,
    cfg: Config,
    /// The reassembled `MessageSecretsStore` after every call that wrote one (configurations B, C).
    secrets_trace: Vec<Vec<u8>>,
}

impl Passive {
    fn call<T>(
        &mut self,
        f: impl FnOnce(&GhostProvider<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut storage = GhostKv::for_group(&self.group_id, 0);
        storage.set_split_past(self.cfg.split);
        let provider = GhostProvider {
            crypto: &self.crypto,
            storage,
        };
        provider.storage.load_plain(self.rows.clone());
        let out = f(&provider)?;
        let (changes, _) = provider.storage.take_changes();
        let wrote_secrets = changes
            .keys()
            .any(|(_, k)| k.starts_with(b"MessageSecrets"));
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
        if wrote_secrets {
            if let Some(s) = self.reassembled_secrets() {
                self.secrets_trace.push(s);
            }
        }
        Ok(out)
    }

    /// The stored `MessageSecretsStore` as canonical JSON bytes, reassembled from the head row and
    /// the per-epoch rows in the split mode (the keys are those `GhostKv` writes).
    fn reassembled_secrets(&self) -> Option<Vec<u8>> {
        let head = self
            .rows
            .iter()
            .find(|((s, k), _)| *s == Scope::Group && k.starts_with(b"MessageSecrets\0"))
            .map(|(_, v)| v.clone())?;
        let mut v: serde_json::Value = serde_json::from_slice(&head).ok()?;
        if self.cfg.split {
            let gid = GroupId::from_slice(&self.group_id);
            let epochs: Vec<u64> = v["past_epoch_trees"]
                .as_array()?
                .iter()
                .filter_map(|e| e.as_u64())
                .collect();
            let mut trees = Vec::new();
            for e in epochs {
                let mut k = b"MessageSecretsPast\0".to_vec();
                k.extend_from_slice(&serde_json::to_vec(&(&gid, e)).ok()?);
                let row = self.rows.get(&(Scope::Group, k))?;
                trees.push(serde_json::from_slice::<serde_json::Value>(row).ok()?);
            }
            v["past_epoch_trees"] = serde_json::Value::Array(trees);
        }
        serde_json::to_vec(&v).ok()
    }

    fn load(p: &GhostProvider<'_>, gid: &[u8]) -> Result<MlsGroup, String> {
        MlsGroup::load(p.storage(), &GroupId::from_slice(gid))
            .map_err(|e| format!("load: {e:?}"))?
            .ok_or_else(|| "no group".to_string())
    }

    /// The reload oracle (fingerprint half): the group as the call left it in memory against the
    /// group reloaded from the rows the call's change-set produced.
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

fn join_config(past: usize) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .number_of_resumption_psks(16)
        .max_past_epochs(past)
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
    strict_join_refused: bool,
    /// Lifetimes of the KeyPackages of the Adds the replayed commits carried.
    add_lifetimes: Vec<(u64, u64)>,
    secrets_trace: Vec<Vec<u8>>,
}

fn run(v: &Vector, cfg: Config) -> Outcome {
    let mut o = Outcome {
        suite: v.cipher_suite,
        epochs_total: v.epochs.len(),
        epochs_ok: 0,
        initial_ok: false,
        stop: None,
        reloads: 0,
        strict_join_refused: false,
        add_lifetimes: Vec::new(),
        secrets_trace: Vec::new(),
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
        cfg,
        secrets_trace: Vec::new(),
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
        match ProcessedWelcome::new_from_welcome(&p, &join_config(cfg.past), welcome.clone()) {
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
            let pw = ProcessedWelcome::new_from_welcome(p, &join_config(cfg.past), w2)
                .map_err(|e| format!("{e:?}"))?;
            let mut jb = JoinBuilder::new(p, pw);
            if let Some(t) = t2 {
                jb = jb.with_ratchet_tree(t);
            }
            jb.build().map(|_| ()).map_err(|e| format!("{e:?}"))
        });
        pc.rows = saved;
        pc.secrets_trace.clear();
        o.strict_join_refused = strict.is_err();
    }
    let joined = pc.call(|p| {
        let pw = ProcessedWelcome::new_from_welcome(p, &join_config(cfg.past), welcome)
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
        let mut lifetimes = Vec::new();
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
                        lifetimes.push((lt.not_before(), lt.not_after()));
                    }
                    g.merge_staged_commit(p, *sc)
                        .map_err(|e| format!("merge: {e:?}"))?
                }
                _ => return Err("commit expected".into()),
            }
            Ok(fingerprint_of(&g, p.crypto()))
        });
        o.add_lifetimes.extend(lifetimes);
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
    o.secrets_trace = std::mem::take(&mut pc.secrets_trace);
    o
}

fn provider_suite(suite: u16) -> bool {
    matches!(suite, 1 | 3)
}

#[test]
fn v10_12_passive_client_through_ghostkv() {
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    let (a, b, c) = (
        Config {
            past: 0,
            split: false,
        },
        Config {
            past: 16,
            split: false,
        },
        Config {
            past: 16,
            split: true,
        },
    );
    let mut total_vectors = 0;
    // Per suite: (vectors, fully replayed, joined, epochs ok, epochs total) under configuration A.
    let mut by_suite: BTreeMap<u16, (usize, usize, usize, usize, usize)> = BTreeMap::new();
    let (mut reloads, mut strict_refused, mut adds, mut unbounded_adds) = (0, 0, 0, 0);
    let (mut bc_equal, mut bc_compared, mut bc_epochs, mut max_past_seen) =
        (0usize, 0usize, 0usize, 0usize);
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
        total_vectors += vectors.len();
        for (i, v) in vectors.iter().enumerate() {
            let o = run(v, a);
            let e = by_suite.entry(o.suite).or_default();
            e.0 += 1;
            e.1 += usize::from(o.stop.is_none());
            e.2 += usize::from(o.initial_ok);
            e.3 += o.epochs_ok;
            e.4 += o.epochs_total;
            if !provider_suite(o.suite) {
                continue;
            }
            println!(
                "V10-12 {file} #{i:>3} suite 0x{:04x}: {}/{} epochs{} (reload checks {})",
                o.suite,
                o.epochs_ok,
                o.epochs_total,
                o.stop
                    .as_ref()
                    .map_or(String::new(), |s| format!(", stopped: {s}")),
                o.reloads
            );
            assert!(o.stop.is_none(), "{file} #{i}: {:?}", o.stop);
            reloads += o.reloads;
            strict_refused += usize::from(o.strict_join_refused);
            adds += o.add_lifetimes.len();
            unbounded_adds += o
                .add_lifetimes
                .iter()
                .filter(|(nb, na)| *nb == 0 && *na == u64::MAX)
                .count();
            // B and C: 16 retained past epochs, unsplit and split, byte-identical stores.
            let ob = run(v, b);
            let oc = run(v, c);
            assert!(
                ob.stop.is_none() && oc.stop.is_none(),
                "{file} #{i}: B {:?} C {:?}",
                ob.stop,
                oc.stop
            );
            assert_eq!(ob.epochs_ok, o.epochs_total);
            assert_eq!(oc.epochs_ok, o.epochs_total);
            assert_eq!(ob.secrets_trace.len(), oc.secrets_trace.len());
            bc_compared += ob.secrets_trace.len();
            bc_equal += ob
                .secrets_trace
                .iter()
                .zip(&oc.secrets_trace)
                .filter(|(x, y)| x == y)
                .count();
            bc_epochs += ob.epochs_ok;
            if let Some(last) = ob.secrets_trace.last() {
                let v: serde_json::Value = serde_json::from_slice(last).unwrap();
                max_past_seen =
                    max_past_seen.max(v["past_epoch_trees"].as_array().map_or(0, Vec::len));
            }
        }
    }
    for (s, (n, full, init, ok, tot)) in &by_suite {
        println!("V10-12 SUMMARY suite 0x{s:04x}: {n} vectors, {full} fully replayed, {init} joined, {ok}/{tot} epochs");
    }
    let provider: Vec<_> = by_suite
        .iter()
        .filter(|(s, _)| provider_suite(**s))
        .collect();
    let pv: usize = provider.iter().map(|(_, e)| e.0).sum();
    let (pok, ptot): (usize, usize) = provider
        .iter()
        .fold((0, 0), |a, (_, e)| (a.0 + e.3, a.1 + e.4));
    println!(
        "V10-12 TOTAL {total_vectors} vectors; the provider's suites: {pv} vectors, {pok}/{ptot} epochs; reload-oracle checks (fingerprint half) {reloads}; joins refused without skip_lifetime_validation {strict_refused}/{pv}; Add KeyPackages {adds}, of which with the lifetime [0, u64::MAX] {unbounded_adds}"
    );
    println!(
        "V10-12 SPLIT (B = 16 past epochs unsplit, C = split): {bc_equal}/{bc_compared} reassembled MessageSecretsStore states byte-identical over {bc_epochs} epochs; most past epochs held {max_past_seen}"
    );
    assert_eq!(total_vectors, 148);
    assert_eq!((pv, pok, ptot), (43, 252, 252));
    assert_eq!(by_suite[&3].0, 21, "suite 0x0003: 21 vectors");
    assert_eq!(by_suite[&3].4, 26, "suite 0x0003: 26 epochs");
    assert_eq!(reloads, 1861);
    assert_eq!(strict_refused, 42);
    assert_eq!((adds, unbounded_adds), (1550, 1550));
    assert_eq!(bc_equal, bc_compared);
    assert_eq!(max_past_seen, 16);
}
