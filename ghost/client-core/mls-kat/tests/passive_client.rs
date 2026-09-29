//! The MLS WG passive-client vectors (`vectors/`, the openmls repository's copies at
//! 3a3e35de…, verified by SHA-256 here) replayed **through GhostKv under value semantics** with
//! the libcrux provider (design §12.2 item (2), §10.1; V10-12, S0-13): every call loads the stored
//! rows into a fresh adapter, runs, and applies the change-set only on success; after **every**
//! call the reload oracle's fingerprint half compares the in-memory group with one reloaded from
//! the rows (epoch, `epoch_authenticator`, tree hash, own leaf, an exporter output).
//!
//! **What it proves (S0-13):** that the adapter — value semantics, scopes, the day rewrite, the
//! per-epoch rows of past epochs — carries OpenMLS's own processing of independently produced
//! commits without loss. **What it does not:** GHOST's join path. It joins through OpenMLS's
//! `JoinBuilder` with the vectors' configuration (mixed plaintext, 16 resumption PSKs), never
//! through `welcome_join`, whose structural checks and CO-2 (A) the vectors' KeyPackages fail by
//! design (lifetimes `[0, u64::MAX]`, no `GhostLeaf` or `GhostKpBind`). The behavioural half of
//! the oracle needs application messages, which these vectors do not carry; it runs in
//! `ghost-client-mls`'s own worlds (`tests/state.rs`).
//!
//! Three configurations per vector: (A) OpenMLS's default join retention (no past epoch); (B) 16
//! retained past epochs in OpenMLS's single `MessageSecrets` value; (C) the same split into one row
//! per past epoch (the product layout, S0-6). (B) and (C) are compared byte for byte on the
//! reassembled `MessageSecretsStore` after every call.

use std::collections::BTreeMap;

use ghost_client_mls::kv::{label_of, GhostKv, PastLayout, RowKey, Scope};
use ghost_client_mls::provider::GhostProvider;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls::schedule::PreSharedKeyId;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::storage::StorageProvider as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

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

#[derive(Clone, Copy)]
struct Config {
    past: usize,
    layout: PastLayout,
}

type Fingerprint = (u64, Vec<u8>, Vec<u8>, u32, Vec<u8>);

/// One passive client: its crypto context and its committed rows.
struct Passive {
    crypto: CryptoProvider,
    group_id: Vec<u8>,
    rows: BTreeMap<RowKey, Vec<u8>>,
    reload_checks: usize,
    cfg: Config,
    secrets_trace: Vec<Vec<u8>>,
}

fn adapter(group_id: &[u8], layout: PastLayout) -> GhostKv {
    GhostKv::for_group(group_id, Sha256::digest(group_id).into(), 0).with_layout(layout)
}

impl Passive {
    fn call<T>(
        &mut self,
        f: impl FnOnce(&GhostProvider<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let provider = GhostProvider {
            crypto: &self.crypto,
            storage: adapter(&self.group_id, self.cfg.layout),
        };
        provider
            .storage
            .load(self.rows.clone().into_iter().collect())
            .map_err(|e| format!("load: {e:?}"))?;
        let out = f(&provider)?;
        let changes = provider.storage.take_plain_changes();
        let wrote_secrets = changes
            .keys()
            .any(|(_, k)| label_of(k).starts_with(b"MessageSecrets"));
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
    /// the per-epoch rows in the split layout.
    fn reassembled_secrets(&self) -> Option<Vec<u8>> {
        let head = self
            .rows
            .iter()
            .find(|((s, k), _)| *s == Scope::Group && label_of(k) == b"MessageSecrets")
            .map(|(_, v)| v.clone())?;
        let mut v: serde_json::Value = serde_json::from_slice(&head).ok()?;
        if self.cfg.layout == PastLayout::Split {
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

    /// The reload oracle (fingerprint half).
    fn check_reload(&mut self, fingerprint: Fingerprint) -> Result<(), String> {
        let gid = self.group_id.clone();
        let reloaded = self.call(|p| {
            let g = Self::load(p, &gid)?;
            Ok(fingerprint_of(&g, p.crypto()))
        })?;
        self.reload_checks += 1;
        if reloaded != fingerprint {
            return Err(
                "reload oracle: the reloaded group differs from the in-memory group".into(),
            );
        }
        Ok(())
    }
}

fn fingerprint_of(g: &MlsGroup, crypto: &impl OpenMlsCrypto) -> Fingerprint {
    (
        g.epoch().as_u64(),
        g.epoch_authenticator().as_slice().to_vec(),
        g.public_group().group_context().tree_hash().to_vec(),
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

struct Outcome {
    suite: u16,
    epochs_total: usize,
    epochs_ok: usize,
    initial_ok: bool,
    stop: Option<String>,
    reloads: usize,
    strict_join_refused: bool,
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
    // The group id is known only from the Welcome: the keys are injected under a placeholder id
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
    let gid = {
        let p = GhostProvider {
            crypto: &pc.crypto,
            storage: adapter(&[0u8], cfg.layout),
        };
        p.storage
            .load(pc.rows.clone().into_iter().collect())
            .unwrap();
        match ProcessedWelcome::new_from_welcome(&p, &join_config(cfg.past), welcome.clone()) {
            Ok(pw) => pw.unverified_group_info().group_id().as_slice().to_vec(),
            Err(e) => {
                o.stop = Some(format!("welcome: {e:?}"));
                return o;
            }
        }
    };
    // The global rows move to the real group's adapter (their keys carry no group id).
    pc.group_id = gid.clone();
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
            // KAT-only: the vectors carry standalone proposals, which GHOST never stores (§6.3.2).
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

/// The committed files, checked against `vectors/SOURCE.txt` before use.
fn vector_file(name: &str) -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let source = std::fs::read_to_string(dir.join("SOURCE.txt")).expect("SOURCE.txt");
    let want = source
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 3 && f[0] == name).then(|| f[1].to_string())
        })
        .expect("the file is listed in SOURCE.txt");
    let text = std::fs::read(dir.join(name)).expect("vector file");
    assert_eq!(
        hex::encode(Sha256::digest(&text)),
        want,
        "{name}: SHA-256 differs from SOURCE.txt"
    );
    String::from_utf8(text).unwrap()
}

#[test]
fn passive_client_vectors_through_ghostkv() {
    assert_eq!(ghost_client_mls::pin_rayon_single_worker(), 1);
    let (a, b, c) = (
        Config {
            past: 0,
            layout: PastLayout::Split,
        },
        Config {
            past: 16,
            layout: PastLayout::Whole,
        },
        Config {
            past: 16,
            layout: PastLayout::Split,
        },
    );
    let mut total_vectors = 0;
    let mut by_suite: BTreeMap<u16, (usize, usize, usize, usize, usize)> = BTreeMap::new();
    let (mut reloads, mut strict_refused, mut adds, mut unbounded_adds) = (0, 0, 0, 0);
    let (mut bc_equal, mut bc_compared, mut max_past_seen) = (0usize, 0usize, 0usize);
    for file in [
        "passive-client-welcome.json",
        "passive-client-handling-commit.json",
        "passive-client-random.json",
    ] {
        let vectors: Vec<Vector> =
            serde_json::from_str(&vector_file(file)).expect("vector file parses");
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
            assert!(o.stop.is_none(), "{file} #{i}: {:?}", o.stop);
            reloads += o.reloads;
            strict_refused += usize::from(o.strict_join_refused);
            adds += o.add_lifetimes.len();
            unbounded_adds += o
                .add_lifetimes
                .iter()
                .filter(|(nb, na)| *nb == 0 && *na == u64::MAX)
                .count();
            let ob = run(v, b);
            let oc = run(v, c);
            assert!(
                ob.stop.is_none() && oc.stop.is_none(),
                "{file} #{i}: B {:?} C {:?}",
                ob.stop,
                oc.stop
            );
            assert_eq!(
                (ob.epochs_ok, oc.epochs_ok),
                (o.epochs_total, o.epochs_total)
            );
            assert_eq!(ob.secrets_trace.len(), oc.secrets_trace.len());
            bc_compared += ob.secrets_trace.len();
            bc_equal += ob
                .secrets_trace
                .iter()
                .zip(&oc.secrets_trace)
                .filter(|(x, y)| x == y)
                .count();
            if let Some(last) = ob.secrets_trace.last() {
                let v: serde_json::Value = serde_json::from_slice(last).unwrap();
                max_past_seen =
                    max_past_seen.max(v["past_epoch_trees"].as_array().map_or(0, Vec::len));
            }
        }
    }
    let provider: Vec<_> = by_suite
        .iter()
        .filter(|(s, _)| provider_suite(**s))
        .collect();
    let pv: usize = provider.iter().map(|(_, e)| e.0).sum();
    let (pok, ptot): (usize, usize) = provider
        .iter()
        .fold((0, 0), |a, (_, e)| (a.0 + e.3, a.1 + e.4));
    // The totals of V10-12 (S0-13): 148 vectors, 43 of the provider's suites (0x0001, 0x0003),
    // 252 of 252 epochs, suite 0x0003 21 vectors and 26 epochs; 1 861 reload checks; the joins that
    // need skip_lifetime_validation; every replayed Add at the lifetime [0, u64::MAX]; the split and
    // unsplit stores byte-identical after every call, 16 past epochs held at the end.
    assert_eq!(total_vectors, 148);
    assert_eq!((pv, pok, ptot), (43, 252, 252));
    assert_eq!(by_suite[&3].0, 21, "suite 0x0003: 21 vectors");
    assert_eq!(by_suite[&3].4, 26, "suite 0x0003: 26 epochs");
    assert_eq!(reloads, 1861);
    assert_eq!(strict_refused, 42);
    assert_eq!((adds, unbounded_adds), (1550, 1550));
    assert_eq!(bc_equal, bc_compared);
    assert!(bc_compared > 0);
    assert_eq!(max_past_seen, 16);
}
