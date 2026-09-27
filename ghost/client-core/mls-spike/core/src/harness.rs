//! A small channel world over the real OpenMLS 0.9.0 with GHOST's configuration (design §3.5),
//! extensions (§5.3, §5.4), commit AAD (§19.2) and value semantics (§3.4): every operation of a
//! member loads the member's committed rows into a fresh `GhostKv`, runs, and applies the
//! change-set only on success. Used by the V10-4, V10-5, V10-8, V10-10, V10-11 and V10-13 tests.

use std::collections::BTreeMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::random::OpenMlsRand;

use crate::ext::{self, ChannelContext, CommitAad};
use crate::kv::{self, CallStats, GhostKv, RowKey, Scope};
use crate::provider::{GhostProvider, PseudonymSigner};

/// The P0 suite (D3).
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// V10-9: the suite the harness uses (0 = `SUITE`); set before a world is built.
pub static SUITE_OVERRIDE: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub fn suite() -> Ciphersuite {
    match SUITE_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => SUITE,
        s => Ciphersuite::try_from(s).expect("known suite"),
    }
}
pub const DAY_SECS: u64 = 86_400;

/// The split-past-epochs mode new devices start in (V10-5 compares both).
pub static DEFAULT_SPLIT_PAST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Today's UTC day number on the host clock (days since 1970-01-01).
pub fn host_day() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / DAY_SECS) as u32
}

/// §3.5 KeyPackage lifetime: `[day_start(day) − 4 d, day_start(day) + 80 d]`.
pub fn ghost_lifetime(day: u32) -> Lifetime {
    let start = u64::from(day) * DAY_SECS;
    Lifetime::init(start - 4 * DAY_SECS, start + 80 * DAY_SECS)
}

/// Leaf capabilities of §3.5: the suite, GHOST's three extension types, Basic credentials.
/// `extra_types` appends that many further (unknown, private-use) extension types: each costs
/// two bytes and is how a malicious joiner inflates a KeyPackage up to §6.2.4's 1 024-byte bound.
pub fn ghost_capabilities(suite: Ciphersuite, extra_types: usize) -> Capabilities {
    let mut exts = vec![
        ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
        ExtensionType::Unknown(ext::EXT_LEAF),
        ExtensionType::Unknown(ext::EXT_KP_BIND),
    ];
    for i in 0..extra_types {
        exts.push(ExtensionType::Unknown(0xF100 + i as u16));
    }
    Capabilities::new(
        None,
        Some(&[suite]),
        Some(&exts),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// `RequiredCapabilities` of the group: 0xF0A1 and 0xF0A2 (§5.3).
pub fn required_capabilities() -> Extension {
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[
            ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
            ExtensionType::Unknown(ext::EXT_LEAF),
        ],
        &[],
        &[CredentialType::Basic],
    ))
}

pub fn context_extensions(ctx: &ChannelContext) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::Unknown(ext::EXT_CHANNEL_CONTEXT, UnknownExtension(ctx.encode())),
        required_capabilities(),
    ])
    .expect("valid group context extensions")
}

pub fn leaf_extensions(box_pk: &[u8; 32], refresh_epoch: u64) -> Extensions<LeafNode> {
    Extensions::single(Extension::Unknown(
        ext::EXT_LEAF,
        UnknownExtension(ext::leaf(box_pk, refresh_epoch)),
    ))
    .expect("valid leaf extensions")
}

/// The join configuration of §3.5.
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(0)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(16, 1000))
        .max_past_epochs(64)
        .build()
}

pub fn ser(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().expect("serialise MlsMessageOut")
}

/// Counters of one value-semantics call (V10-5).
#[derive(Clone, Debug, Default)]
pub struct CallReport {
    /// Rows loaded before the call and their plaintext and wrapped bytes.
    pub rows_in: usize,
    pub group_rows_in: usize,
    pub bytes_in: usize,
    pub wrapped_in: usize,
    /// Net change-set: rows put and deleted, plaintext and wrapped bytes put.
    pub net_puts: usize,
    pub net_deletes: usize,
    pub net_put_bytes: usize,
    pub wrapped_out: usize,
    pub raw: CallStats,
    /// Wall time of the whole call: unwrap every row, load, run, wrap the change-set.
    pub micros: u128,
    /// Of which the OpenMLS operation alone (excluding unwrap, load and wrap).
    pub op_micros: u128,
    /// Of which the per-row unwrap and wrap.
    pub wrap_micros: u128,
}

/// One device: its pseudonym signer, its crypto context and its committed rows.
pub struct Device {
    pub id: usize,
    pub signer: PseudonymSigner,
    pub pk: [u8; 32],
    pub crypto: CryptoProvider,
    /// Committed rows (plaintext; the wrapped form is measured, not kept).
    pub rows: BTreeMap<RowKey, Vec<u8>>,
    pub day: u32,
    /// When set, every call unwraps its input rows and wraps its change-set under this key.
    pub wrap_key: Option<[u8; 32]>,
    /// GhostKv's split-past-epochs mode (V10-5 candidate fix).
    pub split_past: bool,
    pub last: CallReport,
}

#[derive(Debug)]
pub struct Received {
    pub kind: &'static str,
    pub aad: Vec<u8>,
    pub sender: Option<u32>,
    pub plaintext: Vec<u8>,
    pub adds: usize,
    pub removes: usize,
    pub update_leaf_ext: Option<Vec<u8>>,
    pub epoch_authenticator: Option<Vec<u8>>,
}

pub struct CommitOut {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info_exported: Option<Vec<u8>>,
}

/// What a commit carries (the proposals by value of §6.2.3 and the AAD of §19.2).
#[derive(Default, Clone)]
pub struct CommitSpec {
    pub adds: Vec<KeyPackage>,
    pub removes: Vec<LeafNodeIndex>,
    pub context: Option<ChannelContext>,
    pub aad: CommitAad,
    /// `GhostLeaf.refresh_epoch` of the update-path leaf; `None` sends no leaf parameters.
    pub refresh_epoch: Option<u64>,
    pub force_path: bool,
    /// GroupInfo extensions for the Welcome (V10-8's `GhostBootstrap`).
    pub group_info_extensions: Vec<Extension>,
    /// `create_group_info(false)` after `load_psks` (no exported GroupInfo).
    pub no_exported_group_info: bool,
    /// V10-4 probe: bytes of an extra (unknown, private-use) extension in the update-path leaf,
    /// with its type added to the leaf capabilities (what a modified client can send).
    pub extra_leaf_bytes: usize,
}

impl Device {
    pub fn new(id: usize, day: u32) -> Self {
        let crypto = CryptoProvider::new().expect("crypto provider");
        let seed: [u8; 32] = crypto.random_array().expect("seed");
        let signer = PseudonymSigner::from_seed(&seed);
        let pk = signer.public();
        Self {
            id,
            signer,
            pk,
            crypto,
            rows: BTreeMap::new(),
            day,
            wrap_key: None,
            split_past: DEFAULT_SPLIT_PAST.load(std::sync::atomic::Ordering::Relaxed),
            last: CallReport::default(),
        }
    }

    pub fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.pk.to_vec()).into(),
            signature_key: self.pk.to_vec().into(),
        }
    }

    fn random32(&self) -> [u8; 32] {
        self.crypto.random_array().expect("random")
    }

    /// Runs `f` under value semantics: fresh adapter, committed rows, change-set applied on Ok.
    pub fn call<T, E: core::fmt::Debug>(
        &mut self,
        channel: &[u8; 32],
        f: impl FnOnce(&GhostProvider<'_>, &PseudonymSigner) -> Result<T, E>,
    ) -> Result<T, String> {
        let mut rep = CallReport {
            rows_in: self.rows.len(),
            ..Default::default()
        };
        rep.group_rows_in = self.rows.keys().filter(|(s, _)| *s == Scope::Group).count();
        rep.bytes_in = self.rows.values().map(Vec::len).sum();
        rep.wrapped_in = self.rows.values().map(|v| 12 + v.len() + 16).sum();
        // Kotlin's stored form, prepared outside the timed section.
        let wrapped: Option<Vec<(RowKey, Vec<u8>)>> = self.wrap_key.map(|k| {
            self.rows
                .iter()
                .enumerate()
                .map(|(i, (rk, v))| {
                    let mut n = [0u8; 12];
                    n[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    (rk.clone(), kv::wrap(&k, n, rk.0, channel, &rk.1, v))
                })
                .collect()
        });
        let t0 = Instant::now();
        let mut storage = GhostKv::new(*channel, self.day);
        storage.set_split_past(self.split_past);
        let provider = GhostProvider {
            crypto: &self.crypto,
            storage,
        };
        let mut wrap_t = 0u128;
        match (&wrapped, self.wrap_key) {
            (Some(w), Some(k)) => {
                let tw = Instant::now();
                let plain: Vec<(RowKey, Vec<u8>)> = w
                    .iter()
                    .map(|(rk, env)| {
                        (
                            rk.clone(),
                            kv::unwrap(&k, rk.0, channel, &rk.1, env).expect("row opens"),
                        )
                    })
                    .collect();
                wrap_t += tw.elapsed().as_micros();
                provider.storage.load_plain(plain);
            }
            _ => provider.storage.load_plain(self.rows.clone()),
        }
        let t1 = Instant::now();
        let out = f(&provider, &self.signer);
        let op = t1.elapsed().as_micros();
        match out {
            Ok(v) => {
                let (changes, stats) = provider.storage.take_changes();
                let tw = Instant::now();
                for (rk, val) in &changes {
                    match val {
                        Some(v) => {
                            rep.net_puts += 1;
                            rep.net_put_bytes += v.len();
                            if let Some(k) = self.wrap_key {
                                let env = kv::wrap(&k, [7u8; 12], rk.0, channel, &rk.1, v);
                                rep.wrapped_out += env.len();
                            } else {
                                rep.wrapped_out += 12 + v.len() + 16;
                            }
                        }
                        None => rep.net_deletes += 1,
                    }
                }
                wrap_t += tw.elapsed().as_micros();
                rep.raw = stats;
                rep.micros = t0.elapsed().as_micros();
                rep.op_micros = op;
                rep.wrap_micros = wrap_t;
                for (rk, val) in changes {
                    match val {
                        Some(v) => {
                            self.rows.insert(rk, v);
                        }
                        None => {
                            self.rows.remove(&rk);
                        }
                    }
                }
                self.last = rep;
                Ok(v)
            }
            Err(e) => {
                self.last = rep;
                Err(format!("{e:?}"))
            }
        }
    }

    /// Like `call`, but never applies the change-set (a validation or trial run, CO-2, CO-3).
    pub fn dry_call<T, E: core::fmt::Debug>(
        &mut self,
        channel: &[u8; 32],
        f: impl FnOnce(&GhostProvider<'_>, &PseudonymSigner) -> Result<T, E>,
    ) -> Result<(T, CallReport), String> {
        let saved = self.rows.clone();
        let r = self.call(channel, f);
        let rep = self.last.clone();
        self.rows = saved;
        r.map(|v| (v, rep))
    }

    pub fn load(p: &GhostProvider<'_>, channel: &[u8; 32]) -> Result<MlsGroup, String> {
        MlsGroup::load(p.storage(), &GroupId::from_slice(channel))
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "no group".to_string())
    }

    /// `groupCreate` (§6.1).
    pub fn create_group(&mut self, channel: [u8; 32], ctx: &ChannelContext) -> Result<(), String> {
        let box_pk = self.random32();
        let cred = self.credential();
        let day = self.day;
        self.call(&channel, |p, s| {
            MlsGroup::builder()
                .with_group_id(GroupId::from_slice(&channel))
                .ciphersuite(suite())
                .padding_size(0)
                .use_ratchet_tree_extension(true)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(16, 1000))
                .max_past_epochs(64)
                .lifetime(ghost_lifetime(day))
                .with_capabilities(ghost_capabilities(suite(), 0))
                .with_group_context_extensions(context_extensions(ctx))
                .with_leaf_node_extensions(leaf_extensions(&box_pk, 0))
                .map_err(|e| format!("{e:?}"))?
                .build(p, s, cred)
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        })
    }

    /// `keyPackage` (§6.2.2): lifetime, `GhostLeaf`, `GhostKpBind`, capabilities. Returns the
    /// MlsMessage bytes the join request carries. `extra_types` inflates the capabilities.
    pub fn key_package(
        &mut self,
        channel: [u8; 32],
        purpose: u8,
        kp_day: u32,
        extra_types: usize,
    ) -> Result<Vec<u8>, String> {
        self.key_package_with(
            channel,
            purpose,
            ghost_lifetime(kp_day),
            kp_day,
            extra_types,
            0,
        )
    }

    pub fn key_package_with(
        &mut self,
        channel: [u8; 32],
        purpose: u8,
        lifetime: Lifetime,
        bind_day: u32,
        extra_types: usize,
        extra_leaf_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let box_pk = self.random32();
        let cred = self.credential();
        self.call(&channel, |p, s| {
            let mut leaf_exts = vec![Extension::Unknown(
                ext::EXT_LEAF,
                UnknownExtension(ext::leaf(&box_pk, 0)),
            )];
            if extra_leaf_bytes > 0 {
                leaf_exts.push(Extension::Unknown(
                    0xF100,
                    UnknownExtension(vec![0x5a; extra_leaf_bytes]),
                ));
            }
            let kpb = KeyPackage::builder()
                .key_package_lifetime(lifetime)
                .leaf_node_capabilities(ghost_capabilities(
                    suite(),
                    extra_types.max(usize::from(extra_leaf_bytes > 0)),
                ))
                .leaf_node_extensions(
                    Extensions::from_vec(leaf_exts).map_err(|e| format!("{e:?}"))?,
                )
                .key_package_extensions(
                    Extensions::single(Extension::Unknown(
                        ext::EXT_KP_BIND,
                        UnknownExtension(ext::kp_bind(&channel, purpose, bind_day)),
                    ))
                    .map_err(|e| format!("{e:?}"))?,
                )
                .build(suite(), p, s, cred)
                .map_err(|e| format!("{e:?}"))?;
            let m = MlsMessageOut::from(kpb.key_package().clone());
            Ok::<_, String>(ser(&m))
        })
    }

    /// The committer's parse of a join request's KeyPackage (OpenMLS's `KeyPackageIn::validate`,
    /// which checks the lifetime against this device's `SystemTime::now()`).
    pub fn parse_key_package(&self, bytes: &[u8]) -> Result<KeyPackage, String> {
        let m = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| format!("{e:?}"))?;
        match m.extract() {
            MlsMessageBodyIn::KeyPackage(kp) => kp
                .validate(&self.crypto, ProtocolVersion::Mls10)
                .map_err(|e| format!("{e:?}")),
            _ => Err("not a key package".into()),
        }
    }

    /// `commit` (§10.2 fn 9): proposals by value, `GhostCommitAad` through `set_aad`, a forced path
    /// whose leaf carries `GhostLeaf.refresh_epoch`, and the Welcome with the ratchet tree.
    pub fn commit(&mut self, channel: [u8; 32], spec: &CommitSpec) -> Result<CommitOut, String> {
        let box_pk = self.random32();
        self.call(&channel, |p, s| {
            let mut g = Self::load(p, &channel)?;
            g.set_aad(spec.aad.encode());
            let mut b = g
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(spec.force_path)
                .propose_removals(spec.removes.iter().copied())
                .propose_adds(spec.adds.iter().cloned());
            if let Some(ctx) = &spec.context {
                b = b
                    .propose_group_context_extensions(context_extensions(ctx))
                    .map_err(|e| format!("{e:?}"))?;
            }
            if let Some(e) = spec.refresh_epoch {
                let mut params = LeafNodeParameters::builder();
                if spec.extra_leaf_bytes > 0 {
                    let exts = Extensions::from_vec(vec![
                        Extension::Unknown(ext::EXT_LEAF, UnknownExtension(ext::leaf(&box_pk, e))),
                        Extension::Unknown(
                            0xF100,
                            UnknownExtension(vec![0x5a; spec.extra_leaf_bytes]),
                        ),
                    ])
                    .map_err(|e| format!("{e:?}"))?;
                    params = params
                        .with_extensions(exts)
                        .with_capabilities(ghost_capabilities(suite(), 1));
                } else {
                    params = params.with_extensions(leaf_extensions(&box_pk, e));
                }
                b = b.leaf_node_parameters(params.build());
            }
            let mut b = b.load_psks(p.storage()).map_err(|e| format!("{e:?}"))?;
            if !spec.group_info_extensions.is_empty() {
                b = b
                    .create_group_info_with_extensions(spec.group_info_extensions.clone())
                    .map_err(|e| format!("{e:?}"))?;
            }
            if spec.no_exported_group_info {
                b = b.create_group_info(false);
            }
            let bundle = b
                .build(p.rand(), p.crypto(), s, |_| true)
                .map_err(|e| format!("{e:?}"))?
                .stage_commit(p)
                .map_err(|e| format!("{e:?}"))?;
            let (c, w, gi) = bundle.into_messages();
            Ok::<_, String>(CommitOut {
                commit: ser(&c),
                welcome: w.map(|w| ser(&w)),
                group_info_exported: gi.map(|g| ser(&g)),
            })
        })
    }

    /// Merges the member's own pending commit (CO-5 for an own winner).
    pub fn merge_own(&mut self, channel: [u8; 32]) -> Result<(), String> {
        self.call(&channel, |p, _| {
            let mut g = Self::load(p, &channel)?;
            g.merge_pending_commit(p).map_err(|e| format!("{e:?}"))
        })
    }

    /// Clears the own pending commit (a lost candidate).
    pub fn clear_own(&mut self, channel: [u8; 32]) -> Result<(), String> {
        self.call(&channel, |p, _| {
            let mut g = Self::load(p, &channel)?;
            g.clear_pending_commit(p.storage())
                .map_err(|e| format!("{e:?}"))
        })
    }

    /// `receive` with `merge = true` persists and merges a commit (a settle); `false` is the
    /// validation run whose change-set is discarded by the caller (`dry_call`).
    fn receive_inner(
        p: &GhostProvider<'_>,
        channel: &[u8; 32],
        bytes: &[u8],
        merge: bool,
    ) -> Result<Received, String> {
        let mut g = Self::load(p, channel)?;
        let m = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| format!("{e:?}"))?;
        let pm = m
            .try_into_protocol_message()
            .map_err(|e| format!("{e:?}"))?;
        let processed = g.process_message(p, pm).map_err(|e| format!("{e:?}"))?;
        let aad = processed.aad().to_vec();
        let sender = match processed.sender() {
            Sender::Member(i) => Some(i.u32()),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => Ok(Received {
                kind: "app",
                aad,
                sender,
                plaintext: a.into_bytes(),
                adds: 0,
                removes: 0,
                update_leaf_ext: None,
                epoch_authenticator: None,
            }),
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                let adds = sc.add_proposals().count();
                let removes = sc.remove_proposals().count();
                let update_leaf_ext = sc
                    .update_path_leaf_node()
                    .and_then(|l| l.extensions().unknown(ext::EXT_LEAF).map(|u| u.0.clone()));
                let ea = sc.epoch_authenticator().map(|a| a.as_slice().to_vec());
                if merge {
                    g.merge_staged_commit(p, *sc)
                        .map_err(|e| format!("{e:?}"))?;
                }
                Ok(Received {
                    kind: "commit",
                    aad,
                    sender,
                    plaintext: vec![],
                    adds,
                    removes,
                    update_leaf_ext,
                    epoch_authenticator: ea,
                })
            }
            ProcessedMessageContent::ProposalMessage(_) => Err("proposal".into()),
            _ => Err("other content".into()),
        }
    }

    pub fn receive(&mut self, channel: [u8; 32], bytes: &[u8]) -> Result<Received, String> {
        self.call(&channel, |p, _| {
            Self::receive_inner(p, &channel, bytes, true)
        })
    }

    pub fn validate(
        &mut self,
        channel: [u8; 32],
        bytes: &[u8],
    ) -> Result<(Received, CallReport), String> {
        self.dry_call(&channel, |p, _| {
            Self::receive_inner(p, &channel, bytes, false)
        })
    }

    /// `welcomeJoin` (§6.2.5) with `skip_lifetime_validation()`; returns the GroupInfo's GHOST
    /// bootstrap extension read from the (then verified) GroupInfo, if present.
    pub fn join(
        &mut self,
        channel: [u8; 32],
        welcome: &[u8],
        skip_lifetimes: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        self.call(&channel, |p, _| {
            let m = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| format!("{e:?}"))?;
            let w = match m.extract() {
                MlsMessageBodyIn::Welcome(w) => w,
                _ => return Err("not a welcome".to_string()),
            };
            let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), w)
                .map_err(|e| format!("{e:?}"))?;
            let boot = pw
                .unverified_group_info()
                .extensions()
                .unknown(ext::EXT_BOOTSTRAP)
                .map(|u| u.0.clone());
            let mut jb = JoinBuilder::new(p, pw);
            if skip_lifetimes {
                jb = jb.skip_lifetime_validation();
            }
            let staged = jb.build().map_err(|e| format!("{e:?}"))?;
            staged.into_group(p).map_err(|e| format!("{e:?}"))?;
            Ok(boot)
        })
    }

    /// `encrypt` (§10.2 fn 10) with `ChannelOrder` in the MLS AAD.
    pub fn encrypt(
        &mut self,
        channel: [u8; 32],
        seq: u32,
        content: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.call(&channel, |p, s| {
            let mut g = Self::load(p, &channel)?;
            g.set_aad(ext::channel_order(g.own_leaf_index().u32(), seq));
            let m = g
                .create_message(p, s, content)
                .map_err(|e| format!("{e:?}"))?;
            Ok::<_, String>(ser(&m))
        })
    }

    pub fn epoch(&mut self, channel: [u8; 32]) -> u64 {
        self.dry_call(&channel, |p, _| {
            Self::load(p, &channel).map(|g| g.epoch().as_u64())
        })
        .unwrap()
        .0
    }

    pub fn leaf_index(&mut self, channel: [u8; 32]) -> u32 {
        self.dry_call(&channel, |p, _| {
            Self::load(p, &channel).map(|g| g.own_leaf_index().u32())
        })
        .unwrap()
        .0
    }

    pub fn authenticator(&mut self, channel: [u8; 32]) -> Vec<u8> {
        self.dry_call(&channel, |p, _| {
            Self::load(p, &channel).map(|g| g.epoch_authenticator().as_slice().to_vec())
        })
        .unwrap()
        .0
    }

    pub fn export(&mut self, channel: [u8; 32], label: &str) -> Vec<u8> {
        self.dry_call(&channel, |p, _| {
            let g = Self::load(p, &channel)?;
            g.export_secret(p.crypto(), label, &channel, 32)
                .map_err(|e| format!("{e:?}"))
        })
        .unwrap()
        .0
    }

    /// `sweepPast` (§10.2 fn 19): count-based deletion with `before_timestamp(UNIX_EPOCH)`.
    pub fn sweep_past(&mut self, channel: [u8; 32], keep: usize) -> Result<(), String> {
        self.call(&channel, |p, _| {
            let mut g = Self::load(p, &channel)?;
            g.delete_past_epoch_secrets(
                p,
                PastEpochDeletion::before_timestamp(UNIX_EPOCH).max_past_epochs(keep),
            )
            .map_err(|e| format!("{e:?}"))
        })
    }
}

/// A channel world: member 0 is the owner (rank 0).
pub struct World {
    pub channel: [u8; 32],
    pub members: Vec<Device>,
    pub day: u32,
}

impl World {
    /// Creates the channel and admits `n − 1` joiners in batches of `batch` Adds per commit (each
    /// with a forced path), every current member processing every commit. With one batch the tree
    /// is the "sparse" shape of §5.7: only the owner's direct path is set.
    pub fn build(n: usize, batch: usize, day: u32) -> Self {
        let mut owner = Device::new(0, day);
        let channel: [u8; 32] = owner.random32();
        let ctx = ChannelContext::initial(channel, owner.pk, if n <= 32 { 0 } else { 1 });
        owner.create_group(channel, &ctx).expect("create");
        let mut w = World {
            channel,
            members: vec![owner],
            day,
        };
        let mut next = 1;
        while next < n {
            let k = batch.min(n - next);
            let mut joiners: Vec<Device> = (next..next + k).map(|i| Device::new(i, day)).collect();
            let kps: Vec<KeyPackage> = joiners
                .iter_mut()
                .map(|j| {
                    let b = j.key_package(channel, 1, day, 0).expect("kp");
                    w.members[0].parse_key_package(&b).expect("parse kp")
                })
                .collect();
            let epoch = w.members[0].epoch(channel);
            let spec = CommitSpec {
                adds: kps,
                aad: CommitAad {
                    commit_minute: day * 1440,
                    ..Default::default()
                },
                refresh_epoch: Some(epoch),
                force_path: true,
                ..Default::default()
            };
            let out = w.members[0]
                .commit(channel, &spec)
                .expect("batch add commit");
            for m in w.members.iter_mut().skip(1) {
                m.receive(channel, &out.commit).expect("process batch add");
            }
            w.members[0].merge_own(channel).expect("merge own");
            let welcome = out.welcome.expect("welcome");
            for j in joiners.iter_mut() {
                j.join(channel, &welcome, true).expect("join");
            }
            w.members.extend(joiners);
            next += k;
        }
        w
    }

    /// Every member but the owner commits an empty self-update in turn (every parent node set).
    pub fn populate(&mut self) {
        for i in 1..self.members.len() {
            self.self_update(i).expect("populate self-update");
        }
    }

    /// Device `i` commits and every other member merges it.
    pub fn commit_and_merge(&mut self, i: usize, spec: &CommitSpec) -> Result<CommitOut, String> {
        let ch = self.channel;
        let out = self.members[i].commit(ch, spec)?;
        for (j, m) in self.members.iter_mut().enumerate() {
            if j != i {
                m.receive(ch, &out.commit)?;
            }
        }
        self.members[i].merge_own(ch)?;
        Ok(out)
    }

    pub fn self_update(&mut self, i: usize) -> Result<CommitOut, String> {
        let e = self.members[i].epoch(self.channel);
        let spec = CommitSpec {
            aad: CommitAad {
                commit_minute: self.day * 1440,
                ..Default::default()
            },
            refresh_epoch: Some(e),
            force_path: true,
            ..Default::default()
        };
        self.commit_and_merge(i, &spec)
    }

    /// Removes leaf `leaf` by member `by` (every member but the removed one merges).
    pub fn remove(&mut self, by: usize, leaf: u32) -> Result<CommitOut, String> {
        let ch = self.channel;
        let e = self.members[by].epoch(ch);
        let spec = CommitSpec {
            removes: vec![LeafNodeIndex::new(leaf)],
            aad: CommitAad {
                commit_minute: self.day * 1440,
                ..Default::default()
            },
            refresh_epoch: Some(e),
            force_path: true,
            ..Default::default()
        };
        let out = self.members[by].commit(ch, &spec)?;
        let mut keep = Vec::new();
        for (j, mut m) in std::mem::take(&mut self.members).into_iter().enumerate() {
            if j != by {
                let li = m.leaf_index(ch);
                if li == leaf {
                    continue; // the removed member leaves the world
                }
                m.receive(ch, &out.commit)?;
            }
            keep.push(m);
        }
        self.members = keep;
        let by_pos = self.members.iter().position(|m| m.id == by).unwrap_or(by);
        self.members[by_pos].merge_own(ch)?;
        Ok(out)
    }

    /// Adds fresh members one Add commit at a time by member `by`.
    pub fn add_one(&mut self, by: usize) -> Result<CommitOut, String> {
        let ch = self.channel;
        let id = self.members.iter().map(|m| m.id).max().unwrap_or(0) + 1;
        let mut j = Device::new(id, self.day);
        let kp = j.key_package(ch, 1, self.day, 0)?;
        let kp = self.members[by].parse_key_package(&kp)?;
        let e = self.members[by].epoch(ch);
        let spec = CommitSpec {
            adds: vec![kp],
            aad: CommitAad {
                commit_minute: self.day * 1440,
                ..Default::default()
            },
            refresh_epoch: Some(e),
            force_path: true,
            ..Default::default()
        };
        let out = self.commit_and_merge(by, &spec)?;
        j.join(ch, out.welcome.as_ref().unwrap(), true)?;
        self.members.push(j);
        Ok(out)
    }

    pub fn authenticators_agree(&mut self) -> bool {
        let ch = self.channel;
        let a: Vec<Vec<u8>> = self
            .members
            .iter_mut()
            .map(|m| m.authenticator(ch))
            .collect();
        a.windows(2).all(|w| w[0] == w[1])
    }
}

/// A KeyPackage (MlsMessage bytes) inflated with extra capability extension types to the largest
/// size ≤ `max` (§6.2.4's admission bound is 1 024 bytes).
pub fn inflated_key_package(d: &mut Device, channel: [u8; 32], day: u32, max: usize) -> Vec<u8> {
    let base = d.key_package(channel, 1, day, 0).expect("kp").len();
    let mut extra = max.saturating_sub(base) / 2;
    loop {
        let b = d.key_package(channel, 1, day, extra).expect("kp");
        if b.len() <= max || extra == 0 {
            return b;
        }
        extra -= 1;
    }
}
