//! The analyzer's ingest (Phase 8 design §13.4 "Exported views"): the T2 world streams every call
//! of the issuer's and the relays' complete views, every wallet call and every database row and
//! journal entry into an [`Accumulator`], which keeps what the checks need:
//!
//! - every distinct value with its sides and first field (J1–J4, T2b, T2c);
//! - the issuer calls in full (they are few: J5 c, J6 a, J9, T2c, S1–S4);
//! - per relay-seen token: its key id, nullifier, `em = s^e mod n` (added to the relay values, J5 a),
//!   the Jacobi symbol of em (J5 b, S2) and the `ring` verification of the authenticator (J10);
//! - per circuit label the namespaces it carried (J6 b) and per client the relay sessions (a session
//!   is a maximal run of relay calls less than 10 minutes apart), the redemptions, the capability
//!   refusals (the relay-visible exhaustion of L7) and the namespaces.
//!
//! Clients are known to the accumulator only through the ground truth of each call: the relay-side
//! clustering oracle of the AD-1 worst case (RP §1.2).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ghost_entitlement::{Kind, Schedule, Token};

use crate::model::{IssuerCall, IssuerOp, IssuerTruth, Label, RelayCall, RelayOp, WalletCall};
use crate::numbers::{jacobi, open_signature};
use crate::values::{relay_bit, Public, Values, ISSUER};

/// The gap that separates two relay sessions of one client (RP §6.6 S3).
pub const SESSION_GAP: u64 = 600;

/// Fields T2b does not compare across relays (ADR-11 replication): the namespace, the blob hash
/// and the blob data it names.
pub const T2B_EXCLUDED: &[&str] = &[
    "namespace_id",
    "blob_hash",
    "stored_hash",
    "data",
    "blob_hashes",
    "capability.namespace",
];

/// Fields holding a Privacy Pass token (split into its parts as well).
const TOKEN_FIELDS: &[&str] = &["token", "credits", "invite_token", "credit"];

/// An issuer call as the checks read it.
#[derive(Debug, Clone)]
pub struct IssuerRecord {
    pub t: u64,
    pub t_resp: u64,
    pub label: Label,
    pub op: IssuerOp,
    pub request: Vec<(&'static str, Vec<u8>)>,
    pub response: Vec<(&'static str, Vec<u8>)>,
    pub ints: Vec<(&'static str, u64)>,
    pub status: i32,
    pub truth: IssuerTruth,
}

impl IssuerRecord {
    pub fn req(&self, name: &str) -> Option<&[u8]> {
        self.request
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| &v[..])
    }

    pub fn reqs<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.request
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, v)| &v[..])
    }

    pub fn resp(&self, name: &str) -> Option<&[u8]> {
        self.response
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| &v[..])
    }

    pub fn resps<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.response
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, v)| &v[..])
    }

    pub fn int(&self, name: &str) -> Option<u64> {
        self.ints.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}

/// The capture result of a redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redeemed {
    Ok,
    Replayed,
    WrongPeriod,
    Refused,
}

#[derive(Debug, Clone)]
pub struct Redemption {
    pub t: u64,
    pub relay: u8,
    pub client: u32,
    /// The token's access week, when its key id names an ES key.
    pub week: Option<u64>,
    pub key_id: [u8; 32],
    pub nullifier: [u8; 32],
    pub result: Redeemed,
    /// Jacobi symbol of `s^e mod n` (0 when the key is not an ES key).
    pub jacobi_em: i8,
    pub corrected: bool,
    pub skewed: bool,
    pub skew: i64,
    pub process: u64,
    pub source: u64,
    pub retry: bool,
}

#[derive(Default)]
pub struct ClientRelay {
    pub sessions: Vec<(u64, u64)>,
    open: Option<(u64, u64)>,
    pub denied: Vec<u64>,
    pub namespaces: BTreeSet<[u8; 32]>,
    pub first_call: Option<u64>,
    pub calls: u64,
    /// Distinct (relay, namespace) pairs listed per week (the relay-visible exhaustion of L7).
    pub pairs: BTreeMap<u64, u32>,
    pairs_seen: std::collections::HashSet<(u64, u8, [u8; 32])>,
}

impl ClientRelay {
    fn touch(&mut self, t: u64) {
        self.calls += 1;
        self.first_call.get_or_insert(t);
        match self.open {
            Some((s, last)) if t < last + SESSION_GAP => self.open = Some((s, t.max(last))),
            Some(done) => {
                self.sessions.push(done);
                self.open = Some((t, t));
            }
            None => self.open = Some((t, t)),
        }
    }

    fn close(&mut self) {
        if let Some(s) = self.open.take() {
            self.sessions.push(s);
        }
    }

    /// The session covering t, if any.
    pub fn in_session(&self, t: u64) -> bool {
        let i = self.sessions.partition_point(|&(s, _)| s <= t);
        i > 0 && self.sessions[i - 1].1 >= t
    }
}

pub struct Accumulator {
    pub schedule: Schedule,
    pub public: Public,
    pub values: Values,
    pub issuer: Vec<IssuerRecord>,
    /// Wallet transfers: txid → (first seen, minor, amount, mined height).
    pub transfers: BTreeMap<[u8; 32], (u64, u32, u64, Option<u64>)>,
    /// Relay circuit label → (first namespace, another namespace seen on it).
    pub relay_labels: HashMap<Label, ([u8; 32], bool)>,
    /// Key ids of every token a relay saw, and of every token the issuer saw.
    pub relay_key_ids: BTreeSet<[u8; 32]>,
    pub issuer_key_ids: BTreeSet<[u8; 32]>,
    /// J10 failures: relay-seen authenticators under an ES key that are not the unique root.
    pub j10: Vec<String>,
    pub redemptions: Vec<Redemption>,
    pub clients: Vec<ClientRelay>,
    pub relay_calls: u64,
    pub issuer_rows: u64,
    pub relay_rows: u64,
    pub wallet_calls: u64,
}

fn split_token(v: &[u8]) -> Option<[(&'static str, &[u8]); 5]> {
    (v.len() == 354).then(|| {
        [
            ("type", &v[..2]),
            ("nonce", &v[2..34]),
            ("challenge", &v[34..66]),
            ("key_id", &v[66..98]),
            ("authenticator", &v[98..]),
        ]
    })
}

fn split_capability(v: &[u8]) -> Vec<(&'static str, &[u8])> {
    match v.len() {
        98 => vec![
            ("header", &v[..50]),
            ("namespace", &v[2..34]),
            ("serial", &v[50..66]),
            ("mac", &v[66..]),
        ],
        82 => vec![
            ("header", &v[..50]),
            ("namespace", &v[2..34]),
            ("mac", &v[50..]),
        ],
        _ => Vec::new(),
    }
}

impl Accumulator {
    pub fn new(schedule: Schedule, public: Public) -> Self {
        Self {
            schedule,
            public,
            values: Values::default(),
            issuer: Vec::new(),
            transfers: BTreeMap::new(),
            relay_labels: HashMap::new(),
            relay_key_ids: BTreeSet::new(),
            issuer_key_ids: BTreeSet::new(),
            j10: Vec::new(),
            redemptions: Vec::new(),
            clients: Vec::new(),
            relay_calls: 0,
            issuer_rows: 0,
            relay_rows: 0,
            wallet_calls: 0,
        }
    }

    fn client(&mut self, c: u32) -> &mut ClientRelay {
        let c = c as usize;
        if self.clients.len() <= c {
            self.clients.resize_with(c + 1, ClientRelay::default);
        }
        &mut self.clients[c]
    }

    /// Adds one field on `side`. A composite value (a token, a capability) is added as its parts
    /// only: a window spanning two parts is an artefact of the layout (a public expiry next to the
    /// first byte of a serial), never a value a derivation produces.
    fn add_field(&mut self, side: u8, prefix: &str, name: &'static str, v: &[u8]) {
        let t2b_excluded = T2B_EXCLUDED.contains(&name);
        if TOKEN_FIELDS.contains(&name) {
            if let Some(parts) = split_token(v) {
                for (part, bytes) in parts {
                    let id = self.values.fields.id(&format!("{prefix}.{name}.{part}"));
                    self.values.add(side, id, bytes, false);
                }
                return;
            }
        }
        if name == "capability" && !split_capability(v).is_empty() {
            for (part, bytes) in split_capability(v) {
                let id = self
                    .values
                    .fields
                    .id(&format!("{prefix}.capability.{part}"));
                // The header is the namespace and public fields (quota, week expiry), identical at
                // every replica by design.
                let excluded = part == "namespace" || part == "header";
                self.values.add(side, id, bytes, excluded);
            }
            return;
        }
        let id = self.values.fields.id(&format!("{prefix}.{name}"));
        self.values.add(side, id, v, t2b_excluded);
    }

    pub fn issuer_call(&mut self, c: &IssuerCall<'_>, ints: &[(&'static str, u64)]) {
        let op = c.op.name();
        let req = format!("issuer.{op}.req");
        let resp = format!("issuer.{op}.resp");
        let mut xor_fields: Vec<&[u8]> = Vec::new();
        for f in &c.request {
            self.add_field(ISSUER, &req, f.name, f.bytes);
            xor_fields.push(f.bytes);
            if TOKEN_FIELDS.contains(&f.name) {
                if let Ok(t) = Token::parse(f.bytes) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(t.key_id());
                    self.issuer_key_ids.insert(id);
                }
            }
        }
        for f in &c.response {
            self.add_field(ISSUER, &resp, f.name, f.bytes);
            xor_fields.push(f.bytes);
        }
        let id = self.values.fields.id(&format!("issuer.{op}"));
        self.values.add_record_xors(ISSUER, id, &xor_fields);
        self.issuer.push(IssuerRecord {
            t: c.t,
            t_resp: c.t_resp,
            label: c.label,
            op: c.op,
            request: c
                .request
                .iter()
                .map(|f| (f.name, f.bytes.to_vec()))
                .collect(),
            response: c
                .response
                .iter()
                .map(|f| (f.name, f.bytes.to_vec()))
                .collect(),
            ints: ints.to_vec(),
            status: c.status,
            truth: c.truth,
        });
    }

    pub fn relay_call(&mut self, c: &RelayCall<'_>) {
        self.relay_calls += 1;
        let side = relay_bit(c.relay);
        let op = c.op.name();
        let req = format!("relay.{op}.req");
        let resp = format!("relay.{op}.resp");
        let mut xor_fields: Vec<&[u8]> = Vec::new();
        let mut namespace: Option<[u8; 32]> = None;
        for f in &c.request {
            self.add_field(side, &req, f.name, f.bytes);
            xor_fields.push(f.bytes);
            if f.name == "namespace_id" && f.bytes.len() == 32 {
                namespace = f.bytes.try_into().ok();
            }
            if f.name == "capability" && namespace.is_none() && f.bytes.len() >= 34 {
                namespace = f.bytes[2..34].try_into().ok();
            }
        }
        for f in &c.response {
            self.add_field(side, &resp, f.name, f.bytes);
            xor_fields.push(f.bytes);
        }
        let cap = format!("relay.{op}.capture");
        for f in &c.capture {
            self.add_field(side, &cap, f.name, f.bytes);
        }
        let id = self.values.fields.id(&format!("relay.{op}"));
        self.values.add_record_xors(side, id, &xor_fields);

        if let Some(ns) = namespace {
            let e = self.relay_labels.entry(c.label).or_insert((ns, false));
            if e.0 != ns {
                e.1 = true;
            }
        }
        if c.op == RelayOp::Redeem {
            self.redeem(c, side);
        }
        let client = self.client(c.truth.client);
        client.touch(c.t);
        if let Some(ns) = namespace {
            client.namespaces.insert(ns);
            if c.op == RelayOp::List {
                let w = ghost_entitlement::grid::week(c.t);
                if client.pairs_seen.insert((w, c.relay, ns)) {
                    *client.pairs.entry(w).or_insert(0) += 1;
                }
            }
        }
        if c.op != RelayOp::Redeem && c.result == "rejected_capability" {
            client.denied.push(c.t);
        }
    }

    fn redeem(&mut self, c: &RelayCall<'_>, side: u8) {
        let Some(bytes) = c
            .request
            .iter()
            .find(|f| f.name == "token")
            .map(|f| f.bytes)
        else {
            return;
        };
        let Ok(token) = Token::parse(bytes) else {
            return;
        };
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(token.key_id());
        self.relay_key_ids.insert(key_id);
        let result = match c.result {
            "ok" => Redeemed::Ok,
            "rejected_nullifier" => Redeemed::Replayed,
            "rejected_period" => Redeemed::WrongPeriod,
            _ => Redeemed::Refused,
        };
        let (week, jacobi_em) = match self.schedule.key_by_id(token.key_id()) {
            Some(key) => {
                let pk = &key.public_key;
                let auth = token.authenticator();
                let unique = ghost_blind_rsa::BigUint::from_bytes_be(auth) < *pk.n()
                    && token.verify_signature(pk).is_ok();
                if !unique {
                    self.j10.push(format!(
                        "relay {} at {}: authenticator of a token under ES key ({:?}, {}) is not the unique root",
                        c.relay, c.t, key.kind, key.epoch
                    ));
                }
                let em = open_signature(auth, pk.n(), pk.e(), 256);
                let j = jacobi(&ghost_blind_rsa::BigUint::from_bytes_be(&em), pk.n());
                let id = self.values.fields.id("relay.redeem.em");
                self.values.add(side, id, &em, false);
                ((key.kind == Kind::Access).then_some(key.epoch), j)
            }
            None => (None, 0),
        };
        self.redemptions.push(Redemption {
            t: c.t,
            relay: c.relay,
            client: c.truth.client,
            week,
            key_id,
            nullifier: token.nullifier(),
            result,
            jacobi_em,
            corrected: c.truth.corrected,
            skewed: c.truth.skewed,
            skew: c.truth.skew,
            process: c.truth.process,
            source: c.truth.source,
            retry: c.truth.retry,
        });
    }

    pub fn wallet(&mut self, c: &WalletCall<'_>) {
        self.wallet_calls += 1;
        let id = self
            .values
            .fields
            .id(&format!("issuer.wallet.{}", c.method));
        for f in &c.fields {
            self.values.add(ISSUER, id, f.bytes, false);
        }
        for e in &c.entries {
            self.values.add(ISSUER, id, &e.txid, false);
            let entry =
                self.transfers
                    .entry(e.txid)
                    .or_insert((e.timestamp, e.minor, e.amount, e.height));
            entry.0 = entry.0.min(e.timestamp);
            if entry.3.is_none() {
                entry.3 = e.height;
            }
        }
    }

    pub fn issuer_row(&mut self, table: &str, key: &[u8], value: &[u8]) {
        self.issuer_rows += 1;
        let id = self.values.fields.id(&format!("issuer.db.{table}"));
        self.values.add(ISSUER, id, key, false);
        self.values.add(ISSUER, id, value, false);
    }

    pub fn issuer_file(&mut self, kind: &str, bytes: &[u8]) {
        let id = self.values.fields.id(&format!("issuer.{kind}"));
        self.values.add(ISSUER, id, bytes, false);
    }

    pub fn relay_row(&mut self, relay: u8, table: &str, key: &[u8], value: &[u8]) {
        self.relay_rows += 1;
        // A nullifier row, `period(8, BE) ‖ nullifier(32) → binding tag(16)`, is added as its parts:
        // the public period, the nullifier and the tag. A window spanning the period's tail and the
        // nullifier's first bytes is an artefact of the layout, which at scale matches another
        // relay's row of the same period by chance.
        if table == "nullifiers" && key.len() == 40 {
            let side = relay_bit(relay);
            let period = self.values.fields.id("relay.db.nullifiers.period");
            self.values.add(side, period, &key[..8], true);
            let nullifier = self.values.fields.id("relay.db.nullifiers.nullifier");
            self.values.add(side, nullifier, &key[8..], false);
            let tag = self.values.fields.id("relay.db.nullifiers.binding");
            self.values.add(side, tag, value, false);
            return;
        }
        let id = self.values.fields.id(&format!("relay.db.{table}"));
        // Blob content rows are the replicated data (T2b exclusion); nullifier rows are not.
        let excluded = table != "nullifiers";
        self.values.add(relay_bit(relay), id, key, excluded);
        self.values.add(relay_bit(relay), id, value, excluded);
    }

    /// Closes the open sessions (after the last call of the world).
    pub fn close(&mut self) {
        for c in &mut self.clients {
            c.close();
        }
    }
}
