//! The value store of the join search (Phase 8 design §13.4): every distinct byte string of at
//! least 4 bytes that the issuer's complete view or any relay's complete view holds, with the sides
//! it occurs on and the field it was first seen in; the public context W (Z values and all their
//! substrings); and the exact searches J1 (equality), J2 (common windows of 8 bytes), J4 (XOR) and
//! T2b (relay ↔ relay).
//!
//! **Structured fields.** Messages are searched as their decoded fields (a protobuf message is its
//! fields plus framing constants), and composite values are also split into their parts (a token
//! into type, nonce, challenge digest, key id and authenticator; a capability into its header,
//! namespace, serial and MAC), so J1 compares atoms and J2 finds any atom embedded in another.
//! Integers are not join values; windows that are structural (four or more zero bytes, or one
//! repeated byte: small big-endian integers and padding) are never counted as joins.

use std::collections::{HashMap, HashSet};

use crate::numbers::{informative, structural_window, window, Bloom};

/// Where a value occurs: bit 0 the issuer view, bit 1 + k relay k.
pub const ISSUER: u8 = 1;

pub fn relay_bit(k: u8) -> u8 {
    2 << k
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Prov {
    pub sides: u8,
    /// Relays where the value occurs in a field T2b does not exclude (`namespace_id`, `blob_hash`
    /// and blob data are replicated by design, ADR-11).
    pub t2b: u8,
    pub issuer_field: u16,
    pub relay_field: u16,
    /// Seen at a relay in a field T2b excludes (a namespace, a blob hash, blob data).
    pub excluded: bool,
}

/// Interned field names ("issuer.blind_sign.req.claim_key", "relay.redeem.req.token.nonce", ...).
#[derive(Debug, Default)]
pub struct FieldNames {
    names: Vec<String>,
    index: HashMap<String, u16>,
}

impl FieldNames {
    pub fn id(&mut self, name: &str) -> u16 {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let i = self.names.len() as u16;
        self.names.push(name.to_string());
        self.index.insert(name.to_string(), i);
        i
    }

    pub fn name(&self, id: u16) -> &str {
        self.names.get(usize::from(id)).map_or("?", |s| s.as_str())
    }
}

/// Every distinct value of the views.
#[derive(Default)]
pub struct Values {
    pub map: HashMap<Box<[u8]>, Prov>,
    pub fields: FieldNames,
    /// XORs of equal-length fields (16 or 32 bytes) within one record, per side (J4).
    pub xor_issuer: HashMap<Box<[u8]>, u16>,
    pub xor_relay: HashMap<Box<[u8]>, u16>,
}

impl Values {
    /// Adds `v` (ignored below 4 bytes) as seen on `side` in `field`.
    pub fn add(&mut self, side: u8, field: u16, v: &[u8], t2b_excluded: bool) {
        if v.len() < 4 {
            return;
        }
        let e = match self.map.get_mut(v) {
            Some(e) => e,
            None => self.map.entry(v.into()).or_default(),
        };
        if e.sides & side == 0 {
            if side == ISSUER {
                e.issuer_field = field;
            } else if e.sides & !ISSUER == 0 {
                e.relay_field = field;
            }
        }
        e.sides |= side;
        if side != ISSUER && !t2b_excluded {
            e.t2b |= side;
        }
        if side != ISSUER && t2b_excluded {
            e.excluded = true;
        }
    }

    /// J4 within one record: the XOR of every pair of equal-length fields of 16 or 32 bytes.
    pub fn add_record_xors(&mut self, side: u8, field: u16, fields: &[&[u8]]) {
        for (i, a) in fields.iter().enumerate() {
            if a.len() != 16 && a.len() != 32 {
                continue;
            }
            for b in &fields[i + 1..] {
                if b.len() != a.len() || a == b {
                    continue;
                }
                let x: Box<[u8]> = a.iter().zip(b.iter()).map(|(p, q)| p ^ q).collect();
                let target = if side == ISSUER {
                    &mut self.xor_issuer
                } else {
                    &mut self.xor_relay
                };
                target.entry(x).or_insert(field);
            }
        }
    }

    pub fn issuer_values(&self) -> impl Iterator<Item = (&[u8], &Prov)> {
        self.map
            .iter()
            .filter(|(_, p)| p.sides & ISSUER != 0)
            .map(|(k, p)| (&k[..], p))
    }

    pub fn relay_values(&self) -> impl Iterator<Item = (&[u8], &Prov)> {
        self.map
            .iter()
            .filter(|(_, p)| p.sides & !ISSUER != 0)
            .map(|(k, p)| (&k[..], p))
    }
}

/// The public context Z and W, its values with all their substrings.
#[derive(Default)]
pub struct Public {
    pub values: Vec<Vec<u8>>,
    windows: HashSet<u64>,
}

impl Public {
    pub fn new(values: Vec<Vec<u8>>) -> Self {
        let mut windows = HashSet::new();
        for v in &values {
            for i in 0..v.len().saturating_sub(7) {
                windows.insert(window(v, i));
            }
        }
        Self { values, windows }
    }

    /// `v` is a substring of a Z value.
    pub fn contains(&self, v: &[u8]) -> bool {
        if v.len() >= 8 && !self.windows.contains(&window(v, 0)) {
            return false;
        }
        self.values
            .iter()
            .any(|z| z.len() >= v.len() && z.windows(v.len()).any(|w| w == v))
    }

    pub fn window(&self, w: u64) -> bool {
        self.windows.contains(&w)
    }
}

/// One join hit.
#[derive(Debug, Clone)]
pub struct Hit {
    pub check: &'static str,
    pub value: Vec<u8>,
    pub a: String,
    pub b: String,
}

impl std::fmt::Display for Hit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} ({} bytes) in {} and {}",
            self.check,
            hex::encode(&self.value[..self.value.len().min(40)]),
            self.value.len(),
            self.a,
            self.b
        )
    }
}

/// J1: a value of at least 4 informative bytes on both sides, outside W.
pub fn j1(values: &Values, public: &Public) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (v, p) in &values.map {
        if p.sides & ISSUER != 0 && p.sides & !ISSUER != 0 && informative(v) && !public.contains(v)
        {
            hits.push(Hit {
                check: "J1",
                value: v.to_vec(),
                a: values.fields.name(p.issuer_field).to_string(),
                b: values.fields.name(p.relay_field).to_string(),
            });
        }
    }
    hits
}

/// Common 8-byte windows between the values `left` and `right` select, outside W and not
/// structural: Bloom filter of the left windows, scan of the right ones, exact verification.
fn common_windows(
    values: &Values,
    left: impl Fn(&Prov) -> bool,
    right: impl Fn(&Prov) -> bool,
    left_is_issuer: bool,
    public: &Public,
) -> Vec<(u64, u16, u16)> {
    let left_field = |p: &Prov| {
        if left_is_issuer {
            p.issuer_field
        } else {
            p.relay_field
        }
    };
    let count: usize = values
        .map
        .iter()
        .filter(|(_, p)| left(p))
        .map(|(v, _)| v.len().saturating_sub(7))
        .sum();
    let mut bloom = Bloom::with_capacity(count, 12);
    for (v, p) in &values.map {
        if left(p) {
            for i in 0..v.len().saturating_sub(7) {
                bloom.insert(window(v, i));
            }
        }
    }
    // Candidates: right windows the filter admits.
    let mut candidates: HashMap<u64, u16> = HashMap::new();
    for (v, p) in &values.map {
        if right(p) {
            for i in 0..v.len().saturating_sub(7) {
                let w = window(v, i);
                if !structural_window(w) && bloom.contains(w) && !public.window(w) {
                    candidates.entry(w).or_insert(p.relay_field);
                }
            }
        }
    }
    // Exact verification against the left windows.
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (v, p) in &values.map {
        if left(p) {
            for i in 0..v.len().saturating_sub(7) {
                let w = window(v, i);
                if let Some(&rf) = candidates.get(&w) {
                    if seen.insert(w) {
                        out.push((w, left_field(p), rf));
                    }
                }
            }
        }
    }
    out
}

/// J2: a common window of 8 bytes between the issuer's and the relays' views, outside W.
pub fn j2(values: &Values, public: &Public) -> Vec<Hit> {
    common_windows(
        values,
        |p| p.sides & ISSUER != 0,
        |p| p.sides & !ISSUER != 0,
        true,
        public,
    )
    .into_iter()
    .map(|(w, a, b)| Hit {
        check: "J2",
        value: w.to_le_bytes().to_vec(),
        a: values.fields.name(a).to_string(),
        b: values.fields.name(b).to_string(),
    })
    .collect()
}

/// The constants J4 XORs every value with: all-zero and all-one bytes and SHA-256 of every label
/// (truncated to the value's length).
fn xor_constants(len: usize, labels: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = vec![vec![0xffu8; len]];
    for l in labels {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(l);
        out.push(d[..len.min(32)].to_vec());
    }
    out
}

/// J4: XORs of equal-length fields within records and XORs with constants, searched with J1.
pub fn j4(values: &Values, public: &Public, labels: &[Vec<u8>]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let found = |v: &[u8], side_mask: u8| -> Option<u16> {
        values
            .map
            .get(v)
            .filter(|p| p.sides & side_mask != 0)
            .map(|p| {
                if side_mask == ISSUER {
                    p.issuer_field
                } else {
                    p.relay_field
                }
            })
    };
    // Record XORs of one side against the other side's values and record XORs.
    for (x, f) in &values.xor_issuer {
        if !informative(x) || public.contains(x) {
            continue;
        }
        let other = found(x, !ISSUER).or_else(|| values.xor_relay.get(x).copied());
        if let Some(o) = other {
            hits.push(Hit {
                check: "J4",
                value: x.to_vec(),
                a: format!("xor({})", values.fields.name(*f)),
                b: values.fields.name(o).to_string(),
            });
        }
    }
    for (x, f) in &values.xor_relay {
        if !informative(x) || public.contains(x) {
            continue;
        }
        if let Some(o) = found(x, ISSUER) {
            hits.push(Hit {
                check: "J4",
                value: x.to_vec(),
                a: values.fields.name(o).to_string(),
                b: format!("xor({})", values.fields.name(*f)),
            });
        }
    }
    // Every value of 16 or 32 bytes XOR a constant, looked up on the other side.
    let mut consts: HashMap<usize, Vec<Vec<u8>>> = HashMap::new();
    for len in [16usize, 32] {
        consts.insert(len, xor_constants(len, labels));
    }
    for (v, p) in &values.map {
        let Some(cs) = consts.get(&v.len()) else {
            continue;
        };
        for c in cs {
            let x: Vec<u8> = v.iter().zip(c).map(|(a, b)| a ^ b).collect();
            if !informative(&x) {
                continue;
            }
            if let Some(q) = values.map.get(&x[..]) {
                let cross = (p.sides & ISSUER != 0 && q.sides & !ISSUER != 0)
                    || (p.sides & !ISSUER != 0 && q.sides & ISSUER != 0);
                if cross && !public.contains(&x) {
                    hits.push(Hit {
                        check: "J4",
                        value: x,
                        a: format!("xor-const({})", values.fields.name(p.issuer_field)),
                        b: values.fields.name(q.relay_field).to_string(),
                    });
                }
            }
        }
    }
    hits
}

/// T2b: J1 and J2 between different relays, excluding only `namespace_id`, `blob_hash` and the
/// blob data they name (ADR-11 replication).
pub fn t2b(values: &Values, public: &Public) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (v, p) in &values.map {
        if p.t2b.count_ones() >= 2 && informative(v) && !public.contains(v) {
            hits.push(Hit {
                check: "T2b",
                value: v.to_vec(),
                a: values.fields.name(p.relay_field).to_string(),
                b: format!("relays {:03b}", p.t2b >> 1),
            });
        }
    }
    // Windows inside an excluded atom (a namespace or a blob hash, which other fields embed: a
    // capability names its namespace) are the replicated values themselves.
    let replicated: HashSet<u64> = values
        .map
        .iter()
        .filter(|(v, p)| p.excluded && v.len() <= 64)
        .flat_map(|(v, _)| (0..v.len().saturating_sub(7)).map(move |i| window(v, i)))
        .collect();
    for k in 0u8..3 {
        for l in k + 1..3 {
            let (bk, bl) = (relay_bit(k), relay_bit(l));
            for (w, a, b) in common_windows(
                values,
                |p| p.t2b & bk != 0 && p.t2b & bl == 0,
                |p| p.t2b & bl != 0 && p.t2b & bk == 0,
                false,
                public,
            ) {
                if replicated.contains(&w) {
                    continue;
                }
                hits.push(Hit {
                    check: "T2b",
                    value: w.to_le_bytes().to_vec(),
                    a: format!("relay {k} {}", values.fields.name(a)),
                    b: format!("relay {l} {}", values.fields.name(b)),
                });
            }
        }
    }
    hits
}
