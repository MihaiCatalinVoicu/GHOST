//! The exported views of a T2 world (Phase 8 design §13.4): every issuer call, relay call, wallet
//! call, database row, journal entry and payout batch, streamed to
//! - the analyzer's [`Accumulator`] (the world under analysis),
//! - canonical digests (the twin-world comparisons NI-1, NI-1d, NI-2, NI-3: exact byte equality,
//!   located by client and day when it fails),
//! - an optional NDJSON export (`GHOST_T2_EXPORT=<dir>`: `issuer_view.ndjson`,
//!   `wallet_view.ndjson`, `issuer_db.ndjson`, `relay_<k>_view.ndjson`, `relay_<k>_db.ndjson`).
//!
//! **Canonical form.** A call is hashed as its exact times, circuit label, operation, every field
//! (name, length, bytes) in message order, its integer fields, its status and its capture result.
//! The NI-2 digest of the issuer view replaces the bytes of the fields derived from token-level
//! client randomness (blinded blocks, blind signatures, and the invite and credit tokens a client
//! presents, which its own seeds produced) by their lengths: "identical modulo the blinded and
//! signature bytes, compared by position".

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use ghost_t2_join::accumulate::Accumulator;
use ghost_t2_join::model::{Field, IssuerCall, RelayCall, WalletCall};
use sha2::{Digest, Sha256};

/// Fields whose bytes the NI-2 digest leaves out (their lengths stay).
pub const NI2_MASKED: &[&str] = &[
    "blinded",
    "blind_signatures",
    "blind_signature",
    "credits",
    "invite_token",
    "credit",
];

#[derive(Default)]
pub struct Digests {
    pub issuer: Sha256,
    pub issuer_masked: Sha256,
    pub wallet: Sha256,
    /// Wallet calls recorded, and (with `per_client`) each call's (time, short hash), to locate a
    /// twin difference of the wallet view (NI-2, NI-3).
    pub wallet_calls: u64,
    pub wallet_seq: Vec<(u64, [u8; 8])>,
    pub relay: [Sha256; 3],
    pub relay_db: Sha256,
    pub issuer_calls: u64,
    pub relay_calls: [u64; 3],
    /// Per client: (time, short hash) of every relay call it made (NI-1 per-client comparison).
    pub relay_by_client: Vec<Vec<(u64, [u8; 8])>>,
    /// Per client: (time, short hash) of every issuer call it made (NI-2, NI-3 localisation).
    pub issuer_by_client: Vec<Vec<(u64, [u8; 8])>>,
    pub issuer_masked_by_client: Vec<Vec<(u64, [u8; 8])>>,
    /// Drop writes: (time, relay, blob length) (NI-1d).
    pub drops: Vec<(u64, u8, usize)>,
    /// Relay database snapshots: (week, relay) → digest.
    pub relay_db_weeks: BTreeMap<(u64, u8), [u8; 32]>,
    /// `GHOST_T2_DEBUG=1`: a readable line per call and client, to locate a twin difference.
    pub issuer_text_by_client: Vec<Vec<String>>,
    pub relay_text_by_client: Vec<Vec<String>>,
    /// `GHOST_T2_DEBUG=1`: client-internal events (an invite taken, a drop listen added, tokens
    /// stored, a drop pair without a token), shown next to a twin difference; never in a view.
    pub notes_by_client: Vec<Vec<(u64, String)>>,
}

fn summary(
    op: &str,
    t: u64,
    fields: &[Field<'_>],
    ints: &[(&'static str, u64)],
    status: i32,
    result: &str,
) -> String {
    let f: Vec<String> = fields
        .iter()
        .map(|f| {
            format!(
                "{}={}",
                f.name,
                hex::encode(&f.bytes[..f.bytes.len().min(6)])
            )
        })
        .collect();
    let i: Vec<String> = ints.iter().map(|(n, v)| format!("{n}={v}")).collect();
    format!(
        "{t} {op} [{}] [{}] status={status} {result}",
        f.join(" "),
        i.join(" ")
    )
}

fn push_text(v: &mut Vec<Vec<String>>, client: u32, s: String) {
    let c = client as usize;
    if v.len() <= c {
        v.resize_with(c + 1, Vec::new);
    }
    v[c].push(s);
}

pub struct Export {
    dir: PathBuf,
    files: BTreeMap<String, BufWriter<File>>,
}

impl Export {
    pub fn open(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).expect("export directory");
        Export {
            dir,
            files: BTreeMap::new(),
        }
    }

    pub fn line(&mut self, file: &str, text: &str) {
        let w = self.files.entry(file.to_string()).or_insert_with(|| {
            BufWriter::new(File::create(self.dir.join(file)).expect("export file"))
        });
        writeln!(w, "{text}").expect("export write");
    }

    pub fn write_file(&mut self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join(name), bytes).expect("export file");
    }

    pub fn flush(&mut self) {
        for w in self.files.values_mut() {
            w.flush().expect("export flush");
        }
    }
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// The canonical encoding of one call.
#[allow(clippy::too_many_arguments)]
pub fn canonical(
    t: u64,
    t_resp: u64,
    label: &[u8; 32],
    op: &str,
    request: &[Field<'_>],
    response: &[Field<'_>],
    ints: &[(&'static str, u64)],
    status: i32,
    result: &str,
    masked: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    b.extend_from_slice(&t.to_be_bytes());
    b.extend_from_slice(&t_resp.to_be_bytes());
    b.extend_from_slice(label);
    put(&mut b, op.as_bytes());
    for (side, fields) in [("req", request), ("resp", response)] {
        put(&mut b, side.as_bytes());
        for f in fields {
            put(&mut b, f.name.as_bytes());
            if masked && NI2_MASKED.contains(&f.name) {
                b.extend_from_slice(&(f.bytes.len() as u32).to_be_bytes());
            } else {
                put(&mut b, f.bytes);
            }
        }
    }
    for (n, v) in ints {
        put(&mut b, n.as_bytes());
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&status.to_be_bytes());
    put(&mut b, result.as_bytes());
    b
}

fn short(bytes: &[u8]) -> [u8; 8] {
    Sha256::digest(bytes)[..8].try_into().unwrap()
}

fn json_fields(fields: &[Field<'_>]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|f| format!("[\"{}\",\"{}\"]", f.name, hex::encode(f.bytes)))
        .collect();
    format!("[{}]", parts.join(","))
}

fn json_ints(ints: &[(&'static str, u64)]) -> String {
    let parts: Vec<String> = ints.iter().map(|(n, v)| format!("[\"{n}\",{v}]")).collect();
    format!("[{}]", parts.join(","))
}

fn push_client(v: &mut Vec<Vec<(u64, [u8; 8])>>, client: u32, t: u64, h: [u8; 8]) {
    let c = client as usize;
    if v.len() <= c {
        v.resize_with(c + 1, Vec::new);
    }
    v[c].push((t, h));
}

pub struct Recorder {
    pub acc: Option<Accumulator>,
    pub digests: Digests,
    pub export: Option<Export>,
    /// Keep the per-client relay call hashes (the NI-1 per-client comparison needs them).
    pub per_client: bool,
    pub debug: bool,
}

impl Recorder {
    pub fn new(acc: Option<Accumulator>, export: Option<PathBuf>, per_client: bool) -> Self {
        Recorder {
            acc,
            digests: Digests::default(),
            export: export.map(Export::open),
            per_client,
            debug: std::env::var("GHOST_T2_DEBUG").is_ok_and(|v| v == "1"),
        }
    }

    /// Records a client-internal event for the twin diagnostics (`GHOST_T2_DEBUG=1` only).
    pub fn note(&mut self, client: u32, t: u64, text: String) {
        if !(self.debug && self.per_client) {
            return;
        }
        let v = &mut self.digests.notes_by_client;
        let c = client as usize;
        if v.len() <= c {
            v.resize_with(c + 1, Vec::new);
        }
        v[c].push((t, text));
    }

    pub fn issuer_call(&mut self, c: &IssuerCall<'_>, ints: &[(&'static str, u64)]) {
        let op = c.op.name();
        let full = canonical(
            c.t,
            c.t_resp,
            &c.label,
            op,
            &c.request,
            &c.response,
            ints,
            c.status,
            "",
            false,
        );
        let masked = canonical(
            c.t,
            c.t_resp,
            &c.label,
            op,
            &c.request,
            &c.response,
            ints,
            c.status,
            "",
            true,
        );
        self.digests.issuer.update(&full);
        self.digests.issuer_masked.update(&masked);
        self.digests.issuer_calls += 1;
        push_client(
            &mut self.digests.issuer_by_client,
            c.truth.client,
            c.t,
            short(&full),
        );
        push_client(
            &mut self.digests.issuer_masked_by_client,
            c.truth.client,
            c.t,
            short(&masked),
        );
        if self.debug {
            let mut fields = c.request.clone();
            fields.extend(c.response.iter().copied());
            push_text(
                &mut self.digests.issuer_text_by_client,
                c.truth.client,
                format!(
                    "{} label={}",
                    summary(op, c.t, &fields, ints, c.status, ""),
                    hex::encode(&c.label[..4])
                ),
            );
        }
        if let Some(e) = &mut self.export {
            e.line(
                "issuer_view.ndjson",
                &format!(
                    "{{\"t\":{},\"t_resp\":{},\"circuit\":\"{}\",\"op\":\"{op}\",\"req\":{},\"resp\":{},\"ints\":{},\"status\":{}}}",
                    c.t,
                    c.t_resp,
                    hex::encode(c.label),
                    json_fields(&c.request),
                    json_fields(&c.response),
                    json_ints(ints),
                    c.status
                ),
            );
        }
        if let Some(acc) = &mut self.acc {
            acc.issuer_call(c, ints);
        }
    }

    pub fn relay_call(&mut self, c: &RelayCall<'_>, ints: &[(&'static str, u64)], drop: bool) {
        let op = c.op.name();
        let mut fields = c.request.clone();
        fields.extend(c.capture.iter().copied());
        let enc = canonical(
            c.t,
            c.t,
            &c.label,
            op,
            &fields,
            &c.response,
            ints,
            c.status,
            c.result,
            false,
        );
        let k = usize::from(c.relay);
        self.digests.relay[k].update(&enc);
        self.digests.relay_calls[k] += 1;
        if self.per_client {
            let mut tagged = enc.clone();
            tagged.push(c.relay);
            push_client(
                &mut self.digests.relay_by_client,
                c.truth.client,
                c.t,
                short(&tagged),
            );
        }
        if self.debug {
            let mut all = fields.clone();
            all.extend(c.response.iter().copied());
            push_text(
                &mut self.digests.relay_text_by_client,
                c.truth.client,
                format!(
                    "relay {} {}",
                    c.relay,
                    summary(op, c.t, &all, ints, c.status, c.result)
                ),
            );
        }
        if drop {
            let len = c
                .request
                .iter()
                .find(|f| f.name == "data")
                .map_or(0, |f| f.bytes.len());
            self.digests.drops.push((c.t, c.relay, len));
        }
        if let Some(e) = &mut self.export {
            e.line(
                &format!("relay_{}_view.ndjson", c.relay),
                &format!(
                    "{{\"t\":{},\"circuit\":\"{}\",\"op\":\"{op}\",\"req\":{},\"resp\":{},\"capture\":{},\"ints\":{},\"status\":{},\"result\":\"{}\"}}",
                    c.t,
                    hex::encode(c.label),
                    json_fields(&c.request),
                    json_fields(&c.response),
                    json_fields(&c.capture),
                    json_ints(ints),
                    c.status,
                    c.result
                ),
            );
        }
        if let Some(acc) = &mut self.acc {
            acc.relay_call(c);
        }
    }

    pub fn wallet(&mut self, c: &WalletCall<'_>) {
        let mut b = Vec::new();
        b.extend_from_slice(&c.t.to_be_bytes());
        put(&mut b, c.method.as_bytes());
        for f in &c.fields {
            put(&mut b, f.bytes);
        }
        for e in &c.entries {
            b.extend_from_slice(&e.txid);
            b.extend_from_slice(&e.minor.to_be_bytes());
            b.extend_from_slice(&e.amount.to_be_bytes());
            b.extend_from_slice(&e.height.unwrap_or(u64::MAX).to_be_bytes());
            b.extend_from_slice(&e.confirmations.to_be_bytes());
            b.extend_from_slice(&e.timestamp.to_be_bytes());
        }
        self.digests.wallet.update(&b);
        self.digests.wallet_calls += 1;
        if self.per_client {
            let h = Sha256::digest(&b);
            let mut short = [0u8; 8];
            short.copy_from_slice(&h[..8]);
            self.digests.wallet_seq.push((c.t, short));
        }
        if let Some(x) = &mut self.export {
            let entries: Vec<String> = c
                .entries
                .iter()
                .map(|e| {
                    format!(
                        "{{\"txid\":\"{}\",\"minor\":{},\"amount\":{},\"height\":{},\"confirmations\":{},\"timestamp\":{}}}",
                        hex::encode(e.txid),
                        e.minor,
                        e.amount,
                        e.height.map_or("null".to_string(), |h| h.to_string()),
                        e.confirmations,
                        e.timestamp
                    )
                })
                .collect();
            x.line(
                "wallet_view.ndjson",
                &format!(
                    "{{\"t\":{},\"method\":\"{}\",\"fields\":{},\"entries\":[{}]}}",
                    c.t,
                    c.method,
                    json_fields(&c.fields),
                    entries.join(",")
                ),
            );
        }
        if let Some(acc) = &mut self.acc {
            acc.wallet(c);
        }
    }

    /// One snapshot of the issuer database at `t`: every row of every table.
    pub fn issuer_rows(&mut self, t: u64, rows: &[(&'static str, Vec<u8>, Vec<u8>)]) {
        if let Some(x) = &mut self.export {
            for (table, k, v) in rows {
                x.line(
                    "issuer_db.ndjson",
                    &format!(
                        "{{\"t\":{t},\"table\":\"{table}\",\"key\":\"{}\",\"value\":\"{}\"}}",
                        hex::encode(k),
                        hex::encode(v)
                    ),
                );
            }
        }
        if let Some(acc) = &mut self.acc {
            for (table, k, v) in rows {
                acc.issuer_row(table, k, v);
            }
        }
    }

    /// Journal segments and payout batch files (issuer view).
    pub fn issuer_file(&mut self, kind: &str, name: &str, bytes: &[u8]) {
        if let Some(x) = &mut self.export {
            x.write_file(&format!("{kind}-{name}"), bytes);
        }
        if let Some(acc) = &mut self.acc {
            acc.issuer_file(kind, bytes);
        }
    }

    /// One snapshot of relay `k`'s databases in `week`.
    pub fn relay_rows(&mut self, week: u64, k: u8, rows: &[(&'static str, Vec<u8>, Vec<u8>)]) {
        let mut h = Sha256::new();
        for (table, key, value) in rows {
            let mut b = Vec::new();
            put(&mut b, table.as_bytes());
            put(&mut b, key);
            put(&mut b, value);
            h.update(&b);
        }
        let d: [u8; 32] = h.finalize().into();
        self.digests.relay_db.update(d);
        self.digests.relay_db_weeks.insert((week, k), d);
        if let Some(x) = &mut self.export {
            for (table, key, value) in rows {
                x.line(
                    &format!("relay_{k}_db.ndjson"),
                    &format!(
                        "{{\"week\":{week},\"table\":\"{table}\",\"key\":\"{}\",\"value\":\"{}\"}}",
                        hex::encode(key),
                        hex::encode(value)
                    ),
                );
            }
        }
        if let Some(acc) = &mut self.acc {
            for (table, key, value) in rows {
                acc.relay_row(k, table, key, value);
            }
        }
    }
}
