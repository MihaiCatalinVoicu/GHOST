//! The statistical tests of T2 (Phase 8 design §13.4 "Statistical tests", §19.16): S1 (learned
//! matching of invoices to relay clusters, full view against the declared-leak attacker, exact
//! one-sided McNemar), S2 (max-T mutual information, Westfall–Young, B = 999 permutations within
//! L-strata), S3 (presence: co-presence, session-edge coincidence, quiet-gap bits reported, payment
//! co-presence) and the absolute bound S4 (Q21: the declared-leak attacker's top-1 accuracy ≤ 0.25).
//!
//! **Pairs and candidates.** Clusters are clients (the relay-side clustering oracle of the AD-1
//! worst case). An invoice's candidates are the clusters with relay activity from 7 days before its
//! `RequestInvoice` to 21 days after it. The attacker is naive Bayes over binned features with
//! Laplace smoothing, trained on `W_train` (true pairs against sampled false pairs) and applied to
//! `W_test`; argmax per invoice and a Hungarian assignment per week are both reported.
//!
//! **Features.** The declared attacker sees the declared leak only: L1 (the day of a cluster's first
//! redemption onset relative to the invoice's activation-slot day), L2 (the cluster stops at the
//! pack's coverage-end week), L3 (co-presence at user-requested calls), L5 (how many of the
//! invoice's background calls fall in a session of the cluster, and how many in a gap of its
//! cadence: the quiet-gap coincidence the design declares as L5, S3 c), L6 (co-presence at the payment's
//! first-seen time) and L7 (a drop of the cluster's active pairs at the week boundary before the
//! purchase and the delay since). The full attacker adds everything else both views hold: exact
//! delays from `BlindSign` and `RequestInvoice` to the cluster's next redemption, the distance of
//! the invoice's calls to the cluster's session edges, namespace and redemption counts, the
//! distance of redemptions to week boundaries, and the Jacobi agreement of the blinded blocks with
//! the cluster's opened authenticators (J5 b).

use std::collections::{BTreeMap, HashMap, HashSet};

use ghost_entitlement::batch::Layout;
use ghost_entitlement::grid::{week, week_start};
use ghost_entitlement::Kind;

use crate::accumulate::{Accumulator, IssuerRecord, Redeemed};
use crate::checks::by_invoice;
use crate::model::{ClientKind, IssuerOp, PayMode, Truth};
use crate::numbers::{jacobi, SplitMix};

pub const DAY: u64 = 86_400;
pub const B: usize = 999;

/// What the issuer view says about one invoice (plus the truth used for scoring).
#[derive(Debug, Clone)]
pub struct InvoiceFacts {
    pub id: Vec<u8>,
    pub client: u32,
    pub xmr: bool,
    pub base: u64,
    pub scored: bool,
    pub genesis: bool,
    pub need: bool,
    pub t_req: u64,
    pub t_sig: Option<u64>,
    pub automatic_calls: Vec<u64>,
    pub user_calls: Vec<u64>,
    pub attempts: usize,
    pub payments: Vec<(u64, PayMode)>,
    /// Fraction of +1 Jacobi symbols of the signed request's blocks of weeks base+1..base+3.
    pub jac_b: Option<f64>,
    pub id_byte: u8,
    pub sub_byte: u8,
}

/// What the relays' views say about one cluster.
#[derive(Debug, Clone, Default)]
pub struct ClusterFacts {
    pub sessions: Vec<(u64, u64)>,
    pub redemption_times: Vec<u64>,
    /// (time, token week, jacobi of em, nullifier first byte) of accepted redemptions.
    pub redemptions: Vec<(u64, u64, i8, u8)>,
    pub namespaces: usize,
    pub first: u64,
    pub last: u64,
    /// Active pairs per week.
    pub pairs: BTreeMap<u64, u32>,
    /// Onsets: first redemption after at least a week without one.
    pub onsets: Vec<u64>,
    pub last_week: u64,
}

impl ClusterFacts {
    pub fn in_session(&self, t: u64) -> bool {
        let i = self.sessions.partition_point(|&(s, _)| s <= t);
        i > 0 && self.sessions[i - 1].1 >= t
    }

    /// Distance (s) from t to the nearest session start or end.
    pub fn edge_distance(&self, t: u64) -> u64 {
        let i = self.sessions.partition_point(|&(s, _)| s <= t);
        let mut best = u64::MAX;
        for j in [i.saturating_sub(1), i] {
            if let Some(&(s, e)) = self.sessions.get(j) {
                best = best.min(s.abs_diff(t)).min(e.abs_diff(t));
            }
        }
        best
    }

    pub fn next_redemption(&self, t: u64) -> Option<u64> {
        let i = self.redemption_times.partition_point(|&x| x < t);
        self.redemption_times.get(i).copied()
    }

    pub fn active_near(&self, t: u64) -> bool {
        self.first <= t + 21 * DAY && self.last + 7 * DAY >= t
    }
}

/// One cluster per client of the world (`clients`: the population size; a client that never made
/// a relay call is an empty cluster).
pub fn cluster_facts(acc: &Accumulator, clients: usize) -> Vec<ClusterFacts> {
    let mut out: Vec<ClusterFacts> = acc
        .clients
        .iter()
        .map(|c| {
            let mut sessions = c.sessions.clone();
            sessions.sort_unstable();
            ClusterFacts {
                first: sessions.first().map_or(u64::MAX, |s| s.0),
                last: sessions.last().map_or(0, |s| s.1),
                sessions,
                namespaces: c.namespaces.len(),
                pairs: c.pairs.clone(),
                ..ClusterFacts::default()
            }
        })
        .collect();
    if out.len() < clients {
        out.resize_with(clients, || ClusterFacts {
            first: u64::MAX,
            ..ClusterFacts::default()
        });
    }
    for r in &acc.redemptions {
        let Some(c) = out.get_mut(r.client as usize) else {
            continue;
        };
        c.redemption_times.push(r.t);
        if r.result == Redeemed::Ok {
            if let Some(w) = r.week {
                c.redemptions.push((r.t, w, r.jacobi_em, r.nullifier[0]));
                c.last_week = c.last_week.max(w);
            }
        }
    }
    for c in &mut out {
        c.redemption_times.sort_unstable();
        c.redemptions.sort_unstable();
        let mut prev: Option<u64> = None;
        for &t in &c.redemption_times {
            if prev.is_none_or(|p| t > p + 7 * DAY) {
                c.onsets.push(t);
            }
            prev = Some(t);
        }
    }
    out
}

fn jac_fraction(signs: &[i8]) -> Option<f64> {
    let n = signs.iter().filter(|&&s| s != 0).count();
    (n > 0).then(|| signs.iter().filter(|&&s| s == 1).count() as f64 / n as f64)
}

pub fn invoice_facts(acc: &Accumulator, truth: &Truth) -> Vec<InvoiceFacts> {
    let groups = by_invoice(acc);
    let tmap: HashMap<&[u8], &crate::model::InvoiceTruth> = truth
        .invoices
        .iter()
        .map(|i| (&i.invoice_id[..], i))
        .collect();
    let mut work: Vec<(Vec<u8>, Vec<&IssuerRecord>)> = groups.into_iter().collect();
    work.sort_by(|a, b| a.0.cmp(&b.0));
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(16);
    let chunk = work.len().div_ceil(threads).max(1);
    let mut facts: Vec<InvoiceFacts> = std::thread::scope(|s| {
        let hs: Vec<_> = work
            .chunks(chunk)
            .map(|part| {
                let tmap = &tmap;
                s.spawn(move || {
                    let mut out = Vec::new();
                    for (id, recs) in part {
                        let Some(it) = tmap.get(&id[..]) else {
                            continue;
                        };
                        let mut f = InvoiceFacts {
                            id: id.clone(),
                            client: it.client,
                            xmr: it.xmr,
                            base: it.base_week,
                            scored: it.scored,
                            genesis: truth.clients[it.client as usize].kind == ClientKind::Genesis,
                            need: it.need_triggered,
                            t_req: u64::MAX,
                            t_sig: None,
                            automatic_calls: Vec::new(),
                            user_calls: Vec::new(),
                            attempts: 0,
                            payments: it
                                .payments
                                .iter()
                                .filter_map(|&(txid, _, mode)| {
                                    acc.transfers.get(&txid).map(|e| (e.0, mode))
                                })
                                .collect(),
                            jac_b: None,
                            id_byte: id[0],
                            sub_byte: 0,
                        };
                        for r in recs {
                            if r.truth.automatic {
                                f.automatic_calls.push(r.t);
                            } else {
                                f.user_calls.push(r.t);
                            }
                            match r.op {
                                IssuerOp::RequestInvoice => {
                                    f.t_req = f.t_req.min(r.t);
                                    if let Some(s) = r.resp("subaddress").filter(|s| !s.is_empty())
                                    {
                                        f.sub_byte = s[s.len() - 1];
                                    }
                                }
                                IssuerOp::BlindSign => {
                                    f.attempts += 1;
                                    if r.int("state") == Some(1)
                                        && f.t_sig.is_none()
                                        && r.status == 0
                                    {
                                        f.t_sig = Some(r.t);
                                        if let Ok(layout) =
                                            Layout::pack(&acc.schedule, it.base_week, it.xmr)
                                        {
                                            let blocks: Vec<&[u8]> = r.reqs("blinded").collect();
                                            let mut signs = Vec::new();
                                            for (p, b) in layout.positions().iter().zip(blocks) {
                                                if p.kind == Kind::Access
                                                    && p.epoch > it.base_week
                                                    && p.epoch <= it.base_week + 3
                                                {
                                                    let pk = &acc
                                                        .schedule
                                                        .key(p.kind, p.epoch)
                                                        .unwrap()
                                                        .public_key;
                                                    signs.push(jacobi(
                                                        &ghost_blind_rsa::BigUint::from_bytes_be(b),
                                                        pk.n(),
                                                    ));
                                                }
                                            }
                                            f.jac_b = jac_fraction(&signs);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        f.automatic_calls.sort_unstable();
                        out.push(f);
                    }
                    out
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    facts.retain(|f| f.t_req != u64::MAX);
    facts.sort_by(|a, b| (a.t_req, &a.id).cmp(&(b.t_req, &b.id)));
    facts
}

// -------------------------------------------------------------------------------------------------
// Features.
// -------------------------------------------------------------------------------------------------

fn log2_bin(x: Option<u64>, cap: u32) -> u32 {
    match x {
        None => cap + 1,
        Some(v) => (64 - (v / 60).leading_zeros()).min(cap),
    }
}

/// The Jacobi fraction of the cluster's accepted redemptions of weeks base+1..base+3.
fn jac_em(c: &ClusterFacts, base: u64) -> Option<f64> {
    let signs: Vec<i8> = c
        .redemptions
        .iter()
        .filter(|r| r.1 > base && r.1 <= base + 3)
        .map(|r| r.2)
        .collect();
    jac_fraction(&signs)
}

/// The declared-leak features (L1–L7) of a pair.
pub fn declared(i: &InvoiceFacts, c: &ClusterFacts) -> Vec<u32> {
    let t_sig = i.t_sig.unwrap_or(i.t_req);
    // L1: onset day relative to the activation-slot day of the batch.
    let d_act = (t_sig + 4 * 3_600).div_ceil(DAY);
    let onset = c.onsets.iter().find(|&&o| o >= t_sig).map(|&o| o / DAY);
    let l1 = match onset {
        Some(d) if d + 1 >= d_act && d <= d_act + 6 => (d + 1 - d_act) as u32,
        Some(_) => 8,
        None => 9,
    };
    // L2: the cluster's last redeemed week is the pack's coverage end.
    let l2 = u32::from(c.last_week == i.base + 4);
    // L3: co-presence at user-requested calls.
    let l3 = u32::from(i.user_calls.iter().any(|&t| c.in_session(t)));
    // L5: background calls in a session of the cluster, and in a gap of its cadence (the quiet-gap
    // coincidence S3c measures, which the design declares as L5, §13.4 S3 c).
    let l5 = i
        .automatic_calls
        .iter()
        .filter(|&&t| c.in_session(t))
        .count()
        .min(3) as u32;
    let l5_gap = i
        .automatic_calls
        .iter()
        .filter(|&&t| in_gap(c, t))
        .count()
        .min(3) as u32;
    // L6: co-presence at a payment's first-seen time.
    let l6 = u32::from(i.payments.iter().any(|&(t, _)| c.in_session(t)));
    // L7: a drop of active pairs at the week boundary before the purchase, and the delay since.
    let w = week(i.t_req);
    let before = c.pairs.get(&(w.saturating_sub(1))).copied().unwrap_or(0);
    let now = c.pairs.get(&w).copied().unwrap_or(0);
    let l7 = if now < before {
        let since = i.t_req.saturating_sub(week_start(w));
        1 + (since / (12 * 3_600)).min(6) as u32
    } else {
        0
    };
    vec![l1, l2, l3, l5, l5_gap, l6, l7]
}

/// A quiet-gap coincidence: `t` falls in no session of the cluster and more than 450 s from its
/// session edges (S3 c; the declared L5).
fn in_gap(c: &ClusterFacts, t: u64) -> bool {
    c.edge_distance(t) > 450 && !c.in_session(t)
}

/// The full-view features of a pair: the declared ones and everything else both views hold.
pub fn full(i: &InvoiceFacts, c: &ClusterFacts) -> Vec<u32> {
    let mut f = declared(i, c);
    let t_sig = i.t_sig.unwrap_or(i.t_req);
    f.push(log2_bin(c.next_redemption(t_sig).map(|t| t - t_sig), 14));
    f.push(log2_bin(
        c.next_redemption(i.t_req).map(|t| t - i.t_req),
        14,
    ));
    let edge = i
        .automatic_calls
        .iter()
        .map(|&t| c.edge_distance(t))
        .min()
        .unwrap_or(u64::MAX);
    f.push(log2_bin((edge != u64::MAX).then_some(edge), 12));
    f.push((c.namespaces as u32).min(8));
    let in_week = c.redemptions.iter().filter(|r| r.1 == i.base + 1).count();
    f.push((in_week as u32).min(12));
    f.push(match (i.jac_b, jac_em(c, i.base)) {
        (Some(a), Some(b)) => ((a - b).abs() * 10.0) as u32,
        _ => 11,
    });
    let boundary = c
        .redemption_times
        .iter()
        .filter(|&&t| t + 14 * DAY >= t_sig && t <= t_sig + 28 * DAY)
        .map(|&t| {
            let p = week(t);
            (t - week_start(p)).min(week_start(p + 1) - t)
        })
        .min();
    f.push(log2_bin(boundary, 12));
    f.push(match c.next_redemption(t_sig) {
        Some(t) => ((t - t_sig) / 3_600).min(47) as u32,
        None => 48,
    });
    f
}

/// Naive Bayes over binned features.
#[derive(Debug, Clone, Default)]
pub struct Model {
    true_counts: Vec<HashMap<u32, f64>>,
    false_counts: Vec<HashMap<u32, f64>>,
    n_true: f64,
    n_false: f64,
}

impl Model {
    fn add(&mut self, f: &[u32], truth: bool) {
        if self.true_counts.len() < f.len() {
            self.true_counts.resize_with(f.len(), HashMap::new);
            self.false_counts.resize_with(f.len(), HashMap::new);
        }
        for (k, &b) in f.iter().enumerate() {
            let m = if truth {
                &mut self.true_counts[k]
            } else {
                &mut self.false_counts[k]
            };
            *m.entry(b).or_insert(0.0) += 1.0;
        }
        if truth {
            self.n_true += 1.0;
        } else {
            self.n_false += 1.0;
        }
    }

    pub fn score(&self, f: &[u32]) -> f64 {
        let mut s = 0.0;
        for (k, &b) in f.iter().enumerate() {
            let bins = (self.true_counts[k].len().max(self.false_counts[k].len()) + 1) as f64;
            let t = self.true_counts[k].get(&b).copied().unwrap_or(0.0);
            let fl = self.false_counts[k].get(&b).copied().unwrap_or(0.0);
            s +=
                ((t + 1.0) / (self.n_true + bins)).ln() - ((fl + 1.0) / (self.n_false + bins)).ln();
        }
        s
    }
}

fn candidates(i: &InvoiceFacts, clusters: &[ClusterFacts]) -> Vec<usize> {
    (0..clusters.len())
        .filter(|&j| clusters[j].active_near(i.t_req) && !clusters[j].sessions.is_empty())
        .collect()
}

/// The attackers trained on a world (true pairs against up to 40 sampled false pairs each).
pub struct Attackers {
    pub full: Model,
    pub declared: Model,
}

pub fn train(invoices: &[InvoiceFacts], clusters: &[ClusterFacts], seed: u64) -> Attackers {
    let mut rng = SplitMix::new(seed);
    let mut a = Attackers {
        full: Model::default(),
        declared: Model::default(),
    };
    for i in invoices.iter().filter(|i| i.scored && i.xmr) {
        let cands = candidates(i, clusters);
        let tc = &clusters[i.client as usize];
        a.full.add(&full(i, tc), true);
        a.declared.add(&declared(i, tc), true);
        let others: Vec<usize> = cands
            .iter()
            .copied()
            .filter(|&j| j != i.client as usize)
            .collect();
        for _ in 0..others.len().min(40) {
            let j = others[rng.below(others.len() as u64) as usize];
            a.full.add(&full(i, &clusters[j]), false);
            a.declared.add(&declared(i, &clusters[j]), false);
        }
    }
    a
}

/// Minimum-cost assignment of rows to distinct columns (rows ≤ columns), Hungarian algorithm.
pub fn hungarian(cost: &[Vec<f64>]) -> Vec<usize> {
    let n = cost.len();
    if n == 0 {
        return Vec::new();
    }
    let m = cost[0].len();
    let inf = f64::INFINITY;
    let mut u = vec![0.0; n + 1];
    let mut v = vec![0.0; m + 1];
    let mut p = vec![0usize; m + 1];
    let mut way = vec![0usize; m + 1];
    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0;
        let mut minv = vec![inf; m + 1];
        let mut used = vec![false; m + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = inf;
            let mut j1 = 0;
            for j in 1..=m {
                if !used[j] {
                    let cur = cost[i0 - 1][j - 1] - u[i0] - v[j];
                    if cur < minv[j] {
                        minv[j] = cur;
                        way[j] = j0;
                    }
                    if minv[j] < delta {
                        delta = minv[j];
                        j1 = j;
                    }
                }
            }
            for j in 0..=m {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }
    let mut out = vec![0; n];
    for j in 1..=m {
        if p[j] != 0 {
            out[p[j] - 1] = j - 1;
        }
    }
    out
}

/// P(X ≥ k) for X ~ Binomial(n, 1/2), exactly (in log space).
pub fn binom_tail(k: u64, n: u64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let ln_half_n = -(n as f64) * std::f64::consts::LN_2;
    let mut ln_c = 0.0f64; // ln C(n, 0)
    let mut terms = Vec::new();
    for x in 0..=n {
        if x > 0 {
            ln_c += ((n - x + 1) as f64).ln() - (x as f64).ln();
        }
        if x >= k {
            terms.push(ln_c + ln_half_n);
        }
    }
    let mx = terms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (mx + terms.iter().map(|t| (t - mx).exp()).sum::<f64>().ln())
        .exp()
        .min(1.0)
}

#[derive(Debug, Clone, Default)]
pub struct S1 {
    pub n: usize,
    pub acc_full: f64,
    pub acc_declared: f64,
    pub n10: u64,
    pub n01: u64,
    pub p: f64,
    pub h_acc_full: f64,
    pub h_acc_declared: f64,
    pub h_p: f64,
    pub mean_candidates: f64,
}

fn argmax(scores: &[(usize, f64)], salt: u64) -> Option<usize> {
    // Ties are broken by a salted hash of the cluster, never by its index (no bias to the truth).
    let key = |j: usize| SplitMix::new(salt ^ (j as u64).wrapping_mul(0x9E37_79B9)).next_u64();
    scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap().then(key(a.0).cmp(&key(b.0))))
        .map(|&(j, _)| j)
}

/// Per invoice, the predicted cluster and every candidate's score.
pub type Predictions = (Vec<Option<usize>>, Vec<Vec<(usize, f64)>>);

/// The top-1 predictions of one attacker model for every invoice `select` keeps.
pub fn predictions(
    invoices: &[&InvoiceFacts],
    clusters: &[ClusterFacts],
    model: &Model,
    use_full: bool,
) -> Predictions {
    let mut preds = Vec::new();
    let mut all = Vec::new();
    for (n, i) in invoices.iter().enumerate() {
        let scores: Vec<(usize, f64)> = candidates(i, clusters)
            .into_iter()
            .map(|j| {
                let f = if use_full {
                    full(i, &clusters[j])
                } else {
                    declared(i, &clusters[j])
                };
                (j, model.score(&f))
            })
            .collect();
        preds.push(argmax(&scores, n as u64));
        all.push(scores);
    }
    (preds, all)
}

fn hungarian_predictions(
    invoices: &[&InvoiceFacts],
    scores: &[Vec<(usize, f64)>],
) -> Vec<Option<usize>> {
    let mut out = vec![None; invoices.len()];
    let mut by_week: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (n, i) in invoices.iter().enumerate() {
        by_week.entry(week(i.t_req)).or_default().push(n);
    }
    for rows in by_week.values() {
        let mut cols: Vec<usize> = rows
            .iter()
            .flat_map(|&r| scores[r].iter().map(|&(j, _)| j))
            .collect();
        cols.sort_unstable();
        cols.dedup();
        if cols.len() < rows.len() || cols.is_empty() {
            continue;
        }
        let index: HashMap<usize, usize> = cols.iter().enumerate().map(|(k, &j)| (j, k)).collect();
        let cost: Vec<Vec<f64>> = rows
            .iter()
            .map(|&r| {
                let mut row = vec![1e6; cols.len()];
                for &(j, s) in &scores[r] {
                    row[index[&j]] = -s;
                }
                row
            })
            .collect();
        let assign = hungarian(&cost);
        for (k, &r) in rows.iter().enumerate() {
            out[r] = Some(cols[assign[k]]);
        }
    }
    out
}

fn mcnemar(truth: &[usize], a: &[Option<usize>], b: &[Option<usize>]) -> (f64, f64, u64, u64, f64) {
    let (mut ca, mut cb, mut n10, mut n01) = (0u64, 0u64, 0u64, 0u64);
    for k in 0..truth.len() {
        let x = a[k] == Some(truth[k]);
        let y = b[k] == Some(truth[k]);
        ca += u64::from(x);
        cb += u64::from(y);
        if x && !y {
            n10 += 1;
        }
        if y && !x {
            n01 += 1;
        }
    }
    let n = truth.len().max(1) as f64;
    (
        ca as f64 / n,
        cb as f64 / n,
        n10,
        n01,
        binom_tail(n10, n10 + n01),
    )
}

/// S1 on `W_test` with attackers trained on `W_train`: every scored XMR pack.
pub fn s1(test: &[InvoiceFacts], clusters: &[ClusterFacts], a: &Attackers) -> S1 {
    let sel: Vec<&InvoiceFacts> = test.iter().filter(|i| i.scored && i.xmr).collect();
    let truth: Vec<usize> = sel.iter().map(|i| i.client as usize).collect();
    let (pf, sf) = predictions(&sel, clusters, &a.full, true);
    let (pd, sd) = predictions(&sel, clusters, &a.declared, false);
    let (af, ad, n10, n01, p) = mcnemar(&truth, &pf, &pd);
    let hf = hungarian_predictions(&sel, &sf);
    let hd = hungarian_predictions(&sel, &sd);
    let (haf, had, _, _, hp) = mcnemar(&truth, &hf, &hd);
    S1 {
        n: sel.len(),
        acc_full: af,
        acc_declared: ad,
        n10,
        n01,
        p,
        h_acc_full: haf,
        h_acc_declared: had,
        h_p: hp,
        mean_candidates: sf.iter().map(|s| s.len()).sum::<usize>() as f64 / sf.len().max(1) as f64,
    }
}

/// S4: the declared-leak attacker's top-1 accuracy over scored XMR packs of non-genesis clients.
pub fn s4(test: &[InvoiceFacts], clusters: &[ClusterFacts], a: &Attackers) -> (f64, usize) {
    let sel: Vec<&InvoiceFacts> = test
        .iter()
        .filter(|i| i.scored && i.xmr && !i.genesis)
        .collect();
    let (pd, _) = predictions(&sel, clusters, &a.declared, false);
    let correct = sel
        .iter()
        .zip(&pd)
        .filter(|(i, p)| **p == Some(i.client as usize))
        .count();
    (correct as f64 / sel.len().max(1) as f64, sel.len())
}

// -------------------------------------------------------------------------------------------------
// S2: max-T mutual information.
// -------------------------------------------------------------------------------------------------

fn mi(x: &[u32], y: &[u32]) -> f64 {
    let n = x.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut joint: HashMap<(u32, u32), f64> = HashMap::new();
    let mut px: HashMap<u32, f64> = HashMap::new();
    let mut py: HashMap<u32, f64> = HashMap::new();
    for (&a, &b) in x.iter().zip(y) {
        *joint.entry((a, b)).or_insert(0.0) += 1.0;
        *px.entry(a).or_insert(0.0) += 1.0;
        *py.entry(b).or_insert(0.0) += 1.0;
    }
    joint
        .iter()
        .map(|(&(a, b), &c)| (c / n) * ((c * n) / (px[&a] * py[&b])).ln())
        .sum()
}

#[derive(Debug, Clone, Default)]
pub struct S2 {
    pub n: usize,
    pub t_max: f64,
    pub exceeded: usize,
    pub p: f64,
    pub strongest: String,
}

pub fn s2(test: &[InvoiceFacts], clusters: &[ClusterFacts], seed: u64) -> S2 {
    let sel: Vec<&InvoiceFacts> = test
        .iter()
        .filter(|i| i.scored && i.xmr && i.t_sig.is_some())
        .collect();
    let bin8 = |v: Option<f64>| v.map_or(8, |f| ((f * 8.0) as u32).min(7));
    let xs: Vec<Vec<u32>> = vec![
        sel.iter().map(|i| bin8(i.jac_b)).collect(),
        sel.iter().map(|i| u32::from(i.id_byte & 7)).collect(),
        sel.iter().map(|i| u32::from(i.sub_byte & 7)).collect(),
        sel.iter().map(|i| i.attempts.min(5) as u32).collect(),
        sel.iter()
            .map(|i| ((i.t_sig.unwrap() % 60) / 8) as u32)
            .collect(),
    ];
    let x_names = [
        "jacobi(B)",
        "invoice id byte",
        "subaddress byte",
        "attempts",
        "t_sig seconds",
    ];
    let ys: Vec<Vec<u32>> = {
        let c = |i: &InvoiceFacts| &clusters[i.client as usize];
        vec![
            sel.iter().map(|i| bin8(jac_em(c(i), i.base))).collect(),
            sel.iter()
                .map(|i| {
                    let t = i.t_sig.unwrap();
                    c(i).redemptions
                        .iter()
                        .find(|r| r.0 >= t)
                        .map_or(8, |r| u32::from(r.3 & 7))
                })
                .collect(),
            sel.iter()
                .map(|i| {
                    (c(i)
                        .redemptions
                        .iter()
                        .filter(|r| r.1 >= i.base && r.1 <= i.base + 4)
                        .count() as u32
                        / 4)
                    .min(8)
                })
                .collect(),
            sel.iter()
                .map(|i| (c(i).namespaces as u32).min(8))
                .collect(),
            sel.iter()
                .map(|i| {
                    let t = i.t_sig.unwrap();
                    c(i).next_redemption(t).map_or(8, |r| ((r % 60) / 8) as u32)
                })
                .collect(),
        ]
    };
    let y_names = [
        "jacobi(em)",
        "nullifier byte",
        "redemptions b..b+4",
        "namespaces",
        "redemption seconds",
    ];
    // Strata: the declared cells (base week, need trigger, a screen payment).
    let strata: Vec<(u64, bool, bool)> = sel
        .iter()
        .map(|i| {
            (
                i.base,
                i.need,
                i.payments.iter().any(|p| p.1 == PayMode::Session),
            )
        })
        .collect();
    let mut groups: HashMap<(u64, bool, bool), Vec<usize>> = HashMap::new();
    for (k, s) in strata.iter().enumerate() {
        groups.entry(*s).or_default().push(k);
    }
    let pairs: Vec<(usize, usize)> = (0..xs.len())
        .flat_map(|a| (0..ys.len()).map(move |b| (a, b)))
        .collect();
    let obs: Vec<f64> = pairs.iter().map(|&(a, b)| mi(&xs[a], &ys[b])).collect();
    let mut rng = SplitMix::new(seed);
    let mut perm_mi: Vec<Vec<f64>> = Vec::with_capacity(B);
    let n = sel.len();
    for _ in 0..B {
        let mut idx: Vec<usize> = (0..n).collect();
        for g in groups.values() {
            let mut shuffled = g.clone();
            rng.shuffle(&mut shuffled);
            for (from, to) in g.iter().zip(shuffled) {
                idx[*from] = to;
            }
        }
        let permuted: Vec<Vec<u32>> = ys
            .iter()
            .map(|y| idx.iter().map(|&k| y[k]).collect())
            .collect();
        perm_mi.push(
            pairs
                .iter()
                .map(|&(a, b)| mi(&xs[a], &permuted[b]))
                .collect(),
        );
    }
    let k = pairs.len();
    let mean: Vec<f64> = (0..k)
        .map(|p| perm_mi.iter().map(|m| m[p]).sum::<f64>() / B as f64)
        .collect();
    let sd: Vec<f64> = (0..k)
        .map(|p| {
            let v = perm_mi
                .iter()
                .map(|m| (m[p] - mean[p]).powi(2))
                .sum::<f64>()
                / (B as f64 - 1.0);
            v.sqrt().max(1e-12)
        })
        .collect();
    let t = |m: &[f64]| -> (f64, usize) {
        (0..k)
            .map(|p| ((m[p] - mean[p]) / sd[p], p))
            .fold((f64::NEG_INFINITY, 0), |a, b| if b.0 > a.0 { b } else { a })
    };
    let (t_obs, at) = t(&obs);
    let exceeded = perm_mi.iter().filter(|m| t(m).0 >= t_obs).count();
    S2 {
        n,
        t_max: t_obs,
        exceeded,
        p: (1 + exceeded) as f64 / (1 + B) as f64,
        strongest: format!("{} x {}", x_names[pairs[at].0], y_names[pairs[at].1]),
    }
}

// -------------------------------------------------------------------------------------------------
// S3: presence.
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Presence {
    pub n: usize,
    pub observed: f64,
    pub max_permuted: f64,
    pub p: f64,
}

/// A presence test: the rate at which the true cluster satisfies `ind` at an event, against
/// clusters of the same stratum (clusters with relay activity on the event's day).
fn presence(
    events: &[(u64, usize)],
    clusters: &[ClusterFacts],
    ind: impl Fn(&ClusterFacts, u64) -> bool,
    seed: u64,
) -> Presence {
    if events.is_empty() {
        return Presence {
            p: 1.0,
            ..Presence::default()
        };
    }
    let mut by_day: HashMap<u64, Vec<usize>> = HashMap::new();
    for (j, c) in clusters.iter().enumerate() {
        for &(s, _) in &c.sessions {
            let v = by_day.entry(s / DAY).or_default();
            if v.last() != Some(&j) {
                v.push(j);
            }
        }
    }
    let observed = events
        .iter()
        .filter(|&&(t, c)| ind(&clusters[c], t))
        .count() as f64
        / events.len() as f64;
    let mut rng = SplitMix::new(seed);
    let mut exceeded = 0;
    let mut max_permuted = 0.0f64;
    for _ in 0..B {
        let mut hits = 0;
        for &(t, c) in events {
            let pool = by_day.get(&(t / DAY)).map_or(&[][..], |v| &v[..]);
            let j = if pool.is_empty() {
                c
            } else {
                pool[rng.below(pool.len() as u64) as usize]
            };
            if ind(&clusters[j], t) {
                hits += 1;
            }
        }
        let rate = hits as f64 / events.len() as f64;
        max_permuted = max_permuted.max(rate);
        if rate >= observed {
            exceeded += 1;
        }
    }
    Presence {
        n: events.len(),
        observed,
        max_permuted,
        p: (1 + exceeded) as f64 / (1 + B) as f64,
    }
}

#[derive(Debug, Clone, Default)]
pub struct S3 {
    pub a: Presence,
    pub b: Presence,
    /// Quiet-gap coincidence: the true cluster's gap rate, the rate of other clusters, bits per call
    /// and per invoice (reported, the declared L5).
    pub gap_true: f64,
    pub gap_other: f64,
    pub bits_per_call: f64,
    pub bits_per_invoice: f64,
    pub d: Presence,
}

pub fn s3(acc: &Accumulator, test: &[InvoiceFacts], clusters: &[ClusterFacts], seed: u64) -> S3 {
    let (lo, hi) = (test.iter().map(|i| i.t_req).min().unwrap_or(0), u64::MAX);
    let events: Vec<(u64, usize)> = acc
        .issuer
        .iter()
        .filter(|r| r.truth.automatic && r.t >= lo && r.t < hi)
        .map(|r| (r.t, r.truth.client as usize))
        .filter(|&(_, c)| c < clusters.len())
        .collect();
    let a = presence(&events, clusters, |c, t| c.in_session(t), seed);
    let b = presence(
        &events,
        clusters,
        |c, t| {
            let i = c.sessions.partition_point(|&(s, _)| s + 120 < t);
            c.sessions[i.saturating_sub(1)..(i + 2).min(c.sessions.len())]
                .iter()
                .any(|&(s, e)| (s + 120 >= t && s <= t + 30) || (e + 120 >= t && e <= t + 30))
        },
        seed ^ 1,
    );
    let gap = in_gap;
    let gap_true = events
        .iter()
        .filter(|&&(t, c)| gap(&clusters[c], t))
        .count() as f64
        / events.len().max(1) as f64;
    let mut rng = SplitMix::new(seed ^ 2);
    let mut other = 0usize;
    let mut total = 0usize;
    for &(t, c) in &events {
        for _ in 0..8 {
            let j = rng.below(clusters.len() as u64) as usize;
            if j == c || !clusters[j].active_near(t) {
                continue;
            }
            total += 1;
            other += usize::from(gap(&clusters[j], t));
        }
    }
    let gap_other = other as f64 / total.max(1) as f64;
    let bits = if gap_other > 0.0 && gap_true > 0.0 {
        (gap_true / gap_other).log2()
    } else {
        0.0
    };
    let calls_per_invoice = test
        .iter()
        .filter(|i| i.scored)
        .map(|i| i.automatic_calls.len())
        .sum::<usize>() as f64
        / test.iter().filter(|i| i.scored).count().max(1) as f64;
    let pay: Vec<(u64, usize)> = test
        .iter()
        .flat_map(|i| {
            i.payments
                .iter()
                .filter(|p| p.1 == PayMode::Screen)
                .map(move |p| (p.0, i.client as usize))
        })
        .collect();
    let d = presence(&pay, clusters, |c, t| c.in_session(t), seed ^ 3);
    S3 {
        a,
        b,
        gap_true,
        gap_other,
        bits_per_call: bits,
        bits_per_invoice: bits * calls_per_invoice,
        d,
    }
}

/// The clusters of the Sybil-invitee world whose client presents a credit its Sybil invitee
/// finalized (for the report).
pub fn scored_clients(test: &[InvoiceFacts]) -> HashSet<u32> {
    test.iter().filter(|i| i.scored).map(|i| i.client).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binomial_tail_is_exact() {
        assert!((binom_tail(0, 10) - 1.0).abs() < 1e-12);
        assert!((binom_tail(10, 10) - 1.0 / 1024.0).abs() < 1e-12);
        assert!((binom_tail(9, 10) - 11.0 / 1024.0).abs() < 1e-12);
        assert!(binom_tail(11, 11) < 0.001);
        assert!(binom_tail(10, 10) > 0.0009);
    }

    #[test]
    fn hungarian_finds_the_minimum() {
        let cost = vec![
            vec![4.0, 1.0, 3.0],
            vec![2.0, 0.0, 5.0],
            vec![3.0, 2.0, 2.0],
        ];
        let a = hungarian(&cost);
        let total: f64 = a.iter().enumerate().map(|(i, &j)| cost[i][j]).sum();
        assert_eq!(total, 5.0);
        let rect = vec![vec![9.0, 1.0, 9.0, 9.0], vec![9.0, 9.0, 9.0, 1.0]];
        assert_eq!(hungarian(&rect), vec![1, 3]);
    }

    #[test]
    fn mutual_information_is_zero_for_independent_and_positive_for_equal() {
        let x: Vec<u32> = (0..800).map(|i| i % 4).collect();
        let y: Vec<u32> = (0..800).map(|i| (i / 4) % 4).collect();
        assert!(mi(&x, &y) < 1e-9);
        assert!(mi(&x, &x) > 1.3);
    }
}
