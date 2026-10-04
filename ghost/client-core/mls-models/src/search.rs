//! The exhaustive search: depth-first over every enabled action, with each reached state stored as
//! a 128-bit fingerprint (hash compaction: two independent 64-bit mixes of the whole state; at the
//! largest run's state count the probability that two distinct states share a fingerprint is far
//! below 10⁻¹⁸, and a collision could only hide states, never invent a violation). No symmetry
//! reduction is applied: the members are not interchangeable (ranks, budgets and the adversary
//! differ per actor), and commit and blob slots are already canonical (assigned by author and
//! sequence, hashes renumbered by rank among siblings).

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::model::{World, NA};
use crate::props::{self, Violation};
use crate::step::{successors, Action, Cfg, Succ};

/// Why an exploration stopped. A budget overflow is not a property failure (the EM-1 rule).
#[derive(Debug)]
pub enum Stop {
    /// A property failed: the property, and the exact action sequence from the start.
    Property {
        violation: Violation,
        trace: Vec<Action>,
    },
    /// The search reached its state budget.
    Budget(usize),
}

impl Stop {
    pub fn property(&self) -> Option<&'static str> {
        match self {
            Stop::Property { violation, .. } => Some(violation.property),
            Stop::Budget(_) => None,
        }
    }

    /// The counter-example, one action per line.
    pub fn render(&self) -> String {
        match self {
            Stop::Property { violation, trace } => {
                let mut s = format!("{violation}\n");
                for (i, a) in trace.iter().enumerate() {
                    s.push_str(&format!("  {:>3}. {a}\n", i + 1));
                }
                s
            }
            Stop::Budget(n) => format!("state budget of {n} reached"),
        }
    }
}

/// What an exhaustive run counted.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    pub states: usize,
    pub transitions: usize,
    /// Transitions that settled at least one epoch (CO-3 decisions taken).
    pub decisions: usize,
    /// Quiescent states (nothing left to do but end a session) where the terminal properties ran.
    pub terminal: usize,
    pub events: u64,
    pub max_depth: usize,
    /// Per terminal property (by the bit position of its `props::T_*`): the quiescent states
    /// where its premise held, so that it could have failed there.
    pub live: [usize; 32],
    /// The bounds the run reached.
    pub reached: Reached,
}

/// The largest values the explored states reached, to compare with the scenario's bounds: epoch
/// transitions merged by any member, commits and posts per actor, days.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reached {
    pub epochs: usize,
    pub commits: [u8; NA],
    pub posts: [u8; NA],
    pub days: u8,
}

impl Reached {
    fn absorb(&mut self, w: &World) {
        for (m, me) in w.m.iter().enumerate() {
            self.epochs = self.epochs.max(me.chain.len());
            self.commits[m] = self.commits[m].max(me.seq);
            self.posts[m] = self.posts[m].max(me.posts + me.beacons);
        }
        self.days = self.days.max(w.day);
    }
}

impl Outcome {
    fn terminal_state(&mut self, live: u32) {
        self.terminal += 1;
        for (bit, count) in self.live.iter_mut().enumerate() {
            if live & (1 << bit) != 0 {
                *count += 1;
            }
        }
    }

    /// The quiescent states where the premise of terminal property `t` (a `props::T_*` bit)
    /// held.
    pub fn live_of(&self, t: u32) -> usize {
        self.live[t.trailing_zeros() as usize]
    }
}

/// A 128-bit state fingerprint: two 64-bit multiply-rotate mixes, finalised with the MurmurHash3
/// avalanche.
#[derive(Default)]
struct Fp {
    a: u64,
    b: u64,
}

impl Fp {
    fn mix(&mut self, x: u64) {
        self.a = (self.a ^ x)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
        self.b = (self.b.rotate_left(17) ^ x.wrapping_add(0x632b_e59b_d9b4_e019))
            .wrapping_mul(0xc2b2_ae3d_27d4_eb4f)
            ^ (self.a >> 31);
    }

    fn avalanche(mut h: u64) -> u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^ (h >> 33)
    }

    fn value(&self) -> u128 {
        ((Self::avalanche(self.a) as u128) << 64)
            | Self::avalanche(self.b ^ self.a.rotate_left(7)) as u128
    }
}

impl Hasher for Fp {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut x = 0u64;
            for (i, &v) in chunk.iter().enumerate() {
                x |= (v as u64) << (8 * i);
            }
            self.mix(x ^ ((chunk.len() as u64) << 56));
        }
    }
    fn write_u8(&mut self, i: u8) {
        self.mix(i as u64 | 0x100);
    }
    fn write_u16(&mut self, i: u16) {
        self.mix(i as u64 | 0x2_0000);
    }
    fn write_u32(&mut self, i: u32) {
        self.mix(i as u64 | 0x4_0000_0000);
    }
    fn write_u64(&mut self, i: u64) {
        self.mix(i);
    }
    fn write_usize(&mut self, i: usize) {
        self.mix(i as u64 ^ 0x5555);
    }
    fn write_isize(&mut self, i: isize) {
        self.mix(i as u64 ^ 0xaaaa);
    }
    fn finish(&self) -> u64 {
        self.value() as u64
    }
}

pub fn fingerprint(w: &World) -> u128 {
    let mut h = Fp::default();
    w.hash(&mut h);
    h.value()
}

struct Frame {
    succs: Vec<Succ>,
    next: usize,
}

/// Explores every state reachable from `start` under `cfg` within `budget` states, checking every
/// property at every transition and quiescent state.
pub fn explore(cfg: &Cfg, start: World, budget: usize) -> Result<Outcome, Stop> {
    cfg.check_bounds();
    let mut out = Outcome::default();
    out.reached.absorb(&start);
    let mut seen: HashSet<u128> = HashSet::new();
    seen.insert(fingerprint(&start));
    out.states = 1;
    let mut stack: Vec<Frame> = Vec::new();
    let mut path: Vec<Action> = Vec::new();
    let mut buf = Vec::new();
    match successors(&start, cfg, &mut buf) {
        Ok(()) => {}
        Err((action, violation)) => {
            return Err(Stop::Property {
                violation,
                trace: vec![action],
            })
        }
    }
    if quiescent(&buf) {
        let live = props::check_terminal(&start, cfg, cfg.terminal).map_err(|violation| {
            Stop::Property {
                violation,
                trace: Vec::new(),
            }
        })?;
        out.terminal_state(live);
    }
    stack.push(Frame {
        succs: std::mem::take(&mut buf),
        next: 0,
    });
    while let Some(top) = stack.last_mut() {
        if top.next == top.succs.len() {
            stack.pop();
            path.pop();
            continue;
        }
        let i = top.next;
        top.next += 1;
        let (action, world, ev, settles) = {
            let s = &top.succs[i];
            (s.action, s.world, s.ev, s.settles)
        };
        out.transitions += 1;
        out.events |= ev;
        if settles > 0 {
            out.decisions += 1;
        }
        if !seen.insert(fingerprint(&world)) {
            continue;
        }
        out.states += 1;
        if out.states > budget {
            return Err(Stop::Budget(budget));
        }
        out.reached.absorb(&world);
        path.push(action);
        out.max_depth = out.max_depth.max(path.len());
        let mut next = Vec::new();
        if let Err((bad, violation)) = successors(&world, cfg, &mut next) {
            let mut trace = path.clone();
            trace.push(bad);
            return Err(Stop::Property { violation, trace });
        }
        if quiescent(&next) {
            match props::check_terminal(&world, cfg, cfg.terminal) {
                Ok(live) => out.terminal_state(live),
                Err(violation) => {
                    return Err(Stop::Property {
                        violation,
                        trace: path.clone(),
                    })
                }
            }
        }
        stack.push(Frame {
            succs: next,
            next: 0,
        });
    }
    Ok(out)
}

/// The same exploration breadth-first, so that a counter-example is a shortest one (the finding
/// probes print it at the PR bound). It holds every state of the current depth in memory: for the
/// probes only.
pub fn explore_shortest(cfg: &Cfg, start: World, budget: usize) -> Result<Outcome, Stop> {
    cfg.check_bounds();
    let mut out = Outcome::default();
    out.reached.absorb(&start);
    let mut seen: HashMap<u128, u32> = HashMap::new();
    // Each reached state's parent and the action that reached it (state 0 is the start).
    let mut nodes: Vec<(u32, Action)> = vec![(0, Action::Observe)];
    seen.insert(fingerprint(&start), 0);
    out.states = 1;
    let path = |nodes: &[(u32, Action)], mut i: u32| -> Vec<Action> {
        let mut v = Vec::new();
        while i != 0 {
            let (p, a) = nodes[i as usize];
            v.push(a);
            i = p;
        }
        v.reverse();
        v
    };
    let mut frontier: Vec<(u32, World)> = vec![(0, start)];
    let mut buf = Vec::new();
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for (idx, w) in frontier {
            if let Err((bad, violation)) = successors(&w, cfg, &mut buf) {
                let mut trace = path(&nodes, idx);
                trace.push(bad);
                return Err(Stop::Property { violation, trace });
            }
            if quiescent(&buf) {
                match props::check_terminal(&w, cfg, cfg.terminal) {
                    Ok(live) => out.terminal_state(live),
                    Err(violation) => {
                        return Err(Stop::Property {
                            violation,
                            trace: path(&nodes, idx),
                        })
                    }
                }
            }
            for s in buf.drain(..) {
                out.transitions += 1;
                out.events |= s.ev;
                if s.settles > 0 {
                    out.decisions += 1;
                }
                let fp = fingerprint(&s.world);
                if seen.contains_key(&fp) {
                    continue;
                }
                let i = nodes.len() as u32;
                nodes.push((idx, s.action));
                seen.insert(fp, i);
                out.states += 1;
                if out.states > budget {
                    return Err(Stop::Budget(budget));
                }
                out.reached.absorb(&s.world);
                next.push((i, s.world));
            }
        }
        if !next.is_empty() {
            out.max_depth += 1;
        }
        frontier = next;
    }
    Ok(out)
}

/// Nothing is left to do but end a session.
fn quiescent(succs: &[Succ]) -> bool {
    succs.iter().all(|s| matches!(s.action, Action::Offline(_)))
}

/// Replays an action sequence (a scripted setup or a trace), returning the world it reaches; the
/// action must be enabled at each step.
pub fn replay(cfg: &Cfg, start: World, actions: &[Action]) -> Result<World, String> {
    let mut w = start;
    let mut buf = Vec::new();
    for (i, a) in actions.iter().enumerate() {
        successors(&w, cfg, &mut buf).map_err(|(b, v)| format!("step {i} ({b}): {v}"))?;
        let next = buf
            .iter()
            .find(|s| s.action == *a)
            .ok_or_else(|| format!("step {i}: {a} is not enabled"))?;
        w = next.world;
    }
    Ok(w)
}
