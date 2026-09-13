//! The state of one reference client of the T2 world. Its decisions are made by the reference
//! policy ([`super::policy`]) in the world's handlers ([`super::world`]); its issuer and relay calls
//! are the production client-core calls over the loopback transport.

use std::collections::{BTreeSet, HashMap};

use ghost_entitlement::Token;

use super::policy::ClockEstimate;
use super::population::ClientSpec;
use super::rng::Rng;

/// An ACCESS token the client holds.
#[derive(Clone)]
pub struct HeldToken {
    pub week: u64,
    pub slot: u8,
    pub token: Token,
    /// Device minute from which it may be used (activation slot, §12.3).
    pub eligible: i64,
    /// The flow that produced it.
    pub source: u64,
    /// Reserved for an ambiguous redemption: relay, namespace, request id (R8).
    pub reserved: Option<(u8, [u8; 32], [u8; 16])>,
    /// A kept reservation refused as too early waits until this relay-facing time
    /// (`RedeemLane.wrongPeriodRetryAfter`).
    pub retry_after: Option<i64>,
}

#[derive(Clone)]
pub struct HeldCredit {
    pub token: Token,
    pub epoch: u64,
    pub source: u64,
}

/// A credit received through the drop, waiting for its `RefreshCredit` (§19.8).
#[derive(Clone)]
pub struct Received {
    pub token: Token,
    pub epoch: u64,
    pub due: i64,
    pub instance: u64,
    pub attempt: usize,
    pub retry: Option<i64>,
}

#[derive(Clone)]
pub struct HeldInvite {
    pub token: Token,
    pub epoch: u64,
    /// The pack flow that produced it, and its position among that pack's invites: the invite's
    /// identity in every world (neither token randomness nor the order packs finalize in).
    pub source: u64,
    pub ordinal: u8,
    /// Device minute from which the user can hand it out (its batch's activation slot: creating
    /// an invite starts the relay-visible drop listening, a relay-visible first, R4).
    pub eligible: i64,
    pub given: bool,
    /// A revocation (self-redemption) planned as quiet-run work: due, instance, attempt.
    pub revoke: Option<(i64, u64, usize)>,
}

/// The invitee's one drop write (§19.12).
pub struct DropOut {
    pub inviter: usize,
    pub ns: [u8; 32],
    /// Device time of the write (drawn at activation in [start(base + 3), start(base + 8))).
    pub due: i64,
    pub written: [bool; 3],
    /// The first XMR pack's credit, when finalized by the write.
    pub credit: Option<Token>,
    /// The sealed blob, the same bytes at every drop relay (replication, ADR-11).
    pub blob: Vec<u8>,
    pub done: bool,
}

/// An inviter's listening on one drop namespace until the invite's expiry + 56 days.
pub struct DropListen {
    pub ns: [u8; 32],
    pub until: u64,
    /// Blob hashes already fetched, per relay.
    pub seen: BTreeSet<Vec<u8>>,
    /// The client that took the invite (world bookkeeping: the receipt a twin replays).
    pub invitee: usize,
}

/// A capability the client holds for a (relay, namespace) pair.
#[derive(Clone)]
pub struct Cap {
    pub token: Vec<u8>,
    pub expiry: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PState {
    Prepared,
    Invoiced,
    Done,
    Failed,
}

/// The kinds of flow instance, each numbered on its own ([`Client::next_flow`]).
#[derive(Debug, Clone, Copy)]
pub enum FlowSeq {
    Purchase = 0,
    Trial = 1,
    Claim = 2,
    Revocation = 3,
    Refresh = 4,
}

/// A pack purchase flow.
pub struct Purchase {
    pub instance: u64,
    pub xmr: bool,
    pub state: PState,
    /// Device time the user started it, and the earliest device time of its `RequestInvoice`.
    pub created: i64,
    pub not_before: i64,
    pub seed: [u8; 32],
    /// The seed of the attempt plan: `seed`, or in an NI-2 twin its base world's.
    pub plan_seed: [u8; 32],
    pub claim_key: [u8; 32],
    pub base_week: Option<u64>,
    pub credits: Vec<Token>,
    pub invoice_id: [u8; 16],
    pub amount: u64,
    pub subaddress: String,
    pub receipt: i64,
    /// `BlindSign` attempts sent (write-ahead count).
    pub attempt: usize,
    /// `RequestInvoice` attempts sent, and the one retry's due time.
    pub req_attempt: usize,
    pub retry_due: Option<i64>,
    pub need: bool,
    /// The user pressed "get invoice now" (a foreground, user-initiated call; declared L3).
    pub button: bool,
    pub truth: Option<usize>,
    /// Rogue key index of mutant M2, from the invoice answer.
    pub rogue: Option<usize>,
    /// Base-week hint of mutant M7.
    pub hint: Option<u64>,
    pub paid: bool,
}

/// A payout claim flow.
pub struct ClaimFlow {
    pub instance: u64,
    pub claim_id: [u8; 16],
    pub credits: Vec<Token>,
    pub address: String,
    pub due: i64,
    pub attempt: usize,
    pub done: bool,
}

/// The onboarding trial of an invitee (foreground, before any relay traffic of the identity).
pub struct Trial {
    pub instance: u64,
    pub inviter: usize,
    pub invite: Token,
    pub drop_ns: [u8; 32],
    pub seed: [u8; 32],
    pub base: Option<u64>,
    pub attempts: usize,
}

/// A pending write: (namespace, blob, blob hash, stored at relay k).
pub type Outbox = ([u8; 32], Vec<u8>, [u8; 32], [bool; 3]);

pub struct Client {
    pub id: u32,
    pub spec: ClientSpec,
    pub installed: bool,
    pub onboarded: bool,
    /// The identity has namespaces (activated): relay sessions happen.
    pub active: bool,
    pub user: Rng,
    pub sched_seed: u64,
    pub token_seed: u64,
    pub ns_seed: u64,
    pub fault_seed: u64,
    pub ns_rng: Rng,
    pub circuit_key: [u8; 32],
    pub user_key: [u8; 32],
    /// Key of the keyed user draws (`World::draw`).
    pub draw_key: [u8; 32],
    /// Runs made (job runs and foreground sessions).
    pub runs: u64,
    // Process state (lost at every process start).
    pub process: u64,
    pub process_ordinal: u64,
    pub process_key: [u8; 32],
    pub prf_key: [u8; 32],
    pub job_in_process: u64,
    pub clock: ClockEstimate,
    /// Relays that answered a redemption since the device clock last changed, and that epoch.
    pub answered: BTreeSet<u8>,
    pub answered_epoch: bool,
    pub first_seen: HashMap<(u8, [u8; 32], bool, i64), i64>,
    pub jobs: u64,
    // Relay-facing state.
    pub namespaces: Vec<[u8; 32]>,
    pub caps: HashMap<(u8, [u8; 32]), Cap>,
    pub cursors: HashMap<(u8, [u8; 32]), Vec<u8>>,
    pub outbox: Vec<Outbox>,
    pub tokens: Vec<HeldToken>,
    pub drop_out: Option<DropOut>,
    pub drops: Vec<DropListen>,
    // Issuer-facing state.
    /// Flow instances started, per [`FlowSeq`].
    pub flows: [u64; 5],
    pub purchases: Vec<Purchase>,
    pub credits: Vec<HeldCredit>,
    pub received: Vec<Received>,
    pub invites: Vec<HeldInvite>,
    pub claim: Option<ClaimFlow>,
    pub trial: Option<Trial>,
    pub coverage_end: i64,
    pub auto_renew_credits: bool,
    pub lapse_done: bool,
    pub resume_at: Option<i64>,
    pub claim_at: Option<u64>,
    pub first_pack_at: Option<u64>,
    pub first_pack_done: bool,
    pub first_pack_eligible: Option<i64>,
    // User-facing state.
    pub foreground_until: u64,
    pub screen_until: u64,
    pub hold_until: u64,
    pub needed_since: Option<i64>,
    pub need_surface: Option<i64>,
    /// A need buyer's one extra pack of the window was started.
    pub need_bought: bool,
    pub pay_queue: Vec<(u64, usize)>,
    pub crash_pending: bool,
    pub redeems: u64,
    pub stores: u64,
    pub shifted: bool,
}

impl Client {
    pub fn new(id: u32, spec: ClientSpec, seeds: &super::rng::Seeds) -> Self {
        let idb = id.to_be_bytes();
        let user = Rng::new(seeds.user, &[b"client", &idb, b"user"]);
        let ns_rng = Rng::new(seeds.ns, &[b"client", &idb, b"ns"]);
        Client {
            id,
            spec,
            installed: false,
            onboarded: false,
            active: false,
            user,
            sched_seed: seeds.sched,
            token_seed: seeds.token,
            ns_seed: seeds.ns,
            fault_seed: seeds.fault,
            ns_rng,
            circuit_key: super::rng::derive32(seeds.ns, &[b"circuit", &idb]),
            user_key: super::rng::derive32(seeds.user, &[b"activity", &idb]),
            draw_key: super::rng::derive32(seeds.user, &[b"draws", &idb]),
            runs: 0,
            process: 0,
            process_ordinal: 0,
            process_key: [0; 32],
            prf_key: [0; 32],
            job_in_process: 0,
            clock: ClockEstimate::default(),
            answered: BTreeSet::new(),
            answered_epoch: false,
            first_seen: HashMap::new(),
            jobs: 0,
            namespaces: Vec::new(),
            caps: HashMap::new(),
            cursors: HashMap::new(),
            outbox: Vec::new(),
            tokens: Vec::new(),
            drop_out: None,
            drops: Vec::new(),
            flows: [0; 5],
            purchases: Vec::new(),
            credits: Vec::new(),
            received: Vec::new(),
            invites: Vec::new(),
            claim: None,
            trial: None,
            coverage_end: -1,
            auto_renew_credits: false,
            lapse_done: false,
            resume_at: None,
            claim_at: None,
            first_pack_at: None,
            first_pack_done: false,
            first_pack_eligible: None,
            foreground_until: 0,
            screen_until: 0,
            hold_until: 0,
            needed_since: None,
            need_surface: None,
            need_bought: false,
            pay_queue: Vec::new(),
            crash_pending: false,
            redeems: 0,
            stores: 0,
            shifted: false,
        }
    }

    /// The device wall clock at true time `t` (a skewed device until its user corrects it).
    pub fn wall(&self, t: u64) -> i64 {
        match self.spec.skew {
            Some((offset, corrected)) if t < corrected => t as i64 + offset,
            _ => t as i64,
        }
    }

    /// Whether the device clock still runs its initial offset at `t` (it is set right once).
    pub fn clock_epoch(&self, t: u64) -> bool {
        matches!(self.spec.skew, Some((_, c)) if t < c)
    }

    pub fn skewed(&self, t: u64) -> bool {
        matches!(self.spec.skew, Some((o, c)) if t < c && o.abs() > 4 * 3_600)
    }

    /// The next flow instance of `kind`: each kind numbers its own flows, so a flow started at an
    /// issuer- or relay-timed moment (a revocation at a pack's finalization, a refresh at a drop
    /// read) never renumbers the client's other flows, whose seeds and claim keys derive from their
    /// number (a real client draws them at random per flow).
    pub fn next_flow(&mut self, kind: FlowSeq) -> u64 {
        let n = &mut self.flows[kind as usize];
        *n += 1;
        (u64::from(self.id) << 24) | ((kind as u64) << 20) | *n
    }

    pub fn pack_in_flight(&self) -> bool {
        self.purchases
            .iter()
            .any(|p| matches!(p.state, PState::Prepared | PState::Invoiced))
    }
}
