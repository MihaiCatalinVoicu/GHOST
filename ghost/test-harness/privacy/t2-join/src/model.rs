//! What the T2 world hands to the analyzer: every call of the issuer's and the relays' complete
//! views as decoded fields with exact times and circuit labels, every wallet call, every database
//! row and journal entry, and, separately, the ground truth used only for scoring, for the
//! completeness checks and for the checks that are stated over it (J6, J8, J9, T2c).

/// A circuit label: `H(isolation token id ‖ service)`, what a server observes of a connection.
pub type Label = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IssuerOp {
    RequestInvoice,
    BlindSign,
    InvoiceStatus,
    RedeemInvite,
    ClaimPayout,
    RefreshCredit,
}

impl IssuerOp {
    pub fn name(self) -> &'static str {
        match self {
            IssuerOp::RequestInvoice => "request_invoice",
            IssuerOp::BlindSign => "blind_sign",
            IssuerOp::InvoiceStatus => "invoice_status",
            IssuerOp::RedeemInvite => "redeem_invite",
            IssuerOp::ClaimPayout => "claim_payout",
            IssuerOp::RefreshCredit => "refresh_credit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RelayOp {
    Store,
    Get,
    Check,
    List,
    Redeem,
}

impl RelayOp {
    pub fn name(self) -> &'static str {
        match self {
            RelayOp::Store => "store",
            RelayOp::Get => "get",
            RelayOp::Check => "check",
            RelayOp::List => "list",
            RelayOp::Redeem => "redeem",
        }
    }
}

/// One named byte field of a message.
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    pub name: &'static str,
    pub bytes: &'a [u8],
}

pub fn field<'a>(name: &'static str, bytes: &'a [u8]) -> Field<'a> {
    Field { name, bytes }
}

/// The kind of an issuer flow instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    PackXmr,
    PackCredits,
    Trial,
    Revocation,
    Refresh,
    Claim,
}

/// Ground truth of one issuer call.
#[derive(Debug, Clone, Copy)]
pub struct IssuerTruth {
    pub client: u32,
    /// The flow instance of this call (R5: one per call).
    pub flow: u64,
    /// The purchase, trial, revocation, refresh or claim the call belongs to.
    pub instance: u64,
    /// The first instance of its lineage: a `WRONG_PERIOD` re-prepare continues a purchase, trial
    /// or revocation in a new instance (new claim key and seed) that keeps the old one's lineage
    /// and attempt count (§19.27); every other instance is its own lineage.
    pub lineage: u64,
    pub kind: FlowKind,
    /// Made by the automatic schedule in a quiet run (false: a scripted user action).
    pub automatic: bool,
    /// The client's run (quiet run or foreground session) the call was made in.
    pub run: u64,
}

pub struct IssuerCall<'a> {
    pub t: u64,
    pub t_resp: u64,
    pub label: Label,
    pub op: IssuerOp,
    pub request: Vec<Field<'a>>,
    pub response: Vec<Field<'a>>,
    /// 0 for an answer, otherwise the gRPC status code.
    pub status: i32,
    pub truth: IssuerTruth,
}

/// Ground truth of one relay call.
#[derive(Debug, Clone, Copy)]
pub struct RelayTruth {
    pub client: u32,
    pub run: u64,
    pub process: u64,
    /// The client's relay-facing clock was corrected (two relays answered in this process since the
    /// device clock last changed).
    pub corrected: bool,
    /// Redeem only: the purchase or trial whose token this is (0: none).
    pub source: u64,
    /// Redeem only: the client's device clock was off by more than 4 h at the call.
    pub skewed: bool,
    /// The device clock's offset from true time at the call (seconds).
    pub skew: i64,
    /// Redeem only: an identical retry of an ambiguous redemption (R8: the same token, relay,
    /// namespace and `request_id`); its first attempt may never have reached the relay.
    pub retry: bool,
    /// Redeem only: the relay answered and the answer never reached the client (the world's
    /// lost-answer fault; an AD-1 relay can withhold one too), so the client learned nothing from
    /// it: no period, no minute, no refusal (S12 review P8-J8-1).
    pub answer_lost: bool,
}

pub struct RelayCall<'a> {
    pub relay: u8,
    pub t: u64,
    pub label: Label,
    pub op: RelayOp,
    pub request: Vec<Field<'a>>,
    pub response: Vec<Field<'a>>,
    pub status: i32,
    /// The capture event's `result`.
    pub result: &'a str,
    /// The capture event's hex fields, decoded (nullifier, capability_scope, request_id, ...).
    pub capture: Vec<Field<'a>>,
    pub truth: RelayTruth,
}

/// One `get_transfers` entry as the view-only wallet answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletEntry {
    pub txid: [u8; 32],
    pub minor: u32,
    pub amount: u64,
    pub height: Option<u64>,
    pub confirmations: u64,
    /// The pool-first-seen time (L6), read only by the T2 view.
    pub timestamp: u64,
}

pub struct WalletCall<'a> {
    pub t: u64,
    pub method: &'static str,
    pub fields: Vec<Field<'a>>,
    pub entries: Vec<WalletEntry>,
}

/// The kind of a client of the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    /// Subscribed before the scored window (first pack in the warm-up tail).
    Existing,
    /// A future credit spender of the warm-up.
    Spender,
    /// Onboarded by an invite trial.
    Invitee,
    /// A genesis identity (no invite, first pack funds onboarding).
    Genesis,
    /// An invitee controlled by the attacker.
    Sybil,
}

#[derive(Debug, Clone)]
pub struct ClientTruth {
    pub kind: ClientKind,
    pub namespaces: usize,
    /// User-initiated issuer calls as the world made them: (time, op) (for the report).
    pub user_calls: Vec<(u64, IssuerOp)>,
    /// The foreground sessions the user script drew for this client, at the start of each day and
    /// before any of them happened: the only moments a user action (and so a user-initiated issuer
    /// call) can happen (J9).
    pub scripted: Vec<u64>,
    /// The client's runs: (start, end, quiet, relay calls, issuer calls).
    pub runs: Vec<Run>,
    /// Device clock offset intervals: (from, until, offset seconds).
    pub skew: Vec<(u64, u64, i64)>,
    /// Process starts.
    pub processes: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct Run {
    pub id: u64,
    pub start: u64,
    pub end: u64,
    /// A periodic-job run (quiet or a background relay session); false for a foreground session.
    pub job: bool,
    pub quiet: bool,
    /// Quiet because the process's PRF drew it (q = 1/8 per job, whatever work is due: P-7).
    pub drawn: bool,
    /// The relay calls the world counted in the run (for the report; J9 reads the relay views).
    pub relay_calls: u32,
    pub issuer_calls: u32,
}

/// How a payment was made (§19.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayMode {
    Screen,
    Session,
}

#[derive(Debug, Clone)]
pub struct InvoiceTruth {
    pub invoice_id: [u8; 16],
    pub client: u32,
    pub instance: u64,
    pub xmr: bool,
    pub base_week: u64,
    pub need_triggered: bool,
    /// In the scored window (not the warm-up).
    pub scored: bool,
    /// Payments: txid, pool-first-seen time, mode.
    pub payments: Vec<([u8; 32], u64, PayMode)>,
    /// The seed of the flow's attempt plan (its blinding seed; an NI-2 twin keeps its base world's)
    /// and the receipt minute (J9 due windows).
    pub seed: [u8; 32],
    pub receipt_minute: u64,
    /// The finalization time of its tokens, if finalized.
    pub finalized: Option<u64>,
}

/// Everything the world knows that the adversary does not.
#[derive(Debug, Clone, Default)]
pub struct Truth {
    pub clients: Vec<ClientTruth>,
    pub invoices: Vec<InvoiceTruth>,
    /// Tokens the attacker knows because its Sybil clients finalized them.
    pub attacker_tokens: Vec<Vec<u8>>,
    /// The nullifier of every token a client handed to a relay (the completeness check: each must
    /// appear in some relay view).
    pub presented: Vec<[u8; 32]>,
    /// Scored window [start, end).
    pub window: (u64, u64),
}
