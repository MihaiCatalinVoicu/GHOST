//! The exhaustive state models **EM-1** (sessions) and **EM-2** (seal modes) of design §15.2,
//! graft RG-1, run in the `rust` job.
//!
//! These are abstract models, not the production code path: they enumerate **states**, not action
//! sequences, so the run is exhaustive over everything reachable inside the stated bound instead of
//! sampling a huge sequence space. Breadth-first search from the initial state applies every
//! enabled action, canonicalises the result (session and root identifiers are renamed to their
//! order of first appearance, so two runs that differ only in numbering are one state), and checks
//! every property at every state. Bounds: at most two user sends per side by default — the design
//! writes "at most 6 user sends per side", and `GHOST_DM_EM_SENDS` (with `GHOST_DM_EM_BUDGET`
//! raised alongside it) takes the run there for a gate-scale run, since the reachable state count
//! grows roughly an order of magnitude per extra send — and at most [`WIRE_MAX`] messages in
//! flight. Recorded deviation: the PR-scale default is 2, not 6.
//!
//! The models complement the ProVerif obligations M-1 … M-8 of §9.5, which check secrecy and
//! authentication rather than state reachability, and mutant MC-19 ("newest decrypt wins") must
//! fail EM-1 — `mc19_newest_decrypt_wins_is_detected` runs the model with that rule substituted and
//! asserts that a property breaks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Design §8.7: an initiator session unacknowledged this long is stale.
const UNACK_MAX: u32 = 28;
/// Design §8.2 R-SS1: a demoted row retires after this many days.
const RETIRE_DAYS: u32 = 46;
/// Messages allowed in flight at once.
const WIRE_MAX: usize = 2;
/// Explored states before the search gives up (a guard against a model change that explodes).
/// Raising `GHOST_DM_EM_SENDS` needs `GHOST_DM_EM_BUDGET` raised with it: the reachable state
/// count grows roughly an order of magnitude per extra send per side.
fn state_budget() -> usize {
    std::env::var("GHOST_DM_EM_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000)
}

fn sends_per_side() -> u8 {
    std::env::var("GHOST_DM_EM_SENDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

// ---------------------------------------------------------------------------------------------
// EM-1: sessions
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    session: u16,
    role: Role,
    acknowledged: bool,
    /// `peer_bind_minute` of §22.8.4, as a day index in this model.
    bind: u32,
    unack_since: Option<u32>,
    retire: Option<u32>,
    /// The peer identity this row was created with (§8.2 rule 5).
    peer_identity: u8,
    /// Chain indices already decrypted on this row (D2a).
    seen: BTreeSet<u16>,
    /// Messages already sent on this row; the next one takes this chain index.
    sent: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Device {
    identity: u8,
    /// The live bundle generation; a restore regenerates it (§8.6).
    generation: u8,
    current: Option<Row>,
    previous: Option<Row>,
    /// D2b, `olm_prekey_used(gen_id, session_id)`.
    reuse: BTreeSet<(u8, u16)>,
    sends_used: u8,
    displayed: BTreeSet<u16>,
    /// The peer identity pinned at first contact; `None` before it.
    pinned_peer: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A first flight: it names the recipient's generation and carries a binding minute.
    PreKey {
        generation: u8,
        bind: u32,
    },
    Normal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Message {
    id: u16,
    from: u8,
    session: u16,
    chain: u16,
    kind: Kind,
    sender_identity: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct World {
    devices: [Device; 2],
    wire: Vec<Message>,
    day: u32,
    next_session: u16,
    next_message: u16,
}

impl World {
    fn new() -> Self {
        let device = |identity| Device {
            identity,
            generation: 1,
            current: None,
            previous: None,
            reuse: BTreeSet::new(),
            sends_used: 0,
            displayed: BTreeSet::new(),
            pinned_peer: None,
        };
        Self {
            devices: [device(10), device(20)],
            wire: Vec::new(),
            day: 0,
            next_session: 1,
            next_message: 1,
        }
    }

    /// Canonical form: session and message identifiers renamed to their order of first appearance,
    /// so two runs that differ only in numbering collapse to one state.
    fn canonical(&self) -> String {
        let mut sessions: BTreeMap<u16, u16> = BTreeMap::new();
        let rename = |id: u16, map: &mut BTreeMap<u16, u16>| -> u16 {
            let next = u16::try_from(map.len()).unwrap_or(u16::MAX);
            *map.entry(id).or_insert(next)
        };
        let mut out = String::new();
        for device in &self.devices {
            for row in [&device.current, &device.previous] {
                if let Some(row) = row {
                    let session = rename(row.session, &mut sessions);
                    out.push_str(&format!(
                        "|r{session}:{:?}:{}:{}:{:?}:{:?}:{}:{:?}",
                        row.role,
                        u8::from(row.acknowledged),
                        row.bind,
                        row.unack_since.map(|d| self.day - d),
                        row.retire.map(|d| d.saturating_sub(self.day)),
                        row.peer_identity,
                        row.seen
                    ));
                } else {
                    out.push_str("|-");
                }
            }
            let reuse: Vec<String> = device
                .reuse
                .iter()
                .map(|(gen, session)| format!("{gen}.{}", rename(*session, &mut sessions)))
                .collect();
            out.push_str(&format!(
                "|g{}|s{}|u{:?}|p{:?}",
                device.generation, device.sends_used, reuse, device.pinned_peer
            ));
        }
        for message in &self.wire {
            out.push_str(&format!(
                "|m{}:{}:{:?}:{}",
                message.from,
                rename(message.session, &mut sessions),
                message.kind,
                message.chain
            ));
        }
        out
    }
}

/// How R-SS2 decides a swap. The mutant substitutes [`Selection::NewestWins`] for MC-19.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selection {
    /// The design's R-SS2.
    Rules,
    /// MC-19: whichever row decrypted last becomes `current`.
    NewestWins,
}

/// R-SS2 (§8.2, with the §22.8.4 age guards): should the row that just decrypted be promoted?
fn should_swap(selection: Selection, current: &Row, previous: &Row, message: &Message) -> bool {
    if selection == Selection::NewestWins {
        return true;
    }
    // Stale traffic of a session the contact dropped never swaps.
    if matches!(message.kind, Kind::PreKey { .. })
        && previous.role == Role::Responder
        && current.role == Role::Responder
        && previous.bind < current.bind
    {
        return false;
    }
    if message.kind == Kind::Normal
        && previous.role == Role::Initiator
        && current.role == Role::Responder
        && previous.bind < current.bind
    {
        return false;
    }
    if !current.acknowledged {
        return true;
    }
    previous.acknowledged && previous.session < current.session
}

/// One transition of EM-1. Returns the worlds reachable by every enabled action.
fn em1_successors(world: &World, selection: Selection, sends: u8) -> Vec<World> {
    let mut out = Vec::new();

    // A user send on either device.
    for index in 0..2 {
        if world.devices[index].sends_used >= sends || world.wire.len() >= WIRE_MAX {
            continue;
        }
        let mut next = world.clone();
        let peer_generation = next.devices[1 - index].generation;
        let day = next.day;
        let device = &mut next.devices[index];
        device.sends_used += 1;

        // R-SS0: `UNACK_MAX` re-establishment demotes `current` and deletes the old `previous`.
        let stale = device.current.as_ref().is_some_and(|row| {
            row.role == Role::Initiator
                && !row.acknowledged
                && row
                    .unack_since
                    .is_some_and(|since| day >= since + UNACK_MAX)
        });
        if device.current.is_none() || stale {
            let session = next.next_session;
            next.next_session += 1;
            let device = &mut next.devices[index];
            if let Some(mut demoted) = device.current.take() {
                demoted.retire = Some(day + RETIRE_DAYS);
                device.previous = Some(demoted);
            }
            device.current = Some(Row {
                session,
                role: Role::Initiator,
                acknowledged: false,
                bind: day,
                unack_since: Some(day),
                retire: None,
                peer_identity: 0,
                seen: BTreeSet::new(),
                sent: 0,
            });
        }
        let device = &mut next.devices[index];
        let row = device.current.as_mut().expect("a send has a current row");
        let kind = if row.acknowledged {
            Kind::Normal
        } else {
            Kind::PreKey {
                generation: peer_generation,
                bind: day,
            }
        };
        let chain = row.sent;
        row.sent += 1;
        let message = Message {
            id: next.next_message,
            from: u8::try_from(index).expect("two devices"),
            session: row.session,
            chain,
            kind,
            sender_identity: device.identity,
        };
        next.next_message += 1;
        next.wire.push(message);
        out.push(next);
    }

    // Deliver, duplicate (a replay: the message stays on the wire) or drop any message in flight.
    for (position, message) in world.wire.iter().enumerate() {
        let message = *message;
        let target = 1 - usize::from(message.from);

        let mut delivered = world.clone();
        delivered.wire.remove(position);
        apply_delivery(&mut delivered, target, &message, selection);
        out.push(delivered);

        let mut replayed = world.clone();
        apply_delivery(&mut replayed, target, &message, selection);
        out.push(replayed);

        let mut dropped = world.clone();
        dropped.wire.remove(position);
        out.push(dropped);
    }

    // A restore: sessions and generations are lost, the Olm identity is not (C-1, §8.6).
    for index in 0..2 {
        if world.devices[index].generation > 1 {
            continue; // one restore per run keeps the model bounded
        }
        let mut next = world.clone();
        let device = &mut next.devices[index];
        device.generation += 1;
        device.current = None;
        device.previous = None;
        device.reuse.clear();
        device.pinned_peer = None;
        out.push(next);
    }

    // Time passing, enough to make an unacknowledged initiator session stale.
    if world.day == 0 {
        let mut next = world.clone();
        next.day = UNACK_MAX;
        out.push(next);
    }

    out
}

/// The receive path: §7.6 dedup, §8.2 R-SS1 and R-SS2, §8.2 rules 3 and 5.
fn apply_delivery(world: &mut World, target: usize, message: &Message, selection: Selection) {
    let day = world.day;
    let device = &mut world.devices[target];

    // §8.2 rule 3 / §8.3: a message under an identity that is not the pinned one is dropped with
    // no state change. The pin is taken at first contact.
    if let Some(pinned) = device.pinned_peer {
        if pinned != message.sender_identity {
            return;
        }
    }

    // A message of a session we already hold.
    let slot = if device
        .current
        .as_ref()
        .is_some_and(|row| row.session == message.session)
    {
        Some(true)
    } else if device
        .previous
        .as_ref()
        .is_some_and(|row| row.session == message.session)
    {
        Some(false)
    } else {
        None
    };

    if let Some(on_current) = slot {
        let (row, other) = if on_current {
            (
                device.current.as_mut().expect("current"),
                device.previous.clone(),
            )
        } else {
            (
                device.previous.as_mut().expect("previous"),
                device.current.clone(),
            )
        };
        // D2a: the message key is gone after the first decryption.
        if row.seen.contains(&message.chain) {
            return;
        }
        row.seen.insert(message.chain);
        row.acknowledged = true;
        row.unack_since = None;
        if let Kind::PreKey { bind, .. } = message.kind {
            row.bind = row.bind.max(bind);
        }
        device.displayed.insert(message.id);

        if !on_current {
            if let Some(current) = other {
                let previous = device.previous.clone().expect("previous");
                if should_swap(selection, &current, &previous, message) {
                    let mut demoted = current;
                    demoted.retire = Some(day + RETIRE_DAYS);
                    let mut promoted = previous;
                    promoted.retire = None;
                    device.current = Some(promoted);
                    device.previous = Some(demoted);
                }
            }
        }
        return;
    }

    let Kind::PreKey { generation, bind } = message.kind else {
        return; // a normal message of an unknown session does not decrypt
    };
    // D2b: a replayed first flight after its session was replaced or deleted.
    if device.reuse.contains(&(generation, message.session)) {
        return;
    }
    // The generation the message names was regenerated by a restore: `unknown_generation`.
    if generation != device.generation {
        return;
    }

    // R-SS1, with the §22.8.4 stale-first-flight exception. MC-19 ("newest decrypt wins") drops
    // that exception together with R-SS2's age guards: it is one rule, not two.
    let stale = selection == Selection::Rules
        && device
            .current
            .as_ref()
            .is_some_and(|row| row.role == Role::Responder && row.bind > bind);
    let row = Row {
        session: message.session,
        role: Role::Responder,
        acknowledged: true,
        bind,
        unack_since: None,
        retire: None,
        peer_identity: message.sender_identity,
        seen: BTreeSet::from([message.chain]),
        sent: 0,
    };
    if stale {
        let replaceable = device
            .previous
            .as_ref()
            .is_none_or(|old| old.role == Role::Responder && old.bind < bind);
        if !replaceable {
            return; // drop(stale_session): no session, no reuse tuple
        }
        let mut demoted = row;
        demoted.retire = Some(day + RETIRE_DAYS);
        device.previous = Some(demoted);
    } else {
        if let Some(mut demoted) = device.current.take() {
            demoted.retire = Some(day + RETIRE_DAYS);
            device.previous = Some(demoted);
        }
        device.current = Some(row);
    }
    device.reuse.insert((generation, message.session));
    device.pinned_peer = Some(message.sender_identity);
    device.displayed.insert(message.id);
}

/// The structural invariants of §15.3 that this model can see, plus the EM-1 properties of §15.2.
fn em1_properties(world: &World) -> Result<(), String> {
    for (index, device) in world.devices.iter().enumerate() {
        if device.previous.is_some() && device.current.is_none() {
            return Err(format!("device {index}: a previous row without a current"));
        }
        if let Some(row) = &device.previous {
            if row.retire.is_none() {
                return Err(format!(
                    "device {index}: a previous row without a retire day"
                ));
            }
        }
        for (name, row) in [("current", &device.current), ("previous", &device.previous)] {
            let Some(row) = row else { continue };
            if row.role == Role::Responder && !row.acknowledged {
                return Err(format!(
                    "device {index}: an unacknowledged responder {name}"
                ));
            }
            let expected = row.role == Role::Initiator && !row.acknowledged;
            if expected != row.unack_since.is_some() {
                return Err(format!(
                    "device {index}: unack_since disagrees with the row state on {name}"
                ));
            }
            if let Some(pinned) = device.pinned_peer {
                if row.role == Role::Responder && row.peer_identity != pinned {
                    return Err(format!(
                        "device {index}: {name} holds a session of another identity"
                    ));
                }
            }
        }
        if let (Some(current), Some(previous)) = (&device.current, &device.previous) {
            if current.session == previous.session {
                return Err(format!("device {index}: both slots hold one session"));
            }
            // §22.8.4 R-SS1's stale exception: a **first flight** older than the responder
            // `current` never becomes `current` itself. (A later *normal* message of that session
            // may still promote it through R-SS2's tie-break, which is deliberate and is what
            // makes R-SS3 converge, so the guard is about creation, not about the pair of rows.)
            if current.role == Role::Responder
                && previous.role == Role::Responder
                && current.bind < previous.bind
                && current.seen.len() == 1
                && previous.seen.len() == 1
            {
                return Err(format!(
                    "device {index}: an older first flight became current ({} < {})",
                    current.bind, previous.bind
                ));
            }
        }
        // D2b: every session ever created from a generation left a reuse tuple behind.
        for row in [&device.current, &device.previous].into_iter().flatten() {
            if row.role == Role::Responder
                && !device
                    .reuse
                    .iter()
                    .any(|(_, session)| *session == row.session)
            {
                return Err(format!(
                    "device {index}: a responder row without its reuse tuple"
                ));
            }
        }
    }
    Ok(())
}

fn explore_em1(selection: Selection) -> Result<usize, String> {
    let sends = sends_per_side();
    let budget = state_budget();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    let start = World::new();
    seen.insert(start.canonical());
    queue.push_back(start);
    let mut states = 0usize;

    while let Some(world) = queue.pop_front() {
        states += 1;
        if states > budget {
            return Err(format!("the state space exceeded {budget} states"));
        }
        em1_properties(&world)?;
        for next in em1_successors(&world, selection, sends) {
            if seen.insert(next.canonical()) {
                queue.push_back(next);
            }
        }
    }
    Ok(states)
}

#[test]
fn em1_sessions_hold_every_property() {
    let states = explore_em1(Selection::Rules).expect("EM-1");
    assert!(states > 1_000, "EM-1 explored only {states} states");
    println!("EM-1: {states} states");
}

/// §8.2 "Model obligation": mutant MC-19 ("newest decrypt wins") must fail EM-1. It breaks
/// R-SS3's convergence — the two sides keep promoting whatever decrypted last and never settle on
/// one session id — which is the property the design names, so the detection is asserted there.
#[test]
fn mc19_newest_decrypt_wins_is_detected() {
    assert!(
        explore_em1(Selection::NewestWins).is_err() || converges(Selection::NewestWins).is_err(),
        "MC-19 must break an EM-1 property"
    );
}

/// R-SS3 (§8.2): simultaneous first contact converges to one session per pair. Every interleaving
/// of both flows with up to three messages per side is enumerated and run to quiescence.
#[test]
fn em1_simultaneous_initiation_converges() {
    converges(Selection::Rules).expect("R-SS3 convergence");
}

fn converges(selection: Selection) -> Result<(), String> {
    let sends = 3u8;
    let mut checked = 0usize;
    // A schedule is a sequence of actions: 0/1 = a user send on that device, 2 = deliver the
    // oldest message in flight. Every schedule of the given length is enumerated.
    let length = 8;
    for code in 0u32..3u32.pow(length) {
        let mut world = World::new();
        let mut digits = code;
        let mut actions = Vec::new();
        for _ in 0..length {
            actions.push(digits % 3);
            digits /= 3;
        }
        for action in actions {
            match action {
                0 | 1 => {
                    let index = usize::try_from(action).expect("0 or 1");
                    if world.devices[index].sends_used < sends && world.wire.len() < 6 {
                        world = em1_successors_send(&world, index, selection);
                    }
                }
                _ => {
                    if !world.wire.is_empty() {
                        let message = world.wire.remove(0);
                        let target = 1 - usize::from(message.from);
                        apply_delivery(&mut world, target, &message, selection);
                    }
                }
            }
        }
        // Quiescence: deliver everything that is still in flight, oldest first.
        while !world.wire.is_empty() {
            let message = world.wire.remove(0);
            let target = 1 - usize::from(message.from);
            apply_delivery(&mut world, target, &message, selection);
        }
        em1_properties(&world)?;
        // Both sides settle the exchange: three more messages each way with immediate delivery,
        // which is the "within two round trips" of R-SS3 with a round trip to spare.
        for _ in 0..3 {
            for index in 0..2 {
                world.devices[index].sends_used = 0;
                world = em1_successors_send(&world, index, selection);
                let message = world.wire.remove(0);
                let target = 1 - usize::from(message.from);
                apply_delivery(&mut world, target, &message, selection);
            }
        }
        let a = world.devices[0].current.as_ref().map(|row| row.session);
        let b = world.devices[1].current.as_ref().map(|row| row.session);
        if a != b {
            return Err(format!(
                "simultaneous initiation did not converge for schedule {code}: {a:?} vs {b:?}"
            ));
        }
        checked += 1;
    }
    assert_eq!(checked, 3usize.pow(length));
    Ok(())
}

/// The send action alone, for the directed convergence enumeration above.
fn em1_successors_send(world: &World, index: usize, selection: Selection) -> World {
    let mut candidates = em1_successors(world, selection, u8::MAX);
    // The first two successors are the sends of device 0 and device 1, in order.
    candidates.remove(index)
}

// ---------------------------------------------------------------------------------------------
// EM-2: seal modes
// ---------------------------------------------------------------------------------------------

/// The seal mode a sender picks (§6.8 sender mode rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Intro,
    Provisional,
    Pair,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Direction {
    /// The sender has an acknowledged session, so a root may ride in a normal message (§21.3).
    acknowledged: bool,
    /// The recipient offered a root and the sender received it.
    root_held: bool,
    /// The recipient's offer is acknowledged, so it stops re-offering (§21.3 point 2).
    offer_acknowledged: bool,
    /// The sender may still key provisional mode from `reply_seed`.
    reply_seed_live: bool,
    /// The recipient's generation this direction's intro envelopes name is still live.
    generation_live: bool,
    /// The recipient still holds the pair week key of the current week.
    pair_key_live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Seal {
    directions: [Direction; 2],
    week: u8,
    /// Sealed messages in flight: (direction, mode, carries a root).
    wire: Vec<(u8, Mode, bool)>,
}

impl Seal {
    fn new() -> Self {
        let direction = Direction {
            acknowledged: false,
            root_held: false,
            offer_acknowledged: false,
            reply_seed_live: true,
            generation_live: true,
            pair_key_live: true,
        };
        Self {
            directions: [direction.clone(), direction],
            week: 0,
            wire: Vec::new(),
        }
    }

    /// §6.8: pair mode when a root is held and its week key lives, provisional while the
    /// `reply_seed` lives, intro otherwise — and `None` when even intro has no key, which is
    /// `NO_SEAL_KEY`: the sender fetches a bundle (EST-START, §5.5) instead of sealing.
    fn mode(&self, index: usize) -> Option<Mode> {
        let direction = &self.directions[index];
        if direction.root_held && direction.pair_key_live {
            Some(Mode::Pair)
        } else if direction.reply_seed_live && direction.acknowledged {
            Some(Mode::Provisional)
        } else if direction.generation_live {
            Some(Mode::Intro)
        } else {
            None
        }
    }
}

/// §21.3 point 1: a root travels only in an acknowledged session's normal message, and only while
/// the offer it answers is unacknowledged.
fn root_rides(seal: &Seal, index: usize, mode: Mode) -> bool {
    seal.directions[1 - index].acknowledged
        && !seal.directions[1 - index].offer_acknowledged
        && mode != Mode::Intro
}

fn em2_successors(seal: &Seal) -> Vec<Seal> {
    let mut out = Vec::new();
    for index in 0..2 {
        // A send in the mode the rule picks; a root rides only in an acknowledged session's
        // normal message (§21.3 point 1), never in a PreKey message.
        if seal.wire.len() < WIRE_MAX {
            if let Some(mode) = seal.mode(index) {
                let carries_root = root_rides(seal, index, mode);
                let mut next = seal.clone();
                next.wire.push((
                    u8::try_from(index).expect("two directions"),
                    mode,
                    carries_root,
                ));
                out.push(next);
            }
        }
        // EST-START: a fetch installs the peer's live generation again (§5.5), which is what a
        // sender with `NO_SEAL_KEY` does instead of naming an erased one.
        if !seal.directions[index].generation_live {
            let mut refetched = seal.clone();
            refetched.directions[index].generation_live = true;
            out.push(refetched);
        }
        // A renewal: out keys for the peer are dropped and a new root is offered (§21.3 point 2).
        let mut renewed = seal.clone();
        renewed.directions[index].root_held = false;
        renewed.directions[index].offer_acknowledged = false;
        out.push(renewed);
        // The erasure schedules (§5.4, §22.8.5, §6.3).
        for erase in 0..3 {
            let mut next = seal.clone();
            match erase {
                0 => next.directions[index].generation_live = false,
                1 => next.directions[index].reply_seed_live = false,
                _ => next.directions[index].pair_key_live = false,
            }
            out.push(next);
        }
    }
    for position in 0..seal.wire.len() {
        let (index, _, carries_root) = seal.wire[position];
        let index = usize::from(index);
        let mut delivered = seal.clone();
        delivered.wire.remove(position);
        delivered.directions[index].acknowledged = true;
        delivered.directions[1 - index].acknowledged = true;
        if carries_root {
            delivered.directions[1 - index].root_held = true;
            delivered.directions[1 - index].pair_key_live = true;
            delivered.directions[index].offer_acknowledged = true;
        }
        out.push(delivered);

        let mut dropped = seal.clone();
        dropped.wire.remove(position);
        out.push(dropped);
    }
    if seal.week < 2 {
        let mut next = seal.clone();
        next.week += 1;
        out.push(next);
    }
    out
}

/// The EM-2 properties, evaluated **at seal time** (§15.2: "the sender never seals with a key the
/// recipient cannot hold"). They are about the choice the sender makes, not about what a later
/// erasure does to an envelope already in flight — a blob whose key the recipient erased after it
/// was sealed is a declared loss (§8.6), not a violation.
fn em2_seal_time(seal: &Seal, index: usize, mode: Mode, carries_root: bool) -> Result<(), String> {
    let direction = &seal.directions[index];
    match mode {
        Mode::Pair if !direction.root_held => {
            return Err("a pair envelope without a root".to_string())
        }
        Mode::Pair if !direction.pair_key_live => {
            return Err("a pair envelope after the week key was erased".to_string())
        }
        Mode::Provisional if !direction.reply_seed_live => {
            return Err("a provisional envelope after the reply seed was erased".to_string())
        }
        Mode::Intro if !direction.generation_live => {
            return Err("an intro envelope naming an erased generation".to_string())
        }
        _ => {}
    }
    // "No root travels in a PreKey message": intro mode carries the first flight.
    if carries_root && mode == Mode::Intro {
        return Err("a root rode in an intro (PreKey) envelope".to_string());
    }
    // A root only leaves an acknowledged session (§21.3 point 1).
    if carries_root && !seal.directions[1 - index].acknowledged {
        return Err("a root left an unacknowledged session".to_string());
    }
    Ok(())
}

/// The state-level property: the mode rule of §6.8 never names a key the sender does not hold.
fn em2_properties(seal: &Seal) -> Result<(), String> {
    for index in 0..2 {
        let Some(mode) = seal.mode(index) else {
            continue;
        };
        let direction = &seal.directions[index];
        if mode == Mode::Pair && !(direction.root_held && direction.pair_key_live) {
            return Err("the mode rule picked pair without a live pair key".to_string());
        }
        if mode == Mode::Provisional && !direction.reply_seed_live {
            return Err("the mode rule picked provisional without a reply seed".to_string());
        }
    }
    Ok(())
}

#[test]
fn em2_seal_modes_hold_every_property() {
    let budget = state_budget();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    let start = Seal::new();
    seen.insert(format!("{start:?}"));
    queue.push_back(start);
    let mut states = 0usize;
    let mut seals_checked = 0usize;
    while let Some(seal) = queue.pop_front() {
        states += 1;
        assert!(states <= budget, "EM-2 exceeded {budget} states");
        em2_properties(&seal).expect("EM-2 state property");
        for index in 0..2 {
            let Some(mode) = seal.mode(index) else {
                continue;
            };
            let carries_root = root_rides(&seal, index, mode);
            em2_seal_time(&seal, index, mode, carries_root).expect("EM-2 seal-time property");
            seals_checked += 1;
        }
        for next in em2_successors(&seal) {
            if seen.insert(format!("{next:?}")) {
                queue.push_back(next);
            }
        }
    }
    assert!(states > 500, "EM-2 explored only {states} states");
    println!("EM-2: {states} states, {seals_checked} seal decisions");
}

/// The EM-2 counterpart of MC-19: a sender that keeps sealing in pair mode after a renewal dropped
/// its root must break the "never seal with a key the recipient cannot hold" property.
#[test]
fn em2_detects_a_sender_that_ignores_a_renewal() {
    let mut seal = Seal::new();
    seal.directions[0].acknowledged = true;
    seal.directions[1].acknowledged = true;
    seal.directions[0].root_held = false;
    assert!(em2_seal_time(&seal, 0, Mode::Pair, false).is_err());
    // And a sender that attaches a root to a first flight.
    seal.directions[0].root_held = true;
    assert!(em2_seal_time(&seal, 0, Mode::Intro, true).is_err());
}
