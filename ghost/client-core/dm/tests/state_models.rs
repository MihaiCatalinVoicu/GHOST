//! The exhaustive state models **EM-1** (sessions) and **EM-2** (seal modes) of design §15.2,
//! graft RG-1, run in the `rust` job.
//!
//! These are abstract models, not the production code path: they enumerate **states**, not action
//! sequences, so the run is exhaustive over everything reachable inside the stated bound instead of
//! sampling a huge sequence space. Breadth-first search from the initial state applies every
//! enabled action, canonicalises the result (session and root identifiers are renamed to their
//! order of first appearance, so two runs that differ only in numbering are one state), and checks
//! every property at every state and every seal decision.
//!
//! **What EM-1 covers.** R-SS0 … R-SS4: `UNACK_MAX` re-establishment, R-SS1's creation and the
//! §22.8.4 stale-first-flight exception, R-SS2's swap, R-SS3's convergence (the directed
//! enumeration of `em1_simultaneous_initiation_converges`) and SWEEP's retirement of a `previous`
//! row at its `retire_day`, with the D2b reuse tuple that outlives it. Properties: the structural
//! invariants of §15.3 this model can see, no decryption on a session of another identity, no
//! second session from a replayed first flight, CS-2 (nothing displayed twice inside one database)
//! and no message lost on a session the device held. Process death at every step (RG-1) is not a
//! separate action: a crash before a commit leaves the world unchanged, which is the same
//! successor as not taking the action, and the search takes every other action from that state.
//!
//! **What EM-2 covers.** The intro → provisional → pair transitions per direction, root offers and
//! acknowledgements, renewals, the erasure of generations and of `prov_env`, and the three clauses
//! of §22.8.5 rule 3 with the write-once anchors and monotone `pair_sent` of rule 4. Its property
//! is §15.2's — the sender never seals with a key the **recipient** cannot hold — which the mode
//! rule never reads, so `em2_detects_a_sender_that_breaks_the_mode_rule` runs three mutants
//! through the search and each breaks it. Rule 5's day arithmetic is not abstracted into the
//! search: `the_provisional_schedule_has_no_gap` checks it exhaustively in days.
//!
//! **Bounds.** At most two user sends per side by default, and at most [`WIRE_MAX`] messages in
//! flight. The design writes "at most 6 user sends per side": the reachable state count grows by
//! roughly an order of magnitude per extra send (140 075 states at two, 2 296 274 at three), so
//! `GHOST_DM_EM_SENDS`, with `GHOST_DM_EM_BUDGET` raised alongside it, takes the run further, and
//! the nightly `dm-state-models` workflow runs three in the release profile. **Recorded
//! deviation:** the enforced bounds are 2 (pull requests) and 3 (nightly), not 6.
//!
//! The models complement the ProVerif obligations M-1 … M-8 of §9.5, which check secrecy and
//! authentication rather than state reachability, and mutant MC-19 ("newest decrypt wins") must
//! fail EM-1 — `mc19_newest_decrypt_wins_is_detected` runs the model with that rule substituted and
//! asserts that a **property** breaks, told apart from a budget overflow by [`Stop`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Design §8.7: an initiator session unacknowledged this long is stale.
const UNACK_MAX: u32 = 28;
/// Design §8.2 R-SS1: a demoted row retires after this many days.
const RETIRE_DAYS: u32 = 46;
/// Messages allowed in flight at once in the exhaustive search.
const WIRE_MAX: usize = 2;
/// Messages allowed in flight in the directed R-SS3 convergence enumeration, which explores
/// schedules rather than states and can afford more: with three sends per side both flows can be
/// wholly in flight at once, which is the simultaneous initiation R-SS3 is about.
const CONVERGENCE_WIRE_MAX: usize = 6;
/// Explored states before the search gives up (a guard against a model change that explodes).
/// The default leaves both models room to grow — EM-1 explores 140 075 states at the default
/// bound and EM-2 356 463 — while still catching an explosion. Raising `GHOST_DM_EM_SENDS` needs
/// `GHOST_DM_EM_BUDGET` raised with it: the reachable state count grows roughly an order of
/// magnitude per extra send per side.
fn state_budget() -> usize {
    std::env::var("GHOST_DM_EM_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
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
    /// Message ids this device rendered. Part of the canonical state: two worlds that differ in
    /// what was displayed are two worlds (§15.2's "no lost message outside the declared bound").
    displayed: BTreeSet<u16>,
    /// Set when a message id was rendered twice, which CS-2 forbids.
    displayed_twice: bool,
    /// Set when a message arrived on a session this device **held**, on a chain index that row had
    /// not seen, and was not displayed: a loss outside the declared classes of §7.7.
    lost_on_held_session: bool,
    /// Sessions SWEEP retired (R-SS4). A retired session never comes back: the D2b reuse tuple
    /// outlives its row.
    retired: BTreeSet<u16>,
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
            displayed_twice: false,
            lost_on_held_session: false,
            retired: BTreeSet::new(),
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
            let retired: Vec<u16> = device
                .retired
                .iter()
                .map(|session| rename(*session, &mut sessions))
                .collect();
            // What was displayed is part of the state, as a count and the two flags that name the
            // ways it can go wrong: message identifiers themselves are not (they would split
            // states that differ only in numbering), but a world that displayed a message and one
            // that did not are different worlds.
            out.push_str(&format!(
                "|g{}|s{}|u{:?}|p{:?}|d{}|x{}|l{}|t{:?}",
                device.generation,
                device.sends_used,
                reuse,
                device.pinned_peer,
                device.displayed.len(),
                u8::from(device.displayed_twice),
                u8::from(device.lost_on_held_session),
                retired
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

/// One user send by device `index`, or `None` when the device cannot send now: its budget is used
/// or the wire is full.
///
/// This is the **only** send transition. `em1_successors` and the convergence enumeration both go
/// through it, so neither can take a different action while believing it sent something.
fn em1_send(world: &World, index: usize, sends: u8, wire_max: usize) -> Option<World> {
    if world.devices[index].sends_used >= sends || world.wire.len() >= wire_max {
        None
    } else {
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
        Some(next)
    }
}

/// One transition of EM-1. Returns the worlds reachable by every enabled action.
fn em1_successors(world: &World, selection: Selection, sends: u8) -> Vec<World> {
    let mut out = Vec::new();

    // A user send on either device.
    for index in 0..2 {
        if let Some(next) = em1_send(world, index, sends, WIRE_MAX) {
            out.push(next);
        }
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

    // SWEEP (R-SS4): a `previous` row is deleted at its `retire_day`. The D2b reuse tuple stays,
    // so a replayed first flight of that session creates nothing afterwards.
    for index in 0..2 {
        let due = world.devices[index]
            .previous
            .as_ref()
            .and_then(|row| row.retire)
            .is_some_and(|retire| world.day >= retire);
        if !due {
            continue;
        }
        let mut next = world.clone();
        let device = &mut next.devices[index];
        if let Some(row) = device.previous.take() {
            device.retired.insert(row.session);
        }
        out.push(next);
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
        device.retired.clear();
        // A restore from seed loses the database, message history and `oracle_displayed` with it
        // (SCN-I): CS-2 is "at most one row per device and message id" inside one database, so what
        // this device rendered before the restore is not what it renders after it.
        device.displayed.clear();
        device.pinned_peer = None;
        out.push(next);
    }

    // Time passing: to `UNACK_MAX`, where an unacknowledged initiator session is stale, and then
    // past the `retire_day` of a row demoted then, where SWEEP's R-SS4 deletion becomes enabled.
    if world.day == 0 {
        let mut next = world.clone();
        next.day = UNACK_MAX;
        out.push(next);
    } else if world.day == UNACK_MAX {
        let mut next = world.clone();
        next.day = UNACK_MAX + RETIRE_DAYS;
        out.push(next);
    }

    out
}

/// The receive path: §7.6 dedup, §8.2 R-SS1 and R-SS2, §8.2 rules 3 and 5.
///
/// It also records what the device rendered. A message delivered on a session the device **held**,
/// on a chain index that row had not seen, must be displayed: every other loss belongs to one of
/// the declared classes of §7.7 (a replay, a reuse tuple, an unknown generation, a stale first
/// flight, an unpinned identity, a normal message of a session that is gone). The two flags the
/// properties read are set here, at delivery time, because that is where the information is.
fn apply_delivery(world: &mut World, target: usize, message: &Message, selection: Selection) {
    // Held by the recipient, on a chain index that row has not consumed: the message must render.
    let held = {
        let device = &world.devices[target];
        let pinned_elsewhere = device
            .pinned_peer
            .is_some_and(|pinned| pinned != message.sender_identity);
        !pinned_elsewhere
            && [&device.current, &device.previous]
                .into_iter()
                .flatten()
                .any(|row| row.session == message.session && !row.seen.contains(&message.chain))
    };
    let displayed = deliver(world, target, message, selection);
    if held && !displayed {
        world.devices[target].lost_on_held_session = true;
    }
}

/// The delivery itself. Returns whether the message was rendered.
fn deliver(world: &mut World, target: usize, message: &Message, selection: Selection) -> bool {
    let day = world.day;
    let device = &mut world.devices[target];

    // §8.2 rule 3 / §8.3: a message under an identity that is not the pinned one is dropped with
    // no state change. The pin is taken at first contact.
    if let Some(pinned) = device.pinned_peer {
        if pinned != message.sender_identity {
            return false;
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
            return false;
        }
        row.seen.insert(message.chain);
        row.acknowledged = true;
        row.unack_since = None;
        if let Kind::PreKey { bind, .. } = message.kind {
            row.bind = row.bind.max(bind);
        }
        // CS-2: at most one rendering per device and message.
        if !device.displayed.insert(message.id) {
            device.displayed_twice = true;
        }

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
        return true;
    }

    let Kind::PreKey { generation, bind } = message.kind else {
        return false; // a normal message of an unknown session does not decrypt
    };
    // D2b: a replayed first flight after its session was replaced or deleted.
    if device.reuse.contains(&(generation, message.session)) {
        return false;
    }
    // The generation the message names was regenerated by a restore: `unknown_generation`.
    if generation != device.generation {
        return false;
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
            return false; // drop(stale_session): no session, no reuse tuple
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
    if !device.displayed.insert(message.id) {
        device.displayed_twice = true;
    }
    true
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
        // R-SS4: SWEEP deleted the row at its retire day, and the session does not come back — a
        // replayed first flight of it meets the reuse tuple, which outlives the row.
        for row in [&device.current, &device.previous].into_iter().flatten() {
            if device.retired.contains(&row.session) {
                return Err(format!(
                    "device {index}: a retired session is live again ({})",
                    row.session
                ));
            }
        }
        // CS-2 and §15.2's "no lost message outside the declared bound of §7.7", as recorded by
        // the delivery: nothing rendered twice, and nothing lost on a session the device held.
        if device.displayed_twice {
            return Err(format!("device {index}: a message was displayed twice"));
        }
        if device.lost_on_held_session {
            return Err(format!(
                "device {index}: a message of a held session on an unseen chain index was lost"
            ));
        }
    }
    Ok(())
}

/// Why an exploration stopped. A budget overflow is **not** a property failure: a model change
/// that merely explodes the state space must not read as "the mutant was detected", which is what
/// an untyped error let `mc19_newest_decrypt_wins_is_detected` accept.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    /// A property of §15.2 or an invariant of §15.3 failed, with its text.
    Property(String),
    /// The search hit `GHOST_DM_EM_BUDGET` states.
    Budget(usize),
}

fn explore_em1(selection: Selection) -> Result<usize, Stop> {
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
            return Err(Stop::Budget(budget));
        }
        em1_properties(&world).map_err(Stop::Property)?;
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

/// §8.2 "Model obligation": mutant MC-19 ("newest decrypt wins") must fail an EM-1 **property**.
///
/// What fires is the §22.8.4 structural invariant — the mutant promotes whatever decrypted last,
/// so a first flight older than the responder `current` becomes `current` itself. R-SS3's
/// convergence is *not* what catches it (measured: `converges(Selection::NewestWins)` returns
/// `Ok`), and a budget overflow is not a detection either, so both are named here rather than
/// accepted as "some error".
#[test]
fn mc19_newest_decrypt_wins_is_detected() {
    match explore_em1(Selection::NewestWins) {
        Err(Stop::Property(reason)) => assert!(
            reason.contains("an older first flight became current"),
            "MC-19 must break the §22.8.4 invariant, not {reason}"
        ),
        other => panic!("MC-19 must fail an EM-1 property, got {other:?}"),
    }
}

/// The two properties this model gained are falsifiable, and this is where that is shown: each
/// half applies the transition function, then breaks one rule by hand — the way a mutant would —
/// and asserts that `em1_properties` names the failure.
///
/// - CS-2, D2a: a message key that comes back renders its message a second time.
/// - R-SS4, D2b: a reuse tuple deleted with the retired row lets a replayed first flight bring the
///   retired session back.
#[test]
fn the_display_and_retirement_properties_catch_their_mutants() {
    // D2a removed: the row forgets the chain index it consumed.
    let mut world = em1_send(&World::new(), 0, 2, WIRE_MAX).expect("send");
    let message = world.wire[0];
    apply_delivery(&mut world, 1, &message, Selection::Rules);
    em1_properties(&world).expect("one delivery holds every property");
    world.devices[1]
        .current
        .as_mut()
        .expect("the first flight created a row")
        .seen
        .clear();
    apply_delivery(&mut world, 1, &message, Selection::Rules);
    let reason = em1_properties(&world).expect_err("a second rendering must be caught");
    assert!(reason.contains("displayed twice"), "{reason}");

    // D2b removed: the reuse tuple goes with the retired row.
    let mut world = em1_send(&World::new(), 0, 2, WIRE_MAX).expect("send");
    let first = world.wire.remove(0);
    apply_delivery(&mut world, 1, &first, Selection::Rules);
    let device = &mut world.devices[1];
    let mut retired = device.current.take().expect("the row").clone();
    retired.retire = Some(RETIRE_DAYS);
    device.retired.insert(retired.session);
    device.current = Some(Row {
        session: 99,
        role: Role::Responder,
        acknowledged: true,
        bind: 0,
        unack_since: None,
        retire: None,
        peer_identity: first.sender_identity,
        seen: BTreeSet::new(),
        sent: 0,
    });
    device.reuse.insert((device.generation, 99));
    em1_properties(&world).expect("a retired session that stays retired holds");
    // The mutant: SWEEP deleted the reuse tuple with the row it retired.
    let session = retired.session;
    world.devices[1]
        .reuse
        .retain(|(_, reused)| *reused != session);
    apply_delivery(&mut world, 1, &first, Selection::Rules);
    let reason = em1_properties(&world).expect_err("a revived retired session must be caught");
    assert!(
        reason.contains("a retired session is live again"),
        "{reason}"
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
                    // A send or nothing: the wire bound of this enumeration is its own, and a
                    // schedule that cannot send at this step simply does not.
                    if let Some(next) = em1_send(&world, index, sends, CONVERGENCE_WIRE_MAX) {
                        assert_eq!(
                            next.devices[index].sends_used,
                            world.devices[index].sends_used + 1,
                            "the send transition must send"
                        );
                        world = next;
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
                world = em1_send(&world, index, sends, CONVERGENCE_WIRE_MAX)
                    .expect("a settling send is always enabled: budget reset, wire empty");
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

// ---------------------------------------------------------------------------------------------
// EM-2: seal modes, the provisional lifetime of §22.8.5 rules 3-5, and the root-travel rules
// ---------------------------------------------------------------------------------------------

/// The seal mode a sender picks (§6.8 sender mode rule, as amended by §22.8.5 rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Intro,
    Provisional,
    Pair,
}

/// Which sender rule the model runs. The mutants are run **through the search**, so what catches
/// them is a property of a reachable state, not a hand-built call to the checker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SealRule {
    /// §6.8 with §22.8.5 rule 3.
    Design,
    /// A sender that keeps sealing in pair mode after a renewal dropped its root.
    IgnoreRenewal,
    /// A sender that ignores rule 3's `olm_session.pair_sent = 0` clause.
    IgnorePairSent,
    /// A sender that ignores rule 3's `now < prov_anchor_minute + 28 d` clause.
    IgnoreWindow,
}

/// One device's side of one session. Time is **ordinal** here, not arithmetic: the instants that
/// matter are "the sealing window closed" and "the erase deadline passed", and the day arithmetic
/// behind them is checked exactly, and separately, by `the_provisional_schedule_has_no_gap`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Party {
    /// It decrypted a message of the peer, so its session is acknowledged (§21.3 point 1).
    acknowledged: bool,
    /// It holds the peer's pair root and seals pair mode toward it (§6.3).
    root_held: bool,
    /// Its own offer reached the peer, so it stops re-offering (§21.3 point 2).
    offer_acknowledged: bool,
    /// §22.8.5 rule 3: it sealed a pair envelope on this session. Never back to `false`.
    pair_sent: bool,
    /// `prov_anchor_minute` is set — write-once (§22.8.5 rule 4).
    anchored: bool,
    /// `now >= prov_anchor_minute + 28 d`: the provisional **sealing** window closed (rule 3).
    window_closed: bool,
    /// It still holds its own `prov_env`, the key that opens provisional envelopes sent **to** it.
    prov_env: bool,
    /// It opened a pair envelope under the newest root: the `pair-open + 45 d` branch of
    /// `prov_erase_minute` (rule 4) is armed for its `prov_env`.
    pair_opened: bool,
    /// It still holds the generation secrets its published bundle names (§5.4).
    generation: bool,
    /// It fetched a bundle of the peer and can name that generation in an intro envelope (§5.5).
    peer_generation_known: bool,
}

/// A sealed envelope in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Envelope {
    from: u8,
    mode: Mode,
    carries_root: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Seal {
    parties: [Party; 2],
    wire: Vec<Envelope>,
}

impl Seal {
    fn new() -> Self {
        let party = Party {
            acknowledged: false,
            root_held: false,
            offer_acknowledged: false,
            pair_sent: false,
            anchored: false,
            window_closed: false,
            prov_env: true,
            pair_opened: false,
            generation: true,
            peer_generation_known: true,
        };
        Self {
            parties: [party.clone(), party],
            wire: Vec::new(),
        }
    }

    /// §6.8 with §22.8.5 rule 3: pair mode while a root is held, provisional while the session's
    /// `reply_seed` may still key it — acknowledged, `pair_sent = 0` and inside the anchor's
    /// 28-day window — intro otherwise, and `None` when even intro has no key, which is
    /// `NO_SEAL_KEY`: the sender fetches a bundle (EST-START, §5.5) instead of sealing.
    fn mode(&self, index: usize, rule: SealRule) -> Option<Mode> {
        let party = &self.parties[index];
        if party.root_held || rule == SealRule::IgnoreRenewal {
            Some(Mode::Pair)
        } else if party.prov_env
            && party.acknowledged
            && party.anchored
            && (!party.pair_sent || rule == SealRule::IgnorePairSent)
            && (!party.window_closed || rule == SealRule::IgnoreWindow)
        {
            Some(Mode::Provisional)
        } else if party.peer_generation_known {
            Some(Mode::Intro)
        } else {
            None
        }
    }
}

/// §21.3 point 1: a root travels only in an acknowledged session's normal message, and only while
/// the offer it answers is unacknowledged.
fn root_rides(seal: &Seal, index: usize, mode: Mode) -> bool {
    seal.parties[index].acknowledged
        && !seal.parties[index].offer_acknowledged
        && mode != Mode::Intro
}

fn em2_successors(seal: &Seal, rule: SealRule) -> Vec<Seal> {
    let mut out = Vec::new();
    for index in 0..2 {
        // A send in the mode the rule picks; a root rides only in an acknowledged session's
        // normal message (§21.3 point 1), never in a PreKey message.
        if seal.wire.len() < WIRE_MAX {
            if let Some(mode) = seal.mode(index, rule) {
                let mut next = seal.clone();
                if mode == Mode::Pair {
                    // Rule 3: `pair_sent` goes 0 -> 1 and never back.
                    next.parties[index].pair_sent = true;
                }
                next.wire.push(Envelope {
                    from: u8::try_from(index).expect("two parties"),
                    mode,
                    carries_root: root_rides(seal, index, mode),
                });
                out.push(next);
            }
        }
        // EST-START: a fetch installs the peer's live generation again (§5.5), which is what a
        // sender with `NO_SEAL_KEY` does instead of naming an erased one.
        if !seal.parties[index].peer_generation_known && seal.parties[1 - index].generation {
            let mut next = seal.clone();
            next.parties[index].peer_generation_known = true;
            out.push(next);
        }
        // A renewal: the root this side holds is dropped and a new one is offered (§21.3 point 2).
        if seal.parties[index].root_held || seal.parties[index].offer_acknowledged {
            let mut next = seal.clone();
            next.parties[index].root_held = false;
            next.parties[index].offer_acknowledged = false;
            out.push(next);
        }
        // `now >= prov_anchor_minute + 28 d`: the provisional sealing window closes (rule 3).
        if seal.parties[index].anchored && !seal.parties[index].window_closed {
            let mut next = seal.clone();
            next.parties[index].window_closed = true;
            out.push(next);
        }
        // `prov_erase_minute`, the `prov_anchor_minute + 119 d` branch of rule 4. It is enabled
        // only once the **peer's** sealing window has closed and no provisional envelope of the
        // peer is still in flight, which is the ordering rule 5 derives and
        // `the_provisional_schedule_has_no_gap` checks in days: 28 d of sealing plus 51 d of
        // acceptance, from an anchor at most 37 d 2 h later than the peer's, stay inside 119 d.
        let peer = u8::try_from(1 - index).expect("two parties");
        if seal.parties[index].prov_env
            && seal.parties[1 - index].window_closed
            && !seal
                .wire
                .iter()
                .any(|envelope| envelope.from == peer && envelope.mode == Mode::Provisional)
        {
            let mut next = seal.clone();
            next.parties[index].prov_env = false;
            out.push(next);
        }
        // The `pair-open + 45 d` branch of rule 4: armed as soon as this side opened a pair
        // envelope. **Nothing else guards it** — what keeps a sender from sealing provisional
        // afterwards is rule 3's `pair_sent = 0` clause, which is why `em2_seal_time`'s first
        // clause holds and why the `IgnorePairSent` mutant breaks it.
        if seal.parties[index].prov_env && seal.parties[index].pair_opened {
            let mut next = seal.clone();
            next.parties[index].prov_env = false;
            out.push(next);
        }
        // §5.4: a superseded generation is erased after its retention, which outlives every
        // sender's use of the bundle that named it — so the peer's knowledge of it goes with it.
        if seal.parties[index].generation {
            let mut next = seal.clone();
            next.parties[index].generation = false;
            next.parties[1 - index].peer_generation_known = false;
            out.push(next);
        }
        // A new generation is published (the weekly rotation of §5.3, or a restore).
        if !seal.parties[index].generation {
            let mut next = seal.clone();
            next.parties[index].generation = true;
            out.push(next);
        }
    }

    for position in 0..seal.wire.len() {
        let envelope = seal.wire[position];
        let recipient = 1 - usize::from(envelope.from);

        let mut delivered = seal.clone();
        delivered.wire.remove(position);
        delivered.parties[recipient].acknowledged = true;
        // Rule 4: the anchor is write-once. The model sets it at the first decryption, which is
        // the initiator's rule and is never later than the responder's (its first provisional
        // seal), so every erase deadline the model derives is at or before the design's.
        delivered.parties[recipient].anchored = true;
        if envelope.mode == Mode::Pair {
            delivered.parties[recipient].pair_opened = true;
        }
        if envelope.carries_root {
            delivered.parties[recipient].root_held = true;
            delivered.parties[usize::from(envelope.from)].offer_acknowledged = true;
        }
        out.push(delivered);

        let mut dropped = seal.clone();
        dropped.wire.remove(position);
        out.push(dropped);
    }
    out
}

/// The EM-2 property of §15.2 — **"the sender never seals with a key the recipient cannot
/// hold"** — and the sender-side clauses of §6.8, §22.8.5 rule 3 and §21.3 point 1.
///
/// The first half is about the **recipient's** state, which the mode rule never reads: it holds
/// only because the recipient's two erasure branches are each blocked by something on the sender's
/// side — the `prov_anchor_minute + 119 d` branch by the sender's closed window (rule 5's
/// arithmetic, checked in days by `the_provisional_schedule_has_no_gap`) and the
/// `pair-open + 45 d` branch by rule 3's `pair_sent = 0` clause. Drop either clause and a
/// reachable state breaks this.
///
/// It is stated at **seal time**, as §15.2 words it: an envelope already in flight when the
/// recipient erases is §8.6's declared loss, not a violation.
fn em2_seal_time(seal: &Seal, index: usize, mode: Mode, carries_root: bool) -> Result<(), String> {
    let party = &seal.parties[index];
    let recipient = &seal.parties[1 - index];
    match mode {
        Mode::Provisional if !recipient.prov_env => {
            return Err("a provisional envelope the recipient can no longer open".to_string())
        }
        Mode::Intro if !recipient.generation => {
            return Err("an intro envelope the recipient can no longer open".to_string())
        }
        _ => {}
    }
    // The sender holds the key it seals with. `pair_sent` and the 28-day window are **rules**, not
    // properties, so they are not restated here: a mutant that drops one of them must be caught by
    // the property above, which is where §22.8.5 rule 3 earns its place.
    match mode {
        Mode::Pair if !party.root_held => return Err("a pair envelope without a root".to_string()),
        Mode::Provisional if !party.prov_env => {
            return Err("a provisional envelope after the reply seed was erased".to_string())
        }
        Mode::Intro if !party.peer_generation_known => {
            return Err("an intro envelope naming an erased generation".to_string())
        }
        _ => {}
    }
    // "No root travels in a PreKey message": intro mode carries the first flight.
    if carries_root && mode == Mode::Intro {
        return Err("a root rode in an intro (PreKey) envelope".to_string());
    }
    // A root only leaves an acknowledged session (§21.3 point 1).
    if carries_root && !party.acknowledged {
        return Err("a root left an unacknowledged session".to_string());
    }
    Ok(())
}

/// The state property: no envelope in flight carries a root it should not (§21.3 point 1), in
/// any state, however it got there.
fn em2_properties(seal: &Seal) -> Result<(), String> {
    for envelope in &seal.wire {
        if envelope.mode == Mode::Intro && envelope.carries_root {
            return Err("a root is in flight inside an intro envelope".to_string());
        }
    }
    Ok(())
}

/// Rule 4's write-once anchor and monotone `pair_sent`, as a property of every transition.
fn em2_transition(before: &Seal, after: &Seal) -> Result<(), String> {
    for index in 0..2 {
        if before.parties[index].anchored && !after.parties[index].anchored {
            return Err(format!(
                "party {index}: the provisional anchor was rewritten"
            ));
        }
        if before.parties[index].pair_sent && !after.parties[index].pair_sent {
            return Err(format!("party {index}: pair_sent went back to 0"));
        }
        if before.parties[index].window_closed && !after.parties[index].window_closed {
            return Err(format!("party {index}: the sealing window reopened"));
        }
        if before.parties[index].pair_opened && !after.parties[index].pair_opened {
            return Err(format!("party {index}: a pair-open was forgotten"));
        }
    }
    Ok(())
}

fn explore_em2(rule: SealRule) -> Result<(usize, usize), Stop> {
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
        if states > budget {
            return Err(Stop::Budget(budget));
        }
        em2_properties(&seal).map_err(Stop::Property)?;
        for index in 0..2 {
            let Some(mode) = seal.mode(index, rule) else {
                continue;
            };
            let carries_root = root_rides(&seal, index, mode);
            em2_seal_time(&seal, index, mode, carries_root).map_err(Stop::Property)?;
            seals_checked += 1;
        }
        for next in em2_successors(&seal, rule) {
            em2_transition(&seal, &next).map_err(Stop::Property)?;
            if seen.insert(format!("{next:?}")) {
                queue.push_back(next);
            }
        }
    }
    Ok((states, seals_checked))
}

#[test]
fn em2_seal_modes_hold_every_property() {
    let (states, seals) = explore_em2(SealRule::Design).expect("EM-2");
    assert!(states > 500, "EM-2 explored only {states} states");
    println!("EM-2: {states} states, {seals} seal decisions");
}

/// The EM-2 counterparts of MC-19, each run **through the search**: a sender that ignores the
/// renewal, one that ignores rule 3's `pair_sent` clause, and one that ignores its 28-day window
/// must each break a property of a reachable state.
#[test]
fn em2_detects_a_sender_that_breaks_the_mode_rule() {
    let cases = [
        // It seals pair with a root it no longer holds.
        (SealRule::IgnoreRenewal, "a pair envelope without a root"),
        // Both of rule 3's clauses are load-bearing: without either, the sender reaches a state in
        // which the recipient has already erased the `prov_env` that opens what it seals.
        (
            SealRule::IgnorePairSent,
            "a provisional envelope the recipient can no longer open",
        ),
        (
            SealRule::IgnoreWindow,
            "a provisional envelope the recipient can no longer open",
        ),
    ];
    for (rule, expected) in cases {
        match explore_em2(rule) {
            Err(Stop::Property(reason)) => {
                assert!(reason.contains(expected), "{rule:?}: got {reason}")
            }
            other => panic!("{rule:?} must break an EM-2 property, got {other:?}"),
        }
    }
}

/// §15.2's EM-2 property, stated over the recipient's own state: a sender that seals provisional
/// to a peer that has erased its `prov_env` breaks it. Under the design rules no reachable state
/// admits this call — which is the point of the mutants above.
#[test]
fn em2_names_a_provisional_envelope_the_recipient_cannot_open() {
    let mut seal = Seal::new();
    seal.parties[0].acknowledged = true;
    seal.parties[0].anchored = true;
    seal.parties[1].prov_env = false;
    seal.parties[1].pair_opened = true;
    let reason = em2_seal_time(&seal, 0, Mode::Provisional, false)
        .expect_err("the recipient cannot open it");
    assert!(reason.contains("can no longer open"), "{reason}");
}

// ---------------------------------------------------------------------------------------------
// The day arithmetic of §22.8.5 rules 3-5, exhaustively
// ---------------------------------------------------------------------------------------------

/// §7.7 point 4 / §6.3: `FRESH` and the `2σ` slack an envelope is accepted with.
const FRESH_DAYS: u32 = 45;
const SIGMA2_DAYS: u32 = 6;
/// The acceptance window of §7.6: an envelope authored at `t` is opened at the latest at
/// `t + FRESH + 2σ`.
const ACCEPT_DAYS: u32 = FRESH_DAYS + SIGMA2_DAYS;
/// §7.6: the relay lifetime, the bound CS-3's premise uses (37 d 2 h, rounded up to whole days).
const RELAY_LIFETIME_DAYS: u32 = 38;
/// §22.8.5 rule 3: provisional sealing stops at `prov_anchor_minute + 28 d`.
const PROV_WINDOW_DAYS: u32 = 28;
/// §22.8.5 rule 4: `prov_erase_minute = min(pair-open + 45 d, prov_anchor_minute + 119 d)`.
const PROV_LIFETIME_DAYS: u32 = 119;
const PAIR_OPEN_KEEP_DAYS: u32 = 45;

/// Rule 5 ("Derivation (no loss inside CS-3)"), checked exhaustively in days rather than argued:
/// every provisional envelope either side seals inside its window is still openable when it
/// arrives, for every anchor offset CS-3 admits, every seal day inside the window and every
/// delivery day inside the acceptance window.
///
/// This is the arithmetic EM-2's search abstracts into an ordering ("the peer's window closed and
/// its last provisional envelope left the acceptance window, therefore the erase may happen"). It
/// is what the numbers of rule 4 are for: widening the window or shortening the lifetime fails
/// here, and the `+ 3 d` of headroom the design derives (`116 d 2 h` against `119 d`) is asserted
/// as the smallest margin of the whole enumeration.
#[test]
fn the_provisional_schedule_has_no_gap() {
    let mut worst = u32::MAX;
    let mut checked = 0usize;
    // The responder's anchor is its first provisional seal; the initiator's is its first
    // decryption, at most one relay lifetime later (CS-3's premise), and never earlier than the
    // responder's first seal (it decrypts that seal).
    for offset in 0..=RELAY_LIFETIME_DAYS {
        let responder_anchor = 0u32;
        let initiator_anchor = responder_anchor + offset;
        for (sender_anchor, recipient_anchor) in [
            (responder_anchor, initiator_anchor),
            (initiator_anchor, responder_anchor),
        ] {
            for seal in sender_anchor..sender_anchor + PROV_WINDOW_DAYS {
                for delivery in seal..=seal + ACCEPT_DAYS {
                    // The recipient's `pair-open` branch cannot apply to a provisional envelope:
                    // a pair envelope from this sender would have set its `pair_sent`, and rule 3
                    // forbids provisional afterwards. What is left is the anchor branch.
                    let erase = recipient_anchor + PROV_LIFETIME_DAYS;
                    assert!(
                        delivery < erase,
                        "a provisional envelope sealed on day {seal} and delivered on day \
                         {delivery} finds an erased reply seed (erase {erase})"
                    );
                    worst = worst.min(erase - delivery);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 100_000, "only {checked} combinations");
    // The design's own margin, restated: the last provisional seal is on day
    // `anchor + 28 d - 1`, its last acceptance `+ 51 d`, from an anchor at most one relay lifetime
    // after the peer's — `38 + 27 + 51 = 116 d` against the 119 d of rule 4, so 3 days of slack
    // (the design writes it as `anchor_R + 116 d 2 h`).
    assert_eq!(
        worst,
        PROV_LIFETIME_DAYS - (RELAY_LIFETIME_DAYS + (PROV_WINDOW_DAYS - 1) + ACCEPT_DAYS)
    );
    println!("rules 3-5: {checked} day combinations, smallest margin {worst} d");
}

/// The other half of rule 4's `min`: the `pair-open + 45 d` branch is safe because no provisional
/// envelope can still be in flight once a pair envelope has been opened — `pair_sent` blocks the
/// sender — and because the branch is never shorter than the acceptance window of the pair
/// envelope that armed it.
#[test]
fn the_pair_open_branch_outlasts_the_acceptance_window() {
    const { assert!(PAIR_OPEN_KEEP_DAYS >= FRESH_DAYS) };
    const { assert!(PAIR_OPEN_KEEP_DAYS + SIGMA2_DAYS >= ACCEPT_DAYS) };
}
