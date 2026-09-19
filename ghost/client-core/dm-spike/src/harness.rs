//! V-2: a scripted two-client harness over real Olm sessions (vodozemac 0.11.0 through
//! [`crate::olm::v11`]) with GHOST's session slots and selection rules: D2b (the first-flight
//! reuse set, §7.6), R-SS0 … R-SS3 (§8.2) with the age rules of §22.8.4.
//!
//! One `Client` models one device's view of one contact: the pinned Olm identity, the `current`
//! and `previous` slots, the reuse set and the own bundle generations. Envelopes carry what the
//! opened seal gives the session layer: the L1 bytes and kind, the recipient generation and the
//! binding minute of intro envelopes, and the L0 author minute. Two switches turn the harness
//! into the mutants that must be detected: `d2b` off (MC-7′) and `age_rules` off (MC-32).

use crate::codes::Code;
use crate::derive;
use crate::msc3814::DehydratedSecrets;
use crate::olm::{random_bytes, v11 as vz, x25519_public, L1Header};
use std::collections::{BTreeMap, HashSet};

pub const RETIRE_DAYS: u32 = 46;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub session_id: String,
    pub pickle: Vec<u8>,
    pub role: Role,
    pub acknowledged: bool,
    pub peer_bind_minute: Option<u32>,
    pub retire_day: Option<u32>,
    pub peer_gen_id: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub l1: Vec<u8>,
    pub is_prekey: bool,
    pub gen_id: u32,
    pub binding_minute: u32,
    pub author_minute: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotName {
    Current,
    Previous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drop {
    Replay,
    StaleSession,
    UnknownGeneration,
    Untrusted,
    Library(Code),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Displayed {
        plaintext: Vec<u8>,
        slot: SlotName,
        created: bool,
        swapped: bool,
    },
    Dropped(Drop),
}

#[derive(Clone, Copy, Debug)]
pub struct Bundle {
    pub identity: [u8; 32],
    pub fallback: [u8; 32],
    pub gen_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Establish {
    /// No session yet.
    First,
    /// `resetSession`, `reconnect`, KEYDEC: both rows deleted first (R-SS0).
    Reset,
    /// `UNACK_MAX` or `NO_SEAL_KEY`: `current` demoted to `previous` (R-SS0).
    Stale,
}

pub struct Client {
    identity_secret: [u8; 32],
    signing_seed: [u8; 32],
    generations: BTreeMap<u32, [u8; 32]>,
    newest_gen: u32,
    pub current: Option<Slot>,
    pub previous: Option<Slot>,
    pub reuse: HashSet<(u32, String)>,
    pub pinned_peer: Option<[u8; 32]>,
    pub d2b: bool,
    pub age_rules: bool,
    pub today: u32,
}

fn sid_bytes(session_id: &str) -> Vec<u8> {
    vz11::base64_decode(session_id).unwrap_or_default()
}

impl Client {
    /// A client whose Olm identity derives from the MESSAGING branch (§3.1).
    pub fn new(messaging_branch: &[u8; 32]) -> Self {
        let secrets = derive::olm_identity(messaging_branch);
        let mut client = Client {
            identity_secret: secrets.identity,
            signing_seed: secrets.account_signing_seed,
            generations: BTreeMap::new(),
            newest_gen: 0,
            current: None,
            previous: None,
            reuse: HashSet::new(),
            pinned_peer: None,
            d2b: true,
            age_rules: true,
            today: 20_000,
        };
        client.publish_generation();
        client
    }

    pub fn identity(&self) -> [u8; 32] {
        x25519_public(&self.identity_secret)
    }

    /// A new bundle generation (OWNER-WEEK or ACTIVATE).
    pub fn publish_generation(&mut self) -> Bundle {
        let mut gen_id = u32::from_be_bytes(random_bytes());
        while self.generations.contains_key(&gen_id) {
            gen_id = u32::from_be_bytes(random_bytes());
        }
        self.generations.insert(gen_id, random_bytes());
        self.newest_gen = gen_id;
        self.bundle()
    }

    pub fn bundle(&self) -> Bundle {
        let fallback = self
            .generations
            .get(&self.newest_gen)
            .copied()
            .unwrap_or([0u8; 32]);
        Bundle {
            identity: self.identity(),
            fallback: x25519_public(&fallback),
            gen_id: self.newest_gen,
        }
    }

    /// Restore from the seed (§8.6): the identity is re-derived; sessions, generations and the
    /// reuse set are lost; a new generation is published.
    pub fn restore(&mut self) {
        self.generations.clear();
        self.current = None;
        self.previous = None;
        self.reuse.clear();
        self.pinned_peer = None;
        self.publish_generation();
    }

    fn secrets(&self, fallback: Option<[u8; 32]>) -> DehydratedSecrets {
        DehydratedSecrets {
            curve25519: self.identity_secret,
            ed25519_seed: self.signing_seed,
            fallback,
        }
    }

    pub fn pin(&mut self, peer_identity: [u8; 32]) {
        self.pinned_peer = Some(peer_identity);
    }

    /// `EST-READY`: `sessionOutbound` to the pinned identity and the bundle's fallback key.
    pub fn establish(&mut self, bundle: &Bundle, reason: Establish) -> Result<(), Code> {
        if self.pinned_peer != Some(bundle.identity) {
            return Err(Code::IdentityMismatch);
        }
        let (pickle, session_id) =
            vz::session_outbound(&self.secrets(None), &bundle.identity, &bundle.fallback)?;
        let slot = Slot {
            session_id,
            pickle,
            role: Role::Initiator,
            acknowledged: false,
            peer_bind_minute: None,
            retire_day: None,
            peer_gen_id: Some(bundle.gen_id),
        };
        match reason {
            Establish::First | Establish::Reset => {
                self.previous = None;
                self.current = Some(slot);
            }
            Establish::Stale => {
                self.previous = self.current.take().map(|mut old| {
                    old.retire_day = Some(self.today + RETIRE_DAYS);
                    old
                });
                self.current = Some(slot);
            }
        }
        Ok(())
    }

    /// `resetSession` without a new establishment yet (R-SS0).
    pub fn delete_sessions(&mut self) {
        self.current = None;
        self.previous = None;
    }

    /// SEND on `current`, value semantics.
    pub fn send(&mut self, content: &[u8], minute: u32) -> Result<Envelope, Code> {
        let slot = self.current.as_mut().ok_or(Code::StateCorrupt)?;
        let out = vz::encrypt(&slot.pickle, content)?;
        slot.pickle = out.pickle;
        Ok(Envelope {
            l1: out.l1,
            is_prekey: out.is_prekey,
            gen_id: slot.peer_gen_id.unwrap_or(0),
            binding_minute: minute,
            author_minute: minute,
        })
    }

    /// RECV R7 dispatch and the selection rules.
    pub fn receive(&mut self, envelope: &Envelope) -> Outcome {
        let header = match vz::parse(&envelope.l1, envelope.is_prekey) {
            Ok(header) => header,
            Err(code) => return Outcome::Dropped(Drop::Library(code)),
        };
        match header {
            L1Header::PreKey {
                session_id,
                identity_key,
                ..
            } => {
                if self.pinned_peer != Some(identity_key) {
                    return Outcome::Dropped(Drop::Untrusted);
                }
                self.receive_prekey(envelope, session_id)
            }
            L1Header::Normal { .. } => self.receive_normal(envelope),
        }
    }

    fn receive_prekey(&mut self, envelope: &Envelope, session_id: String) -> Outcome {
        for name in [SlotName::Current, SlotName::Previous] {
            let matches = self.slot(name).is_some_and(|s| s.session_id == session_id);
            if !matches {
                continue;
            }
            let slot = self.slot_mut(name).expect("matched slot exists");
            return match vz::decrypt(&slot.pickle, &envelope.l1, true) {
                Ok(done) => {
                    slot.pickle = done.pickle;
                    if slot.role == Role::Responder {
                        let raised = slot
                            .peer_bind_minute
                            .map_or(envelope.binding_minute, |m| m.max(envelope.binding_minute));
                        slot.peer_bind_minute = Some(raised);
                    }
                    let swapped = name == SlotName::Previous && self.rss2(envelope);
                    Outcome::Displayed {
                        plaintext: done.plaintext,
                        slot: name,
                        created: false,
                        swapped,
                    }
                }
                Err(code) => Outcome::Dropped(Drop::Library(code)),
            };
        }
        let Some(fallback) = self.generations.get(&envelope.gen_id).copied() else {
            return Outcome::Dropped(Drop::UnknownGeneration);
        };
        if self.d2b && self.reuse.contains(&(envelope.gen_id, session_id.clone())) {
            return Outcome::Dropped(Drop::Replay);
        }
        let Some(pinned) = self.pinned_peer else {
            return Outcome::Dropped(Drop::Untrusted);
        };
        let created =
            match vz::session_inbound(&self.secrets(Some(fallback)), &pinned, &envelope.l1) {
                Ok(created) => created,
                Err(code) => return Outcome::Dropped(Drop::Library(code)),
            };
        self.rss1(
            envelope,
            created.session_id,
            created.pickle,
            created.plaintext,
        )
    }

    /// R-SS1 with the §22.8.4 exception.
    fn rss1(
        &mut self,
        envelope: &Envelope,
        session_id: String,
        pickle: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Outcome {
        let mut slot = Slot {
            session_id: session_id.clone(),
            pickle,
            role: Role::Responder,
            acknowledged: true,
            peer_bind_minute: Some(envelope.binding_minute),
            retire_day: None,
            peer_gen_id: None,
        };
        let older = self.age_rules
            && self.current.as_ref().is_some_and(|c| {
                c.role == Role::Responder
                    && c.peer_bind_minute
                        .is_some_and(|m| m > envelope.binding_minute)
            });
        if older {
            let previous_replaceable = self.previous.as_ref().is_none_or(|p| {
                p.role == Role::Responder
                    && p.peer_bind_minute
                        .is_some_and(|m| m < envelope.binding_minute)
            });
            if !previous_replaceable {
                return Outcome::Dropped(Drop::StaleSession);
            }
            slot.retire_day = Some(self.today + RETIRE_DAYS);
            self.previous = Some(slot);
            self.reuse.insert((envelope.gen_id, session_id));
            return Outcome::Displayed {
                plaintext,
                slot: SlotName::Previous,
                created: true,
                swapped: false,
            };
        }
        self.previous = self.current.take().map(|mut old| {
            old.retire_day = Some(self.today + RETIRE_DAYS);
            old
        });
        self.current = Some(slot);
        self.reuse.insert((envelope.gen_id, session_id));
        Outcome::Displayed {
            plaintext,
            slot: SlotName::Current,
            created: true,
            swapped: false,
        }
    }

    fn receive_normal(&mut self, envelope: &Envelope) -> Outcome {
        let mut codes = Vec::new();
        for name in [SlotName::Current, SlotName::Previous] {
            let Some(slot) = self.slot(name) else {
                continue;
            };
            match vz::decrypt(&slot.pickle, &envelope.l1, false) {
                Ok(done) => {
                    let slot = self.slot_mut(name).expect("slot exists");
                    slot.pickle = done.pickle;
                    slot.acknowledged = true;
                    let swapped = name == SlotName::Previous && self.rss2(envelope);
                    return Outcome::Displayed {
                        plaintext: done.plaintext,
                        slot: name,
                        created: false,
                        swapped,
                    };
                }
                Err(code) => codes.push(code),
            }
        }
        let code = if codes.contains(&Code::DuplicateOrLost) {
            Code::DuplicateOrLost
        } else if codes.contains(&Code::GapTooBig) {
            Code::GapTooBig
        } else {
            Code::Undecryptable
        };
        Outcome::Dropped(Drop::Library(code))
    }

    /// R-SS2 after a message decrypted on `previous`; returns whether the slots swapped.
    fn rss2(&mut self, envelope: &Envelope) -> bool {
        let (Some(current), Some(previous)) = (self.current.as_ref(), self.previous.as_ref())
        else {
            return false;
        };
        if self.age_rules && current.role == Role::Responder {
            let current_bind = current.peer_bind_minute.unwrap_or(0);
            let stale = if envelope.is_prekey {
                previous.role == Role::Responder
                    && previous.peer_bind_minute.is_some_and(|m| m < current_bind)
            } else {
                previous.role == Role::Initiator && envelope.author_minute < current_bind
            };
            if stale {
                return false;
            }
        }
        let swap = !current.acknowledged
            || (previous.acknowledged
                && sid_bytes(&previous.session_id) < sid_bytes(&current.session_id));
        if swap {
            std::mem::swap(&mut self.current, &mut self.previous);
            if let Some(demoted) = self.previous.as_mut() {
                demoted.retire_day = Some(self.today + RETIRE_DAYS);
            }
            if let Some(promoted) = self.current.as_mut() {
                promoted.retire_day = None;
            }
        }
        swap
    }

    fn slot(&self, name: SlotName) -> Option<&Slot> {
        match name {
            SlotName::Current => self.current.as_ref(),
            SlotName::Previous => self.previous.as_ref(),
        }
    }

    fn slot_mut(&mut self, name: SlotName) -> Option<&mut Slot> {
        match name {
            SlotName::Current => self.current.as_mut(),
            SlotName::Previous => self.previous.as_mut(),
        }
    }
}
