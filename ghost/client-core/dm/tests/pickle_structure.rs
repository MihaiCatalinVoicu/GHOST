//! The **pickle structure test** (design §13.6 R-M3, invariant T33), slice S5.
//!
//! > "**Library state holds no time at all** (vodozemac reads no clock and stores none): round 9's
//! > record-timestamp decode test is replaced by a **pickle structure test** that decodes a
//! > wrapped pickle in a test build and fails on any field outside the pickle schema pinned for
//! > the vodozemac version."
//!
//! R-M3's other half — every column of every table — is a JVM test over the schema
//! (`:storage` `DmSchemaIntrospectionTest`). It stops at `olm_session.state_env`, which is an
//! opaque envelope to SQL: whatever vodozemac writes inside its pickle is invisible there. This
//! test is the half that opens the envelope. It decodes the stored state, parses the pickle and
//! enumerates **every field of every object**, at every depth, as a path; the set of paths and
//! their JSON types must equal [`PINNED_SCHEMA`], in both directions:
//!
//!  - a field vodozemac **adds** at a bump — a creation time, a last-used time, a counter with a
//!    clock behind it — fails, which is the T33 claim this test exists to keep executable;
//!  - a field that **disappears** fails too, because a schema that has stopped describing the
//!    pickle is not pinning anything, and because `chainPosition` and `sessionPrune` read four of
//!    these paths by name (§2.1): a rename is exactly the drift they must not survive silently.
//!
//! The corpus is every shape a stored session can have: the three states of the pinned version's
//! golden file, and five live states built here — an outbound session before its first
//! message and after it, an inbound session before its reply and after it, and an initiator that
//! has received. The two sending-ratchet shapes (`active`, `inactive`) and a chain carrying
//! skipped keys are all represented, so the pinned schema describes the whole type and not the one
//! moment a single fixture caught.
//!
//! Regenerating: this is not a golden file. A bump that legitimately changes the layout changes
//! [`PINNED_SCHEMA`] in the same commit, beside the regenerated goldens (§2.8, gate G-R7), and the
//! diff is the record of what the new version stores.

use ghost_client_dm::derive::{self, MessagingBranch, OlmSecret};
use ghost_client_dm::olm::session::{self, Slot, StoredSession};
use ghost_client_dm::olm::state::SessionState;
use ghost_client_dm::olm::VODOZEMAC_VERSION;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The day index the live corpus is built at. Every call takes it as an argument: the crate reads
/// no clock, which is what makes "no time in library state" checkable rather than hopeful.
const TODAY: u32 = 1_000;

/// Every field of a vodozemac 0.11.0 session pickle, as `path : json-type`, array elements written
/// `[]`. Four of these paths are read by name in `src/olm/pickle.rs` — `/receiving_chains/inner`,
/// `…/ratchet_key`, `…/hkdf_ratchet/index` and `…/skipped_message_keys/inner` — and the rest are
/// here to be counted: nothing in this list is a time, a date or a clock reading, and no path may
/// appear that is not on it.
const PINNED_SCHEMA: &[&str] = &[
    // The session configuration: version 1 everywhere (D1, gate G-R2).
    "/config : object",
    "/config/version : string",
    // The receiver chains: the gap hold reads their position, SWEEP prunes their skipped keys.
    "/receiving_chains : object",
    "/receiving_chains/inner : array",
    "/receiving_chains/inner[] : object",
    "/receiving_chains/inner[]/hkdf_ratchet : object",
    "/receiving_chains/inner[]/hkdf_ratchet/index : number",
    "/receiving_chains/inner[]/hkdf_ratchet/key : array",
    "/receiving_chains/inner[]/hkdf_ratchet/key[] : number",
    "/receiving_chains/inner[]/ratchet_count : object",
    "/receiving_chains/inner[]/ratchet_count/Known : number",
    "/receiving_chains/inner[]/ratchet_key : array",
    "/receiving_chains/inner[]/ratchet_key[] : number",
    "/receiving_chains/inner[]/skipped_message_keys : object",
    "/receiving_chains/inner[]/skipped_message_keys/inner : array",
    "/receiving_chains/inner[]/skipped_message_keys/inner[] : object",
    "/receiving_chains/inner[]/skipped_message_keys/inner[]/index : number",
    "/receiving_chains/inner[]/skipped_message_keys/inner[]/key : array",
    "/receiving_chains/inner[]/skipped_message_keys/inner[]/key[] : number",
    // The sending ratchet, in both of its shapes. `active`: a ratchet key and root key inside
    // `active_ratchet`, with the previous ratchet key beside it. `inactive` (a session that has
    // not sent yet): the key and root sit at the top and `parent_ratchet_key` is null.
    "/sending_ratchet : object",
    "/sending_ratchet/type : string",
    "/sending_ratchet/active_ratchet : object",
    "/sending_ratchet/active_ratchet/ratchet_key : array",
    "/sending_ratchet/active_ratchet/ratchet_key[] : number",
    "/sending_ratchet/active_ratchet/root_key : array",
    "/sending_ratchet/active_ratchet/root_key[] : number",
    "/sending_ratchet/ratchet_key : array",
    "/sending_ratchet/ratchet_key[] : number",
    "/sending_ratchet/root_key : object",
    "/sending_ratchet/root_key/key : array",
    "/sending_ratchet/root_key/key[] : number",
    "/sending_ratchet/parent_ratchet_key : array",
    "/sending_ratchet/parent_ratchet_key[] : number",
    "/sending_ratchet/parent_ratchet_key : null",
    "/sending_ratchet/ratchet_count : object",
    "/sending_ratchet/ratchet_count/Known : number",
    "/sending_ratchet/symmetric_key_ratchet : object",
    "/sending_ratchet/symmetric_key_ratchet/index : number",
    "/sending_ratchet/symmetric_key_ratchet/key : array",
    "/sending_ratchet/symmetric_key_ratchet/key[] : number",
    // The three public keys that name the session; no identifier of GHOST's reaches the library
    // (§8.1: no address, no contact id, no device id).
    "/session_keys : object",
    "/session_keys/base_key : array",
    "/session_keys/base_key[] : number",
    "/session_keys/identity_key : array",
    "/session_keys/identity_key[] : number",
    "/session_keys/one_time_key : array",
    "/session_keys/one_time_key[] : number",
];

/// The enum tags the pinned layout admits, pinned by value: a variant added at a bump is a shape
/// this schema has never seen, and the paths of its payload would be missing from the set above.
const CONFIG_VERSIONS: &[&str] = &["V1"];
const SENDING_RATCHET_TYPES: &[&str] = &["active", "inactive"];

/// Words a field name must not contain if "no time value enters library state" is to hold. The
/// list is the one the JVM introspection test uses for the schema, plus `clock`, `second` and
/// `created`, which a serde field could carry where a SQL column would not.
const TIME_WORDS: &[&str] = &[
    "time", "date", "clock", "stamp", "second", "minute", "hour", "day", "week", "month", "year",
    "epoch", "created", "updated", "expir", "_at", "since", "until", "elapsed", "instant",
];

/// The one field whose **name** trips the rule while the value is not a time:
/// `session_keys.one_time_key` is the recipient's one-time prekey (its X25519 public key), the
/// third of the three keys that name an Olm session. It is declared here rather than dropped from
/// the word list, so `time` keeps matching everywhere else, and the test asserts the exemption is
/// still reached — an exemption that stops matching is removed.
const TIME_WORD_EXEMPTIONS: &[&str] = &["/session_keys/one_time_key"];

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Collects `path : type` for every field of every object and every element of every array.
fn walk(prefix: &str, value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (name, child) in fields {
                let path = format!("{prefix}/{name}");
                out.insert(format!("{path} : {}", kind(child)));
                walk(&path, child, out);
            }
        }
        Value::Array(items) => {
            // Every element is walked, not a sample: a layout is one shape for all entries, and a
            // pickle whose tenth skipped key had an extra field would otherwise pass.
            for item in items {
                let path = format!("{prefix}[]");
                out.insert(format!("{path} : {}", kind(item)));
                walk(&path, item, out);
            }
        }
        _ => {}
    }
}

/// Decodes one wrapped state and returns its pickle as JSON, with the sidecar beside it.
fn open(state: &[u8]) -> (Value, SessionState) {
    let decoded = SessionState::decode(state).expect("a stored session state decodes");
    let json: Value =
        serde_json::from_slice(&decoded.pickle).expect("the pickle is the JSON layout §2.1 pins");
    (json, decoded)
}

struct Party {
    identity: OlmSecret,
    signing: OlmSecret,
    public: [u8; 32],
}

fn party(tag: u8) -> Party {
    let branch = MessagingBranch::from_bytes([tag; 32]);
    let identity = derive::derive_olm_identity(&branch);
    let signing = derive::derive_olm_account_signing(&branch);
    let public = derive::olm_identity_public(&identity);
    Party {
        identity,
        signing,
        public,
    }
}

/// The five live states: both sending-ratchet shapes on both sides, plus one that has received.
fn live_states() -> Vec<(&'static str, Vec<u8>)> {
    let a = party(0x51);
    let b = party(0x52);
    let fallback_secret = [0x5fu8; 32];
    let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));

    let outbound =
        session::session_outbound(&a.identity, &a.signing, &b.public, &fallback_public, TODAY)
            .expect("outbound");
    let first = session::encrypt(&outbound.state, b"structure", TODAY).expect("encrypt");
    let inbound = session::session_inbound(
        &b.identity,
        &b.signing,
        fallback_secret,
        &a.public,
        &first.l1,
        TODAY,
    )
    .expect("inbound");
    let reply = session::encrypt(&inbound.state, b"structure back", TODAY).expect("encrypt");
    let received = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &first.state,
        }],
        &reply.l1,
        reply.is_pre_key,
        TODAY,
    )
    .expect("decrypt");

    vec![
        ("outbound before its first message", outbound.state),
        ("outbound after its first message", first.state),
        ("inbound before its reply", inbound.state),
        ("inbound after its reply", reply.state),
        ("initiator after receiving", received.state),
    ]
}

/// The three states the golden file of the pinned version carries, including the pruned one.
fn golden_states() -> Vec<(&'static str, Vec<u8>)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(format!("vodozemac-{VODOZEMAC_VERSION}"))
        .join("olm-session.txt");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{} is missing", path.display()));
    let mut out = Vec::new();
    for key in [
        "initiator_state",
        "responder_state",
        "responder_state_pruned",
    ] {
        let line = text
            .replace("\r\n", "\n")
            .lines()
            .find(|line| line.trim_start().starts_with(key) && line.contains('='))
            .map(str::to_string)
            .unwrap_or_else(|| panic!("the golden has no {key}"));
        let value = line
            .split_once('=')
            .expect("key = value")
            .1
            .trim()
            .to_string();
        out.push((
            match key {
                "initiator_state" => "golden initiator",
                "responder_state" => "golden responder (4 skipped keys)",
                _ => "golden responder, pruned",
            },
            hex::decode(value).expect("hex"),
        ));
    }
    out
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut all = golden_states();
    all.extend(live_states());
    all
}

/// The test R-M3 names: every field of every corpus pickle is on the pinned schema, and every
/// entry of the pinned schema is reached by the corpus.
#[test]
fn the_pickle_holds_exactly_the_pinned_fields() {
    let mut seen = BTreeSet::new();
    for (label, state) in corpus() {
        let (json, _) = open(&state);
        let mut here = BTreeSet::new();
        walk("", &json, &mut here);
        assert!(!here.is_empty(), "{label} produced an empty pickle");
        for path in &here {
            assert!(
                PINNED_SCHEMA.contains(&path.as_str()),
                "{label}: the pickle of vodozemac {VODOZEMAC_VERSION} carries `{path}`, \
                 which is not in the schema pinned for this version (design §13.6 R-M3, T33)"
            );
        }
        seen.extend(here);
    }
    let unreached: Vec<&&str> = PINNED_SCHEMA
        .iter()
        .filter(|path| !seen.contains(**path))
        .collect();
    assert!(
        unreached.is_empty(),
        "the pinned schema describes fields no corpus pickle has: {unreached:?} — \
         either the layout changed or the corpus stopped covering a shape"
    );
}

/// The mechanism, proved on a drifted pickle rather than assumed: a field added at the top level
/// and one added deep inside a receiver chain are both reported as outside the schema, and the
/// time-word rule names the first of them. Without this, the test above could be green because it
/// walks nothing.
#[test]
fn a_field_the_schema_does_not_know_is_seen_at_any_depth() {
    let (mut json, _) = open(&golden_states()[1].1);
    json.as_object_mut()
        .expect("the pickle is an object")
        .insert("created_at".into(), Value::from(1_700_000_000u64));
    json.pointer_mut("/receiving_chains/inner/0")
        .and_then(Value::as_object_mut)
        .expect("the golden responder has a receiver chain")
        .insert("last_used_second".into(), Value::from(42u64));

    let mut paths = BTreeSet::new();
    walk("", &json, &mut paths);
    let extra: Vec<String> = paths
        .iter()
        .filter(|path| !PINNED_SCHEMA.contains(&path.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        extra,
        vec![
            "/created_at : number".to_string(),
            "/receiving_chains/inner[]/last_used_second : number".to_string(),
        ]
    );
    for name in ["/created_at", "/receiving_chains/inner[]/last_used_second"] {
        assert!(
            TIME_WORDS.iter().any(|word| name.contains(word)),
            "{name} would not be recognised as a time"
        );
        assert!(
            !TIME_WORD_EXEMPTIONS
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            "{name} is covered by an exemption"
        );
    }
}

/// T33 itself: not one field of the library's own state is a time, under any name.
#[test]
fn no_field_of_the_library_state_names_a_time() {
    let mut exemptions_used = BTreeSet::new();
    for (label, state) in corpus() {
        let (json, _) = open(&state);
        let mut paths = BTreeSet::new();
        walk("", &json, &mut paths);
        for path in paths {
            let name = path.split(" : ").next().unwrap_or_default().to_lowercase();
            if let Some(exempt) = TIME_WORD_EXEMPTIONS
                .iter()
                .find(|prefix| name.starts_with(&prefix.to_lowercase()))
            {
                exemptions_used.insert(*exempt);
                continue;
            }
            for word in TIME_WORDS {
                assert!(
                    !name.contains(word),
                    "{label}: the pickle field `{path}` names a time (`{word}`); \
                     vodozemac reads no clock and stores none (T33)"
                );
            }
        }
    }
    let unused: Vec<&&str> = TIME_WORD_EXEMPTIONS
        .iter()
        .filter(|exempt| !exemptions_used.contains(**exempt))
        .collect();
    assert!(
        unused.is_empty(),
        "these exemptions match no pickle field any more and must go: {unused:?}"
    );
}

/// The enum tags of the layout, pinned by value: a new variant would bring a payload the schema
/// has never described, and this is where it is seen first.
#[test]
fn the_layouts_enum_tags_are_the_pinned_ones() {
    let mut versions = BTreeSet::new();
    let mut ratchets = BTreeSet::new();
    for (label, state) in corpus() {
        let (json, _) = open(&state);
        let version = json
            .pointer("/config/version")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{label}: the pickle has no /config/version"));
        assert!(
            CONFIG_VERSIONS.contains(&version),
            "{label}: session config version `{version}` is not pinned (D1, G-R2)"
        );
        versions.insert(version.to_string());
        let ratchet = json
            .pointer("/sending_ratchet/type")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{label}: the pickle has no /sending_ratchet/type"));
        assert!(
            SENDING_RATCHET_TYPES.contains(&ratchet),
            "{label}: sending ratchet shape `{ratchet}` is not pinned"
        );
        ratchets.insert(ratchet.to_string());
    }
    // Both sending-ratchet shapes really occur in the corpus, so the schema's two halves are each
    // reached by a pickle rather than by the list above.
    assert_eq!(
        ratchets.len(),
        SENDING_RATCHET_TYPES.len(),
        "the corpus covers {ratchets:?}, not both pinned sending-ratchet shapes"
    );
    assert_eq!(
        versions.len(),
        1,
        "the corpus mixes session config versions"
    );
}

/// The GHOST half of the same envelope: the sidecar beside the pickle holds `u32` **day** indices
/// and nothing finer (§7.7 point 4, T33 as clarified by S0′ V-15). The pruned golden proves the
/// reconciliation empties it, so the day values are not merely unread.
#[test]
fn the_sidecar_beside_the_pickle_holds_only_day_indices() {
    let states: Vec<(&str, Vec<u8>)> = golden_states();
    let mut with_keys = 0;
    for (label, state) in &states {
        let (json, decoded) = open(state);
        // The sidecar is a projection of the pickle: exactly the skipped keys the pickle holds.
        let in_pickle: usize = json
            .pointer("/receiving_chains/inner")
            .and_then(Value::as_array)
            .map(|chains| {
                chains
                    .iter()
                    .filter_map(|chain| {
                        chain
                            .pointer("/skipped_message_keys/inner")
                            .and_then(Value::as_array)
                    })
                    .map(Vec::len)
                    .sum()
            })
            .unwrap_or_default();
        assert_eq!(
            decoded.sidecar.len(),
            in_pickle,
            "{label}: the sidecar and the pickle disagree on how many keys were skipped"
        );
        for key in decoded.sidecar.keys() {
            let day = decoded
                .sidecar
                .day_of(&key)
                .expect("a sidecar key has a recorded day");
            // A day index, not a Unix second: the golden's own day is 1 000, and a second-granular
            // value would be six orders of magnitude larger.
            assert!(
                day < 100_000,
                "{label}: the sidecar records {day}, which is not a day index"
            );
            with_keys += 1;
        }
    }
    assert!(
        with_keys > 0,
        "no golden state carried a skipped key: the sidecar check ran on nothing"
    );
}
