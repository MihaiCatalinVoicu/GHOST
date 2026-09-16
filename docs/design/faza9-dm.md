# GHOST Phase 9: Direct Messages with libsignal — Final Design

| Field | Value |
|---|---|
| Status | **Approved for implementation by the owner's standing instruction of 2026-09-13 to continue directly with Phase 9 once Phase 8 closes; the owner questions apply with their proposed defaults** (§19), **except Q1, which needs the owner's explicit decision** (§21.13). ADR-28 … ADR-34 are "propus, aplicat" (the ADR-17 … ADR-26 practice): this design applies them and the owner decides them. **Q1 (the client licence under AGPL-3.0) gates the first distribution of any APK**, not the implementation. |
| Review | Synthesis of the judged design competition, followed by the adversarial design review (cryptography, metadata privacy, correctness, implementability; 49 findings, none rejected, four duplicate pairs merged). Its corrections are §21 "Normative corrections after review", which wins over earlier sections (the Phase 8 §19 practice); local corrections are also made in place and cite §21.n. |
| Date | 2026-09-16 |
| Phase | 9 (plan §6.2 row 9, as amended by ADR-27): "DM cu libsignal: publicare prekeys prin relay, sesiuni, safety number, PQ mode, mesaje efemere implicit 7 zile (timer în conținutul criptat, ștergere locală completă, TTL pe relee ≤ timer cu treaptă nouă de 1 h; ADR-27)" |
| Depends on | Phase 3 (`android/identity`), Phase 4 (`android/storage`), Phase 5 (relay), Phase 6 (`client-core/net`), Phase 7 (`android/sync`, schema v2, ADR-20), Phase 8 (`android/entitlement`, schema v3, capability v2, ES slots, D11; closed on `main` at `e833250`, including §19.29) |
| Exit gate | "2 dispozitive fizice: reorder/restart/replay; schimbare de cheie blochează; T25 verde" (plan:310), with the spec's DM gate (spec p.23: "two physical devices, reordering/restart/replay suite") and the FR-2.1, FR-4.1, FR-4.4, FR-4.5, FR-4.6 acceptance criteria |
| Basis | The judged winner **security-first** (strongest metadata privacy under AD-1; relay-blind addressing, a uniform seal without new crates, binding-authenticated key change, seed-derived identity, the D11 inbox read key). This version grafts seventeen elements from **operations-first** and **delivery-first**, decides the twenty-five conflicts the judge listed, fixes the eighteen errors it found, and records seven further corrections found while merging (§0.3). |
| ADR impact | **ADR-28 … ADR-34 (propus, aplicat)**, drafts in Romanian in Appendix A. They record the 17 deviations of §0.5 from plan Annex B, ADR-07, ADR-14, ADR-17, ADR-19, ADR-20, ADR-23, ADR-25, `allowed-observables.json`, INVARIANTS (T9, T13, T20, T25), the Phase 7 usage idiom, the Phase 8 design (§8.2, §10.7) and the Phase 8 T2 gate. ADR-27 is kept exactly (no deviation from point 11). |
| Sources | Spec v2.0 PDF amended by Master Plan v2.1 (Annex B, C, D); ADR-01 … ADR-20, ADR-22 … ADR-27; THREAT_MODEL v2.1; LIMITE; INVARIANTS T1–T25; `allowed-observables.json`; the Phase 7 and Phase 8 designs; research notes R-spec ("RS Kn/On"), R-libsignal ("RL §n", `[Unn]`), R-code ("RC Fn"), R-privacy ("RP Fn"), R-envelope ("RE Fn/En"); the three candidate designs and the judge verdict. Appendix C separates what was verified from what is assumed and names the slice that checks each assumption. |

**How to read this document.** §0 is the summary. §1 fixes the adversary views and the declared DM leakage. §2–§13 are normative and answer I1–I10. §14 lists the invariants, §15 the test and exit-gate plan (I11), §16–§17 gates and slices, §18–§19 risks and owner questions, §20 findings outside the phase, **§21 the normative corrections after the adversarial review, which win over every earlier section**. Appendix A holds the ADR drafts (Romanian), Appendix B the text changes for other documents (Romanian), Appendix C the evidence, Appendix D the sources. Where a section says "(normative)" it wins over a summary table. Citations `path:line` are relative to `D:/Forum` (or `ghost/…`); `F7` = `docs/design/faza7-sync-engine.md`, `F8` = `docs/design/faza8-issuer.md`, `TM` = `docs/THREAT_MODEL_v2.1.md`, `INV` = `ghost/test-harness/privacy/INVARIANTS.md`, `OBS` = `ghost/test-harness/privacy/allowed-observables.json`.

**Identifier conventions.** Grafts `G-n`, conflicts `C-n`, judge errors `E-n`, synthesis corrections `SC-n` (§0.3); deviations `X-n` (§0.5); guarantees `P-n` (privacy) and `CS-n` (correctness); transactions by name in capitals (`SEND`, `RECV`, …, §7.2); crash scenarios `SCN-A…SCN-L` (§15.3); mutants `PM-n` (privacy), `MC-n` (correctness), `ME-n` (ephemeral and envelope) (§15.7); residues `L7-Dn` (LIMITE section L7; unrelated to the Phase 8 declared-leak cell L7 of T2). Slices are `S0…S13`.

---

## 0. Summary

### 0.1 Decisions

| # | Decision | Issue | Plan / ADR alignment |
|---|---|---|---|
| D1 | **libsignal through the official Android artifacts** `org.signal:libsignal-android` + `org.signal:libsignal-client`, one exact version (**0.102.2**, re-pinned in S0 to the newest release ≥ 0.100, never below), from Signal's repository `build-artifacts.signal.org` behind a Gradle `exclusiveContent` filter for group `org.signal` only, sha256-pinned in `verification-metadata.xml`. The Android build and JVM tests move to **JDK 21**. The Rust-crate route inside `client-core` is the documented fallback (Q2). | I1 | FR-2.1, spec Appendix A, Annex D (group already allowlisted); new ADR-28 |
| D2 | **Closed API surface:** `SessionBuilder`, `SessionCipher`, five store interfaces (`IdentityKeyStore`, `SessionStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, and a fail-closed empty `PreKeyStore`), key and record classes, message classes, typed exceptions, `NumericFingerprintGenerator`, and the logger provider. **No** `SealedSessionCipher`, sender certificates, `metadata.*`, `net`, `zkgroup`, `usernames`, `messagebackup`, `svr`, `media`, `attest`, `keytrans`, `groups`: an import gate enforces it. Stores are **stateless views bound to one `SyncTransaction`** (no cache across transactions). A **silent logger** is installed before first use and is load-bearing for T3: libsignal's decrypt path logs untrusted identity keys in hex (E-18). | I1, I2 | TM A1 ("we do not modify libsignal"); ADR-28 |
| D3 | **Sealed sender without a server = a GHOST outer seal in two modes, no certificates.** *Pair mode* (every established conversation): a symmetric key per (pair, direction, ISO week) ratcheted from a **random root generated by the recipient**, erased 45 days after its week ends, so relay-stored pair envelopes become unattributable even with both seeds and devices. Roots travel only in acknowledged sessions, and a session renewal resets the peer's out keys (§21.3). *Intro mode* (first contact, reset, reconnect, any unacknowledged session): an outer AEAD keyed by the recipient's card plus an inner X25519 layer to the recipient's seed-derived intro key; the sender's card and an Ed25519 binding of its libsignal identity, bound to the recipient namespace, a sealing minute and the L1 hash, ride inside (§21.4). Both modes present `salt(16) ‖ hint(16) ‖ AEAD`: uniform bytes, at most one AEAD attempt per blob. Self-issued libsignal sender certificates, sealed sender v2, per-message Elligator 2 keys and raw X25519 keys are rejected (C-2). | I2, I4 | Annex B "fără câmp de expeditor" made exact; ADR-31 |
| D4 | **Relay-blind addressing (T26).** Nothing relay-visible is derived from public identity material. A 163-byte signed **contact card** (Ed25519 identity key, card index, `card_secret`, intro key) is exchanged by QR in person or by a `ghost://contact/` link. Every DM namespace, deposit secret, bundle read secret and seal key is an HKDF output of `card_secret`; the inbox read secret, the intro key and the libsignal identity derive from the seed's MESSAGING branch only. **No contacting by bare `ghost1…`.** | I3, I4, I9 | deviates Annex B "citire publică după ghost1" (ADR-30) |
| D5 | **Static namespaces per card index, credentials static per relay slot** (G-4, C-4; §21.2): inbox `X_i = HKDF(card_secret_i, "ghost/v1/card/inbox-ns")`, bundle namespace `P_i = HKDF(card_secret_i, "ghost/v1/card/bundle-ns")`. The relay set of any DM namespace is `set(ns, w)`, a public keyed permutation of the week's ES slots, independent of the week itself (§21.1), spanning ≥ 2 operators; when the slot table changes, readers keep the union with earlier sets for 6 weeks. | I3, I4, I8 | Annex B inbox; ADR-30 |
| D6 | **Shared deposit keys (T27): senders never spend tokens on another identity's namespace.** The recipient redeems its own write capability per (relay, namespace, week) and registers, with a new RPC **`RegisterKey`**, the verifier of a deposit secret per relay slot shared by all its card holders; senders present the same 67-byte **bearer credential v3**, bound to the relay's slot, which allows `store` and `check` only. Registrations cover weeks `{cap_week, cap_week + 1}`, checked by the relay against the capability's week, never against its own clock (G-3); senders choose no week and have no fallback, and a recipient may be offline about two to three weeks without a deposit failing (§21.2). Verifiers accumulate and are never replaced (SC-1). | I4 | deviates Annex B "scriere cu capabilitate" per sender and Phase 8 interim (ADR-30) |
| D7 | **D11 implemented** (C-5, C-6): the same RPC registers the **seed-derived inbox read secret** (so contacts cannot read the inbox with the card) and the card-derived bundle read secret (shared by all card holders, so fetchers are indistinguishable). The verifier binds the relay slot and the namespace: `SHA-256(label(kind) ‖ slot ‖ namespace ‖ secret)`; the week lives in the registration period (§21.2). T21 in `client-core` learns the v3 credential. Registrations live in a new relay store `keys.redb` with its own quota ledger per registration (E-11). | I3, I4 | F8 §10.7 points 2–3, ADR-25 point 9 (implemented, generalized) |
| D8 | **Prekey bundles:** one sealed 4 KiB bundle per card in `P_i`, republished weekly at a seed-PRF offset, valid for its ISO week and the next: signed EC prekey + **last-resort Kyber prekey**, both XEdDSA-signed by the libsignal identity, plus an **Ed25519 binding signature** under the `ghost1` key. **No one-time prekeys through relays** (a blind store cannot allocate them). Private prekeys are kept 91 days after they are superseded (C-10), then erased with their reuse tuples. Fetched once per establishment or explicit reset, in at most three 15-minute attempts, never polled; bundles carry an issuance hour and the newest valid one wins (§21.7). Rejected alternative: bundles pushed in a signed HELLO with one-time prekeys and an accept round trip (C-7). | I3, I6 | plan row 9 "publicare prekeys prin relay"; TM "prekeys rotated periodically" given numbers; ADR-30 |
| D9 | **Envelope (T9, T29):** three layers, L0 canonical content → L1 unchanged libsignal output → L2 seal. Bucket ∈ {4, 16, 64} KiB chosen **from the body length plus fixed reserves only** (§21.11) with a measured worst-case overhead `O_MAX` (provisional 2 560 B); DMs never use 1 KiB, so PreKey vs normal, intro vs pair, control vs text of equal length share one class. All lengths and zero padding inside the AEAD; non-canonical blobs refused. **Seal and L0 codec live in Kotlin on BouncyCastle** in `:crypto-bridge`, an explicit ADR-19/ADR-20 point 8 deviation (C-3, E-4, E-16), cross-checked by an independent implementation on the JDK's own providers; `client-core` keeps refusing non-bucket blobs. | I4 | T9 made executable; ADR-31 |
| D10 | **No reflex traffic (T28):** nothing is stored, redeemed, registered or rescheduled because a blob arrived. No delivery or read receipts, no typing, no `DecryptionErrorMessage`, no automatic session reset. Undecryptable, duplicate, replayed and forged blobs are consumed silently. FR-4.3 "delivery status" = the Phase 7 relay-quorum outcome. The only automatic resend is the Phase 7 identical-bytes resend of an INDETERMINATE op, at most twice (G-7, C-15), caused by the user's own send. | I4, I8 | ADR-08 (optional, off in high-privacy) made stricter; ADR-31 |
| D11 | **Identity (C-1):** the libsignal identity key pair derives from the seed's existing MESSAGING branch (`DerivationLabels.kt:18-19`), so it and every safety number survive a restore; sessions, prekeys, pair roots and dedup tags do not. The Ed25519 identity (`ghost1…`) signs the libsignal identity key in every bundle and intro envelope. Registration id random 14-bit per install; device id 1 (multi-device P2). | I5 | FR-1.2 (P0), spec Figure 2, TM:81; ADR-33 |
| D12 | **Safety number** = `NumericFingerprintGenerator(5200)` with stable identifier = the 32-byte Ed25519 key of each side, so the 60 digits commit to both identities of both parties; QR from `ScannableFingerprint`; UI-less API for Phase 13; no network I/O. | I5 | FR-4.6; ADR-33 |
| D13 | **Key change blocks both directions (C-14, E-1):** a key change is classified **only** when a binding signature valid under the contact's pinned Ed25519 key names a different libsignal identity; anything else is a forgery and is dropped with no state change. In `changed`, sending is refused before any libsignal call and PreKey messages under the new key are **held undecrypted** (bounded by the relay expiry) until the user acknowledges or verifies. | I5 | FR-4.6, spec §7.2(d), plan gate; ADR-33 |
| D14 | **PQ:** PQXDH and SPQR are mandatory in libsignal ≥ 0.100 (`min_version: V1`); no GHOST knob, no fallback, no standalone KEM. A test asserts session version 4, a Kyber ciphertext in the first PreKey message and a non-empty `pq_ratchet` field in both directions, at S0 and at every bump. Last-resort prekey KEM = ML-KEM-1024 if the pinned Java API generates it, otherwise Kyber1024 (Q21). | I6 | ADR-12; ADR-28 |
| D15 | **TTL buckets become seconds** `{3600, 86400, 604800, 2592000, 7776000}`; the relay accepts **exactly** a bucket (`rejected_ttl` otherwise); `allowed-observables.json` v2 replaces `ttl_bucket_days` with `ttl_bucket_seconds`. **DM relay TTL = ADR-27 point 11 exactly** (G-5, C-8): 5 min and 1 h → 1 h, 1 d → 1 d, 7 d → 7 d, 30 d → 30 d, timer off → 30 d. Every DM op carries the deadline `author + min(bucket, 7 d)` (SC-3; 5-minute messages share the 1-hour deadline) and runs to it, never cancelled at expiry (§21.10). The Phase 7 window rules are re-derived for TTL < 2σ (G-10). | I7 | ADR-27 C.11 kept; T25 wording; ADR-32 |
| D16 | **Ephemeral execution:** timer and timer version inside every L0; sender countdown from the send commit; recipient countdown from first display; an unread message is deleted at `min(relay expiry E, consume + bucket + 1 h)` with E passed through `InboundBlob.relayExpiryHour` (C-11); expiry times only move earlier; the expiry clock never runs backwards; one-transaction deletion cascade, then `wal_checkpoint(TRUNCATE)` with `busy = 0` checked and a checkpoint at every database open; notifications never carry content or sender; quotes are references; no FTS; sweeps in process, at open, in the consumer tail, in every read query, plus **one inexact non-exported alarm** (C-12). | I7 | ADR-27 C.8–C.10; ADR-32 |
| D17 | **Traffic:** Phase 7 schedules unchanged. Sends immediate in STANDARD, at pair events after U[0, 10 min] in HIGH (DM namespaces cannot be set to `SendDelay.OFF`). Reads only on own namespaces (T31). Bundle publication and owner registrations at activity-independent times. No cover traffic (P2); reply-timing and session co-occurrence residues declared (LIMITE L7) and measured by T32. | I8 | ADR-09, ADR-15, ADR-20 |
| D18 | **Contact establishment:** card exchange (QR in person → `verified`; link → `unverified`); the initiator's card rides inside its first intro envelope, so one scan suffices; unknown card holders appear as **requests** (cap 64, 7 days; C-24); block and delete are local. **Deferred:** cut-off card rotation to Phase 13 with the P1 contact backup (C-16), the Invite v3 card to Phase 13 with ADR-05 kept open (C-18), the Phase 8 drop outer-shape change (C-17). | I9 | ADR-05 (card deferred, not declined); ADR-30 |
| D19 | **Modules:** `:crypto-bridge` = the only `org.signal` importer (facade, stores, seal, codec, card, fingerprints); `:messaging` = DM engine behind a UI-less facade for Phase 13, one **DM actor thread** as the only writer. **Schema v4**: `dm_*` and `sig_*` tables (random keys, minute/hour/day time columns with `typeof` CHECKs, state and write-once triggers, REPLACE guards), unused v1 DM tables dropped behind a fail-closed guard, `outbox_op`/`outbox_delivery` rebuilt for the 1 h bucket with explicit column lists (G-9, E-5), `inbox_blob.relay_expiry_hour`, `sync_namespace.capability_source`, `relay_key_registration`. | I10 | spec §6.1, §8; ADR-33, ADR-34 |
| D20 | **`:sync` and `:entitlement` additions (ADR-34):** `TtlBucket.HOUR_1`; `InboundBlob.relayExpiryHour` and `offers`; `CapabilitySource {REDEEM, LOCAL}` (the planner never redeems a LOCAL need); `Registrations` on the work lane; pending registrations count as write work, so a new or restored inbox is redeemed at once (Q31, G-17); **`ConsumerTail`** run on the job thread after a background session's lanes and redeem hold and after a quiet run's issuer call, after the transport closed, with the DM actor as the only writer (G-8, C-13). | I10 | amends ADR-20, ADR-23 (the participant slot stays one); ADR-34 |
| D21 | **Exit gate proved** on the JVM with real libsignal (the desktop natives of `libsignal-client`), the real sync engine and a conformance-pinned Kotlin `ModelRelay`: a full transaction inventory with crash enumeration at every SQL statement, native-crash poison and `SQLITE_FULL` suites (G-1), seeded worlds across week boundaries, slot-table changes, 40-day offline windows and clock steps (G-13), key-change blocking, T25 logical and physical scans, the **DM privacy world T32** (exact joins, twins, statistics at α = 0.001, C-19), 79 mutants. An **emulator job** on loopback model relays (G-11) and a **signed two-device checklist** close the gap to real Android, SQLCipher, Tor and relays. | I11 | exit gate; ADR-34 |
| D22 | **Licence (Q1):** libsignal and `spqr` are AGPL-3.0-only on every integration route, so the distributed APK is an AGPLv3 combined work. Proposed: the Android client AGPL-3.0-only; `client-core` keeps `MIT OR Apache-2.0` for its own files; relay and issuer unchanged. Phase 9 code is written; **no APK is distributed, and CI uploads no APK artifact, before the owner decides explicitly**; Q1 is excluded from the default rule (ADR-29, §21.13). | I1 | revisits ADR-07 |

### 0.2 Guarantees claimed (each has a test in §15)

**Metadata at relays (AD-1: the operator with every relay and the issuer)**

| ID | Guarantee | Proof |
|---|---|---|
| P-1 | **No identity at relays.** No relay-visible value (namespace, verifier, credential, stored byte, capture field) is computable from public identity material (`ghost1`, Ed25519 key, libsignal identity key, safety number) without a card or the seed. | T26: derivation vectors, static IKM check, JD1, JD2, S-DM3 |
| P-2 | **No sender field, in substance.** Every store into one inbox namespace at one relay with a deposit credential presents the same credential scope, in every week and whatever the sender's clock or earlier refusals (§21.2); no honest client redeems for a namespace it does not own; a client's redemptions and registrations do not depend on its DM activity. | T27: JD3, JD8, NI-DM3, relay vectors |
| P-3 | **No reflex.** Relay-visible behaviour, including relay-session close times, is identical whatever arrives in the inbox (valid, forged, replayed, key-changed, undecryptable). | T28: NI-DM1, JD6, static call-graph test |
| P-4 | **No type, state or sender in sizes or bytes.** Bucket = f(L0 length); envelope and bundle bytes are uniform; no libsignal header leaves the AEAD. | T29: JD2, JD4, NI-DM2, byte-uniformity test |
| P-5 | **Bounded relay lifetime.** An honest relay holds a DM blob at most until `deadline_hour + bucket + 1 h`, where `deadline_hour` is the Phase 7 stored hour of the deadline `author + min(bucket, 7 d)` (§10.1), and stores exactly the bucket it was given. | T30: JD5, relay and client vectors |
| P-6 | **Read confinement.** A client lists and gets only its own namespaces, plus one bundle fetch (at most three 15-minute attempts, §21.7) per establishment or explicit user reset. | T31: JD7, static check |
| P-7 | **Attribution forward secrecy of pair envelopes.** For an ISO week w with `now ≥ start(w + 1) + 45 d`, no key on either device and nothing derivable from either seed opens a pair-mode envelope of week w, except through a root-carrying message whose libsignal key survives as a skipped key on the seized recipient of that root (declared, §21.3). Intro envelopes, including every envelope of an unanswered conversation, stay attributable by anyone who later holds the recipient's seed (declared). | T34: seizure scenario, erasure tests |

**Correctness and local soundness**

| ID | Guarantee | Proof |
|---|---|---|
| CS-1 | **Atomic send.** A ratchet step commits if and only if its message row and outbox op commit; no message key encrypts two plaintexts after process death (spec §7.2(b)). | SCN-A crash enumeration, MC-1, MC-2 |
| CS-2 | **Exactly-once display.** Each `message_id` appears at most once per device across crashes at any SQL statement, native crashes, disk-full faults, restarts, several relays, relay re-serves and resurrections, identical-bytes resends and re-encryptions after FAILED. | SCN-B, SCN-G, SCN-J, `oracle_displayed` primary key |
| CS-3 | **No loss inside the declared envelope.** A message whose op ends `SENT` or `DEGRADED` is displayed once by a recipient that lists its inbox within the TTL, inside libsignal's limits (2 000 skipped keys per chain, jumps ≤ 25 000, sessions answered within 30 days), unless a declared loss applies: restore (§8.6), an undecided key change past its hold bound (§8.3), an unread ephemeral past its cap (§10.3), content refused as stale (FRESH = 45 d, §7.6), a recipient offline beyond its registrations (§4.8), a poison blob that killed the consumer's process three times (§7.4 R2). | seeded worlds, SCN-E, SCN-H, SCN-J |
| CS-4 | **Deterministic order** on both devices whatever the arrival order, restarts or replays (except the clamp for a peer clock in the future). | reorder oracle (all 720 permutations of 6), SCN-B |
| CS-5 | **Key change blocks.** No ciphertext is produced toward, and no plaintext is shown from, a changed identity before an explicit user decision; a change without a valid binding causes no state change. | KC suite, SCN-D, PM-15…PM-17, MC-6 |
| CS-6 | **T25 bounds.** After expiry, no row, plaintext, envelope bytes, retained blob or notification content remains on either device; the WAL is truncated. | T25 logical and physical scans, emulator T25 |
| CS-7 | **Replay refusal.** Replays, cross-namespace copies, resurrections after tombstone GC, replayed first flights and stale content never create a second row and never cause traffic. | RP suite with each dedup layer isolated |
| CS-8 | **Bounded local state.** Skipped keys (libsignal), held rows, dedup tags, superseded prekeys, pair keys, retained blobs, requests and registrations each have a stated bound and a GC rule. | introspection, SCN-H, unit tests |
| CS-9 | **Migration safety.** v1/v2/v3 → v4 preserves every sync and entitlement row, `outbox_op` rowids, and the trigger set; a crash at any statement leaves the previous version, which migrates again. | SCN-L, `SchemaAndMigrationTest`, emulator SQLCipher migration |

### 0.3 What changed from the base design

**Grafts (judge list, all adopted)**

| # | Graft | Source | Where |
|---|---|---|---|
| G-1 | Full DM transaction inventory and crash-point table; native-crash poison (consume unprocessed after 3 offers, through `InboundBlob.offers`); the `SQLITE_FULL` fault suite; `TxSignalStores` rules (no cache across transactions, `sig_session` record length CHECK, store exceptions limited to `IllegalStateException`). | operations §5.1, §5.9, §5.10 | §7.2, §7.8, §2.4, §13.6 |
| G-2 | Golden libsignal record fixtures `messaging/src/test/resources/libsignal-golden/<version>/` and the `LibsignalUpgradeTest` drill, required by the version-lock gate at every pin change. | operations §5.10, §12.1 | §2.4, §16.1 |
| G-3 | Registrations for weeks `{cap_week, cap_week + 1}` made with the installed write capability, checked by the relay against the capability's week; the sender's fallback to the previous week's credential (removed by §21.2: credentials are static per relay slot); the ~2-week offline argument (about 2–3 weeks after §21.2); the need reason of a registration-only namespace stated (pending registrations count as write work, Q31). Replaces the base's `t_roll` and assumption A14. | operations §3.2–§3.4 | §4.4, §4.8, §13.3 |
| G-4 | Static inbox and bundle namespaces per card index, credentials rotated weekly; `set(ns, w)` over the week's ES slots with a 6-week union when slots change; AD binding (namespace, bucket) kept; the credential's week bound through the verifier; the static-inbox residue on a seized relay disk declared. | operations D5, §3.1 | §5.1–§5.2, §11.5 (L7-D13) |
| G-5 | ADR-27 point 11 kept exactly (30 d timer → 30 d; off → 30 d; 5 min and 1 h → 1 h); the collapse to 7 d is only an owner question (Q15). FRESH = 45 d; prekey retention re-derived; the pair-mode week-key window widened to the longest legitimate blob lifetime. | delivery §7.1, operations §6.1 | §10.1, §7.6, §5.4, §6.3 |
| G-6 | Restore healing: intro envelopes carry the sender card; on a restored device a PreKey arrival or a `NoSession`/`InvalidKeyId` failure marks the rebuilt or requested contact `reset_needed`; the user's `reconnect(contacts)` fetches bundles and sends a reset at PRF times over 48 h. The residue that pair envelopes of established contacts are unopenable after a restore stays, visible as `unknown_seal` counts. | operations §2.5, §10.3; security §6.4 | §8.6 |
| G-7 | Automatic identical-bytes resend of INDETERMINATE ops, at most 2, only while `now < resendNotAfter` and before the op deadline, from messaging's retained blob; FAILED stays a user retry that re-encrypts the same L0. | operations §5.5 | §7.5 |
| G-8 | The `ConsumerTail` contract (job thread, after a background session's lanes and redeem hold, after a quiet run's issuer call, no transport, deadline = job deadline − 20 s, the DM actor the only writer) with its `SessionParticipantTest` cases. Replaces the base's `ConsumerTask`, whose text contradicted itself on quiet runs (E-14). | operations D14, §8.1–§8.2 | §13.3 |
| G-9 | The `outbox_op`/`outbox_delivery` rebuild with explicit column lists including `rowid`, the `legacy_alter_table = OFF` assertion, `PRAGMA foreign_key_check`, trigger text shared as one constant with migrations 2 and 3, and a before/after `sqlite_master` object-set test. | operations §7.2 | §13.6 |
| G-10 | The Phase 7 window re-derivation for TTL ∈ {1 h, 1 d}: safety unchanged, liveness degrades to INDETERMINATE, the receipt lower bound vacuous and declared; S-F gains offline windows of 30 min, 3 h and 3 d. | operations §6.7 | §10.4, §11.5 (L7-D15) |
| G-11 | Emulator job on in-process loopback model relays, a SHA-pinned emulator action, API 29 and 35 x86_64 images, a separate `:peer` process killed with SIGKILL, real SQLCipher v3 → v4 migration, a release-variant native-load smoke test. Public Tor stays manual. | operations §11.9; delivery §11.6 | §15.9 |
| G-12 | Scope cuts: cut-off rotation deferred to Phase 13 with the P1 contact backup (`card_index` stays in the card); the DropSeal outer-shape change deferred; Invite v3 deferred to Phase 13 rather than declined. | delivery §0.6; operations Q22 | §0.6, §12.5 |
| G-13 | Seeded worlds with week boundaries, one ES slot-table change, offline windows up to 40 days, backward and forward clock steps; scenarios SCN-E (recipient offline across 3 week boundaries) and SCN-H (13-week prekey rotation with a PreKey message at the retention boundary and a replayed first message). | operations §11.2–§11.3 | §15.3–§15.4 |
| G-14 | Lazy native load mapping a missing library to `CryptoUnavailable`; R8 keep rules for `org.signal.libsignal.internal.Native` and the store callbacks only if the AAR ships none; a recording-logger test proving GHOST installs only the silent logger. | delivery §2.2, §9.7 | §2.5–§2.6 |
| G-15 | A physical-device checklist step for restore and reconnect; debug-only order digests (SHA-256 of rendered `message_id`s); a host orchestrator that records digests, never content. | operations §11.10; delivery §11.7 | §15.10 |
| G-16 | The T2 world exports every relay database table and fails on an unknown one (F8 §19.24 point 6): `keys.redb` joins the T2 export and completeness checks, and `t2-exit-gate` changes. | verification | §4.9, §16.2 |
| G-17 | First-contact reachability after activation and restore stated (at the first relay session under Q31's default; up to the READ MISSING PRF time of ≤ 6 h otherwise) and made an owner question. | delivery §5.4 | §4.8, Q31 |

**Conflicts decided**

| # | Conflict | Decision | Why |
|---|---|---|---|
| C-1 | libsignal identity: derived or random per install | **Derived** from MESSAGING; key changes authenticated by an Ed25519 binding under the pinned identity; residue: a mnemonic thief on the official client raises no warning (L7-D18) | FR-1.2 is P0 with recovery vectors; spec Figure 2, TM:81 and `DerivationLabels.kt:19` say so; a random identity makes every restore a blocking key change at every contact |
| C-2 | Outer seal | **Two-mode `salt ‖ hint ‖ AEAD`** (security) | The Elligator 2 variant depends on an alpha fork crate and omits the low-order component (E-3); raw X25519 declares T9 unmet |
| C-3 | Where seal and codec live | **Kotlin on BouncyCastle**, explicit ADR-19 deviation, rationale corrected (E-4) | ADR-24 DropSeal precedent; the libsignal output is in Kotlin; JVM tests need no host-native build |
| C-4 | Inbox namespace rotation | **Static per card, weekly credentials** (G-4) | Rotation does not break continuity under AD-1, costs read pairs and tokens at each roll, and loses all mail for recipients offline more than 3 weeks |
| C-5 | Owner inbox read | **Seed-derived READ key via `RegisterKey`** | F8 §10.7 points 2–3 and ADR-25 point 9 require it in Phase 9; the RPC exists for deposits anyway |
| C-6 | Verifier registration | **`RegisterKey`** with the `{w, w + 1}` rule against the capability week | Piggybacking on `RedeemToken` ties deposit liveness to one capability week and cannot register read keys |
| C-7 | Prekey distribution | **Sealed bundle in a card-derived namespace**; HELLO recorded as the rejected alternative with its benefits (no fetch linkability, one-time-prekey forward secrecy) | plan row 9 and Annex B; asynchronous first message without an accept round trip |
| C-8 | Relay TTL for 30 d and off | **30 d**, as ADR-27 point 11; the 7 d collapse is Q15 | approved text |
| C-9 | FRESH | **45 d**, with deadlines ≤ 7 d (SC-3); `dm_seen`, pair-key and prekey windows re-derived | follows C-8 |
| C-10 | Private prekey retention | **Derived: superseded + 91 d** (bundle validity + 30-day unacknowledged age + FRESH + 2σ) | recomputed for the final TTL table and bundle validity |
| C-11 | Unread cap source | **Relay expiry through `InboundBlob.relayExpiryHour`**, clamped to `consume + bucket + 1 h` | ADR-27 C.9 literally; a sender clock ahead cannot extend the deadline |
| C-12 | Deletion wake-up | **One inexact non-exported alarm**, T20 wording amended | Doze would otherwise delay physical deletion for hours |
| C-13 | Background DM consumption | **`ConsumerTail`** (G-8) | otherwise fetched ciphertext and `FETCHED_CAP` wait for the next foreground (E-17) |
| C-14 | Key-change behaviour | **Block sending and hold new-key inbound, classified only through a valid Ed25519 binding** | the variant without a binding is spoofable (E-1); showing old-key messages alone is weaker against a mnemonic thief |
| C-15 | INDETERMINATE | **Automatic identical-bytes resend, ≤ 2** (G-7) | allowed by the Phase 7 contract; not a reflex |
| C-16 | Cut-off rotation | **Deferred to Phase 13** | needs the P1 contact backup to survive a restore |
| C-17 | Phase 8 drop outer shape | **Deferred** (Q18) | T2 NI-2/NI-3 were just closed with no exemption (F8 §19.29) |
| C-18 | Invite v3 card | **Phase 13**; ADR-05 stays open | UX work; T16 untouched in Phase 9 |
| C-19 | T32 statistical DM world | **In the Phase 9 gate**: PR scale in the `android` job, gate scale nightly | R-privacy §6, CP-10 (no claim without a test) |
| C-20 | Restore semantics | **Security residue + operations healing** (G-6) | the only combination consistent with C-1 and random pair roots |
| C-21 | Emulator relays | **Loopback model relays** (G-11); live Tor manual | a job that depends on public Tor reports "not run" too often to be gate evidence |
| C-22 | APK size limit | **Owner question, default 70 MiB** (spec), native library reported separately (Q24) | estimate ≈ 64 MB fits both 70 and 80 MiB |
| C-23 | Local content key | **Keystore-wrapped**, same authentication policy as the database key | the "no plaintext content column" rule and a meaningful T25 byte scan |
| C-24 | First contact from an unknown card holder | **Requests** with caps | asynchronous first message; no reflex on accept |
| C-25 | Revocation certificate | **v2** (minute timestamp) inside E2E | T13 alignment; it only travels in new DM code |

**Judge errors fixed**

| # | Error | Fix |
|---|---|---|
| E-1 | (operations) Any `UntrustedIdentityException` became a held key change without a binding: forgeable by anyone holding two cards. | §8.3: a key change requires a binding valid under the pinned Ed25519 key, checked **before** libsignal (`RECV` step R6); an exception alone is a drop; mutant PM-17 and test KC5. |
| E-2 | (operations) §3.5 refused a bundle whose identity differs from the card, §10.2 treated it as a key change. | §5.5 and §8.3 say the same: a bundle whose binding verifies under the pinned Ed25519 key but names another libsignal identity is a key change; a bundle whose binding does not verify is refused. |
| E-3 | (operations) Elligator 2 recipe without the low-order component; candidate crate an alpha fork. | Not used (C-2). §6.1 records why. |
| E-4 | (security, delivery) "No AEAD crate in the lock": `ring` 0.17.14 provides ChaCha20-Poly1305 and is `required` in the `ghost-client-net` graph (`ghost/scripts/gates/rust-crypto-pins.txt:19`). | ADR-31 and §2.8 give the true reasons for Kotlin (C-3). `ring` is transitive for `ghost-client-net` (through `rustls`, `ghost/Cargo.toml:57,62`), not a direct dependency. |
| E-5 | (delivery) `INSERT … SELECT rowid, *` supplies one value too many. | §13.6 step 1 lists every column explicitly (G-9). |
| E-6 | (delivery, operations) A new relay table was said to leave T2 unaffected. | §4.9: `keys.redb` joins the T2 export and completeness checks; `t2-exit-gate` changes (G-16, X-14). |
| E-7 | (delivery) Weekly inbox redemptions claimed equal to the Phase 8 interim. | §4.8 counts the new redemptions (1 per relay, own namespace and week) and §4.9 models them in T2. |
| E-8 | (delivery) "Offline up to a month still receives" while registrations lapse within a week. | §4.8: registrations live `start(week + 2) + 1 h`, a sender falls back one week, so the tolerance is about two weeks of absence; messages stored in that time live up to their TTL. |
| E-9 | (delivery) Random DM keys contradict FR-1.2 and Figure 2. | C-1. |
| E-10 | (security) Token accounting: WRITE MISSING only where the outbox has work; a weekly namespace roll cost two tokens. | Static namespaces (1 token per relay, own namespace and week, on the EXPIRING path); registration rows count as write work (§4.8, §13.3). |
| E-11 | (security) Deposits charged to the capability's ledger entry, which expires before the registration. | §4.5: a `DepositLedger` entry per registration, allowance credited by each registering capability, bounded by the registration's validity. |
| E-12 | (security) Bundle plaintext length. | 1 886 bytes (§5.3). |
| E-13 | (security) Hint workload understated. | §6.2 R-S5: at most 9 week keys per contact plus one intro key, so ≤ 9 001 HMACs per blob at `MAX_CONTACTS = 1 000`, computed lazily, most recent first. |
| E-14 | (security) The consumer task both never ran and ran in quiet runs. | G-8: the `ConsumerTail` runs in quiet runs after the issuer call returned and the transport closed. |
| E-15 | (delivery) Client-chosen, card-carried inbox slots (R-privacy F11). | Not used: `set(ns, w)` is a public function (§5.2). |
| E-16 | (delivery) Kotlin seal without recording the ADR-19 deviation. | X-9, ADR-31. |
| E-17 | (delivery) Background consumption through the listener slot only. | G-8. |
| E-18 | (all) libsignal logs untrusted identity keys in hex at warn level (`session_management.rs:130-131, 336-337`; first cited from the test-only `session_cipher_legacy.rs`, §21.6) and a decryption-failure report at error level (`:253`). | §2.6: the silent logger is load-bearing for T3; the T3 canary test drives an untrusted-identity decrypt with a recording logger; the emulator job scans logcat. |

**Corrections found during synthesis (normative)**

| # | Finding | Correction |
|---|---|---|
| SC-1 | The base's `RegisterKey` let any write-capability holder **replace** a verifier. A card holder can redeem its own token for a contact's inbox and replace the owner's deposit verifier: a targeted denial of service on every other sender. | Verifiers accumulate per (namespace, week, kind); nothing is replaced; one capability registers at most one verifier per (namespace, week, kind) (§4.4). Cut-off, the only planned use of replacement, moves to a new card index in Phase 13. |
| SC-2 | A card holder can redeem its own token for a contact's inbox and list it with that write capability (write grants read): inbound volume and timing, content sealed. No candidate declared it. | Declared L7-D16; an owner-bound read rule is a Phase 12 finding (§20 F-5). |
| SC-3 | FRESH = 45 d does not hold if a parked 30-day or timer-off op may be stored 30 days after compose (fetch up to 60 days after compose). | Deadline `author + min(bucket, 7 d)` for every DM op (§10.1), so a legitimate fetch comes at most 43 d 2 h after compose, clock skew included (§7.6). |
| SC-4 | "Widen the pair-mode window" had no bound. | A week key is erased at `start(w + 1) + FRESH`: no legitimate blob of week w can be accepted later (§6.3), which is also the T34 horizon. |
| SC-5 | The 277-character card link fits QR version 11-L (byte capacity 321), not 12-L. | §3.3. |
| SC-6 | Prekey retention depends on bundle validity, which no candidate fixed together with the 30-day TTL. | Bundle validity = its ISO week and the next; retention = superseded + 91 d (§5.4). |
| SC-7 | A consumer that runs while the transport is still open would make the relay session's close time depend on inbound volume. | The `ConsumerTail` runs after the transport closed (§13.3); NI-DM1 compares close times. |

### 0.4 Issue → section map

| Issue | Sections | Short answer |
|---|---|---|
| I1 libsignal integration | §2, §16.3 | AAR + client JAR 0.102.2 exact from Signal's repository, JDK 21, closed API, tx-bound stores, silent logger, golden records, gates, ≈ 22 MB, AGPL (Q1) |
| I2 sealed sender without a server | §6.1–§6.5 | GHOST seal: recipient-rooted pair mode + card-keyed intro mode with an inner X25519 layer; no certificates |
| I3 prekeys via relays | §4, §5.2–§5.6 | sealed 4 KiB bundle in a card-derived static namespace, card-derived shared read key, signed + last-resort Kyber only, weekly rotation, 91-day retention, one-shot fetch |
| I4 DM inbox | §4, §5.1, §6, §7 | static card-derived inbox, seed-derived read key, shared deposit key via `RegisterKey`, 4 KiB floor, four dedup layers, content-order display |
| I5 sessions, safety numbers, key change | §3, §8 | MESSAGING-derived identity, Ed25519 binding, blocking both directions with a hold, revocation v2 through inboxes, restore healing |
| I6 PQ | §9 | PQXDH + SPQR mandatory by library version; asserted at every bump |
| I7 ephemeral | §10 | seconds buckets, exact TTLs, ADR-27 table, deadlines, countdowns, deletion cascade, checkpoint, alarm, T25 |
| I8 traffic and metadata | §11 | schedules unchanged, activity-independent owner writes, observation matrix, LIMITE L7 |
| I9 contact establishment | §12 | card QR/link, one-scan flow, requests, local block; cut-off and Invite v3 deferred |
| I10 Android | §13 | modules, `:sync` and `:entitlement` additions, schema v4, DM actor, `ConsumerTail` |
| I11 tests and slices | §14, §15, §17 | JVM worlds, crash enumeration, seeded worlds, T32, 79 mutants, emulator job, device checklist, S0–S13 |

### 0.5 Deviations from approved documents (each recorded in an ADR, "propus, aplicat")

| # | Deviation | From | ADR |
|---|---|---|---|
| X-1 | libsignal 0.86.5 (Maven Central, unused) replaced by 0.102.2 from Signal's repository; `libsignal-client` declared; JDK 17 → 21 for the Android build | `libs.versions.toml:18,39`; CI JDK 17 (`ci.yml:185,218,273`) | ADR-28 |
| X-2 | The client licence is AGPL-3.0-only (proposed; owner decides) | ADR-07 ("MIT sau GPL pentru client") | ADR-29 |
| X-3 | Prekeys are not readable by anyone who knows `ghost1…`; bundles are sealed in a card-derived namespace; no one-time prekeys through relays | plan Annex B ("citire publică"); TM §6 "Publicare prekeys" | ADR-30 |
| X-4 | Senders do not buy write capabilities for a recipient's inbox; the recipient registers a shared deposit key | Annex B ("scriere doar cu capabilitate"); F8 §10.7 interim | ADR-30 |
| X-5 | `RegisterReadKey` (D11) generalized into `RegisterKey(kind ∈ {READ, DEPOSIT})`, verifier bound to namespace and week, bearer credential v3, new `op` value `register` and field `key_kind` | F8 §10.7 point 3; ADR-25 point 9; ADR-19 addendum (capability formats); `allowed-observables.json` | ADR-30 |
| X-6 | The ADR-14 attestation chain is not published in the bundle; deferred and, if shipped, only inside E2E and opt-in | ADR-14 ("lanț publicat în prekey bundle") | ADR-30 |
| X-7 | Revocation certificates travel inside E2E to contacts' inboxes in a v2 format with a minute timestamp, not as a blob in an identity namespace that contacts poll | LIMITE L1 "Recuperare"; ADR-14; `RevocationCertificate.kt:6-8` | ADR-33 |
| X-8 | The Phase 7 usage idiom (pad, libsignal-encrypt, store the libsignal output) is replaced by seal-after-encrypt | F7 §9 idiom (F7:1395-1398) | ADR-31 |
| X-9 | The E2E envelope (L0 codec, padding, seal) lives in Kotlin (`:crypto-bridge`, BouncyCastle), not Rust; a CP-09 exception (a project construction from standard primitives), with external review recommended before the first distributed APK | ADR-19 ("nicio logică de protocol în Kotlin"); ADR-20 point 8; ADR-17 surface (already widened by ADR-24 X15); spec CP-09 | ADR-31 |
| X-10 | TTL observable in seconds with five exact buckets; the relay refuses non-bucket TTLs; `client-core` refuses instead of snapping | `allowed-observables.json:11`; `relay/crates/api/src/lib.rs:21-24,171-175`; `relay_client.rs:260-268` | ADR-32 |
| X-11 | T20: the messaging layer may hold one inexact alarm with no extras; T25 wording ("the relay observes only `bucket(timer)`") | INVARIANTS T20, T25 | ADR-32 |
| X-12 | `:sync` API additions (`HOUR_1`, `relayExpiryHour`, `offers`, `CapabilitySource`, `Registrations`, `ConsumerTail`, registrations as write work) and the `outbox_op`/`outbox_delivery` rebuild in migration 4 | F7 §9; ADR-20 points 1 and 8; ADR-23 point 9 (the participant slot stays one) | ADR-34 |
| X-13 | The contact card does not become Invite v3 in Phase 9 (deferred to Phase 13; ADR-05's optional card stays open) | F8:1149, F8 §18 F7 | ADR-30 |
| X-14 | The Phase 8 T2 world and `t2-exit-gate` change: `keys.redb` exported and completeness-checked; world clients register their DM owner namespaces | F8 §19.24 point 6; ADR-25 tests | ADR-34 |
| X-15 | FR numbering: key change is spec **FR-4.6** (FR-4.5 is encrypted local storage); TM S12, LIMITE L1 and plan §1.2 corrected | TM:151, LIMITE:38, plan:63 | erratum (Appendix B.1) |
| X-16 | Plan row 9 "TTL pe relee ≤ timer" is read as ADR-27 point 11 ("cea mai mică treaptă ≥ timer"; 5 min → 1 h), the approved and only satisfiable text | plan:274, plan:310 | erratum (Appendix B.1) |
| X-17 | Phase 9 CI adds a third-party GitHub Action (the Android emulator runner), pinned by commit SHA | `ci.yml:5` pinning rule (allowed with a pin) | ADR-34 |

### 0.6 What this design deliberately does not do

- **No libsignal sealed sender, no sender certificates, no fake trust root** (§6.1). The only libsignal code GHOST calls is the session layer and the fingerprint.
- **No per-sender write capabilities, no token spent on a foreign namespace, and no fallback to them** when a recipient has not registered: the deposit waits for a credential and the op ends at its deadline.
- **No delivery or read receipts, no typing indicators, no automatic retry requests or session resets** in Phase 9. Read receipts may come in Phase 13 as an opt-in flag piggybacked on a user message, STANDARD mode only (Q8).
- **No contacting from a bare `ghost1…`.** A discoverable mode would reopen R-privacy F1 by construction (Q7).
- **No one-time prekeys, no attestation chain and no revocation namespace on relays.**
- **No weekly inbox rotation** (C-4) and **no cut-off card rotation** in Phase 9 (C-16; `card_index` stays 0, reserved in the card).
- **No Invite v3** (C-18) and **no change to the Phase 8 drop format** (C-17).
- **No cover traffic** (P2), no DM-specific schedule, no shorter listing interval: NFR-1 is measured and recorded, not claimed (Q23).
- **No multi-device** (P2): in P0 a "new device of a contact" is an identity-key change (RS K17).
- **No FTS index, no copied quote text, no content in notifications, no conversation "last activity" column, no persisted rejection history.**
- **No second periodic job, no exact alarm, no WorkManager, no FCM, no coroutines in GHOST code.**
- **No new Rust crate, no new AEAD or curve crate, no new Gradle coordinate other than libsignal and its transitive artifacts.**

---

## 1. Adversary views and the declared DM leakage

### 1.1 Who sees what (effective views, not only T1 captures)

T1 constrains what an honest relay records in capture mode. AD-1 keeps everything its processes see (RP §0.1). This design reasons about the **effective view**.

| Observer | Effective view per DM-related event |
|---|---|
| Relay (AD-2) | op; namespace; blob hash; size bucket; the TTL as stored; exact arrival time; the credential presented (so its scope hash and, by construction, its kind); request id; the onion circuit (all requests of one circuit are linkable); stored bytes; `keys.redb` records; its own quota ledgers |
| AD-1 | the union over all relays, plus the issuer (Phase 8 declared leak L1–L7) |
| AD-4 / AD-5 | Tor traffic timing and volume at one or both ends |
| AD-7 (a contact) | the target's card (hence `X`, `P`, every week's deposit and bundle read secrets, the bundle and intro outer keys), the content of their own conversation, the safety number; with its own tokens, a write capability for `X` (SC-2) |
| AD-8 / AD-12 | local rows, WAL and files; a seized relay disk (blobs, `keys.redb`, `nullifiers.redb`) |

**Rule V1 (normative).** Access control on relays protects nothing against the relay itself. Every relay-stored DM byte is sealed under keys that are **never presented to a relay**. Read secrets, deposit secrets and capabilities are presented; seal keys, bundle keys, pair keys, intro keys and card secrets never are.

### 1.2 Declared DM leakage LD (the only information T32 lets through)

Per inbox namespace per relay:
- the minutes of stores, their size buckets (4/16/64 KiB) and TTL buckets (1 h / 1 d / 7 d / 30 d), and the one static deposit scope of the (relay, inbox) (§21.2);
- `check` events on the same scope;
- the owner's list schedule (T19, presence) and the number of gets per list;
- the owner's weekly redemption and `register` events at the redeem lane's renewal time (§4.8);
- bundle publications at the card's fixed weekly offset;
- bundle fetches (one read scope per bundle namespace per relay; at most three attempts per establishment, §21.7);
- the moments of activation, restore and revocation notices (L7-D10);
- the session-start co-occurrence windows of Phase 7 (LIMITE L2.1 #1);
- (§21.11) the grouping of one client's requests per circuit within a session (L7-D5), exact arrival times, the identical hash of an identical-bytes resend (L7-D9), and the result of every request, refusals included.

Everything else a relay can compute from its effective view is a T32 violation.

### 1.3 The property T32 proves (the privacy statement of the exit gate)

1. **(a) Join-freedom.** The exact searches JD1–JD9 find nothing in the effective relay view (§15.6).
2. **(b) Non-interference.** Worlds that differ only in inbound content, message type, a client's degree, the timer within a bucket, or local trust actions give identical shape views (NI-DM1–NI-DM6).
3. **(c) No learned advantage.** No attacker on the full effective view recovers conversation edges or identity mappings better than the same attacker restricted to LD (S-DM1, S-DM3 at α = 0.001). The LD attacker's success is measured and reported (S-DM2, S-DM4), not claimed away.

(a) and (b) are exact for every seed; (c) is statistical for the pinned seeds. The residue inside LD is declared in LIMITE L7 (§11.5) and in the UI copy (CP-10).

---

## 2. libsignal integration and licensing (I1; ADR-28, ADR-29)

### 2.1 Route comparison and decision

| Criterion | J: Android artifacts (chosen) | R: Rust crates in `client-core` (fallback) | H: build `signal_jni` from source |
|---|---|---|---|
| GHOST code on the crypto boundary | none: Kotlin calls Signal's own Java layer; stores are Java callbacks | a GHOST JNI over async store traits (new audit surface) | none |
| Networking code in the APK | dormant `libsignal-net` + TLS inside `libsignal_jni.so` [U16][U17] | none | same as J |
| Native bytes built by | Signal (sha256-pinned) | GHOST (T12 by hash) | GHOST, upstream Docker |
| FR-2.1 wording ("official Android artifacts") | met | deviation | met in spirit |
| JVM tests with real crypto | yes (`libsignal-client` desktop natives) | yes (host build) | yes |
| New build infrastructure | Signal repository, JDK 21 | git crates, `deny.toml` git + AGPL exceptions, `curve25519-dalek` 5.x beside 4.1.3 | Docker build of libsignal, JDK 21 |
| Bump cost | version bump + full DM harness + golden-record drill | re-bridge the API | as J + native rebuild |

**Decision: J** (ADR-28). The part that must be correct is the protocol implementation and its store callbacks; J leaves both as Signal ships and tests them (Signal-Android is on 0.102.1 [U42]), while R would put a GHOST-written JNI and an async-to-sync store adapter on the path of every ratchet step. J's costs (dormant networking code, a binary GHOST did not build) are contained by gates (§2.7) and T6; R's cost cannot be contained by a gate. **R is the fallback** if the owner rejects dormant networking code in the APK (Q2). **H** is a Phase 15 hardening option (rebuild the `.so` from the tag in upstream's pinned Docker image and diff the stripped output).

### 2.2 Version and distribution (normative)

- **Coordinates.** `org.signal:libsignal-android` and `org.signal:libsignal-client`, **both** declared in `libs.versions.toml` at the same exact version (`libsignal = "0.102.2"` today; spec Appendix A, `spec.txt:1084-1085`). The unused 0.86.5 pin is removed: its SPQR can fall back to none (`min_version: V0`, RL §3) and it gets no fixes.
- **Repository.** `settings.gradle.kts` gains `exclusiveContent { forRepository { maven("https://build-artifacts.signal.org/libraries/maven/") }; filter { includeGroup("org.signal") } }`. No other group may resolve from it; `org.signal` may resolve from nowhere else. This is build-machine egress (T7, T12), not app egress (ADR-01).
- **Verification.** sha256 of the AAR, the JAR and their POM/module files, and of every new transitive artifact, in `verification-metadata.xml` (today 0 `org.signal` entries, RC F10).
- **Toolchain.** `libsignal-client` 0.102.2 declares `org.gradle.jvm.version = 21` [U5]. The Android build and the CI jobs `android`, `sync-exit-gate`, `reproducible` and `entitlement-exit-gate` move to JDK 21; module `jvmTarget`s stay 17 wherever that compiles. S0 verifies D8/R8 dexing of the libsignal classes, Kotlin interop, and that the Phase 7 and Phase 8 harnesses stay green unchanged. If D8 refuses the class files, the fallback is the newest release ≥ 0.100 whose client JAR targets 17; if none exists, route R (Q2).
- **Bump policy.** "Use outside of Signal is unsupported", and API breaks are signalled only on a best-effort basis [U2]. Every bump is its own PR that runs the full `messaging-exit-gate`, the golden sizes (§6.6), PQ-3 (§9.2), and the golden-record drill (§2.4 rule 4), and records the new sha256 values and the new golden directory. No automatic bumps.

### 2.3 API surface (closed list, enforced by gate G-LS3)

| Class | Use |
|---|---|
| `protocol.SessionBuilder.process(PreKeyBundle, Instant now)` | establishment from a fetched, verified bundle |
| `protocol.SessionCipher(stores…, localAddress, remoteAddress)`: `encrypt(byte[], Instant now)`, `decrypt(PreKeySignalMessage)`, `decrypt(SignalMessage)` (no `Instant`), `getSessionVersion()`; `SessionBuilder` takes both addresses too (§21.6) | all DM traffic |
| `protocol.state.PreKeyBundle`, `SignedPreKeyRecord`, `KyberPreKeyRecord`, `SessionRecord` | bundle construction, opaque records |
| `protocol.state.{IdentityKeyStore, SessionStore, SignedPreKeyStore, KyberPreKeyStore, PreKeyStore}` | implemented on SQLCipher as transaction-bound views (§2.4); `PreKeyStore` holds nothing |
| `protocol.SignalProtocolAddress`, `protocol.IdentityKey`, `IdentityKeyPair`, `ecc.ECPrivateKey(bytes)`, `ecc.ECPublicKey`, `ecc.ECKeyPair`, `kem.KEMKeyPair`, `kem.KEMKeyType`, `kem.KEMPublicKey`, `IdentityKeyStore.Direction`, `IdentityKeyStore.IdentityChange` (§21.6) | addresses; identity from the seed; prekey generation |
| `protocol.message.{PreKeySignalMessage, SignalMessage, CiphertextMessage}` | typed L1 parsing; `PreKeySignalMessage.getIdentityKey()` for the pre-check of §8.3 |
| `protocol.fingerprint.{NumericFingerprintGenerator, Fingerprint, ScannableFingerprint, DisplayableFingerprint, FingerprintVersionMismatchException, FingerprintParsingException}` (§21.6) | safety numbers |
| `protocol.logging.{SignalProtocolLogger, SignalProtocolLoggerProvider}` | the silent logger (§2.6) |
| typed exceptions (`UntrustedIdentityException`, `DuplicateMessageException`, `InvalidMessageException`, `InvalidKeyIdException`, `InvalidKeyException`, `NoSessionException`, `InvalidVersionException`, `LegacyMessageException`, and the reuse-refusal type of `markKyberPreKeyUsed`, fixed in S0) | caught by type only (G-LS6), never by a catch-all |

Everything else in `org.signal.libsignal.*` is banned in GHOST sources, in particular `metadata.*` (sealed sender), `net.*`, `zkgroup.*`, `usernames.*`, `messagebackup.*`, `svr*`, `media.*`, `attest.*`, `keytrans.*`, `internal.*` and `protocol.groups.*` (Sender Keys: groups are MLS). Without sealed sender no `SenderKeyStore` and no aggregate `SignalProtocolStore` are needed: `SessionCipher` takes the stores individually (RL §2.3).

**Time rule (T20 spirit, RE F9).** Every libsignal call that takes `Instant now` receives `floor_minute(now)`; generated prekey records receive `floor_day(now)` timestamps. A unit test decodes the records after a scripted session and asserts no finer timestamp (§15.2). S0 lists every libsignal path that reads the system clock by itself; the harness keeps those paths away from assertions about virtual time, and each one is recorded in Appendix C.

### 2.4 Store rules: `TxSignalStores` (normative; G-1, G-2)

1. **Transaction-bound and stateless.** `TxSignalStores(tx)` is built inside `SyncDatabase.transaction` from `tx.sql`, together with the `SessionCipher`/`SessionBuilder` of that operation, on the DM actor thread (§13.7), and dies with the transaction. Every call reads or writes rows. There is no cache, memoization or pooled `SessionRecord`: a cache that survived a rollback would resurrect a ratchet state the database no longer has (mutant MC-2). A call after the transaction ended, or from another thread, throws (`SyncTransaction.kt:13-38`).
2. **Bounded records.** `sig_session.record` ≤ 1 MiB, enforced by the store as the typed `SessionRecordOversizeException` and handled as a bounded outcome (§21.5): a peer can exceed it deliberately, because skipped keys are capped per receiver chain and archived states keep their chains. The SQL CHECK is an unreachable backstop.
3. **Exceptions.** Store implementations throw `IllegalStateException` for broken invariants, plus the reuse exception of `markKyberPreKeyUsed` and `SessionRecordOversizeException` (§21.6 point 5), (for example `saveIdentity` with a key different from the pinned one, or a second current signed prekey). Pipelines catch only libsignal's typed protocol exceptions; anything else propagates, and `sync-no-catch-all.sh` enforces this in `:messaging` and `:crypto-bridge`.
4. **Golden records (G-2).** Fixtures of every record type serialized by the pinned version (identity key pair, a session after N messages each way including skipped keys and an archived state, signed and Kyber prekey records, reuse tuples) are committed under `crypto-bridge/src/test/resources/libsignal-golden/<version>/` (§21.6). `LibsignalUpgradeTest` loads the previous version's fixtures with the new pin and continues their sessions both ways. `libsignal-version-lock.sh` (G-LS4) requires, at every pin change, the new directory and the previous one.
5. **Thread-safety.** `SessionCipher` and `SessionBuilder` are not thread-safe [U23][U24]. The DM actor is the only thread that constructs or calls them.

### 2.5 Native library, ABIs, size, loading (normative; G-14)

- **ABIs.** `arm64-v8a` and `x86_64` (app `abiFilters`, ADR-19); the AAR's `armeabi-v7a` and `x86` are filtered out.
- **Stripping.** The AAR sets `doNotStrip '**/*.so'` ("defer stripping to the app") [U9]; AGP strips `libsignal_jni.so` with the NDK pinned by `android.ndkVersion` and installed in every job that builds the APK (§21.13). Expected ≈ 11 MB per ABI (issue #660 [U39]), measured in S0 and reported separately (NFR-4 measurement condition). The current release APK is 41.5 MB (RC §7), so ≈ 64 MB is expected, inside the spec's 70 MiB (Q24).
- **16 KB page alignment** checked in S0 (`zipalign -c -P 16`).
- **Desktop natives.** The `libsignal-client` JAR carries Linux, Windows and macOS natives. JVM tests need them (`testImplementation`); they **must not reach the APK**: `packaging.resources.excludes` for every `*.so`, `*.dylib`, `*.dll` and `*.jnilib` outside `lib/`, and gate G-LS2 fails otherwise.
- **Lazy load.** The native library loads on the DM actor thread at the first libsignal use, never in `Application.onCreate`. A missing or unloadable library maps to the facade result `CryptoUnavailable` (the `NativeLibrary.kt:8-18` pattern), never to a crash loop; the status flag is a count.
- **R8.** Keep rules for `org.signal.libsignal.internal.Native` and the store callback interfaces are added in `:crypto-bridge` `consumer-rules.pro` **only if** the AAR ships no consumer rules that cover them (S0), each with a comment naming the library (`app/proguard-rules.pro:1-3` rule). The emulator job's release-variant smoke test (§15.9) proves the shrunk APK loads both libraries and completes one in-process libsignal session, with no transport (§21.13).

### 2.6 Logging (normative; E-18, T3)

- libsignal's Rust layer logs through the Java `SignalProtocolLoggerProvider`. The decrypt path logs **untrusted identity keys in hex at warn level** (`"Identity key {} is not trusted for remote address {}"`, `session_management.rs:130-131, 336-337`) and a decryption-failure report at error level (`:240-250`; `session_cipher_legacy.rs`, cited first, is a test-only snapshot, §21.6); `session.rs:145` logs the remote address at warn. The silent logger is therefore **load-bearing for T3**, not cosmetic.
- `SignalLog.install()` sets a provider whose `log` method does nothing, once, on the DM actor thread, **before** the first libsignal call (and before the lazy native load if the library initializes its logger at load, S0). No GHOST code installs any other provider (gate G-LS3 checks the only call site).
- **Tests.** (1) `SilentLoggerTest`: a recording provider installed by the test around a real untrusted-identity decrypt and a corrupt-session decrypt shows that the production wiring replaces it with the silent one before any call; (2) the T3 canary test drives an untrusted-identity decrypt and scans stdout, stderr and every recorded log line for the canary identity key in hex; (3) the emulator job captures `logcat` during a scripted key change and fails on any line containing a canary key or a `SignalProtocol` tag (§15.9). **S0 assumption A5:** native logging reaches no sink other than the Java provider (no direct `android_logger` output). If it does, S0 records it and the build must disable it; if it cannot be disabled, the finding blocks route J (Q2).

### 2.7 Gates (each with a negative fixture and a `self-test.sh` entry)

| Gate | Rule |
|---|---|
| G-LS1 `apk-native-libs.sh` | `libsignal_jni.so` added to `NATIVE_ALLOWLIST`; the sha256 of the **stripped** `.so` per ABI recorded in the committed `libsignal-natives.sha256` and compared; no `.debug_*` section and ≤ 16 MiB per ABI (§21.13) (third-party `.so` files are checked by name only today, `apk-native-libs.sh:7`) |
| G-LS2 `apk-foreign-natives.sh` (new) | fails on any `*.so`, `*.dll`, `*.dylib` or `*.jnilib` in the APK outside `lib/{arm64-v8a,x86_64}/` |
| G-LS3 `kotlin-libsignal-imports.sh` (new) | only `android/crypto-bridge/src/main` may reference `org.signal`; only the classes of §2.3 (wildcard and fully-qualified use included); `SignalProtocolLoggerProvider.setProvider` has exactly one call site, `SignalLog.install` (at most one before S4); `crypto-bridge/src/gate` is also allowed (§21.6, §21.13) |
| G-LS4 `libsignal-version-lock.sh` (new) | both coordinates at the same exact version ≥ 0.100; both sha256 present; the repository filter present; at a pin change, `libsignal-golden/<new>/` and `libsignal-golden/<previous>/` both exist (the first pin, from the unused 0.86.5, is exempt, §21.13) |
| G-LS5 R8 rules | keep rules only with a comment naming the library; the release smoke test of §15.9 |
| G-LS6 `sync-no-catch-all.sh` | scope extended to `android/messaging/src/main` and `android/crypto-bridge/src/main` |
| G-LS7 merged manifest (T15m) | unchanged rule; S0 confirms the AAR adds no permission or component |
| T12 | two release builds identical with the AAR inside. T12 does **not** prove that the `.so` matches libsignal's source: that is trust in Signal's build, declared in ADR-28 and LIMITE L5 |

The dormant networking code is contained three ways: G-LS3 makes its Java entry points unreachable from GHOST code and R8 removes unreferenced classes; the Tor-only runtime test T6 (Phase 13 emulator) would catch any direct connection; no GHOST path ever passes it a configuration. The bytes stay present in the `.so` (declared, LIMITE L5).

### 2.8 Why the envelope is in Kotlin (C-3, E-4)

The seal and the L0 codec (§6, §7.1) live in `:crypto-bridge` on BouncyCastle, next to the libsignal Java API, and not in `client-core` as ADR-19 and ADR-20 point 8 would place protocol framing and padding. The reasons, corrected:

1. **The libsignal output is a Kotlin byte array** produced inside a SQLCipher transaction on the DM actor. A Rust seal would add one JNI round trip per message inside that transaction.
2. **Precedent.** ADR-24 X15 already put the Phase 8 `DropSeal` (X25519, HKDF, ChaCha20-Poly1305) in Kotlin on BouncyCastle.
3. **JVM tests without a host-native build.** The DM world (§15.1) runs the real seal on the JVM with no `libghost_client_net` build for the host.
4. It is **not** true that the workspace lacks an AEAD: `ring` 0.17.14 (ChaCha20-Poly1305) is `required` in the `ghost-client-net` graph (`rust-crypto-pins.txt:19`), reached through `rustls` (`ghost/Cargo.toml:57,62`). A Rust seal would need no new crate; it is rejected for reasons 1–3, not for a missing dependency.

What stays in Rust: `client-core` refuses any blob that is not exactly one bucket, validates relay responses, parses capability and credential headers (T21) and refuses non-bucket TTLs (§10.2). Vectors `dm_seal.txt` and `dm_content.txt` are replayed by the production Kotlin code and by an independent test-only implementation on the JDK's own providers (`javax.crypto` ChaCha20-Poly1305, XDH, HmacSHA256), so a BouncyCastle-path encoding bug cannot vouch for itself. ADR-31 records the deviation and the CP-09 exception (X-9).

### 2.9 Licence (Q1; ADR-29)

- **Facts.** libsignal ("Licensed under the GNU AGPLv3", workspace `license = "AGPL-3.0-only"`) and `spqr` (AGPL-3.0-only) [U2][U13][U15]. Linking them, statically or dynamically, makes the distributed APK a combined work that must be conveyed under AGPLv3 terms on either route (GNU FAQ #IfLibraryIsGPL, #GPLStaticVsDynamic, #AGPLGPL [U41]; not legal advice). No AGPL-free library meets FR-2.1 with PQXDH and SPQR: `libsignal-protocol-java` is archived, GPLv3, and has neither.
- **Consequences.** Every APK recipient is entitled to the Corresponding Source of the whole APK: GHOST Kotlin and Rust, build scripts, and the pinned libsignal source, which GHOST release artifacts mirror (tarball plus sha256) rather than relying on GitHub. GHOST files may still carry MIT, Apache-2.0, GPLv3 or AGPLv3 notices, but the binary cannot be distributed under permissive or proprietary terms: ADR-07's "MIT client" option survives only as "MIT files inside an AGPL app". The AGPL §13 network clause adds little for a client. Relay and issuer do not link libsignal and are unaffected. The other native dependencies (SQLCipher community, Arti, BouncyCastle) are AGPL-compatible (S0 records each licence).
- **Proposed default (Q1).** Android client AGPL-3.0-only; `client-core` keeps `MIT OR Apache-2.0` for its own files; relay and issuer per ADR-07. Implementation proceeds; **the first distributed APK waits for the owner's explicit decision**: Q1 is excluded from the default rule, and from S0 CI uploads no APK artifact (the repository is public; §21.13; exit-gate checklist item 17.2 #13; a release-checklist item from Phase 14).

---

## 3. Identity, key hierarchy and the contact card (I5, I9; ADR-30, ADR-33)

### 3.1 Keys (normative)

Let `m = RootEntropy.deriveBranch(DerivationLabels.MESSAGING)` (the existing MESSAGING branch, vector `messaging_seed` in `KeyDerivationTest.kt:37`). Every DM secret derived from the seed is `HKDF-SHA256(ikm = m, salt = ∅, info = label ‖ params, L = 32)` with a label of `DmLabels` (prefix `ghost/v1/dm/`). Every card-level value is `HKDF-SHA256(ikm = card_secret_i, salt = ∅, info = label ‖ params, L = 32)` with a label of `CardLabels` (prefix `ghost/v1/card/`).

| Key | Derivation / generation | Stored | Leaves the device |
|---|---|---|---|
| Ed25519 identity (`ghost1…`) | `HKDF(root, "ghost/v1/identity")` (Phase 3) | Keystore-wrapped seed; re-derived | the public key, in cards and bundles (to card holders only) |
| libsignal identity (Curve25519, XEdDSA) | private scalar = `HKDF(m, "ghost/v1/dm/identity")`, clamped by libsignal; `IdentityKeyPair(IdentityKey(pub), ECPrivateKey(bytes))` | re-derived at unlock; never persisted (the store returns the derived pair) | public key inside bundles and PreKey messages, both sealed |
| `card_secret_i` | `HKDF(m, "ghost/v1/dm/card" ‖ u16_be(i))`, card index i (0 in Phase 9) | re-derived | inside the card |
| intro key `(y_i, Y_i)` | X25519 secret `HKDF(m, "ghost/v1/dm/intro-key" ‖ u16_be(i))`, clamped | re-derived | `Y_i` inside the card |
| inbox read secret `RX_{i,s}` | `HKDF(m, "ghost/v1/dm/inbox-read" ‖ u16_be(i) ‖ u8(s))`, s = the relay's ES slot (§21.2) | re-derived | presented to the relay of slot s in `X_i`'s set (bearer) |
| schedule key `S_i` | `HKDF(m, "ghost/v1/dm/schedule" ‖ u16_be(i))` | re-derived | never |
| card-level values | §3.2 | derived on demand | only deposit and bundle read secrets are presented to relays |
| signed EC prekey, last-resort Kyber prekey | libsignal key generation (CSPRNG), weekly | `sig_signed_prekey`, `sig_kyber_prekey` | public parts in the bundle |
| pair roots and week keys | CSPRNG root (32 B) generated by the **recipient** per contact; week keys by ratchet (§6.3) | `dm_pair_offer`, `dm_pair_key` (window only) | the root, once, inside E2E content to that contact |
| `seen_key` | CSPRNG 32 B at identity creation or restore | `dm_self` | never |
| content key | CSPRNG 32 B, wrapped by a Keystore key (§13.8) | `dm_self` (wrapped) | never |
| registration id | CSPRNG, 1 … 16 380 | `dm_self` | inside sealed PreKey messages and bundles |

- The derivation from `m` keeps the MESSAGING branch the source of all messaging material (FR-1.2, spec Figure 2, TM:81) and leaves room for Phase 10 MLS labels under another prefix. `DerivationLabels.MESSAGING`'s comment ("seeds the libsignal identity key pair") stays true; `DERIVATION_VERSION` stays 1 because no label changes.
- `DmLabels` and `CardLabels` each have a prefix test (no label is a prefix of another, the `DerivationLabelsTest` rule) and vectors in `KeyDerivationTest`.
- **No derivation takes a public key, a `ghost1` string or a safety number as its key input** (T26; gate G-DM3 and a static IKM check).
- Random per install, never derived: registration id, `seen_key`, content key, pair roots. They must match nothing on another device (RE R-D3), and pair roots must not be recoverable from a seed (P-7).

### 3.2 Card-level labels (`CardLabels`)

| Output | Info | Presented to relays? |
|---|---|---|
| inbox namespace `X_i` (32) | `ghost/v1/card/inbox-ns` | as the namespace id |
| bundle namespace `P_i` (32) | `ghost/v1/card/bundle-ns` | as the namespace id |
| deposit secret `D_{i,s}` (32) | `ghost/v1/card/deposit` ‖ u8(s) | yes (bearer, the relay of slot s; §21.2) |
| bundle read secret `RP_{i,s}` (32) | `ghost/v1/card/bundle-read` ‖ u8(s) | yes (bearer, the relay of slot s; §21.2) |
| bundle seal key `KB_i` (32) | `ghost/v1/card/bundle-seal` | **never** |
| intro outer key `KIO_i` (32) | `ghost/v1/card/intro-outer` | **never** |

s is the ES slot number of the relay the secret is presented to (the slot Phase 8 binds tokens to); credentials carry no week (§21.2). Relays see `D` and `RP` but never `card_secret`, so they cannot derive `KB` or `KIO` (HKDF outputs under distinct labels are independent PRF outputs). A card holder can derive everything in this table; the inbox read secret, the intro private key and the libsignal identity are **not** in it.

### 3.3 Contact card v1 (normative)

```
card = version(1) = 0x01 || card_index(2, BE) || identity_pk(32, Ed25519) || card_secret(32)
       || intro_pk(32, X25519) || signature(64, Ed25519 over "ghost/v1/contact-card" || all previous bytes)
     = 163 bytes
link = "ghost://contact/" + z-base-32(163 bytes) = 16 + 261 = 277 characters   (QR version 11-L, byte mode, capacity 321)
```

- **Parse order (fail closed; each step has a negative test):** scheme exactly `ghost://contact/` with no other URL structure; exact-length z-base-32 decode; `version = 1`; `card_index = 0` in Phase 9 (another index is "card version unsupported", FR-7.7); `intro_pk` canonical and not of small order; signature under `identity_pk`; `identity_pk` ≠ own. `ghost1 = z32(SHA-256(identity_pk))` is derived, never carried.
- **One card per (identity, index), identical for all contacts.** A per-contact card would let relays re-partition senders by namespace and would be a per-contact identifier if a card leaked.
- The card carries **no relay addresses** (the relay set is a public function, §5.2), **no expiry**, **no nonce** (a replayed card re-adds the same contact) and **no one-time prekey** (a card shown twice or photographed would make a second use fail).
- It is a bearer secret for "may message me": whoever holds it can fetch the bundle, deposit (spam, quota: L7-D8) and, with its own token, list the inbox's volume (SC-2, L7-D16). The Phase 13 UI states this when a link is shared through another app (the T16 warning pattern).

### 3.4 Identity binding

- **In every bundle:** an Ed25519 signature by `identity_pk` over the whole bundle, which contains the libsignal identity key (§5.3).
- **In every intro envelope:** the sender's card plus `binding_minute` and `binding_sig = Ed25519(identity_sk, "ghost/v1/dm-binding/v2" ‖ libsignal_identity_pk(33) ‖ u16_be(card_index) ‖ recipient_namespace(32) ‖ u32_be(binding_minute) ‖ SHA-256(L1))`, verified with its freshness before any state change (§6.4, §21.4).
- libsignal cannot verify Ed25519 (ADR-17). The binding is verified with BouncyCastle (`Ed25519` of `:identity`) **before** any libsignal call on that input. `IdentityKeyPair.signAlternateIdentity` (XEdDSA, the wrong direction) is not used.
- Because both identities derive from one seed, a libsignal key `K′ ≠ K` under a valid binding by the pinned Ed25519 key happens only when the holder of that Ed25519 secret signed another libsignal key: the contact itself (including a modified client), a derivation-version change, or a seed thief. All deserve a stop (§8.3, §21.4).

---

## 4. Relay authorization: `RegisterKey`, bearer credential v3, deposit and read keys (I3, I4; D11; ADR-30)

### 4.1 Why (the security argument)

With per-sender write capabilities (Annex B literally, and the Phase 8 interim), every store into a recipient's inbox carries `capability_scope = SHA-256(capability)`, and the v2 serial makes that value distinct per sender token (`relay/crates/capability/src/lib.rs:190-195`; ADR-25 point 6). The relay then partitions the inbox by sender, counts correspondents per week (and at rest through E13 binding tags), sees each new correspondent as redeem-then-store (WRITE MISSING redeems at once, F8 §12.4), and token spend grows with DM breadth (E16). That is a sender field in substance, which Annex C T1 forbids (RP F2, RC F4, F5). The fix adapts Signal's delivery-token idea to blind relays: **the recipient authorizes deposits with one weekly secret shared by all its card holders and pays for them with its own capability.** The same RPC implements D11's shared read keys (F8 §10.7).

### 4.2 `relay.proto` additions (normative)

```proto
enum KeyKind {
  KEY_KIND_UNSPECIFIED = 0;
  KEY_KIND_READ = 1;                // list, get, check
  KEY_KIND_DEPOSIT = 3;             // store, check (2 is Write in capability headers; never used here)
}

enum RegisterResult {
  REGISTER_RESULT_UNSPECIFIED = 0;
  REGISTER_RESULT_OK = 1;           // recorded, or an identical record already existed
  REGISTER_RESULT_WRONG_PERIOD = 2; // period not in {cap_week, cap_week + 1}; nothing recorded
}

message RegisterKeyRequest {
  uint32 version = 1;               // MUST be 1 (proto-check.sh)
  bytes namespace_id = 2;           // 32 bytes
  uint64 period_id = 3;             // ISO week of the key (Phase 8 period)
  KeyKind kind = 4;
  bytes verifier = 5;               // 32 bytes (§4.3); the secret never reaches the relay at registration
  Capability capability = 6;        // a usable WRITE capability (v1 or v2) for namespace_id
  bytes request_id = 7;             // 16 random bytes, identical on an identical retry
}

message RegisterKeyResponse {
  RegisterResult result = 1;
  uint64 relay_period_id = 2;       // always (R9 relay-facing clock source, as RedeemToken)
  uint64 relay_minute = 3;          // always
  uint64 valid_until_unix = 4;      // OK only: when the relay forgets the record
}

service RelayService {
  // ... the existing six RPCs ...
  rpc RegisterKey(RegisterKeyRequest) returns (RegisterKeyResponse);
}
```

`StoreBlob`, `GetBlob`, `CheckBlobs` and `ListNamespace` keep their messages; their `Capability.token` may now also carry a bearer credential v3 (§4.3).

### 4.3 Bearer credential v3 and verifiers (normative; `ghost_relay_api::capability_header` gains a third layout)

```
credential v3 (67 bytes) = version(1) = 3 || kind(1) ∈ {0x01 read, 0x03 deposit} || slot(1) || namespace(32) || secret(32)      (§21.2)
verifier (32 bytes)      = SHA-256(label(kind) || u8(slot) || namespace(32) || secret(32))
label(read)              = "ghost/v1/read-verifier"        (the D11 label, F8 §10.7 point 3)
label(deposit)           = "ghost/v1/deposit-verifier"
```

- Anyone holding the secret can build the credential; it carries no MAC because its authority is the registered verifier. It is deterministic: every presenter of the same secret at the same relay sends **identical bytes**, so `capability_scope = SHA-256(credential)` is one value per (relay, namespace, kind) for all depositors (inbox) or all fetchers (bundle), in every week (§21.2).
- The verifier binds the relay slot and the namespace (D11's `SHA-256(label ‖ secret)` refined, X-5): a verifier registered for one namespace cannot authorize another, and a relay refuses a credential naming another slot, so a relay cannot replay a secret it saw at other relays (§21.2). The week lives only in the registration period.
- **Rights.** read → `list`, `get`, `check`; deposit → `store`, `check` only. A deposit credential presented to `list` or `get` is `rejected_capability` (contacts must not read the inbox with the card: F8 §10.7 rejected alternative "free reads").
- **`client-core` (T21).** `NamespaceClient::authorize(credential, access)` parses the v3 header before any I/O, checks the kind/operation matrix and that the header's namespace is the client's, and refuses otherwise with `invalid_argument` (0 requests, 0 connections). The refused-token matrix of `namespace_client.rs:444-694` gains the v3 rows: read at store; deposit at list and get; wrong namespace; lengths 66 and 68; unknown kind 0x02 (§21.2). The circuit is the namespace's (`IsolationScope::Namespace`).

### 4.4 `RegisterKey` semantics (normative; `Relay::register_key_at(req, now)`, exactly one capture event; SC-1)

1. `version = 1`; lengths `namespace_id` 32, `verifier` 32, `request_id` 16; `kind ∈ {READ, DEPOSIT}` → else `INVALID_ARGUMENT`, `rejected_size`.
2. The capability parses as v1 or v2, its MAC verifies (`RelayKey::verify`), its kind is Write, its namespace is `namespace_id`, and it has not expired at `now` → else `PERMISSION_DENIED`, `rejected_capability`.
3. `cap_week` = the ISO week the capability belongs to: for v2, `week(expiry − 3600 − 1)` (expiry is `start(cap_week + 1) + 3600`, F8 §10.3); for a CLI-minted v1, `week(now)`. Require `period_id ∈ {cap_week, cap_week + 1}` → else `OK` with `WRONG_PERIOD`, `rejected_period`, nothing recorded. **The relay's clock never selects the period** (G-3): a registration made late in a week with that week's capability, or early in a week with the previous week's still-valid capability, is judged by the capability.
4. **Accumulate, never replace.** In one redb write transaction, committed before the response:
   - key `namespace ‖ period ‖ kind ‖ verifier` in `bearer_keys`: absent → insert `valid_until = start(period + 2) + 3600`, `quota_bytes = capability.quota_bytes`, `serials = [serial]`; present → if `serial` is not in `serials` and `|serials| < 4`, append it and add `capability.quota_bytes` (the allowance of §4.5); otherwise unchanged. `serial` is the v2 capability's 16-byte serial, or the first 16 bytes of the v1 capability's scope hash.
   - key `namespace ‖ period ‖ kind ‖ serial` in `serial_use` → `verifier`: absent → insert with the same `valid_until`; present with the same verifier → unchanged; **present with another verifier → `PERMISSION_DENIED`, `rejected_capability`, nothing recorded** (one capability registers at most one verifier per (namespace, week, kind)).
   - Response `OK` with `valid_until_unix`.
5. **Why accumulate (SC-1).** A card holder can redeem its own token for a contact's inbox (the namespace id is in the card's derivations) and would, under a "last registration wins" rule, replace the owner's deposit verifier and lock every other sender out. Under accumulation it can only add its own verifier, whose scope is its own (it gains nothing it did not already have) and whose quota it paid for. Replacement is not needed: a cut-off moves to a new card index (Phase 13, §12.5), and the old index's registrations lapse on their own within two weeks.
6. Error messages are constants; forged, unknown, expired and conflicting registrations share one result (`rejected_capability`): no oracle.

### 4.5 Deposits, reads and the `DepositLedger` (normative; E-11)

- **`store` with a deposit credential.** Parse v3; the header's slot is the relay's own and its namespace equals the request's; compute the verifier; a `bearer_keys` record `(namespace, p, DEPOSIT, verifier)` with `now < valid_until` exists for some period p (§21.2) → else `rejected_capability`. All other store rules are unchanged (bucket size, exact TTL bucket §10.2, hash recomputation).
- **Quota.** Deposits are charged to a **`DepositLedger` entry of the matching record `(namespace, period, verifier)`**, the live one with the earliest `valid_until` that has allowance left (§21.2), not to the registering capability's `QuotaLedger` entry: that entry expires at `start(cap_week + 1) + 1 h`, and `QuotaLedger::charge` returns `Expired` once `cap.expiry_unix ≤ pruned_through` (`relay/crates/capability/src/lib.rs:205-217`), while a registration of week `cap_week + 1` lives until `start(cap_week + 3) + 1 h`. The entry's allowance is the record's `quota_bytes` (the sum credited by its registering capabilities, §4.4 point 4); its expiry is the record's `valid_until`. Over the allowance → `RESOURCE_EXHAUSTED`, capture `rejected_capability`, as for a write capability over quota. Like `QuotaLedger`, the used bytes live in memory and restart empty: a registration may be exceeded once per relay restart, bounded by its validity (E29 of ADR-25 extended, declared).
- **`list`, `get`, `check` with a read credential.** The same verification with `kind = READ`. `check` also accepts a deposit credential (senders verify their own copies, F7:626).
- **Write capabilities keep working** for every operation as today (write grants read). A card holder that redeems its own token for a contact's inbox can list it (SC-2, L7-D16); closing that needs an owner-bound read rule, a Phase 12 item (§20 F-5, Q36).
- **Sweep.** The existing 60-second loop deletes `bearer_keys` and `serial_use` rows with `valid_until ≤ now` in one write transaction and never runs below a persisted high-water minute (the ADR-25 point 3 clock rule).

### 4.6 `keys.redb` (normative)

- A separate `<data-dir>/keys.redb`, `SCHEMA_VERSION = 1`, `Durability::Immediate`; tables `bearer_keys` (`namespace(32) ‖ period(8) ‖ kind(1) ‖ verifier(32)` → `valid_until(8) ‖ quota_bytes(8) ‖ n(1) ‖ serial(16) × n`), `serial_use` (`namespace ‖ period ‖ kind ‖ serial(16)` → `verifier(32) ‖ valid_until(8)`), `meta` (`schema_version`, `sweep_high_water_minute`).
- **Why a separate file and not a table in `nullifiers.redb`.** Registrations are soft state that owners re-create (§4.8 healing rule), while nullifiers are money state with strict start-up rules (a missing `nullifiers.redb` next to `relay.key` refuses start, F8 §10.5). A missing `keys.redb` is created empty at start and never refuses it; `--nullifiers-reset` does not touch it; losing it is healed by owners within a session and costs senders at most the refusals until then. Registrations never enter the reconciliation of runbook R2.
- **Privacy at rest (AD-12).** Namespaces, periods, verifiers (hashes of secrets the seizer does not hold), validity instants aligned to weeks, allowances and up to four capability serials per record: no request history, no per-sender data. With the relay key also seized, a serial lets its holder test candidate nullifiers, linking a nullifier to a namespace for at most two weeks: the E13 residue, unchanged in kind. A seizer learns which namespaces had registrations in the last ≤ 2 weeks, which the blob store already implies.

### 4.7 Observables (T1; `allowed-observables.json` version 2, the "decizie de confidențialitate" rule of INV:50) and vectors

- `op` gains `"register"`. The register event carries `op`, `protocol_version`, `namespace_id`, `period_id`, `key_kind` ∈ {`read`, `deposit`} (a new field, on `register` only), `capability_scope` (the hash of the registering write capability), `request_id`, `time_bucket`, `result`. The verifier never appears.
- `capability_scope`'s note becomes "SHA-256 of the presented credential: a write capability, or a bearer read or deposit key v3 (ADR-30); never the credential itself".
- `ttl_bucket_days` is replaced by `ttl_bucket_seconds` ∈ {3600, 86400, 604800, 2592000, 7776000} (§10.2). `result` values are unchanged (`rejected_ttl`, `rejected_period` and `rejected_capability` already exist).
- No other field is added in Phase 9. `circuit_id` stays allowed and unemitted (a Phase 12 item, §20 F-4); the DM world exports circuits in its effective view instead (§15.6).
- Fixtures: positive lines for `register` with each `key_kind`, for stores with `ttl_bucket_seconds = 3600`, for a store presenting a deposit scope; negative lines for `ttl_bucket_seconds = 7200`, the old `ttl_bucket_days` field, `key_kind` on a store, and a 64-hex verifier-shaped value in a field not declared as a hash.
- **Vectors `protocol/test-vectors/register.txt`** (new; `relay_semantics.txt` gets only the TTL section, §10.2), about 45 cases: register read and deposit ok; identical retry; a second capability crediting the same record (allowance doubled, no fifth credit); `cap_week + 1` accepted and `cap_week + 2`, `cap_week − 1` refused as `WRONG_PERIOD`, from a capability redeemed late in its week; no, expired, foreign-namespace and read-kind capabilities; a second verifier from the same capability refused; a second verifier from another capability accumulated; deposit store ok and charged to the record's allowance (exhaustion → `RESOURCE_EXHAUSTED`); deposit at list and get refused; read at store refused; wrong secret; credential for another week or namespace; after `valid_until`; sweep boundary; restart keeps records and empties the ledger. Replayed by the Rust relay (`tests/register_vectors.rs`) and by the Kotlin `ModelRelay` (`ModelRelayConformanceTest`), which keeps the model honest.

### 4.8 Owner flow, token accounting and reachability (normative; G-3, E-10, G-17)

**Registrations the owner keeps (the `REGROWS` transaction, §7.2).** For each own namespace `ns ∈ {X_0, P_0}`, each relay r of its current relay set (§5.2) and each kind it needs (`X`: DEPOSIT and READ; `P`: READ), the owner keeps rows `(r, ns, week, kind)` in `relay_key_registration` (§13.6) for:
- `week(now)`, whether or not a capability exists (so a pending row exists to be served);
- `c` and `c + 1` for the week c of every usable write capability of `(r, ns)`.

The verifier of a row is fixed at insert (§4.3). The `:sync` work lane runs a pending row with a usable write capability of week c such that `row.week ∈ {c, c + 1}` (§13.3). Results: `OK` → `done` with `valid_until_hour`; `WRONG_PERIOD` → stays pending until the capability generation changes; transient categories → the Phase 7 backoff. Pending rows with `week < week(now) − 1` are deleted unexecuted; `done` rows are deleted after `valid_until_hour`. **Healing rule:** when the owner's READ credential for `(r, X, w)` is marked `rejected` (for example after `keys.redb` was lost), every `done` row of `(r, X, week ≥ w)` returns to pending in the same transaction and the READ credential is replaced by the write capability for reads until the rows are done again.

**Credentials the owner installs (the `KEEPER` transaction).** Once per relay r of `X_0`'s set: `Capabilities.put(r, X_0, READ, credential_v3(read, slot(r), X_0, RX_{0,slot(r)}), expires_hour = ceil_hour(now) + 8 d)`, refreshed when fewer than 7 days remain (§21.2). Reads prefer a usable READ credential and fall back to a write capability (§13.3 item 7), so the relay sees the owner's read scope for the week.

**When the relay sees it.** The owner's redemptions for `X_0` and `P_0` follow the Phase 8 planner (F8 §12.4): the EXPIRING renewal at a PRF time in the last 23 h of each week with the next week's token. The rows of the new capability's week + 1 then run in the same session on the work lane. So the weekly pattern at a relay is: one redeem per own namespace, then one `register` per missing (week, kind), at the renewal time the redeem lane already chose. Nothing about contacts, messages or fetches enters these times (T27, T31).

**Need reason of a registration-only namespace (Q31, default).** `Capabilities.needed()` treats a pending registration row like outbox work: `WRITE MISSING` where a pending row exists and no write capability does (§13.3 item 4). The planner then redeems as soon as an eligible token exists (F8 §12.4), instead of READ MISSING's PRF time within 6 h. The Phase 8 redeem hold (Q29) arms for it, which closes the Phase 8 Q34 gap for DM owners whose capabilities lapsed (§13.4). The alternative (READ MISSING, ≤ 6 h) is Q31's.

**Token accounting (T27; E-10).** Exactly **one ACCESS token per (relay, own namespace, week)** on the EXPIRING path, whatever the number of contacts or messages; at most **2 per ES slot per week** (when a relay belongs to both sets). A trial (8 per slot per week) and a pack (16) both cover it. Senders spend **0** on others' namespaces: `CapabilitySource.LOCAL` needs are never redeemed (§13.3 item 3, mutant PM-1b). There is no weekly namespace roll, so no week-p token redeems a namespace that a week-(p + 1) token renews a day later (the base's double cost). After a slot-table change, one extra token per extra union relay per week, for at most 6 weeks (§21.1).

**Reachability (G-17).**
- **After activation:** under Q31's default, a new identity's inbox is redeemed and registered in its first relay session once a token is eligible: at once for a trial in STANDARD mode; at the activation slot in HIGH mode (F8 §12.3: the next UTC day boundary after 4 h, plus U[0, 6 h], plus geometric extra days); at the activation slot for genesis. Under the alternative, up to 6 h later.
- **After a restore:** tokens are not recoverable from the seed (Phase 8 E11), but registrations are relay state. For up to two weeks after the old device's last renewal, contacts' deposits still succeed and the restored device reads its inbox with the seed-derived read key without any capability. After that it needs tokens (a trial from a new invite, or a pack).

**Offline tolerance (G-3, E-8; §21.2).** An owner online in week w registers `{w, w + 1}` and, after its renewal at the end of w, `{w + 1, w + 2}`. A sender presents its one credential for the relay; there is no week choice and no fallback. Therefore:
- a recipient whose newest write capability is of week c receives deposits until `start(c + 3) + 1 h`; about **two to three weeks** of absence cost no deposit;
- a message deposited in that time lives on the relays for its TTL (up to 30 days) and is fetched when the owner returns within it;
- beyond that, deposits wait in `wait_capability` and every DM op ends at its deadline (§10.1): at most 7 days after compose, then FAILED (no copy existed; the user may retry).

### 4.9 T2 world and gate (normative; G-16, E-6, E-7, X-14)

The Phase 8 T2 world exports every table of the relay databases and fails on a table it does not know (F8 §19.24 point 6). Phase 9 therefore changes `t2-exit-gate`:
1. **Export and completeness.** `keys.redb`'s tables (`bearer_keys`, `serial_use`, `meta`) and the in-memory `DepositLedger` (a read-only `Relay::deposit_ledger_snapshot`, the `quota_snapshot` precedent) join the export and the completeness check; `register` capture events are counted in the relays' capture files.
2. **Client model.** Every activated world client registers its DM owner namespaces `X` and `P` at activation (redeem at once under Q31's default) and renews them at the EXPIRING PRF time, with the `register` events of §4.8. DM deposits are not modelled: they spend no token and involve no issuer (T27), which the DM world proves (JD3, JD8, NI-DM3).
3. **Report.** The `population` line gains `dm_owner_namespaces` (2 per activated client); the PR and gate baselines are re-recorded; `t2-report-check.sh` requires the new field. NI-1, NI-2, NI-3 and NI-K are unchanged in rule (no issuer input reaches the new events).
4. **Expected effect.** Two more namespaces per client in the declared attacker's relay-side features (its namespace count, F8 §19.24 point 5), identical for every client: a uniform shift, not a new signal. E16 (exhaustion-triggered purchases) cannot grow with DM breadth.

---

## 5. Addressing, relay sets and prekey bundles (I3, I4; ADR-30)

### 5.1 Namespaces (normative; G-4)

| Namespace | Registered by | `Namespaces.register` | Read | Write |
|---|---|---|---|---|
| own inbox `X_0` | owner, at activation and restore | `(X_0, DM, union set, listen = true, REDEEM)` | owner: READ credential `RX_{0,s}`, or its write capability | card holders with `D_{0,s}`; owner's capability (never used for stores) |
| own bundle `P_0` | owner, same moments | `(P_0, PREKEYS, set, listen = false, REDEEM)` | fetchers with `RP_{0,s}` | owner's write capability (bundles); owner verifies with `check` |
| contact inbox `X_c` | us, at the first send to c | `(X_c, DM, set(X_c, w), listen = false, LOCAL)` | nobody on our side | us, with `D_{c,s}` per relay slot (§21.2) |
| contact bundle `P_c` | us, during establishment only (§5.5) | `(P_c, PREKEYS, set(P_c, w), listen = true, LOCAL)`, removed after | us, with `RP_{c,s}` per relay slot (§21.2) | nobody on our side |

- Namespaces are **static per card index**; credentials rotate weekly (§3.2). Weekly namespace rotation is rejected (C-4): under AD-1 the new namespace starts in the same sessions as the old one (session co-occurrence, LIMITE L2.1 #1), so it does not break continuity; it would cost extra read pairs and tokens at every roll and lose mail for recipients offline beyond the listening window. What it would have bought, a seized relay disk showing unrelated weekly namespaces, is given up and declared (L7-D13).
- `Namespaces.remove(X_c)` when the contact is deleted and its ops are released; `P_c` is removed at the end of each establishment (§5.5).

### 5.2 Relay set of a DM namespace (normative; RP F11, G-4)

```
order(ns, w)  = the ES slots of week w sorted by HMAC-SHA256(key = ns, "ghost/v1/dm/slot-order" || u8(slot))      (no week in the HMAC, §21.1)
set(ns, w)    = the relays of the first slots in order(ns, w) until 3 are taken and they span >= 2 distinct operators
```

- Anyone who knows the namespace and the signed ES computes the set, so senders need no relay list in the card, and the set carries no information about the owner (a client choosing its own 3 of 32 slots would be a C(32, 3) = 4 960-way fingerprint across its namespaces, RP F11, E-15). Vectors `protocol/test-vectors/dm_relay_set.txt`, replayed by Kotlin (`:crypto-bridge`) and by the Rust T2 world.
- If week w offers fewer than 2 operators, `Outbox.enqueue` throws `InsufficientReplicasException` and the facade reports `NO_REPLICAS` (ADR-11 rule; rare by ES design).
- **Slot-table changes.** Writers (senders, the owner's bundle op) use `set(ns, week(now))`. The owner, as a reader, keeps `setRelays(ns, ⋃ set(ns, w′))` over the weeks `w′ ∈ [week(now) − 5, week(now)]` whose sets differ: a blob stored in week w′ may live until `w′ + 6` weeks (store ≤ compose + 7 d + 1 h, TTL ≤ 30 d + 1 h, §10.1). A relay that left the ES gets no new capability (`NO_SLOT`); the owner reads it with its still-valid READ key, and blobs there were also written to the other relays of that week's set. The `KEEPER` step recomputes the sets at each week change and calls `setRelays` only when they differ (Phase 7 repairs the deliveries, F7 §3.9).

### 5.3 Bundle format (normative; E-12)

```
bundle_plain = ver(1) = 0x01 || card_index(2) || bundle_week(8) || issued_hour(4) || registration_id(4) || device_id(4) = 1
             || identity_key(33) || signed_prekey_id(4) || signed_prekey(33) || signed_prekey_sig(64, XEdDSA)
             || kyber_prekey_id(4) || kyber_prekey(1569) || kyber_prekey_sig(64, XEdDSA)
             || identity_pk(32, Ed25519) || binding_sig(64, Ed25519 over "ghost/v1/dm-bundle" || all previous bytes)
             = 1 890 bytes      (issued_hour: u32 hours since the epoch, §21.7)
blob(4096)   = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, AD, 0x03 || bundle_plain || zeros)      (the §6.2 layout)
k            = HKDF-SHA256(ikm = KB_i, salt = salt, info = "ghost/v1/dm-seal" || P_i, L = 32)
hint         = HMAC-SHA256(KB_i, "ghost/v1/dm-hint" || salt)[0..16]
AD           = "ghost/v1/dm-seal" || 0x01 || P_i(32) || u32_be(4096)
```

The hint is useless for a single key but keeps one byte shape for every DM blob (T29). The Kyber key is 1 568 bytes plus its type byte, for both Kyber1024 and ML-KEM-1024 (RL §3), so the layout does not depend on Q21.

### 5.4 Publication, rotation and retention (normative; C-10, SC-6)

- **When.** At activation and restore, at once. Then once per ISO week w at `t_pub(w) = start(w) + (HMAC-SHA256(S_0, "ghost/v1/dm/pub-offset") mod 7 d)` floored to the minute (a fixed offset per card, so exactly 7 days apart), at the first actor wake at or after it (the `OWNER-WEEK` transaction, §7.2). A missed week publishes at the next wake. Nothing about contacts, fetches or messages enters the timing (T31, mutant PM-11).
- **What.** A new signed EC prekey and a new last-resort Kyber prekey (random 24-bit ids distinct from retained ones; day-floored record timestamps); the previous pair gets `superseded_day = today`; `bundle_week = w`; the blob is sealed and enqueued to `P_0` with `TtlBucket.DAYS_30` and deadline `start(w + 2)` (a bundle is useless after its validity); `dm_self.bundle_week = w`. Idempotent per week (guard `bundle_week < w`) and atomic. A FAILED or INDETERMINATE bundle op is re-sealed (new salt) and enqueued again at the next time-triggered pass while the week's validity lasts, tracked by `dm_self.bundle_published_week` (§21.8, §21.9).
- **Validity.** A bundle of week w is valid while `now < start(w + 2)` and `w ≤ week(now) + 1`. With weekly publication, a live owner always has a valid bundle; an owner offline for more than about two weeks has none, and new contacts cannot establish until it returns (declared, L7-D10).
- **Retention of superseded private prekeys: `delete_after_day = superseded_day + 91`.** Derivation:
  1. a fetcher can still pick generation g until its validity ends, at most 7 days after g was superseded;
  2. libsignal keeps sending PreKey messages on an unacknowledged session for up to 30 days (`MAX_UNACKNOWLEDGED_SESSION_AGE`) [U37];
  3. a message authored on the last such day is accepted by the recipient until `author + FRESH` = 45 days later (§7.6), and cannot be accepted after it;
  4. two clocks within σ = 3 d each add 6 days.

  7 + 30 + 45 + 6 = 88 days, rounded up to 13 weeks. After deletion (cascading to the reuse tuples) a later PreKey message fails with `InvalidKeyIdException` and is dropped (outside CS-3's bounds by construction). A device holds at most 14 generations (≈ 70 KB of records).
- **PQ-4.** The last-resort Kyber prekey rotates with the signed prekey; its reuse tuples live exactly as long as the key (§5.6).

### 5.5 Fetch (normative; T31; E-2)

- **When.** A bundle of contact c is fetched **only** (a) when the user sends to a contact with no session, (b) when the user asks to reset or reconnect (§8.6, §8.7), or (c) when a user send finds no usable session (`NoSessionException`, or libsignal's 30-day soft archive). Never on key change, restore, inbound traffic or a schedule.
- **Mechanism (superseded in part by §21.7: `Inbox.forgetConsumed`, candidates, `EST-READY`, at most three 15-minute attempts, trust and deadline pre-checks).** In the send transaction: the message row stays `queued` with a `dm_pending_send` row (`fail_after_hour = ceil_hour(min(author + 7 d, deadline))`); `Namespaces.register(P_c, PREKEYS, set(P_c, w), listen = true, LOCAL)`; `Capabilities.put(READ, credential_v3(read, P_c, w, RP_{c,w}))`; `dm_contact.establishment = fetching`, `fetch_until_day = today + 7`. The next list events of those pairs fetch every live bundle blob; the consumer opens each, keeps the newest valid one (below), builds the session with `SessionBuilder.process(bundle, floor_minute(now))` and encrypts and enqueues every pending send of c **in one transaction**; then `setListening(P_c, false)`, and `Namespaces.remove(P_c)` once no fetched row remains. If `fetch_until_day` passes without a valid bundle, `establishment = unreachable`, the pending sends fail, and the user may retry. A refused READ credential is re-put at most once per relay session start (§21.2).
- **Checks (all before any libsignal call).** The blob opens under `KB_c` with the hint; version; `card_index` = the card's; `identity_pk` = the card's; `binding_sig` verifies under it; validity (§5.4); `bundle_week ≥ dm_contact.bundle_week_seen` (no rollback; the newest valid bundle wins; relays cannot delete old ones and at most five are live). Then:
  - no pinned libsignal identity yet → GHOST pins `identity_key` (`dm_contact.pinned_identity`) in the same transaction, before `SessionBuilder.process` (so libsignal's `saveIdentity` then sees an equal key, §8.2);
  - `identity_key` = pinned → process;
  - `identity_key` ≠ pinned **with the binding valid under the pinned Ed25519 key** → **key change** (§8.3): no session is built, the contact goes to `changed` with `pending_identity = identity_key`, and after the user's decision the fetch runs again (E-2: §5.5 and §8.3 now agree);
  - binding invalid → the blob is dropped (counter `bad_binding`) and the next blob is tried.
  libsignal verifies both XEdDSA prekey signatures and refuses a bundle without a Kyber prekey [U34].
- **In HIGH mode** the fetch is the pair's next read event like any read; the deposit follows the HIGH send delay. The Phase 7 read schedule of other pairs is unaffected (T19 "adding or removing other pairs does not change a pair's schedule").
- **Relay-visible.** One listing of `P_c` with the week's shared read scope (all fetchers of that card look alike), then a deposit into `X_c` in the same or a later session. Under AD-1 this links `P_c` and `X_c` as one owner at establishment (declared L7-D6); a relay without the card learns nothing more.

### 5.6 One-time prekeys: none (normative; Q9)

- A blind store cannot hand a one-time prekey to exactly one fetcher: every fetcher sees all of them, two fetchers can pick the same one, and the second PreKey message fails, a message loss by construction (NFR-12). Replenishment writes would follow consumption, so the bundle namespace's write times would reveal the owner's new-contact rate (RP F15).
- PQXDH allows sessions without a one-time EC prekey [U25]; the Kyber prekey is mandatory and GHOST uses a **last-resort** one. libsignal then requires the `(kyber_prekey_id, signed_prekey_id, base_key)` reuse set (`KyberPreKeyStore.markKyberPreKeyUsed`, [U27]), persisted in `sig_kyber_reuse` in the same transaction as the session: a replayed first message is refused while the keys live and fails for lack of keys after they are erased.
- **Cost, declared (L7-D11).** The first flight of a session has no one-time-prekey forward secrecy: an attacker who records it and later obtains the recipient's identity key plus that generation's signed and Kyber prekey secrets **before their erasure** (≤ 13 weeks after supersession) can decrypt it. The ratchet heals from the second flight on.
- **Rejected alternative (C-7): HELLO.** Pushing a per-contact bundle with genuine one-time EC and Kyber prekeys inside a signed HELLO into the recipient's inbox removes fetch linkability and restores one-time-prekey forward secrecy, but requires an accept round trip before the adder can write, keeps no prekey namespace (plan row 9 names "publicare prekeys prin relay"), and ties the first message to the card owner's consent flow. Recorded in ADR-30 for Phase 13 reconsideration with the contact backup.

### 5.7 Attestation (ADR-14 P1): deferred, never relay-readable (Q10)

Not in Phase 9, for three reasons:
1. The identity keys are seed-derived (FR-1.2, ADR-17, C-1); Android Key Attestation covers Keystore-generated keys only, so no chain could attest the key contacts see (RS K14).
2. The chain carries OS, patch level and model family (against ADR-08 "fără model/OS în mesajele de protocol"), and with Remote Key Provisioning the certificates are per device: a cross-context identifier (RP F12).
3. Its size would put some users' bundles in a different bucket (T29).

If ever shipped (Phase 13 or later): a Keystore-generated device key signed by the identity, its chain sent inside the E2E session, opt-in, with a UI line on what it reveals. ADR-30 records the deviation (X-6).

---

## 6. The DM envelope: sealed sender without a server (I2, I4; T9; ADR-31)

### 6.1 Why an outer seal, and which (the I2 decision; C-2, E-3)

A libsignal `SignalMessage` shows its version byte, ratchet public key, counters and SPQR field in clear; a `PreKeySignalMessage` adds the sender's identity key, base key, prekey ids, registration id and a 1 568-byte Kyber ciphertext (`protocol.rs:67-395` [U33]). Stored as is, it is a sender field (T1), a per-session linkable identifier and a type marker (T9). An outer seal is mandatory (RL §4, RE §0 item 1).

| Option | Relay sees | Recipient authenticates the sender by | Assessment |
|---|---|---|---|
| A. libsignal sealed sender v1 with self-issued `ServerCertificate`/`SenderCertificate` and an overriding `CertificateValidator` | version byte 0x11, a raw X25519 key, variable length, no padding: a GHOST layer is needed outside it anyway | a certificate whose validity comes entirely from GHOST's override | **Rejected.** A fictional PKI; dependence on certificate semantics Signal can change (hard-coded `KNOWN_SERVER_CERTIFICATES` ids, UUID/E164/self-send checks); a `SenderKeyStore` stub; sealed to the long-term identity key (no key separation, no attribution forward secrecy); a wider audited API |
| B. GHOST seal around plain libsignal messages | uniform bytes of one bucket | the pair key (pair mode) or the card and binding signature (intro mode), then libsignal's own MAC over both identity keys | **Chosen**, in the two-mode form below |
| C. sealed sender v2 multi-recipient | recipient service ids, device ids and registration ids **in clear** [U22] | as A | **Rejected**: the recipient set, a social graph, on the relay |
| B′. per-message ephemeral X25519 with Elligator 2 to one inbox key (operations) | uniform only with a correct Elligator 2 encoding | the card in the slot, then libsignal | **Rejected.** The candidate crate is `curve25519-elligator2` 0.1.0-alpha.2 (2024-07-26), a BSD-3-Clause fork of `curve25519-dalek` beside the locked 4.1.3 (`ghost/Cargo.lock:772-774`), unaudited and pre-release; the recipe omitted the random low-order component, so representatives of prime-order-subgroup keys stay distinguishable (the "dirty key" step of Monocypher and obfs4); and one long-term inbox key opens every past envelope, so a seed plus AD-1's archive attributes the whole relay history |
| B″. raw X25519 key with a random top bit (delivery) | a valid curve point in the first 32 bytes (about half of all strings are not) | as B′ | **Rejected**: T9 "indistinguishable from random" declared unmet |

**Decision.** *Pair mode* is a per-pair symmetric seal whose key is ratcheted weekly from a **root generated by the recipient** (attribution forward secrecy, P-7). *Intro mode* covers every moment without a pair key: a symmetric outer layer keyed by the recipient's card (uniform bytes without curve work) and an inner X25519 layer to the recipient's intro key, so other card holders cannot read it. Both modes present the same `salt ‖ hint ‖ AEAD` shape, built from HKDF-SHA256, HMAC-SHA256, X25519 and ChaCha20-Poly1305 only (BouncyCastle, already approved by ADR-17 and widened by ADR-24; CP-09 exception recorded in ADR-31).

### 6.2 L2 layout (normative)

```
blob(B)  = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, AD, P)        |P| = B − 48,  B ∈ {4096, 16384, 65536}
hint     = HMAC-SHA256(K_sel, "ghost/v1/dm-hint" || salt)[0..16]
k        = HKDF-SHA256(ikm = K_sel, salt = salt, info = "ghost/v1/dm-seal" || namespace(32), L = 32)
AD       = "ghost/v1/dm-seal" || 0x01 || namespace(32) || u32_be(B)                   (not transmitted)
K_sel    = a pair week key (pair mode) | KIO_i of the recipient's card (intro mode) | KB_i (bundle, §5.3)
P        = mode(1) ∈ {0x01 pair, 0x02 intro, 0x03 bundle} || mode-specific body || zeros
```

- **R-S1 (T9).** `|blob| = B` exactly; every length is inside P; the bytes are uniform under the PRF security of HMAC-SHA256 and the IND$-CPA security of ChaCha20-Poly1305 (salt random, hint a PRF output, key fresh per salt).
- **R-S2 (canonical).** A blob is accepted only if it opens and parses exactly: a known mode and kind byte, every length within P, **all padding bytes zero**. Otherwise it is consumed and dropped (a counter, no content). Padding cannot carry a covert channel; the format is not malleable.
- **R-S3 (binding).** AD and k bind the namespace and the bucket: a relay that copies the blob into another namespace (one relay store can hold one ciphertext under several namespaces, `relay/crates/storage/src/lib.rs:6-12`) or truncates it produces something that does not open.
- **R-S4 (nonce).** k is fresh per salt; nonce 0 never repeats under one key (a 16-byte salt repeats with probability ≈ n²/2¹²⁹).
- **R-S5 (one attempt, no oracle; E-13).** The recipient computes the hints of its candidate keys and opens with **at most one** key, the one whose hint matches. There is no trial decryption across keys, so the partitioning-oracle attack on the non-committing AEAD (Len, Grubbs, Ristenpart, USENIX Security 2021) does not apply. A hint match whose AEAD fails is a forgery: dropped, counted. **Candidate keys:** for each contact with pair keys, the stored in-week keys of every live root generation for the weeks `w` with `now < start(w + 1) + FRESH` (at most 8) plus `K_{week(now)+1}` computed on demand (sender clock ahead), so **at most 9 per contact per live root generation**, plus `KIO_0` of the own card. At `MAX_CONTACTS = 1 000` with one generation each this is **≤ 9 001 HMAC-SHA256 evaluations per blob**. Hints are computed lazily, the most recent week first, contacts in an in-memory most-recently-matched order (never persisted), stopping at the first match; a forged or unknown blob costs the full set. S7 measures a 16-blob batch at 1 000 contacts on the reference mid-range device against a 1 s foreground budget; if it misses, `MAX_CONTACTS` is lowered (Q37). A card holder flooding forged blobs spends its own deposits' allowance and the victim's CPU, bounded by `FETCHED_CAP` and the consumer budgets (L7-D8).

### 6.3 Pair mode (normative; SC-4)

```
P = 0x01 (pair) || kind(1) ∈ {0x01 SignalMessage, 0x02 PreKeySignalMessage} || l1_len(4, BE) || L1 || zeros
```

- **Roots.** For each contact c, **I as the recipient** generate `root_{c→me}` (32 B, CSPRNG), a base week `b = week(now)` and a generation number `root_gen` (previous + 1, starting at 0), store them in `dm_pair_offer`, and send `(root, b, root_gen)` to c inside the E2E content of my user-initiated messages to c whose libsignal output is a `SignalMessage` (L0 TLV `seal_root`, §7.1; never in a PreKey message, §21.3) until a pair-mode envelope from c opens under a key of that generation. A root is never derived from a seed, so no seed compromise recovers it.
- **Week keys.** `K_b = HKDF-SHA256(root, "ghost/v1/dm/pair-epoch" ‖ u64_be(b))`; `K_{w+1} = HKDF-SHA256(K_w, "ghost/v1/dm/pair-next")`.
  - **Sender c** (who received my root) keeps only `K_{week(now)}` of the newest generation, ratchets forward at each week boundary and erases the previous key; it erases the root as soon as `K_b` is computed.
  - **Recipient (me)** keeps, per live generation, `K_w` for every week w with `now < start(w + 1) + FRESH` (FRESH = 45 d, §7.6) up to `week(now)`, computes `K_{week(now)+1}` on demand, and erases each `K_w` in the first sweep at or after `start(w + 1) + FRESH` (by the expiry clock, §10.3), after deriving the keys up to `week(now)` in the same sweep (§21.3). No legitimate blob sealed under `K_w` can be accepted after that instant: its author minute is before `start(w + 1)` by the sender's clock, and content older than FRESH is refused. My offered root stays in `dm_pair_offer` only so that later messages can carry it again: it is erased when a pair envelope under its generation opens (acknowledged) or at `start(b + 1) + FRESH`, whichever comes first (a new root is then offered on my next user message); the week keys already computed follow the window rule, and opening never needs the root. A generation stops advancing (no new week keys) once a pair envelope under a newer generation from c opens.
- **Mode rule (sender).** Pair mode iff I hold an out key for c of `week(author_minute)` **and** the libsignal output is a `SignalMessage` (my session with c is acknowledged). Otherwise intro mode. First messages, messages after a reset or reconnect, and every message of an unanswered session are intro; everything else is pair.
- **Replacement.** I offer a new root (a) after my restore, to every contact I reconnect (§8.6); (b) after I acknowledge or verify a key change of c (§8.3); (c) when `week(now) ≥ base_week + 13` for my newest root for c, to bound a stolen-state window. The new root rides on my next user message to c.
- **P-7 (attribution forward secrecy).** An attacker who later seizes both devices and both seeds, and holds AD-1's archive of all blobs, cannot tell which pair-mode envelopes of a week w with `now ≥ start(w + 1) + 45 d` belong to which conversation: the keys are erased, not derivable, and the envelopes are uniform (the skipped-key exception of §21.3 point 6 is declared). Content was already protected by libsignal; this protects the **who-talked-to-whom-when history** of expired messages, which T25 alone does not.

### 6.4 Intro mode (normative)

```
P       = 0x02 (intro) || e_pub(32) || ChaCha20-Poly1305(k2, 0^12, AD2, Q)          |Q| = B − 97
k2      = HKDF-SHA256(ikm = X25519(e, Y_i), salt = e_pub || Y_i, info = "ghost/v1/dm-intro-inner" || namespace, L = 32)
          (refuse an all-zero shared secret)
AD2     = "ghost/v1/dm-intro" || 0x01 || namespace(32) || u32_be(B)
Q       = kind(1) || sender_card(163) || binding_minute(4) || binding_sig(64) || l1_len(4, BE) || L1 || zeros      (binding v2, §21.4)
K_sel   = KIO_i of the recipient's card (outer layer, §6.2)
```

- The outer layer (`KIO_i`, known to every holder of the recipient's card) makes the bytes uniform and selects the key by hint; the inner layer (a fresh ephemeral X25519 key to the recipient's intro key) keeps other card holders from reading the content, in particular a PreKey message's identity key of *another* contact (which would hand contacts part of the recipient's social graph). `e_pub` travels inside the outer AEAD, so its non-uniformity is invisible.
- `sender_card` is the sender's full card (the recipient needs `card_secret` to reply and to rebuild a contact after a restore); `binding_sig` binds the sender's libsignal identity key to its Ed25519 key (§3.4). For a `SignalMessage` in intro mode, the identity key is the pinned one and the binding is still checked; one from an unknown identity is handled by §21.4 point 3.
- **Residue (declared, L7-D3).** A holder of my card colluding with a relay can recognise intro envelopes in my inbox (it can compute `KIO`'s hints) though not read them: it learns the rate of my first contacts, resets and reconnects. Pair envelopes are unrecognisable to it. Intro envelopes are attributable by anyone who later holds my seed (the intro key is seed-derived) together with AD-1's archive: first contacts are not covered by P-7. The inner layer is X25519, not post-quantum (§9.3).

### 6.5 Recipient procedure (normative; runs inside the `RECV` transaction, §7.4)

1. `|blob| ∈ {4096, 16384, 65536}`, else drop.
2. Compute candidate hints (R-S5); no match → drop (counter `unknown_seal`). A match with a pair key of contact c → open; the mode byte must be 0x01. A match with `KIO_0` → open the outer layer; mode 0x02; open the inner layer with `y_0`.
3. Canonical parse (R-S2).
4. Intro: parse and verify `sender_card` (§3.3), `binding_sig` v2 and the freshness of `binding_minute` (§21.4); look the contact up by `identity_pk`.
5. Continue with identification and the identity pre-check of §7.4 (R5, R6).

### 6.6 Sizes, `O_MAX` and bucket choice (normative)

| Component | Bytes (worst case) | Source |
|---|---|---|
| L2 outer (salt, hint, tag) | 48 | §6.2 |
| intro extra (mode, `e_pub`, inner tag, card, binding minute, binding, kind, length) | 1 + 32 + 16 + 163 + 4 + 64 + 1 + 4 = 285 | §6.4, §21.4 |
| L1 PreKey extra (version, ids, Kyber ciphertext 1 568 + framing, base key, identity key, inner header) | ≤ 1 671 | RE §9.1 |
| L1 `SignalMessage` (version, ratchet key, counters, CBC padding ≤ 16, MAC 8) | ≤ 81 | RE §9.1 |
| SPQR `pq_ratchet` field | ≤ 128 (estimate; **measured in S0**) | [U33], [U38] |
| sum | ≈ 2 213 | |
| **`O_MAX` (provisional)** | **2 560** | frozen by a test in S0 |

- **R-B1 (as corrected by §21.11).** `B = min{ b ∈ {4096, 16384, 65536} : L_class ≤ b − O_MAX }` with `L_class = 52 + |body| + EXT_RESERVE (160)`, computed **before** encryption, so pending TLVs and quotes never change the bucket. After sealing, the fit is asserted; a failure is a bug (`IllegalStateException`) and rolls the transaction back before the ratchet state commits.
- **R-B2 (floor, T29).** DMs never use 1 KiB. A PreKey message cannot fit 1 KiB (the Kyber ciphertext alone is 1 568 B), and libsignal sends PreKey messages until the peer answers (`session_cipher_legacy.rs:86-137`); a 1 KiB class for established sessions would mark first contact, reset, reconnect and key change (RP F4). With R-B1, PreKey vs normal, intro vs pair, text vs control of equal content length land in one bucket.
- **Capacities** (with `O_MAX = 2 560`, §21.11): body ≤ 1 324 B at 4 KiB; ≤ 13 612 B at 16 KiB; ≤ 62 764 B at 64 KiB. API cap `MAX_BODY_BYTES = 61 440`; longer content waits for Phase 11 media. One L0 per blob, no DM fragmentation.
- **Golden sizes (S0 and every bump).** Encrypt PreKey and normal messages, both modes, at every content length in `[C(B) − 64, C(B)]` for each bucket, with both KEM types if exposed; assert the fit and record the measured maximum overhead against `O_MAX`.

---

## 7. Content, transactions, pipelines, dedup, ordering and replay (I4; T13; ADR-31, ADR-33)

### 7.1 L0 content `DmContent` v1 (normative)

Canonical binary, big-endian, fixed order, one encoding per value (RE §4).

| Field | Size | Meaning |
|---|---|---|
| `version` | 1 | 0x01 |
| `kind` | 1 | 0x01 TEXT; 0x02 TIMER_SET; 0x03 REACTION (rows in Phase 9, UI in Phase 13); 0x04 CONTROL (no body; TLVs only); 0x05 MEDIA (reserved for Phase 11, refused in Phase 9). **No DELIVERY or RECEIPT kind** (D10) |
| `message_id` | 16 | CSPRNG; the end-to-end idempotency key; never relay-visible |
| `author_minute` | 4 | u32 minutes since the Unix epoch at compose: seconds are zero by type (T13) |
| `minute_index` | 2 | order of the sender's own messages within `author_minute` (§7.7) |
| `timer_code` | 1 | 0 off, 1 = 5 min, 2 = 1 h, 3 = 1 d, 4 = 7 d, 5 = 30 d (ADR-27 C.7): this message's own timer |
| `timer_version` | 4 | the sender's conversation timer version (§10.5) |
| `flags` | 1 | bit 0 `has_quote`; other bits 0 |
| `quote_ref` | 0 or 16 | `message_id` of the quoted message; never copied text |
| `body_len`, `body` | 4 + n | TEXT: UTF-8 (strict), n ≤ 61 440; TIMER_SET, CONTROL: n = 0; REACTION: target `message_id`(16) ‖ one grapheme (≤ 32 B; empty = remove) |
| `ext_len`, `ext` | 2 + m | TLVs `type(u16) ‖ len(u16) ‖ value`, strictly ascending type, each at most once; bit 15 of type = critical |

TLV registry (Phase 9):

| Type | Name | Value | Rule |
|---|---|---|---|
| 0x0001 | `seal_root` | `root(32) ‖ base_week(8) ‖ root_gen(2)` | the root the sender of this L0 wants the recipient to use for recipient → sender pair envelopes (§6.3); accepted only inside a libsignal-authenticated L0 carried by a `SignalMessage`; a `root_gen` not greater than the stored out generation is ignored, and a session renewal clears that generation (§21.3) |
| 0x0002 | `card_update` | reserved (Phase 13 cut-off rotation) | non-critical; ignored in Phase 9 |
| 0x0003 | `revocation` | revocation certificate v2 (102 B, §8.5) | verified under the pinned `identity_pk` |
| 0x0004 | `session_reset` | empty | the reconnect notice (§8.6); a content-free contact event, no message row |
| 0x0010 | `read_upto` | reserved for Phase 13 opt-in read receipts (Q8) | non-critical; ignored in Phase 9 |
| 0x0100–0x01FF | media descriptors | Phase 11 | non-critical; ignored |

- **R-C1 (T13).** Author time exists only as `author_minute`. It is the compose minute, before any HIGH send delay (the delay applies to the store only; plan §2.3 declares author minutes visible to recipients).
- **R-C2.** No field names the sender or the recipient; the seal and the session identify the sender (§6.5).
- **R-C3 (no reflex content).** TLVs 0x0001, 0x0003 and 0x0004 are attached **only to user-initiated sends**: the next TEXT, TIMER_SET or REACTION to that contact whose libsignal output is a `SignalMessage` carries a pending `seal_root` (§21.3); an explicit user action (reconnect, notify contacts of a revocation) enqueues a CONTROL message. No inbound blob ever causes a CONTROL message (T28).
- **Timestamps (T13, normative summary).** Every time a DM carries or stores is minute-granular or coarser: `author_minute` is a u32 count of minutes (seconds zero by type); the revocation certificate v2 carries `issued_minute`; libsignal calls receive `floor_minute(now)` and generated prekey records `floor_day(now)` (§2.3); `bundle_week` and credential weeks are ISO-week indices; local columns are `*_minute`, `*_hour` or `*_day` with `typeof` CHECKs (§13.6); the relay sees only its own minute `time_bucket`. No DM byte carries seconds or milliseconds. T13 becomes executable in Phase 9 (§14.2): `dm_content.txt` vectors, a property test on stored `author_minute`/`sort_minute`, the record-timestamp decode test, and mutant ME-5.
- **R-C4 (limits and strictness).** `|L0| ≤ 65 536 − O_MAX`; `ext_len ≤ 1 024`; an over-read, a trailing byte, a non-ascending TLV list, an unknown critical TLV, invalid UTF-8 or a non-zero reserved bit refuses the whole L0. Vectors `protocol/test-vectors/dm_content.txt`; seeded decoder property tests (10⁶ inputs per CI run: never throws untyped, never over-reads).

### 7.2 Transaction inventory (normative; G-1)

Every DM state change is exactly one `SyncDatabase.transaction` run by the DM actor (§13.7). Nothing outside this table writes DM state. §21.7, §21.8 and §21.12 add `EST-READY`, `OVERSIZE` and the orphan-namespace step; §21.9 restricts which triggers may run which transaction.

| Tx | Trigger | Writes (all through `tx.sql`) | After commit |
|---|---|---|---|
| **SEND** | user: `send`, `react`, `setTimer`; scheduled CONTROL due (reconnect, revocation notice) | ratchet (session), `dm_outbound_item` (every kind, §21.8), `dm_message` (out; TEXT and TIMER_SET only), `dm_outbound_op` (+ retained blob), `Outbox.enqueue`; or `dm_pending_send` plus `EST-START` effects when no session exists | `requestExpedite()` in STANDARD |
| **RESEND** | automatic for INDETERMINATE (identical bytes, §7.5); user `retry` for FAILED (re-encrypt the same L0) | new op; the same blob, or a new ratchet step over the same L0 | as SEND |
| **RECV** | `SyncChange.INBOX`, consumer tail | `markConsumed`; ratchet or held row; `sig_kyber_reuse`; `dm_seen`; message, reaction, contact, request or pair-key effects | notification count |
| **BUNDLE** | `Inbox.claim(PREKEYS)` during establishment | `markConsumed`; the best verified candidate kept in `dm_bundle_candidate`; key-change classification (§21.7) | — |
| **EST-READY** | time-triggered: the first candidate + 2 min, or the attempt window's end with a usable session (§21.7) | pin; `SessionBuilder.process`; encrypt and enqueue pending items; `establishment = ready`; `setListening(P_c, false)` | `requestExpedite()` in STANDARD |
| **EST-START** | first send without a session, `resetSession`, reconnect due | `Namespaces.register(P_c, …, LOCAL)`, read credential, `establishment = fetching`, `fetch_until_day` | — |
| **EST-END** | time-triggered: an attempt window ends without a candidate or a usable session (§21.7) | `setListening(P_c, false)`; the next attempt (≤ 3) or `establishment = unreachable` and pending items failed; `Namespaces.remove(P_c)` once no fetched row remains | — |
| **OUTCOME** | `SyncChange.OUTCOMES`, consumer tail | `Outbox.release`, message state, retained blob dropped, RESEND decision | — |
| **KEYDEC** | user: `acknowledgeKeyChange`, `verifyKeyChange`, `block` of a changed contact | trust state, pinned and pending identity, held rows (deleted on block), pair keys and offers | HELD posted |
| **HELD** | after KEYDEC accepted | per held row: the RECV steps R7–R12 on the stored L1, then delete the row | notification count |
| **DISPLAY** | user: `markDisplayed(ids)` | `expire_at_minute`, `delete_at_minute`, state `read` | timer and alarm rescheduled |
| **OWNER-WEEK** | first wake at or after `t_pub(w)`; activation | prekey records, `superseded_day`, `dm_self.bundle_week`, bundle op | — |
| **ACTIVATE** | `:entitlement` hook: activation (trial, genesis) or restore | `dm_self`, own namespaces, first prekeys and bundle, `accept_after_minute` on restore | — |
| **KEEPER** | session start, week change, `CAPABILITIES` hint (maintenance only, §21.9) | own READ credential; contacts' deposit and bundle read credentials per relay slot, refreshed before expiry, a refused one re-put at most once per session start (§21.2); `setRelays` on slot changes | — |
| **REGROWS** | session start, week change, `CAPABILITIES` hint, a rejected own READ credential | `relay_key_registration` rows (insert missing, return `done` to pending per the healing rule, delete stale) | — |
| **SWEEP** | in-process timer, alarm, database open, consumer tail, foreground start | expired messages (cascades), held rows, requests, pending sends, `dm_seen`, superseded prekeys, pair keys past their window, `expiry_clock_minute` | `checkpointTruncate()`, notification count |

Every transaction is idempotent against re-execution after a crash: guards on expected state (OWNER-WEEK per week, ACTIVATE per identity, KEEPER puts only a differing token, REGROWS inserts only missing rows, SWEEP deletes by time).

### 7.3 `SEND` (normative)

```
send(contact c, content):                                    [DM actor; one SyncDatabase.transaction]
tx {
  S1  guard: c.trust ∈ {unverified, verified}; else KEY_CHANGED | BLOCKED | REVOKED | REQUEST_NOT_ACCEPTED
      (before any libsignal call; the identity store would refuse anyway, §8.2); crypto not loaded → CRYPTO_UNAVAILABLE
  S2  conv = dm_conversation(c); timer = the conversation timer (the new timer for TIMER_SET)
      L0 = encode(message_id = random16, author_minute = floor_minute(now), minute_index (§7.7), timer, TLVs per R-C3)
      |body| > MAX_BODY_BYTES → TOO_LARGE;  B = bucketFor(L_class = 52 + |body| + EXT_RESERVE)            (R-B1, §21.11)
  S3  insert dm_message(out, 'queued', body_env = AEAD(content_key, flags ‖ quote_ref? ‖ body, AD = message_id),   (TEXT, TIMER_SET; §21.8)
                        expire_at_minute = timer ≠ off ? ceil_minute(commit_now + timer) : NULL)            (§10.3)
      insert dm_outbound_item(message_id, c, kind, l0_env, deadline_hour, 'pending')                 (every kind; §21.8)
  S4  if c has no usable session: insert dm_pending_send(item_id, c, fail_after_hour); EST-START effects (§5.5, §21.7); return QUEUED
  S5  l1 = SessionCipher(TxSignalStores(tx), c).encrypt(L0, floor_minute(now))                          (ratchet advances in tx)
  S6  mode = (out key of c for week(author_minute) exists AND l1 is a SignalMessage) ? pair : intro      (§6.3)
      blob = seal(mode, X_c, B, l1)                                                  (fit asserted, else throw → rollback)
  S7  ensure Namespaces.register(X_c, DM, set(X_c, week), listen = false, LOCAL) and a deposit credential (KEEPER rule)
  S8  op = random16; insert dm_outbound_op(op, purpose = item, item_id, blob, deadline_hour); item state 'enqueued'   (§21.8)
      Outbox.enqueue(OutboundBlob(op, X_c, blob, ttl = ttlFor(conv, kind) (§10.1 R-T2, R-T3),
                                  deadlineEpochSeconds = author + min(bucket, 7 d)))                (§10.1)
}
after commit: SyncController.requestExpedite()                       (STANDARD only; a no-op in HIGH; no read event, T19)
```

| Exception inside SEND | Effect (the whole transaction rolls back first) | Facade result |
|---|---|---|
| `InsufficientReplicasException` | nothing sent, no ratchet step | `NO_REPLICAS` |
| `UntrustedIdentityException` (SENDING) | nothing (defence behind S1) | `KEY_CHANGED` |
| `NoSessionException` (no session, or soft-archived after 30 days unacknowledged) | a separate EST-START transaction keeps the message as a pending send; caused by the user's send, not by inbound traffic | `QUEUED` (re-establishing) |
| `StorageFullException` (the `:storage` executors' typed mapping of `SQLITE_FULL`) | nothing | `STORAGE_FULL` |
| R-B1 fit failure (`IllegalStateException`) | a bug: `O_MAX` too small | propagates (never caught) |
| anything else | propagates (`sync-no-catch-all.sh`) | crash |

**Why SEND is safe (CS-1).** libsignal state is loaded inside the transaction and written back through `tx.sql`; no protocol object survives the transaction (§2.4). The ciphertext leaves the device only through the outbox, which sees it only after commit. A crash before commit leaves no ratchet step, row or op; after commit, an op the engine sends. A message key is used only inside a transaction that either commits the op or leaves no trace.

### 7.4 `RECV` (normative; one transaction per blob)

`Inbox.claim(Consumer.DM, 16)` runs its own short transaction (Inbox contract); then, per blob:

```
tx {
  R1  if !Inbox.markConsumed(ns, hash): continue                                            (exactly once)
  R2  if blob.offers ≥ 4: counter poison; return        (three earlier offers died unconsumed: consumed unprocessed, no crash loop; G-1)
  R3  ns must be an own inbox (dm_own_namespace) else drop(foreign_ns)
  R4  open per §6.5 steps 1–3 (hint → at most one AEAD; canonical parse) else drop(counter)
      pair mode: week(author_minute) must later equal the key's week (R9); pair mode with a PreKey L1 → drop(non_canonical)
  R5  identify: pair → the contact of the matched key;
      intro → verify card + binding v2 and its freshness, before any state change (§21.4); contact = dm_contact by identity_pk:
        unknown → request path (§12.3): insert dm_contact('request', card, request_until_day) if < 64 requests, else drop(request_overflow)
        blocked or revoked → drop(blocked)
  R6  identity pre-check (§8.3), before any libsignal call, for a PreKey L1 (K′ = PreKeySignalMessage(l1).identityKey):
        pinned NULL          → binding valid (intro) → pin K′                          (first contact from their side)
        K′ = pinned          → continue
        K′ ≠ pinned, trust = 'request'                      → drop(request_key_mismatch); no state change   (§21.4)
        K′ ≠ pinned, binding valid under pinned identity_pk → HOLD: dm_held + trust 'changed', pending = K′; return
        K′ ≠ pinned, binding invalid                       → drop(bad_binding); no state change            (E-1)
      trust = 'changed': a PreKey L1 under pending → hold; a SignalMessage continues under the pinned session
  R7  content = DmSessions.decrypt(tx, c, l1) (SessionCipher.decrypt(l1), no Instant; §21.6), typed results only:
        DuplicateMessage → drop(duplicate)
        NoSession | InvalidKeyId → contact.reset_needed = 1; drop(no_session)       (a request row is kept, §8.6)
        reuse refusal of the Kyber tuple → drop(replay)
        InvalidMessage | InvalidKey | InvalidVersion | LegacyMessage → drop(undecryptable)
        UntrustedIdentity (unreachable after R6) → drop(untrusted); never a hold             (E-1)
  R8  L0 = decode(content), canonical, else drop(bad_content)             (the ratchet advance commits anyway: the key was used)
  R9  freshness (§7.6): author_minute ≥ now − FRESH(bucket(timer_code)) (§21.10); author_minute ≤ now + 2σ; author_minute ≥ dm_self.accept_after_minute;
      pair mode: week(author_minute) = the opening key's week                                          else drop(stale)
  R10 tag = HMAC-SHA256(seen_key, contact_id ‖ message_id)[0..16];  INSERT OR IGNORE dm_seen(tag, until_day)
      an existing row → drop(duplicate)
  R11 apply (§7.4.1) and TLVs: seal_root → out key (§6.3); revocation (§8.5); session_reset (§8.6)
  R12 pair mode: a pair envelope under my offered root_gen → that generation is acknowledged (§6.3)
}
after commit: NotificationPort.onUnreadChanged(count)                        (a constant text, no sender, §10.7)
```

- **R-P1 (commit together).** `markConsumed`, libsignal store writes, the Kyber reuse tuple, `dm_seen`, message rows, pair-key and contact changes commit in one transaction (spec §7.2(b)). A crash anywhere re-offers the blob against rolled-back state, so a second attempt decrypts the same way.
- **R-P2 (drop is final and silent).** A `drop` is `markConsumed` plus one in-memory counter increment (`MessagingStatus`, counts only, no persisted rejection history, T33) and nothing else: no outbound blob, redeem, registration, read-schedule change or `Inbox.defer` (T28). The only kept data are a hold (§8.3) and a request (§12.3), both bounded.
- **R-P2b (a request row lives only with its message).** A request row inserted at R5 is deleted again in the same transaction when a later step drops the blob, except for the R7 `NoSession`/`InvalidKeyId` case, which keeps it with `reset_needed = 1` (§8.6). A forged or undecryptable intro envelope therefore leaves no contact behind; §21.4 point 3 keeps a request only under a fresh, envelope-bound binding.
- **R-P3 (bounded work).** One transaction handles one blob; hint work is bounded by R-S5; `claim` batches of 16.
- **T28 (static half).** No branch of RECV, BUNDLE or HELD calls `Outbox.enqueue`, `Registrations.request`, `Capabilities.put` or `Namespaces.register` (pending sends are flushed by the time-triggered `EST-READY`, §21.7); `NoReflexTest` walks the call graph (gate G-DM2), and twin NI-DM1 checks the behaviour.

#### 7.4.1 Applying content

| Kind | Effect |
|---|---|
| TEXT | insert `dm_message(in, 'unread', sort_minute = min(author_minute, floor_minute(now)), unread_deadline_minute = timer ≠ off ? ceil_minute(min(relayExpiryHour, consume + bucket(timer) + 1 h)) : NULL)` (§10.3) |
| TIMER_SET | the timer-version rule (§10.5); an informational row `kind = TIMER_SET` with no body, subject to its own timer (ADR-27 C.8: shown to both sides) |
| REACTION | if the target exists and is not expired: insert or update `dm_reaction(target_id, from_self = 0)` (empty grapheme = delete); otherwise ignore |
| CONTROL | TLVs only; no row |
| any | `timer_version > conversation.timer_version` → adopt (§10.5) |

### 7.5 `OUTCOME` and `RESEND` (normative; G-7, C-15)

```
for o in Outbox.outcomes(DM, 64) + Outbox.outcomes(PREKEYS, 16): tx {
  if !Outbox.release(o.operationId): continue                                               (once)
  op = dm_outbound_op(o.operationId) ?: continue                        (the message expired and was swept meanwhile)
  when (o.outcome) {
    SENT, DEGRADED → message state sent | degraded; op.blob = NULL
    INDETERMINATE  → if op.resend_count < 2 AND o.resendNotAfterEpochSeconds ≠ null AND now < resendNotAfter AND now < op.deadline_hour
                         RESEND: new op id, the identical retained blob, resend_count + 1   (Phase 7 accepts identical bytes after release)
                     else message state indeterminate; op.blob = NULL
    FAILED         → bundle op: re-seal at the next time-triggered OWNER-WEEK pass while the week's validity lasts (§21.8)
                     message op: state failed; op.blob = NULL
  }
}
```

| Outcome (F7 contract) | Messaging rule | Why |
|---|---|---|
| SENT | `sent`; blob dropped | a quorum of operators verified it |
| DEGRADED | `degraded`; blob dropped; **never resent** | a copy exists; another would only be a duplicate |
| INDETERMINATE | automatic resend of the **identical blob** as a new op, at most twice, only while `now < resendNotAfter` and before the op's deadline; then `indeterminate` ("may not have been delivered") | the F7 contract (F7:1414-1416); identical bytes dedup at D1; caused by the user's own send, not by inbound traffic (T28) |
| FAILED | `failed`; the user may `retry`, which **re-encrypts the same L0** (same `message_id`, author minute, minute index, timer fields) under the next ratchet step as a new op, while `now` is before the original deadline (else `DEADLINE_PASSED`) | no copy ever existed, so re-encrypting is safe; D3 makes a wrongly decided FAILED harmless |

- **Retained blob.** Phase 7 wipes an op's payload when the outcome is decided (rule W, F7 §3.5), so the identical resend needs messaging's copy in `dm_outbound_op.blob`. It is E2E ciphertext no key on the sender's device opens; it is dropped at the terminal outcome and cascades with the message row at expiry (T25; L7-D7).
- **Short TTLs.** For the 1 h and 1 d buckets `resendNotAfter` is already past (§10.4), so an INDETERMINATE ephemeral message ends `indeterminate` at once; stated and correct.
- An `indeterminate` message is terminal: it has no user retry in Phase 9 (the F7 contract allows only identical bytes, which the window no longer admits). Phase 13 offers "send again" as a new message.

### 7.6 Dedup and replay: four layers, two structural bindings, freshness (normative; C-9, SC-3)

| Layer | Key | Catches | Lifetime |
|---|---|---|---|
| D0 outbox | `operation_id` (local) | repeated enqueue (`AlreadyEnqueued`) | Phase 7 |
| D1 blob | `(namespace, blob_hash)` | re-listing, several relays, identical resend | Phase 7 tombstone `ceil7(day(E) + 24)` |
| D2 ratchet | libsignal counters; Kyber reuse tuples (`sig_kyber_reuse`, in the RECV transaction, §5.6) | a second decryption within live chains; a replayed first flight while the prekeys live | libsignal (5 receiver chains, 40 archived states); tuples until the Kyber key is erased |
| D3 content | `HMAC-SHA256(seen_key, contact_id ‖ message_id)[0..16]` | the same logical message under different bytes: re-encryption after a wrong FAILED, replay after session loss or reset, resurrection after D1 expired | `until_day = ceil7(day(author_minute) + ceil_days(FRESH(bucket)) + 1)` (§21.10) |
| B1 binding | AD binds namespace and bucket (R-S3); pair mode: `week(author_minute)` = the key's week (R9) | a blob copied into another namespace; an old L0 re-sealed under a later week key | structural |
| B2 erasure | pair week keys erased at `start(w + 1) + FRESH` (§6.3); prekeys at `superseded + 91 d` (§5.4) | a pair-mode replay beyond its key window cannot be opened; an intro replay opens but is refused at R5, before any state change, once older than FRESH (§21.4) | structural |

**FRESH = 45 days (normative derivation).** Let σ = 3 d, the Phase 7 per-device clock tolerance.
1. A DM op's deadline is `author + min(bucket, 7 d)` (§10.1), and Phase 7 stores it as `deadline_hour = max(ceil_hour(deadline), floor_hour(not_before) + 1 h)` (`OutboxStore.kt:179-182`) with `not_before ≤ compose + 10 min`: every store happens before `author + 7 d + 1 h`.
2. An honest relay expires the blob at `ceil_hour(store + TTL) ≤ author + 7 d + 1 h + 30 d + 1 h`; a fetch happens before expiry.
3. The sender's `author_minute` and the recipient's `now` each err by at most σ.

So a legitimate blob is accepted by `now − author_minute ≤ 37 d 2 h + 6 d = 43 d 2 h < 45 d`, and FRESH = 45 d refuses nothing legitimate. `author_minute ≤ now + 2σ` bounds the future side. A D3 tag lives while a replay could still pass freshness (`until_day` covers `author + 45 d` plus a day of rounding). A sender whose clock runs more than 45 days slow loses its messages (refused as stale; counter `stale`; Phase 13 may show "the contact's clock looks wrong"). Declared.

**The four replay cases Phase 7 leaves to the protocol layer (F7 §0.2):**
1. A relay lies about expiry or re-serves an expired blob: D1 while the tombstone lives, then B2, D2, D3, freshness; each layer is proven sufficient on its own with the others disabled (§15.5 RP2).
2. A consumer resends the same bytes as a new op long after: only our own INDETERMINATE resend does this, bounded by `resendNotAfter`; the recipient catches it with D1 or D3.
3. A namespace removed and re-added: D3 tags are keyed by contact and `message_id`, not by namespace; D2 as well.
4. A relay retired and re-added with old blobs: as case 1.

**Restore.** `dm_self.accept_after_minute` = the restore minute: content authored before the restore is refused (R9), since `dm_seen` and pair keys are gone (RE §7).

### 7.7 Ordering (normative; CS-4)

- **R-O1.** A conversation is ordered by `(sort_minute, minute_index, message_id)` (bytes ascending), a pure function of stored content: outgoing `sort_minute = author_minute`; incoming `sort_minute = min(author_minute, receive_minute)`, which stops a peer with a future clock from pinning its messages below all later ones (`receive_minute` is used inside RECV and never stored). There is no arrival-order column and no AUTOINCREMENT (RE §6.3).
- **`minute_index`** = `1 + max(minute_index)` over the sender's own live outgoing rows of the conversation with the same `author_minute`, 0 if none. No counter is persisted (T33). An expired row can make an index repeat; `message_id` breaks the tie.
- **Reorder tolerance** is libsignal's per chain (`MAX_FORWARD_JUMPS` 25 000, `MAX_MESSAGE_KEYS` 2 000, 5 receiver chains, 40 archived states; [U37]). Beyond it a blob is dropped (`undecryptable`) and the loss is declared (L7-D11). No gap detection (a persisted sequence would outlive the messages). Within one minute the two directions interleave by index and id, not by causality (T13 makes the minute the clock resolution).

### 7.8 Crash points, poison and fault suites (normative; G-1)

| Crash point | State after restart | Behaviour |
|---|---|---|
| inside SEND | nothing: no ratchet step, row or op | not sent; the draft lived in memory (Phase 13) |
| after SEND, before `requestExpedite` | op pending | the next foreground or job session stores it |
| relay stored, receipt lost | Phase 7 ambiguity (`copy_hour`) | identical bytes within the Phase 7 window, or RESEND; the recipient dedups at D1 |
| inside RECV, before or after the libsignal decrypt | rolled back, ratchet included | the blob is re-offered and decrypted again with the same result |
| **native crash** (SIGSEGV) inside libsignal or BouncyCastle during RECV | the process died; the Phase 7 offer counter was committed by `claim` before the hand-off | re-offered alone (`claim` returns a twice-offered row alone); at the fourth offer (`offers ≥ 4`, three process deaths on it) RECV consumes it unprocessed (R2): no crash loop, and a double crash during recovery still processes the blob at its third offer; `CONSUMER_POISONED` in status |
| after RECV, before the notification update | row committed | `onUnreadChanged` runs at every database open |
| inside OUTCOME, KEYDEC, HELD, DISPLAY, OWNER-WEEK, ACTIVATE, EST-START, EST-END, BUNDLE, KEEPER, REGROWS | atomic | redone at the next wake (ACTIVATE by the resumable check at actor start and database open, §21.12); each is idempotent (§7.2) |
| after SWEEP, before the checkpoint | rows gone, frames still in the WAL | **R-K1: `wal_checkpoint(TRUNCATE)` runs at every database open**, after migration and before any read by UI or notification code |
| during the checkpoint | SQLite WAL recovery | R-K1 at the next open |
| process death with timers pending | none in memory | timers rebuilt from `idx_dm_message_delete` and the alarm; the open-time sweep runs first |
| during migration 4 | the previous version (one transaction) | migration runs again at the next open (CS-9) |
| disk full (`SQLITE_FULL`) at any statement | the transaction rolled back | SEND → `STORAGE_FULL`; RECV → `Inbox.defer` resets the offer counter and the blob is re-offered later (§21.12); SWEEP → retried; other steps → retried at the next wake; suite SCN-J |
| power loss | `synchronous = FULL` (`Schema.kt:728-739`) | committed transactions survive; torn writes are SQLite's responsibility (not modelled, F7 §8.1) |

---

## 8. Sessions, identity store, key change, safety numbers, revocation, restore (I5; ADR-33)

### 8.1 Addresses and records

- libsignal remote address = `SignalProtocolAddress(hex(contact_id), 1)` (the random local 16-byte contact id), local address = the constant `SignalProtocolAddress("ghost-local", 1)`: **never** `ghost1…`, a key, a namespace or a ServiceId-shaped name, so libsignal serializes no `addresses` field and a log line carries no identifier (T3; §21.6). Device id is 1 everywhere (multi-device P2; RS K17).
- Session records, signed prekey records, Kyber prekey records and reuse tuples are opaque BLOBs in `sig_*` tables (§13.6), written only through `tx.sql` (spec §8 "dedicated representation").

### 8.2 Store semantics (normative)

| Method | GHOST behaviour |
|---|---|
| `getIdentityKeyPair()` | the MESSAGING-derived pair held by the unlocked DM actor (§3.1); zeroized on lock and wipe; never read from a table |
| `getLocalRegistrationId()` | `dm_self.registration_id` |
| `isTrustedIdentity(addr, key, dir)` | **true iff** the contact exists, `pinned_identity = key`, and either `trust_state ∈ {unverified, verified}`, or `trust_state ∈ {request, changed}` and `dir = RECEIVING` (a `changed` contact's old-session `SignalMessage`s still decrypt under the old pinned key). **False otherwise in both directions**: any mismatch, no pinned key, SENDING in `request` or `changed`, `blocked`, `revoked`, unknown address |
| `saveIdentity(addr, key)` | GHOST pins identities in its own code before any libsignal call (bundle §5.5, RECV R6). Equal → `NEW_OR_UNCHANGED`; anything else → write nothing and throw `IllegalStateException` (unreachable when the pre-checks hold; the transaction rolls back; mutants MC-6 and PM-16 prove the pre-check is load-bearing) |
| `getIdentity(addr)` | `pinned_identity` |
| `SessionStore` | `sig_session(contact_id, record)`; `getSubDeviceSessions` returns the empty list; deleting a contact deletes its session; written with UPDATE then INSERT (no REPLACE) |
| `SignedPreKeyStore`, `KyberPreKeyStore` | own records with `superseded_day` and `delete_after_day` (§5.4); `markKyberPreKeyUsed` selects the tuple first, throws the pinned reuse exception if it exists, and otherwise inserts it into `sig_kyber_reuse` and records the session renewal (§21.3, §21.6) |
| `PreKeyStore` | empty: `loadPreKey` throws `InvalidKeyIdException`, `containsPreKey` is false, `storePreKey` throws `IllegalStateException` (never called), `removePreKey` is a no-op (§5.6) |

### 8.3 Key change (normative; FR-4.6, spec §7.2(d), plan gate "schimbare de cheie blochează"; C-14, E-1, E-2)

**Definition.** For a contact c with pinned Ed25519 `identity_pk` and pinned libsignal identity `K`:

| Event | Classification |
|---|---|
| A PreKey L1 in an intro envelope, or a fetched bundle, carrying `K′ ≠ K`, **with** a binding signature valid under c's pinned `identity_pk` | **key change** |
| The same with a binding **not** valid under the pinned `identity_pk`, or with no binding (a PreKey L1 in a pair envelope is already dropped, R4) | **forgery**: dropped (`bad_binding` or `non_canonical`), no state change, nothing shown |
| An `UntrustedIdentityException` raised by libsignal | never a key change on its own: a drop (`untrusted`) |
| A card or intro envelope with a different `identity_pk` | a different identity: an unknown sender becomes a request (§12.3); GHOST never links two Ed25519 identities |
| A PreKey L1 with `K′ = K` (the contact restored, reset or reconnected) | not a key change: libsignal replaces the session; a content-free "session renewed" contact event |
| A valid revocation certificate v2 for c | **revoked** (§8.5), stronger than a key change |

Anyone who holds c's card and my card can build an intro envelope that names c's genuine card; without c's Ed25519 secret key it cannot produce a binding for another libsignal key, so it cannot move c to `changed` (the operations variant could, E-1). A valid binding for `K′ ≠ K` exists only when the holder of c's Ed25519 secret signed another libsignal key: c itself (including a modified client), a derivation-version change, or a seed thief (§3.4); a genuine binding replayed from another envelope fails its namespace, minute or L1 hash (§21.4).

**State machine** (`dm_contact.trust_state`):

```
            scan card in person / compare safety number
 unverified ────────────────────────────────────────────► verified
     ▲  │ key change detected                                │ key change detected
     │  ▼                                                     ▼
     │ changed (pending_identity = K′, held L1 rows) ◄────────┘
     │  │ acknowledgeKeyChange()          │ verifyKeyChange(scanned fingerprint) ok
     └──┘ (pinned := K′, → unverified)    └────────────► verified (pinned := K′)
 changed ──block()──► blocked (held rows deleted)
 any except request ──block()──► blocked ──unblock()──► deleted (card, session and pair keys were erased at block: add the card again)
 any ──valid revocation──► revoked (terminal; only deleteContact())
 request ──acceptRequest()──► unverified;  request ──rejectRequest() / request_until_day──► deleted;  request ──blockRequest()──► blocked
```

- **Blocking both directions (CS-5).** In `changed`: `send` returns `KEY_CHANGED` before any libsignal call (SEND S1), and `isTrustedIdentity` is false for SENDING; inbound PreKey L1 under `K′` are **held undecrypted** in `dm_held(held_id, contact_id, identity = K′, l1_env, hold_until_minute)` with `l1_env` the L1 bytes under the content key and `hold_until_minute = ceil_minute(min(relayExpiryHour, consume + 30 d + 1 h))` (the held timer is unknown until decryption, so the longest DM bucket bounds it). `SignalMessage`s that still decrypt under the old pinned session are shown: they were authenticated to `K`. At most `MAX_HELD_PER_CONTACT = 256` held rows (older ones deleted first, counted).
- **A second pending key.** A valid binding for `K″ ∉ {K, K′}` while `changed` replaces `pending_identity` with `K″` and deletes the held rows of `K′` (the newest valid binding wins; two live devices with one seed flip-flop, declared R-20).
- **Unblock.** `acknowledgeKeyChange(c)` ("explicit confirmation", FR-4.6) or `verifyKeyChange(c, scanned)` (full verification), in one KEYDEC transaction: `pinned := K′`, `pending := NULL`, `verified_fp` cleared (set again only by `verifyKeyChange`); the secrets of my offered roots for c (the rows stay for the generation counter, §21.3) and my out keys for c are erased and a new `seal_root` is attached to my next user `SignalMessage` (a different device may now speak for c); then the held rows are replayed through R7–R12 in `held_id` order in HELD transactions (local work, no network, no reflex).
- **Nothing reaches a relay.** Detection, holding, acknowledgement and verification produce no relay-visible event (T28, T31, NI-DM5). A PreKey message has the same bucket as any message (T29).
- **Timeouts.** A `changed` state never resolves itself. Held rows are deleted at `hold_until_minute`; the state stays `changed` until the user acts (declared, L7-D17).

### 8.4 Safety numbers (FR-4.6; D12)

- `NumericFingerprintGenerator(5200).createFor(GHOST_FP_VERSION, own identity_pk(32), own libsignal IdentityKey, peer identity_pk(32), peer pinned IdentityKey)`: 60 digits that commit to both Ed25519 identities and both libsignal keys; `GHOST_FP_VERSION` is a constant fixed in S0 among the values the pinned API accepts, never mixed with Signal clients (RL §2.5).
- The scannable form is `ScannableFingerprint.serialized`; `verifyKeyChange` and `markVerified` compare with `ScannableFingerprint.compareTo` (a version mismatch fails). A manual digit comparison is recorded with `markVerifiedManually(c)`; Phase 13 states what the user asserted.
- `dm_contact.verified_fp = SHA-256(displayable digits)` records what was verified; any change of the pinned key clears it. `pendingSafetyNumber(c)` computes the number with `pending_identity` while `changed`, so the user can verify before acknowledging.
- An in-person QR scan of a card sets `verified` (`source = qr_in_person`): the scanned `identity_pk` authenticates the libsignal key transitively through the binding (§3.4), so no prekey MITM is possible for that contact. A card received as a link starts `unverified` (a substituted link is a MITM).
- Computing, displaying, scanning and comparing cause no network I/O (T31). Phase 13 marks the digits `accessibilityDataSensitive` (T24).

### 8.5 Revocation (X-7; C-25; LIMITE L1 "Recuperare")

- **Certificate v2** (102 B): `0x02 ‖ identity_pk(32) ‖ issued_minute(u32 minutes since the epoch) ‖ reason(1) ‖ Ed25519 sig(64) over "ghost/v1/revocation" ‖ previous bytes`. The Phase 3 v1 (`RevocationCertificate.kt:11-13`, seconds) stays a local artifact and never leaves the device.
- **Issuing** (`issueRevocation(reason)`) is local. **Propagation** is the explicit user action `notifyContactsOfRevocation()`: one CONTROL message per contact with TLV `revocation`, each due at its own `U[0, 24 h]` offset drawn at the action and persisted (`dm_scheduled`, §13.6), because a burst of k deposits in one session would show degree k (RP §3.8). Nothing is published in a namespace that contacts poll (RP F8, T31).
- **Receiving** a valid certificate for c: `trust_state := revoked`; session, pair keys, held rows and pending sends deleted in the same transaction; displayed messages follow their timers. A revocation can only block, so a thief holding the seed gains nothing by forging one.
- **The DM equivalent of "a revoked device does not decrypt new epochs"** (LIMITE L1): after revocation no ciphertext is produced toward c and nothing from c is shown (KC7, SCN-K).

### 8.6 Restore from seed and healing (normative; G-6, C-20)

| Re-derived | Regenerated | Lost (declared, L7-D12) |
|---|---|---|
| Ed25519 identity; libsignal identity (same safety numbers); `card_secret_0`, intro key, inbox read secrets, schedule key; hence `X_0`, `P_0`, every week's `D`, `RP`, `RX` | registration id, signed and Kyber prekeys, `seen_key`, content key, pair roots | contacts and their cards, sessions, pair keys, `dm_seen`, held rows, messages, scheduled controls |

- **`Messaging.onRestored()`**, called from the Phase 8 restore path next to `Entitlement.restore` (RS K20), runs ACTIVATE: `accept_after_minute` = the restore minute; own `X_0` and `P_0` registered; the first relay session with a token publishes a fresh bundle and registers keys (a relay-visible restore moment, L7-D10); a restored device has no token until it obtains a trial or a pack (§21.7 point 8). A card index other than 0 cannot exist in Phase 9.
- **Inbound after a restore.**
  - **Pair envelopes** from established contacts do not open (their keys came from roots the old device generated): counted `unknown_seal`, shown in `status()` as "unopenable envelopes since restore"; their content is lost.
  - **Intro envelopes** open (the intro key is seed-derived) and carry the sender's card. RECV creates a `request` contact from it (R5). If decryption fails with `InvalidKeyIdException` (a PreKey built on a pre-restore bundle) or `NoSessionException`, the request row is kept with `reset_needed = 1` and the blob is consumed; otherwise the request carries the message as usual.
  - Contacts who hold my card can also reset from their side once I have published a new bundle (their `resetSession` fetches it); until then they fetch the lost device's bundles and their PreKey messages fail here with `InvalidKeyIdException` (§21.7 point 8). A reset arrives as an intro PreKey under the same libsignal identity: a session renewal, no key change (C-1).
- **`reconnect(contacts)`** (user action; Phase 13 shows "N contacts tried to reach you"). For each contact: accept the request (→ `unverified`), then a `dm_scheduled` row due at a `U[0, 48 h]` offset drawn at the action (skipped if the user sends to that contact earlier). When due (a time-triggered step, §21.9): a CONTROL item with `session_reset` waits for EST-START and `EST-READY` (§21.8). The contact's libsignal sees a PreKey message from the **same** identity key and replaces the session without a key-change warning; the contact detects the renewal and drops its out keys for me (§21.3); new roots follow in both directions once the sessions are acknowledged, and pair envelopes then open both ways. Spreading avoids a burst of k deposits into k inboxes revealing degree k (RP §3.8).
- **Relay state after a restore.** Registrations are relay state: for up to about two weeks after the old device's last renewal, deposits still succeed and the restored device reads `X_0` with its seed-derived read key without a capability (§4.8). Tokens are not restored (Phase 8 E11).
- **No reflex.** No revocation, reset notice, bundle fetch or registration is triggered by an inbound blob after a restore (T28, T31).

### 8.7 Session reset and staleness

- `resetSession(c)` (user action) and a user send that finds no usable session (`NoSessionException`, or the 30-day soft archive of `MAX_UNACKNOWLEDGED_SESSION_AGE`) go through the one-shot bundle fetch (§5.5); the new PreKey session is intro mode until c answers.
- No automatic reset, no `DecryptionErrorMessage`, no retry request (D10).
- Two live devices with one seed (unsupported multi-device, or a thief) publish competing bundles for the same week; fetchers take the one with the smaller blob hash among equal `bundle_week`s, and sessions may fail on either device (declared, R-20).

---

## 9. Post-quantum (I6; ADR-12, ADR-28)

### 9.1 What the pinned library provides (verified at 0.102.2, RL §3)

- **PQXDH is the only session setup.** `PreKeyBundle` takes a non-nullable Kyber prekey; `session.rs` verifies its signature and rejects message version 3 ("X3DH no longer supported") [U25][U34]. `CIPHERTEXT_MESSAGE_CURRENT_VERSION = 4`.
- **SPQR (triple ratchet) is mandatory for new sessions from 0.100.0** (`min_version: V1`, `ratchet.rs:73-83`) [U1][U35]; it mixes ML-KEM-768 material, sent in erasure-coded chunks, into the Double Ratchet keys [U38].
- **KEM for prekeys:** Kyber1024 (type 0x08) always compiled and the generation default; ML-KEM-1024 (0x0A) enabled in the protocol crate's features [U14][U36]; both have 1 568-byte ciphertexts.

### 9.2 Decisions (normative)

- **PQ-1. No knob, no fallback, no standalone KEM** (spec §7.5, ADR-12). There is no "PQ mode" setting: every GHOST session is PQXDH + SPQR, and a peer that cannot speak both cannot establish a session.
- **PQ-2. KEM type.** The last-resort prekey uses **ML-KEM-1024** if the pinned Java API exposes it for generation (checked in S0), because the spec's PQC row asks for FIPS 203 conformance "through reviewed library integration" (`spec.txt:1087`); otherwise `KEMKeyType.KYBER_1024`, and ADR-28 records that the FIPS 203 row is met by the library's PQXDH as exposed (Q21). Sizes are equal, so `O_MAX` and the bundle layout do not change.
- **PQ-3. Asserted, not assumed.** A `:crypto-bridge` test (S4, rerun at every bump) establishes a session between two real clients and requires `getSessionVersion() == 4`, a Kyber ciphertext in the first PreKey L1, a non-empty `pq_ratchet` field in the first messages of both directions (decoded by a test-only protobuf parser, `protocol.rs:105-109`), and that the pinned version refuses a bundle without a Kyber prekey. A bump that makes SPQR optional again fails the gate.
- **PQ-4. Rotation.** The last-resort Kyber prekey rotates weekly with the signed EC prekey and is erased 91 days after supersession (§5.4); reuse tuples live exactly as long as the key (§5.6).

### 9.3 PQ status of GHOST's own layers

| Layer | Primitive | Against a future quantum adversary holding AD-1's archive |
|---|---|---|
| Content | libsignal PQXDH + SPQR | protected (ADR-12) |
| Pair-mode seal (§6.3), bundle seal (§5.3) | symmetric (HKDF, HMAC, ChaCha20-Poly1305) under 256-bit keys | protected; P-7 holds unchanged |
| Deposit and read credentials (§4.3) | hashes of 256-bit secrets | protected |
| Intro-mode outer layer | symmetric under `KIO` | protected against anyone without my card |
| Intro-mode inner layer (§6.4) | X25519 to my intro key | **not PQ**: a card holder with a quantum computer and the archive could open recorded intro envelopes to me and learn each sender's full card (Ed25519 identity and `card_secret`, hence that sender's namespaces and deposit credentials) and binding: who first-contacted, reset, reconnected or wrote unanswered to me, not the content. Declared (L7-D3, §21.11) |
| Card and binding signatures (§3.3, §3.4) | Ed25519 | authenticity only; a forged binding under a pinned key would surface as a blocking key change, but before a libsignal key is pinned (first contact, including a card verified in person before its bundle was fetched) it would be pinned silently. Declared (R-19, §21.11) |

---

## 10. Ephemeral messages (I7; ADR-27, ADR-32)

### 10.1 Timer values, TTL buckets and deadlines (normative; G-5, C-8, SC-3)

| Timer (`timer_code`) | off (0) | 5 min (1) | 1 h (2) | 1 d (3) | **7 d (4, default)** | 30 d (5) |
|---|---|---|---|---|---|---|
| Relay TTL (`ttl_bucket_seconds`) | 2 592 000 | **3 600** | 3 600 | 86 400 | 604 800 | 2 592 000 |
| Op deadline `author + min(bucket, 7 d)` (§21.10) | author + 7 d | author + 1 h | author + 1 h | author + 1 d | author + 7 d | author + 7 d |
| Honest relay copy gone by (`deadline_hour`: R-T4) | `deadline_hour + 30 d + 1 h` | `deadline_hour + 2 h` | `deadline_hour + 2 h` | `deadline_hour + 1 d + 1 h` | `deadline_hour + 7 d + 1 h` | `deadline_hour + 30 d + 1 h` |

- **R-T1 (ADR-27 point 11, exactly).** TTL = the smallest bucket ≥ timer; timer off → 30 d, the DM store-and-forward horizon. With the bucket set {1 h, 1 d, 7 d, 30 d, 90 d} the TTL equals the timer except for 5 min. The plan row's "TTL ≤ timer" cannot hold for 5 min and is read as ADR-27 (erratum X-16). DMs never use 90 d. The collapse of 30 d and off into 7 d (fewer TTL classes, loss of mail for recipients offline 7–30 days) is only offered as Q15.
- **R-T2 (one bucket per conversation).** Every blob of a conversation uses `bucket(conversation timer)`, including TIMER_SET, REACTION and CONTROL: a control message in another bucket would stand out in the recipient's inbox.
- **R-T3.** A TIMER_SET uses the **larger** of the old and the new bucket, so a change from 7 d to 1 h reaches a recipient offline for more than an hour.
- **R-T4 (deadline; SC-3).** Every DM op carries `deadlineEpochSeconds = author + min(bucket, 7 d)` (off uses the 30 d bucket; §21.10); Phase 7 stores `deadline_hour = max(ceil_hour(deadline), floor_hour(not_before) + 1 h)` (`OutboxStore.kt:179-182`), so a 5-minute message has the same deadline as a 1-hour one and is never cancelled at expiry (§21.10). After the deadline no copy is stored anywhere and the op closes (FAILED if no copy can exist, else INDETERMINATE; F7 M3). The 7-day cap (the Phase 7 store window H) makes FRESH = 45 d hold for parked ops too (§7.6), and gives an op parked for an offline recipient a bounded life.
- **R-T5 (pending sends).** A message waiting for a bundle (§5.5) fails at `deadline_hour`: it never reaches libsignal after its store deadline.
- **Bundles** (§5.4) use the 30 d bucket, a class DMs already use, with deadline `start(bundle_week + 2)`.

### 10.2 Seconds buckets: relay, client, observables (normative change list; X-10)

| # | Where | Change |
|---|---|---|
| 1 | `relay/crates/api/src/lib.rs:21-24, 171-175` | `TTL_BUCKETS_SECONDS = [3600, 86400, 604800, 2592000, 7776000]`; `ttl_bucket_seconds(ttl) -> Option<u32>` matches **exactly** (replaces the rounding `ttl_bucket_days`) |
| 2 | `relay/crates/node/src/lib.rs:215, 236-239`; `capture.rs:25` | a store with a non-bucket TTL → `INVALID_ARGUMENT`, capture `result = rejected_ttl` (the relay persisted raw TTLs until now, RE F2); capture field `ttl_bucket_seconds` = the stored value |
| 3 | `relay/crates/storage/src/lib.rs:59-72` | unchanged: expiry `ceil_hour(now + ttl)`, so a 1 h blob lives 1–2 h; a conformance vector re-checks that a namespace's sequence seed stays monotone when 1 h memberships empty it |
| 4 | `allowed-observables.json` v2, fixtures, `capture-check` tests | `ttl_bucket_seconds` enum replaces `ttl_bucket_days`; with §4.7's `register` and `key_kind` |
| 5 | `relay.proto:27`; `relay_semantics.txt` | comment lists the five buckets; a TTL section: 3600 accepted with an hour-rounded expiry; 1, 3599, 3601, 7200, 172800 → `rejected_ttl`; list and get across the 1 h expiry; renewal; Rust and `ModelRelay` replayers |
| 6 | `client-core/net/src/relay_client.rs:260-268, 292, 736-742` | refuse a non-bucket TTL (`invalid_argument`, before any I/O) instead of snapping; add the receipt **upper** bound `expiry ≤ ceil_hour(now + ttl) + σ` (else `malformed_response`), so a relay that promises to store longer than asked is detected (T30); the lower bound is unchanged (§10.4 finding 3) |
| 7 | `android/sync/.../api/Types.kt:46-56`; `TorRelayTransport.kt:59, 167` | `TtlBucket.HOUR_1(3600)`; every user of `days` rounds up; S3 audits each (`ownRetainDay`: `ceil(ttl / day) + 8` still covers TTL + 1 h + 2σ) |
| 8 | `Schema.kt:245` | migration 4 rebuilds `outbox_op`/`outbox_delivery` (§13.6); the v2 freeze rule is kept (no in-place amendment of a released version) |
| 9 | THREAT_MODEL §6, INVARIANTS T25 | wording: the relay observes `bucket(timer)` of the table, nothing finer (X-11) |

### 10.3 Countdowns and bounds (normative; ADR-27 C.9; C-11)

| Party / state | Start | Column | Rule |
|---|---|---|---|
| Sender, every outgoing row | the commit of SEND (S3) | `expire_at_minute = ceil_minute(commit + timer)` | set at insert; independent of the network |
| Recipient, displayed | `markDisplayed(ids)` (Phase 13 UI; the DISPLAY transaction) | `expire_at_minute = ceil_minute(now + timer)` | only if earlier than an existing value |
| Recipient, never displayed | consume (RECV) | `unread_deadline_minute = ceil_minute(min(E, consume + bucket + 1 h))` | set at insert |
| Held L1 (key change) | consume | `hold_until_minute = ceil_minute(min(E, consume + 30 d + 1 h))` | §8.3 |
| Request messages | consume | as "never displayed"; the request itself at `request_until_day` | §12.3 |

- **E** is `InboundBlob.relayExpiryHour`: the expiry the serving relay returned at `get`, validated in Rust (≤ now + 90 d + σ, `relay_client.rs:309-322`), stored in `inbox_blob.relay_expiry_hour` only while `fetched` (§13.3 item 2). An honest relay's E ≤ store + bucket + 1 h ≤ consume + bucket + 1 h, so the `min` is E, exactly ADR-27 C.9 ("cel târziu la expirarea blob-ului pe relee"). A relay lying short can only make deletion earlier (a denial of service it could cause by withholding); a relay lying long is clamped. Content-derived deadlines (`author + bucket`) are rejected: a sender clock ahead of the recipient's would extend them (C-11).
- `delete_at_minute = COALESCE(expire_at_minute, unread_deadline_minute)` (CHECK). Displaying a message may move `delete_at` later than the unread cap, because the recipient countdown starts at display (ADR-27 point 9).
- **R-T6 (only earlier).** `expire_at_minute`, `unread_deadline_minute` and `hold_until_minute` never increase once set (triggers, §13.6).
- **R-T7 (expiry clock).** `now_e = max(floor_minute(wall), dm_self.expiry_clock_minute)`; every sweep raises `expiry_clock_minute`. A clock stepped backwards never delays deletion, also across reboots; a forward step deletes early (data loss, no leak; declared).
- **Bounds (the T25 oracle).** Sender plaintext gone by `ceil_minute(commit + timer) + lag`; recipient by `ceil_minute(display + timer) + lag` or `unread_deadline_minute + lag`; held ciphertext by `hold_until_minute + lag`; the sender's retained blob with its message row, and its Phase 7 payload by the op's last possible store (≤ `deadline_hour`); honest relay copies by the §10.1 table. `lag` is the sweep lag of §10.7.

### 10.4 Phase 7 window rules for TTL ∈ {1 h, 1 d} (normative; G-10)

The re-derivation below is owned by the sync track (S3) and must keep `sync-exit-gate` green with no other change. With σ = 3 d:

1. **Resolution never applies.** `now < copy_hour + ttl − σ` is never true, so no delivery becomes resolvable and a check-before-restore never clears `copy_hour` (the resolvable-copy clause of `CapabilityStore.needed()`, `CapabilityStore.kt:141`, is empty for such TTLs). Deliveries close by the deadline (every short-TTL DM op has one) or by window expiry, and D2 then decides `indeterminate` if a `copy_hour` exists without a verified copy.
   - The **safety** invariants of F7 §8.4 do not use σ and are unchanged: `failed ⇒ never held` (FAILED needs no `copy_hour`), `sent ⇒ memberships`, and no duplicates at the recipient (stores are confined to `[F, deadline] ⊂ [F, F + H]`, and recipient tombstones live `E + 24 d`).
   - **Liveness** changes: an ambiguous short-TTL op ends `indeterminate` instead of being resolved into `failed` and re-sent. Weaker, correct ("may not have been delivered").
2. **`resendNotAfter = copy_hour + ttl − σ`** is in the past, so no identical resend happens for short TTLs; OUTCOME already expects it (§7.5).
3. **The receipt lower bound** `expiry + σ ≥ now + ttl` is vacuous for short TTLs: a relay may acknowledge with an early expiry and it is accepted. The effect is that the blob disappears early, equivalent to withholding (availability only; ADR-11 independence and recipients listing every relay of the set). Declared (L7-D15); a relay-corrected bound is a Phase 12 option.
4. **Retention** is unchanged and still safe: a contact's inbox is write-only, so there is no own tombstone; recipient tombstones are `ceil7(day(E) + 24)`; every store happens before the deadline, far inside H.
5. **Tests.** The seeded scenario S-F of the Phase 7 exhaustive suite gains TTLs of 1 h and 1 d, with and without deadlines, and offline windows of 30 min, 3 h and 3 d. `sync-exit-gate` (20 000 seeds, 17 mutants, crash counts) stays green with its report lines unchanged apart from the scenario list.

### 10.5 Timer changes and versions (normative; ADR-27 C.8)

- The conversation timer changes only through TIMER_SET, a message shown to both sides, with `timer_version = local + 1`. Every L0 carries its own `timer_code` and the sender's `timer_version`.
- **R-T9 (adoption).** The recipient adopts `(timer_code, timer_version)` from any L0 with a **greater** version (TIMER_SET or any message: a lost TIMER_SET is healed implicitly). Equal versions with different codes: **the shorter timer wins** (off = ∞). A lower version changes nothing, so a replayed or delayed old message cannot lengthen the timer (Signal's `expireTimerVersion` with a deterministic tie-break, RE §8.2).
- A message is always deleted by **its own** `timer_code`, whatever the conversation timer is now.

### 10.6 Deletion cascade (normative; ADR-27 C.10)

One SWEEP transaction deletes, for every row with `delete_at_minute ≤ now_e` (at most 500 per transaction):

| Item | Mechanism |
|---|---|
| `dm_message` row (`body_env`, quote reference, timers) | `DELETE` |
| its reactions | `dm_reaction` `ON DELETE CASCADE` |
| quotes of it | nothing stored: replies hold only `quote_ref` and render "unavailable" |
| its outbound items, ops and retained blobs | `dm_outbound_item` and `dm_outbound_op` cascade; **no `Outbox.cancel`**: every op runs to its outcome or deadline with E2E ciphertext no key on the device opens (§21.10) |
| a pending send | `dm_pending_send` cascade; `P_c` removed when no pending send is left (EST-END) |
| held rows past `hold_until_minute`; requests past `request_until_day` | `DELETE` (a request cascades its contact, session, pair keys and rows) |
| `dm_seen` rows past `until_day`; pair week keys past `start(w + 1) + FRESH`; superseded prekeys past `delete_after_day` (with their reuse tuples) | `DELETE` |
| notification | after commit, `NotificationPort.onUnreadChanged(count)`; cancelled at 0 (§10.7) |
| media, thumbnails | `MediaPort.onMessagesDeleted(tx, ids)` (Phase 11; a no-op port in Phase 9) |
| inbox ciphertext | already NULL at `markConsumed` (Phase 7) |
| libsignal skipped keys | belong to messages not yet received; stay in the session record (declared, L7-D7) |

### 10.7 Physical deletion, sweep scheduling, notifications (normative; C-12)

- **Checkpoint.** After a SWEEP that deleted rows: `PRAGMA wal_checkpoint(TRUNCATE)` read through `query`, **require `busy = 0`**, retry 3 times 100 ms apart, else keep `checkpoint_due` in memory and retry at the next sweep. The same result check replaces the ignored result in the Phase 7 `Gc.checkpoint` (`Gc.kt:90-92`, RE F5). **R-K1:** a checkpoint runs at every database open, after migration and before the first read. `secure_delete = ON` (never FAST).
- **Sweeps run** at: (1) the actor's in-process timer (§21.9), which includes the next `delete_at_minute`, while the process lives (lag ≤ 1 min); (2) every database open; (3) the start of every foreground session and every `ConsumerTail` run (§13.3), including quiet runs after the issuer call returned and the transport closed; (4) every read query filters `delete_at_minute IS NULL OR delete_at_minute > :now_e` (an expired row is never shown before physical deletion; a lint test runs every DAO query against an expired row); (5) **one inexact alarm**: `AlarmManager.setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + (next − now), pendingIntent)` (§21.10) on an explicit, **non-exported** `ExpiryAlarmReceiver` through `FLAG_IMMUTABLE`, one fixed request code, no extras, no new permission; cancelled when nothing is pending and at wipe; the receiver calls `goAsync()`, posts a sweep to the actor and finishes. Doze limits delivery to about once per 9 minutes per app. Alarms do not survive a reboot and no boot receiver exists: after a reboot the next sweep waits for the persisted periodic job (network-constrained) or the next app open (§21.10, L7-D14).
- **T20 amendment (X-11).** "One periodic job without extras" is unchanged; the messaging layer may hold this one inexact alarm with no extras. A rooted examiner can read the next expiry minute from the alarm (L7-D7).
- **Lag bound (declared, L7-D14).** With the process frozen and the alarm deferred by Doze, physical deletion waits for the next alarm window or job run; rows stay under SQLCipher and are never shown. With an authentication-bound database key (ADR-20 Q6), deletion waits for the next unlock.
- **Notifications (Q19).** `NotificationPort` exposes only `onUnreadChanged(count: Int)`; the Phase 13 implementation posts one constant text with no sender, conversation id or content, **locked or not** (Android's notification history keeps what was posted for 24 h, RE §8.4). Phase 9 ships the port and a no-op implementation; T33 tests the port contract.
- **No FTS.** No virtual table exists over DM content (`secure_delete` does not scrub FTS shadow tables); gate `dm-no-fts.sh` and schema test R-M4.

### 10.8 Interaction with Phase 7 retention (declared)

- Inbox tombstones of `X_0` keep `(namespace, hash, retain_until_day)` for `ceil7(day(E) + 24)` (ADR-20 point 6); `dm_seen` keeps one keyed 16-byte tag per received message until `ceil7(day(author) + ceil_days(FRESH(bucket)) + 1)` (§21.10). A tombstone says "a blob existed that week"; a tag also lets a seizer who knows a `message_id` (its sender, a colluding contact) confirm receipt and its week. They outlive a 1 h message by up to about two weeks and a 30 d message by up to about seven (L7-D7). A TTL-aware tombstone retention would reopen the Phase 7 retention proof: a Phase 12 option.
- Contacts' inboxes are write-only (`listen = false`): Phase 7 keeps no tombstone for them.
- Fetched but unconsumed DM ciphertext is never collected by Phase 7 GC; the DM consumer runs in every foreground session and in the `ConsumerTail` of every background and quiet run (§13.3), so `FETCHED_CAP` drains and the unread cap applies without a foreground (E-17).

### 10.9 T25 for DMs (summary; cases in §15.5 EP)

For each timer × path (sender; recipient displayed; recipient unread with an honest, a short-lying and a long-lying relay expiry; held; request; pending send): advance the virtual clock to the §10.3 bound + 1 min, sweep, then assert:
1. **logically:** no row, reaction, held row, pending row, retained blob or outbound mapping remains; the notification sink's last count is correct and every posted text equals the constant;
2. **physically:** the raw `.db` and `-wal` bytes contain neither the plaintext canary, nor the `body_env` bytes, nor the retained blob (checked at the op's outcome or `deadline_hour`, §21.10), nor the `message_id`; a logical scan decrypts every `*_env` column with the harness content key and finds no canary (§21.8);
3. the WAL is 0 bytes; a busy reader delays but does not defeat truncation;
4. a clock stepped back one day does not delay deletion;
5. every captured store TTL follows §10.1, and captures for 5 min vs 1 h timers are identical (NI-DM4).

---

## 11. Traffic and metadata (I8; ADR-09, ADR-15, ADR-20)

### 11.1 When DM traffic happens (normative)

| Traffic | STANDARD | HIGH | Depends on |
|---|---|---|---|
| Own inbox listings (`X_0` on its set) | Phase 7 schedule (T = 30 s × U[0.5, 1.5] per pair; background W = 90 s) | same | nothing DM-related (T19) |
| Gets | per new blob at list events | same | inbound volume (declared, LIMITE L2.1 #3) |
| DM deposit (store into `X_c`) | when due, right after the SEND commit (`requestExpedite`) | at a pair event after U[0, 10 min]; **DM namespaces cannot be set to `SendDelay.OFF`** (API refusal and trigger, §13.3 item 8) | user sends; scheduled CONTROL due times |
| Deposit verification (`check` with the deposit credential) | pair event ≥ ack + 60 s (F7:626) | same, at pair events | user sends |
| Automatic identical resend | when the INDETERMINATE outcome is released, within `resendNotAfter` | at pair events | the user's own earlier send (§7.5) |
| Bundle fetch of a contact | the next list events of the temporary `P_c` pairs | same | user action only (§5.5) |
| Own redeem for `X_0`, `P_0` | activation: at once (Q31); weekly: the EXPIRING PRF time in the last 23 h of the week | same, at pair events | the week; the redeem lane |
| Own `register` events | right after a capability install, on the work lane | at pair events | the capability install times |
| Own bundle publication | first session after `t_pub(w)` (fixed seed-PRF offset per card) | same | the week only |
| Reconnect resets, revocation notices | each at its own pre-drawn offset (U[0, 48 h], U[0, 24 h]) | same, then the HIGH delay | user action |
| Anything caused by an inbound blob | **nothing** (T28) | nothing | — |

No cover traffic (P2), no DM-specific schedule, no shorter listing interval: NFR-1 is measured on the gate devices and recorded, not claimed (Q23).

### 11.2 Per-event observation matrix (THREAT_MODEL §6 rows; Romanian text in Appendix B.3)

| Event | Relay (AD-2, effective view) | AD-1 adds | AD-4 / AD-5 | AD-7 (holds my card) | AD-8 (seized device) |
|---|---|---|---|---|---|
| Deposit into `X` | `store(X, hash, 4/16/64 KiB, ttl ∈ {3600, 86400, 604800, 2592000}, minute, the inbox's static deposit scope at that relay (identical for all senders, §21.2), request id, sender circuit)` | the same on the set's relays; the sender's circuit ties its stores in one session (L7-D5) | upload 3 × bucket | with AD-1: its own blobs' hashes, hence my fetch times | message row; frozen outbox ciphertext until the deadline; retained blob until the outcome |
| Receive | `list(X)` on T19 times with my static read scope at that relay (§21.2); `get` per new blob | presence, foreground/background cadence (LIMITE L2.1 #4) | download at list events | with AD-1: my online times and total inbound volume (L7-D3) | rows, `dm_seen` tags, tombstones |
| Weekly owner renewal | `redeem(X)`, `redeem(P)` at the renewal PRF time; `register(X, deposit)`, `register(X, read)`, `register(P, read)` after them | nullifier ↔ `X`, `P` for ≤ 2 weeks (E13) | — | knows `X`, `P` | — |
| Bundle publication | `store(P, hash, 4 KiB, 2592000, minute, owner write scope)` at the card's fixed weekly offset | "this identity is alive this week" (L7-D10) | — | sees rotations and the publication week; with a relay, the owner's first session after `t_pub`, absences and restore or activation minutes (§21.9, L7-D10) | prekey records |
| Bundle fetch | `list/get(P)` with the card-shared read scope of that relay, a fresh circuit, in at most three attempts (§21.7) | fetch → first deposit into `X` links `P` and `X` as one owner (L7-D6) | 4 KiB download | — | — |
| Key change, verification, acknowledgement, block, request accept or reject | **nothing** | nothing | nothing | nothing | trust state, held rows |
| Timer change | a user send in the larger bucket (R-T3); later blobs switch bucket | the first blob in a new bucket marks the change time (L7-D4) | — | sees the change | timer and version |
| Ephemeral expiry | nothing (TTL fixed at store) | — | — | — | deletion; tombstone and tag remain (L7-D7) |
| Restore | new registrations and a bundle from a new circuit set, same namespaces | the restore moment (L7-D10) | — | — | — |
| Reconnect / revocation notice | k user-initiated sends spread over 48 h / 24 h | degree k over one or two days, weakly (L7-D10) | — | receives it | scheduled rows until due |
| A card holder redeems its own token for `X` | a redeem and lists of `X` under a foreign write scope | — | — | inbound volume and timing of my inbox (L7-D16) | — |

### 11.3 Consequences for the existing invariants

- **T1.** Observables v2 (§4.7, §10.2). Each new field and value is a declared privacy decision (INV:50), recorded in ADR-30 and ADR-32.
- **T19.** Unchanged and re-tested with DM activity: sends, consumption, sweeps, key change, requests, owner steps and registrations create no read event and move no pair's schedule; a temporary bundle pair does not change any other pair's schedule; registrations run on the work lane only (mutant MC-13).
- **T21.** v3 credentials are authorized by kind and namespace before I/O and use the namespace's circuit (§4.3). A DM deposit and a bundle fetch never share a circuit with another namespace.
- **T2 (Phase 8).** Deposit keys make token spend independent of DM breadth (T27), so E16 cannot grow with contacts; the T2 world models the owner namespaces (§4.9). The `ConsumerTail` runs only after a quiet run's issuer call returned and after the transport closed, so issuer-call timing and session close times cannot depend on inbound DM volume.

### 11.4 Adversary conclusions (quantitative models from RP §4; T32 measures)

- **AD-1 without cards or seeds** learns no identity (P-1, S-DM3), no sender partition inside an inbox (P-2), no message type, first contact, reset, restore of a contact or key change (P-4), no degree of anyone (NI-DM3), and no conversation edge beyond what LD gives. Reply-timing SDA on LD recovers inbox ↔ inbox edges after about 6 exchanges in STANDARD and 8 in HIGH on a 10 000-inbox relay, 1–2 rounds with active delaying (L7-D1). T32 reports these numbers (S-DM2); the design does not claim them away.
- **AD-1 + AD-7** anchors one inbox to an identity, sees that identity's presence and inbound volume, recognises its intro envelopes, and, through session-start co-occurrence, the channel namespaces of the same client (L7-D2, L7-D3). No UI claim of channel-pseudonym unlinkability against relays is allowed until Phase 12 decouples session starts (CP-10, Q22).
- **AD-7 alone** can deposit (spam, quota), fetch the bundle, and with its own tokens list the inbox's volume (L7-D8, L7-D16).
- **AD-5** correlates an upload with the recipient's download at its next list event whatever the mode; only P2 cover traffic removes it (LIMITE L2).
- **AD-8** sees contacts, timers, trust states, ratchet counters and residue tags (L7-D7); never expired content (T25) or pair-mode history older than the T34 horizon.

### 11.5 New LIMITE section L7 (DM residues; Romanian text in Appendix B.4)

Naming note: LIMITE **section** L7 is unrelated to the Phase 8 declared-leak **cell** L7 of T2 ("the start of a purchase after `ENTITLEMENT_NEEDED`"); DM residue ids carry the `-D` suffix.

| ID | Residue | Why it remains | Mitigation |
|---|---|---|---|
| L7-D1 | Reply-timing SDA recovers inbox ↔ inbox edges (~6 exchanges STANDARD, ~8 HIGH; 1–2 with active delay; ~2–3 for conversations with a non-default timer, L7-D4) | activity-dependent traffic, no cover | no reflexes (T28), HIGH delay, P2 cover; measured per TTL class (S-DM2, §21.11) |
| L7-D2 | Session-start co-occurrence links a client's namespaces on a relay in ~3 sessions and, with a contact, the DM identity to channel namespaces | LIMITE L2.1 #1 | Phase 12 decoupling (P1); no UI claim |
| L7-D3 | A card holder colluding with relays recognises intro envelopes in my inbox (first contacts, resets, reconnects, the first reply of each conversation, and every message of a conversation I never answer), sees my presence and total inbound volume; intro envelopes are attributable with my seed; a future quantum adversary holding my card reads from them each sender's full card (identity and `card_secret`) | the card is a shared "may message me" secret; the intro inner layer is X25519; pair roots travel only in acknowledged sessions (§21.3) | pair mode for answered conversations; card rotation (Phase 13); a KEM-based intro layer (P2, §21.11) |
| L7-D4 | The TTL bucket (1 h / 1 d / 7 d / 30 d) partitions an inbox by conversation class and pairs the two inboxes of a conversation whose timer is not the default (reply-timing SDA then needs ~2–3 exchanges, §21.11); the first blob in a new bucket marks a timer change | TTL ≥ timer (ADR-27 point 11); both directions use the conversation's bucket | one bucket per conversation; Q15 or Q39 would reduce the classes; the Phase 13 copy states it |
| L7-D5 | Several deposits of one sender in one session share a circuit | T21 per-namespace isolation | a fresh circuit per deposit, rejected (cost) |
| L7-D6 | Establishment: the fetch of `P_c` followed by a deposit links `P_c` and `X_c` as one owner, and a relay serving the bundle chooses when that deposit happens (≥ 2 min later); up to three fetch attempts each co-occur with a session start of the fetcher (a relay set withholding bundles gets all three); an unanswered conversation repeats the fetch after libsignal's 30-day soft archive; an invitee's first DM to its inviter soon after onboarding links the two clusters | establishment needs a bundle; people message their inviter | HIGH delay; bounded attempts (§21.7); none cheap |
| L7-D7 | On the device: contacts, per-conversation timers, trust states, ratchet counters and skipped keys, `dm_seen` tags (≤ ~2 to ~7 weeks by bucket; with a known `message_id` they confirm receipt and its week), inbox tombstones, held ciphertext until its bound, retained E2E blobs and outbox payloads until the outcome or deadline, superseded prekeys (≤ 13 weeks), pair week keys (≤ FRESH after their week), a blocked or deleted contact's namespaces and credentials until its last op's deadline (≤ 7 d), minute/day times inside libsignal records, the next expiry minute in the alarm | needed to operate | T33; minute/day floors; per-bucket tag lifetimes (§21.10); content-free notifications |
| L7-D8 | The recipient pays its inbox; a card holder can exhaust a week's deposit allowance (256 MiB per relay per registering capability, ≈ 65 000 blobs of 4 KiB) and make the recipient spend CPU on hints of forged blobs; a relay that reports a short expiry can re-serve a rejected or deleted requester's genuine intro message within its freshness window and bring the request back (§21.4) | no sender-bought capabilities (T27) | allowance per registration; `FETCHED_CAP` and consumer budgets; card rotation (Phase 13) |
| L7-D9 | An identical-bytes resend after an ambiguous store links two sender sessions by hash | Phase 7 exactly-once | at most 2 resends, rare |
| L7-D10 | Weekly owner redeems, registrations and bundle publications show "this identity is alive this week"; relays see the minute of the first session after `t_pub`, hence absences, and activation and restore moments (card holders see only the week, §21.9); a reconnect or revocation notice shows degree weakly over one or two days; an owner offline > ~2 weeks has no valid bundle, and after ~2–3 weeks stops receiving | the inbox must be paid, registered and published | activity-independent times (T31, §21.9); `uploaded_at` floored to the week for v3 reads |
| L7-D11 | No one-time prekeys: a recorded first flight is decryptable by whoever later obtains the recipient's identity key plus that week's signed and Kyber prekey secrets before their erasure (≤ 13 weeks after supersession); messages beyond libsignal's reorder limits are lost; a message whose libsignal key survives as a skipped key on a seized device is decryptable, and if it carried a pair root it opens that generation's pair envelopes (the P-7 exception, §21.3) | blind relays cannot allocate one-time prekeys; libsignal keeps skipped keys without a time bound | weekly rotation and erasure (§5.4); roots only in acknowledged sessions (§21.3) |
| L7-D12 | A restore without a contact backup loses contacts, sessions and pair keys: pair envelopes of established contacts are unopenable (counted), their content lost, until a reconnect; a reset from their side fails until the restored device holds a token and publishes a bundle (they fetch the lost device's bundles meanwhile) | no contact backup in P0; tokens are not restorable (Phase 8 E11) | intro-envelope healing and `reconnect`, which needs no token (§8.6, §21.7); P1 encrypted contact-card backup (Q28) |
| L7-D13 | The inbox and bundle namespaces and their credential scopes are static per card and relay: a seized relay disk links the weeks of an inbox for as long as its blobs (≤ ~6 weeks) and registrations (≤ 3 weeks) live; after a slot-table change, blobs stored only on relays that left the ES are lost once their registrations lapse | no weekly rotation (C-4, §21.1, §21.2) | card rotation (Phase 13) |
| L7-D14 | Physical deletion can lag the timer while the process is frozen (alarm deferred by Doze), the database key needs an unlock, or the device rebooted without network (no boot receiver; the periodic job needs a network; §21.10) | Android scheduling | read filter, sweeps at open and in the consumer tail, inexact alarm |
| L7-D15 | For the 1 h and 1 d buckets a relay's early-expiry receipt is accepted (the σ = 3 d tolerance makes the bound vacuous); equivalent to withholding | Phase 7 clock tolerance | recipients list every relay (ADR-11); a relay-corrected bound in Phase 12 |
| L7-D16 | A card holder can spend its own token to redeem a write capability for my inbox and list it: inbound volume and timing, content sealed | write grants read at relays | owner-bound read rule (Phase 12, Q36) |
| L7-D17 | A key change left undecided past its hold bound (≤ relay expiry, ≤ 30 d + 1 h) loses the held messages | holding is bounded | a persistent Phase 13 prompt |
| L7-D18 | A mnemonic thief using the official client presents the same libsignal identity: contacts see no key-change warning | the identity is seed-derived (FR-1.2) | revocation v2 through contacts' inboxes; safety numbers do not help against the same key |

---

## 12. Contact establishment, requests, block (I9; ADR-30, ADR-33)

### 12.1 What is exchanged, and how (normative)

| Path | Carries | Starting trust | Relay-visible |
|---|---|---|---|
| **QR in person** (`source = qr_in_person`) | my card (163 B, QR 11-L) | `verified` (the scanned `identity_pk` authenticates the libsignal key through the binding, §8.4) | nothing |
| **Link** `ghost://contact/…` shared through another channel (`source = link`) | my card | `unverified`; Phase 13 warns that the channel sees the link and could substitute it (T16-style warning) | nothing |
| **Intro envelope** from someone who holds my card | the sender's card inside the sealed intro layer (§6.4) | a **request** (§12.3) unless I already hold that `identity_pk` | a deposit into my inbox, like any message |
| Invite v2 (Phase 8) | **no card** (unchanged, T16) | — | — |

### 12.2 One-scan flow

1. A scans B's card → A's contact B (`verified`, no pinned libsignal key yet, `establishment = card_only`).
2. A's first send (SEND S4) keeps the message pending and starts the fetch of `P_B` (§5.5).
3. BUNDLE keeps B's verified bundle; `EST-READY` (§21.7) pins `K_B`, builds the PreKey session, encrypts and seals the pending message in intro mode with A's card and binding inside, and deposits it into `X_B`; the first message carries no root (a PreKey L1, §21.3).
4. B's RECV opens the intro envelope: unknown `identity_pk` → a request with the message.
5. B accepts → contact A (`unverified`, or `verified` if B also scanned A in person). B's reply (a `SignalMessage`, since B's session is the responder's) is sealed in **intro mode** (B holds no root of A yet) and carries B's `seal_root` for A → B.
6. A's session is now acknowledged; A's next message is pair-sealed under B's root and carries A's `seal_root`; B seals in pair mode from its next message (§21.3).

- **R-E1.** Adding a card is local: it never registers, fetches or stores anything until the user sends (T31).
- **R-E2.** A card is parsed and verified (§3.3) before any storage; an own card, an invalid signature or the `identity_pk` of a `revoked` contact is refused locally.
- **R-E3.** Re-adding a card of an existing contact: an identical card is a no-op; any other difference is refused in Phase 9 (no card rotation).
- **R-E4 (simultaneous first contact).** When both sides send first, each receives a PreKey message while its own session is unacknowledged; libsignal keeps several session states and the sessions converge after one round trip (suite RO5, §15.5).

### 12.3 Requests from unknown card holders (normative; C-24, Q26)

- An intro envelope whose card and binding verify, from an `identity_pk` not in `dm_contact`, becomes a **request** if fewer than `MAX_PENDING_REQUESTS = 64` requests exist; otherwise it is dropped (`request_overflow`).
- In the RECV transaction: insert `dm_contact(trust_state = 'request', source = 'request', card_env, request_until_day = day(now) + 7)`, pin the bound libsignal key (R6), decrypt (RECEIVING is trusted for requests, §8.2), store the content rows as for any contact (their own timers and unread caps apply). A decryption that fails with `InvalidKeyId` or `NoSession` keeps the request with `reset_needed = 1` (§8.6).
- `acceptRequest(c)` → `unverified`, sending allowed. `rejectRequest(c)` or `request_until_day` → the contact, its session, pair keys and rows deleted in one transaction. `blockRequest(c)` → `blocked` (the identity is kept, so later requests from it are dropped).
- **No reflex (T28).** Neither arrival, nor accept, nor reject, nor expiry sends anything. The requester cannot tell whether it was seen, accepted or rejected until a user reply arrives.

### 12.4 Block, unblock, delete (FR-3.6, FR-4.7: local and documented)

| Action | Local effect | Relay-visible |
|---|---|---|
| `block(c)` | `trust_state = blocked`; card, session, pair keys, offers, held rows, pending sends and scheduled controls deleted; the conversation's messages kept until their timers (the UI may delete them) | nothing; c's deposits still land in my inbox (charged to my allowance) and are dropped: pair hints no longer match (`unknown_seal`), intro envelopes hit the blocked identity |
| `unblock(c)` | the blocked row is deleted; the user must add c's card again (the card was erased, so unblocking cannot silently restore an address) | nothing |
| `deleteContact(c)` | every row of c deleted; `X_c` and `P_c` recorded in `dm_orphan_namespace` and removed by SWEEP once their ops are released (§21.12); a later intro envelope from c is a new request | nothing |

The Phase 13 UI states what block does **not** do: it does not stop c from depositing, it does not tell c, and it cannot delete copies on c's device (FR-4.7).

### 12.5 Deferred in Phase 9 (G-12)

- **Cut-off (card rotation)** (C-16, Q27): stopping a card holder from depositing needs a new card index, the redistribution of the new card to the remaining contacts, and a contact backup so that a restore knows the index. Deferred to Phase 13 with the P1 encrypted contact-card backup. Phase 9 keeps `card_index` in the card, `CardLabels` indexed, and a `dm_self.card_index` column fixed at 0 by a trigger that Phase 13 drops. Old-index registrations lapse by themselves within two weeks once not renewed, so no relay replacement rule is needed (SC-1).
- **Invite v3** (C-18, Q32): the card inside an invite is Phase 13 UX; ADR-05's optional contact card stays open, not declined. An invite carries no identity by design (T16) and its drop carries exactly one blob at a pre-drawn time (ADR-24), so Phase 9 changes neither.
- **The Phase 8 drop outer shape** (C-17, Q18): drops keep the ADR-24 `DropSeal` format; aligning them with the DM shape would reopen the T2 NI-2/NI-3 twins just closed without exemption (F8 §19.29 point 7). A Phase 12 item with Elligator 2 or an equivalent.

### 12.6 Limits (NFR-14)

`MAX_CONTACTS = 1 000` (bounds the hint work, R-S5; Q37); `MAX_PENDING_REQUESTS = 64`; `MAX_HELD_PER_CONTACT = 256`; blocked rows ≤ 10 000; `MAX_BODY_BYTES = 61 440`. The API returns `LIMIT_REACHED`; nothing is silently dropped except requests and held rows beyond their caps, each counted.

---

## 13. Android modules, `:sync` and `:entitlement` extensions, schema v4, background (I10; ADR-33, ADR-34)

### 13.1 Module layout (normative)

| Module / package | Contents | Depends on |
|---|---|---|
| `:crypto-bridge` `org.ghost.crypto.bridge.signal` | `SignalRuntime` (lazy native load, `CryptoUnavailable`, session-version check), `SignalLog` (the silent logger), `DmSessions` (per-operation `SessionBuilder`/`SessionCipher` bound to a transaction), `DmKeys` (identity pair from `m`, prekey generation with day-floored timestamps) | `org.signal:*` (the only module allowed, G-LS3/G-LS4) |
| `…bridge.stores` | `TxSignalStores`: `SqlIdentityKeyStore`, `SqlSessionStore`, `SqlSignedPreKeyStore`, `SqlKyberPreKeyStore`, `EmptyPreKeyStore` (§2.4, §8.2) | `:sync` API (`SyncTransaction`) |
| `…bridge.seal` | `DmSeal` (pair, intro, bundle; §5.3, §6.2–§6.5), `Buckets.forContent` (R-B1), `DmCodec` (L0, §7.1) | BouncyCastle (ChaCha20-Poly1305, X25519, HMac-SHA256), HKDF of `:identity` |
| `…bridge.card` | `ContactCard` codec, `DmLabels`, `CardLabels`, `CredentialV3` builder and verifier (§4.3), `RelaySets.forNamespace` (§5.2) | `:identity` (Ed25519, root derivation) |
| `…bridge.fingerprint` | `SafetyNumbers` (§8.4) | `org.signal` fingerprint classes |
| `:messaging` `org.ghost.messaging.api` | `Messaging` facade, value types, `MessagingListener`, `NotificationPort`, `MediaPort`, `MessagingStatus` | — |
| `…messaging.engine` | `DmActor` (single thread), the transactions of §7.2 (`SendStep`, `ReceiveStep`, `BundleStep`, `EstablishmentSteps`, `OutcomeStep`, `KeyDecision`, `HeldReplay`, `DisplayStep`, `OwnerWeek`, `Activation`, `Keeper`, `RegistrationRows`, `Sweeper`), `Requests`, `Revocation`, `Reconnect`, `DmConsumerTail` | `:crypto-bridge`, `:sync` API, `:identity` |
| `…messaging.store` | DAOs over `dm_*` and `sig_*` (every read applies the expiry filter, §10.7) | `:storage`, `:sync` API |
| `…messaging.android` | `ExpiryAlarm` + `ExpiryAlarmReceiver` (non-exported, no extras), `KeystoreContentKeyWrapper` | Android |
| `:storage` | migration 4 (§13.6), `Checkpoint.truncate()` (busy-checked), `StorageFullException` mapping in both executors | — |
| `:sync` | the additions of §13.3 | — |
| `:entitlement` | the changes of §13.4 | `:sync` |
| `client-core/net` (Rust) | credential v3 in `capability_header` and T21; `registerKey`; exact TTL refusal; the receipt upper bound | — |
| relay | `RegisterKey`, credential v3, `keys.redb`, `DepositLedger`, exact TTLs, capture | — |
| `:app` | `MessagingWiring`: `Inbox.setListener(actor hints)`, `SyncController.setConsumerTail(tail)`, activation and restore hooks with `:entitlement`, the receiver in the manifest | all |

Rules: no class in `:messaging` or `:crypto-bridge` references `org.ghost.network`, `java.net`, `javax.net`, sockets, HTTP or `kotlinx.coroutines` (gate G-DM1): the DM layer never does network I/O, and never inside a transaction (F7:1418). Typed catches only (G-LS6). No coroutines (ADR-20).

### 13.2 UI-less facade for Phase 13 (normative signatures)

```kotlin
interface Messaging {
    fun myCard(): CardExport                                   // bytes + ghost://contact/ link; no network
    fun addContact(card: ByteArray, source: CardSource, name: String?): AddContactResult
        // ADDED | INVALID_CARD | OWN_CARD | ALREADY_KNOWN | REVOKED_IDENTITY | LIMIT_REACHED
    fun contacts(): List<ContactView>                          // id, name, TrustState, Establishment, resetNeeded; no times
    fun conversation(contact: ContactId, limit: Int, before: MessageCursor?): List<MessageView>
    fun send(contact: ContactId, text: String, quote: MessageId?): SendResult
        // QUEUED | KEY_CHANGED | BLOCKED | REVOKED | REQUEST_NOT_ACCEPTED | TOO_LARGE | NO_REPLICAS
        // | LIMIT_REACHED | STORAGE_FULL | CRYPTO_UNAVAILABLE
    fun react(target: MessageId, grapheme: String?): SendResult
    fun setTimer(contact: ContactId, timer: Timer): SendResult            // OFF, MIN_5, HOUR_1, DAY_1, DAYS_7, DAYS_30
    fun markDisplayed(ids: List<MessageId>)
    fun retry(message: MessageId): SendResult                  // FAILED only; re-encrypts the same L0; DEADLINE_PASSED after the deadline
    fun safetyNumber(contact: ContactId): SafetyNumberView?    // digits + scannable bytes
    fun pendingSafetyNumber(contact: ContactId): SafetyNumberView?        // while CHANGED
    fun markVerified(contact: ContactId, scanned: ByteArray): VerifyResult
    fun markVerifiedManually(contact: ContactId): VerifyResult
    fun acknowledgeKeyChange(contact: ContactId): Boolean
    fun verifyKeyChange(contact: ContactId, scanned: ByteArray): VerifyResult
    fun resetSession(contact: ContactId): SendResult
    fun reconnect(contacts: List<ContactId>): Int               // accepted and scheduled (§8.6)
    fun acceptRequest(contact: ContactId); fun rejectRequest(contact: ContactId); fun blockRequest(contact: ContactId)
    fun block(contact: ContactId); fun unblock(contact: ContactId); fun deleteContact(contact: ContactId)
    fun issueRevocation(reason: RevocationReason); fun notifyContactsOfRevocation(): Int
    fun status(): MessagingStatus                              // counts only: drops by reason, unknown_seal, held, requests,
                                                               // reset_needed, poisoned, pending registrations
    fun setListener(listener: MessagingListener?)              // coarse, content-free change hints
    fun setNotificationPort(port: NotificationPort?)           // onUnreadChanged(count: Int) only
}
```

Every method posts to the DM actor and returns after its transaction commits; none performs network I/O; `toString()` of every value type is redacted (T3). `MessageView` holds decrypted text only in memory.

### 13.3 `:sync` additions (normative; ADR-34, X-12)

```kotlin
enum class TtlBucket(val seconds: Int) { HOUR_1(3_600), DAY_1(86_400), DAYS_7(604_800), DAYS_30(2_592_000), DAYS_90(7_776_000) }

/** Who obtains write access. LOCAL: the consumer installs bearer credentials; never redeemed. */
enum class CapabilitySource { REDEEM, LOCAL }

interface Namespaces {
    fun register(tx: SyncTransaction, namespace: NamespaceId, consumer: Consumer, relays: Set<RelayId>, listen: Boolean,
                 sendDelay: SendDelay = SendDelay.DEFAULT, capabilitySource: CapabilitySource = CapabilitySource.REDEEM)
    // setRelays, setListening, remove: unchanged; setSendDelay refuses OFF for Consumer.DM
}

class InboundBlob(val namespace: NamespaceId, val hash: BlobHash, ciphertext: ByteArray,
                  val relayExpiryHour: Long, val offers: Int)

class CapabilityNeed(val relay: RelayId, val namespace: NamespaceId, val kind: CapabilityKind,
                     val reason: Reason, val source: CapabilitySource)

enum class KeyKind { READ, DEPOSIT }
interface Registrations {
    /** In the caller's transaction; idempotent on (relay, namespace, period, kind); a different verifier throws. */
    fun request(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, periodId: Long, kind: KeyKind, verifier: ByteArray)
    /** Rows of (relay, namespace) with period >= fromPeriod return to pending with new request ids (healing rule, §4.8). */
    fun rearm(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, fromPeriod: Long)
    fun forget(tx: SyncTransaction, relay: RelayId, namespace: NamespaceId, beforePeriod: Long)
    fun pendingCount(): Int
}

/** Runs on the job thread after a BACKGROUND session's lanes and redeem hold and after a QUIET run's issuer call, both
 *  after the transport closed. Local work only; returns by the deadline. */
fun interface ConsumerTail { fun run(kind: SessionKind, deadlineMonotonicMillis: Long) }
// SyncController gains: fun setConsumerTail(tail: ConsumerTail?)   (one slot, set at wiring, like the participant)
```

1. **`TtlBucket.HOUR_1`**, schema v4 (§13.6), the §10.4 window rules, and S-F with short TTLs.
2. **`InboundBlob.relayExpiryHour` and `offers`.** `recordFetched` stores `relay_expiry_hour = floor_hour(E)` beside the ciphertext; `claim` returns it and the committed offer count; `markConsumed` sets the column to NULL in the same statement.
3. **`CapabilitySource`** on `Namespaces.register`, stored in `sync_namespace.capability_source`; `CapabilityNeed.source` reports it. The entitlement planner never redeems a LOCAL need (§13.4). A LOCAL namespace without a usable credential parks its deliveries in `wait_capability` exactly like a REDEEM one; a new credential generation re-arms them.
4. **Needs rule (Q31).** `CapabilityStore.needed()` reports WRITE MISSING also where a pending `relay_key_registration` row exists for (relay, namespace) and no write capability does, with the same "active relay in the namespace's set" joins.
5. **`Registrations` on the work lane.** A pending row is due when `inflight = 0`, `next_attempt_minute ≤ now`, and a usable, unexpired write capability of week c exists for (relay, namespace) with `period_id ∈ {c, c + 1}`; at most 8 per pass; in HIGH mode at the pair's events, in STANDARD when due. The step follows the store pattern: a lease transaction, `registerKey` on the namespace's circuit, a result transaction. `OK` → `done` with `valid_until_hour`; `WRONG_PERIOD` or `unauthorized` → pending, re-armed by the next capability generation (the M2 idea); transient categories → Phase 7 backoff and breakers; a crash inside the call → lease normalization (M1); an identical registration is idempotent at the relay. Registrations never touch the read lane (T19; `T19BasicTest` gains registrations in run (b); mutant MC-13). The RPC maps onto the existing JNI error categories (`ErrorPolicyTest` stays at 21).
6. **`ConsumerTail` (G-8, SC-7).** `SyncRuntime` calls the tail (a) after a background session's lanes ended, the Q29 redeem hold ended and the transport closed, and (b) after a quiet run's issuer call returned and its transport closed, with `deadline = job deadline − 20 s`; not in foreground sessions (the listener and the facade drive the actor there). The tail posts a drain request to the DM actor and waits for it; the actor stays the only DM writer. The tail has no transport access. Because it runs after the close, relay session close times and issuer-call times cannot depend on inbound volume (NI-DM1 compares close times; mutant PM-25). **`SessionParticipantTest` gains:** a tail that runs to its deadline does not delay the job's end past the deadline; in a quiet run the tail starts only after the issuer call returned and the transport closed; in a background session only after the lanes, the redeem hold and the transport close.
7. **Credential selection.** For `list` and `get`, a usable READ credential of (relay, namespace) is preferred and a write capability is the fallback; `store` uses the write-kind credential (a write capability, or a deposit credential stored as `kind = 'write'` for a LOCAL namespace); `check` uses the write-kind credential when present, else the READ credential. S3 verifies `CapabilityStore`'s current selection and changes it where it differs. The engine treats all tokens as opaque; `client-core` parses them (T21).
8. **`SendDelay.OFF` refused for `Consumer.DM`** by `Namespaces.setSendDelay`/`register` and by a v4 trigger (mutant PM-14).
9. **Checkpoint.** `Gc.checkpoint` uses `Checkpoint.truncate()` (busy checked, §10.7).

### 13.4 `:entitlement` changes (normative)

- **`RedeemPlanner`** skips every need with `source = LOCAL` (counted `LOCAL_SKIPPED`, never `ENTITLEMENT_NEEDED`; mutant PM-1b).
- **Activation and restore hooks (RS K20).** The activation finalization (trial and genesis) and `Entitlement.restore` call an `IdentityActivationHook` after their own transactions; `:app` wires it to `Messaging.onActivated()` / `onRestored()`, which run ACTIVATE. This closes the F8 §8.3 step 4 gap ("prekey and inbox namespaces registered at activation").
- **Phase 8 Q34 (redeem hold for read needs), re-evaluated.** A DM owner whose capabilities all lapsed has pending registration rows for the current week (§4.8), which count as write work (§13.3 item 4), so the Q29 hold arms and the owner recovers in the background. Other listen-only namespaces (drops) keep Q34's declared behaviour.
- **NI-K** stays identical: its worlds have no DM activity. The DM world adds JD8 on an `EntHarness`-based variant (§15.1): a client's redemption and registration trace is identical with 0 and 30 contacts and any message volume.

### 13.5 State machines (summary; each has a JVM test of every legal and illegal transition)

| Machine | States | Driven by |
|---|---|---|
| Outgoing message | queued → sent / degraded / failed / indeterminate; failed → queued (user retry) | SEND, OUTCOME, RESEND, SWEEP |
| Incoming message | unread → read | RECV, DISPLAY, SWEEP |
| Contact trust | §8.3 diagram | RECV, KEYDEC, user actions |
| Establishment | card_only → fetching → ready (only through `EST-READY`, also when an inbound PreKey built the session first; §21.7); fetching → unreachable after three attempts → fetching (user retry); ready → fetching (reset, reconnect, stale session at a user send) | EST-START, BUNDLE, EST-READY, EST-END |
| Pending send | waiting → encrypted and enqueued (BUNDLE) / failed (`fail_after_hour`) | SEND, BUNDLE, SWEEP |
| Key registration | pending (⇄ inflight) → done → deleted after `valid_until_hour`; done → pending (healing) | REGROWS, work lane |
| Pair roots | offered → acknowledged (root erased) → superseded (stops advancing; keys erased by window) | SEND, RECV, KEYDEC, reconnect, 13-week replacement |
| Owner week | not published → published (per ISO week) | OWNER-WEEK |
| Scheduled control | due → sent (SEND) / cancelled (block, delete, user send first) | Reconnect, Revocation, SWEEP |

### 13.6 Schema v4 (normative; migration 4, one transaction, append-only, fail-closed; G-9, E-5)

Migration 4 runs in the helper's transaction (R-code F1). It first asserts `PRAGMA legacy_alter_table` is 0 (off) and fails closed otherwise. Steps, in order:

**Step 0: guard and drop the unused v1 DM tables** (no production writer: `Repositories.kt` writes only `identity`, `invite_nonces`, `revocations`).

```sql
CREATE TABLE v4_migration_guard (row_count INTEGER NOT NULL CHECK (row_count = 0));
INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM messages;
INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM conversations;
INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM contacts;
INSERT INTO v4_migration_guard(row_count) SELECT count(*) FROM signal_state;
DROP TABLE v4_migration_guard;
DROP INDEX idx_messages_conversation;
DROP INDEX idx_messages_expiry;
DROP TABLE messages;
DROP TABLE conversations;
DROP TABLE contacts;
DROP TABLE signal_state;
```

`devices` (P2), `revocations` (Phase 3 writer), `media`/`media_blobs` (Phase 11), `channels`/`channel_pseudonyms`/`mls_state`/`posts` (Phase 10) stay. S3 confirms the v1 index names from `Schema.kt:88-89`.

**Step 1: rebuild `outbox_op` and `outbox_delivery` to admit TTL 3600** (SQLite cannot alter a CHECK; the v2 CHECK is frozen, `Schema.kt:25-27, 245`).

1. `CREATE TABLE outbox_op_v4 (…)`: the v2 definition verbatim (`Schema.kt:240-253`) except `ttl_seconds IN (3600, 86400, 604800, 2592000, 7776000)`. `outbox_op` is a rowid table (no INTEGER PRIMARY KEY alias).
2. `CREATE TABLE outbox_delivery_v4 (…)`: the v2 definition verbatim (`Schema.kt:259-273`) with `REFERENCES outbox_op_v4(operation_id) ON DELETE CASCADE`; WITHOUT ROWID.
3. Copy with explicit column lists (E-5):
   ```sql
   INSERT INTO outbox_op_v4(rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute,
                            deadline_hour, required_operators, outcome, released)
   SELECT rowid, operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute,
          deadline_hour, required_operators, outcome, released
   FROM outbox_op;
   INSERT INTO outbox_delivery_v4(operation_id, relay_id, state, attempts, next_attempt_minute, inflight, lease_hour,
                                  copy_hour, ack_minute, strikes)
   SELECT operation_id, relay_id, state, attempts, next_attempt_minute, inflight, lease_hour, copy_hour, ack_minute, strikes
   FROM outbox_delivery;
   ```
   The new tables have no triggers yet, so `outbox_delivery_insert` (which refuses non-pending rows) does not fire. Rowids are preserved because the v3 guard `outbox_op_rowid` protects them.
4. `DROP TABLE outbox_delivery;` The child goes first: with `foreign_keys = ON`, dropping the parent first would cascade-delete the deliveries (an implicit DELETE runs FK actions but no triggers).
5. `DROP TABLE outbox_op;` This removes its 5 v2 triggers and the 2 v3 guards with it.
6. `ALTER TABLE outbox_op_v4 RENAME TO outbox_op; ALTER TABLE outbox_delivery_v4 RENAME TO outbox_delivery;` With `legacy_alter_table = OFF`, SQLite rewrites the FK reference in the delivery table to `outbox_op`.
7. Recreate `idx_outbox_op_open`, `idx_outbox_delivery_due`, `idx_outbox_delivery_relay`; then the 8 v2 triggers (`outbox_op_immutable`, `outbox_op_payload`, `outbox_op_outcome`, `outbox_op_release`, `outbox_op_delete`, `outbox_delivery_insert`, `outbox_delivery_state`, `outbox_delivery_copy`); then the 2 v3 guards (`outbox_op_no_replace`, `outbox_op_rowid`). Each text is one Kotlin constant shared with migrations 2 and 3, so it cannot drift.
8. `PRAGMA foreign_key_check` must return no row; otherwise the migration throws and the transaction rolls back.

**Test (G-9; corrected by §21.13).** S3 first lists every `sqlite_master` object whose SQL names `outbox_op` or `outbox_delivery`; the migration test asserts that trigger and index rows are identical by (type, name, sql), that the two tables are equal by `PRAGMA table_info`, `foreign_key_list` and `index_list` plus SQL normalized for identifier quoting, with the `ttl_seconds` CHECK as the only difference, and that every row and `outbox_op` rowid is preserved on fixtures holding ops and deliveries in every state, in-flight leases and every outcome.

**Step 2: relay expiry of fetched blobs** (§10.3).

```sql
ALTER TABLE inbox_blob ADD COLUMN relay_expiry_hour INTEGER
  CHECK (relay_expiry_hour IS NULL OR (typeof(relay_expiry_hour) = 'integer' AND relay_expiry_hour % 3600 = 0));
CREATE TRIGGER inbox_blob_relay_expiry_insert BEFORE INSERT ON inbox_blob
WHEN NEW.relay_expiry_hour IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'relay expiry is kept only while fetched'); END;
CREATE TRIGGER inbox_blob_relay_expiry_update BEFORE UPDATE OF state, relay_expiry_hour ON inbox_blob
WHEN NEW.relay_expiry_hour IS NOT NULL AND NEW.state <> 'fetched'
BEGIN SELECT RAISE(ABORT, 'relay expiry is kept only while fetched'); END;
```

**Step 3: capability source and the DM send-delay rule.**

```sql
ALTER TABLE sync_namespace ADD COLUMN capability_source TEXT NOT NULL DEFAULT 'redeem'
  CHECK (capability_source IN ('redeem', 'local'));
CREATE TRIGGER sync_namespace_dm_delay BEFORE UPDATE OF send_delay ON sync_namespace
WHEN NEW.consumer = 'dm' AND NEW.send_delay = 'off'
BEGIN SELECT RAISE(ABORT, 'DM namespaces cannot turn the send delay off'); END;
CREATE TRIGGER sync_namespace_dm_delay_insert BEFORE INSERT ON sync_namespace
WHEN NEW.consumer = 'dm' AND NEW.send_delay = 'off'
BEGIN SELECT RAISE(ABORT, 'DM namespaces cannot turn the send delay off'); END;
```

**Step 4: key registrations.**

```sql
CREATE TABLE relay_key_registration (
  relay_id            INTEGER NOT NULL REFERENCES relay_directory(relay_id) ON DELETE CASCADE,
  namespace_id        BLOB NOT NULL REFERENCES sync_namespace(namespace_id) ON DELETE CASCADE,
  period_id           INTEGER NOT NULL CHECK (typeof(period_id) = 'integer' AND period_id >= 0),
  kind                TEXT NOT NULL CHECK (kind IN ('read', 'deposit')),
  verifier            BLOB NOT NULL CHECK (length(verifier) = 32),
  request_id          BLOB NOT NULL CHECK (length(request_id) = 16),
  state               TEXT NOT NULL CHECK (state IN ('pending', 'done')),
  inflight            INTEGER NOT NULL DEFAULT 0 CHECK (inflight IN (0, 1)),
  lease_hour          INTEGER CHECK (lease_hour IS NULL OR (typeof(lease_hour) = 'integer' AND lease_hour % 3600 = 0)),
  attempts            INTEGER NOT NULL DEFAULT 0 CHECK (typeof(attempts) = 'integer' AND attempts >= 0),
  next_attempt_minute INTEGER NOT NULL CHECK (typeof(next_attempt_minute) = 'integer' AND next_attempt_minute % 60 = 0),
  valid_until_hour    INTEGER CHECK (valid_until_hour IS NULL OR (typeof(valid_until_hour) = 'integer' AND valid_until_hour % 3600 = 0)),
  CHECK ((state = 'done') = (valid_until_hour IS NOT NULL)),
  CHECK (inflight = 0 OR lease_hour IS NOT NULL),
  CHECK (state = 'pending' OR inflight = 0),
  PRIMARY KEY (relay_id, namespace_id, period_id, kind)
) WITHOUT ROWID;
```

**Step 5: messaging and libsignal tables.** Every table: random keys (WITHOUT ROWID) or a libsignal id, no created/last-activity column, time columns `*_minute` (Unix seconds, `% 60 = 0`), `*_hour` (`% 3600 = 0`) or `*_day` (day index) with `typeof = 'integer'`; content columns are envelopes `nonce(12) ‖ ChaCha20-Poly1305(content_key, AD = the row key)` (28 bytes of overhead).

```sql
CREATE TABLE dm_self (
  id                  INTEGER PRIMARY KEY CHECK (id = 1),
  registration_id     INTEGER NOT NULL CHECK (typeof(registration_id) = 'integer' AND registration_id BETWEEN 1 AND 16380),
  card_index          INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
  seen_key            BLOB NOT NULL CHECK (length(seen_key) = 32),
  content_key_wrapped BLOB NOT NULL CHECK (length(content_key_wrapped) BETWEEN 40 AND 256),
  bundle_week         INTEGER CHECK (bundle_week IS NULL OR (typeof(bundle_week) = 'integer' AND bundle_week >= 0)),
  expiry_clock_minute INTEGER NOT NULL CHECK (typeof(expiry_clock_minute) = 'integer' AND expiry_clock_minute % 60 = 0),
  accept_after_minute INTEGER CHECK (accept_after_minute IS NULL
                                     OR (typeof(accept_after_minute) = 'integer' AND accept_after_minute % 60 = 0)),
  bundle_published_week INTEGER CHECK (bundle_published_week IS NULL
                                       OR (typeof(bundle_published_week) = 'integer' AND bundle_published_week >= 0))   -- §21.8
);

CREATE TABLE dm_own_namespace (
  namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32),
  role         TEXT NOT NULL CHECK (role IN ('inbox', 'bundle')),
  card_index   INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
  UNIQUE (role, card_index)
) WITHOUT ROWID;

CREATE TABLE dm_contact (
  contact_id        BLOB PRIMARY KEY NOT NULL CHECK (length(contact_id) = 16),
  identity_pk       BLOB NOT NULL UNIQUE CHECK (length(identity_pk) = 32),
  card_env          BLOB CHECK (card_env IS NULL OR length(card_env) = 191),              -- card(163) + 28
  card_index        INTEGER NOT NULL CHECK (typeof(card_index) = 'integer' AND card_index BETWEEN 0 AND 65535),
  pinned_identity   BLOB CHECK (pinned_identity IS NULL OR length(pinned_identity) = 33),
  pending_identity  BLOB CHECK (pending_identity IS NULL OR length(pending_identity) = 33),
  bundle_week_seen  INTEGER CHECK (bundle_week_seen IS NULL OR (typeof(bundle_week_seen) = 'integer' AND bundle_week_seen >= 0)),
  trust_state       TEXT NOT NULL CHECK (trust_state IN ('request', 'unverified', 'verified', 'changed', 'blocked', 'revoked')),
  source            TEXT NOT NULL CHECK (source IN ('qr_in_person', 'link', 'request')),
  establishment     TEXT NOT NULL CHECK (establishment IN ('card_only', 'fetching', 'ready', 'unreachable')),
  fetch_attempts    INTEGER NOT NULL DEFAULT 0 CHECK (fetch_attempts BETWEEN 0 AND 3),                                -- §21.7
  fetch_listen_until_minute INTEGER CHECK (fetch_listen_until_minute IS NULL
                                           OR (typeof(fetch_listen_until_minute) = 'integer' AND fetch_listen_until_minute % 60 = 0)),
  reset_needed      INTEGER NOT NULL DEFAULT 0 CHECK (reset_needed IN (0, 1)),
  verified_fp       BLOB CHECK (verified_fp IS NULL OR length(verified_fp) = 32),
  name_env          BLOB CHECK (name_env IS NULL OR length(name_env) BETWEEN 29 AND 284),
  request_until_day INTEGER CHECK (request_until_day IS NULL OR (typeof(request_until_day) = 'integer' AND request_until_day >= 0)),
  CHECK ((trust_state = 'changed') = (pending_identity IS NOT NULL)),
  CHECK ((trust_state = 'request') = (request_until_day IS NOT NULL)),
  CHECK (trust_state IN ('blocked', 'revoked') OR card_env IS NOT NULL),
  CHECK (trust_state <> 'changed' OR pinned_identity IS NOT NULL),
  CHECK (pending_identity IS NULL OR pending_identity IS NOT pinned_identity),
  CHECK ((establishment = 'fetching') = (fetch_listen_until_minute IS NOT NULL))
) WITHOUT ROWID;

CREATE TABLE dm_pair_key (           -- in: keys I accept (window); out: the key I seal with
  contact_id BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  direction  TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  root_gen   INTEGER NOT NULL CHECK (typeof(root_gen) = 'integer' AND root_gen BETWEEN 0 AND 65535),
  week       INTEGER NOT NULL CHECK (typeof(week) = 'integer' AND week >= 0),
  week_key   BLOB NOT NULL CHECK (length(week_key) = 32),
  PRIMARY KEY (contact_id, direction, root_gen, week)
) WITHOUT ROWID;

CREATE TABLE dm_pair_offer (         -- my root for c → me, kept only until its first key is computed and acknowledged
  contact_id   BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  root_gen     INTEGER NOT NULL CHECK (typeof(root_gen) = 'integer' AND root_gen BETWEEN 0 AND 65535),
  root         BLOB CHECK (root IS NULL OR length(root) = 32),                            -- NULL once erased
  base_week    INTEGER NOT NULL CHECK (typeof(base_week) = 'integer' AND base_week >= 0),
  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
  PRIMARY KEY (contact_id, root_gen)
) WITHOUT ROWID;

CREATE TABLE dm_conversation (
  conversation_id BLOB PRIMARY KEY NOT NULL CHECK (length(conversation_id) = 16),
  contact_id      BLOB NOT NULL UNIQUE REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  timer_code      INTEGER NOT NULL DEFAULT 4 CHECK (timer_code BETWEEN 0 AND 5),          -- 7 d (ADR-27 point 7)
  timer_version   INTEGER NOT NULL DEFAULT 0 CHECK (typeof(timer_version) = 'integer' AND timer_version >= 0)
) WITHOUT ROWID;

CREATE TABLE dm_message (
  message_id             BLOB PRIMARY KEY NOT NULL CHECK (length(message_id) = 16),
  conversation_id        BLOB NOT NULL REFERENCES dm_conversation(conversation_id) ON DELETE CASCADE,
  direction              TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  kind                   INTEGER NOT NULL CHECK (kind IN (1, 2)),                           -- TEXT, TIMER_SET notice
  author_minute          INTEGER NOT NULL CHECK (typeof(author_minute) = 'integer' AND author_minute % 60 = 0),
  sort_minute            INTEGER NOT NULL CHECK (typeof(sort_minute) = 'integer' AND sort_minute % 60 = 0 AND sort_minute <= author_minute),
  minute_index           INTEGER NOT NULL CHECK (minute_index BETWEEN 0 AND 65535),
  timer_code             INTEGER NOT NULL CHECK (timer_code BETWEEN 0 AND 5),
  body_env               BLOB CHECK (body_env IS NULL OR length(body_env) BETWEEN 30 AND 61485),   -- flags ‖ quote_ref? ‖ body; no quote_ref column (§21.8)
  state                  TEXT NOT NULL CHECK (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate', 'unread', 'read')),
  expire_at_minute       INTEGER CHECK (expire_at_minute IS NULL OR (typeof(expire_at_minute) = 'integer' AND expire_at_minute % 60 = 0)),
  unread_deadline_minute INTEGER CHECK (unread_deadline_minute IS NULL
                                        OR (typeof(unread_deadline_minute) = 'integer' AND unread_deadline_minute % 60 = 0)),
  delete_at_minute       INTEGER CHECK (delete_at_minute IS NULL OR (typeof(delete_at_minute) = 'integer' AND delete_at_minute % 60 = 0)),
  CHECK ((direction = 'out') = (state IN ('queued', 'sent', 'degraded', 'failed', 'indeterminate'))),
  CHECK (direction = 'in' OR sort_minute = author_minute),
  CHECK ((kind = 1) = (body_env IS NOT NULL)),
  CHECK (timer_code <> 0 OR (expire_at_minute IS NULL AND unread_deadline_minute IS NULL)),
  CHECK (timer_code = 0 OR direction = 'in' OR expire_at_minute IS NOT NULL),
  CHECK (timer_code = 0 OR direction = 'out' OR unread_deadline_minute IS NOT NULL),
  CHECK (state <> 'read' OR timer_code = 0 OR expire_at_minute IS NOT NULL),
  CHECK (delete_at_minute IS (CASE WHEN expire_at_minute IS NOT NULL THEN expire_at_minute ELSE unread_deadline_minute END))
) WITHOUT ROWID;
CREATE INDEX idx_dm_message_order  ON dm_message(conversation_id, sort_minute, minute_index, message_id);
CREATE INDEX idx_dm_message_delete ON dm_message(delete_at_minute) WHERE delete_at_minute IS NOT NULL;

CREATE TABLE dm_outbound_item (       -- every outgoing L0, all kinds (§21.8)
  item_id       BLOB PRIMARY KEY NOT NULL CHECK (length(item_id) = 16),                     -- the L0 message_id
  contact_id    BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  message_ref   BLOB REFERENCES dm_message(message_id) ON DELETE CASCADE,                  -- TEXT, TIMER_SET: itself; REACTION: target
  kind          INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
  control       TEXT CHECK (control IS NULL OR control IN ('reconnect', 'revocation', 'reset')),
  l0_env        BLOB CHECK (l0_env IS NULL OR length(l0_env) BETWEEN 29 AND 65564),
  deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
  state         TEXT NOT NULL CHECK (state IN ('pending', 'enqueued', 'sent', 'degraded', 'failed', 'indeterminate')),
  CHECK ((kind = 4) = (control IS NOT NULL)),
  CHECK (kind = 4 OR message_ref IS NOT NULL)
) WITHOUT ROWID;

CREATE TABLE dm_outbound_op (
  operation_id  BLOB PRIMARY KEY NOT NULL CHECK (length(operation_id) = 16),
  purpose       TEXT NOT NULL CHECK (purpose IN ('item', 'bundle')),                         -- §21.8
  item_id       BLOB REFERENCES dm_outbound_item(item_id) ON DELETE CASCADE,
  bundle_week   INTEGER CHECK (bundle_week IS NULL OR (typeof(bundle_week) = 'integer' AND bundle_week >= 0)),
  blob          BLOB CHECK (blob IS NULL OR length(blob) IN (4096, 16384, 65536)),          -- retained for RESEND
  resend_count  INTEGER NOT NULL DEFAULT 0 CHECK (resend_count BETWEEN 0 AND 2),
  deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
  CHECK ((purpose = 'item') = (item_id IS NOT NULL)),
  CHECK ((purpose = 'bundle') = (bundle_week IS NOT NULL))
) WITHOUT ROWID;
CREATE INDEX idx_dm_outbound_op_item ON dm_outbound_op(item_id) WHERE item_id IS NOT NULL;

CREATE TABLE dm_pending_send (
  item_id         BLOB PRIMARY KEY NOT NULL REFERENCES dm_outbound_item(item_id) ON DELETE CASCADE,   -- §21.8
  contact_id      BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  fail_after_hour INTEGER NOT NULL CHECK (typeof(fail_after_hour) = 'integer' AND fail_after_hour % 3600 = 0)
) WITHOUT ROWID;

CREATE TABLE dm_bundle_candidate (    -- the best verified bundle of an attempt (§21.7)
  contact_id   BLOB PRIMARY KEY NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  bundle_env   BLOB NOT NULL CHECK (length(bundle_env) = 1918),
  bundle_week  INTEGER NOT NULL CHECK (typeof(bundle_week) = 'integer' AND bundle_week >= 0),
  issued_hour  INTEGER NOT NULL CHECK (typeof(issued_hour) = 'integer' AND issued_hour % 3600 = 0)
) WITHOUT ROWID;

CREATE TABLE dm_orphan_namespace (    -- namespaces of blocked or deleted contacts, removed by SWEEP (§21.12)
  namespace_id BLOB PRIMARY KEY NOT NULL CHECK (length(namespace_id) = 32)
) WITHOUT ROWID;

CREATE TABLE dm_scheduled (
  sched_id   BLOB PRIMARY KEY NOT NULL CHECK (length(sched_id) = 16),
  contact_id BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  what       TEXT NOT NULL CHECK (what IN ('reconnect', 'revocation')),
  payload    BLOB CHECK (payload IS NULL OR length(payload) = 102),                         -- revocation certificate v2
  due_minute INTEGER NOT NULL CHECK (typeof(due_minute) = 'integer' AND due_minute % 60 = 0),
  CHECK ((what = 'revocation') = (payload IS NOT NULL)),
  UNIQUE (contact_id, what)
) WITHOUT ROWID;

CREATE TABLE dm_held (
  held_id           BLOB PRIMARY KEY NOT NULL CHECK (length(held_id) = 16),
  contact_id        BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  identity          BLOB NOT NULL CHECK (length(identity) = 33),
  l1_env            BLOB NOT NULL CHECK (length(l1_env) BETWEEN 29 AND 65564),
  hold_until_minute INTEGER NOT NULL CHECK (typeof(hold_until_minute) = 'integer' AND hold_until_minute % 60 = 0),
  relay_expiry_hour INTEGER NOT NULL CHECK (typeof(relay_expiry_hour) = 'integer' AND relay_expiry_hour % 3600 = 0),   -- §21.10
  consume_minute    INTEGER NOT NULL CHECK (typeof(consume_minute) = 'integer' AND consume_minute % 60 = 0)
) WITHOUT ROWID;

CREATE TABLE dm_reaction (
  target_id    BLOB NOT NULL REFERENCES dm_message(message_id) ON DELETE CASCADE,
  from_self    INTEGER NOT NULL CHECK (from_self IN (0, 1)),
  grapheme_env BLOB NOT NULL CHECK (length(grapheme_env) BETWEEN 29 AND 60),
  PRIMARY KEY (target_id, from_self)
) WITHOUT ROWID;

CREATE TABLE dm_seen (                 -- D3: a keyed tag and its day, nothing else
  tag       BLOB PRIMARY KEY NOT NULL CHECK (length(tag) = 16),
  until_day INTEGER NOT NULL CHECK (typeof(until_day) = 'integer' AND until_day >= 0 AND until_day % 7 = 0)
) WITHOUT ROWID;

-- libsignal records (opaque; spec §8)
CREATE TABLE sig_session (
  contact_id BLOB PRIMARY KEY NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
  record     BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 1048576)     -- backstop; the store throws SessionRecordOversizeException first (§21.5)
) WITHOUT ROWID;
CREATE TABLE sig_signed_prekey (
  prekey_id        INTEGER PRIMARY KEY NOT NULL CHECK (prekey_id BETWEEN 1 AND 16777215),
  record           BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 4096),
  superseded_day   INTEGER CHECK (superseded_day IS NULL OR (typeof(superseded_day) = 'integer' AND superseded_day >= 0)),
  delete_after_day INTEGER CHECK (delete_after_day IS NULL OR (typeof(delete_after_day) = 'integer' AND delete_after_day >= 0)),
  CHECK ((superseded_day IS NULL) = (delete_after_day IS NULL))
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_sig_signed_current ON sig_signed_prekey((superseded_day IS NULL)) WHERE superseded_day IS NULL;
CREATE TABLE sig_kyber_prekey (
  prekey_id        INTEGER PRIMARY KEY NOT NULL CHECK (prekey_id BETWEEN 1 AND 16777215),
  record           BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 8192),
  superseded_day   INTEGER CHECK (superseded_day IS NULL OR (typeof(superseded_day) = 'integer' AND superseded_day >= 0)),
  delete_after_day INTEGER CHECK (delete_after_day IS NULL OR (typeof(delete_after_day) = 'integer' AND delete_after_day >= 0)),
  CHECK ((superseded_day IS NULL) = (delete_after_day IS NULL))
) WITHOUT ROWID;
CREATE UNIQUE INDEX idx_sig_kyber_current ON sig_kyber_prekey((superseded_day IS NULL)) WHERE superseded_day IS NULL;
CREATE TABLE sig_kyber_reuse (         -- last-resort reuse tuples (D2); a conflict is the replay signal
  kyber_prekey_id  INTEGER NOT NULL REFERENCES sig_kyber_prekey(prekey_id) ON DELETE CASCADE,
  signed_prekey_id INTEGER NOT NULL CHECK (signed_prekey_id BETWEEN 1 AND 16777215),
  base_key         BLOB NOT NULL CHECK (length(base_key) = 33),
  PRIMARY KEY (kyber_prekey_id, signed_prekey_id, base_key)
) WITHOUT ROWID;
```

**Step 6: triggers and guards; `CURRENT_VERSION = 4`; `expectedTables` and `expectedTriggers` updated.**

| Trigger | Rule |
|---|---|
| `dm_self_fixed` | `id`, `registration_id` and `seen_key` immutable; `card_index` immutable in Phase 9 (Phase 13 drops this trigger for cut-off rotation) |
| `dm_self_monotonic` | `bundle_week` and `expiry_clock_minute` never decrease |
| `dm_contact_identity` | `contact_id`, `identity_pk` immutable |
| `dm_contact_pin` | `pinned_identity` changes only from NULL (pin), or to `OLD.pending_identity` while `OLD.trust_state = 'changed'` (KEYDEC) |
| `dm_contact_trust` | only the transitions of §8.3 and §12; `revoked` is terminal |
| `dm_message_identity` | no update of any column other than `state` and the three expiry columns (no edits in Phase 9) |
| `dm_message_state` | `queued → sent, degraded, failed, indeterminate`; `failed → queued`; `unread → read`; nothing else |
| `dm_message_expiry`, `dm_held_expiry` | `expire_at_minute`, `unread_deadline_minute` and `hold_until_minute`, once non-NULL, only decrease (NULL-safe, R-T6); `delete_at_minute` follows its CHECK and may move later at display (§21.10) |
| `dm_conversation_timer` | `timer_version` never decreases |
| `dm_held_limit` | at most 256 rows per contact (an insert beyond aborts; RECV deletes the oldest first, counted) |
| `dm_pair_offer_root` | `root` may only become NULL; `acknowledged` only 0 → 1 |
| `sig_prekey_superseded` (both prekey tables) | `record` immutable; `superseded_day` and `delete_after_day` write-once |
| `sig_kyber_reuse_append_only` | no update; delete only by cascade |
| `relay_key_registration_state` | `verifier`, `kind`, `period_id` immutable; `pending → done`, `done → pending` (healing) only |
| `<table>_no_replace` | REPLACE guards (Phase 8 §19.21 point 4) for `dm_self`, `dm_own_namespace`, `dm_contact` (both keys), `dm_conversation` (both keys), `dm_message`, `dm_outbound_item`, `dm_outbound_op`, `dm_pending_send`, `dm_bundle_candidate`, `dm_orphan_namespace`, `dm_scheduled`, `dm_held`, `dm_reaction`, `dm_pair_offer`, `sig_signed_prekey`, `sig_kyber_prekey`, `sig_kyber_reuse`, `relay_key_registration` (§21.6, §21.14). `dm_seen` inserts with `INSERT OR IGNORE` (which deletes nothing); `sig_session`, `sig_*_prekey` and `dm_pair_key` are written with UPDATE-then-INSERT pairs. No `REPLACE`, `INSERT OR REPLACE` or UPSERT anywhere in DM code (gate G-DM4) |

**R-M3 (introspection; T20, T33).** The exact set of time columns added by v4 is: `inbox_blob.relay_expiry_hour`; `relay_key_registration.{lease_hour, next_attempt_minute, valid_until_hour}`; `dm_self.{expiry_clock_minute, accept_after_minute}`; `dm_contact.{fetch_listen_until_minute, request_until_day}`; `dm_message.{author_minute, sort_minute, expire_at_minute, unread_deadline_minute, delete_at_minute}`; `dm_outbound_item.deadline_hour`; `dm_outbound_op.deadline_hour`; `dm_pending_send.fail_after_hour`; `dm_bundle_candidate.issued_hour`; `dm_scheduled.due_minute`; `dm_held.{hold_until_minute, relay_expiry_hour, consume_minute}`; `dm_seen.until_day`; `sig_signed_prekey.{superseded_day, delete_after_day}`; `sig_kyber_prekey.{superseded_day, delete_after_day}`. Period indices (`bundle_week`, `bundle_week_seen`, `bundle_published_week`, `week`, `base_week`, `period_id`) are integer indices with `typeof` CHECKs (§21.14). The sync set grows from 11 to 15 columns. A test lists every column of every table and fails on any other time-like name. **R-M4:** no `CREATE VIRTUAL TABLE` (gate `dm-no-fts.sh`). **R-M1:** after every message of a conversation has expired, a full dump shows only the contact, its trust and establishment state, the conversation's timer code and version, and unlinked `dm_seen` tags.

**Migration tests (CS-9).** Every upgrade path (v1, v2, v3 → v4) on populated fixtures (outbox ops in every delivery state, in-flight leases, every outcome, `ent_*` rows); an interruption at every statement of migration 4 (`FaultySqlExecutor`), after which the reopened database is the previous version and migrates; after migration identical rows and rowids, the exact trigger set, an empty `foreign_key_check`, `integrity_check = ok`; the guard aborts when any v1 DM table holds a row; `legacy_alter_table` on → refused; `ReplaceGuardsTest` extended to every new guard. The emulator job repeats v3 → v4 on real SQLCipher (§15.9).

### 13.7 Threads, background, wiring (normative)

- **DM actor.** One process-wide single-thread executor (`ghost-dm`) owns every `:messaging` transaction and every libsignal call (§2.4 rule 5). It is woken by: listener hints (`SyncChange.INBOX`, `OUTCOMES`, `CAPABILITIES`, `TOPOLOGY`), facade calls, the in-process expiry timer, the alarm receiver, the database open, and the `ConsumerTail`. Hints carry no payload and the actor re-reads state, so a lost or duplicated hint is harmless.
- **No work on lane threads.** `Inbox.setListener` (one slot, unused until Phase 9, `Inbox.kt:26`) fires on the committing thread, which can be a lane thread (`SyncDatabase.kt:16-19`); the listener only posts a coalesced flag to the actor (test: "the listener returns without touching the database"). Phase 10 will turn the slot into a fan-out in `:app`; the API stays unchanged.
- **Actor pass** (split by §21.9). Every pass (until empty or the deadline): SWEEP → OUTCOME loop → BUNDLE claims (`Consumer.PREKEYS`) → RECV claims (`Consumer.DM`; one blob at a time in the `ConsumerTail`, none while the native library or DM keys are unavailable, §21.12) → HELD replays → reschedule the timer and the alarm. Only a **time-triggered** pass (the actor timer, database open, a relay session start) also runs OWNER-WEEK and re-seals, the week-change parts of KEEPER and REGROWS, scheduled controls due, `EST-READY`, `EST-END` and expired pending items.
- **Background.** The Phase 7 JobScheduler job (one periodic job, no extras, ADR-20), the `ConsumerTail` in background sessions and quiet runs (§13.3 item 6), plus the inexact alarm (§10.7). No FCM, no WorkManager, no coroutines, no foreground service.
- **Wiring.** `MessagingWiring` (in `:app`) creates the actor after the sync controller, sets the listener and the tail at process start, wires the `IdentityActivationHook` (§13.4), and runs a sweep, R-K1 and the resumable ACTIVATE check (§21.12) at the first database open. Lock and wipe zeroize the in-memory derived keys; wipe also cancels the alarm.

### 13.8 Keys at rest (normative; C-23)

- **Never stored:** the libsignal identity private key, `card_secret`, the intro private key, inbox read secrets, the schedule key (all re-derived at unlock from the Keystore-wrapped seed and held only by the DM actor; zeroized on lock and wipe).
- **Stored in SQLCipher:** prekey records, session records, pair keys and offers (erased on schedule, §6.3, T34), `seen_key`.
- **Content key:** 32 random bytes, stored wrapped (`nonce(12) ‖ AES-256-GCM(32) ‖ tag(16)`, 60 bytes on the reference provider) by a non-exportable Android Keystore key created with **the same authentication policy as the database-key wrapper** (not authentication-bound by default, ADR-20 Q6). `body_env`, `card_env`, `name_env`, `grapheme_env`, `l1_env` are ChaCha20-Poly1305 under it with the row's key as AD. Purpose: the "no plaintext content column" rule (`Schema.kt:7`), a meaningful T25 byte scan, and no plaintext in SQLite freed pages even before `secure_delete` runs. It adds no secrecy against AD-8 with the database unlocked. JVM tests use an in-memory wrapper port.

---

## 14. Invariants (new T26–T34; changes to T1, T3, T9, T13, T19, T20, T21, T25)

### 14.1 New invariants (normative; Romanian rows for INVARIANTS.md in Appendix B.2)

| ID | Invariant | Verification | Executable from | Code |
|---|---|---|---|---|
| **T26** Relay-blind DM addressing | No relay-visible value (namespace, verifier, credential, stored byte, capture field) is computable from public identity material (`ghost1`, Ed25519 key, libsignal identity key, safety number) without a card or the seed: every DM derivation takes `m`, a `card_secret` or a random root as its key input; relay sets are `set(ns, w)`; every relay-stored DM byte is sealed under keys never presented to a relay (Rule V1); no libsignal header byte string appears outside the seal | derivation vectors; static check of every `DmLabels`/`CardLabels` call site (IKM type, gate G-DM3); JD1, JD2, JD9; the model relay tries to open every stored blob with every secret it was shown (must open 0); S-DM3; mutants PM-3, PM-13, PM-20, PM-24 | Phase 9 | `:crypto-bridge`, `:messaging`, DM world |
| **T27** Sender-indistinguishable deposits; DM-independent tokens | Every store into one inbox namespace at one relay with a deposit credential presents the same credential scope, in every week and whatever the sender's clock or earlier refusals (§21.2); no honest client redeems or registers for a namespace it does not own (LOCAL needs are never redeemed); a client's redemptions and registrations (count, minute, relay, namespace) are identical in worlds that differ only in its DM activity, below quota exhaustion; a registration never replaces another | JD3, JD8; NI-DM3; `register.txt`; the planner test for LOCAL; NI-DM6; mutants PM-1, PM-1b, PM-21, PM-23, PM-26, PM-27, PM-28 | Phase 9 | relay, `:sync`, `:entitlement`, `:messaging` |
| **T28** No reflex traffic | Processing any inbound blob (valid, malformed, duplicate, replayed, reordered, undecryptable, forged, key-changed, request, probe, poison) enqueues nothing, redeems nothing, registers nothing, changes no read schedule and does not change the relay session's close time; every DM store maps to a user action, a scheduled user action, the owner's weekly bundle, or an automatic identical resend of the user's own INDETERMINATE op | `NoReflexTest` (call graph, gate G-DM2); NI-DM1 (with session close times); JD6; mutants PM-2, PM-6, PM-25 | Phase 9 | `:messaging`, `:sync`, DM world |
| **T29** Uniform, type-hiding blobs | DM envelopes and bundles are exactly 4, 16 or 64 KiB, with the bucket a function of the L0 length only (never 1 KiB); all lengths and zero padding inside the AEAD; non-canonical blobs refused; bytes uniform (salt, PRF hint, AEAD output) | property test over kinds × lengths × modes × session states; byte-frequency χ² per offset on 10 000 blobs; golden sizes; NI-DM2; mutants PM-4, PM-12, ME-1…ME-4 | Phase 9 | `:crypto-bridge`, DM world |
| **T30** TTL mapping and bounded relay lifetime | Relay TTL = the §10.1 table; the relay accepts exactly the five buckets (`rejected_ttl` otherwise) and captures the stored bucket in seconds; every DM op has the deadline `author + min(bucket, 7 d)` and no copy is stored after it; an honest relay's copy is gone by `deadline_hour + bucket + 1 h`; a relay promising longer storage is detected at the receipt | relay and client vectors; capture-check fixtures (3600 positive; 7200 and the old field negative); JD5; client receipt upper-bound test; mutants PM-5, PM-9, ME-14, ME-15 | Phase 9 | relay, `client-core/net`, `:sync`, `:messaging` |
| **T31** Read confinement; activity-independent owner writes | A client lists and gets only its own namespaces (inbox, drops) and channels, plus one bundle fetch (at most three 15-minute attempts, §21.7) per establishment or explicit reset or reconnect; owner redemptions, registrations and bundle publications happen at times independent of contacts and activity; revocation and resets travel through recipients' inboxes as user sends; safety-number work, verification, acknowledgement, block and request decisions cause no network I/O | JD7; static check: `Namespaces.register(listen = true)` from `:messaging` only for own namespaces or the establishment steps; NI-DM3, NI-DM5; mutants PM-7, PM-8, PM-11 | Phase 9 | `:messaging`, DM world |
| **T32** DM unlinkability world | Exact joins JD1–JD9 find nothing; twins NI-DM1–NI-DM6 give identical shape views; no learned attacker on the full effective relay view beats the attacker restricted to LD on conversation edges or identity mappings (S-DM1, S-DM3 at α = 0.001); S-DM2, S-DM4 measured and reported against a recorded baseline | §15.6 | Phase 9 (PR scale in `android`; gate scale in `dm-privacy-gate.yml`) | `android/messaging/src/test/.../dmworld/`, `dm-report-check.sh` |
| **T33** Local DM forensic minimality | DM tables keep only `*_minute`/`*_hour`/`*_day` time columns with `typeof` CHECKs (R-M3) and period indices; no conversation activity time or counter; no persisted rejection history; random WITHOUT ROWID keys; no virtual table; content columns are envelopes under the content key; notifications carry a constant text only; libsignal calls receive minute-floored times and prekey records day-floored times | schema introspection; record-timestamp decode test; notification-port contract test; mutants PM-10, ME-12, ME-13, ME-18 | Phase 9 (JVM); device checklist | `:messaging`, `:storage` |
| **T34** Attribution forward secrecy of pair envelopes | For an ISO week w with `now ≥ start(w + 1) + 45 d`, no key stored on either device and nothing derivable from either seed opens a pair-mode envelope of week w: roots are random, travel only in acknowledged sessions and are erased, week keys are ratcheted and erased by the window; declared exception: a root carrier whose libsignal key survives as a skipped key (§21.3); intro envelopes remain attributable with the recipient's seed (declared) | seizure scenario (§15.6): dump both databases and seeds at day 70 of a world, try every stored key, every derivation and libsignal decryption with every retained prekey and session record on every archived blob (pair-mode opened for old weeks = the skipped-key ground truth, 0 in the lossless variant; intro-mode opened = ground truth); erasure unit tests at week boundaries; mutants PM-19, PM-29 | Phase 9 | `:crypto-bridge`, `:messaging`, DM world |

### 14.2 Changes to existing invariants

| ID | Change |
|---|---|
| T1 | `allowed-observables.json` v2: `op += register`; `key_kind` on `register`; `ttl_bucket_seconds` replaces `ttl_bucket_days`; `capability_scope` covers read and deposit keys |
| T3 | canaries add: the libsignal identity private key, session and prekey records, card secrets, pair keys, read and deposit secrets, inbox and bundle namespaces, safety-number digits, message plaintext; scanned in public strings, exception messages, `toString` of every DM type, **and every libsignal log line during an untrusted-identity decrypt with a recording logger** (E-18) |
| T9 | executable for DMs in Phase 9: bucket from content length, DM floor 4 KiB, uniform bytes (T29) |
| T13 | executable in Phase 9 (`android/messaging` tests): `author_minute` by type; `dm_content.txt` vectors |
| T19 | re-tested with DM activity (sends, consumption, sweeps, owner steps, registrations, key change, requests); temporary bundle pairs do not move other pairs |
| T20 | the sync time-column set gains `inbox_blob.relay_expiry_hour` and `relay_key_registration.{lease_hour, next_attempt_minute, valid_until_hour}` (15 columns); "one periodic job without extras" unchanged; the messaging layer holds one inexact alarm with no extras (X-11) |
| T21 | v3 credentials: the kind/operation matrix and the namespace checked before I/O; the circuit of the credential's namespace |
| T25 | wording: the relay observes only `bucket(timer)` of the §10.1 table (ADR-27 point 11), nothing finer; executable for DMs in Phase 9 (§10.9) |

---

## 15. Test plan and exit-gate argument (I11)

### 15.1 Infrastructure

- **`DmWorld`** (`android/messaging/src/test/.../harness/`), built on the Phase 7 harness through the shared-test-source pattern of `:entitlement` (`srcDir` of `storage/src/testShared` and the `:sync` harness, `friendPaths`, `excludeTestsMatching("org.ghost.sync.*")`; harness `-D` properties declared as test inputs; RC §8).
  - **Clients:** 2 to 6 per world (up to 600 in T32), each a real `:messaging` + `:crypto-bridge` + `:sync` stack on its own SQLite **file** (`JdbcSqlExecutor`, production pragmas; both `journal_mode = WAL` and `DELETE`), migrated to v4, with the real engine lanes driven by the `DeterministicDriver`.
  - **Real libsignal** through the `libsignal-client` desktop natives (linux-x86_64 in CI, windows-x86_64 on the owner's machine; **S0 blocking check**: if they do not load, the libsignal-dependent suites move to the emulator job with fewer seeds and the exit-gate argument is re-stated before S7). The seal and codec are Kotlin, so no host-native `libghost_client_net` build is needed (§2.8).
  - **Two capability variants:** (a) the *core world*, where a harness "redeem fairy" installs own write capabilities at the planner's times (fast: crash enumeration, reorder, replay, key change, T25); (b) the *entitlement world* on `EntHarness`, where the real redeem lane redeems trial tokens and the real work lane registers keys (JD8, week-boundary renewals, the registration healing rule).
  - **`ModelRelay` extensions**, conformance-pinned by `relay_semantics.txt` (TTL section) and `register.txt`, which the Rust relay also replays: `RegisterKey`, v3 credentials, verifier accumulation, the `DepositLedger`, exact TTL buckets with hour-rounded expiry, circuit labels (the effective view, RP F10). Hostile modes: the existing REWIND, REPEATS, WITHHOLD, WRONG_BYTES, STALL, SHORT_EXPIRY, plus **RESURRECT** (re-serve after the recipient's tombstone GC), **COPY_NAMESPACE**, **TRUNCATE**, **SHUFFLE**, **DELAY_RELEASE**, **LONG_EXPIRY**, **WITHHOLD_NEWEST_BUNDLE**, **LOSE_KEYS** (`keys.redb` lost), **ATTACKER_REGISTERS** (a card holder redeems and registers its own verifier).
  - **Faults:** `FaultySqlExecutor` (a crash before every statement, before and after commit, and `SQLITE_FULL` injection mapped to `StorageFullException`); `SimulatedNativeCrash` thrown from the `:crypto-bridge` port during RECV (the process-death model of a SIGSEGV); `HarnessDriver` interleavings of actor passes between lane items; a virtual clock with steps.
  - **Oracles:** `oracle_sent(message_id, outcome)` written in OUTCOME; `oracle_displayed(device, message_id)` with a primary key that catches a duplicate at the event that caused it; `oracle_user_action(op)` written by every facade call and by scheduled controls, so JD6 maps stores to actions; a recording `Outbox` wrapper that fails on an enqueue inside RECV, BUNDLE or HELD; a recording `SessionCipher.encrypt` counter per contact trust state.
- **Debug key-change hook** (test sources and the `gate` debug source set only): an identity whose libsignal key differs from the derived one but is bound by its real Ed25519 key (the "stolen seed on a modified client" scenario). Gate G-DM5 fails if the hook class, or any harness package, is in the release APK.

### 15.2 Unit, vector and property tests

- Derivation vectors for every `DmLabels` and `CardLabels` output; label prefix tests.
- Card codec: round trip; every single-byte mutation and every length refused; small-order `intro_pk` refused; alphabet; own card; index ≠ 0.
- Seal vectors `dm_seal.txt` (fixed keys, salts, ephemeral keys; pair, intro, bundle; every bucket) replayed by the production Kotlin code **and** by the independent JDK-provider implementation (§2.8).
- L0 vectors `dm_content.txt`; decoder property tests (10⁶ seeded inputs per CI run).
- Credential v3 and verifier vectors (shared with the Rust capability crate); `dm_relay_set.txt` (Kotlin and Rust).
- **Golden sizes** (S0, every bump) and **golden records** with `LibsignalUpgradeTest` (§2.4 rule 4).
- **PQ-3** (§9.2); record-timestamp granularity (session records minute, prekey records day).
- Safety-number vectors (fixed keys → digits and scannable bytes); `compareTo` mismatch cases; `pendingSafetyNumber`.
- **One-attempt test:** for any blob at most one AEAD open is attempted (counting spy), whatever the number of contacts (PM-18); hint-cost benchmark at 1 000 contacts (reported).
- **`SilentLoggerTest`** and the T3 libsignal log canary (§2.6).
- Store semantics: every row of the §8.2 table, including `saveIdentity` refusal and the Kyber reuse refusal.
- Schema v4: §13.6 migration tests; triggers (legal and illegal transitions); REPLACE guards; R-M1, R-M3, R-M4; the expired-row lint over every DAO query.
- `:sync`: `CapabilitySource` planner filter; the registration need rule; the work-lane registration step; credential selection (§13.3 item 7); `ConsumerTail` cases in `SessionParticipantTest`; T19 run (b) with registrations.

### 15.3 Crash enumeration (CS-1, CS-2; the F7 §8.3 method)

For each scenario: run it without faults and record K events (every `exec`, `execUpdate` and `query`, pre-commit and post-commit, and the model relay's before-send, after-apply and after-response events); for every k crash at k, reboot (drop the uncommitted connection, reopen the same file, migrate, `verifyIntegrity`, R-K1, build a new client: engine, actor, `TxSignalStores`, libsignal objects), check the structural invariants, run to quiescence, check everything. Every relay event also runs as "timeout after apply". Double crashes (the second during recovery) for SCN-A, SCN-B, SCN-F and SCN-I.

| Scenario | Content |
|---|---|
| **SCN-A** send | A → B: 3 messages; 3 relays over 2 operators, one refusing; STANDARD and HIGH |
| **SCN-B** receive | 6 messages reordered across relays (SHUFFLE, REPEATS), one RESURRECTed after tombstone GC, one COPY_NAMESPACE'd |
| **SCN-C** establishment | card → fetch with WITHHOLD_NEWEST_BUNDLE → `SessionBuilder.process` → PreKey messages → reply → pair mode on both sides; the recipient's request and accept |
| **SCN-D** key change | the debug hook changes B's libsignal key with a valid binding: A holds and moves to `changed`, A's send refused; acknowledge → HELD replays; a block variant; a **forged** variant (a third client with its own identity sends an intro envelope naming B's genuine card and a PreKey under another key): dropped, no state change (E-1) |
| **SCN-E** offline recipient | B offline across 3 week boundaries: deposits succeed with the current credential, then the fallback, then wait in `wait_capability`; B returns, renews, registers; waiting ops of A delivered before their deadlines or FAILED after; a LOSE_KEYS variant exercising the healing rule |
| **SCN-F** ephemeral | 5 min, 1 h, 7 d; displayed, unread (honest, short and long E), held; a sweep with a busy reader; a wall clock stepped back |
| **SCN-G** outcomes | an ambiguous store → INDETERMINATE → identical resend (≤ 2); every relay refusing → FAILED → user retry (re-encryption; the recipient dedups by D3) |
| **SCN-H** prekeys | weekly publication across 13 weeks; a PreKey message accepted at the 91-day retention boundary and refused after; a replayed first message (reuse tuple) |
| **SCN-I** restore | B restores from seed: pair envelopes counted `unknown_seal`; an intro envelope rebuilds A as a request with `reset_needed`; B reconnects (scheduled reset, waiting for A's bundle, §21.8); A renews its session without a key-change warning and drops its out keys for B; later pair envelopes open in both directions (§21.3) |
| **SCN-J** faults | `SQLITE_FULL` injected at every statement of SEND, RECV, BUNDLE and SWEEP; `SimulatedNativeCrash` during RECV: re-offered alone, consumed as poison at the fourth offer (a declared loss); single and double SQL crashes never reach the threshold |
| **SCN-K** revocation | A notifies its revocation (scheduled); B drops the session, refuses sending, drops later blobs |
| **SCN-L** migration | a v3 database with a live outbox and inbox migrates to v4, then SCN-A traffic |

**Structural invariants (after every reboot):** `integrity_check` ok, `foreign_key_check` empty, every expected trigger present; every `queued` outgoing message has an unreleased outbox op or a pending send; every `dm_outbound_op` of purpose `item` references a live outbox op or a released outcome; held rows exist only for `changed` contacts; no session row for a `revoked` contact; the `delete_at` CHECK holds; after SWEEP and R-K1 no row has `delete_at_minute ≤ now_e` and the WAL is 0 bytes; every registration row is consistent with its capability; every F7 §8.4 structural invariant holds.

**At quiescence:** CS-2 (`oracle_displayed` at most one row per device and `message_id`); CS-3 under the stated premises; CS-4 (the rendered order is equal on both devices and across all crash runs); CS-5 (no encrypt to a `changed` contact; no held content displayed before KEYDEC); T28 (every store maps to an action); ratchet liveness (one more message each way decrypts); the F7 OUT-1…IN-2 invariants. The job summary prints `dm crash classes: <n> singles, <m> doubles` per scenario (report-checked).

### 15.4 Seeded worlds (G-13)

1 000 seeds per PR (`android` job), 20 000 in `messaging-exit-gate.yml`; plain JUnit loops with `SplittableRandom`; a failure message carries its seed. Each world draws: 2–6 clients, 2–4 relays over 2–3 operators, both modes; 0–40 messages per pair with a timer mix; displays at random times; **offline windows from 1 minute to 40 days**; **week boundaries** crossed by every world; **one ES slot-table change** in a quarter of the worlds; **clock steps** backwards up to 1 h and forwards up to 2 d while READY, large jumps while not READY; key changes (1 %), restores with reconnect (1 %), blocks and requests; one hostile relay per set; a crash probability per event and a `SQLITE_FULL` probability.

### 15.5 Functional suites

| Suite | Cases |
|---|---|
| **RO reorder** (CS-4) | RO1 all 720 orders of 6 messages each way: identical rendering on both clients; RO2 50 messages in random orders over 3 relays with HIGH delays; RO3 gaps up to 2 000 skipped keys decrypt, beyond the limit dropped and counted; RO4 several unacknowledged PreKey messages reordered; RO5 simultaneous first contact from both sides converges |
| **RS restart** | RS1 process death at every lane item and actor step on seeded interleavings; RS2 a client offline 60 days (blobs past TTL lost and declared, no duplicates, sessions usable or reset by the user); RS3 a 30-day unacknowledged session: send takes the reset path, fetch, delivery |
| **RP replay** (CS-7) | RP1 re-listing within the tombstone (D1); RP2 RESURRECT after tombstone GC with each other layer disabled in turn (B2, D2, D3, freshness each sufficient); RP3 COPY_NAMESPACE (B1: does not open); RP4 first-flight replay after session resets (D2 reuse tuple, then D3); RP5 PreKey replay across a restart (tuple persisted); RP6 re-encryption after a wrongly reported FAILED (D3); RP7 an old L0 re-sealed under a later week key (B1 week binding); RP8 pre-restore content (`accept_after_minute`); RP9 TRUNCATE and byte flips (does not open, no counter difference that could be an oracle); RP10 a blob of contact A presented as contact B's (hint mismatch) |
| **KC key change** (CS-5) | KC1 B's libsignal key changes (debug hook): A `changed`, `send` → `KEY_CHANGED`, session record and outbox byte-identical before and after the attempt; KC2 new-key messages held, not displayed, no plaintext in DB or WAL, held rows gone at their bound; KC3 acknowledge: held messages displayed once in order, sending allowed, a new `seal_root` offered, `verified_fp` cleared; KC4 a wrong scanned fingerprint keeps `changed`, the right one → `verified`; KC5 **forged binding or no binding**: dropped, no state change (E-1); KC6 key change found in a fetched bundle before any encrypt (E-2); KC7 revocation: nothing produced toward B, nothing shown from B; KC8 same-key PreKey (B restored): session renewed, no block; KC9 old-session messages of B shown while `changed`; KC10 a second pending key replaces the first; KC11 NI-DM5 on the whole suite |
| **CB contacts** | requests (limit, expiry, accept, reject, block, no reflex), block, unblock, delete, `MAX_CONTACTS`, R-E1…R-E4 |
| **RE restore** | same safety numbers; `accept_after_minute`; `unknown_seal` counts; intro healing with `reset_needed`; `reconnect` spread over 48 h and cancelled by an earlier user send; reads with the seed-derived key before any token |
| **EP ephemeral** (CS-6, T25) | the §10.9 cases for every timer × path; timer versions (concurrent equal versions converge to the shorter timer; a lost TIMER_SET healed; a replayed old version ignored); R-T3 bucket on TIMER_SET; the checkpoint busy-reader case; a clock step back; the alarm contract (non-exported receiver, no extras, one request code, cancel at wipe); a sender clock 5 days ahead does not extend the unread deadline (ME-19) |
| **OS owner schedule** | registrations for `{c, c + 1}` from a capability redeemed late in its week and from one redeemed early; `WRONG_PERIOD` from a stale capability; the healing rule after LOSE_KEYS; ATTACKER_REGISTERS changes nothing for other senders (SC-1); publication at the PRF offset with and without sessions nearby; prekey and pair-key erasure at their windows; owner offline across week boundaries (the bundle gap declared, registrations catch up) |
| **RK relay** | `register.txt` and TTL vectors (Rust relay, `ModelRelay`); `keys.redb` restart, sweep and loss; the `DepositLedger` after restart; capture fixtures v2; `two_nodes.rs` capture with `register`, deposits and 3600 TTLs validated by `capture-check` |

### 15.6 DM privacy world (T32) and the seizure scenario (T34)

- **World.** N = 120 clients over 14 virtual days (PR, in the `android` job), N = 600 over 42 days (gate, `dm-privacy-gate.yml`, nightly and on dispatch, 10 seed pairs, STANDARD and HIGH); 3 model relays, all AD-1, exporting the effective view (exact times, circuits, raw TTLs, stored bytes, `keys.redb` records, credential kinds). Behaviour: degree ~ Poisson(6); bursty conversations with LogNormal reply delay (median 2 min); the Phase 7 app-session and job model; timers 60 % 7 d, 10 % 30 d, 5 % off, 10 % 1 d, 10 % 1 h, 5 % 5 min; 2 % key changes (debug hook), 1 % restores with reconnect, 3 % requests rejected, 10 % of clients onboard by invite and message their inviter; one ES slot-table change; 10 % of devices with a clock offset U[−3 d, +3 d] (§21.2); hostile modes REFUSE_ONE_SENDER and WITHHOLD_ALL_BUNDLES in a quarter of the seeds. Ground truth: identities, cards, namespaces, sessions, edges, the user action behind each store, timers.
- **Exact joins (must find 0).**
  - JD1 identity dictionary (every `ghost1` hash, Ed25519 key, libsignal key in 32/33-byte forms, safety-number bytes, and for each SHA-256, SHA-256 with every label, HKDF with every label) scanned over every captured field, circuit-level byte, stored blob and `keys.redb` record;
  - JD2 libsignal header strings (ratchet keys, base keys, 32-byte Kyber ciphertext prefixes, registration ids in context) absent;
  - JD3 per (relay, inbox, week) the deposit-credential store scopes ⊆ {the deposit scope}, and no redeem or register by an honest client for a namespace it does not own;
  - JD4 `size_bucket` = class(L0 length) for every DM store;
  - JD5 TTL = the §10.1 table, no store after the deadline, every membership expiry ≤ the T30 bound;
  - JD6 every store maps to an `oracle_user_action`, a scheduled action, a bundle publication or an identical resend;
  - JD7 every list or get is on own namespaces, except one bundle fetch per establishment, reset or reconnect;
  - JD8 redemptions and registrations depend only on own namespaces and the week;
  - JD9 every DM namespace's relay set equals `set(ns, w)` or the declared 6-week union.
- **Twins** (identical shape views `(op, relay, ns, size, ttl, minute, scope, key_kind, batch_count, result, circuit open/close minute)`): NI-DM1 inbound content (valid, malformed, replays, probes, forged, key-changed, requests) with identical user actions; NI-DM2 message type and session state at equal length (first vs later, intro vs pair, text vs TIMER_SET vs CONTROL, SPQR-heavy vs light); NI-DM3 degree (k vs k′ idle contacts); NI-DM4 timer within a bucket (5 min vs 1 h; 30 d vs off); NI-DM5 local trust actions (verify, acknowledge, block, request decisions); NI-DM6 inbound arrival times, unrelated send times, sender clock offsets and one relay's refusals (owner, scheduled and registration store minutes; deposit-scope multisets per (relay, inbox); §21.9).
- **Statistics.** S-DM1 (gating): conversation-edge attackers on the full view (reply-timing survival, co-occurrence plus fetch → store lag, logistic regression over every effective-view feature) vs the same family restricted to LD (§1.2): full-view AUC − LD AUC not significantly > 0 (stratified permutation test, 999 permutations, α = 0.001). S-DM2 (reported): LD-attacker AUC and rounds-to-single-out per mode and per TTL class (§21.11); the report check fails on a regression above the recorded baseline + 0.02. S-DM3 (gating): an attacker holding every `ghost1` but no card maps namespaces to identities within the 99.9 % binomial interval of chance; a control with a colluding subset's cards maps exactly that subset's contacts. S-DM4 (reported): mutual information between an inbox's TTL-bucket sequence and the conversation label. Floors as in F8 §19.24 point 6: a statistical check with n < 100 fails rather than passes.
- **T34 seizure scenario** (a separate world: 10 clients, 70 virtual days, daily conversations): at day 70 dump two clients' databases and seeds; try every stored key, every derivation and libsignal decryption with the retained prekey and session records (§21.3) on every archived blob: pair-mode blobs of weeks with `start(w + 1) + 45 d ≤ day 70` opened = 0; intro-mode opened = ground truth (declared).
- **Report.** `scripts/gates/dm-report-check.sh` (the `t2-report-check.sh` pattern) requires every line and refuses a PASS on an empty sample.

### 15.7 Mutants (79 with the 15 of §21.14; each detected against a same-scale control world; implemented only in `src/test`; `DmMutantDetectionTest`)

**Privacy (PM, 27 here; 32 with §21.14)**

| ID | Mutation | Detected by |
|---|---|---|
| PM-1 | per-sender token-bought write capability for a contact inbox (Annex B literal) | JD3, JD8, NI-DM3 |
| PM-1b | the planner redeems a LOCAL need | JD8, planner test |
| PM-2 | automatic delivery receipt on decrypt | JD6, NI-DM1 |
| PM-3 | inbox or bundle namespace = SHA-256(label ‖ `ghost1` hash) | JD1, S-DM3 |
| PM-4 | pad, libsignal-encrypt, store the next bucket up | JD4, NI-DM2 |
| PM-5 | TTL = exact timer seconds, or 1 h through day rounding | relay `rejected_ttl`, capture-check, JD5 |
| PM-6 | `DecryptionErrorMessage` or automatic session reset on an undecryptable blob | NI-DM1 |
| PM-7 | contacts refetch a bundle on key change or restore | JD7, NI-DM5 |
| PM-8 | contacts listen to a per-identity revocation namespace | JD7, static check |
| PM-9 | no deadline on DM ops (a relay-outage world) | JD5 |
| PM-10 | the conversation row keeps `last_activity_minute` | T33 introspection |
| PM-11 | bundle publication triggered by fetches or new contacts | NI-DM3, JD7 timing |
| PM-12 | intro-mode `e_pub` outside the outer AEAD | T29 χ² and structure test |
| PM-13 | sealed-sender v2 multi-recipient bytes on the wire | JD1, JD2 |
| PM-14 | DM namespaces set to `SendDelay.OFF` in HIGH | HIGH world (stores off pair events); trigger test |
| PM-15 | `isTrustedIdentity(SENDING)` true on mismatch and the S1 guard skipped | KC1 |
| PM-16 | RECEIVING trusts a new key (TOFU replace) and the R6 pre-check skipped | KC2, the `saveIdentity` test |
| PM-17 | a key change classified from `UntrustedIdentityException` without a binding (E-1) | KC5, SCN-D forged variant |
| PM-18 | trial decryption over all candidate keys instead of the hint | one-attempt test |
| PM-19 | pair week keys kept beyond the FRESH window | T34 seizure scenario, erasure tests |
| PM-20 | bundle seal key derived from the presented bundle read secret | the model relay opens bundles (T26) |
| PM-21 | a deposit credential accepted for list or get | `register.txt`, T21 matrix |
| PM-22 | an older `bundle_week` accepted (rollback) | OS suite, bundle checks |
| PM-23 | `RegisterKey` replaces an existing verifier (SC-1) | `register.txt`, OS ATTACKER_REGISTERS |
| PM-24 | the relay set chosen by the client and carried in the card (E-15) | JD9 |
| PM-25 | the `ConsumerTail` runs while the transport is open (SC-7) | `SessionParticipantTest` ordering assertion; NI-DM1 close times with the consumer cost model (§21.9) |
| PM-26 | owner registrations created on the first inbound deposit instead of from capabilities and the week | JD8, NI-DM1 |

**Correctness (MC, 17 here; 25 with §21.14)**

| ID | Mutation | Detected by |
|---|---|---|
| MC-1 | ratchet and op committed in two transactions | SCN-A (a lost message, then an undecryptable next message) |
| MC-2 | a session record cached across transactions | crash enumeration (a stale ratchet after rollback) |
| MC-3 | INDETERMINATE resend re-encrypted instead of identical bytes | SCN-G oracle (a second hash, an extra ratchet step) |
| MC-4 | `markConsumed` in a separate transaction | `oracle_displayed` primary key, or a lost message |
| MC-5 | D3 off | SCN-G FAILED retry after a lost receipt; RP2 with D1 expired |
| MC-6 | `saveIdentity` overwrites (TOFU) | SCN-D |
| MC-7 | Kyber reuse tuple not enforced, or written outside the decrypt transaction | RP5, SCN-B |
| MC-8 | `Inbox.defer` instead of a hold on key change | SCN-D with a long hold (poison and loss) |
| MC-9 | no freshness check | RP2 beyond the window with D3 expired, RP7 |
| MC-10 | arrival-order display | RO1 |
| MC-11 | one-time prekeys published in the bundle and deleted on use | SCN-C with two fetchers of one bundle (the second PreKey message fails, CS-3) |
| MC-12 | offers ignored (no poison guard) | SCN-J native crash loop |
| MC-13 | registrations scheduled on the read lane | T19 run (b) with registrations |
| MC-14 | registration rows not re-armed after a rejected own READ credential | SCN-E LOSE_KEYS variant |
| MC-15 | a refused LOCAL credential re-put on every `CAPABILITIES` hint (redefined by §21.2) | SCN-E bound on refused stores per session |
| MC-16 | automatic resend beyond 2 or past the deadline | SCN-G |
| MC-17 | the outbox rebuild loses a rowid or a trigger | SCN-L, the `sqlite_master` set test |

**Ephemeral and envelope (ME, 20 here; 22 with §21.14)**

| ID | Mutation | Detected by |
|---|---|---|
| ME-1 | a length prefix in clear | T29 |
| ME-2 | a raw libsignal blob stored | T29, seal vectors |
| ME-3 | bucket from the ciphertext length | NI-DM2 |
| ME-4 | non-zero padding accepted | canonical refusal test |
| ME-5 | seconds in the author time | T13 |
| ME-6 | an unkeyed `dm_seen` tag | dictionary test over keyed and unkeyed tags of known `message_id`s (§21.10) |
| ME-7 | recipient countdown at receive | EP bounds |
| ME-8 | no unread cap | EP unread path |
| ME-9 | expiry extendable | trigger test, EP |
| ME-10 | checkpoint result ignored | EP busy reader |
| ME-11 | no checkpoint | WAL size |
| ME-12 | a quote copies the text | logical scan decrypting every `*_env` column (§21.8) |
| ME-13 | a notification with content | notification-port test |
| ME-14 | TIMER_SET uses the new bucket | TTL assertion (R-T3) |
| ME-15 | a control message in the default bucket | TTL assertion (R-T2) |
| ME-16 | a read path ignores expiry | DAO lint |
| ME-17 | a wall-clock back step delays deletion | EP clock case |
| ME-18 | an FTS index present | R-M4, `dm-no-fts.sh` |
| ME-19 | unread deadline from `author + bucket` (content-derived) | EP sender-clock-ahead case (C-11) |
| ME-20 | the retained blob survives its message's deletion | T25 physical scan of the blob bytes |

The gate summary line is `dm mutants: 79 run, 79 detected` (report-checked; the 15 mutants added after review are defined in §21.14).

### 15.8 Exit-gate evidence and argument

Gate: *"2 dispozitive fizice: reorder/restart/replay; schimbare de cheie blochează; T25 verde"* (plan:310), with spec p.23 and the FR-2.1, FR-4.1, FR-4.4, FR-4.5, FR-4.6 acceptance criteria.

| Gate item | What proves it on the JVM (exhaustive, real libsignal, real `:sync`) | What the emulator job adds (real Android, SQLCipher, Keystore, JobScheduler, process death) | What the two physical devices add (signed checklist) |
|---|---|---|---|
| reorder | RO1–RO5, CS-4 oracle, SCN-B, seeded SHUFFLE and HIGH delays | the SCN-B script on SQLCipher and the Android natives, order digests equal | vendor schedulers, real Tor latency, airplane toggles; order digests equal (step 2) |
| restart | SCN-A…SCN-L crash enumeration with doubles, native-crash poison, `SQLITE_FULL`; RS1–RS3 | the `:peer` process killed with SIGKILL at scripted points; emulator reboot | `am kill`, force-stop and reboot during sends and receives (step 3) |
| replay | RP1–RP10 with each layer isolated; SCN-B, SCN-G, SCN-H | the replay scripts over the loopback model relay | identical-bytes re-stores and debug-hook resurrection against staging relays (step 4) |
| key change blocks | KC1–KC11, SCN-D (with the forged variant), PM-15…PM-17, MC-6 | the debug hook on the peer, blocking and acknowledgement | the same through the `gate` variant (step 5) |
| T25 green | EP suite, logical and physical scans, SCN-F, ME-6…ME-22; the `NotificationPort` contract | SQLCipher WAL at 0 bytes after sweep; the alarm scheduled and cancelled | exported database and WAL hold no canary; staging capture shows 3600 (step 6); notification evidence is Phase 13's (§21.10) |
| privacy (not in the gate text; required by CP-10 before any claim) | T32 (JD1–JD9, NI-DM1–6, S-DM1/S-DM3 gating), T34, 32 privacy mutants | logcat holds no libsignal log line (E-18) | staging capture: `register`, deposit scopes, `ttl_bucket_seconds`, validated by `capture-check` (step 8) |
| restore (FR-1.4, C-05; the checklist names it) | SCN-I, RE suite | — | restore and reconnect on a real device (step 7) |

**Argument.** Every correctness property of the gate is a property of transactions, stores and state machines that the JVM world exercises exhaustively with the real protocol library and the real sync engine against a relay model whose semantics are pinned by vectors the real relay replays. The emulator job removes the JVM-specific assumptions: SQLCipher instead of plain SQLite, Keystore wrapping, JobScheduler, alarm delivery, process death, the Android build of `libsignal_jni.so` and R8. The physical devices are what the gate names: they add vendor power management, real notification history, real flash, real Tor and staging relays, and they are where NFR-1, NFR-4 and NFR-5 are measured. **The gate is closed only when all three columns are green on the same commit.**

**What the proof assumes:** libsignal implements the protocol correctly (TM A1); the desktop natives of `libsignal-client` behave like the Android build of the same tag (same Rust source; the emulator and devices exercise the Android build); BouncyCastle's primitives are correct (the JDK cross-implementation checks GHOST's use of them, not the primitives); SQLite and SQLCipher durability with `synchronous = FULL`; the Phase 7 exactly-once proof (`sync-exit-gate` stays green).

### 15.9 Emulator substitute (`dm-emulator.yml`; G-11, C-21)

- **Runner.** `reactivecircus/android-emulator-runner` pinned by commit SHA (the `ci.yml:5` rule for third-party actions, like `android-actions/setup-android`; X-17), on ubuntu with KVM; **API 29 and API 35 `x86_64`** AOSP images without Google services.
- **Suite.** The instrumented `DeviceGateSuite` in `:messaging`'s `androidTest`:
  1. Client B runs in a separate `:peer` process (a service declared only in the `androidTest` manifest, so the app's merged manifest, T15m, is unaffected), killed with **SIGKILL** at scripted points.
  2. **Real SQLCipher:** a v3 fixture database migrates to v4 (CS-9 on the real engine), then the SCN-A, SCN-B, SCN-D and SCN-F scripts.
  3. **Real natives:** `libsignal_jni.so` and `libghost_client_net.so` (x86_64); a **release-variant smoke test**: the R8-shrunk APK starts, loads both libraries, installs the silent logger and completes one in-process libsignal session between two in-memory store sets, with no transport (§21.13); the loopback-relay session runs in the debug `androidTest` variant.
  4. **In-process loopback model relays** over a test-only transport; no Tor. `live-tor` stays manual.
  5. **T25 on SQLCipher:** WAL at 0 bytes after `TRUNCATE`; the alarm is scheduled and cancelled (notification checks move to Phase 13, §21.10) (`dumpsys alarm` through `UiAutomation`).
  6. **Logcat scan:** during a scripted key change, no line holds a canary key or a libsignal log tag (E-18).
- **Triggers.** Push to `main`, nightly, and pull requests touching `android/{messaging,crypto-bridge,storage,sync,network}`.
- **Status.** A regression net and gate evidence for the Android-specific parts, not the physical gate; a run that cannot start the emulator reports **not run**, never green. It also closes the Phase 7/8 "device-only" items that fit an emulator (SQLCipher migration, JNI on x86_64).

### 15.10 Physical-device checklist (manual, signed; G-15)

**Setup.** Two phones: A a mid-range arm64 device on API 29–31, B a recent arm64 device on API 35 or later; the release candidate APK and its `gate` debug variant (never released) for the steps marked †, which exposes `Messaging` to an instrumentation runner and includes the debug key-change hook and the debug-only order digest export; live Tor; 3 staging relays over 2 operators with the stagenet ES; a host orchestrator `scripts/device/dm-gate.sh` that drives both phones through adb and **records digests, never content**.

1. † **Establishment:** each phone's card is injected into the other by adb as `addContact(card, qr_in_person)` (no camera, no new permission; §21.13); both `verified`; safety numbers equal.
2. † **Reorder:** 30-message bursts each way, HIGH mode on A, airplane-mode toggles on B (`cmd connectivity airplane-mode`); the order digests (SHA-256 of the rendered `message_id` sequence) are equal on both phones.
3. † **Restart:** `am kill`, `am force-stop` and a reboot during 20 sends on A and during receives on B; after quiescence the multiset digest shows no duplicate and nothing missing after its relay quorum.
4. † **Replay:** the host re-store tool (§21.13) re-stores 5 delivered blobs with B's deposit credential (identical bytes, D1); † A's debug hook re-encrypts a delivered L0 after a forced FAILED (D3); † B's debug hook clears its Phase 7 tombstones for its inbox and re-lists (D2, D3, freshness). Nothing shown twice; the drop counters rise.
5. † **Key change blocks:** B's debug hook switches to a bound new libsignal key and sends to A; A shows `changed`, A's send is refused, held messages are invisible; after acknowledgement they appear once, in order, and both directions work.
6. † **T25:** a 5-minute timer both ways; both locked for 20 minutes; unlocked: the messages are gone; database and WAL exported through `run-as`; the host scan finds no canary and no `body_env` bytes (notification history is Phase 13 evidence, §21.10).
7. † **Restore and reconnect (G-15):** B is wiped and restored from its mnemonic; A's pair messages are counted `unknown_seal` on B; B reconnects A (the scheduled reset is forced due through †); A's session renews with no key-change warning; A's later messages are delivered to B.
8. † **Staging capture** (S1 relays deployed to staging, §21.13): the 5-minute message stored with `ttl_bucket_seconds = 3600`; `register` events with `key_kind`; one deposit scope per inbox per week; validated by `capture-check`.
9. **Measurements, recorded and not gated:** NFR-1 (30 min of 4 KiB messages in the foreground, p50/p95/p99), NFR-4 (APK size universal and per ABI, `libsignal_jni.so` reported separately), NFR-5 (idle battery over 6 h with the screen off, if time allows).

**Evidence.** `docs/reviews/<date>-faza9-devices.md`: device models and Android versions, build and relay commit hashes, orchestrator logs, digests; signed off by the owner.

---

## 16. Gates, CI and dependencies (I1, I11)

### 16.1 Gates (each change has a negative fixture and a `self-test.sh` hit count)

| Gate | Rule | Supports |
|---|---|---|
| G-LS1 … G-LS7 | §2.7: native allowlist with stripped-`.so` hashes, no foreign natives, the libsignal import allowlist and single logger call site, the version lock with repository filter and golden-record directories, R8 rule comments, typed catches in the new modules, merged manifest | I1, T3, T12, T15m |
| **G-DM1** `messaging-no-network.sh` | `android/messaging` and `android/crypto-bridge` sources reference no `org.ghost.network`, `java.net`, `javax.net`, socket or HTTP class, and no `kotlinx.coroutines` | T28, ADR-20 |
| **G-DM2** `dm-enqueue-callers.sh` | `Outbox.enqueue`, `Registrations.request`/`rearm`, `Namespaces.register`, `Namespaces.setListening` and `Capabilities.put` are called only from the SEND, RESEND, EST-START, EST-READY, EST-END, OWNER-WEEK, ACTIVATE, KEEPER and REGROWS steps, and `Namespaces.remove` also from SWEEP (never from RECV, BUNDLE, HELD, apply code or the store layer; §21.7); `NoReflexTest` is the behavioural half | T28, T31 |
| **G-DM3** `dm-derivation-inputs.sh` | `DmLabels` are used only through typed functions whose key input is `MessagingBranch`; `CardLabels` only with `CardSecret`; pair labels only with `PairRoot`/`PairWeekKey`; no DM label appears next to a raw `ByteArray` key input | T26 (static half) |
| **G-DM4** `dm-no-replace.sh` | no `REPLACE`, `INSERT OR REPLACE`, `UPDATE OR REPLACE` or `ON CONFLICT … DO UPDATE` in DM SQL | REPLACE-guard rule |
| **G-DM5** `apk-no-debug-hooks.sh` | the release variant's source sets and R8 `mapping.txt` contain no class of the key-change debug hook, the order-digest export, a harness package or a transport-injection seam; the hook lives in `android/crypto-bridge/src/gate/`, and `anti-placeholder.sh` scans `*/src/gate/*` (§21.13) | §15.1, §15.10 |
| **G-DM6** `dm-no-fts.sh` | no `CREATE VIRTUAL TABLE` and no `fts` token in production SQL | T25, T33 |
| **G-DM7** merged manifest | `ExpiryAlarmReceiver` present, `exported="false"`, no intent filter; Phase 9 adds no permission | T15m, Q17 |
| `sync-no-catch-all.sh`, `no-logging.sh`, `anti-placeholder.sh`, `kotlin-clearnet.sh` | scopes cover `android/messaging` and `android/crypto-bridge` (S0 checks each script's file set and extends it where needed) | T3, T8 |
| `capture-check`, `privacy-capture.sh` | observables v2 fixtures (§4.7, §10.2) | T1 |
| `proto-check.sh` | `RegisterKeyRequest` carries `uint32 version = 1;`; `KeyKind` and `RegisterResult` field-for-field | T1 |
| `rust-client-allowlist.sh`, `rust-crypto-pins.sh`, `deny.toml` | **unchanged**: no new Rust crate (credential v3 uses `sha2` and the capability crate's constant-time comparison; `keys.redb` uses `redb`; S1 confirms) | T7 |
| `t2-report-check.sh` | requires the new `dm_owner_namespaces` population field (§4.9) | T2 |
| **`dm-report-check.sh`** (new) | requires the `messaging-exit-gate` and `dm-privacy-gate` summary lines: seeded worlds, crash classes per SCN scenario, `dm mutants: 79 run, 79 detected`, JD1–JD9 = 0, NI-DM1–6 equal, S-DM1/S-DM3 p ≥ 0.001 with floors, S-DM2/S-DM4 within baseline + 0.02, the T34 line | T32, T34 |
| `ErrorPolicyTest` | unchanged count (21): `RegisterKey` maps onto the existing JNI categories | ADR-19 |

### 16.2 CI jobs

| Job | Change |
|---|---|
| `static-gates` | the new gates and fixtures |
| `rust` | relay `RegisterKey` unit, restart and loss tests; `register.txt` and TTL vector replayers; `two_nodes.rs` capture with `register`, deposits and 3600; `client-core` T21 v3 matrix, TTL refusal, receipt upper bound; the T2 PR variant with the §4.9 changes |
| `android-native` | unchanged (two identical `client-core` builds) |
| `android` | **JDK 21**; DM unit, vector, schema and property tests; the PR `DmWorld` variant (1 000 seeded worlds, crash singles for SCN-A and SCN-B, 79 mutants on a small world, T32 at N = 120 over 14 days with one seed pair per mode); `merged-manifest-lint.sh` |
| `sync-exit-gate` | JDK 21; S-F with 1 h and 1 d TTLs and the new offline windows; report lines otherwise unchanged (`mutants: 17 run`) |
| `entitlement-exit-gate.yml` | JDK 21; planner cases for LOCAL needs and pending registrations |
| `reproducible` | JDK 21; two release builds identical with the AAR inside; stripped `libsignal_jni.so` hashes compared with the sums file; an `apk-size:` report line (universal, per ABI, `libsignal_jni.so` separately) |
| **`messaging-exit-gate.yml`** (new; push to `main`, nightly, dispatch) | 12 shards: full crash enumeration SCN-A…SCN-L (singles, doubles on a stride), 20 000 seeded worlds, 79 mutants, T34 seizure world; `dm-report-check.sh` |
| **`dm-privacy-gate.yml`** (new; nightly, dispatch) | T32 at gate scale (N = 600, 42 days, 10 seed pairs, STANDARD and HIGH); `dm-report-check.sh` |
| **`dm-emulator.yml`** (new; push to `main`, nightly, relevant pull requests) | §15.9 |
| `t2-exit-gate.yml` | the §4.9 export, completeness and client-model changes; baselines re-recorded |

### 16.3 Dependencies and approvals

| Item | Scope | Approval |
|---|---|---|
| `org.signal:libsignal-android` **0.102.2** (re-pinned in S0 to the newest ≥ 0.100) | release (AAR: Java API + `libsignal_jni.so`, ABIs filtered to arm64-v8a and x86_64) | group already allowlisted (Annex D, `dependency-allowlist.txt:12`); **ADR-28**; sha256 in `verification-metadata.xml` |
| `org.signal:libsignal-client` **0.102.2** | release (classes); JVM tests (desktop natives, excluded from the APK by G-LS2) | ADR-28 |
| transitive `org.jetbrains.kotlinx:kotlinx-serialization-json` 1.9.0, `kotlinx-coroutines-android/-core` 1.10.2, `kotlin-stdlib` 2.2.20 [U4][U5] | release; the stdlib resolves to GHOST's 2.4.20 (`libs.versions.toml:5`) | groups allowlisted; verification entries; GHOST code may not import coroutines (G-DM1) |
| BouncyCastle `bcprov-jdk18on` 1.85.2 (existing) | `:crypto-bridge` uses ChaCha20Poly1305, X25519, HMac/SHA256Digest, Ed25519 verification | **ADR-31** widens the ADR-17 surface, as ADR-24 X15 did for `DropSeal` |
| Signal Maven repository `build-artifacts.signal.org` | build-machine egress, `exclusiveContent` for `org.signal` only | ADR-28, Q3 |
| JDK 21 | build and JVM tests (`libsignal-client` declares JVM 21 [U5]) | ADR-28, Q3 |
| `reactivecircus/android-emulator-runner` pinned by commit SHA; Android SDK system images (API 29, 35, x86_64) | CI only | ADR-34 (X-17) |
| Rust crates | **none new** | — |
| Test-only | **none new**: the cross-implementation uses the JDK's own providers | — |
| Not added | `SealedSessionCipher`, `libsignal-net` use, WorkManager, coroutines in GHOST code, FCM, any JVM crypto library beyond BouncyCastle, any Elligator 2 or AEAD crate | — |

### 16.4 Documents updated in S13 (Romanian text in Appendix B)

`INVARIANTS.md` (T26–T34 rows; T1, T3, T9, T13, T19, T20, T21, T25 wording); `allowed-observables.json` v2 and fixtures; `THREAT_MODEL_v2.1.md` §6 rows, S12 citation (FR-4.6), key-lifecycle row; `LIMITE_REZIDUALE_SI_MITIGARI.md` new section L7, L1 "Detectare" and "Recuperare", L1.1 rows, L5 (Q34 re-evaluated); plan §1.2 FR citation and row 9 TTL wording; `docs/adr/README.md` (ADR-28 … ADR-34); ADR-05 note (card deferred to Phase 13); `docs/STATUS.md` (Phase 8 closed, Phase 9 row); `ghost/android/sync/README.md` (API additions and the new send idiom); `ghost/client-core/README.md` (credential v3, TTL refusal); the relay `README` (`RegisterKey`, `keys.redb`, exact TTLs); `DerivationLabels.kt` comment unchanged (still true); `ghost/infra/issuer/RUNBOOK.md` (O1 expected listings with `keys.redb`, its loss and healing); `LICENSE` and `NOTICE` before any distribution (§21.13).

---

## 17. Implementation slices and exit-gate checklist

### 17.1 Slices (each ends green in CI; the owner's standing instruction applies the Q defaults unless the owner objects, Q1 excepted)

| Slice | Content | Depends on |
|---|---|---|
| **S0** | **Decisions and spike.** Before libsignal enters the build, CI stops uploading APK artifacts (§21.13). ADR-28 … ADR-34 filed as "propus, aplicat"; Q2–Q43 defaults recorded (Q1 waits for the owner's explicit decision). libsignal re-pin (newest ≥ 0.100), repository filter, sha256 pins, **JDK 21 for every Android job with the Phase 7 and Phase 8 harnesses green unchanged**. Measurements on the real artifacts: stripped `libsignal_jni.so` per ABI, 16 KB alignment, desktop natives and `packaging.resources.excludes`, **desktop natives loading on Linux CI and Windows (blocking)**, AAR consumer R8 rules and manifest, golden sizes and `O_MAX` with SPQR, timestamps inside records, the libsignal paths that read the system clock, native logging sinks (A5), KEM types exposed for generation (PQ-2), `GHOST_FP_VERSION`, the reuse-refusal exception type, `PreKeySignalMessage.getIdentityKey()` before decryption, the licences of the other native dependencies. The first golden-record directory. Gates G-LS1 … G-LS7. Results written as normative corrections of this design (Appendix C) | — |
| **S1** | **Relay and observables.** `RegisterKey`, `KeyKind`, `RegisterResult`; credential v3 layout and verification; `keys.redb` (accumulation, `serial_use`, sweep, restart, loss); `DepositLedger`; exact seconds TTL buckets and `rejected_ttl`; capture (`register`, `key_kind`, `ttl_bucket_seconds`); `allowed-observables.json` v2 with fixtures; `register.txt` and the TTL section of `relay_semantics.txt` with the Rust replayers; `two_nodes.rs` capture; `proto-check.sh`; the T2 world enumerates every `*.redb` and exports `keys.redb` (§21.13) | S0 |
| **S2** | **`client-core` and model relay.** T21 v3 authorization and refused-credential matrix; TTL refusal; receipt upper bound; JNI `registerKey` on existing error categories; Kotlin `ModelRelay` extensions and hostile modes; conformance replays | S1 |
| **S3** | **`:sync`, `:storage` and `:entitlement` part 1.** `HOUR_1` and the §10.4 re-derivation with S-F extensions; migration 4 whole, steps 0–6 with the §21.14 schema delta, `CURRENT_VERSION = 4` and the expected sets (§21.13), with the migration tests; `InboundBlob` fields; `CapabilitySource` and the planner filter; the registration need rule; `Registrations` on the work lane; `ConsumerTail` and its `SessionParticipantTest` cases; credential selection; the DM `SendDelay.OFF` refusal; `Checkpoint.truncate()` and `StorageFullException`; `sync-exit-gate` and `entitlement-exit-gate` green | S2 |
| **S4** | **`:crypto-bridge`.** `SignalRuntime` (lazy load, `CryptoUnavailable`), `SignalLog` and the logger tests; `TxSignalStores`; `DmSessions`, `DmKeys`; golden records and `LibsignalUpgradeTest`; `DmLabels`, `CardLabels` and vectors; card codec; `DmSeal` (pair, intro, bundle) with the JDK cross-implementation; `DmCodec`; credential v3 builder; `RelaySets`; `SafetyNumbers`; golden sizes frozen; PQ-3 | S0, S3 |
| **S5** | **Schema v4 tests.** Trigger transition tests, REPLACE-guard tests, introspection (R-M1, R-M3, R-M4), the expired-row DAO lint (the DDL landed whole in S3, §21.13) | S3 |
| **S6** | **Owner side.** ACTIVATE with the `:entitlement` hooks (K20); own namespaces; OWNER-WEEK (bundle publication, rotation, retention, erasure); KEEPER (own READ credential, set changes); REGROWS (rows, healing rule); `myCard` | S4, S5 |
| **S7** | **Send and receive.** Contacts from cards; establishment (EST-START, BUNDLE, EST-END); SEND and RECV; pair and intro modes and roots; dedup layers, bindings, freshness; ordering; OUTCOME with the automatic resend and user retry; requests; block and delete; KEEPER for contacts with the fallback; the DM actor, the listener hand-off and the `ConsumerTail` body; the facade; the hint-cost benchmark (Q37) | S6 |
| **S8** | **Trust and restore.** Key-change classification and hold, KEYDEC and HELD; safety numbers; revocation v2 and scheduled notices; reset; restore healing and `reconnect` | S7 |
| **S9** | **Ephemeral.** Timer codes and versions; TTL and deadline mapping; countdowns; SWEEP cascade, checkpoint, `Outbox.cancel` at expiry; alarm and receiver; notification and media ports; T25 logical and physical tests | S7 |
| **S10** | **Exit-gate harness.** `DmWorld` suites RO, RS, RP, KC, CB, RE, EP, OS, RK; crash enumeration SCN-A…SCN-L; seeded worlds; the 47 correctness and ephemeral mutants; `messaging-exit-gate.yml`; `dm-report-check.sh` | S8, S9 |
| **S11** | **Privacy worlds.** T32 (JD1–JD9, NI-DM1–6, S-DM1–4), the T34 seizure world, recorded S-DM2/S-DM4 baselines, the 32 privacy mutants, `dm-privacy-gate.yml`; the T2 world and `t2-exit-gate` changes of §4.9 | S10 |
| **S12** | **App wiring and emulator.** `MessagingWiring`, R8 rules, the manifest receiver, T12 with the AAR; `dm-emulator.yml` green on API 29 and 35; the `gate` build type, `scripts/device/dm-gate.sh`, the digest export and the host re-store tool; S1 relays deployed to staging (§21.13) | S9 (S10 for the scripts) |
| **S13** | **Devices, documents, review.** The physical checklist executed and signed; the documents of §16.4; ADR files and statuses; the adversarial review of the phase (the Phase 8 S12 practice) with its corrections recorded in a final "Normative corrections" section | S11, S12 |

**Critical path:** S0 → S1 → S2 → S3 → S4 → S5 → S6 → S7 → S8/S9 → S10 → S11 → S13. S4 may start after S0 on its pure parts (codec, seal, card) while S1–S3 proceed; S12 runs beside S10–S11.

**Size.** About **9–11 weeks**, against the plan's 5–7: the relay changes (S1–S2), the `:sync` extensions with the Phase 7 re-derivation (S3) and the two gate harnesses (S10–S11) carry most of the difference. The G-12 scope cuts removed about two weeks from the base design. If the desktop natives do not load on the JVM (S0), add about two weeks and move the seed counts to the emulator.

### 17.2 Exit-gate checklist (all on the closing commit)

| # | Item | Evidence |
|---|---|---|
| 1 | S0 results recorded as normative corrections; `O_MAX` frozen; golden records for the pinned version | this design, Appendix C; `libsignal-golden/0.102.x/` |
| 2 | libsignal pinned, repository-filtered, sha256-verified; JDK 21; G-LS1…G-LS7 green | `static-gates`, `android`, `reproducible` |
| 3 | Relay `RegisterKey`, credential v3, `keys.redb`, `DepositLedger`, exact seconds TTLs; observables v2; vectors replayed by Rust and the model | `rust`, `android` |
| 4 | Schema v4 migrations, triggers and guards green on every upgrade path, including the outbox rebuild set test | `android` |
| 5 | Reorder, restart, replay on the JVM: RO, RS, RP suites and SCN-A…SCN-L crash enumeration with doubles | `messaging-exit-gate` summary |
| 6 | Key change blocks: KC1–KC11, SCN-D with the forged variant; PM-15/16/17 and MC-6 detected | `messaging-exit-gate` summary |
| 7 | T25 green on the JVM (logical and physical) | EP suite |
| 8 | T26–T34 executable and green; `dm mutants: 79 run, 79 detected`; T32 gating statistics pass; S-DM2/S-DM4 baselines recorded | `dm-report-check.sh` on `messaging-exit-gate` and `dm-privacy-gate` |
| 9 | Phase 7 and Phase 8 gates green (`sync-exit-gate`, `entitlement-exit-gate`, `t2-exit-gate` with the §4.9 changes) | CI |
| 10 | Emulator job green on API 29 and API 35, including the SQLCipher migration, the release-variant smoke test and the logcat scan | `dm-emulator.yml` run link |
| 11 | Two physical devices: checklist steps 1–8 signed | `docs/reviews/<date>-faza9-devices.md` |
| 12 | NFR-1, NFR-4 (libsignal reported separately), NFR-5 measurements recorded | checklist step 9 |
| 13 | **Q1 (licence) decided explicitly by the owner before any APK is distributed** (not required to merge the phase); no CI APK artifact while it is open; `LICENSE`, `NOTICE`, the libsignal source mirror and the Corresponding Source offer ready before the first distribution (§21.13) | ADR-29 status, `ci.yml` |
| 14 | Documents of §16.4 updated; ADR-28 … ADR-34 in `docs/adr`; STATUS row | S13 commit |
| 15 | Phase review recorded with no open confirmed finding | `docs/reviews/<date>-faza9-review.md` |

---

## 18. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| R-1 libsignal is "unsupported outside Signal", ships about weekly, and signals API breaks only best-effort [U2] | integration churn, silent semantic changes | exact pin; every bump its own PR with golden sizes, golden records (`LibsignalUpgradeTest`), PQ-3 and the full `messaging-exit-gate`; closed API (G-LS3); route R documented |
| R-2 Dormant `libsignal-net`/TLS code inside `libsignal_jni.so` | a future bug or library path could open a clearnet connection | G-LS3 import ban, R8 removal, T6 (Phase 13), no configuration passed; Q2 allows route R |
| R-3 The native library is built by Signal, not GHOST | T12 proves APK reproducibility, not source correspondence | sha256 pin; declared in ADR-28 and LIMITE L5; Phase 15 rebuild-and-diff (route H) |
| R-4 The JDK 21 move breaks AGP, D8, Kotlin or the Phase 7/8 harnesses | lost time, flaky gates | done first in S0; Phase 7 and 8 gates green unchanged before any DM code; fallback release targeting 17 or route R |
| R-5 The desktop natives do not load on the JVM | no real libsignal in the JVM worlds; a weaker proof | S0 blocking check; fallback: emulator-hosted suites with fewer seeds (+2 weeks), argument re-stated |
| R-6 `O_MAX` underestimated (SPQR chunk variance, varints, KEM type) | a message does not fit its bucket | golden sizes near every boundary; the runtime fit assertion rolls back before the ratchet commits; rerun at every bump |
| R-7 libsignal logs identities through a sink the silent provider does not cover | T3 failure | S0 assumption A5; the emulator logcat scan; blocks route J if not disableable (Q2) |
| R-8 The GHOST seal (pair, intro, bundle) has a design flaw; a CP-09 exception | metadata or authenticity loss | standard primitives only; one AEAD attempt per blob; canonical parsing; vectors plus the JDK cross-implementation; T29/T34; ADR-31 records the exception; targeted external review of §4–§7 before the first distributed APK, and the Phase 15 audit |
| R-9 Relay protocol changes (`RegisterKey`, accumulation, the ledger, exact TTLs) carry bugs | refused deposits, stale verifiers, wrong expiry | vectors replayed by the Rust relay and the Kotlin model; restart, sweep and loss tests; capture fixtures; the owner healing rule |
| R-10 The recipient pays its inbox: 1 token per relay, own namespace and week, for every activated identity | exhaustion means the user cannot receive; a cost for users who never DM | constant in contacts (T27); `ENTITLEMENT_NEEDED`; trials and packs cover it; measured in the T2 world |
| R-11 Card-only establishment (no contacting by `ghost1`) hurts adoption | fewer contacts | QR and link UX in Phase 13; a discoverable mode would be a separate ADR whose residue is RP F1 by construction (Q7) |
| R-12 The key-change hold blocks a legitimate change or confuses users | friction | rare by construction (seed-derived keys); acknowledgement path; Phase 13 copy; held messages kept until their bound |
| R-13 Restore without a contact backup loses inbound messages of established contacts until reconnect | message loss after restore | declared (L7-D12); intro healing and `reconnect`; P1 encrypted contact-card backup (Q28) |
| R-14 Hint computation at 1 000 contacts on low-end devices | slow consumption | lazy, most recent first; measured in S7; `MAX_CONTACTS` lowered if needed (Q37) |
| R-15 Short timers lose messages for offline recipients; recipients offline beyond ~2 weeks lose deposits made after that | user-visible loss | ADR-27 accepts the first; the second is declared (§4.8); Phase 13 UI states both |
| R-16 Physical deletion lags under Doze | encrypted plaintext stays on disk longer than the timer | read filter (never shown), sweeps at open and in the consumer tail, inexact alarm; declared (L7-D14) |
| R-17 T32 statistics give false alarms or are too weak | a flaky gate or a missed leak | fixed seed pairs, permutation tests at α = 0.001, floors, recorded baselines, mutants that must move the statistics (PM-1, PM-2, PM-3) |
| R-18 The outbox rebuild or the Phase 7 short-TTL re-derivation introduces a sync bug | lost or duplicated sends | S3 runs the full `sync-exit-gate` with the new S-F scenarios and the migration set test before any DM code uses `HOUR_1` |
| R-19 Metadata layers use classical primitives (intro inner X25519, Ed25519 cards and bindings) | a future quantum adversary with a card reads intro headers; forgeries would surface as key changes | declared (§9.3, L7-D3); a KEM-based intro layer when a reviewed library path exists (P2) |
| R-20 Two live devices with one seed (thief or unsupported multi-device) | competing bundles, flip-flopping pending keys, session failures | declared (§8.3, §8.7); revocation; multi-device P2 |
| R-21 The licence decision (Q1) delays distribution | no release | implementation proceeds; distribution gated by checklist item 13 |
| R-22 APK size approaches the limit (≈ 64 MB estimated against 70 MiB) | NFR-4 failure | measured in S0; per-ABI splits (NFR-4 split < 50 MiB); Q24 |
| R-23 Emulator CI flakiness | a red or not-run job without a defect | loopback relays (no Tor); "not run" never green; one retry with a visible marker; the physical checklist is required anyway |
| R-24 Real libsignal through JNI slows the JVM worlds | long gate runs | shard counts and seeds tunable; PR subsets; measured in S10 |

---

## 19. Owner questions (the proposed default applies unless the owner objects; Q1 excepted, §21.13)

| # | Question | Proposed default | Pe scurt (RO) |
|---|---|---|---|
| **Q1** | **Client licence under the AGPL consequence.** libsignal and `spqr` are AGPL-3.0-only on every integration route, so the distributed APK is an AGPLv3 combined work whatever GHOST's own files say (every recipient may ask for the Corresponding Source of the whole APK; not legal advice). Options: (a) Android client AGPL-3.0-only; (b) GHOST code GPL-3.0-or-later, APK conveyed under AGPLv3; (c) GHOST code MIT, APK conveyed under AGPLv3 | **(a)**; `client-core` keeps `MIT OR Apache-2.0` for its own files; relay and issuer per ADR-07; release artifacts mirror the pinned libsignal source; **no APK is distributed before this decision** (ADR-29); confirmation with a lawyer recommended. **This question needs an explicit answer: the default does not apply by silence, and CI uploads no APK artifact while it is open (the repository is public; §21.13)** | libsignal e AGPL-3.0: APK-ul distribuit devine AGPL oricum. Propunere: clientul Android AGPL-3.0-only, client-core rămâne MIT OR Apache-2.0, relay și issuer neschimbate; niciun APK distribuit înainte de decizie |
| Q2 | Accept the dormant `libsignal-net`/TLS code in `libsignal_jni.so` (route J, contained by gates and T6), or require route R (a GHOST JNI over the Rust crates, +2–3 weeks, `deny.toml` git and AGPL exceptions)? | **J** | Acceptăm codul de rețea inactiv din biblioteca Signal, blocat prin gate-uri |
| Q3 | Add Signal's Maven repository (`exclusiveContent` for `org.signal`, sha256 pins) and move Android builds and tests to JDK 21? | **yes** | Depozitul Maven Signal doar pentru `org.signal`; build pe JDK 21 |
| Q4 | Approve ADR-28 … ADR-34 (Appendix A) as "propus, aplicat"? | **yes** | Aprobarea ADR-28 … ADR-34 |
| Q5 | Sealed sender: the GHOST two-mode seal without certificates (§6), instead of libsignal sealed sender with self-issued certificates, a per-message Elligator 2 key, or a raw X25519 key? | **two-mode seal** | Plic exterior GHOST în două moduri, fără certificate false și fără cod de curbă nou |
| Q6 | DM floor of 4 KiB (no 1 KiB DMs)? | **yes** | Orice DM are cel puțin 4 KiB, ca releul să nu vadă „primul mesaj” |
| Q7 | Contacting only with a card (QR or link), never from a bare `ghost1…`? | **yes**; a discoverable mode would be a separate ADR | Contactul se face doar cu cardul (QR sau link), nu doar cu ghost1 |
| Q8 | Receipts and typing: none in Phase 9; read receipts in Phase 13 only as an opt-in flag piggybacked on a user message, STANDARD mode only, never in HIGH? | **yes** | Fără confirmări automate; confirmări de citire opționale doar în Faza 13, doar în modul standard |
| Q9 | No one-time prekeys through relays (signed + last-resort Kyber, weekly rotation, private prekeys kept 91 days after supersession), accepting L7-D11? | **yes** | Fără prekeys de unică folosință prin relee; rotație săptămânală; cheile vechi șterse după 13 săptămâni |
| Q10 | ADR-14 attestation deferred; never in a relay-readable bundle; later only inside E2E, opt-in? | **yes** | Atestarea hardware amânată; niciodată în bundle-ul de pe releu |
| Q11 | A shared weekly deposit key registered by the recipient; senders never spend tokens on other identities' namespaces; no fallback to per-sender capabilities? | **yes** | Destinatarul plătește și înregistrează o cheie de depunere comună; expeditorii nu cheltuie token-uri |
| Q12 | Key change blocks both directions: sending refused, new-key messages held undecrypted until the user acknowledges (explicit confirmation) or verifies the safety number; classified only with a valid Ed25519 binding? | **yes**; acknowledgement suffices, verification recommended | Schimbarea cheii blochează trimiterea și afișarea până la confirmare; doar cu semnătura identității |
| Q13 | libsignal identity derived from the MESSAGING branch (same safety numbers after restore, no warning at contacts, sessions lost; a mnemonic thief on the official client raises no warning), not random per install? | **derived** | Cheia libsignal derivă din seed: safety number-ul rămâne același după restaurare |
| Q14 | Static inbox and bundle namespaces per card with weekly credentials (no weekly namespace rotation), accepting L7-D13 (a seized relay disk links an inbox's weeks)? | **static** | Inbox-ul are aceeași adresă opacă; se schimbă doar cheile de acces, săptămânal |
| Q15 | Relay TTL for 30-day and "off" conversations: 30 days as ADR-27 point 11 (four TTL classes visible), or 7 days (three classes; recipients offline 7–30 days lose those messages; an ADR-27 deviation)? | **30 days (ADR-27 unchanged)** | Mesajele cu timer de 30 de zile sau fără timer stau pe relee 30 de zile, cum spune ADR-27 |
| Q16 | Relays accept exactly the five TTL buckets; the observable becomes `ttl_bucket_seconds`? | **yes** | Releul acceptă doar treptele TTL exacte; câmpul observat e în secunde |
| Q17 | One inexact alarm (non-exported receiver, no extras, no new permission) to wake deletion sweeps, amending T20's wording? | **yes** | O alarmă de sistem trezește aplicația ca să șteargă la timp |
| Q18 | Change the Phase 8 drop blobs to the uniform DM outer shape now? | **no, deferred to Phase 12** (T2 NI-2/NI-3 just closed without exemption) | Formatul drop-urilor din Faza 8 rămâne neschimbat în Faza 9 |
| Q19 | Notifications never show content or sender, locked or unlocked? | **yes** | Notificările spun doar „activitate nouă”, niciodată textul sau expeditorul |
| Q20 | Freshness window FRESH = 45 days (older author times refused; dedup tags and pair keys kept that long), with every DM op's store deadline capped at 7 days? | **yes** | Mesajele scrise cu peste 45 de zile în urmă sunt refuzate; stocarea pe relee cel târziu la 7 zile după scriere |
| Q21 | Prekey KEM: ML-KEM-1024 if the pinned Java API generates it, otherwise Kyber1024 recorded in ADR-28? | **yes** | ML-KEM-1024 dacă biblioteca îl oferă, altfel Kyber1024, consemnat |
| Q22 | Declare session-start co-occurrence (L7-D2), decouple DM and channel session starts in Phase 12 (P1), and allow no UI claim of channel unlinkability against relays until then? | **yes** | Legarea prin pornirea sesiunii rămâne declarată până în Faza 12; fără afirmații în UI |
| Q23 | NFR-1 (DM latency) measured on the gate devices and recorded, not claimed, in Phase 9? | **yes** | Latența DM se măsoară și se consemnează, fără promisiuni |
| Q24 | Governing APK size limit: the spec's 70 MiB universal or the plan's 80 MiB? | **70 MiB**, native libraries reported separately; per-ABI splits | Limita APK: 70 MiB, bibliotecile native raportate separat |
| Q25 | Message bodies, cards, names and held ciphertext stored as envelopes under a content key wrapped by a Keystore key with the database key's authentication policy? | **yes** | Conținutul local e criptat suplimentar cu o cheie păstrată în Keystore |
| Q26 | Unknown card holders' first messages shown as requests (cap 64, 7 days), rather than dropped or gated by an accept round trip? | **requests** | Mesajele de la necunoscuți apar ca cereri, fără niciun răspuns automat |
| Q27 | Cut-off (card rotation) deferred to Phase 13 with the contact backup; block is local in Phase 9? | **yes** | „Tăierea” unui contact vine în Faza 13; în Faza 9 blocarea e locală |
| Q28 | Encrypted contact-card backup deferred to P1 (a restore loses contacts in Phase 9)? | **yes, P1** | Backup-ul criptat al contactelor vine mai târziu (P1) |
| Q29 | Apply the errata: key change is FR-4.6 (TM S12, LIMITE L1, plan §1.2); plan row 9 "TTL ≤ timer" reads as ADR-27 point 11? | **yes** | Corectura referințelor FR-4.5 → FR-4.6 și a formulării TTL |
| Q30 | Exit-gate evidence = JVM gates + emulator job on loopback relays + a signed two-device checklist over Tor and staging relays, all on the same commit? | **yes** | Dovada porții: JVM, emulator și două telefoane fizice pe același commit |
| Q31 | First-contact reachability: count pending key registrations as write work, so a new or restored inbox is redeemed at its first relay session (and the Q29 hold covers it), or keep READ MISSING's PRF time (up to 6 h)? | **count as write work** | Inbox-ul nou devine accesibil la prima sesiune, nu după până la 6 ore |
| Q32 | Invite v3 (card inside the invite) deferred to Phase 13, keeping ADR-05's optional card open? | **yes** | Cardul în invitație vine în Faza 13; ADR-05 rămâne deschis |
| Q33 | The statistical DM world (T32 S-DM1…S-DM4) in the Phase 9 gate (PR scale per PR, gate scale nightly), not deferred to Phase 12? | **yes, Phase 9** | Testele statistice de nelegabilitate DM intră în poarta Fazei 9 |
| Q34 | Automatic identical-bytes resend of an INDETERMINATE op, at most twice, within the Phase 7 window and the op deadline? | **yes** | Retrimitere automată a acelorași octeți, de cel mult două ori, doar când rezultatul e nesigur |
| Q35 | The Phase 8 T2 world models every client's DM owner namespaces and exports `keys.redb`, with `t2-exit-gate` re-baselined? | **yes** | Testul T2 al Fazei 8 include inbox-ul și bundle-ul fiecărui client |
| Q36 | A card holder can spend its own token to list your inbox's volume and timing (content sealed): declare it (L7-D16) and design an owner-bound read rule in Phase 12? | **declare; Phase 12** | Un contact care cheltuie propriile token-uri poate vedea volumul inbox-ului; se rezolvă în Faza 12 |
| Q37 | `MAX_CONTACTS = 1 000`, lowered in S7 if the hint benchmark misses a 1 s foreground budget per 16-blob batch on the reference mid-range device? | **yes** | Maximum 1 000 de contacte, redus dacă testul de performanță o cere |
| Q38 | Deposit, bundle-read and inbox-read credentials static per (card, relay slot, kind) and bound to the relay's slot, with the week kept only in registrations (§21.2: removes the clock-offset and refusal partitions and cross-relay replay), instead of weekly credentials with a fallback? | **static per slot** | Credențialele de depunere și de citire sunt fixe per releu și legate de slotul lui; săptămâna rămâne doar în înregistrări |
| Q39 | DM TTL classes: keep ADR-27 point 11 (four classes; a non-default timer pairs the two inboxes of its conversation at relays in about 2–3 exchanges, declared in L7-D4 and stated in the Phase 13 copy), or reduce to two DM classes (timers ≤ 1 d → 1 d; all others → 7 d, so recipients offline more than 7 days lose messages of 30-day and timer-off conversations), an ADR-27 deviation? | **keep ADR-27** | Păstrăm treptele ADR-27; un timer diferit de cel implicit face conversația mai ușor de legat la relee, iar interfața o spune |
| Q40 | Pair-mode roots only inside acknowledged sessions (one more intro envelope per new conversation) so that P-7 holds for first contacts, rather than restating P-7 with the prekey-erasure horizon (about 14 weeks)? | **roots after acknowledgement** | Cheile de pereche se trimit doar după primul răspuns, ca istoricul conversației să nu mai poată fi atribuit după 45 de zile |
| Q41 | 5-minute messages get the same one-hour store deadline as 1-hour messages and are never cancelled at expiry (otherwise about half are never stored in HIGH mode, and relays could tell the two timers apart)? | **yes** | Mesajele de 5 minute pot fi stocate pe relee până la o oră după scriere, ca cele de o oră |
| Q42 | A bundle fetch makes at most three 15-minute attempts (the first at once, the others at session starts at least 6 h apart), then the contact is shown unreachable until the user retries? | **yes** | Preluarea bundle-ului unui contact: cel mult trei încercări scurte, apoi „inaccesibil” până la o nouă încercare a utilizatorului |
| Q43 | Relays report a blob's upload time only to the ISO week for reads with v3 credentials, so a card holder cannot read the owner's weekly first-session minute from the bundle? | **yes** | Releele arată ora încărcării doar la nivel de săptămână pentru citirile DM |

---

## 20. Findings outside Phase 9 (proposed as separate tasks)

- **F-1.** `docs/STATUS.md` is stale: the Phase 8 row still says "următoarea", and ADR-22 … ADR-27 statuses are incomplete (RS K23). Updated in S13 at the latest.
- **F-2.** NFR text conflicts: NFR-1 has three values (spec, plan, ADR-20) and NFR-4 two (70 or 80 MiB); the owner fixes the text (RS K7, K8; Q23, Q24).
- **F-3.** ADR-27 names an observable `ttl_bucket` that does not exist (the field is `ttl_bucket_days`); corrected by ADR-32 and Appendix B.
- **F-4.** The T1 capture does not emit `circuit_id` although it is allowed; real captures under-estimate linkability (RP F10). The DM world exports circuits; the relay capture should too (Phase 12).
- **F-5.** Owner-bound read rule (SC-2, L7-D16, Q36): a relay could refuse `list`/`get` with a write capability on a namespace whose owner registered a READ key with an ownership proof; needs a proof unknown to card holders (for example a seed-derived preimage of the namespace carried in the card). Phase 12.
- **F-6.** Session-start co-occurrence now links DM identities to channel namespaces through a contact (L7-D2); the P1 decoupling belongs in Phase 12.
- **F-7.** The Phase 7 receipt lower bound is vacuous for TTLs below σ; a relay-corrected bound is a Phase 12 item (L7-D15).
- **F-8.** TTL-aware tombstone retention for ephemeral blobs (RP §3.9 item 5) would shorten the AD-8 trail; it reopens the Phase 7 retention proof. Phase 12.
- **F-9.** Phase 8 drops keep a raw X25519 key first (`DropSeal.kt:14-20`), distinguishable from uniform bytes (RP F9); aligning drops with a uniform shape is a Phase 12 item (C-17, Q18).

---

## 21. Normative corrections after review

The adversarial review of this design (four lenses: cryptography, metadata privacy, correctness, implementability; 49 findings) was checked against this document, the five research notes, the libsignal v0.102.2 sources copied during the review (`session.rs`, `session_management.rs`, `protocol.rs`, `core/src/address.rs`, `storage.proto`, `SessionCipher.java`) and the repository at `e833250` (`InboxStore.kt`, `DirectoryStore.kt`, `Namespaces.kt`, `OutboxStore.kt`, `MigrationRunner.kt`, `RestoreScan.kt`, `EngineTestKit.kt`, `AndroidManifest.xml`, `MainActivity.kt`, `app/build.gradle.kts`, `ci.yml`, `build-native.sh`, `issuer/crates/service/tests/t2/world.rs`, `infra/issuer/RUNBOOK.md`, `relay.proto`, `relay/crates/node/src/lib.rs`; the repository is public and has no licence file). **No finding was rejected as wrong.** Four pairs are duplicates and are merged (CR-2 = CR-04, CR-6 = CR-06, PRIV-11 = CR-10, CR-15 = BUILD-10), and CR-16 is resolved by the §21.2 credential rule. For nine findings (CR-2, CR-3, CR-4, CR-5, CR-6, CR-02, PRIV-1, PRIV-4, PRIV-12) the proposed fix is replaced, narrowed or only partly adopted, each with its reason in the subsection. Two claims inside findings are narrowed: an oversize session write rolls back, so a later SEND crashes only when its own write crosses the bound (CR-6); `ReusedBaseKeyException extends InvalidMessageException` (CR-7 c) was not in the copied sources and is an S0 check. **This section is normative: where it and an earlier section disagree, this section wins.** Earlier sections were corrected in place where the change is local; those places cite "(§21.n)".

### 21.0 Finding → correction map

| Correction | Findings | Corrected in place |
|---|---|---|
| 21.1 Relay sets independent of the week | CR-01 | §0.1 D5, §5.2 |
| 21.2 Credentials static per (card, relay slot, kind), bound to the slot; no week choice, no fallback | PRIV-1, CR-5, CR-16 | §0.1 D5–D7, §0.2 P-2, §3.1, §3.2, §4.3, §4.8, §5.1, ADR-30 |
| 21.3 Pair roots only in acknowledged sessions; renewal reset; ratchet before erasure; P-7 restated | CR-1, CR-2 = CR-04, CR-13, PRIV-12 | §0.1 D3, §0.2 P-7, §6.3, §7.1, §12.2, §14.1 T34, ADR-31 |
| 21.4 Intro bindings bound to their envelope and fresh; request key changes; pre-checks | CR-3, CR-4, CR-05 | §3.4, §6.4, §7.4 R5–R7, §7.6, §8.3, ADR-33 |
| 21.5 libsignal session record bound as a typed outcome | CR-6 = CR-06 | §2.4, §13.6, ADR-28 |
| 21.6 libsignal API, addresses, store exceptions, module boundary | CR-7, CR-19, BUILD-4 | §2.3, §2.4, §2.6, §2.7, §8.1, §8.2, ADR-28 |
| 21.7 Establishment: forgotten tombstones, candidates, `EST-READY`, bounded attempts, restore without tokens | CR-02, CR-03, CR-09, PRIV-4, PRIV-11 = CR-10 | §0.1 D8, §5.3, §5.5, §7.2, §7.4, §8.6, §13.5, §16.1 G-DM2 |
| 21.8 Durable outbound items; FAILED controls and bundles; quote reference inside the envelope | CR-07, CR-17, BUILD-5 | §7.5, §13.6 |
| 21.9 Activity-independent triggers; coarse upload times; consumer cost model | PRIV-3, PRIV-9, PRIV-7 | §7.2, §11.2, §13.7, §15.7 |
| 21.10 Ephemeral: bucket deadlines without cancel, freshness per bucket, held expiry, display guard, alarm, reboot, notifications | PRIV-2, PRIV-8, CR-11, CR-14, BUILD-13, BUILD-9, BUILD-6 | §0.1 D15, §7.6, §10.1, §10.6, §10.7, §10.8, §10.9, §15.8–§15.10, ADR-32 |
| 21.11 Declared leakage, TTL-class pairing, size classes, PQ wording | PRIV-6, PRIV-5, PRIV-10, CR-8 | §1.2, §6.6, §9.3, §11.5, §19 |
| 21.12 Poison guard, resumable activation, orphan namespaces | CR-08, CR-12, CR-18 | §7.8, §12.4 |
| 21.13 Licence and CI artifacts, NDK and sums, slices, device checklist, smoke test, T2 export, gate variant, runbook, migration test | BUILD-1, BUILD-2, BUILD-3, BUILD-7, BUILD-8, BUILD-11, BUILD-12, BUILD-14, CR-15 = BUILD-10 | header, §2.9, §13.6, §16.4, §17.1, §17.2, ADR-29, ADR-34 |
| 21.14 Tests, mutants, counts, schema delta, questions | all | §15.7, §17.2, §19 |

### 21.1 Relay sets do not depend on the week (CR-01)

**Defect.** §5.2 put `u64_be(w)` into the slot-order HMAC, a leftover of the base design's weekly namespaces. With static namespaces (C-4) every DM namespace got a fresh relay set each week: owners registered on last week's relays, senders deposited on this week's, readers unioned up to 18 relays, and `setRelays` failed in-flight deliveries at every boundary.

**Rules.**
1. `order(ns, w)` = the ES slots valid in week w sorted by `HMAC-SHA256(key = ns, "ghost/v1/dm/slot-order" || u8(slot))`; `set(ns, w)` = the relays of the first slots in that order until 3 are taken and they span ≥ 2 operators. With an unchanged slot table the set is identical in every week; it changes only when the slot numbers valid in a week, or the operator behind a slot among the first ones, change.
2. `KEEPER` recomputes the set at each week change and calls `setRelays` only on a difference (unchanged, now rare).
3. **Reader union after a real change.** The owner reads the relays of `set(ns, w′)` for `w′ ∈ [week(now) − 5, week(now)]`. `REGROWS` keeps READ rows for every union relay that still holds an ES slot, and DEPOSIT rows only on the current set; the registration need rule (§13.3 item 4) then redeems there. Cost: one extra ACCESS token per extra union relay per week, for at most 6 weeks after a slot-table change; §4.8's accounting and the T2 client model (§4.9) count it. A union relay that left the ES gets no capability; its last registrations lapse by themselves (§21.2 point 9), it then leaves the union, and blobs stored there are lost only if every relay of their week's set left too (declared in L7-D13).
4. **Tests.** `dm_relay_set.txt` gains: the same table in weeks w and w + 1 gives identical sets; a change of a slot outside the first three gives an identical set; a change inside changes it. Mutant **MC-22** (order keyed by the week) is detected by JD9 and by SCN-E (deposits refused after a week boundary).

### 21.2 Credentials: static per (card, relay slot, kind), bound to the slot (PRIV-1, CR-5, CR-16)

**Defects.** (1) The deposit credential's week was chosen by the sender's own clock, KEEPER timing and a relay's refusal (the fallback), while relays accepted three weeks at once: a sender with a clock offset switched scope at a device-specific minute in every inbox it wrote to, a malicious relay could tag a refused sender across sessions, and P-2 was false. (2) v3 credentials named no relay: a relay that saw a deposit or read secret could replay it at the other relays and operators of the set, exhausting the recipient's allowance there or listing the owner's inbox, against ADR-11 independence. (3) The fallback had no stop rule and could alternate refused stores without bound.

**Why not the reviewer's fixes.** "Always present week(now) − 1" and per-store random weeks near boundaries still select by the device clock, so the switch minute still leaks the offset, only diluted. The week in a card-derived secret protects nothing: every card holder derives every week's secret, the namespace is static (C-4), and relay binding (point 2) covers replay. The week is therefore removed from credentials and kept only in registrations, which lapse.

**Rules.**
1. **Secrets** (no week): `D_{i,s} = HKDF(card_secret_i, "ghost/v1/card/deposit" || u8(s))`, `RP_{i,s} = HKDF(card_secret_i, "ghost/v1/card/bundle-read" || u8(s))`, `RX_{i,s} = HKDF(m, "ghost/v1/dm/inbox-read" || u16_be(i) || u8(s))`, where s is the ES slot of the relay (the slot number Phase 8 already binds access tokens to, F8 D2). New vectors replace the weekly ones.
2. **Credential v3 (67 bytes)** = `version(1) = 3 || kind(1) ∈ {0x01 read, 0x03 deposit} || slot(1) || namespace(32) || secret(32)`; **verifier** = `SHA-256(label(kind) || u8(slot) || namespace(32) || secret(32))`. Every presenter at one relay sends identical bytes, so `capability_scope` is one value per (relay, namespace, kind) for all depositors or fetchers, in every week.
3. **Relay.** A relay without a configured slot (the Phase 8 `--slot` flag) refuses every v3 credential; a header whose slot is not the relay's own is `rejected_capability` before any verifier is computed (constant error, no oracle). `client-core` (T21) parses the 67-byte layout, checks the kind/operation matrix and the namespace, and refuses lengths 66 and 68; the slot check is the relay's.
4. **`RegisterKey` keeps its shape and the period rule** (`period_id ∈ {cap_week, cap_week + 1}`, judged by the capability, G-3; accumulation, SC-1). Records stay keyed `namespace || period || kind || verifier` with `valid_until = start(period + 2) + 1 h`; the owner registers the same verifier for each period.
5. **Authorization.** `store`/`check` with a deposit credential, and `list`/`get`/`check` with a read credential, need a record `(namespace, p, kind, verifier)` with `now < valid_until` for some p; the relay looks at `p ∈ [week(now) − 3, week(now) + 1]` by its own clock (internal to the relay, not observable).
6. **`DepositLedger`** entries are per record; a deposit is charged to the live matching record with the earliest `valid_until` that has allowance left; none → `RESOURCE_EXHAUSTED`. Restart semantics unchanged (§4.5).
7. **Senders.** One deposit credential per (contact, relay slot); no week choice and no fallback. `KEEPER` installs it with `expires_hour = ceil_hour(now) + 8 d` and refreshes it when fewer than 7 days remain; it never re-puts a credential on a listener hint. A credential refused by a relay (Phase 7 `unauthorized` → `wait_capability`) is re-put as a new generation **at most once per relay session start per (relay, namespace)**, so refused store attempts are bounded by one retry per session (CR-16).
8. **Owner.** The READ credential of `(r, X_0)` is installed once per relay and refreshed like point 7. Healing rule (§4.8) restated: when it is refused, every `done` row of `(r, X_0)` with `period ≥ week(now)` returns to pending, and reads use the write capability until a row is done again.
9. **Offline tolerance, restated.** Deposits are accepted while any registration lives: an owner whose newest write capability is of week c receives deposits until `start(c + 3) + 1 h`. An owner last online at its end-of-week-w renewal (capability w + 1) receives until `start(w + 4) + 1 h`, about three weeks; one last online earlier in week w until `start(w + 3) + 1 h`. §4.8's "about two weeks" and the fallback bullets are replaced.
10. **P-2 restated.** Every store into one inbox namespace at one relay with a deposit credential presents the same credential scope, in every week, whatever the sender's clock, session timing or earlier refusals. JD3: per (relay, inbox) at most one deposit scope over the whole world. The T32 world gains the F8 T2 clock model (10 % of devices offset U[−3 d, +3 d]) and the hostile mode **REFUSE_ONE_SENDER**; twin NI-DM6 (§21.9).
11. **Declared.** A relay sees one scope per inbox for as long as the card lives, which the static namespace already implies (L7-D13). F8 §10.7's "shared read keys per (namespace, epoch)" are realized per relay slot, with the epoch carried by the registration period (X-5, ADR-30, Q38).
12. **Tests and mutants.** `register.txt`: a credential replayed at another slot refused; a relay without a slot refuses v3; lengths 66 and 68; records of periods p and p + 1 authorize the same credential; the ledger charges the earliest record. T21 matrix rows. **PM-27** (weekly credential selected by the device clock) is detected by JD3 in the clock-offset world; **PM-28** (credential without slot) by the RK cross-slot replay case; **MC-15** is redefined as "a refused LOCAL credential re-put on every `CAPABILITIES` hint", detected by the SCN-E bound on refused stores per session.

### 21.3 Pair roots travel only in acknowledged sessions; renewal reset; P-7 restated (CR-1, CR-2 = CR-04, CR-13, PRIV-12)

**Defects.** (1) The first root of every conversation rode inside PreKey messages, which the recipient's seed-derived identity plus its retained prekey records (kept until `superseded + 91 d`) decrypt later: a seizure at day 70 recovered the root and opened week-0…2 pair envelopes, contradicting P-7 and T34. (2) `root_gen` restarted at 0 after a restore (or delete and re-add), the peer ignored a generation "not greater" than its stored one, and nothing cleared the peer's out keys on a session renewal: the peer kept sealing under a root the restored device no longer had. (3) A recipient that did not run for about 52 days erased its newest in-key in the first sweep before ratcheting forward. (4) Unanswered conversations stay intro-mode for good, which L7-D3 did not declare.

**Rules.**
1. **Roots only in SignalMessages.** A `seal_root` TLV is attached only when libsignal's output for that send is a `SignalMessage` (the session is acknowledged). A `seal_root` carried in a PreKey L1 is ignored on receipt (counter `root_in_prekey`). The one-scan flow (§12.2) becomes: A's first message is intro without a root; B's reply (a `SignalMessage` from the responder session) is intro-sealed and carries B's root; A's second message is pair-sealed under B's root and carries A's root; B's second message is pair-sealed. One more intro envelope per new conversation (Q40).
2. **Session renewal.** A `RECV` or `HELD` decrypt of a PreKey L1 from contact c during which libsignal called `markKyberPreKeyUsed` is a *renewal from c*. libsignal makes that call exactly when it creates a new session state, after the inner message decrypted (`session_management.rs:270-281`); a PreKey message matching an existing state is promoted without it (`session.rs:97-103`). `TxSignalStores` records the call in the transaction; once the decrypt returned and the blob passed R9 and R10, the same transaction (a) deletes every out key for c, so the next `seal_root` from c is accepted whatever its generation, and (b) inserts a new offer for c unless an unacknowledged one exists. Causality makes this safe: c's roots travel only in `SignalMessage`s, which exist only after c received my reply to the renewal.
3. **Generations never repeat on a device that kept the contact.** `dm_pair_offer` rows are kept while the contact exists; KEYDEC, acknowledgement and the 13-week replacement set `root` to NULL; SWEEP may delete a row with `root = NULL` only if a row of a higher generation exists. The next generation is `1 + max(root_gen)` over c's rows. A restore, delete and re-add, or unblock and re-add start again at 0, and the peer's floor is cleared by point 2 (my first message in the new state is a PreKey). §8.3's "my offered roots are erased" means their secrets.
4. **Stale roots from an archived state** (a delayed `SignalMessage` of c's previous session arriving after the renewal) follow libsignal, which promotes that state; the conversation then needs a reset from either side, exactly as without pair mode (declared with L7-D12).
5. **Ratchet before erasure (CR-13).** SWEEP first derives and stores, for every live in-generation, `K_w` for every week up to `week(now)` from the newest stored key, then erases keys past `start(w + 1) + FRESH`, in one transaction. RS2 asserts that pair envelopes open after a 60-day absence; mutant **MC-21** (erase before ratcheting) is detected by RS2.
6. **P-7 and T34 restated.** For an ISO week w with `now ≥ start(w + 1) + 45 d`, no key on either device and nothing derivable from either seed opens a pair-mode envelope of week w, **except** through a root-carrying message whose libsignal message key is still stored, as a skipped key, in the seized session record of that root's recipient (a copy lost or reordered in transit). libsignal keeps up to 2 000 skipped keys per receiver chain, 5 chains per state and 40 archived states, with no time bound; an active conversation evicts such a chain after five ratchet turns, an archived state keeps it. Declared in L7-D11.
7. **T34 seizure attacker extended.** It also runs libsignal decryption on every archived blob it can open, with the seed-derived identity, every retained signed and Kyber prekey record and every session record (current, archived, skipped keys). Expectation: pair-mode envelopes of old weeks opened = the ground-truth set of generations whose root carrier has a stored skipped key, and 0 in a lossless variant. Mutant **PM-29** (root in a PreKey L1) opens week-0…2 envelopes at day 70.
8. **Tests.** SCN-I asserts that pair envelopes open in both directions after the reconnect; KC8 asserts the same after a same-key renewal; mutant **MC-18** (out-key floor kept across a renewal) is detected by SCN-I.
9. **Unanswered conversations (PRIV-12), declared.** When the recipient never sends a user message, every envelope of that conversation is intro-mode (recognisable by a holder of the recipient's card colluding with relays, attributable with the recipient's seed), and the sender re-fetches a bundle after libsignal's 30-day soft archive, repeating the L7-D6 fetch→deposit link monthly. L7-D3 and L7-D6 are extended; P-7 covers answered conversations only; Phase 13 copy states it.

### 21.4 Intro bindings are bound to their envelope and fresh (CR-3, CR-4, CR-05)

**Defects.** (1) The binding signature named no recipient, time or message, so anyone who ever received an intro envelope from C could replay C's card and binding: to move C to `changed` with a historical key, to create "C tried to reach you" requests or `reset_needed` with a bogus `signed_pre_key_id` (libsignal throws `InvalidKeyId` before any key agreement, `session.rs:117-120`), or to make a new contact pin a historical key. (2) Intro envelopes stay openable forever and freshness ran after decryption, so a relay re-serving old intro PreKeys after prekey erasure or a restore brought back deleted, rejected or pre-restore-blocked identities as requests and filled the request cap; §7.6's B2 claim that such replays "cannot even be opened" was false. (3) A requester sending a second key drove `request → changed`, which no trigger or CHECK allows: an untyped abort crashed the process three times per blob.

**Rules.**
1. **Layout.** `Q = kind(1) || sender_card(163) || binding_minute(4) || binding_sig(64) || l1_len(4, BE) || L1 || zeros`, with `binding_minute` = `floor_minute(now)` at sealing (u32 minutes since the epoch) and
   `binding_sig = Ed25519(identity_sk, "ghost/v1/dm-binding/v2" || libsignal_identity_pk(33) || u16_be(card_index) || recipient_namespace(32) || u32_be(binding_minute) || SHA-256(L1))`.
   The intro extra of §6.6 becomes 285 B; `O_MAX` is unchanged. The minute is sealing time, not `author_minute`, because a pending send may be sealed days after compose.
2. **R5, before any state change.** Card valid; binding valid over the blob's own namespace, the L1 bytes and `binding_minute`; `now − FRESH ≤ binding_minute ≤ now + 2σ` (FRESH = 45 d, the timer being unknown before decryption). Otherwise `drop(stale)` or `drop(bad_binding)` with no state change.
3. **State before decryption.** Only two changes may precede R7, both under a binding that passed point 2: pinning a NULL `pinned_identity`, and a hold (§8.3). A request row inserted at R5 is kept only if the message is applied (R7–R10 pass), or R7 fails with `NoSession`/`InvalidKeyId` (kept with `reset_needed = 1`); every other drop deletes it in the same transaction. A genuine envelope that decrypts again after its requester was rejected or deleted (a new `contact_id`, so D3 does not match) is refused at R9 once older than the freshness of its bucket (§21.10), which an honest relay's D1 tombstone outlives; a relay that reports a short expiry and re-serves the envelope after the tombstone expired can bring back that requester's genuine message as a request within the window (declared, L7-D8). `reset_needed` on an existing contact needs the same fresh binding. An intro `SignalMessage` from an unknown identity creates a request with `reset_needed` (the post-restore healing signal of §8.6) and no content. §6.4's sentence on intro `SignalMessage`s is replaced by this point.
4. **Replays.** Within FRESH, a genuine intro PreKey hits a matching session (`DuplicateMessage`), the reuse tuple (`drop(replay)`) or, after a restore, `InvalidKeyId` (a genuine earlier attempt, which is what the request says). Beyond FRESH it stops at R5. Prekeys are erased at `superseded + 91 d`, later than `binding_minute + FRESH` for every bundle they served, so no replay after erasure passes R5. §7.6 B2 now reads: "a pair-mode replay beyond its key window cannot be opened; an intro replay opens but is refused at R5, before any state change, once older than FRESH".
5. **Requests (CR-05).** For `trust_state = request`, a PreKey L1 with `K′ ≠ pinned` under a valid binding is `drop(request_key_mismatch)` with no state change; a `request → changed` transition does not exist. After the request is rejected or expires, a later intro creates a fresh request. Every trust-state precondition of RECV, HELD, KEYDEC, `EST-*` and SEND is a Kotlin pre-check; a trigger or CHECK abort inside a DM transaction is a bug, never an expected path.
6. **Reasoning corrected (§3.4, §8.3).** A valid binding for `K′ ≠ K` exists whenever the holder of c's Ed25519 secret signs one: c itself (including a modified client), a derivation-version change, or a seed thief. A key change therefore means "c's identity asserts a new libsignal key".
7. **Tests.** KC5b: a genuine binding replayed with another recipient namespace, another L1 or a stale minute → no state change. KC12: a requester sending two keys → no crash, no state change. CB: a request-cap flood by RESURRECT after prekey erasure and after a restore → no request. Mutants **MC-20** (binding without namespace, minute and L1 hash) and **MC-24** (`request → changed` attempted).

### 21.5 libsignal session record bound (CR-6 = CR-06)

**Defect.** "2 000 skipped keys and 40 archived states fit in 1 MiB with a wide margin" is false: skipped keys are capped per receiver chain (5 chains per state, `MessageKey { index, seed }` ≈ 40 B), archived states keep their chains, so a record can reach about 41 × 5 × 80 KB ≈ 16 MB. Any peer with a session, including a requester, can push a victim's record past 1 MiB with counter-jumping messages and new PreKey states; the CHECK then threw an untyped constraint error inside RECV.

**Rules.**
1. The bound stays, as `SESSION_RECORD_MAX = 1 MiB` (records are read through the SQLCipher cursor window on Android; S5 measures the limit on the pinned SQLCipher), but `SqlSessionStore.storeSession` enforces it before writing and throws the GHOST type `SessionRecordOversizeException`. The SQL CHECK remains as an unreachable backstop.
2. **RECV and HELD.** The whole transaction rolls back; then an `OVERSIZE` transaction runs `markConsumed` (RECV), deletes `sig_session` of c, sets `reset_needed = 1` and counts `oversize`. **SEND, RESEND, `EST-READY`.** Rollback; a separate transaction deletes the session and keeps the item pending (result `QUEUED`, the §5.5 re-establishment path). A peer can only destroy its own session with me.
3. **Tests.** RO6 drives 41 states with full receiver chains through `TxSignalStores` and asserts the typed outcome, no crash, and a later reset that works; S0 records the measured worst-case record for an honest 10 000-message session. Mutant **MC-25** (oversize as an untyped exception) is detected by RO6.

### 21.6 libsignal API, addresses, store exceptions, module boundary (CR-7, CR-19, BUILD-4)

1. **API list (§2.3).** `SessionCipher(identityStore, sessionStore, preKeyStore, signedPreKeyStore, kyberPreKeyStore, SignalProtocolAddress localAddress, SignalProtocolAddress remoteAddress)` (`SessionCipher.java:57-78`); `encrypt(byte[], Instant)`; `decrypt(PreKeySignalMessage)` and `decrypt(SignalMessage)` **without** an `Instant` (`:193`, `:265`); R7 calls `decrypt(l1)`. `SessionBuilder` likewise takes both addresses. Added to the closed list: `SignalProtocolAddress`, `kem.KEMPublicKey`, `fingerprint.DisplayableFingerprint`, `FingerprintVersionMismatchException`, `FingerprintParsingException`, `IdentityKeyStore.Direction`, `IdentityKeyStore.IdentityChange`, and the Kyber reuse refusal type (`ReusedBaseKeyException` per the review; S0 confirms).
2. **Addresses (§8.1).** Remote = `SignalProtocolAddress(hex(contact_id), 1)` (32 lowercase hex characters); local = the constant `SignalProtocolAddress("ghost-local", 1)`. Neither parses as a Signal ServiceId (a hyphenated UUID, optionally prefixed `PNI:`, `address.rs:263-280`), so libsignal's `addresses` field (`protocol.rs:71-125`, MAC-checked by `verify_mac_with_addresses`) is never serialized. A unit test decodes a PreKey L1 and asserts the field is absent; a source comment forbids UUID-shaped or `PNI:` names. §6.1's header list gains `addresses` (present only for ServiceId names).
3. **Catch order.** The reuse refusal is caught before `InvalidMessageException` (if it is a subclass); a G-LS6 test pins the order.
4. **E-18 citations.** Production logging is `session_management.rs:130-131` and `:336-337` (the untrusted identity key in hex at warn) and the decryption-failure report at error (`:240-250`); `session_cipher_legacy.rs` is a `#![cfg(test)]` snapshot. The silent-logger conclusion is unchanged.
5. **`markKyberPreKeyUsed`** selects the tuple first: present → throws the pinned reuse exception; absent → inserts (and records the renewal of §21.3). **§2.4 rule 3 amended:** stores throw `IllegalStateException` for broken invariants, the reuse exception from `markKyberPreKeyUsed`, `SessionRecordOversizeException` from `storeSession` (§21.5), and nothing else. REPLACE guards `sig_signed_prekey_no_replace` and `sig_kyber_prekey_no_replace` are added; `ReplaceGuardsTest` covers them; RP5 asserts a replay is a typed drop.
6. **Module boundary (BUILD-4).** `:messaging` references no `org.signal` type. `:crypto-bridge` exposes GHOST types: `L1.parse(bytes)` → `PreKey(identityKey33, baseKey33) | Signal | Invalid`; `DmSessions.decrypt(tx, contact, l1)` → `Ok(plaintext, renewed) | Duplicate | NoSession | InvalidKeyId | Replay | Undecryptable | Untrusted | Oversize`; `DmSessions.encrypt(tx, contact, l0, now)` → `Ok(l1, isPreKey) | NoSession | Untrusted | Oversize`; `DmSessions.process(tx, contact, bundle, now)` → `Ok | Untrusted | InvalidKey | Oversize`. G-LS3 scans the `src/main` sets of every module and allows `org.signal` only in `crypto-bridge/src/main` (and `crypto-bridge/src/gate`, §21.13 point 7). The golden fixtures and `LibsignalUpgradeTest` live in `crypto-bridge/src/test/resources/libsignal-golden/<version>/`.

### 21.7 Establishment: forgotten tombstones, candidates, `EST-READY`, bounded attempts, restore without tokens (CR-02, CR-03, CR-09, PRIV-4, PRIV-11 = CR-10)

**Defects.** (1) Phase 7 keeps consumed-blob tombstones across `remove` and re-register (`Namespaces.kt:5`, `InboxStore.kt:118-131`), so a reset, a key-change re-establishment or a re-added contact could not see bundles consumed earlier and waited up to a week. (2) After a restore, contacts fetched the lost device's bundles (the restored device has no tokens to publish, and equal-week ties were a coin flip), so contact-initiated resets failed silently. (3) BUNDLE enqueued without the exact deadline (`OutboxStore.enqueue` requires `deadline > now`) or a trust check (`UntrustedIdentityException` in `process` for a contact that became `changed`). (4) A missing bundle kept `P_c` listening for 7 days, co-occurring with the fetcher's session starts and linkable by AD-1 withholding bundles. (5) T28's static rule forbade the enqueue that §5.5 and G-DM2 required, and nothing flushed pending sends when an inbound PreKey built the session first.

**Why not the reviewers' fixes in full.** A per-contact long-lived bundle cache was not adopted: forgetting tombstones gives the same availability without keeping a deleted contact's keys. A separate short transport session per fetch does not exist in Phase 7; attempts are bounded instead.

**Rules.**
1. **Issuance marker.** `bundle_plain` gains `issued_hour(4)` (u32 hours since the epoch, `floor_hour` at sealing) after `bundle_week`: 1 890 bytes. Bundles are ranked by `(bundle_week, issued_hour)` descending, then the smaller blob hash.
2. **`EST-START`** calls the new `:sync` operation `Inbox.forgetConsumed(tx, namespace)`, which deletes the consumed tombstones of a namespace whose consumer is `PREKEYS` (refused for any other consumer; re-consuming a bundle is idempotent), then registers `P_c` listening, installs the `RP_{c,s}` credentials (§21.2), and sets `fetch_attempts = 1`, `fetch_listen_until_minute = ceil_minute(now + 15 min)`.
3. **BUNDLE** (one consumed blob): open and verify as in §5.5, then keep the better candidate in `dm_bundle_candidate(contact_id, bundle_env, bundle_week, issued_hour)`; nothing else. A key change found in a bundle (`K′ ≠ pinned` under a valid binding) still moves the contact to `changed` and keeps the candidate; after the user's decision `EST-READY` builds from that candidate while it is valid, otherwise a new attempt starts (with `forgetConsumed`).
4. **`EST-READY`** (time-triggered, §21.9: at the first candidate's insert + 2 min, or at `fetch_listen_until_minute` if a usable session exists without a candidate; the 2-minute delay lives in memory, so after a restart an existing candidate is processed at the next time-triggered pass): require `trust_state ∈ {unverified, verified}`, else keep the pending items and the candidate and stop; fail every pending item whose exact deadline is ≤ now + 1 min; pin a NULL identity; `DmSessions.process(best candidate)` unless a usable session already exists (an inbound PreKey built it, R-E4); encrypt and enqueue every remaining pending item; `establishment = ready`; `setListening(P_c, false)`; delete the candidate. Typed results: `Untrusted` → keep pending; `InvalidKey` → drop the candidate, count, and let the attempt continue; `Oversize` → §21.5; `StorageFullException` → retried at the next time-triggered pass.
5. **`EST-END`** (time-triggered at `fetch_listen_until_minute` with no candidate and no usable session): `setListening(P_c, false)`; if `fetch_attempts < 3`, the next attempt starts at the first relay session start at least 6 h later with a new 15-minute window; after the third, `establishment = unreachable` and the pending items fail (the user may retry). `Namespaces.remove(P_c)` runs once no fetched row remains (SWEEP retries).
6. **Declared (L7-D6 extended).** A listening `P_c` co-occurs with at most three session starts per establishment; a relay set that withholds bundles gains those samples; a relay that serves a bundle chooses when `EST-READY` runs (≥ 2 min later). Hostile mode **WITHHOLD_ALL_BUNDLES**; a JD7 variant requires ≤ 3 attempts and `P_c` list events only inside attempt windows; mutant **PM-31** (unbounded attempts).
7. **T28 static half (PRIV-11 = CR-10).** RECV, BUNDLE and HELD never call `Outbox.enqueue`, `Namespaces.register`/`setListening`/`remove`, `Registrations` or `Capabilities.put`. G-DM2's allowed callers: SEND, RESEND, `EST-START`, `EST-READY`, `EST-END`, OWNER-WEEK, ACTIVATE, KEEPER, REGROWS, and SWEEP (`Namespaces.remove` only). The recording Outbox wrapper of §15.1 stands; JD6 maps each `EST-READY` store to the user action of its item. §13.5's establishment row: `fetching → ready` only through `EST-READY`.
8. **Restore (CR-03).** A restored device has no tokens (Phase 8 E11), so it can neither register nor publish until it gets tokens (a trial from a new invite, or a pack). Meanwhile contacts' fetches return the lost device's bundles (valid up to two weeks, stored up to 30 days), whose PreKey messages fail at the restored device with `InvalidKeyId` (a request with `reset_needed` there, §21.4 point 3). Healing therefore starts from the restored side: `reconnect` needs no token (it fetches the contact's bundle and deposits with the contact's credential). §8.6's "their `resetSession` fetches my new bundle" holds only after the restored device has published; with tokens, its week-w bundle outranks the old device's by `issued_hour`. L7-D12 extended. RE cases: the old device's bundle in the same and the previous week, a restored device without tokens, and a contact-initiated reset in each.
9. **Schema.** `dm_contact.fetch_until_day` is replaced by `fetch_attempts INTEGER NOT NULL DEFAULT 0 CHECK (fetch_attempts BETWEEN 0 AND 3)` and `fetch_listen_until_minute` (minute column, `CHECK ((establishment = 'fetching') = (fetch_listen_until_minute IS NOT NULL))`); new table `dm_bundle_candidate` (`contact_id` PK, cascade; `bundle_env` 1 918 B; `bundle_week`; `issued_hour` in seconds with `% 3600 = 0`) with a REPLACE guard.

### 21.8 Durable outbound items; FAILED controls and bundles; quote reference inside the envelope (CR-07, CR-17, BUILD-5)

**Defects.** CONTROL messages and reactions had no row a pending send, an outcome or a retry could use (`dm_message.kind IN (1, 2)`, `dm_pending_send` and `dm_outbound_op` referenced `dm_message`), so a reconnect could not wait for a bundle and a FAILED control vanished; a user retry could not rebuild the L0 (timer version and TLVs were not stored). A FAILED bundle op could not be re-sealed because OWNER-WEEK's week guard had already advanced. `dm_message.quote_ref` was a plaintext column equal to a quoted `message_id`, which fails the T25 physical scan legitimately, while content copied into `body_env` is invisible to a byte scan.

**Rules.**
1. **`dm_outbound_item`** holds every outgoing L0:
   ```sql
   CREATE TABLE dm_outbound_item (
     item_id       BLOB PRIMARY KEY NOT NULL CHECK (length(item_id) = 16),            -- the L0 message_id
     contact_id    BLOB NOT NULL REFERENCES dm_contact(contact_id) ON DELETE CASCADE,
     message_ref   BLOB REFERENCES dm_message(message_id) ON DELETE CASCADE,         -- TEXT, TIMER_SET: itself; REACTION: target; CONTROL: NULL
     kind          INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
     control       TEXT CHECK (control IS NULL OR control IN ('reconnect', 'revocation', 'reset')),
     l0_env        BLOB CHECK (l0_env IS NULL OR length(l0_env) BETWEEN 29 AND 65564),
     deadline_hour INTEGER NOT NULL CHECK (typeof(deadline_hour) = 'integer' AND deadline_hour % 3600 = 0),
     state         TEXT NOT NULL CHECK (state IN ('pending', 'enqueued', 'sent', 'degraded', 'failed', 'indeterminate')),
     CHECK ((kind = 4) = (control IS NOT NULL)),
     CHECK (kind = 4 OR message_ref IS NOT NULL)
   ) WITHOUT ROWID;
   ```
   `l0_env` is the exact L0 under the content key. It becomes NULL at SENT, DEGRADED or INDETERMINATE and at the deadline; a FAILED item keeps it until the deadline. `dm_pending_send` is keyed by `item_id`; `dm_outbound_op.purpose ∈ {'item', 'bundle'}` with `item_id` for items and `bundle_week` for bundles. REPLACE guard and state trigger added.
2. **SEND** writes an item for every kind; `dm_message` rows exist only for TEXT and TIMER_SET, own reactions in `dm_reaction(from_self = 1)`.
3. **Retry** of a FAILED TEXT, TIMER_SET or REACTION item re-encodes the stored L0 with identical `message_id`, author minute, minute index, timer code, timer version and body, and the TLVs pending now (§21.3 point 1 applies to the new output); D3 dedups by `message_id`.
4. **FAILED controls.** A reconnect or revocation item that ends FAILED is rescheduled as a new item (new `message_id` and author minute) at a fresh `U[0, 24 h]` offset, at most 3 times, then counted `control_failed` in `status()`. A `reset` control (from `resetSession`) and a REACTION end `failed` and may be retried by the user. INDETERMINATE items behave as messages (§7.5).
5. **Bundles (CR-17).** `dm_self` gains `bundle_published_week`. OUTCOME sets it to the op's `bundle_week` at SENT or DEGRADED. OWNER-WEEK rotates when `bundle_week < w`, and re-seals the current bundle (new salt, same prekeys and `issued_hour`) when `bundle_published_week < bundle_week` and `now < start(bundle_week + 2) − 1 h`. An OS case covers a FAILED and an INDETERMINATE publication.
6. **Quote reference (BUILD-5).** `dm_message.quote_ref` is removed; `body_env = AEAD(content_key, flags(1) || quote_ref(0 | 16) || body, AD = message_id)`. The T25 physical scan keeps looking for expired `message_id`s. ME-12 is detected by a logical scan that decrypts every `*_env` column with the harness content key and searches for the canary, in addition to the byte scan.
7. **Structural invariants and scenarios.** Every `pending` or `enqueued` item has a pending send or an unreleased op; SCN-I gains a variant in which the reconnect CONTROL waits for the contact's bundle; SCN-K gains a FAILED revocation that is rescheduled.

### 21.9 Activity-independent triggers; coarse upload times; consumer cost model (PRIV-3, PRIV-9, PRIV-7)

**Defects.** Bundle publications, scheduled reconnect and revocation controls and re-seals ran at the first actor wake after their time, and wakes include `INBOX` hints (fetched inbound blobs) and the user's own sends: a card holder with AD-1 could deposit a probe during the target's session and watch its due controls go out a minute later into its contacts' inboxes. Relays return `uploaded_at` to the minute, so any card holder saw the owner's first session after `t_pub` each week. PM-25 could not be detected, because the harness charges virtual time only for relay calls (`EngineTestKit.kt:241-242`).

**Rules.**
1. **Time-triggered steps** (OWNER-WEEK, re-seals, the week-change parts of KEEPER and REGROWS, due scheduled controls, `EST-READY`, `EST-END`) run only from: the actor timer set to `min(next delete_at_minute, t_pub, next due_minute, next week boundary, next EST timer)`; database open; and a relay session start (foreground or background, a Phase 7 event).
2. **Hint- and facade-triggered passes** run only SWEEP, RECV, BUNDLE, HELD, OUTCOME/RESEND, DISPLAY, KEYDEC, user SEND, and KEEPER/REGROWS maintenance for a capability just installed (`CAPABILITIES`). §13.7's pass order is split accordingly.
3. **Twin NI-DM6.** Worlds that differ only in inbound arrival times, in the send times of unrelated contacts, in sender clock offsets and in REFUSE_ONE_SENDER give identical minutes of bundle stores, scheduled-control stores and registrations, and identical deposit-scope multisets per (relay, inbox). Mutant **PM-30** (time-triggered steps on any wake) is detected by NI-DM6.
4. **Coarse upload time (PRIV-9).** For `get` authorized by a v3 read credential, a relay returns `uploaded_at_unix_seconds` floored to the start of its ISO week (the proto already allows relay-policy granularity; a `relay_semantics.txt` case and a capture-independent node test). §11.2's AD-7 cell for bundle publication reads: "sees rotations and the publication week; with a relay, the owner's first session after `t_pub` each week, absences and the restore or activation minute (L7-D10)". Q43.
5. **PM-25 (PRIV-7).** Detected by a direct ordering assertion in `SessionParticipantTest` (the tail starts only after the issuer call returned and the transport closed) and by NI-DM1 with a `DmWorld` consumer cost model: virtual time per claimed blob (1 ms per 1 000 HMACs, 1 ms per AEAD open, 5 ms per libsignal decrypt, 1 ms per row write; a forged blob costs its full hint set), plus an NI-DM1 variant with equal blob counts and a different valid/forged mix, comparing session close minutes.

### 21.10 Ephemeral: bucket deadlines without cancel, freshness per bucket, held expiry, display guard, alarm, reboot, notifications (PRIV-2, PRIV-8, CR-11, CR-14, BUILD-13, BUILD-9, BUILD-6)

1. **Deadline (PRIV-2).** Every DM item carries `deadline = author + min(bucket(timer), 7 d)` (off → 7 d). Only 5-minute messages change: their store deadline is `author + 1 h`, like 1-hour messages, so NI-DM4 compares equal inputs and a HIGH-mode send delay of up to 10 minutes can no longer outlive the deadline. §10.1's deadline row and R-T4, D15 and T30 read accordingly; the honest-relay bound for 5 minutes becomes that of 1 hour. Q41.
2. **No cancel at expiry.** SWEEP never calls `Outbox.cancel` for a DM op: ops run to their outcome or deadline. The message row, its item and the retained blob cascade at expiry (T25 logical); the Phase 7 op payload (the same E2E bytes, which no key on the device opens) is bounded by the op's outcome or `deadline_hour`, and the T25 physical scan for blob bytes uses that bound. EP case: HIGH mode, a 5-minute message whose `not_before` falls after its expiry is stored. Mutant **ME-21** (`Outbox.cancel` at expiry) is detected by that case and NI-DM4.
3. **Freshness per bucket (PRIV-8).** `FRESH(b) = min(b, 7 d) + b + 2 h + 2σ`: 1 h → 6 d 4 h; 1 d → 8 d 2 h; 7 d → 20 d 2 h; 30 d and off → 43 d 2 h, kept at 45 d. R9 uses `FRESH(bucket(timer_code))` of the decrypted L0; D3's `until_day = ceil7(day(author_minute) + ceil_days(FRESH(b)) + 1)`. The pair-key window, the prekey retention and R5's binding freshness keep FRESH = 45 d. HELD evaluates R9 at the held row's consume minute.
4. **Declared, corrected.** A seizer who knows candidate `message_id`s (their sender, a colluding contact) can confirm from `dm_seen` that the device received them and in which week, until `until_day` (§10.8, R-M1 and L7-D7 no longer say "nothing about content or sender"). ME-6 is detected by a dictionary test that recomputes keyed and unkeyed tags of the world's `message_id`s over the dump after expiry.
5. **Held messages (CR-11).** `dm_held` gains `relay_expiry_hour` (hour) and `consume_minute` (minute), both in R-M3. HELD's R9 and R11 use them; a replayed message whose computed unread deadline is ≤ `now_e` is not inserted (counted `expired_while_held`). EP cases: hold, acknowledge and replay with 1 h and 30 d timers, deletion by the original `min(E, consume + bucket + 1 h)`.
6. **DISPLAY (CR-14)** ignores ids whose `delete_at_minute ≤ now_e`. Trigger `dm_message_expiry` names `expire_at_minute` and `unread_deadline_minute` only; `delete_at_minute` follows its CHECK and may move later at display (ADR-27 point 9). EP case: a stale `markDisplayed` after the unread cap.
7. **Alarm call (BUILD-13).** `setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + (next − now), pendingIntent)`; a unit test checks the computed trigger time.
8. **Reboot (BUILD-9).** No boot receiver exists or is added (G-DM7). After a reboot the next sweep waits for the persisted periodic job, which has a network constraint, or the next app open; an offline rebooted device keeps expired rows (encrypted, never shown) until then. The §10.7 sentence about `RECEIVE_BOOT_COMPLETED` is withdrawn; L7-D14 is extended.
9. **Notifications (BUILD-6).** Phase 9 posts no notification (a no-op port; no `POST_NOTIFICATIONS`). ADR-27's notification rules are proven in Phase 9 only by the `NotificationPort` contract test; the `getActiveNotifications()` check (§15.9 item 5), the notification-history check (§15.10 step 6) and the corresponding §15.8 evidence are removed and move to Phase 13 with its permission ADR and device check.

### 21.11 Declared leakage, TTL-class pairing, size classes, PQ wording (PRIV-6, PRIV-5, PRIV-10, CR-8)

1. **LD (PRIV-6)** gains everything the honest protocol shows relays and the design already declares: the grouping of one client's requests per circuit within a session (L7-D5); exact arrival times; the identical hash of an identical-bytes resend (L7-D9); the `result` of every request, refusals included; the one static credential scope per (relay, namespace, kind) (§21.2); the bounded bundle fetch attempts (§21.7). S-DM1's LD attacker receives the same features; the baselines are recomputed.
2. **TTL-class pairing (PRIV-5).** Both directions of a conversation use its bucket, so a non-default timer pairs the conversation's two inboxes: with the T32 mix (1-hour bucket 15 %), reply-timing SDA isolates such a pair in about 2–3 exchanges instead of ~6–8. L7-D1 and L7-D4 say so; S-DM2 and rounds-to-single-out are reported per TTL class and per mode; S-DM4 adds the cross-inbox pairing measure; ADR-32's consequences and the Phase 13 copy (CP-10) state that non-default timers make a conversation easier to link at relays. Q39 offers fewer DM TTL classes as an ADR-27 deviation (default: keep ADR-27).
3. **Size classes (PRIV-10).** `B = min{ b : L_class ≤ b − O_MAX }` with `L_class = 52 + |body| + EXT_RESERVE`, where 52 B are the fixed L0 fields with the quote reference always counted and `EXT_RESERVE = 160 B` (a `seal_root` TLV 46, a revocation TLV 106, `session_reset` 4, 4 spare). Senders refuse `ext_len > 160` in Phase 9 (receivers accept up to 1 024). Body capacities: 4 KiB → 1 324 B; 16 KiB → 13 612 B; 64 KiB → 62 764 B (`MAX_BODY_BYTES = 61 440` unchanged). NI-DM2 and the property test use body lengths at the class boundaries with and without pending TLVs and quotes. Mutant **ME-22** (bucket from the full L0 length) is detected by NI-DM2.
4. **PQ wording (CR-8).** §9.3, intro inner layer: a future quantum adversary holding my card and AD-1's archive opens recorded intro envelopes to me and learns each sender's full card (Ed25519 identity, hence `ghost1`, and `card_secret`, hence that sender's inbox and bundle namespaces and deposit credentials) and binding: the identities of my first-contact, reset, reconnect and unanswered-conversation senders. §9.3, signatures: while no libsignal key is pinned (first contact, including a card verified in person before its bundle was fetched), a forged binding or bundle signature is pinned silently. L7-D3 and R-19 are extended; ADR-31 names a KEM-based intro inner layer as the P2 mitigation.

### 21.12 Poison guard, resumable activation, orphan namespaces (CR-08, CR-12, CR-18)

1. **Poison guard (CR-08).** `Inbox.claim` commits the offer counter before the hand-off (`InboxStore.kt:306-335`), so non-fatal failures used to count as process deaths. Rules: the actor claims no `DM` or `PREKEYS` blob while the native library or the DM keys are unavailable; the `ConsumerTail` claims one blob at a time and stops claiming when fewer than 2 s of its deadline remain; a RECV or BUNDLE transaction that rolls back with `StorageFullException` is followed by `Inbox.defer(ns, hash, 60 s)` in its own transaction, which resets the counter (`InboxStore.kt:347-354`; a local re-offer time, no relay-visible effect, so not a T28 reflex), and if that also fails an in-memory storage-full latch stops DM claims until a write transaction succeeds. R2's threshold then counts process deaths and native crashes only. SCN-J gains a persistent `SQLITE_FULL` over four passes and a deadline-truncated tail, asserting no loss.
2. **Resumable activation (CR-12).** At every actor start and database open: if an activated identity exists and `dm_self` does not, ACTIVATE runs. Restore semantics apply when the Phase 8 restore state (`ent_state.restore_scan_root`, written before the seed is persisted, `RestoreScan.kt:48-61`) commits to the stored identity; `accept_after_minute` is then `floor_minute(now)` of the resumed ACTIVATE (a later minute only refuses more pre-restore content). A migrated v3 database with an activated identity is activated at the first actor start (SCN-L). Crash-enumeration cases between identity persistence and the ACTIVATE commit, for activation and for restore.
3. **Orphan namespaces (CR-18).** `block` and `deleteContact` insert `dm_orphan_namespace(namespace_id)` rows for `X_c` and `P_c` in their transaction (REPLACE guard; no time column); SWEEP calls `Namespaces.remove` for each and deletes the row when it returns true (no op, no fetched row left; `remove` also deletes the credentials, `DirectoryStore.kt:187-205`). The residue lasts at most until the last op's deadline (≤ 7 d) and is declared in L7-D7; R-M1 and a T25 assertion cover the `:sync` tables after block and delete plus that bound.

### 21.13 Licence and CI artifacts, NDK and sums, slices, device checklist, smoke test, T2 export, gate variant, runbook, migration test (BUILD-1, BUILD-2, BUILD-3, BUILD-7, BUILD-8, BUILD-11, BUILD-12, BUILD-14, CR-15 = BUILD-10)

1. **Licence and conveying (BUILD-1).** The repository is public and `ci.yml:198-203` uploads `app-release-unsigned.apk` on every push and pull request; from S0 that APK contains AGPL libsignal, and the repository has no licence file. **S0, before libsignal enters the build**, removes every APK artifact upload (release and debug) while Q1 is open; CI artifacts, emulator images and staging uploads count as conveying. **Q1 is excluded from the default rule:** its default is a proposal, ADR-29 stays "Propus" until the owner decides, and no APK leaves the build machines before that. A release-checklist item (S13, required before the first distribution): `LICENSE` and `NOTICE` files, the APK's legal notices (a Phase 13 screen), the libsignal source tarball mirrored with its sha256, and the Corresponding Source offer.
2. **NDK and sums (BUILD-2).** `:app` pins `android.ndkVersion` to the CI `NDK_PACKAGE` version; the `android`, `reproducible` and `dm-emulator` jobs install that NDK. A committed `ghost/libsignal-natives.sha256` (the stripped `libsignal_jni.so` per ABI), changed only by a libsignal bump PR, is checked by `apk-native-libs.sh`; `build-native.sh`'s regenerated `native-libs.sha256` stays for `libghost_client_net.so` only. G-LS1 also fails when the packaged library has any `.debug_*` section or exceeds 16 MiB per ABI; a self-test fixture covers both.
3. **Slices (BUILD-3).** Migration 4 lands whole in S3: steps 0–6 including the `dm_*` and `sig_*` DDL of §13.6 and §21.14, the triggers, `CURRENT_VERSION = 4`, `expectedTables` and `expectedTriggers`, so every slice leaves a consistent v4 that `MigrationRunner.verifyIntegrity` accepts. S5 becomes the trigger transition tests, the introspection tests (R-M1, R-M3, R-M4) and the DAO lint. G-LS3's logger rule reads "at most one call site" until S4 adds `SignalLog`. G-LS4's previous-directory rule is exempt for the first pin (0.86.5 was never used).
4. **Device checklist (BUILD-7).** Every step that adds a contact, sends, displays or sets a timer is † and runs through the `gate` variant's instrumentation; step 1 injects the scanned card by adb as `addContact(card, qr_in_person)` (no camera, no new permission). S12 gains the `gate` build type, `scripts/device/dm-gate.sh`, the digest export and a host re-store tool (a `client-core` test binary that stores captured blobs over Tor with a deposit credential), each with a self-test.
5. **Release smoke test (BUILD-8).** On the release variant: load both native libraries, install the silent logger, run one in-process libsignal session between two in-memory store sets; no transport. The loopback-relay session runs in the debug `androidTest` variant only. The release APK gains no transport-injection seam (G-DM5 extended).
6. **T2 export (BUILD-11).** The T2 world enumerates every `*.redb` in each relay data directory and fails on an unknown file or table (`world.rs:4068-4085` iterates two named files today); the `keys.redb` export and completeness check land in S1 with the relay change.
7. **Gate variant (BUILD-12).** ADR-34 records the `gate` variant: built locally or in a job that uploads nothing, signed with a throwaway key, installed only on the gate devices, never distributed. The debug key-change hook lives in `crypto-bridge/src/gate` (a G-LS3 exception for that source set); G-DM5 checks source-set membership of the release variant and R8's `mapping.txt`, not obfuscated class names; `anti-placeholder.sh` scans `*/src/gate/*`.
8. **Runbook and staging (BUILD-14).** §16.4 adds `ghost/infra/issuer/RUNBOOK.md` (the O1 expected listings now include `keys.redb`, created at start; its loss and healing) and an S12 item deploying S1 relays to staging (`infra/relay/docker-compose.staging.yml`) in capture mode before checklist step 8.
9. **Migration test (CR-15 = BUILD-10).** Trigger and index rows naming `outbox_op`/`outbox_delivery` are compared by (type, name, sql) exactly; the two tables by `PRAGMA table_info`, `foreign_key_list` and `index_list` equality plus normalized SQL (identifier quoting normalized), asserting the `ttl_seconds` CHECK as the only difference; row and rowid preservation are unchanged. MC-17 relies on this test.

### 21.14 Tests, mutants, counts, schema delta, questions

**New and changed mutants.** Privacy: PM-27 (§21.2), PM-28 (§21.2), PM-29 (§21.3), PM-30 (§21.9), PM-31 (§21.7); PM-25 detection per §21.9. Correctness: MC-15 redefined (§21.2), MC-18 (§21.3), MC-20 (§21.4), MC-21 (§21.3), MC-22 (§21.1), MC-23 (EST-START without `forgetConsumed`: RS/KC cases of a reset and a key-change acknowledgement in the bundle's week), MC-24 (§21.4), MC-25 (§21.5). Ephemeral and envelope: ME-21 (§21.10), ME-22 (§21.11); ME-6 and ME-12 detection per §21.10 and §21.8. **Counts:** 32 privacy, 25 correctness, 22 ephemeral and envelope; the gate line becomes `dm mutants: 79 run, 79 detected`.

**New cases.** KC5b, KC12, RO6, the RE old-bundle and no-token cases, OS FAILED and INDETERMINATE publications, EP (HIGH 5-minute store, held replay, stale display), SCN-I and SCN-K variants, SCN-J persistent disk-full and truncated tail, CB request flood, the reset and key-change establishment within the bundle's week (MC-23). Twin NI-DM6; hostile modes REFUSE_ONE_SENDER and WITHHOLD_ALL_BUNDLES; the T32 clock-offset population.

**Schema delta (migration 4, S3).** New tables `dm_outbound_item`, `dm_bundle_candidate`, `dm_orphan_namespace`. `dm_contact`: `fetch_until_day` → `fetch_attempts`, `fetch_listen_until_minute`. `dm_message`: `quote_ref` removed. `dm_outbound_op`: `purpose ∈ {'item', 'bundle'}`, `item_id`, `bundle_week` (replacing `message_id` and `contact_id`). `dm_pending_send`: keyed by `item_id`. `dm_held`: `relay_expiry_hour`, `consume_minute`. `dm_self`: `bundle_published_week`. REPLACE guards for every new table and for `sig_signed_prekey`, `sig_kyber_prekey`. R-M3's time-column set: minus `dm_contact.fetch_until_day`, plus `dm_contact.fetch_listen_until_minute`, `dm_held.{relay_expiry_hour, consume_minute}`, `dm_outbound_item.deadline_hour`, `dm_bundle_candidate.issued_hour`; period indices plus `dm_self.bundle_published_week`, `dm_bundle_candidate.bundle_week`, `dm_outbound_op.bundle_week`. `:sync` API (X-12, ADR-34) gains `Inbox.forgetConsumed`.

**Vectors.** `dm_relay_set.txt` (§21.1), `register.txt` and the credential and derivation vectors (§21.2), `dm_seal.txt` intro cases with binding v2 (§21.4), bundle layout with `issued_hour` (§21.7), `dm_content.txt` with `EXT_RESERVE` class cases (§21.11), `relay_semantics.txt` coarse `uploaded_at` (§21.9).

**Owner questions.** Q1 is amended (excluded from the default rule; no APK artifacts while open). New: Q38 (static per-slot credentials), Q39 (DM TTL classes), Q40 (roots only in acknowledged sessions), Q41 (5-minute store deadline of one hour), Q42 (bounded bundle fetch attempts), Q43 (coarse `uploaded_at` for v3 reads). ADR-28 … ADR-34 in Appendix A carry these corrections.

---

## Appendix A: ADR drafts (Romanian)

Numerele încep la ADR-28 (ADR-21 e rezervat; ADR-22 … ADR-26 sunt ale Fazei 8, propuse și aplicate; ADR-27 e aprobat). Toate au statusul „Propus, aplicat în Faza 9”: designul le aplică, iar proprietarul decide (§19, Q4). Q1 (licența) condiționează prima distribuire a unui APK și cere o decizie explicită. Corecturile de după revizie (§21) sunt incluse în fiecare ADR, fie direct în text, fie în secțiunea „Corecturi după revizie”, care are prioritate.

> # ADR-28 — Integrarea libsignal: artefactele Android oficiale, versiune fixată, depozitul Signal, JDK 21, API închis, jurnalizare oprită
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9, `docs/design/faza9-dm.md`) |
> | Sursă | Design Faza 9 (§2, §9, §16), cercetarea R-libsignal |
> | Completează | FR-2.1, Anexa A a specificației, ADR-12, ADR-06 (T7), ADR-07 (T12) |
> | Modifică | `libs.versions.toml` (0.86.5 → 0.102.2; se adaugă `libsignal-client`); `settings.gradle.kts` (depozit `exclusiveContent` doar pentru `org.signal`); CI (JDK 17 → 21); `apk-native-libs.sh` (hash per ABI pentru `libsignal_jni.so`); porți noi G-LS2 … G-LS4; ADR-12 (precizează cum e îndeplinit) |
>
> ## Context
> FR-2.1 cere artefactele Android oficiale libsignal. Versiunea fixată azi, 0.86.5, e ultima de pe Maven Central, nefolosită, cu SPQR opțional. De la 0.86.6 artefactele se publică doar în depozitul Signal; de la 0.100 SPQR e obligatoriu pentru toate sesiunile; `libsignal-client` 0.102.2 cere JVM 21. Biblioteca nativă conține cod de rețea inactiv și e construită de Signal. Crate-urile Rust nu sunt pe crates.io. Calea de decriptare a bibliotecii scrie în jurnal cheile de identitate neîncrezute, în hex.
>
> ## Decizie
> 1. `org.signal:libsignal-android` și `org.signal:libsignal-client`, aceeași versiune exactă (0.102.2, refixată la S0 la cea mai nouă ≥ 0.100), din `build-artifacts.signal.org`, prin `exclusiveContent` doar pentru grupul `org.signal`, cu sha256 în `verification-metadata.xml`. Fără actualizări automate: fiecare actualizare e un PR separat care rulează toată poarta DM, dimensiunile de referință și exercițiul cu înregistrări-martor (`libsignal-golden/<versiune>/`, `LibsignalUpgradeTest`).
> 2. ABI livrate: arm64-v8a și x86_64; strip prin AGP cu NDK-ul fixat prin `android.ndkVersion` și instalat în joburile care construiesc APK-ul; bibliotecile native desktop din `libsignal-client` servesc doar testelor JVM și nu intră în APK (G-LS2). Biblioteca se încarcă leneș; lipsa ei devine rezultatul `CryptoUnavailable`, nu o buclă de crash.
> 3. API închis: `SessionBuilder`, `SessionCipher`, cinci interfețe de store (cea de prekey-uri de unică folosință e goală), cheile și înregistrările, tipurile de mesaj, excepțiile tipizate, `NumericFingerprintGenerator`, furnizorul de logger. Sunt interzise `metadata.*` (sealed sender), `net`, `zkgroup`, `usernames`, `messagebackup`, `svr`, `media`, `attest`, `keytrans`, `internal`, `groups` (G-LS3). Doar `:crypto-bridge` depinde de `org.signal` (G-LS3); `:messaging` folosește tipuri de rezultat GHOST (§21.6).
> 4. Store-urile sunt vederi fără stare legate de tranzacția SQLCipher curentă, construite și folosite doar pe firul actorului DM; aruncă `IllegalStateException`, excepția de refolosire Kyber și `SessionRecordOversizeException`; o înregistrare de sesiune peste 1 MiB e un rezultat tipizat (sesiunea contactului se șterge și se marchează `reset_needed`), nu un crash (§21.5, §21.6).
> 5. PQ: PQXDH și SPQR obligatorii prin versiunea bibliotecii, fără setare și fără KEM separat; testul PQ-3 verifică la fiecare actualizare. Prekey-ul KEM e ML-KEM-1024 dacă API-ul îl generează, altfel Kyber1024 (Q21).
> 6. Bibliotecii i se transmite timpul rotunjit la minut; înregistrările prekey primesc timpul rotunjit la zi.
> 7. Un logger care nu scrie nimic se instalează o singură dată, înaintea primei folosiri; e obligatoriu pentru T3, iar testul canar T3 rulează o decriptare cu identitate neîncrezută cu un logger care înregistrează.
>
> ## Consecințe
> (+) PQ implicit; nicio linie de JNI scrisă de GHOST pe granița criptografică; audit restrâns; configurația pe care o livrează Signal. (−) Cod de rețea inactiv în `.so` (acoperit de G-LS3, R8 și T6); încredere în build-ul Signal (T12 nu dovedește corespondența cu sursa, LIMITE L5); aproximativ 22 MB în APK; migrări de API frecvente; utilizarea în afara Signal e „nesuportată”.
>
> ## Alternative respinse
> 0.86.5 (SPQR poate lipsi, fără corecții); crate-urile Rust în `client-core` (JNI propriu peste store-uri asincrone, excepții `deny.toml` pentru git și AGPL, `curve25519-dalek` 5.x alături de 4.1.3), păstrate ca rezervă dacă proprietarul respinge codul de rețea inactiv (Q2); build propriu al `signal_jni` (același cod de rețea, cost mare; opțiune pentru Faza 15).
>
> ## Teste
> Dimensiunile de referință; înregistrările-martor și `LibsignalUpgradeTest`; PQ-3; granularitatea timpului din înregistrări; `SilentLoggerTest` și canarul T3; G-LS1 … G-LS7 cu fixture-uri negative; T12 cu AAR-ul inclus; testul de fum pe varianta release în jobul emulator; harness-urile Fazelor 7 și 8 neschimbate pe JDK 21; RO6 (înregistrare de sesiune supradimensionată), mutantul MC-25.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. `SessionCipher` și `SessionBuilder` primesc adresa locală (constanta `ghost-local`) și adresa contactului (`hex(contact_id)`); niciuna nu are forma unui ServiceId, deci libsignal nu serializează câmpul `addresses`; `decrypt` nu primește timp. Lista închisă include `SignalProtocolAddress`, `KEMPublicKey`, `DisplayableFingerprint`, excepțiile de fingerprint și enumerările din `IdentityKeyStore`.
> 2. `:messaging` nu importă nimic din `org.signal`: `:crypto-bridge` expune tipuri de rezultat GHOST pentru decriptare, criptare, procesarea bundle-ului și parsarea L1; înregistrările-martor stau în `crypto-bridge/src/test`.
> 3. `markKyberPreKeyUsed` verifică întâi tuplul și aruncă excepția de refolosire; apelul marchează și reînnoirea sesiunii (ADR-31). Tabelele de prekey primesc gărzi REPLACE.
> 4. Hash-urile `libsignal_jni.so` stau în fișierul separat `libsignal-natives.sha256`, modificat doar de PR-ul de actualizare; poarta refuză secțiuni `.debug_*` și biblioteci peste 16 MiB per ABI. Primul pin (de la 0.86.5, nefolosit) e scutit de regula directorului anterior.
> 5. Jurnalizarea de producție e în `session_management.rs`; `session_cipher_legacy.rs` este un instantaneu folosit doar în teste. Concluzia (loggerul tăcut e obligatoriu) rămâne.

> # ADR-29 — Licența clientului sub consecința AGPL
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16; **decizia explicită a proprietarului (Q1, exclusă de la regula valorilor implicite) condiționează prima distribuire a unui APK și orice artefact APK din CI** (§21.13) |
> | Sursă | Design Faza 9 (§2.9, Q1), R-libsignal §8 |
> | Modifică | ADR-07 („MIT sau GPL pentru client”) |
>
> ## Context
> libsignal și `spqr` sunt AGPL-3.0-only. Un program care leagă o bibliotecă din familia GPL, static sau dinamic, formează o operă combinată care se distribuie în întregime sub acea licență (GNU FAQ). Nu există o alternativă conformă cu specificația fără AGPL: `libsignal-protocol-java` (GPLv3) e arhivat și nu are PQXDH sau SPQR. Concluzia nu e consultanță juridică.
>
> ## Decizie propusă
> 1. Clientul Android se distribuie sub AGPL-3.0-only.
> 2. `client-core` păstrează `MIT OR Apache-2.0` pentru propriile fișiere (compatibile cu AGPL).
> 3. Relay-ul și issuer-ul rămân neschimbate (nu leagă libsignal).
> 4. Artefactele de release includ sursa corespondentă a întregului APK, inclusiv sursa libsignal la tag-ul fixat, oglindită (arhivă cu sha256, nu doar un link GitHub).
> 5. Niciun APK nu se distribuie înainte de decizie (punctul 13 al listei de închidere a Fazei 9). Se recomandă confirmarea cu un jurist.
> 6. **(după revizie, §21.13)** Q1 nu intră sub regula „valoarea implicită se aplică dacă proprietarul nu obiectează”: cere o decizie explicită. Depozitul este public, iar CI încărca până acum APK-ul ca artefact la fiecare push; din S0, înainte ca libsignal să intre în build, niciun job nu mai încarcă APK-uri cât timp Q1 e deschisă. Artefactele CI, imaginile de emulator și încărcările pe staging contează ca distribuire.
> 7. **(după revizie)** Înaintea primei distribuiri: fișierele `LICENSE` și `NOTICE` în depozit, notificările legale din aplicație (ecran în Faza 13), arhiva sursei libsignal la tag-ul fixat, oglindită cu sha256, și oferta de sursă corespondentă.
>
> ## Consecințe
> (+) Conformitate clară; compatibil cu F-Droid; coerent cu ADR-07 (open source). (−) Nimeni nu poate distribui clientul sub termeni permisivi sau proprietari; opțiunea „client MIT” supraviețuiește doar ca „fișiere MIT într-o aplicație AGPL”.
>
> ## Alternative
> Codul GHOST sub GPL-3.0-or-later, cu APK-ul transmis sub AGPLv3; codul GHOST sub MIT, cu APK-ul transmis sub AGPLv3. Ambele sunt posibile; propunerea (a) le evită doar pentru simplitate.

> # ADR-30 — Adresare și autorizare DM oarbe pentru relee: card de contact, namespace-uri statice derivate din secrete, `RegisterKey`, chei de depunere și de citire, bundle-uri sigilate
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9) |
> | Sursă | Design Faza 9 (§3–§5, §12), R-privacy F1, F2, F8, F11, F12, F15 |
> | Modifică | Anexa B a planului (prekeys citibile public după `ghost1`; scriere în inbox cu capabilitatea fiecărui expeditor; citirea inbox-ului cu token derivat din identitate); designul Fazei 8 §10.7 (D11: `RegisterReadKey` generalizat, verificatorul legat de namespace și săptămână) și ADR-25 punctul 9 (implementat); ADR-14 (lanțul de atestare nu se publică în bundle); designul Fazei 8 (cardul ca Invitație v3 amânat în Faza 13; ADR-05 rămâne deschis); `relay.proto`; `allowed-observables.json` (op `register`, `key_kind`, nota `capability_scope`); THREAT_MODEL §6 |
>
> ## Context
> Citită literal, Anexa B lasă releul să calculeze namespace-ul de prekeys din `ghost1` și să citească bundle-ul cu același secret public, deci leagă identitatea de namespace pentru fiecare utilizator, fără ajutorul vreunui contact. Capabilitățile de scriere cumpărate de fiecare expeditor fac din `capability_scope` un câmp de expeditor: releul împarte inbox-ul pe expeditori, numără corespondenții săptămânal, vede „expeditor nou” ca răscumpărare urmată de stocare, iar consumul de token-uri crește cu numărul de contacte.
>
> ## Decizie
> 1. **Card de contact v1** (163 de octeți: versiune, index, cheia Ed25519, `card_secret`, cheia X25519 de intro, semnătură), schimbat prin QR în persoană sau prin link; identic pentru toate contactele; fără adrese de relee, fără expirare, fără nonce. Contactul se stabilește doar prin card, niciodată doar din `ghost1`.
> 2. **Derivări:** secretele DM derivă din ramura MESSAGING a seed-ului (identitatea libsignal, `card_secret`, cheia de intro, secretul de citire al inbox-ului per slot de releu, cheia de program). Din `card_secret` derivă inbox-ul `X` și namespace-ul bundle-ului `P` (**statice** per index de card), secretul de depunere și secretul de citire al bundle-ului (per slot de releu, fără săptămână; §21.2), cheile de sigilare ale bundle-ului și ale modului intro (niciodată prezentate releelor). Nicio derivare nu are ca intrare-cheie `ghost1` sau o cheie publică (T26).
> 3. Mulțimea de relee a unui namespace este o permutare publică a sloturilor ES ale săptămânii, cheiată cu namespace-ul și independentă de săptămână (se schimbă doar când se schimbă tabela de sloturi; §21.1), peste cel puțin doi operatori; la schimbarea sloturilor, cititorul păstrează reuniunea cu mulțimile vechi 6 săptămâni.
> 4. **RPC nou `RegisterKey`** (namespace, perioadă, tip ∈ {READ, DEPOSIT}, verificator, capabilitate de scriere, `request_id`). Verificatorul este `SHA-256(etichetă ‖ slot ‖ namespace ‖ secret)`; săptămâna stă doar în perioada înregistrării (§21.2). Perioada trebuie să fie săptămâna capabilității sau următoarea, judecată după capabilitate, nu după ceasul releului. Înregistrările se **acumulează** și nu se înlocuiesc niciodată; o capabilitate înregistrează cel mult un verificator per (namespace, săptămână, tip). Înregistrările stau în `keys.redb`, valabile până la `start(săptămână + 2) + 1 h`; cota depunerilor se ține într-un registru propriu per înregistrare.
> 5. **Credențial purtător v3** de 67 de octeți (versiune, tip, slotul releului, namespace, secret), determinist și static: toți cei care prezintă același secret la același releu trimit aceiași octeți, în orice săptămână; un releu refuză credențialul care numește alt slot, deci nu îl poate folosi la alte relee (§21.2). Citirea permite list, get și check; depunerea doar store și check.
> 6. **Destinatarul plătește:** un token per (releu, namespace propriu, săptămână), pe calea de reînnoire; expeditorii nu cheltuie nimic pe namespace-uri străine (`CapabilitySource.LOCAL`), fără alternativă cu capabilități per expeditor (T27). Expeditorul nu alege nicio săptămână și nu are credențial de rezervă, deci nici ceasul lui, nici refuzul unui releu nu îl deosebesc de ceilalți expeditori; un credențial refuzat se reîncearcă cel mult o dată la începutul fiecărei sesiuni; un destinatar poate lipsi două-trei săptămâni fără ca vreo depunere să eșueze (§21.2).
> 7. **Bundle sigilat de 4 KiB** în `P`: prekey EC semnat, prekey Kyber de ultimă instanță, legătura Ed25519; valabil în săptămâna lui și în următoarea; publicat săptămânal la un decalaj PRF fix; cheile private păstrate 91 de zile după înlocuire; fără prekeys de unică folosință; preluat doar la stabilirea contactului, la resetare sau la reconectare, în cel mult trei încercări de 15 minute (T31); bundle-ul poartă ora emiterii, iar cel valid mai nou câștigă (§21.7). HELLO cu prekeys de unică folosință rămâne alternativa respinsă, reevaluată în Faza 13.
> 8. Atestarea ADR-14 se amână; nu apare niciodată în bundle; ulterior, eventual doar în sesiunea E2E și opțional.
> 9. Invitația v2 rămâne neschimbată, fără card (T16); cardul în invitație vine în Faza 13. Rotația cardului („tăierea”) vine în Faza 13, odată cu backup-ul contactelor.
> 10. Modelul T2 al Fazei 8 exportă `keys.redb` și include namespace-urile DM ale fiecărui client (vezi ADR-34).
>
> ## Consecințe
> (+) Releele nu pot lega un namespace de o identitate fără card sau seed, nu separă expeditorii și nu numără corespondenții; consumul de token-uri nu depinde de activitatea DM (E16 nu crește); un deținător de card nu poate bloca ceilalți expeditori înlocuind verificatorul. (−) Contactul cere cardul; un deținător de card poate trimite spam, poate epuiza cota și, cu propriile token-uri, poate vedea volumul inbox-ului (L7-D8, L7-D16); preluarea bundle-ului leagă `P` de `X` la stabilire (L7-D6); primul mesaj nu are prekey de unică folosință (L7-D11); un disc de releu confiscat leagă săptămânile unui inbox static (L7-D13); fiecare identitate activă plătește inbox-ul și bundle-ul.
>
> ## Alternative respinse
> Anexa B literală; namespace-uri derivate din `ghost1` sau din chei publice; rotația săptămânală a inbox-ului (nu rupe continuitatea sub AD-1, costă perechi de citire și token-uri, pierde mesaje după trei săptămâni offline); câte o căsuță per pereche de contacte; verificatorul atașat la `RedeemToken` (leagă depunerile de o singură săptămână de capabilitate și nu înregistrează chei de citire); înlocuirea verificatorului la înregistrare (un deținător de card ar bloca inbox-ul); sloturi de relee alese de client și purtate în card; prekeys de unică folosință prin relee; cardul în Invitația v3 în Faza 9.
>
> ## Teste
> T26, T27, T31; `register.txt` (relay Rust și modelul Kotlin); `dm_relay_set.txt`; JD1, JD3, JD7, JD8, JD9; NI-DM3, NI-DM6; S-DM3; suitele OS și RK; mutanții PM-1, PM-1b, PM-3, PM-7, PM-8, PM-11, PM-20 … PM-24, PM-26 … PM-28, PM-31, MC-22, MC-23.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. Setul de relee nu depinde de săptămână (§21.1). După o schimbare a tabelei de sloturi, proprietarul citește și releele setului vechi încă 6 săptămâni, cu cel mult un token în plus per releu per săptămână.
> 2. Credențialele de depunere, de citire a bundle-ului și de citire a inbox-ului sunt statice per (card, slot de releu, tip) și legate de slot (§21.2). Dispar partiționarea expeditorilor după ceas și după refuzuri și folosirea de către un releu a unui credențial văzut la alte relee; acoperirea offline este până la `start(c + 3) + 1 h`, unde c este săptămâna celei mai noi capabilități.
> 3. Stabilirea contactului (§21.7): tombstone-urile bundle-urilor deja consumate se uită la fiecare stabilire (`Inbox.forgetConsumed`, doar pentru namespace-urile PREKEYS); bundle-ul valid cel mai nou se alege după (săptămână, oră de emitere); sesiunea și trimiterile în așteptare pornesc dintr-un pas temporizat (`EST-READY`), nu din consumul blob-ului; cel mult trei încercări, apoi contactul e „inaccesibil”.
> 4. Un dispozitiv restaurat nu are token-uri, deci nu poate înregistra chei și nu poate publica un bundle nou până nu primește unele. Contactele care resetează între timp folosesc bundle-ul dispozitivului pierdut, iar mesajele lor eșuează; refacerea pornește din partea celui restaurat, prin reconectare, care nu cere token (§21.7).
> 5. Releele întorc `uploaded_at` rotunjit la începutul săptămânii pentru citirile cu credențial v3, ca un deținător de card să nu afle din bundle minutul primei sesiuni săptămânale a proprietarului (§21.9).

> # ADR-31 — Plicul DM: sealed sender fără server în două moduri, padding în AEAD cu prag de 4 KiB, fără trafic reflex, implementare în Kotlin
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9); **excepție CP-09** (construcție a proiectului din primitive standard), cu revizie externă țintită recomandată înaintea primului APK distribuit |
> | Sursă | Design Faza 9 (§2.8, §6, §7), R-envelope, R-privacy F3, F4, F9 |
> | Modifică | Idiomul Fazei 7 (padding, apoi libsignal; F7:1395-1398); ADR-19 și ADR-20 punctul 8 (codec-ul L0, padding-ul și sigilarea E2E sunt în Kotlin, în `:crypto-bridge`; `client-core` refuză în continuare blob-urile care nu au exact o treaptă); ADR-17 (suprafața BouncyCastle: ChaCha20-Poly1305, X25519, HMAC, ca ADR-24 X15); ADR-08 (nicio confirmare în Faza 9); INVARIANTS T9, T13 |
>
> ## Context
> Mesajele libsignal au antete în clar: cheia de identitate a expeditorului, cheia ratchet, contoarele, ciphertext-ul Kyber. Sealed sender din libsignal cere certificate semnate de un server; formatul v2 pune destinatarii în clar. O cheie publică X25519 brută se poate deosebi de octeți aleatori, iar singurul crate Elligator 2 disponibil e o bifurcație alfa. Confirmările automate accelerează atacurile de dezvăluire statistică și oferă un oracol de prezență.
>
> ## Decizie
> 1. **Trei straturi:** L0 conținut canonic (minutul autorului, timer și versiune, `message_id`, TLV) → L1 ieșirea libsignal neschimbată → L2 sigiliul `salt(16) ‖ hint(16) ‖ ChaCha20-Poly1305`, de exact 4, 16 sau 64 KiB, cu namespace-ul și treapta în datele asociate.
> 2. **Modul pereche** (conversații confirmate): o cheie simetrică per (pereche, direcție, săptămână ISO), dintr-o rădăcină aleatoare generată de destinatar și trimisă în conținutul E2E doar în sesiuni confirmate, niciodată într-un mesaj PreKey (§21.3); ratchet săptămânal; destinatarul șterge cheia săptămânii w la `start(w + 1) + 45 zile`, iar expeditorul păstrează doar cheia curentă (T34).
> 3. **Modul intro** (primul contact, resetare, reconectare, sesiune neconfirmată): strat exterior cu cheia derivată din card, strat interior X25519 către cheia de intro derivată din seed; cardul expeditorului și legătura Ed25519 a identității libsignal, legată de namespace-ul destinatarului, de minutul sigilării și de hash-ul L1, stau înăuntru și se verifică, împreună cu prospețimea lor, înaintea oricărei schimbări de stare (§21.4).
> 4. Destinatarul alege cheia după hint și încearcă cel mult o decriptare AEAD per blob (fără oracol de partiționare); cel mult 9 chei per contact per generație de rădăcină; parsarea e canonică; padding-ul trebuie să fie zero.
> 5. Treapta depinde doar de lungimea corpului plus rezerve fixe (referința de citare și 160 de octeți pentru extensii; §21.11), cu O_MAX măsurat; DM-urile nu folosesc niciodată 1 KiB.
> 6. **Fără trafic reflex:** nicio confirmare de livrare sau de citire, niciun indicator de tastare, niciun `DecryptionErrorMessage`, nicio resetare automată; blob-urile invalide se consumă în tăcere (T28). Singura retrimitere automată este retrimiterea acelorași octeți a unei operații cu rezultat nesigur, de cel mult două ori, în fereastra Fazei 7. Confirmările de citire pot veni doar în Faza 13, opțional, atașate unui mesaj al utilizatorului și doar în modul standard.
> 7. Implementarea e în Kotlin pe BouncyCastle, în `:crypto-bridge`. Motivele reale: ieșirea libsignal e deja în Kotlin, în tranzacția SQLCipher; precedentul `DropSeal` (ADR-24); testele JVM fără build nativ pentru gazdă. Nu lipsește un AEAD în Rust: `ring` 0.17.14 (ChaCha20-Poly1305) e deja în graful `ghost-client-net`. Vectorii sunt verificați și de o implementare independentă pe furnizorii JDK.
> 8. Deduplicare în patru straturi (operația outbox; (namespace, hash); contoarele libsignal și tuplurile Kyber; etichete HMAC cu cheie locală) plus două legături structurale (namespace–treaptă–săptămână, ștergerea cheilor); fereastra de prospețime 45 de zile; ordinea afișării e o funcție de conținut.
>
> ## Consecințe
> (+) Releul nu vede expeditorul, tipul mesajului, primul contact, resetarea sau schimbarea cheii; istoricul „cine cu cine” al conversațiilor confirmate nu mai poate fi atribuit după fereastră, nici cu seed-urile (excepție declarată: o cheie de mesaj sărit păstrată de libsignal pe dispozitivul confiscat; §21.3). (−) Lățime de bandă de 4× pentru textele scurte; un deținător de card care colaborează cu releul recunoaște plicurile intro (L7-D3); stratul interior intro nu e post-cuantic; costul hint-urilor crește cu numărul de contacte; fără bife de livrare.
>
> ## Alternative respinse
> Sealed sender libsignal cu certificate auto-emise (PKI fictivă, dependență de semantica certificatelor, sigilare pe cheia de identitate); formatul v2 cu mai mulți destinatari; cheie efemeră per mesaj cu Elligator 2 către o cheie de inbox (crate alfa, componenta de ordin mic lipsă, o singură cheie deschide tot istoricul); cheie X25519 brută cu bitul de sus aleator (T9 neîndeplinit); stocarea ieșirii libsignal brute; padding înainte de libsignal; treaptă de 1 KiB pentru sesiunile confirmate; sigiliul în Rust.
>
> ## Teste
> Vectorii `dm_seal.txt` și `dm_content.txt` (cu implementarea JDK); T9, T13, T28, T29, T34; NI-DM1, NI-DM2; testul unei singure încercări AEAD; testul χ² pe octeți; suita RP; KC5b, KC12; mutanții PM-2, PM-4, PM-6, PM-12, PM-13, PM-18, PM-19, PM-25, PM-29, MC-3, MC-5, MC-7, MC-9, MC-16, MC-18, MC-20, MC-21, MC-24 și ME-1 … ME-6, ME-22.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. **P-7** (§21.3): rădăcinile circulă doar în `SignalMessage`, deci primul răspuns al unei conversații e încă un plic intro. Excepție declarată: dacă un mesaj care a purtat o rădăcină a fost pierdut sau reordonat, iar libsignal i-a păstrat cheia ca cheie sărită, cine confiscă dispozitivul destinatarului rădăcinii poate deschide plicurile pereche ale acelei generații. Conversațiile fără răspuns rămân în modul intro.
> 2. **Reînnoirea sesiunii** (un mesaj PreKey care creează o stare nouă, semnalat de apelul `markKyberPreKeyUsed`) șterge cheile de ieșire către acel contact și pregătește o rădăcină nouă; generațiile nu se repetă cât timp contactul există; după o restaurare sau o re-adăugare, contactul își șterge pragul la reînnoire. SWEEP derivă cheile săptămânii curente înainte de a le șterge pe cele vechi.
> 3. **Legătura intro v2** (§21.4) acoperă cheia libsignal, indexul cardului, namespace-ul destinatarului, minutul sigilării și SHA-256(L1); nu se mai poate relua din alt plic, iar un plic mai vechi de 45 de zile e refuzat înaintea oricărei schimbări de stare. O cerere nu își poate schimba cheia libsignal (nu există tranziția `request → changed`).
> 4. **Treapta** se calculează din lungimea corpului plus rezerve fixe, deci o rădăcină sau o revocare atașată nu schimbă mărimea (§21.11).
> 5. **Post-cuantic** (§21.11): un adversar cuantic viitor care are cardul meu și arhiva releelor află din plicurile intro cardurile complete (identitate și `card_secret`) ale celor care mi-au scris; până la fixarea cheii libsignal, o legătură falsificată s-ar fixa în tăcere. Atenuare P2: un strat intro interior bazat pe KEM.
> 6. Scurgerea declarată LD include gruparea cererilor pe circuit, momentele exacte, hash-ul retrimiterilor identice și rezultatele cererilor (§21.11).

> # ADR-32 — Mesaje efemere în DM: trepte TTL în secunde, acceptare exactă, termene, numărătoare, ștergere (precizează ADR-27)
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9); **ADR-27 punctul 11 rămâne neschimbat** |
> | Sursă | Design Faza 9 (§10), R-envelope §8, R-privacy §3.9 |
> | Modifică | `allowed-observables.json` (`ttl_bucket_seconds` în locul `ttl_bucket_days`); relay-ul (acceptă doar treptele exacte); `client-core` (refuză în loc să rotunjească; limită superioară a expirării la confirmare); `relay_semantics.txt`; INVARIANTS T20 (o alarmă inexactă permisă) și formularea T25; plan §6.2 rândul 9 („TTL pe relee ≤ timer” se citește ca ADR-27 punctul 11, erată); regulile ferestrei Fazei 7 pentru TTL sub 2σ (re-derivate) |
>
> ## Context
> Nicio componentă nu poate exprima 1 oră (câmpul observat e în zile). Releul acceptă orice TTL. Fereastra de stocare de 7 zile a Fazei 7 permite copii după ce textul expeditorului a expirat. T25 spune că timer-ul nu apare în nimic din ce observă releul, dar treapta derivă din el. ADR-27 numește un câmp `ttl_bucket` care nu există.
>
> ## Decizie
> 1. Treptele sunt {3600, 86400, 604800, 2592000, 7776000} de secunde; releul acceptă exact aceste valori (`rejected_ttl` altfel); câmpul observat devine `ttl_bucket_seconds`.
> 2. **Tabelul DM, exact ca ADR-27 punctul 11:** 5 minute și 1 oră → 1 oră; 1 zi → 1 zi; 7 zile → 7 zile; 30 de zile → 30 de zile; dezactivat → 30 de zile. Toate blob-urile unei conversații folosesc treapta conversației; TIMER_SET folosește treapta mai mare dintre cea veche și cea nouă. Comprimarea la 7 zile rămâne doar întrebarea Q15.
> 3. Fiecare operație DM are termenul `autor + min(treaptă, 7 zile)`; după termen nu se mai stochează nicio copie; mesajele de 5 minute au termenul celor de o oră, iar expirarea mesajului nu anulează operația (§21.10). Plafonul de 7 zile face ca fereastra de prospețime de 45 de zile să fie corectă.
> 4. Numărătoarea pornește la expeditor la commit-ul trimiterii, la destinatar la prima afișare; un mesaj necitit se șterge la `min(expirarea pe releu, consum + treaptă + 1 h)`, cu expirarea venită prin `InboundBlob.relayExpiryHour`; termenele pot doar să scadă; ceasul de expirare nu merge înapoi.
> 5. Timer-ul și versiunea lui stau în L0; versiunea mai mare câștigă; la versiuni egale câștigă timer-ul mai scurt.
> 6. Se șterg: rândul, reacțiile, maparea operațiilor și blob-ul reținut, trimiterile în așteptare, mesajele reținute peste limită, cererile expirate, etichetele de deduplicare și cheile de pereche expirate, prekey-urile vechi. Citările sunt doar referințe; nu există FTS; notificarea are text constant; urmează `wal_checkpoint(TRUNCATE)` cu `busy = 0` verificat, plus un checkpoint la fiecare deschidere a bazei.
> 7. Ștergerile rulează la deschiderea bazei, la fiecare sesiune în prim-plan, în coada de consum a joburilor de fundal și a rulărilor liniștite, printr-un timer în proces și printr-o alarmă inexactă (receiver neexportat, fără extras, fără permisiune nouă); fiecare interogare filtrează rândurile expirate.
> 8. Pentru treptele de 1 oră și 1 zi, regulile ferestrei Fazei 7 au fost re-derivate: siguranța rămâne; un rezultat ambiguu se încheie `indeterminate`; limita inferioară a confirmării e vidă și e declarată.
>
> ## Consecințe
> (+) T25 e verificabil pe fiecare cale; releele oneste nu păstrează o copie după ora-termen stocată de Faza 7 + treaptă + 1 h; ADR-27 rămâne neschimbat. (−) Releele văd patru clase TTL, care împart inbox-ul pe clase de conversație și leagă cele două inbox-uri ale unei conversații cu timer diferit de cel implicit în ~2–3 schimburi (L7-D4, Q39); un mesaj efemer nelivrat la timp eșuează; ștergerea fizică poate întârzia sub Doze (L7-D14).
>
> ## Alternative respinse
> Câmp în ore sau zile fracționare; rotunjire pe client; 7 zile pentru „30 de zile” și „dezactivat” (abatere de la ADR-27, lăsată la decizia proprietarului); operații fără termen (copii târzii); termenul necitit calculat din conținut (un ceas al expeditorului înainte îl prelungește); numărătoarea destinatarului pornită la primire; FTS; notificări cu text; nicio alarmă.
>
> ## Teste
> T25 (logic și fizic), T30, T33; JD5; NI-DM4; vectorii relay și client; fixture-urile `capture-check`; scenariile S-F ale Fazei 7 cu 1 h și 1 zi; SCN-F; mutanții PM-5, PM-9, PM-10 și ME-7 … ME-21.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. Mesajele de 5 minute au termenul de stocare de o oră, ca cele de o oră, iar nicio operație DM nu se anulează la expirarea mesajului: altfel, în modul high-privacy, aproximativ jumătate din mesajele de 5 minute nu ar fi fost stocate niciodată, iar releele ar fi deosebit cele două timere (§21.10, Q41).
> 2. Prospețimea și durata etichetelor de deduplicare depind de treaptă: 6 zile și 4 ore pentru 1 h, 8 zile și 2 ore pentru 1 zi, 20 de zile și 2 ore pentru 7 zile, 45 de zile pentru 30 de zile și dezactivat. Declarat: cine confiscă dispozitivul și cunoaște un `message_id` poate confirma din etichetă primirea mesajului și săptămâna ei.
> 3. Mesajele reținute la schimbarea cheii păstrează expirarea pe releu și minutul consumului, deci termenul lor de necitit nu se prelungește; afișarea ignoră mesajele deja expirate; triggerul „doar descreștere” numește explicit coloanele.
> 4. Alarma primește un moment absolut (`SystemClock.elapsedRealtime()` plus întârzierea). Nu există receiver de boot: după o repornire fără rețea, ștergerea fizică așteaptă jobul periodic sau deschiderea aplicației (declarat, L7-D14).
> 5. Faza 9 nu postează notificări; regulile ADR-27 pentru notificări se dovedesc în Faza 9 doar prin contractul portului, iar verificările pe emulator și pe dispozitive trec în Faza 13.

> # ADR-33 — Sesiuni DM: identitatea derivată și legătura ei, schimbarea cheii, safety numbers, revocarea v2, restaurarea și refacerea contactelor, cererile, modelul local
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9) |
> | Sursă | Design Faza 9 (§3.4, §7, §8, §12.3–§12.4, §13.6, §13.8), R-spec K1, K3, K15–K17 |
> | Modifică | THREAT_MODEL S12 și LIMITE L1 (citarea FR-4.6; revocarea prin inbox-urile contactelor, nu într-un namespace de identitate); `RevocationCertificate` (v2, timp la minut, doar prin E2E); `Schema.kt` (tabelele DM v1 înlocuite); ADR-14 (după restaurare safety number-ul rămâne același) |
>
> ## Decizie
> 1. Identitatea libsignal derivă din ramura MESSAGING (`HKDF(m, "ghost/v1/dm/identity")`), aceeași după restaurare; cheia Ed25519 semnează cheia libsignal în fiecare bundle și în fiecare plic intro; id de înregistrare aleator; dispozitivul 1.
> 2. Store-urile stau în SQLCipher, legate de tranzacția curentă; `isTrustedIdentity` întoarce fals în ambele direcții la orice nepotrivire; GHOST fixează identitatea înaintea oricărui apel libsignal, iar `saveIdentity` nu înlocuiește niciodată o cheie fixată.
> 3. **Schimbarea cheii** există doar când o semnătură de legătură validă sub cheia Ed25519 fixată numește o altă cheie libsignal; orice altceva (inclusiv o excepție `UntrustedIdentityException` fără legătură) e ignorat, fără schimbare de stare. În starea `changed`, trimiterea e refuzată înaintea oricărui apel libsignal, iar mesajele sub cheia nouă sunt reținute necriptate cel mult până la expirarea pe releu (maximum 30 de zile și o oră); deblocarea cere confirmarea explicită a utilizatorului sau verificarea safety number-ului; rădăcinile de sigilare se înlocuiesc.
> 4. Safety number: `NumericFingerprintGenerator(5200)`, cu identificatorul stabil = cheia Ed25519 de 32 de octeți; QR din `ScannableFingerprint`; scanarea cardului în persoană valorează verificare; nicio operație de rețea.
> 5. Revocarea v2 (102 octeți, timp la minut) se trimite, la cererea utilizatorului, ca mesaj de control fiecărui contact, eșalonat pe 24 de ore; la primire contactul devine `revoked` (stare terminală).
> 6. Restaurarea re-derivează identitățile, cardul, namespace-urile și secretele; pierde contactele, sesiunile, cheile de pereche și mesajele; conținutul scris înainte de restaurare e refuzat. Plicurile pereche ale contactelor vechi nu se mai deschid (numărate). Plicurile intro poartă cardul expeditorului și refac contactul ca cerere, marcată „necesită reconectare” când decriptarea eșuează; reconectarea o pornește utilizatorul, eșalonat pe 48 de ore.
> 7. Cererile de la necunoscuți: cel mult 64, 7 zile; blocarea e locală și șterge cardul, sesiunea și cheile; nicio acțiune nu produce trafic reflex.
> 8. Modelul local: tabele WITHOUT ROWID cu chei aleatoare; coloane de timp doar la minut, oră sau zi, cu CHECK `typeof`; fără coloane sau contoare de activitate; conținutul criptat cu o cheie păstrată în Keystore, cu aceeași politică de autentificare ca cheia bazei; triggere de stare și de „doar descreștere”; gărzi REPLACE.
>
> ## Consecințe
> (+) Schimbarea cheii blochează în ambele sensuri fără nimic vizibil la relee și nu poate fi falsificată fără cheia de identitate a contactului, nici prin reluarea unei legături mai vechi (§21.4); safety number-ul supraviețuiește restaurării; un seed furat folosit pe un client modificat apare ca schimbare de cheie. (−) Un hoț de mnemonic care folosește clientul oficial nu produce avertisment (L7-D18); restaurarea pierde mesajele contactelor stabilite până la reconectare (L7-D12); backup-ul criptat al contactelor vine în P1.
>
> ## Alternative respinse
> Identitate libsignal aleatoare la fiecare instalare (avertisment blocant la fiecare restaurare, contrar FR-1.2); schimbare de cheie din orice `UntrustedIdentityException` (falsificabilă de oricine are două carduri); TOFU cu înlocuire; avertisment fără blocare; revocare publicată într-un namespace ascultat de contacte (graful social la relee); resetare automată a sesiunii.
>
> ## Teste
> Suitele KC, CB, RE; SCN-C, SCN-D (cu varianta falsificată), SCN-I, SCN-K; KC5b, KC12; mutanții PM-15 … PM-17, MC-4, MC-6, MC-8, MC-10, MC-11, MC-24.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. O cerere care primește o altă cheie libsignal se ignoră, fără schimbare de stare; tranziția `request → changed` nu există. Toate precondițiile de stare de încredere sunt verificări în Kotlin, nu erori de trigger.
> 2. Adrese libsignal: `hex(contact_id)` pentru contact și constanta locală `ghost-local`.
> 3. Revocarea și reconectarea sunt elemente de ieșire durabile, care pot aștepta bundle-ul contactului (§21.8); una eșuată se reprogramează de cel mult trei ori, apoi se numără în stare.
> 4. Activarea DM se reia la pornirea actorului și la deschiderea bazei dacă identitatea există și `dm_self` lipsește; restaurarea se recunoaște din starea `restore_scan_root` a Fazei 8 (§21.12).
> 5. Blocarea și ștergerea înregistrează namespace-urile contactului ca orfane; SWEEP le elimină, împreună cu credențialele, când nu mai au operații (≤ 7 zile).
> 6. Un dispozitiv restaurat primește plicurile pereche ale contactelor abia după reconectare; resetarea din partea unui contact reușește doar după ce dispozitivul restaurat are un token și publică un bundle nou (§21.7).

> # ADR-34 — Extensiile `:sync` și `:entitlement`, schema v4, coada de consum, joburi CI și modificările testului T2 pentru DM
>
> | Câmp | Valoare |
> |---|---|
> | Status | **Propus** 2026-09-16 (aplicat în designul Fazei 9) |
> | Sursă | Design Faza 9 (§4.8–§4.9, §10.4, §10.7, §13.3–§13.7, §16.2), R-code F1–F8, R-envelope F3–F5 |
> | Modifică | ADR-20 punctele 1 și 8 (o alarmă inexactă în stratul de mesagerie; încadrarea E2E nu mai stă în Rust, vezi ADR-31); ADR-23 punctul 9 (slotul de participant rămâne unul; se adaugă coada de consum, care nu e participant); API-ul `:sync` (Faza 7 §9); INVARIANTS T20 (setul coloanelor de timp); `Schema.kt` (migrarea 4); designul Fazei 8 §19.24 punctul 6 și ADR-25 (exportul T2 include `keys.redb`); CI (joburi noi, o acțiune terță fixată prin SHA) |
>
> ## Decizie
> 1. `TtlBucket.HOUR_1`; regulile ferestrei Fazei 7 re-derivate pentru 1 oră și 1 zi; scenariile S-F rulează și cu aceste trepte și cu ferestre offline de 30 de minute, 3 ore și 3 zile.
> 2. `InboundBlob.relayExpiryHour` (coloana `inbox_blob.relay_expiry_hour`, nenulă doar în starea `fetched`) și `InboundBlob.offers`; un blob oferit de trei ori se consumă neprocesat (fără buclă de crash).
> 3. `CapabilitySource {REDEEM, LOCAL}` pe namespace și pe nevoie; planificatorul entitlement nu răscumpără niciodată o nevoie LOCAL.
> 4. `Registrations`: operațiile `RegisterKey` rulează pe banda de lucru, cu lease, reîncercări și breakere, ca stocările; un rând în așteptare contează ca nevoie de scriere, deci un inbox nou sau restaurat se răscumpără la prima sesiune, iar reținerea Q29 îl acoperă (Q31). Un credențial de citire propriu refuzat readuce înregistrările în așteptare.
> 5. `ConsumerTail`: rulează pe firul jobului după benzile unei sesiuni de fundal și după reținerea de răscumpărare, și după apelul către issuer al unei rulări liniștite, în ambele cazuri după închiderea transportului, cu termenul jobului minus 20 s; actorul DM rămâne singurul care scrie.
> 6. Citirile preferă un credențial de citire utilizabil; `SendDelay.OFF` e refuzat pentru namespace-urile DM; `Gc.checkpoint` verifică `busy = 0`; executoarele mapează `SQLITE_FULL` la o excepție tipizată.
> 7. Migrarea 4: gardă și eliminarea tabelelor DM v1; reconstruirea `outbox_op`/`outbox_delivery` cu liste explicite de coloane, `rowid` păstrat, `legacy_alter_table` oprit, `foreign_key_check` gol; triggere și indecși identici înainte și după, iar tabelele egale ca structură, cu singura diferență CHECK-ul TTL (§21.13); coloanele noi; `relay_key_registration`; tabelele `dm_*` și `sig_*`.
> 8. CI: JDK 21; joburile noi `messaging-exit-gate.yml`, `dm-privacy-gate.yml` și `dm-emulator.yml` (emulator API 29 și 35 cu relee-model locale, acțiunea `reactivecircus/android-emulator-runner` fixată prin SHA).
> 9. Testul T2 al Fazei 8: exportul și verificarea completitudinii includ `keys.redb` și registrul de depuneri; clienții lumii își înregistrează namespace-urile DM proprii; valorile de referință se reînregistrează.
>
> ## Consecințe
> (+) Niciun client nu poate cheltui un token pe inbox-ul altcuiva; consumul DM și ștergerile rulează și în fundal fără să influențeze momentele issuer-ului sau durata sesiunilor de relay; T2 rămâne fidel clientului real. (−) API mai mare; o migrare care reconstruiește tabelele outbox; o alarmă în plus; joburi CI mai lungi; poarta T2 se schimbă.
>
> ## Alternative respinse
> Consumatorul pe firul unei benzi (blochează banda); mai mulți participanți (amestecă I/O de rețea cu munca locală); doar listener-ul (mesajele aduse în fundal așteaptă prim-planul); coada de consum cu transportul deschis (durata sesiunii ar depinde de volumul primit); renunțarea la treapta de 1 oră (abatere de la ADR-27); modificarea pe loc a CHECK-ului din v2; relee pe Tor public în jobul emulator.
>
> ## Teste
> `SchemaAndMigrationTest` (toate căile de migrare, testul setului de obiecte), `SchemaIntrospectionTest` (15 coloane de timp în sync), testele planificatorului pentru LOCAL și pentru înregistrări, `SessionParticipantTest` (coada de consum), T19 cu înregistrări, NI-DM1 (momentul închiderii sesiunii), `sync-exit-gate`, `entitlement-exit-gate` și `t2-exit-gate` verzi, `dm-emulator.yml` verde pe API 29 și 35; mutanții MC-1, MC-2, MC-12 … MC-15, MC-17, MC-25, PM-14, PM-25, PM-30.
>
> ## Corecturi după revizie (§21; au prioritate)
> 1. Migrarea 4 intră întreagă în S3 (toate tabelele, triggerele, versiunea 4 și seturile așteptate), ca fiecare felie să lase o schemă v4 consistentă; tabele noi: `dm_outbound_item`, `dm_bundle_candidate`, `dm_orphan_namespace`.
> 2. API-ul `:sync` primește `Inbox.forgetConsumed` (doar pentru namespace-urile PREKEYS).
> 3. Pașii temporizați (publicarea și re-sigilarea bundle-ului, controalele programate, `EST-READY`, `EST-END`, părțile săptămânale din KEEPER și REGROWS) rulează doar din timerul actorului, la deschiderea bazei și la începutul unei sesiuni de relay, niciodată dintr-un hint de primire sau dintr-o trimitere a utilizatorului (§21.9).
> 4. Paza de „otravă” numără doar morțile procesului: fără preluări cât biblioteca nativă sau cheile lipsesc, câte un blob în coada de consum, `Inbox.defer` după `SQLITE_FULL` (§21.12).
> 5. Varianta de build `gate` (hook-ul de schimbare a cheii și exportul digest-urilor) se construiește fără nicio încărcare, se semnează cu o cheie de unică folosință și se instalează doar pe dispozitivele porții; hook-ul stă în `crypto-bridge/src/gate`; G-DM5 verifică seturile de surse și `mapping.txt`, nu nume de clase ofuscate.
> 6. Testul de fum al variantei release nu folosește transport; lumea T2 enumeră toate fișierele `*.redb`, iar exportul `keys.redb` intră în S1; NDK-ul se fixează prin `android.ndkVersion`; CI nu mai încarcă APK-uri cât timp Q1 e deschisă; RUNBOOK O1 și releele de staging se actualizează.
> 7. Mutanți: 79 (32 de confidențialitate, 25 de corectitudine, 22 efemere și de plic).

---

## Appendix B: Text changes in other documents (Romanian; applied in S13)

### B.1 Erate (X-15, X-16, Q29; F-3)

- **THREAT_MODEL S12** (TM:151), **LIMITE L1 „Detectare”** (LIMITE:38), **plan §1.2** (plan:63): „FR-4.5” → „FR-4.6” pentru avertismentul blocant la schimbarea cheii. FR-4.5 rămâne cerința „istoricul DM și starea sesiunilor doar în stocare locală criptată”.
- **LIMITE L1 „Recuperare”** (LIMITE:39): „certificat de revocare publicat ca blob în namespace-ul identității; contactele îl preiau la sync” → „certificat de revocare v2 (timp la minut), trimis contactelor ca mesaj E2E în inbox-urile lor, eșalonat pe 24 de ore, la cererea utilizatorului (ADR-33); contactul devine revocat și blocat”.
- **Plan §6.2 rândul 9** (plan:310) și **FR-7.15** (plan:274): „TTL pe relee ≤ timer cu treaptă nouă de 1 h” → „TTL pe relee = cea mai mică treaptă ≥ timer (ADR-27 punctul 11): 5 min și 1 h → 1 h; 1 zi → 1 zi; 7 zile → 7 zile; 30 de zile și dezactivat → 30 de zile; fiecare mesaj are termen de stocare (ADR-32)”.
- **ADR-27, rândul „Modifică”**: câmpul observat se numește `ttl_bucket_days` (nu `ttl_bucket`) și devine `ttl_bucket_seconds` (ADR-32).

### B.2 INVARIANTS.md

Rânduri noi:

| ID | Invariant | Verificare | Executabil din | Unde |
|---|---|---|---|---|
| T26 | Adresarea DM e oarbă pentru relee: niciun namespace, verificator, credențial sau octet stocat nu se poate calcula din material public de identitate (ghost1, cheia Ed25519, cheia libsignal, safety number) fără card sau seed; tot ce stă pe relee e sigilat sub chei neprezentate niciodată unui releu; mulțimea de relee e o funcție publică de (namespace, săptămână); niciun antet libsignal în afara sigiliului | vectori de derivare; verificare statică a intrărilor-cheie; JD1, JD2, JD9; releul-model încearcă să deschidă fiecare blob cu fiecare secret primit; S-DM3; mutanții PM-3, PM-13, PM-20, PM-24 | Faza 9 | `android/crypto-bridge`, `android/messaging`, lumea DM |
| T27 | Toate depunerile într-un inbox la un releu, făcute cu credențialul de depunere, au același scop, în orice săptămână și oricare ar fi ceasul expeditorului (§21.2); niciun client onest nu răscumpără și nu înregistrează pentru un namespace care nu e al lui; răscumpărările și înregistrările unui client nu depind de activitatea lui DM; o înregistrare nu o înlocuiește pe alta | JD3, JD8; NI-DM3, NI-DM6; `register.txt`; mutanții PM-1, PM-1b, PM-21, PM-23, PM-26, PM-27, PM-28 | Faza 9 | relay, `android/sync`, `android/entitlement`, `android/messaging` |
| T28 | Niciun blob primit nu produce trafic: nicio trimitere, răscumpărare, înregistrare, schimbare a programului de citire sau a momentului de închidere a sesiunii | analiza grafului de apeluri; NI-DM1; JD6; mutanții PM-2, PM-6, PM-25 | Faza 9 | `android/messaging`, `android/sync` |
| T29 | Plicurile și bundle-urile DM au exact 4, 16 sau 64 KiB, cu treapta funcție doar de lungimea conținutului; lungimile și padding-ul zero în AEAD; octeți uniformi | test de proprietăți; χ² pe octeți; dimensiuni de referință; NI-DM2; mutanții PM-4, PM-12, ME-1 … ME-4 | Faza 9 | `android/crypto-bridge` |
| T30 | TTL după tabelul ADR-27 punctul 11; releul acceptă doar treptele exacte, în secunde; fiecare operație DM are termenul `autor + min(treaptă, 7 zile)`, după care nu se mai stochează nimic; o copie pe un releu onest dispare până la ora-termen stocată de Faza 7 + treaptă + 1 h | vectori relay și client; fixture-uri capture-check; JD5; mutanții PM-5, PM-9, ME-14, ME-15 | Faza 9 | relay, `client-core/net`, `android/sync`, `android/messaging` |
| T31 | Un client citește doar namespace-urile proprii și canalele, plus o preluare de bundle (cel mult trei încercări de 15 minute) la stabilirea contactului, la resetare sau la reconectare; scrierile proprii (răscumpărări, înregistrări, publicări) au loc la momente independente de activitate; verificarea, confirmarea, blocarea și cererile nu produc I/O | JD7; verificare statică; NI-DM3, NI-DM5; mutanții PM-7, PM-8, PM-11 | Faza 9 | `android/messaging` |
| T32 | Lumea DM: joinurile JD1–JD9 nu găsesc nimic; gemenii NI-DM1–NI-DM6 dau vederi identice; S-DM1 și S-DM3 la α = 0,001; S-DM2 și S-DM4 măsurate și raportate | `messaging-exit-gate`, `dm-privacy-gate`, `dm-report-check.sh` | Faza 9 | `android/messaging/src/test/.../dmworld/` |
| T33 | Minimalitate criminalistică locală: doar coloane de timp la minut, oră sau zi cu CHECK; fără timp de activitate, contoare pe conversație sau istoric de respingeri; conținut criptat cu cheia de conținut; notificări cu text constant; timpii din înregistrările libsignal rotunjiți | introspecția schemei; testul portului de notificări; mutanții PM-10, ME-12, ME-13, ME-18 | Faza 9 (JVM); dispozitiv | `android/messaging`, `android/storage` |
| T34 | Plicurile pereche ale unei săptămâni w nu mai pot fi atribuite după `start(w + 1) + 45 de zile`: nicio cheie păstrată și nimic derivabil din seed-uri nu le deschide, cu excepția declarată a unei chei de mesaj sărit păstrate de libsignal pentru mesajul care a purtat rădăcina (§21.3); plicurile intro și conversațiile fără răspuns rămân atribuibile cu seed-ul destinatarului (declarat) | scenariul de confiscare, cu decriptare libsignal folosind prekey-urile și sesiunile păstrate; teste de ștergere a cheilor; mutanții PM-19, PM-29 | Faza 9 | `android/crypto-bridge`, `android/messaging` |

Rânduri modificate:
- **T1** — `allowed-observables.json` v2: `op` include `register`; câmpul `key_kind` doar la `register`; `ttl_bucket_seconds` înlocuiește `ttl_bucket_days`; `capability_scope` acoperă și cheile de citire și de depunere.
- **T3** — canarii includ cheia privată de identitate libsignal, înregistrările de sesiune și prekey, secretele de card, cheile de pereche, secretele de citire și de depunere, namespace-urile DM, cifrele safety number, textul mesajelor; se caută și în liniile de jurnal libsignal în timpul unei decriptări cu identitate neîncrezută.
- **T9** — „Faza 9 (DM: treapta din lungimea conținutului, prag 4 KiB, padding în AEAD, octeți uniformi; T29)”.
- **T13** — executabil din **Faza 9**, testele `android/messaging`, vectorii `dm_content.txt`.
- **T19** — retestat cu activitate DM (trimiteri, consum, ștergeri, pașii proprietarului, înregistrări, schimbări de cheie, cereri).
- **T20** — setul coloanelor de timp din sync are 15 coloane (plus `inbox_blob.relay_expiry_hour` și `relay_key_registration.{lease_hour, next_attempt_minute, valid_until_hour}`); stratul de mesagerie are o alarmă inexactă fără extras (ADR-32).
- **T21** — și credențialele v3 (citire, depunere): tipul, operația și namespace-ul verificate înainte de orice I/O.
- **T25** — „TTL-ul trimis releului urmează ADR-27 punctul 11 (5 min și 1 h → 1 h; 1 zi → 1 zi; 7 zile → 7 zile; 30 de zile și dezactivat → 30 de zile); releul observă doar treapta, nimic mai fin; executabil pentru DM din Faza 9”.

### B.3 THREAT_MODEL §6 (rânduri noi sau completate) și S12

| Eveniment | Relay | Issuer | Rețea locală | Contact | Test |
|---|---|---|---|---|---|
| DM trimis (depunere) | namespace-ul inbox al destinatarului (derivat din secretul cardului, nelegabil de ghost1); hash; treaptă 4/16/64 KiB independentă de tipul mesajului; treapta TTL (1 h, 1 zi, 7 zile sau 30 de zile); minutul; scopul static al cheii de depunere a inbox-ului la acel releu, **același pentru toți expeditorii** (§21.2); circuitul expeditorului | — | upload 3 × treaptă (imediat în modul standard, U[0, 10 min] în high-privacy) | — | T1, T9, T26, T27, T29, T30 |
| DM primit | listări la programul T19 cu scopul de citire static per releu, derivat din seed; câte un get per blob nou; prezența | — | download la listări | cu releul: momentul aducerii propriului blob | T19, T28 |
| Reînnoirea săptămânală proprie | răscumpărări pentru inbox și bundle la momentul PRF de reînnoire; apoi `register` (depunere, citire) cu `key_kind` | — | — | cunoaște namespace-urile | T1, T27, T31 |
| Publicare bundle | namespace-ul P derivat din card; bundle sigilat de 4 KiB, TTL 30 de zile; la un decalaj fix al săptămânii, independent de activitate | — | trafic Tor | vede rotațiile și săptămâna; cu un releu, minutul primei sesiuni după `t_pub` (L7-D10) | T26, T31 |
| Preluare bundle | o listare a lui P cu secretul de citire al acelui releu, comun tuturor deținătorilor cardului, doar la stabilirea contactului, la resetare sau la reconectare, în cel mult trei încercări | — | 4 KiB | — | T31 |
| Schimbare de cheie, verificare, blocare, cereri | **nimic** | — | — | — | T28, T31 |
| Expirare / schimbare timer | nimic la expirare; primul blob pe o treaptă nouă marchează schimbarea | — | — | vede schimbarea | T25, T30 |
| Restaurare | înregistrări și bundle nou pe aceleași namespace-uri, din circuite noi, după ce dispozitivul restaurat are un token | — | — | mesajele pereche trimise înainte de reconectare se pierd; o resetare din partea lui eșuează până la publicarea bundle-ului nou | T26, T31 |
| Reconectare / revocare | k trimiteri inițiate de utilizator, eșalonate pe 48 h / 24 h | — | — | primește mesajul | T28, T31 |
| Un deținător de card cumpără acces la inbox | o răscumpărare și listări cu un scop de scriere străin | — | — | volumul și momentele inbox-ului (L7-D16) | — |

**S12** (erată și completare): „Mitigări: avertisment blocant (**FR-4.6**): schimbarea cheii se recunoaște doar printr-o semnătură validă sub identitatea Ed25519 fixată; trimiterea se blochează, iar mesajele sub cheia nouă sunt reținute până la confirmare; safety number verificabil offline; atestarea hardware amânată (ADR-30). **Rezidual:** utilizatorul confirmă fără verificare; mesajele reținute peste limită se pierd; un hoț de mnemonic pe clientul oficial nu produce avertisment. **Test:** suita KC, SCN-D (Faza 9), pasul 5 pe dispozitive.”

**Ciclul de viață al cheilor, rândul libsignal:** „biblioteca; identitatea derivată din ramura messaging (`ghost/v1/dm/identity`); SQLCipher; prekey semnat și prekey Kyber de ultimă instanță rotite săptămânal, șterse la 91 de zile după înlocuire; ratchet per mesaj; ștergerea sesiunii; PCS”.

### B.4 LIMITE

- **L1, rândul „Detectare”**, a doua mitigare: „orice cheie nouă a unui contact, semnată de identitatea lui, înseamnă avertisment blocant (**FR-4.6**); în P0 (un singur dispozitiv), «dispozitiv nou» înseamnă «cheia libsignal a contactului s-a schimbat»”.
- **L1, rândul „Recuperare”**: textul din B.1.
- **L1.1, rânduri noi (Faza 9):** contactele, starea de încredere și timer-ele conversațiilor; înregistrările libsignal (sesiuni cu contoare, chei sărite, timpi la minut; prekey-uri înlocuite cel mult 91 de zile); cheile de pereche până la 45 de zile după săptămâna lor; etichetele de deduplicare cu cheie locală, până la `ceil7(zi(autor) + prospețimea treptei + 1)` (de la 6 zile și 4 ore pentru 1 h la 45 de zile pentru 30 de zile; cu un `message_id` cunoscut confirmă primirea); blob-urile E2E reținute până la rezultatul operației; mesajele reținute la schimbarea cheii, până la limita lor; minutul următoarei expirări, în alarma de sistem.
- **L5:** Q34 al Fazei 8 reevaluat: un proprietar DM ale cărui capabilități au expirat își revine în fundal (înregistrările în așteptare armează reținerea Q29); drop-urile rămân cum au fost declarate.
- **Secțiune nouă L7 (DM)**, după L6.1:

> Notă: secțiunea L7 din acest document nu e celula L7 a scurgerii declarate din T2 (Faza 8); reziduurile DM au sufixul „-D”.

| ID | Reziduu | De ce rămâne | Atenuare |
|---|---|---|---|
| L7-D1 | Releele reconstruiesc muchia dintre două inbox-uri din momentele răspunsurilor după ~6 schimburi (standard) sau ~8 (high-privacy); cu întârziere activă, în 1–2 runde; pentru conversațiile cu timer diferit de cel implicit, în ~2–3 schimburi (L7-D4) | trafic dependent de activitate, fără cover | fără reflexe (T28); întârzierea high-privacy; cover P2; măsurat pe clase TTL (S-DM2) |
| L7-D2 | Co-apariția la pornirea sesiunii leagă în ~3 sesiuni namespace-urile unui client și, cu un contact, identitatea DM de namespace-urile canalelor | L2.1 punctul 1 | decuplare în Faza 12 (P1); fără afirmații în UI |
| L7-D3 | Un deținător de card care colaborează cu releele recunoaște plicurile intro (prim contact, resetare, reconectare, primul răspuns al fiecărei conversații și toate mesajele unei conversații la care nu răspund), vede prezența și volumul primit; plicurile intro sunt atribuibile cu seed-ul destinatarului; un adversar cuantic viitor cu cardul citește din ele cardul complet al fiecărui expeditor (identitatea și `card_secret`) | cardul e un secret comun „îmi poți scrie”; stratul interior intro e X25519; rădăcinile de pereche circulă doar în sesiuni confirmate | modul pereche pentru conversațiile cu răspuns; rotația cardului (Faza 13); strat intro cu KEM (P2) |
| L7-D4 | Treapta TTL (1 h / 1 zi / 7 zile / 30 de zile) împarte inbox-ul pe clase de conversație și leagă cele două inbox-uri ale unei conversații cu timer diferit de cel implicit (~2–3 schimburi); primul blob pe o treaptă nouă arată schimbarea timer-ului | TTL ≥ timer (ADR-27 punctul 11); ambele sensuri folosesc treapta conversației | o treaptă per conversație; Q15 sau Q39 ar reduce clasele; textul din Faza 13 o spune |
| L7-D5 | Mai multe depuneri ale aceluiași expeditor într-o sesiune folosesc același circuit | izolarea per namespace (T21) | circuit nou per depunere, respins (cost) |
| L7-D6 | La stabilire, preluarea lui P urmată de o depunere leagă P de X, iar releul care servește bundle-ul alege momentul depunerii (cel puțin 2 minute mai târziu); până la trei încercări de preluare coincid fiecare cu începutul unei sesiuni; o conversație fără răspuns repetă preluarea după 30 de zile; primul DM al unui invitat către cel care l-a invitat, curând după onboarding, leagă cele două clustere | stabilirea cere un bundle | întârzierea high-privacy; încercări limitate |
| L7-D7 | Pe dispozitiv rămân contactele, timer-ele, stările de încredere, contoarele ratchet și cheile sărite, etichetele de deduplicare (între ~2 și ~7 săptămâni, după treaptă; cu un `message_id` cunoscut confirmă primirea și săptămâna), tombstone-urile, mesajele reținute până la limita lor, blob-urile reținute și încărcăturile outbox până la rezultat sau termen, namespace-urile și credențialele unui contact blocat sau șters până la termenul ultimei operații (≤ 7 zile), prekey-urile vechi (≤ 13 săptămâni), cheile de pereche din fereastră, timpii la minut sau zi din înregistrările libsignal, minutul următoarei expirări în alarmă | necesare funcționării | T33; notificări fără conținut |
| L7-D8 | Destinatarul plătește inbox-ul; un deținător de card îi poate epuiza cota săptămânii și îl poate face să calculeze hint-uri pentru plicuri false; un releu care declară o expirare scurtă poate re-servi, în fereastra de prospețime, mesajul intro autentic al unui solicitant respins sau șters și readuce cererea | fără token-uri cheltuite de expeditori (T27) | cotă per înregistrare; limitele consumatorului; rotația cardului (Faza 13) |
| L7-D9 | O retrimitere a acelorași octeți după o stocare ambiguă leagă două sesiuni ale expeditorului prin hash | exactly-once (Faza 7) | cel mult două retrimiteri; rară |
| L7-D10 | Răscumpărările, înregistrările și publicările săptămânale arată „identitatea e activă în săptămâna asta”; releele văd minutul primei sesiuni după `t_pub`, deci absențele, și momentele activării și ale restaurării (deținătorii de card văd doar săptămâna); o reconectare sau o revocare arată slab gradul pe una-două zile; un proprietar offline peste ~2 săptămâni nu mai are bundle valid, iar după ~2–3 săptămâni nu mai primește | inbox-ul trebuie plătit, înregistrat și publicat | momente independente de activitate (T31); `uploaded_at` rotunjit la săptămână |
| L7-D11 | Fără prekeys de unică folosință: primul mesaj înregistrat poate fi decriptat de cine obține ulterior cheia de identitate și cheile prekey ale săptămânii înainte de ștergerea lor (≤ 13 săptămâni); mesajele peste limitele de reordonare libsignal se pierd; un mesaj a cărui cheie rămâne ca cheie sărită pe un dispozitiv confiscat poate fi decriptat, iar dacă purta o rădăcină de pereche deschide plicurile pereche ale acelei generații (excepția P-7) | relee oarbe nu pot aloca prekeys unice; libsignal păstrează cheile sărite fără limită de timp | rotație săptămânală și ștergere; rădăcini doar în sesiuni confirmate |
| L7-D12 | Restaurarea fără backup pierde contactele, sesiunile și cheile de pereche: plicurile pereche ale contactelor stabilite nu se mai deschid (numărate) până la reconectare; o resetare din partea lor eșuează până când dispozitivul restaurat are un token și publică un bundle | fără backup de contacte în P0; token-urile nu se restaurează | refacerea din plicurile intro și reconectarea, care nu cere token; backup criptat al cardurilor (P1, Q28) |
| L7-D13 | Inbox-ul, bundle-ul și scopurile credențialelor lor sunt statice per card și releu: un disc de releu confiscat leagă săptămânile unui inbox cât trăiesc blob-urile (≤ ~6 săptămâni) și înregistrările (≤ 3 săptămâni); după o schimbare a tabelei de sloturi, blob-urile aflate doar pe relee ieșite din ES se pierd când le expiră înregistrările | fără rotație săptămânală a namespace-ului sau a credențialelor | rotația cardului (Faza 13) |
| L7-D14 | Ștergerea fizică poate întârzia față de timer cât procesul e înghețat (alarma amânată de Doze) sau cât cheia bazei așteaptă deblocarea, ori după o repornire fără rețea (nu există receiver de boot; jobul periodic cere rețea) | planificarea Android | filtrul de citire, ștergeri la deschidere și în coada de consum, alarmă inexactă |
| L7-D15 | Pentru treptele de 1 h și 1 zi, o confirmare cu expirare prea devreme e acceptată (toleranța σ = 3 zile face limita vidă); echivalent cu reținerea blob-ului | toleranța de ceas a Fazei 7 | clienții listează toate releele (ADR-11); limită corectată de releu în Faza 12 |
| L7-D16 | Un deținător de card își poate cheltui propriul token pentru o capabilitate de scriere pe inbox-ul meu și îl poate lista: volumul și momentele, fără conținut | la relee scrierea include citirea | regulă de citire legată de proprietar (Faza 12, Q36) |
| L7-D17 | O schimbare de cheie nedecisă peste limita de reținere (≤ expirarea pe releu, ≤ 30 de zile și o oră) pierde mesajele reținute | reținerea e limitată | notificare persistentă în Faza 13 |
| L7-D18 | Un hoț de mnemonic care folosește clientul oficial are aceeași identitate libsignal: contactele nu văd avertisment | identitatea derivă din seed (FR-1.2) | revocarea v2 prin inbox-urile contactelor |

### B.5 `allowed-observables.json` v2 (English, like the file; written in S1)

```json
"version": 2,
"op": { "type": "enum", "values": ["store", "get", "check", "list", "redeem", "gossip", "register"] },
"key_kind": { "type": "enum", "values": ["read", "deposit"], "note": "register events only (ADR-30)" },
"ttl_bucket_seconds": { "type": "enum", "values": [3600, 86400, 604800, 2592000, 7776000],
                        "note": "exact TTL bucket of a store; the relay refuses any other TTL (ADR-32)" },
"capability_scope": { "type": "hex", "len": 64,
                      "note": "SHA-256 of the presented credential: a write capability, or a bearer read or deposit key v3 (ADR-30); never the credential itself" }
```

`ttl_bucket_days` is removed. Positive fixtures gain `register` lines for each `key_kind` and 3600 lines; negative fixtures gain 7200, the old field, `key_kind` on a store, and a verifier-shaped hex value in an undeclared field.

### B.6 Plan, ADR index, READMEs, STATUS

- Plan §6.2 row 9 and FR-7.15: B.1. Plan §1.2 and every "FR-4.5" about key change → "FR-4.6". Annex B: a note pointing to ADR-30 for prekeys, the inbox and capabilities. Annex D: `org.signal` coordinates at 0.102.2 from Signal's repository (ADR-28).
- `docs/adr/README.md`: a section "Propuse (aplicate în Faza 9)" with rows ADR-28 … ADR-34; ADR-05 gets a line "cardul de contact opțional: amânat în Faza 13 (ADR-30)".
- `ghost/android/sync/README.md`: the §13.3 API additions and the new send idiom (seal after libsignal, the bucket from the content length).
- `ghost/client-core/README.md`: credential v3, `RegisterKey`, exact TTLs (no new error category).
- Relay `README`: `RegisterKey`, `keys.redb`, the deposit ledger, exact TTLs.
- `docs/STATUS.md`: the Phase 8 row closed (F-1) and the Phase 9 row.

---

## Appendix C: Evidence, verified vs assumed

**Verified in this session (repository at `e833250`, 2026-09-16)**

- `ghost/android/gradle/libs.versions.toml`: `kotlin = "2.4.20"` (:5), `libsignal = "0.86.5"` (:18), `bouncycastle = "1.85.2"` (:19); only `libsignal-android` is declared as a library alias (:39). `dependency-allowlist.txt:12` allows `org.signal`.
- `.github/workflows/ci.yml:3-8`: every action pinned by full commit SHA (the rule X-17 follows).
- `ghost/scripts/gates/rust-crypto-pins.txt:14,19`: `lock ring 0.17.14` and `graph ghost-client-net aarch64-linux-android,x86_64-linux-android ring 0.17.14 required`; `ghost/Cargo.toml:57,62` (`rustls` with feature `ring`; `ring = "0.17.14"`); `issuer/crates/entitlement/Cargo.toml:14`. Hence E-4.
- `Schema.kt:240-253`: `outbox_op` is a rowid table with `operation_id BLOB PRIMARY KEY`, columns `operation_id, namespace_id, blob_hash, ciphertext, ttl_seconds, not_before_minute, deadline_hour, required_operators, outcome, released`, and `ttl_seconds IN (86400, 604800, 2592000, 7776000)`; `:259-273`: `outbox_delivery` WITHOUT ROWID with columns `operation_id, relay_id, state, attempts, next_attempt_minute, inflight, lease_hour, copy_hour, ack_minute, strikes` and the cascading FK; `:280-296`: `inbox_blob` with `offers`; `:312-352`: the 8 v2 outbox triggers; `:682-688`: the v3 guards `outbox_op_no_replace` and `outbox_op_rowid`; `:219-228`: `relay_capability(kind IN ('read','write'), token 1..512)`. Hence E-5 and §13.6.
- `sync/api/Inbox.kt`: `InboundBlob(namespace, hash, ciphertext)`; `claim` commits the offer counter and returns a twice-offered row alone. `sync/api/Outbox.kt`: `OutboundBlob.deadlineEpochSeconds`; `OutboundOutcome.resendNotAfterEpochSeconds` for INDETERMINATE; `enqueue` throws on a closed resend window; `cancel` true only while no copy can exist. `sync/api/Namespaces.kt`: `register(…, listen, sendDelay)`.
- `sync/store/CapabilityStore.kt:93-148`: `needed()` reports READ MISSING for a listening namespace with no token of either kind, and WRITE MISSING only where the outbox has work (the resolvable-copy clause at `:141`). Hence E-10 and §13.3 item 4.
- `entitlement/engine/RedeemPlanner.kt:11-32`: the timing table (EXPIRING in the last 23 h with a p + 1 token; WRITE MISSING at once; READ MISSING within 6 h; ±1 h deferral; `NO_SLOT`).
- `relay/crates/capability/src/lib.rs:199-219`: `QuotaLedger` in memory; `charge` returns `Expired` when `cap.expiry_unix ≤ pruned_through` (:215-217). Hence E-11.
- `protocol/relay/v1/relay.proto`: `Capability { bytes token }`; six RPCs including `RedeemToken`; no registration RPC. `allowed-observables.json`: `op` without `register`; `result` already includes `rejected_ttl` and `rejected_period`.
- `DerivationLabels.kt:18-19`: MESSAGING "seeds the libsignal identity key pair (§7.2)"; the `ALL` list.
- `docs/adr/ADR-27`: points 7–11 as cited, including "cea mai mică treaptă TTL ≥ timer" and the non-existent field name `ttl_bucket`; `ADR-19`: "Nicio logică de protocol în Kotlin"; `ADR-20` point 8 (framing, gRPC, padding in Rust); `ADR-23` point 9 (one participant) and Q34; `ADR-25` point 9 (D11); `ADR-07`, `ADR-12`, `ADR-14` texts; THREAT_MODEL key-lifecycle row ("seed din ramura messaging").
- `docs/design/faza8-issuer.md`: §10.2–§10.7 (redeem order, capability v2 expiry `start(p+1) + 3600`, D11 text), §12.3–§12.6 (activation slots, redemption timing, residues E1–E30), §19.24 point 6 (every relay table exported; an unknown table fails the world), §19.28, §19.29 (Q31 simplified: one refresh time; NI-2/NI-3 without exemption). Hence E-6 and C-17.
- (After review, §21.6: the logging lines below are in a `#![cfg(test)]` snapshot; the production lines are `session_management.rs:130-131, 336-337`.) libsignal v0.102.2 sources copied in the research scratchpad: `session.rs:59` checks `is_trusted_identity(…, Receiving)` in `process_prekey` before any session state changes (hence E-1's attack path is real); `session.rs:193` checks `Sending` for a bundle; `session.rs:145` logs the remote address at warn; `session_cipher_legacy.rs:160-164` and `:344-348` log `"Identity key {} is not trusted for remote address {}"` with the key in hex at warn; `:253` logs a decryption-failure report at error. Hence E-18.
- `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`: sections L1–L6 and L6.1; no L7. `INVARIANTS.md`: T1–T25; T9 "Faza 9/10"; T13 "Faza 10"; T20 "11 coloane de timp".

**Verified by the research notes (cited, not re-run here)**

- RL: 0.102.2 (2026-09-10) in Signal's repository only; 0.86.5 last on Maven Central; AAR and JAR sizes and JVM 21; SPQR `min_version` V0 at 0.86.5 and V1 at 0.102.2; `PreKeyBundle` one-time EC prekey nullable and Kyber prekey mandatory; the store interfaces and `markKyberPreKeyUsed` semantics; `ECPrivateKey(bytes)` and `IdentityKeyPair(IdentityKey, ECPrivateKey)`; `NumericFingerprintGenerator`; `SealedSessionCipher.decrypt` always validates through an overridable `CertificateValidator`; SSv2 cleartext recipient ids; libsignal crates not on crates.io; AGPL-3.0-only for libsignal and `spqr`; dormant `libsignal-net` in the JNI library; issue #660 size figures; `MAX_UNACKNOWLEDGED_SESSION_AGE` 30 days.
- RC: F1–F12 (the frozen v2 CHECK, day-granular TTL paths, the store window vs short TTLs, per-sender scopes, the token budget, no D11 code, one participant slot, one job and no alarm permission, no client `pad_plaintext`, the stale libsignal pin, AGPL vs the licence posture, FR numbering).
- RE: F2 (raw TTL persisted), F3 (σ vs short TTLs), F4 (consumers do not see the relay expiry), F5 (`Gc.checkpoint` ignores the result), F6 (v1 tables unused), F8 (PreKey until acknowledged), F9 (timestamps inside records); the Signal comparisons.
- RS: K1–K26, O1–O22, D1–D10.
- RP: F1–F16; the SDA and co-occurrence models of §4.
- The judge's verification of `curve25519-elligator2` 0.1.0-alpha.2 (crates.io API, 2024-07-26) and of the missing low-order component (E-3).

**Assumptions checked in S0–S7 (a false assumption changes the named section before code depends on it)**

| # | Assumption | Checked in | Affects |
|---|---|---|---|
| A1 | Stripped `libsignal_jni.so` ≈ 11 MB per ABI; 16 KB aligned | S0 | §2.5, Q24 |
| A2 | The desktop natives of `libsignal-client` load in JVM tests on ubuntu-24.04 and Windows, and can be excluded from the APK by `packaging.resources.excludes` | S0 (blocking) | §2.5, §15.1, G-LS2 |
| A3 | The AAR ships an empty manifest; its consumer R8 rules cover the JNI callbacks, or GHOST's keep rules suffice | S0 | G-LS5, G-LS7 |
| A4 | Worst-case L1 overhead with SPQR ≤ `O_MAX` = 2 560 | S0 | §6.6 |
| A5 | libsignal native logging reaches no sink other than the Java `SignalProtocolLoggerProvider` (no direct logcat output) | S0, emulator | §2.6, R-7, Q2 |
| A6 | The pinned Java API can generate ML-KEM-1024 prekeys | S0 | PQ-2, Q21 |
| A7 | `CiphertextMessage.getType()` distinguishes PreKey from Whisper output after `encrypt`, and `PreKeySignalMessage(bytes).getIdentityKey()` parses before decryption | S0 | §6.3 mode rule, §7.4 R6 |
| A8 | A Java store callback's exception surfaces as a Java exception after the native call and leaves nothing committed (the SQLCipher transaction rolls back) | S0 | §2.4, §8.2 |
| A9 | The exception type of the Kyber reuse refusal and the accepted fingerprint `version` values | S0 | §8.2, §8.4 |
| A10 | Only the times GHOST passes in end up inside session and prekey records; the list of libsignal paths that read the system clock | S0 | T33, §2.3 |
| A11 | JDK 21 works with AGP, D8/R8, Kotlin 2.4.20 and the Phase 7/8 harnesses | S0 | R-4 |
| A12 | `kotlin-clearnet.sh`, `no-logging.sh`, `anti-placeholder.sh` cover the new modules or can be extended | S0 | §16.1 |
| A13 | SQLite and SQLCipher's SQLite accept `legacy_alter_table = OFF` renames rewriting FK references, and the v1 index names are those of `Schema.kt:88-89` | S3 (both engines) | §13.6 |
| A14 | `CapabilityStore`'s credential selection can prefer a READ credential for list and get without breaking Phase 7 tests | S3 | §13.3 item 7 |
| A15 | The relay capability crate's constant-time comparison serves v3 verification without a new crate | S1 | §16.3 |
| A16 | Hint computation for 1 000 contacts meets the 1 s foreground budget per 16-blob batch on a mid-range device | S7 | R-S5, Q37 |
| A17 | The emulator runner action works with API 29 and 35 x86_64 images and KVM on the CI runner class | S12 | §15.9 |
| A18 | `markKyberPreKeyUsed` is called exactly when libsignal creates a new session state from a PreKey message, after the inner message decrypted (read in `session_management.rs:270-281` and `session.rs:97-103` at 0.102.2; re-checked at every bump) | S0 | §21.3 |
| A19 | The Kyber reuse refusal type and whether it subclasses `InvalidMessageException`; the SQLCipher cursor-window limit for `sig_session` records | S0, S5 | §21.5, §21.6 |

---

## Appendix D: Sources

- **Research notes** (phase9 scratchpad): `R-spec.md`, `R-libsignal.md`, `R-code.md`, `R-privacy.md`, `R-envelope.md`; the candidate designs `D-security.md` (base), `D-operations.md`, `D-delivery.md`; the judge verdict.
- **Repository** (at `e833250`): the files cited inline; `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`; `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`; `docs/design/faza7-sync-engine.md`; `docs/design/faza8-issuer.md`; `docs/adr/ADR-01 … ADR-20, ADR-22 … ADR-27`; `docs/THREAT_MODEL_v2.1.md`; `docs/LIMITE_REZIDUALE_SI_MITIGARI.md`; `ghost/test-harness/privacy/{INVARIANTS.md, allowed-observables.json}`; `docs/STATUS.md`.
- **Upstream** (through R-libsignal §15, keys `[U1]`–`[U43]`): libsignal releases and sources at v0.102.2 (https://github.com/signalapp/libsignal), Signal's Maven repository (https://build-artifacts.signal.org/libraries/maven/), the SparsePostQuantumRatchet repository, Signal-Android's version catalog, issue #660.
- **Specifications and papers:** PQXDH (https://signal.org/docs/specifications/pqxdh/); SPQR (https://signal.org/blog/spqr/); Signal sealed sender (https://signal.org/blog/sealed-sender/); RFC 7748 (X25519); RFC 5869 (HKDF); RFC 8439 (ChaCha20-Poly1305); FIPS 203 (ML-KEM); Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021; Martiny et al., "Improving Signal's Sealed Sender", NDSS 2021; Danezis, "Statistical Disclosure Attacks", 2003; Elligator (https://elligator.cr.yp.to/) and the Monocypher `crypto_elligator_key_pair` documentation.
- **Platform and tooling:** SQLite `PRAGMA` (secure_delete, wal_checkpoint, legacy_alter_table, foreign_key_check), WAL and foreign-key documentation; Android AlarmManager (`setAndAllowWhileIdle`), Doze, notification history (source.android.com), Key Attestation and Remote Key Provisioning pages; GNU GPL FAQ (#IfLibraryIsGPL, #GPLStaticVsDynamic, #AGPLGPL).
