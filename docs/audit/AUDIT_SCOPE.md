# GHOST external audit: scope document

| Field | Value |
|---|---|
| Purpose | Tells an auditor (and the owner, who budgets and schedules the audit) what GHOST consists of, how big it is, what it claims, what is in and out of scope, and where to spend the first weeks. One of the English documents of the audit package in `docs/audit/` (index in section 9). |
| Handling | **Confidential, for auditors under NDA.** It lists unfixed weaknesses and the trust model of the build infrastructure. The owner-only file `OWNER_ONLY_MARKET_AND_BUDGET.md` (market notes, budget method, negotiating notes) is **never** attached to anything sent outside the project. |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (`main`, 2026-10-03; not yet on `origin/main`, which was `d1a19cd` when read on 2026-10-04). Every measurement below was taken on this tree. Product code and workflows are identical to `197b2b4` (2026-09-28) except `ghost/scripts/gates/self-test.sh` (+9 -1 lines) and three 6-line `paths-ignore` blocks in workflow triggers (`git diff --stat 197b2b4 a0f3f58 -- ghost .github`); the package commits change only `docs/`. |
| Date | 2026-10-03; revised 2026-10-04 after two adversarial reviews (the CI history was read on 2026-10-03 and again on 2026-10-04; the artifact listing behind KI-SUP-7 and KI-SUP-8 on 2026-10-04) |
| Authorship | Drafted by an AI agent for the owner from the repository, its design documents and the public sources cited with URL and access date. External facts are marked with URL and access date; anything inferred is marked **(inferred)**. The owner should re-check external facts before sending any of this to a third party. |
| Language | English. A Romanian cover note for the owner (summary first, then the steps and the owner's decisions) is `README-RO.md`; it is not sent to anyone. |
| What this is not | A statement that GHOST is ready for audit or for release. Section 0 lists the preconditions that are **not** met. Nothing here is a privacy or security claim for users (CP-10; `docs/STATUS.md`: "Afirmații permise în marketing/UI: niciuna"). |

---

## 0. Read this first: the honest state, and what the audit can start from

GHOST is a private, closed-source Android forum and messenger: Tor-only transport, blind capability tokens bought with Monero, direct messages (DMs) with Olm from vodozemac under a GHOST-built post-quantum sealing layer (X-Wing), forum channels planned on OpenMLS. The master plan (`docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` §6.2, row 15) makes an external audit a **release gate** ("Hardening + audit extern + retest: mobil, integrarea vodozemac și a stratului PQ DM, OpenMLS, relay, issuer/blind sig, supply chain", 6-8 weeks, exit "0 Critical/High deschise"; spec NFR-13: "0 open Critical/High at production"). Row 15 depends on rows 9-14.

**Preconditions for a final audit that are not met at the base commit** (details and sources in `KNOWN_ISSUES.md` and `EVIDENCE_INDEX.md`):

| # | Precondition | State at the base commit |
|---|---|---|
| PC-1 | Phase 9 (DM) closed | **No.** Of the 16 exit-gate items of design `faza9-dm.md` §17.2, items **5, 6, 7, 8, 9, 10, 11, 12, 14 and 16 are open** and item 15 must be re-checked on the closing commit (read against §22.34, §22.38 item 22 and the CI picture of `EVIDENCE_INDEX.md` section 3). Items 5 and 6: suite cases RP1, RP2, RP10 and most of RO, KC, CB, RE, OS and RK are not built, and the mutants PM-15/16/17, PM-34 and MC-6 that item 6 requires are not among the registered ones. Item 7: the EP timer versions (R-T9), the ME-14 and ME-10 seams and the held replay are not built, and defect R-T3 is open (KI-DM-3). Item 8: correctness mutants 26 of 57 and privacy mutants 15 of 40 run and detected, and T32 at gate scale is red (PC-5). Item 9: the T2 sweep is red on pairs 2, 3 and 9 (PC-4). Item 10: the emulator job never ran on a runner (no KVM). Item 11: the two-device checklist is not executed. Item 12: NFR-1, NFR-4 and NFR-5 are not measured. Item 14: ProVerif covers M-1, M-2, M-3, M-6 step (3) and M-7's structure only. Item 15: `docs/STATUS.md` is stale (KI-DOC-1). Item 16: the phase review has 8 owner decisions open. Items 1-4 and 13 are not recorded as open in the design notes (not re-checked item by item; item 2's `static gates` job was red at the last completed `ci` run, KI-SUP-1). |
| PC-2 | Phase 10 (OpenMLS channels) implemented | **No code on `main`.** Design approved by the owner 2026-09-27 (Q1-Q41) and 2026-09-28 (Q42-Q50). The Rust crate `ghost-client-mls` and its JNI surface exist only on unmerged branches whose tips move daily (read 2026-10-04 02:46 +0300: `p10-s2a` at `7fab557`, `p10-em3` at `5c37997`, `p10-s1a` at `6d79173`, `p10-s2b` at `3abbeb9`, and the integration branches `p10-integ` and `p10-s3` at `ba21ad3`, which merge S2a and S1a). The Kotlin channel facade in `:crypto-bridge` is on `p10-s2b`; no branch yet holds Kotlin channel-engine code (slices S3-S12 of the design; `p10-s3` points at the integration merge). Only the evidence spike `ghost/client-core/mls-spike` is on `main`. |
| PC-3 | Phases 11 (media), 13 (UI), 14 (distribution) done; Phase 12 (metadata hardening) done | **No.** Phase 11, 13 and 14 are designs "proposed, not approved"; Phase 12 not started (`docs/STATUS.md`). There is no UI, no media pipeline, no updater, no signed-release pipeline. `ghost/android/media` is an empty module. |
| PC-4 | T2 (issuer-relay unlinkability) green at the gate scale on all ten seed pairs | **No.** Pair 0 passed (closing Phase 8); in the nightly of 2026-10-03 pairs 2, 3 and 9 fail (run 37108461415). |
| PC-5 | Gate-scale T32 (DM privacy world) green | **Not now.** It was green on all ten seed pairs once (nightly 2026-09-27, run 36310990671, harness with the earlier one-pass-per-minute cadence). Since the harness was moved to production's trigger mix (design `faza9-dm.md` §22.36) every nightly from 2026-09-28 to 2026-10-02 (five runs) fails all ten pair jobs. The report check lists three joins, identically in the three nightlies read line by line (09-28, 10-01, 10-02): **JD5** (TTL after a user-set timer; T25, T30) on 10 of 10 pairs, **JD6** (no reflex; T28) on 7 of 10 (pairs 1, 2, 3, 4, 5, 7, 8) and **JD7** (read confinement; T31) on 1 of 10 (pair 4), each with "0 PASS lines over a non-empty sample". The eleventh job of the nightly (twins NI-DM1 to NI-DM3, the JD7 withhold variant, the T34 seizure worlds, JD8, the privacy mutants, the S-DM1 controls) is green every night. The only candidate cause is a guess: the open TIMER_SET defect (KI-DM-3) could explain JD5 and perhaps JD6; it does not obviously explain JD7 (`KNOWN_ISSUES.md` KI-PRV-2). The nightly of 2026-10-03 was cancelled after pairs 0, 1 and 2 had failed. |
| PC-6 | Device evidence | **None on real devices.** Emulator (API 29, 35, x86_64, software Keystore) runs were local; `dm-emulator.yml` has never run on a runner. arm64 was built, never executed. |
| PC-7 | Staging | **Not deployed.** Runbooks and compose files exist (`ghost/infra/`); there is no three-operator relay staging, no running issuer stagenet, no staging capture (T1). |
| PC-8 | Open owner decisions | Eight Phase 9 review items, G-DM3's allowlist, several design defects (`KNOWN_ISSUES.md` section "Owner decisions"). ADR-22 to ADR-26 (the issuer core) are still "propus, aplicat", awaiting the owner. |
| PC-9 | Verifiability package of ADR-38 | **Nothing exists**: no transparency log, no auditor-reproduced build (T12b), no escrow. Build reproducibility is proven only for the same build path (T12). Commits are not signed (FR-8.1 gap, `docs/STATUS.md`). |
| PC-10 | CI evidence green | **Mixed** (`EVIDENCE_INDEX.md` section 3): `ci` at `197b2b4` and at `d1a19cd` (same product code and workflows) had every job green except `static gates`, which failed one self-test case (G-R7 "fails closed on an unreadable base") on CI's shallow checkout only; the same case passed in the `rust` job's full checkout. The case was repaired in `a0f3f58`, which is not on `origin/main` and **has never run in CI**. This package's own self-test run skipped the Rust block that holds the case, so the repair was checked separately: the case's code, before and after the repair, was run on a full and on a shallow clone in the runner image (`EVIDENCE_INDEX.md` section 1.2); the whole repaired `self-test.sh` has still not run on a shallow CI checkout. Nightlies `dm-fuzz`, `dm-privacy-gate`, `t2-exit-gate`, `dm-emulator` are red. CI is advisory only (no branch protection on the Free plan). |

**What an auditor can start from today** (inferred): the Rust `ghost-client-dm` crate and its JNI surface, the relay, the issuer and the entitlement formats are implemented, reviewed internally and stable in structure; the Android engines (`:sync`, `:entitlement`, `:messaging`, `:storage`, `:identity`) are implemented and heavily tested on the JVM. A **pre-audit review of Tier A1 (DM composition) and Tier C (relay, issuer)** is possible now; the full audit needs PC-1 to PC-3 closed or explicitly waived. `AUDITOR_RFQ.md` sections B3 and B8 (item 6) describe a two-stage option.

---

## 1. The system on one page

```
  Android client (one process)                       Tor network                  Operators (AD-1 may control all of them)
  ----------------------------                       -----------                  ---------------------------------------
  Kotlin modules (UI later, Phase 13)                                             relay A, B, C (onion services, Rust)
    :identity  :storage(SQLCipher)  :sync  ------>   onion circuits  ---------->   ghost-relay: opaque blobs, TTL buckets,
    :entitlement  :messaging  :crypto-bridge          (Arti 0.46, one               capabilities, token redemption, key
    :network (JNI)  :media(empty)  :app               circuit scope per             registration; stores nothing readable
  Rust library libghost_client_net.so                 namespace / issuer flow)
    ghost-client-net (Arti, relay+issuer clients)                                  issuer (onion service, Rust, Monero view
    ghost-client-dm  (Olm/X-Wing/seal, 29 JNI fns)   ---------------------------->  wallet; blind-signs tokens for paid
    ghost-entitlement / ghost-relay-api / issuer-api                               invoices; operator station + air-gapped
  Android Keystore (AES-GCM wrap keys)                                             signer pay referral batches)
```

Trust roles used throughout (`docs/THREAT_MODEL_v2.1.md` §3-§4):

* **Client endpoint**: the only party that holds content keys (CP-01). Trusted for its own user's secrets; its compromise is out of scope (AD-8, LIMITE L1).
* **Relay**: untrusted for content, identity and linkage (AD-2); trusted only for availability (assumption A6: at least one of at least three relays honest and available).
* **Issuer**: untrusted for linkage (AD-3: "issuer compromis"); it sees invoices, amounts and call times but must not be able to join a payment to a relay-side activity cluster (T2).
* **Operator (AD-1)**: controls the issuer, the release manifest and one or more relays; with closed source it is in practice the same party as the vendor adversary AD-V (ADR-38), so every guarantee "against the operator" holds only for a build that is published in a transparency log and reproduced by auditors, which does not exist yet (LIMITE L-SRC).
* **Tor**: assumed to resist local observers, not a global passive adversary (A3, AD-5).

Trust boundaries TB-1 to TB-7 (Android process-Keystore; client-relay; relay-relay; client-issuer; issuer-Monero network; build-release; member-MLS group) are tabulated in section 6.

### 1.1 Assets and secrets

English digest of `docs/THREAT_MODEL_v2.1.md` §2 (assets AS-1 to AS-12) and §5 (key lifecycle), which are in Romanian, plus the secrets those two tables do not list (rows marked **+**, compiled from `docs/adr/ADR-26-issuer-operations.md` point 4, `ghost/issuer/crates/service/src/custody.rs`, `ghost/relay/crates/node/src/main.rs`, `ghost/protocol/entitlement/README.md`, `docs/ci-self-hosted.md`). The claim ids refer to section 7.

| ID | Asset or secret | Where it lives | Impact of compromise | Main protection |
|---|---|---|---|---|
| AS-1 | Root entropy (256 bit) and its 24-word BIP-39 mnemonic | Keystore-wrapped on the device; the user's memory or paper | Critical: every key, the identity, referral | Android Keystore wrap (assumption A2); never leaves the device; user custody (assumption A8); CP-01 |
| AS-2 | Ed25519 identity key; per-channel pseudonym seeds | derived by HKDF-SHA256 (`ghost/v1/identity`, `ghost/v1/channel-pseudonym`); Keystore and encrypted DB | Impersonation; linking one user's pseudonyms across channels | T14; revocation certificates |
| AS-3 | Olm session state and weekly generation secrets; OpenMLS epoch state (planned) | SQLCipher; Olm state is an envelope under a state key that is held in native memory and Keystore-wrapped at rest | Reading future messages until post-compromise healing | `wrap.rs`; T33; classical pair roots do cross into the JVM heap (CRY-P9-03) |
| AS-4 | Content: messages, posts, media in clear | endpoint only; encrypted DB; decrypted in memory | Confidentiality | CP-01, CP-02; separate Keystore-wrapped content key (`ContentCipher`) |
| AS-5 | SQLCipher database key | Keystore-wrapped (AES-256-GCM; StrongBox when available, else TEE) | Offline access to AS-3 and AS-4 | TB-1; backups excluded (T4, not yet inspected on a real backup) |
| AS-6 | Access, invite and credit tokens (bearer value) | encrypted DB | Quota abuse; credit theft; the finalisation day of a pack (E19) | T2, T22, T23; MS-1 to MS-8 |
| AS-7 | Social graph: who is in which channel, who invited whom | only at group members (MLS, planned); the sponsor is visible in-channel | Relational deanonymisation | design only (Phase 10) |
| AS-8 | Traffic metadata: times, sizes, namespaces | observable at relays and on the network | Activity correlation | T1, T9, T19 to T21; declared residues L2, L7 |
| AS-9 | Issuer data: invoices, amounts, subaddresses, nullifiers, claims, `issued.journal`, snapshots, counters, view-wallet history | issuer host (redb, journal, wallet) and the operator's payout station | Financial linkability (not identity) | retention rules (ADR-26 point 5); T2 |
| AS-10 | Release signing key and manifest | offline, HSM (planned) | Malicious distribution | assumption A7; Phase 14 (not built) |
| AS-11 | Relay keys | relay host | Impersonating a relay; DoS; not content | operator procedure (runbook O1) |
| AS-12 | Source code and dependencies | private GitHub repository, registries | Supply chain | tier D |
| **+** | Issuer blind-signing keys: RSA-2048, one per (kind, epoch) | sealed files (`GHKS`) on the issuer's encrypted disk; only a window of keys in memory; destroyed after the last invoice that uses them (epoch end + 42 days at the latest) | Forging tokens; stealing value | custody (ADR-26 point 4); `CheckedSigner`; permutation proofs; T2 |
| **+** | Custody secret (32 bytes); each `k_seal = HKDF-SHA256(custody_secret, "ghost/v1/key-seal" ‖ kind ‖ epoch)` | removable media of the offline machine only (runbook K1); the issuer receives a load file (`GHKL`) with the needed `k_seal` values at each key load (K3, every 2 weeks), never the secret | Opening every sealed key file | operational (air gap); `custody_window.rs` |
| **+** | Entitlement Schedule signing key (Ed25519) | offline; its public key is pinned in the native library per network; the schedule in `main` is stagenet seq 1, signed with a stagenet key generated outside the repository | Forging the schedule (prices, keys, relay slots) | custody discipline of the release key (assumption A7); gate `entitlement-schedule.sh` keeps key material out of the repository; the K1 ceremony with the real key is owed (KI-ISS-3) |
| **+** | Monero keys and issuer host secrets: the spend key; the view-only wallet and its password; the RPC logins of `monero-wallet-rpc` and `monerod` (digest authentication); the 32-byte `ops.key` seed (payout batch files, runbook P1); the key-load file | the spend key offline and air-gapped; the rest as Docker secrets of the issuer stack (`ghost/infra/issuer/docker-compose.stagenet.yml`), copied to a tmpfs in the container | Spend key: theft of funds; view key and logins: payment history, wallet RPC control | MS-5; runbook P1, I1 |
| **+** | Onion service keys of the issuer and of each relay | generated with `ghost-issuer-ops` or by the operator outside the repository; the schedule lists each relay's onion address per slot | Impersonating a service; a lost key means a new schedule | gate `entitlement-schedule.sh` refuses onion secret keys in the repository; runbook O1 |
| **+** | Relay secret `relay.key` (32 bytes) and the relay's `nullifiers.redb` and `keys.redb` | relay data directory | Forging capabilities, list cursors and redemption bindings; replay of redeemed tokens if `nullifiers.redb` is restored from an old backup (KI-RLY-2) | file permissions; startup refusals (`--nullifiers-reset`) |
| **+** | CI and runner credentials: the registration of four self-hosted runners; the `runner` user (passwordless `sudo`, Docker) | WSL2 distribution on the owner's laptop | Running code on the owner's machine (anyone who can push a branch) | none technical beyond not granting repository access to third parties (KI-SUP-3); no signing key, wallet or onion key is in CI (TB-6) |

### 1.2 Entry points and untrusted input

Every place where bytes from a party outside the trust boundary are parsed or acted on. "Fuzzed" means one of the six `dm-fuzz` targets (`EVIDENCE_INDEX.md` section 6); every other parser is covered by unit tests, vectors and negative fixtures only.

| Surface | Reachable by | Untrusted input and parsers on the path | Tier; tests |
|---|---|---|---|
| Relay gRPC over a Tor onion service: 7 RPCs (`StoreBlob`, `GetBlob`, `CheckBlobs`, `ListNamespace`, `RedeemToken`, `RegisterKey`, and `GossipSync`, which is off unless `--gossip`) | any Tor client that knows the onion address; no account | request messages (each carries `version`), capability headers (v1 82 B, v2 98 B, bearer v3 67 B), blobs of exactly 1/4/16/64 KiB treated as opaque, sealed list cursors, 354-byte tokens | C1, A4; `relay/crates/node/tests/*`, vectors `relay_semantics.txt`, `redeem.txt`, `register.txt`; not fuzzed |
| Issuer gRPC (loopback behind an onion service): 6 RPCs (`RequestInvoice`, `BlindSign`, `InvoiceStatus`, `RedeemInvite`, `ClaimPayout`, `RefreshCredit`) | any Tor client | blinded messages of fixed layout, claim hashes, invite and credit tokens, payout addresses (Monero address parser), invoice ids | C2, A3; `issuer/crates/service/tests/*`; not fuzzed |
| Issuer to `monero-wallet-rpc` and `monerod` (JSON-RPC, digest authentication) | the third-party Monero binaries and whatever sits between | JSON replies: transfers, subaddresses, heights | C2; `monero_rail.rs`, `monero_regtest.rs` |
| Operator tools `ghost-issuer-ops` | the operator | sealed key files (`GHKS`), key-load files (`GHKL`), the schedule, the journal, snapshots, payout batches: binary formats with magic and version | C2; `ops/tests/*` |
| Client: replies of relays and issuers (through the 22 network JNI entry points) | relays, issuers and anything on the Tor path | protobuf replies, the Entitlement Schedule (signed by the pinned key; permutation proofs), onion addresses (v3 checksum parser) | B1; `net/tests/*`, vector `onion_addresses.txt` |
| Client: DM blobs fetched from the user's inbox namespaces (4/16/64 KiB envelopes) | any holder of the user's contact card, and any relay | recognition hint, at most one AEAD open, canonical parse of the intro layer (X-Wing decapsulation, card v2, binding v3 signature), pair and provisional bodies, bundle v2, the L0 content codec and TLVs, Olm messages | A1, B1; **fuzzed:** `card`, `bundle`, `intro_inner`, `l0`, `tlvs`, `olm_message`; vectors |
| Client: out-of-band inputs | whoever the user scans or pastes from | contact card link or QR (`ghost://contact/…`, 131-byte card v2), invite link or QR (876 characters), BIP-39 words | A1, B2; `card` is fuzzed; `InviteTest`, BIP-39 vectors |
| Android components | other apps on the device | `MainActivity` (the only exported component, a placeholder), `SyncJobService` (not exported; bind permission), `ExpiryAlarmReceiver` (not exported, no intent filter), the `androidx.startup` provider (not exported; the EmojiCompat initializer is removed); no content provider; permissions `INTERNET`, `RECEIVE_BOOT_COMPLETED`, `ACCESS_NETWORK_STATE`; `allowBackup=false` | B4; `manifest-lint.sh`, `merged-manifest-lint.sh` |
| JNI boundary: 51 entry points (29 `DmNative`, 22 network) | the Kotlin layer only (closed list, gate G-R6), but attacker-controlled bytes pass through | handle registry, `catch_unwind`, constant error categories | B1; `dm-jni-surface.sh`, `jni_error_canaries.rs` |
| Local storage and restore | a local attacker with the device (AD-8); the user restoring from words | SQLCipher database, schema triggers, migrations, restore scan | B2; `storage/src/test` |
| Build and supply chain | anyone who can push a branch, or compromise a dependency or a download | Cargo and Gradle downloads, workflow files of pushed branches, the pinned Monero archives | D; section 5.3 |

### 1.3 Data flows

Five flows, in the order an auditor needs them. TB-n are the trust boundaries of section 6; every network hop is over Tor.

**F-1 Identity (device only; Phase 3).** (1) At first start 256 bits come from the OS CSPRNG (AS-1) and are wrapped by an Android Keystore key [TB-1]. (2) The 24 BIP-39 words are the recovery form (the screens that show and confirm them are Phase 13, not built); recovery re-derives everything from them. (3) HKDF-SHA256 branches `ghost/v1/*` derive the Ed25519 identity, the per-channel pseudonym seeds, the DM branch (Olm identity, card secrets) and the invite and credit derivations. (4) The SQLCipher key and the DM content key are Keystore-wrapped; the DM state key lives in native memory. Claims: T14, CP-03. Tier B2.

**F-2 DM first contact with an offline recipient (the one-scan flow, design `faza9-dm.md` §12.2).** (1) A scans B's contact card (QR in person gives `verified`, a pasted link gives `unverified`); nothing is sent. (2) A's first send keeps the message pending and fetches B's bundle from B's bundle namespace through B's relay set [TB-2]. (3) After a short wait (`EST-READY`), A pins B's Olm identity from the signed bundle, stores B's X-Wing key, builds the Olm initiator session, encrypts the message as an Olm PreKey message and seals it in **intro mode** (an X-Wing inner layer carrying A's card, the binding v3 signature and the `reply_seed`); the 4/16/64 KiB envelope is deposited into B's inbox namespace at B's relays [TB-2]. (4) B lists its own inbox namespaces on the fixed schedule, recognises the blob with one hint (at most one AEAD open), decapsulates, verifies binding v3; an unknown identity becomes a **request**; B's responder session exists. (5) If B accepts, B's reply is an Olm message sealed in **provisional mode** carrying B's `seal_root`; later messages are pair-sealed, and a PQ-C re-key follows at most every 4 weeks. Claims: T26 to T35; models M-1, M-2, M-3, M-6, M-7. Tier A1, B1, B3.

**F-3 DM send and receive in an established pair (`SEND` and `RECV`, design §7.3, §7.4).** Send: one database transaction guards the contact's trust state, encodes the L0 content with the conversation timer, inserts the message and an outbound item, runs the Olm encryption over the stored session envelope (the new state is written in the same transaction), chooses the seal mode and enqueues the sealed blob in the outbox with the TTL tier of the timer. After commit the sync engine deposits it at two or more relays of the recipient's relay set for the week [TB-2] with a bearer deposit credential; timeouts are resolved by `CHECK`. Receive: the sync engine lists the user's inbox namespaces on a schedule independent of activity and fetches new blobs; the actor orders them and processes each in its own transaction: mark consumed (exactly once), recognise (one hint, one AEAD), canonical parse, identity pre-check (a changed key is held), Olm decrypt with typed results, store, schedule the expiry. Nothing is sent in response to a received blob. Claims: T25, T28 to T31, T33. Tier A1, B3.

**F-4 Purchase to redeem (entitlement, Phase 8, design `faza8-issuer.md` §5.3, §10.2).** (1) The user prepares a purchase locally (claim key, seed, base week); nothing is sent. (2) In the next quiet run `RequestInvoice` goes to the issuer on a fresh isolation scope [TB-4]; the client checks the amount against the schedule's price and the Monero subaddress. (3) The user pays from an external Monero wallet [TB-5]; the issuer's view-only wallet observes the payment. (4) At planned times the client sends `BlindSign` with blinded messages derived from the seed; after the payment gate, range checks and the `CheckedSigner` fault check the issuer returns blind signatures, which the client unblinds, verifies with `ring` and stores as tokens. (5) To use a token the client calls `RedeemToken` on a relay on another scope [TB-2]; the relay verifies the token (schedule key, period, slot, RSA-PSS), records the nullifier durably and mints a deterministic write capability for the client's namespace, which `StoreBlob` then presents. Claims: T2, T22, T23; MS-1 to MS-8; P-1 to P-7. Tier A3, A4, C1, C2.

**F-5 Channels (planned; design `faza10-forum.md`, not on `main`).** (1) A creator makes an OpenMLS group (suite 0x0003); every MLS byte is sealed by GHOST before it reaches a relay, and channel namespaces rotate per generation. (2) Invitations are password-sealed (Argon2id) and lead to a Welcome. (3) Members post application messages and commits as sealed blobs; commit order is decided by a deterministic rule without a server (settle window, sticky merged epoch). (4) Readers list the channel namespaces with read capabilities. Claims: planned T36 to T41. Tier A2.

---

## 2. Component inventory

### 2.1 Method (reproducible)

* **Files**: `git ls-files` on the base commit, restricted to `ghost/` and `.github/` and to the source extensions `rs kt kts java proto sh pl pv yml yaml toml xml sql json patch ps1 bat pro properties`: 1,145 files, 247,042 physical lines (this includes the gate fixtures; the table below excludes them).
* **Lines**: `wc -l` (physical lines; comments and blank lines included; all tracked text is LF-normalised by `.gitattributes`, so `wc -l` counts every line). The non-blank count (`grep -c -v '^[[:space:]]*$'`) is about 6 % lower for the Rust `src/` of the shipped crates and about 10 % lower for Kotlin `src/main` (4 to 13 % per module); both are in the script's output.
* **"Production" Rust** = every file under `src/` of a shipped or deployed crate **minus its test-only code**: items gated by `#[cfg(test)]` or by the features `test-vectors`, `pq-spy` or `clippy-fixture` (test and fixture features that no shipped build enables). The rule is mechanical, not by hand: an item runs from its attribute line to its closing brace at the same indentation (rustfmt layout, enforced by `cargo fmt --check`) or to its terminating `;`, and a `#[cfg(test)] mod x;` makes the whole file `x.rs` test-only. So it removes inline test modules wherever they sit in a file, the whole files `pq_bump.rs`, `property.rs` and `equivalence.rs` of `ghost-client-dm` and `loopback.rs` and `clippy_fixture.rs` of `ghost-client-net`, the `hooks`, `spy`, `gate` and `fixtures` modules, and small gated functions and statements; it keeps the production alternative of a gated function (`#[cfg(not(…))]`). `ghost-dm-host` (35 lines, a test-only library) is in no total. Integration tests (`tests/`), `examples/` and `fuzz/` are counted separately. The first version of this package subtracted only the trailing `mod tests` block of each file and so counted about 2,900 test-only lines as production (36,407 instead of 33,503 Rust lines, and 12,308 instead of 9,578 for `ghost-client-dm`).
* **"Production" Kotlin** = `src/main` (39,712 lines in 203 files) plus `src/release` (24 lines in 1 file, `DmBranch.kt` of `:app`, compiled into the release APK) = **39,736 lines in 204 files**. `src/debug` (16 lines), `src/gate` (gate devices only), `androidTest`, `deviceRunner`, `equivalence` and `testShared` are not in the release APK; they are counted as "other source sets" (1,798 lines in 12 files), not as production.
* The measurement script is `docs/audit/tools/measure.sh`, reproduced in Appendix A (about 100 lines of bash and awk) with its result lines; `docs/audit/tools/check-package.sh` re-runs it and fails if a number in this package no longer matches. Nothing was measured in a build; no generated code is tracked (the proto code is generated at build time by `build.rs`).
* Upstream crates' sizes quoted in section 3.3 were measured the same way on the crate sources in the local cargo registry (`~/.cargo/registry/src/*/<crate>/src`, all `*.rs`, inline tests included).

### 2.2 Components that ship or are deployed

Sizes are physical lines at the base commit. "Prod" = production lines (definition above); "src" = all `src/` lines including inline tests; "tests" = `tests/` integration tests of the crate (Rust) or `src/test` (Kotlin).

| ID | Component | Path | Lang | Prod / src lines (files) | Tests lines | Purpose and trust role |
|---|---|---|---|---|---|---|
| R1 | Relay | `ghost/relay/crates/{api,storage,capability,transport,gossip,prune,node}` | Rust | 4,387 / 6,217 (15) | 4,927 (10) | Blind blob store over redb: bucket sizes 1/4/16/64 KiB, exact TTL tiers, HMAC capabilities (v1 82 B, v2 98 B), bearer credentials v3 (67 B) with hash-registered verifiers, `RedeemToken` with persisted nullifiers, `RegisterKey`, sealed list cursors, capture mode for T1. Internet-facing as a Tor onion service, run by operators. gRPC with 7 RPCs (`protocol/relay/v1/relay.proto`, 167 lines). Binary `ghost-relay`. |
| R2a | Issuer: blind-RSA and entitlement formats | `ghost/issuer/crates/{blind-rsa,entitlement,api}` | Rust | 2,733 / 3,249 (12) | 2,026 (12) | Public-side RFC 9474 arithmetic (EMSA-PSS, blinding, finalisation, `ring` verification, permutation proofs), Privacy Pass type 0x0002 tokens, nullifiers, the Entitlement Schedule (ES), seed-derived batches, Monero address parsing. **Also linked into the client library and the relay** (verification side). |
| R2b | Issuer service | `ghost/issuer/crates/service` | Rust | 9,456 / 9,785 (22) | 27,124 (53) | Payment-gated blind signing (`blind-rsa-signatures =0.17.2` on pre-release `rsa 0.10.0-rc.18`, wrapped by `CheckedSigner`), redb store plus append-only `issued.journal`, Monero view-only wallet adapter (JSON-RPC, digest auth), referral credits, payout batches, gRPC server on loopback behind an onion service (6 RPCs, `protocol/issuer/v1/issuer.proto`). Money and anonymity critical. |
| R2c | Issuer operator tools | `ghost/issuer/crates/ops` | Rust | 3,559 / 3,940 (21) | 3,714 (10) | Offline: key ceremony (K1) and key-load tooling that call the sealed key file format implemented in R2b (`service/src/custody.rs`: GHKS/GHKL, `ring` ChaCha20-Poly1305), ES signing and verification, journal pruning, payout tools, reconciliation. |
| R3 | Client network core | `ghost/client-core/net` (crate `ghost-client-net`, cdylib) | Rust | 3,790 / 6,538 (13, of which 2 wholly test-only) | 3,339 (8) + 380 examples | Arti (Tor) onion-only transport with per-scope circuit isolation, vanguards-lite, relay and issuer clients, entitlement crypto for the client, JNI network surface (22 `external fun` in 3 Kotlin classes), handle registry with `catch_unwind`. Links `ghost-client-dm`; this is `libghost_client_net.so`. |
| R4 | DM cryptography | `ghost/client-core/dm` (crate `ghost-client-dm`, rlib) | Rust | 9,578 / 17,724 (26, of which 3 wholly test-only) | 4,867 (8) + fuzz 771 (7) + 241 example | Derivations, contact card v2, four-mode sealed-sender envelope (pair, intro with X-Wing inner layer, provisional, bundle), binding v3, L0 codec, Olm facade over vodozemac 0.11.0 (including GHOST's pickle-layout deviation and session-selection rules), PQ-C root re-key, safety numbers, revocation certificates, state wrapping. Closed JNI surface `DmNative`: **29 entry points** (`#![forbid(unsafe_code)]` in this crate; the `#[no_mangle] extern "system"` exports are emitted by its `export_jni!` macro into the crate that invokes it, `ghost-client-net`). |
| R5 | DM host test library | `ghost/client-core/dm-host` | Rust | 35 (in no total) | n/a | Test-only `cdylib` so JVM tests call the real Rust crate; never shipped (G-R2/G-R6 enforce it). Exports the 29 `DmNative` entry points through the same macro and four extra test symbols (`DmEquivalence.run`, `bindingHooks`, `stateWrapHook`, `sidecarLogHook`). |
| K1 | `:identity` | `ghost/android/identity` | Kotlin | 3,290 (15) | 1,172 (9) | Entropy, BIP-39 (24 words, own implementation and wordlist), HKDF-SHA256 branches, Ed25519 identity (BouncyCastle), per-channel pseudonym derivation, signed invites, revocation certificates, Keystore wrapper (AES-256-GCM, StrongBox then TEE), drop sealing (X25519 + ChaCha20-Poly1305). |
| K2 | `:storage` | `ghost/android/storage` | Kotlin | 1,883 (7) | 7,825 (23) + 203 shared | SQLCipher 4.19.0 over `sqlcipher-android`, schema v1-v5 with triggers enforcing state machines, transactional migration runner (fail-closed downgrade), DB key wrapped by Keystore, repositories. |
| K3 | `:sync` | `ghost/android/sync` | Kotlin | 8,645 (62) | 15,163 (64) | Exactly-once outbox/inbox engine: per-(relay, namespace) schedules, opaque cursors, capability and relay directory stores, JobScheduler job plus foreground session, consumer API for DMs and channels. |
| K4 | `:entitlement` | `ghost/android/entitlement` | Kotlin | 4,767 (44) | 9,158 (34) | Client of the issuer: purchases, trial, token redemption, credits and refresh, drops, payout claims, quiet runs (1 in 8 background runs contacts the issuer instead of relays). |
| K5 | `:messaging` | `ghost/android/messaging` | Kotlin | 15,309 (48) | 36,046 (79) + 705 device | DM engine: single-writer actor, passes RECV/HELD/SEND/OUTCOME/SWEEP/KEEPER/OWNER-WEEK, establishment, key change, ephemeral deletion, expiry alarm, stores, `ContentCipher`. |
| K6 | `:crypto-bridge` | `ghost/android/crypto-bridge` | Kotlin | 3,674 (14) | 3,072 (12) + 395 device | The JNI wrapper `DmNative` (29 `external fun`), result codec, `DmFacade`, credential v3, relay-set order, recognition hints. |
| K7 | `:network` | `ghost/android/network` | Kotlin | 1,264 (6) | 682 (4) | Native library loader, onion address parsing (v3 checksum), JNI declarations of the relay, issuer and entitlement transports. |
| K8 | `:app` | `ghost/android/app` | Kotlin | 880 (7) + 24 release (1) | 1,312 (6) + 479 device | Application class, wiring of the engines, manifest (permissions allowlist), `MainActivity` placeholder (no UI before Phase 13), R8 rules. |
| K9 | `:media` | `ghost/android/media` | n/a | 0 | 0 | Empty (Phase 11 not built). |

**Totals (shipped or deployed code; `ghost-dm-host` is in none of them):** Rust production **33,503** lines in 104 source files (47,453 `src/` lines in 109 files, of which 13,950 lines are test-only code; 45,997 lines of integration tests in 101 files); Kotlin production **39,736** lines in 204 files (`src/main` plus `src/release`); together **73,239** production lines. Kotlin unit tests 74,430 lines in 231 files; other Kotlin source sets (androidTest, debug, device, gate, shared) 1,798 lines in 12 files. Test code (Kotlin unit tests, Rust integration tests and Rust test-only code, together 134,377 lines) is about **1.8 times** the production code, which matters for the effort of a review: the auditor is not expected to review tests line by line, only to judge whether they establish the claims in section 7.

### 2.3 Supporting artifacts that carry claims or evidence

| Artifact | Path | Size | Role |
|---|---|---|---|
| Wire schemas | `ghost/protocol/{relay,issuer}/v1/*.proto` | 322 lines | Normative RPC schemas; every request message must carry `uint32 version = 1` (gate `proto-check.sh`). |
| Test vectors | `ghost/protocol/test-vectors/*.txt` | 15 files, 2,777 lines | Shared conformance vectors replayed by Rust and by Kotlin models (relay semantics, redeem, register, ES, issuer semantics, DM derive/seal/bundle/content/equivalence, RFC 9474 blind-RSA, Monero and onion addresses). |
| ProVerif models | `ghost/protocol/models/dm/*.pv` + `expected.txt` | 4 models (506 lines) + 4 mutant patches (8 models, 48 queries in the CI run) | M-1/M-3 (HNDL secrecy, PQ-B), M-2 (binding v3), M-6 step (3) (PQ-C healing), M-7 structure (erasure). Not modelled: M-4, M-5, M-8. |
| Privacy harness | `ghost/test-harness/privacy` | 5,723 lines Rust src (capture-check, `ghost-t2-join`), INVARIANTS.md | T1 validator and fixtures; the T2 join analyser. The worlds themselves are in `issuer/crates/service/tests/t2/` (Rust) and `android/messaging/src/test/.../dmworld`, `entworld` (Kotlin). |
| Gates | `ghost/scripts/gates` | 44 shell + 2 perl scripts (8,768 lines), 59 fixture roots (735 files) in `ghost/test-harness/gates` | Static and build gates with negative fixtures; `self-test.sh` proves each gate rejects its fixtures. |
| CI | `.github/workflows` | 13 workflows (2,217 lines) | Run on four self-hosted runners in a WSL2 distro on the owner's laptop (`docs/ci-self-hosted.md`). |
| Deployment | `ghost/infra/{relay,issuer}` | 713 lines (Dockerfiles, torrc, compose files, entrypoints, configuration, the Monero pin file) plus `RUNBOOK.md` (883 lines) | Staging/stagenet definition and the issuer operations runbook (K1-K4 keys, B1 backups, M2 Monero hard fork, O1 relay operators, P1 payouts, R2 reconciliation, I1 compromise). |
| Notices and licences | `ghost/licenses` | 4 generated notices files | Third-party notices per shipped graph: 455 Rust components in the client library, 113 in the relay, 136 in the issuer, 66 JVM libraries in the APK. |
| Design and decision records | `docs/` | ~19,000 lines of design (7 phase designs), 36 ADR files, 3 reviews, plan, threat model, limits, status | See `BUILD_AND_REVIEW_GUIDE.md` section 5 for a reading order. |

### 2.4 Not on `main` (planned, in progress or absent)

| Item | State | Indicative size (inferred) |
|---|---|---|
| `ghost-client-mls` (OpenMLS 0.9.0 with libcrux provider, storage adapter, seal, commit arbitration, JNI `MlsNative`) | Unmerged branch `p10-s2b` (read at `3abbeb9`, 2026-10-04 02:46 +0300; it was `91d7fec` on 2026-10-03): `ghost/client-core/mls` is +13,585 source lines in 17 files and +4,560 lines of tests in 9 files (`git diff --numstat main p10-s2b -- ghost/client-core/mls`; work in progress, not final, and the figure moves with every push to the branch). | 13,600 Rust lines before the remaining slices |
| Kotlin channel engine, schema migrations 6-7 | Design only (`faza10-forum.md` §9-§10, slices S3-S12); migration 6 and `Funding` on branch `p10-s1a`. | Unknown; Phase 9's `:messaging` is 15,309 lines |
| Media pipeline, UI, updater and release signing, Phase 12 hardening | Designs `faza11-media.md`, `faza13-ux.md`, `faza14-distribution.md` (proposed); Phase 12 not started. | Unknown |

The RFQ therefore asks for a **scope freeze date** and prices components that do not exist yet as options.

---

## 3. In scope and out of scope, with reasons

### 3.1 Scope tiers (identical to the RFQ)

| Tier | Name | Components |
|---|---|---|
| **A** | Cryptographic composition and protocols | A1 DM composition (R4, design `faza9-dm.md` §2-§10, §22; ADR-30'-36; ProVerif models); A2 MLS channels (planned: `ghost-client-mls`, storage adapter, commit arbitration, seal, generations, password-sealed invites; design `faza10-forum.md` §3.7, §5, §6, §19); A3 entitlement cryptography (R2a, R2b signing path, ES, permutation proofs, deterministic blinding, nullifiers; design `faza8-issuer.md` §2-§3, §5, §10; ADR-22-25); A4 relay authorisation scheme and metadata claims (capabilities, credentials v3, `RegisterKey`, list cursors; T1; design `faza9-dm.md` §4); A5 optional: independent review of the threat model and claims register (closes Phase 2's open gate) and of the metadata capture (Phase 12's gate). |
| **B** | Android client including the native boundary | B1 JNI and native boundary (R3, R4, K6, K7: closed surfaces, handle registry, panic containment, zeroisation, memory residue); B2 key management and storage (K1, K2: BIP-39, HKDF, Keystore wrapper, SQLCipher integration, schema triggers, migrations, wipe); B3 engines (K3, K4, K5: crash consistency, exactly-once contracts, ephemeral deletion, key change, quiet runs, resource and time discipline); B4 platform hardening (K8: manifest and permissions, R8, backup/extraction rules, alarm and job residues, notifications, clipboard and screen protection once Phase 13 exists); B5 dynamic testing on physical devices and emulator (never done so far); B6 UI security (when Phase 13 exists). |
| **C** | Relay and issuer services | C1 relay (R1: authorisation, quota, redemption, registration, TTL and cursors, DoS and resource exhaustion, onion-service configuration); C2 issuer (R2b, R2c: money safety MS-1 to MS-8, journal and snapshot restore, Monero rail, payout flow, key custody, reconciliation, signer timing); C3 infrastructure and runbooks (`ghost/infra/**`: containers, Tor config, key ceremonies, operator procedures); C4 abuse and load behaviour of both services. |
| **D** | Supply chain and build | D1 dependency governance (cargo-deny, `rust-crypto-pins`, feature policy, allowlists, Gradle verification, notices); D2 build reproducibility (T12 same-path; T12b auditor build once Phase 14's fixed-path builder exists); D3 CI/CD security (self-hosted runners, workflow trust, secrets handling, action pinning); D4 release signing and distribution (Phase 14: offline keys, manifest, transparency log, updater; when it exists); D5 licensing gates are **not** a security audit item (listed for completeness). |

### 3.2 In scope

* All first-party code and configuration in the tables of section 2.2 and 2.3 that ships, is deployed or underpins a claim, at the frozen tag.
* **How third-party code is selected, pinned, configured and used**: vodozemac 0.11.0 usage and the recorded pickle-layout deviation (assumption A1); libcrux X-Wing/ML-KEM usage (`libcrux-kem` 0.0.9 through the slice trait with explicit `validate_public_key`, portable-only build, gate G-R3); OpenMLS configuration (planned); Arti configuration (onion-service client, vanguards-lite, bridges simple); `blind-rsa-signatures`/`rsa` pre-release usage and the RUSTSEC-2023-0071 exception; SQLCipher and Keystore integration; BouncyCastle usage.
* The design documents as the specification against which the code is reviewed (every module-to-section pointer is in `BUILD_AND_REVIEW_GUIDE.md` section 6).
* The **CP-09 exceptions**: spec CP-09 requires "maintained, reviewed libraries and standard constructions. Exceptions require an ADR and external review". The GHOST-built constructions recorded as exceptions (ADR-31', ADR-33', the session-selection and pickle rules of ADR-35, ADR-36's composition) are exactly what Tier A1 reviews; this audit is the "external review" those ADRs name (design `faza9-dm.md` §9.5, Q57, ADR-38 point 3).
* The claims register (section 7): the auditor is invited to try to falsify each row.

### 3.3 Out of scope, and why

| Item | Why it is out | What stays in scope about it |
|---|---|---|
| `legacy/` (80 files: simulated prototypes in quarantine) | Not built, not shipped, known to be non-functional (plan §1). | Nothing. |
| Upstream source of vodozemac (14,452 lines in `src`), libcrux (`libcrux-ml-kem` 20,563; `libcrux-kem` 1,111), OpenMLS (86,295 lines in the `openmls` crate, plus traits/provider/storage), hpke-rs, Arti (`arti-client` 7,196 + `tor-proto` 50,757, 36 `tor-*` crates in the lock), redb (31,918), ring, rustls, RustCrypto crates, SQLCipher, BouncyCastle, AndroidX, Kotlin stdlib | Separate projects with their own audits or reviews (below); the 633 third-party Rust packages in the lock (651 with GHOST's own 18; shipped graphs: client library 455, relay 113, issuer 136 components) cannot be source-audited inside the plan's 6-8 weeks. Line counts measured on the registry sources, inline tests included (inferred as upper bounds of production code). | Version choice, pin enforcement, configuration, call sites, error handling, and any upstream defect the auditor happens to find (to be reported upstream with the owner's consent, RFQ B6). |
| Monero (`monerod`, `monero-wallet-rpc` v0.18.5.1, pinned by SHA-256 in `infra/issuer/monero-release.pin`) and the Monero network | Third-party binaries; chain privacy is Monero's, not GHOST's (LIMITE E7). | RPC usage, view-only wallet set-up, the payout flow with an air-gapped signer, digest authentication (MD5 only, an upstream limitation), reconciliation. |
| Tor network, Arti internals, Android OS, StrongBox/TEE firmware, OEM behaviour | Not controlled by the project. | Use of their APIs and the assumptions A2, A3. |
| `ghost/client-core/mls-spike` (own workspace, evidence probes) | Not shipped. | May be read as evidence for the Phase 10 design. |
| `ghost/test-harness/**` test code and fixtures | Test tooling, not shipped. | The auditor may sample the oracles of T1, T2 and T32 to judge whether they can fail (each has mutants that must be detected). |
| Operator organisational security (physical custody of the spend key, key-ceremony conduct, laptop hosting the CI runners) | Not code. | The runbooks as written (`infra/issuer/RUNBOOK.md`), and the CI trust model (D3). |
| Usability studies, legal compliance (licences, payments law, Monero regulation), NFR performance measurement, load testing at scale | Different disciplines; plan rows 12, 13 and 16 own most of them. **One measurement belongs to Phase 15 itself:** ADR-18 assigns the NFR-3 measurement (at least 1,000 blobs per second per relay node on redb, with RocksDB as the recorded fallback) to Phase 15. It has not been done (`KNOWN_ISSUES.md` KI-RLY-5). A storage-engine change after the audit would void the relay review (C1), so the project should measure before the freeze; it is not an auditor task. | Abuse and resource-exhaustion behaviour of the services (C4). |
| Prior public audits of third parties (listed in `EVIDENCE_INDEX.md` section 9) | Re-auditing would duplicate them. | Whether their scope covers GHOST's configuration and versions. For example the OpenMLS audit by SRLabs excluded the crypto and storage providers and the PQ suites (per design `faza10-forum.md` §3.1, §3.7). |

---

## 4. Risk-ranked priority list (what to do in the first weeks)

Ranking is the preparer's judgement **(inferred)** from the facts cited; the auditor should re-rank after a first read. "Why" gives the evidence; "First activities" is a suggestion.

| Rank | Area (tier) | Why it ranks here | Where | First activities |
|---|---|---|---|---|
| 1 | **DM cryptographic composition** (A1, B1) | GHOST-designed constructions that replace libsignal after the owner excluded AGPL code (ADR-35/36/37): four-mode sealed-sender envelope, binding v3, provisional mode, PQ-B transport invariant, PQ-C re-key, session selection (at most two sessions per contact), an encoder/reader of vodozemac's undocumented serde pickle (assumption A1), dehydrated-device account derivation. No independent assessment of the composition exists: the only formal results are the project's own ProVerif models for M-1, M-2, M-3, M-6 step (3) and M-7 structure; **M-4 is an unwritten argument, M-5 has no model**; the internal reviews are by AI agents (3 documents). The phase review found a third instance of the "non-canonical encoding of a peer X25519 value" class (CRY-P9-01) and memory-residue defects (CRY-P9-02, -04); vodozemac fixed the non-contributory-DH class itself in 0.10.0 after a public disclosure in February 2026. Upstream libraries are young or contested: vodozemac audited in 2022 (code since then unaudited), libcrux "pre-verification" with public vulnerability reports in 2026 (see `EVIDENCE_INDEX.md` section 9). | `ghost/client-core/dm/src` (R4), `android/crypto-bridge`, design `faza9-dm.md` §2-§10 and §22, `protocol/models/dm` | Read §22 (precedence over §0-§21); rebuild the key schedule on paper from `derive.rs` against §3, §5, §6; review `seal.rs`, `binding.rs`, `bundle.rs`, `olm/*` and `pqroot.rs`; attack canonicality of every peer-supplied public value; review state wrapping and context registry (`jni.rs`, `wrap.rs`); run and extend the fuzz targets; check the ProVerif models against the code. |
| 2 | **MLS channels** (A2) once merged | Highest design novelty after DMs: commit ordering without a server (settle windows, deterministic winner, sticky merged epoch), generation-rotating namespaces, committer anchors for Welcomes, a storage adapter with value semantics around OpenMLS (answering SRLabs finding S1-3), canonical KeyPackages, password-sealed invites with Argon2id. Design reviewed in rounds 10a-10e (about 100 findings and corrections in all, many re-run with probes: `EVIDENCE_INDEX.md` section 8); several accepted residues (forks detectable only out of band, L8-C17/L8-C25; classical suite only). No code on `main`. | planned `client-core/mls`, `faza10-forum.md` §3-§6, §19 | Needs the code; until then review §19.27-§19.29 (rounds 10d/10e) and the probes in `mls-spike/core/tests`. |
| 3 | **Entitlement cryptography and the issuer money path** (A3, C2) | Anonymity and money in one service. RFC 9474 implemented as a split design (public side on `num-bigint-dig`/`ring`, signing side on a pre-release RSA stack, `rsa 0.10.0-rc.18` with a cargo-deny exception for RUSTSEC-2023-0071 argued in `deny.toml`), permutation proofs of keys, seed-derived deterministic blinding, an offline-signed append-only ES, 8 money-safety and 7 privacy guarantees (F8 MS-1..MS-8, P-1..P-7), 34 declared residues (E1-E34). Marked for Phase 15 by the Phase 8 review ("reverify the refresh budget E34 and the timing evidence of signing"). T2's ten-pair nightly sweep has never been green according to the design record (`faza9-dm.md` §22.24 item 9; on 2026-10-03, 3 of 10 pairs were red, `EVIDENCE_INDEX.md` section 3). | `issuer/crates/{blind-rsa,entitlement,service,ops}`, design `faza8-issuer.md` §2-§3, §5-§7, §9, §19, `infra/issuer/RUNBOOK.md` | Verify RFC 9474/9578 conformance independently (vectors exist: `rfc9474_vectors.rs`, `rfc9578_vectors.rs`); review `CheckedSigner`, fault checks, reply quantum, signer timing test; journal/snapshot restore (`journal_*.rs`, B1 runbook); payout and Monero adapters; key custody (GHKS/GHKL). |
| 4 | **Relay authorisation and metadata discipline** (A4, C1) | Internet-facing, run by third parties, and the enforcement point for T1/T9/T27-T31: capabilities, credentials v3 with hash-registered verifiers, quotas in memory (E29), nullifier persistence, list cursor sealing (Feistel over HMAC-SHA256), exact TTL tiers. Everything a relay can observe is normative in `allowed-observables.json` (v2) and checked on every PR. | `ghost/relay/crates`, `protocol/relay/v1/relay.proto`, `allowed-observables.json`, design `faza8-issuer.md` §10, `faza9-dm.md` §4, ADR-25/30' | Review capability and credential verification (constant-time comparison, scope binding), `RegisterKey` accumulation rules, idempotent redemption (`redeem.rs`), resource limits (batch caps 256, bucket checks), startup refusals (`--nullifiers-reset`). |
| 5 | **Crash consistency of the Kotlin engines** (B3) | About 29,000 production lines of state machines (`:sync` 8,645; `:entitlement` 4,767; `:messaging` 15,309) whose contracts (OUT-1..4, IN-1..3, MS-6, ENG-*) are enforced by SQL triggers and proven mostly in a JVM model with **plain SQLite (sqlite-jdbc), not SQLCipher**, a model relay and no device runs. The Phase 9 whole-phase review found 8 engine defects in `:messaging` alone (ENG-1..ENG-8; seven fixed, ENG-6 fixed in part); across all five lenses it confirmed 32 findings, of which 21 were fixed, 3 fixed in part and 8 left to the owner (`KNOWN_ISSUES.md` section 2). | `android/{sync,entitlement,messaging,storage}` | Compare the JVM model's assumptions with SQLCipher/Android (WAL, `secure_delete`, `synchronous = FULL`, Doze, process death); review triggers in `Schema.kt`; review the actor's catch-all policy; read the exhaustive crash harnesses to see what they cannot reach. |
| 6 | **Native boundary and Tor client use** (B1, A4) | One native library with 51 JNI entry points (29 DM + 22 network) and 455 third-party Rust components behind it (the shipped graph for the two Android targets, `ghost/licenses/THIRD_PARTY_NOTICES-client-net.txt`); GHOST's own Rust has zero `unsafe` tokens (grep over production sources; the workspace is edition 2021, so the `#[no_mangle] extern "system"` JNI exports, 22 written out in `ghost-client-net` and 29 emitted by the DM crate's `export_jni!` macro, are not flagged by that grep, and `ghost-client-net` carries no `forbid(unsafe_code)`) but depends on `jni`, Arti and libcrux; handle lifetime was the top finding of the Phase 6 review. | `client-core/net/src`, `android/network`, `scripts/gates/dm-jni-surface.sh` | Review handle registry and cancellation, panic containment (`catch_unwind`, silent panic hook, unwinding kept), error categories (20 constant strings), onion-only API surface (`compile_fail` doctest, clippy bans), isolation scopes. |
| 7 | **Android platform and key management** (B2, B4) | Root secrets and the DB key live here; the SQLCipher file is in `databases/`, not `no_backup/` (SQLCipher 4.19.0 ignores the request; backup exclusion relies on manifest and extraction rules); wipe and lock flows have no caller until Phase 13; Keystore wrappers have only been exercised on the emulator's software Keystore. | `android/{identity,storage,app}`, manifests, `data_extraction_rules.xml` | Review derivation and wrapping, authentication binding policy, backup rules, R8 output (release APK strips the DM facade today), manifest lint output; test on real hardware. |
| 8 | **Supply chain, CI and release** (D1-D4) | Closed source makes the vendor an adversary (AD-V); the CI runs on the owner's laptop and executes whatever workflow a pushed branch contains; Gradle verification trusts all POM/module files and the Linux `aapt2` (review GATES-5); commits are unsigned; reproducibility only same-path; Phase 14's builder, log and updater do not exist. | `.github/workflows`, `ghost/scripts/gates`, `ghost/android/gradle/verification-metadata.xml`, `deny.toml` | Review pin policy and its gates' evasion resistance (text gates have declared blind spots, design `faza9-dm.md` §22.33 item 16); reproduce the build in a clean environment; review runner trust. |

**Time-boxing hint (inferred):** ranks 1-3 deserve deep, line-by-line review by cryptographers; ranks 4-7 standard security code review plus targeted dynamic testing; rank 8 a sampled review plus an independent clean-room rebuild.

---

## 5. Cryptographic inventory

Sources: `ghost/Cargo.lock` (651 packages), `ghost/Cargo.toml` and crate manifests, `ghost/deny.toml`, `ghost/scripts/gates/rust-crypto-pins.txt`, `ghost/android/gradle/libs.versions.toml`, `ghost/android/gradle/verification-metadata.xml` (332 components), `ghost/licenses/THIRD_PARTY_NOTICES-*.txt`, Kotlin sources (`grep` of `javax.crypto`, `java.security`, `org.bouncycastle`). Versions are exact lock values at the base commit.

### 5.1 Protocols and compositions built by GHOST (CP-09 exceptions; review targets)

| # | Construction | Built from | Spec | Notes |
|---|---|---|---|---|
| X1 | **DM sealed-sender envelope, four modes** (pair, intro, provisional, bundle): `salt(16) ‖ hint(16) ‖ ChaCha20-Poly1305(k, 0¹², AD, padded plaintext)`, buckets 4/16/64 KiB, keys derived with HKDF-SHA256 from card secrets, pair roots or X-Wing secrets | RustCrypto `chacha20poly1305 0.11.0`, `hkdf 0.13.0`, `hmac 0.13.0`, `sha2 0.11.0` | `faza9-dm.md` §6, ADR-31' | Rule V1: access control on relays protects nothing against relays; every stored byte is sealed under keys never presented to a relay. |
| X2 | **Binding v3**: Ed25519 signature by the sender's identity over (OI_A, base key, X-Wing ciphertext, namespace, minute, OI_B) | `ed25519-dalek 2.2.0` | §3.4, §6, ADR-33' | Provable by the recipient to a third party (L7-D20); KCI-hardened; model M-2. |
| X3 | **Contact card v2, bundle, derivations**: `ghost/v1/dm/*` labels, typed key inputs (Rust gate `every_derive_function_is_enumerated…`, Kotlin allowlist gate G-DM3) | HKDF-SHA256, HMAC-SHA256 | §3, §5 | Vectors `dm_derive.txt`, `dm_bundle.txt`; seed-derived Olm identity (Q13). |
| X4 | **X-Wing intro layer (PQ-A/PQ-B)**: `libcrux_kem::XWing` (draft-06, wire-identical to draft-10) over ML-KEM-768 + X25519 + SHA3-256; invariant: every symmetric key sealing relay-stored bytes is card-derived, X-Wing-derived or transported only under such keys | `libcrux-kem 0.0.9`, `libcrux-ml-kem 0.0.10`, `libcrux-curve25519 0.0.8`, `libcrux-sha3 0.0.10`, `libcrux-traits 0.0.8`, `libcrux-hacl-rs 0.0.5`, `libcrux-intrinsics 0.0.8`, `libcrux-secrets 0.0.6`, `hax-lib 0.3.7` | §9.2-§9.3, ADR-36 | Portable-only build enforced (G-R3); `validate_public_key` called explicitly; differential test against RustCrypto `x-wing 0.1.0` (dev only). Model M-1/M-3; T35. |
| X5 | **PQ-C root re-key**: `HKDF-SHA256(root_rand ‖ ss, salt = SHA-256(label ‖ OI_me ‖ OI_c ‖ gen ‖ Q_c ‖ ct))`, at most every 4 weeks | as X4 | §9.4 | Model M-6 step (3) only; healing latency measured by a world, not proven. |
| X6 | **Olm sessions** (3DH, double ratchet; AES-256-CBC with 8-byte truncated HMAC-SHA256 MAC, "V1") through vodozemac's public API, plus GHOST's rules: at most two sessions per contact, R-SS0..R-SS5 selection, 12-minute gap hold, skipped-key age prune at 51 days via a **pinned-schema edit of the serde pickle**, MSC3814 dehydrated-device encoder | `vodozemac 0.11.0`, `matrix-pickle 0.2.3`, `aes 0.9.3`, dalek 5/3/3 majors | §2.1, §7.7-§7.9, §8, ADR-35 | Assumption A1 and its declared deviation (reads and writes the pickle format); golden pickles and `UpgradeTest` guard the pin. |
| X7 | **State wrapping**: session state and secrets wrapped under a state key held in native memory; content under a separate Keystore-wrapped content key (`nonce(12) ‖ ChaCha20-Poly1305(AD = row key)`) | `wrap.rs`; Kotlin `ContentCipher` using the platform `ChaCha20-Poly1305` (API 28+; minSdk 29) | §2.5, §13.8 | `Zeroizing` buffers; Kotlin cannot erase `SecretKeySpec` clones (Phase 9 review item A-1). |
| X8 | **Safety number, key change, revocation certificate v2** | SHA-256 based, Ed25519 | §8 | Vectors `dm_safety_number.txt`. |
| X9 | **Entitlement tokens**: Privacy Pass type 0x0002 (RFC 9578) with RSABSSA-SHA384-PSS-Deterministic (RFC 9474), RSA-2048, one key per (kind, epoch) in an **offline Ed25519-signed, append-only Entitlement Schedule**; key well-formedness by permutation proof (8 e-th roots, soundness about 2^-128); nullifier = SHA-256(label ‖ token input); seed-derived deterministic blinding (HKDF, r by rejection sampling) | `ring 0.17.14` (RSA-PSS verification, ChaCha20-Poly1305 for sealed key files), `num-bigint-dig 0.8.6`, `sha2`, `ed25519-dalek 2.2.0`; **issuer only:** `blind-rsa-signatures 0.17.2`, `rsa 0.10.0-rc.18`, `crypto-bigint 0.7.5` | `faza8-issuer.md` §2-§3, ADR-22 | RFC vectors replayed (2048 and 4096-bit); signer timing test (Welch) nightly; client/relay graph keeps `rsa 0.9.10` only inside Arti. |
| X10 | **Relay authorisation**: capability v1/v2 = HMAC-SHA256 tags over scope, quota and expiry (v2 adds a 16-byte deterministic serial); bearer credential v3 (67 B) verified against `SHA-256(label ‖ slot ‖ namespace ‖ secret)` registered by `RegisterKey`; list cursor = 64-bit Feistel over HMAC-SHA256 keyed by the relay | `hmac`, `sha2`, `rand` | `faza8-issuer.md` §10, `faza9-dm.md` §4, ADR-25/30' | Constant-time comparison claim (design assumption A15 of `faza9-dm.md`). |
| X11 | **Drop sealing** of referral credits: X25519 + HKDF + ChaCha20-Poly1305 | BouncyCastle 1.85.2 + platform HMAC | `faza8-issuer.md` §9, §19.12, ADR-24 | Deviation X15 (BouncyCastle beyond Ed25519). |
| X12 | **Identity**: 256-bit entropy, BIP-39 24 words, HKDF-SHA256 (RFC 5869) branches (`ghost/v1/*`), Ed25519 from seed (ADR-17), per-channel pseudonym seeds, signed invites (replay/expiry) | BouncyCastle `Ed25519Signer`, platform `HmacSHA256` | spec §7, ADR-04/17 | Trezor BIP-39 vectors and RFC 5869 vectors in tests. |
| X13 | **Local encryption at rest**: SQLCipher 4 (`net.zetetic:sqlcipher-android:4.19.0`, `androidx.sqlite 2.7.1`), key wrapped by an AES-256-GCM Android Keystore key (StrongBox when available, else TEE), `cipher_memory_security = ON`, `secure_delete`, `synchronous = FULL`, `foreign_keys` | platform | `docs/STATUS.md` Phase 4 row, ADR-14, design `faza9-dm.md` §22.32 item 5 | Real SQLCipher exercised only on the emulator (DM suites). |
| X14 | **MLS channels (planned)**: OpenMLS 0.9.0, suite 0x0003 (X25519/ChaCha20-Poly1305/Ed25519), libcrux provider 0.4.0, `hpke-rs 0.7.0` (MPL-2.0), GHOST seal around every MLS byte, exporter-derived generation secrets, X25519 box keys with HPKE for reveals, Argon2id (RFC 9106, `argon2 0.6.0`) for password-sealed invites | see `faza10-forum.md` §3, §4 | `faza10-forum.md` | **No post-quantum claim for channels** (D3). Not on `main`. |

### 5.2 Primitive libraries by role and exact version

| Role | Library and version (lock) | Where linked | Notes |
|---|---|---|---|
| Olm / Matrix pickle | `vodozemac 0.11.0`, `matrix-pickle 0.2.3` | client library, `ghost-client-dm` | `default-features = false`; `low-level-api` only as a dev feature; G-R2 keeps forbidden features out of shipped graphs. `hpke 0.14.1` is a non-optional dependency of vodozemac 0.11.0, dropped by the linker (checked in V-9, gate G-R7(c) greps the shipped library) and outside the audit scope. |
| X-Wing / ML-KEM | `libcrux-kem 0.0.9`, `libcrux-ml-kem 0.0.10`, `libcrux-sha3 0.0.10`, `libcrux-curve25519 0.0.8`, `libcrux-ecdh 0.0.8`, `libcrux-p256 0.0.8`, `libcrux-sha2 0.0.8`, `libcrux-traits 0.0.8`, `libcrux-hacl-rs 0.0.5`, `libcrux-intrinsics 0.0.8`, `libcrux-secrets 0.0.6`, `libcrux-platform 0.0.3`, `libcrux-macros 0.0.3`, `hax-lib 0.3.7` | client library | Whole libcrux graph pinned by `rust-crypto-pins.txt` (a transitive bump changes verified code). `RUSTSEC-2026-0173` (proc-macro-error2, build-time only) is an accepted exception. |
| AEAD / KDF / MAC / hash | `chacha20poly1305 0.11.0` (`chacha20 0.10.2`, `poly1305 0.9.1`, `aead 0.6.1`), `hkdf 0.13.0` (DM; Arti uses `0.12.4`), `hmac 0.13.0` (`0.12.1` in Arti), `sha2 0.11.0` (`0.10.9`), `sha3 0.10.9` (also `0.11.0`, `0.12.0` via other crates), `aes 0.9.3`, `cipher 0.4.4/0.5.2`, `digest 0.10.7/0.11.3` | client library, relay, issuer | Several majors coexist by design; version sets are pinned per graph (`graph ... required` lines). |
| Curves / signatures | `curve25519-dalek 4.1.3` and `5.0.0`, `ed25519-dalek 2.2.0` and `3.0.0`, `x25519-dalek 2.0.1` and `3.0.0`, `ed25519 2.2.3/3.0.0`, `signature 2.2.0/3.0.0` | client library (GHOST uses 2.x/4.x; vodozemac 3.x/5.x), entitlement, issuer ops | `x25519-dalek 2.0.1` is used for the contributory-key trial. |
| RSA / bignum | `ring 0.17.14`; `num-bigint-dig 0.8.6`; `rsa 0.9.10` (**inside Arti only**) and `rsa 0.10.0-rc.18` (**issuer only**); `crypto-bigint 0.5.5` and `0.7.5`; `blind-rsa-signatures 0.17.2` (issuer only) | `ring` and `num-bigint-dig`: client, relay, issuer; `rsa 0.10.0-rc.18`: issuer and issuer-ops | A cargo-deny exception for RUSTSEC-2023-0071 (Marvin attack) applies per version and scope; `rust-feature-policy.sh` and `rust-crypto-pins.sh` enforce the scopes. `md-5 0.10.6`: issuer-only RFC 2617 digest authentication to the Monero RPC. |
| Randomness | `rand 0.10.2` and `0.8.8`, `getrandom 0.2.17`, `0.3.4`, `0.4.3`, `rand_core 0.10.1/0.6.4` | all | The DM crate draws from the OS CSPRNG; deterministic randomness exists only in test hosts (`ghost-dm-host`). |
| Memory hygiene | `zeroize 1.9.0` (with derive), `subtle 2.6.1` | DM crate, entitlement | |
| Tor | `arti-client 0.46.0` and the `tor-*` crates at `0.46.0` (`tor-proto`, `tor-llcrypto`, `tor-hsclient`, `tor-hscrypto`, `tor-circmgr`, `tor-guardmgr`, ...), `rustls 0.23.45` with `ring`, `rustls-webpki 0.103.15`, `libsqlite3-sys 0.37.0` (bundled SQLite 3.51.3 per design `faza10-forum.md` §3.2) | client library | Features restricted by policy: `onion-service-client`, `bridge-client`, `vanguards`, `compression`, `tokio`, `rustls`; no pluggable transports until Phase 12. |
| RPC / storage | `tonic 0.14.6` (client: `codegen` only), `prost 0.14.4`, `hyper 1.11.1`, `tokio 1.53.1`, `redb 4.2.0` | relay, issuer (servers); client (codegen) | No `Channel`/`Endpoint` in the client graph (T6). |
| JNI | `jni 0.21.1` | client library | |
| JVM crypto | `org.bouncycastle:bcprov-jdk18on:1.85.2`: Ed25519 sign/verify and keys, X25519, `ChaCha20Poly1305` (drop sealing), `SHA3Digest` (onion address checksum); platform JCA: `HmacSHA256`, `SHA-256`, `AES/GCM/NoPadding` (Keystore), `ChaCha20-Poly1305` (`ContentCipher`), `SecureRandom` | `:identity`, `:network`, `:crypto-bridge`, `:messaging`, `:entitlement`, `:sync` | |
| Local database | `net.zetetic:sqlcipher-android:4.19.0`; test-only `org.xerial:sqlite-jdbc:3.53.4.0` | `:storage`; tests | The JVM harnesses run on plain SQLite. |
| Build toolchain | JDK 17, Gradle 9.7.1 (distribution SHA-256 pinned), AGP 9.4.0, Kotlin 2.4.20, compile/target SDK 37, min SDK 29, Compose BOM 2026.09.00, Rust 1.98.1, NDK 30.0.16248370, cargo-ndk 4.1.2, protoc 36.x (pinned by hash in `scripts/install-protoc.sh`) | | See `BUILD_AND_REVIEW_GUIDE.md` section 2. |

Future (Phase 10, unmerged): `openmls 0.9.0`, `openmls_traits 0.6.0`, `openmls_libcrux_crypto 0.4.0`, `openmls_memory_storage 0.6.0` (linker-dropped), `hpke-rs 0.7.0`, `hpke-rs-crypto 0.7.0`, `hpke-rs-libcrux 0.7.0` (MPL-2.0, unmodified, source offer under ADR-37), `libcrux-aes/aead/chacha20poly1305/poly1305/ed25519/hkdf/hmac/sha2/hmac-drbg` at 0.0.6-0.0.9, `argon2 0.6.0`, `rayon` (one worker), plus a manifest stub for the never-compiled `openmls_sqlite_storage` (design `faza10-forum.md` §3.2).

### 5.3 Pin and policy enforcement (what the repository already checks)

| Control | File or gate | What it enforces | Known limit |
|---|---|---|---|
| Lock and registry | `--locked` everywhere; `deny.toml` `[sources]` | Only crates.io; unknown git/registry denied | |
| Advisories | `cargo deny` (advisories, yanked = deny) and `cargo audit --ignore RUSTSEC-2023-0071` in CI | Three documented ignores: RUSTSEC-2023-0071 (rsa Marvin; scopes argued), RUSTSEC-2024-0436 (`paste`, build-time), RUSTSEC-2026-0173 (`proc-macro-error2`, build-time) | RustSec does not carry OpenMLS advisories, and two libcrux advisories are filed under a renamed crate (design `faza10-forum.md` §3.1, §3.7). A clean advisory check is weaker evidence for libcrux and hpke-rs than for most crates: a researcher alleges that RustSec maintainers closed advisory pull requests for them, and the vendor disputes the findings (The Register, 2026-03-20, updated 2026-03-24, https://theregister.com/2026/03/20/cryptographer_nadim_kobeissi_rustsec_ban , accessed 2026-10-04; allegations of one party, read both sides). |
| Licences | `deny.toml` allowlist, gates G-L1..G-L5, G-R5; `unused-allowed-license = deny` | No GPL/LGPL/AGPL in shipped graphs; MPL-2.0 only unmodified with source offer | |
| Bans | `deny.toml` | No telemetry SDKs (sentry, bugsnag, opentelemetry), no HTTP clients (reqwest, ureq, isahc, surf, attohttpc, curl), 14 libsignal-family names | Name-based. |
| Exact versions | `rust-crypto-pins.sh` / `rust-crypto-pins.txt` | `lock` lines (exact lock versions) and `graph` lines (exact version sets per shipped graph, per target) for rsa, crypto-bigint, blind-rsa, num-bigint-dig, ring, vodozemac, matrix-pickle, hpke, the libcrux set, dalek majors, chacha20poly1305, hkdf, hmac, rand, zeroize | |
| Feature policy | `rust-feature-policy.sh`, `rust-client-allowlist.sh` + `client-core/rust-dependency-allowlist.txt` (417 names) | Arti/tonic feature sets, no clearnet-capable features, issuer-only crates kept out of client and relay graphs | Allowlist matches package names, not code. |
| Gradle | `dependency-allowlist.sh`, `dependency-denylist.txt`, `gradle/verification-metadata.xml` | Group allowlist; SHA-256 per artifact (332 components) | `verify-signatures = false`; all `.pom`/`.module` files and the `aapt2` jar are trusted by rule (review GATES-5, open). |
| Native build | `scripts/build-native.sh`, `apk-native-libs.sh`, `reproducible-build.sh` | Pinned cargo-ndk, remapped paths, no build path in the library, two same-path builds compared, APK contains exactly the recorded libraries | Cross-environment identity is **not** claimed. |
| Shipped-graph hygiene | G-R3 (portable libcrux), G-R4 (no logging crates), G-R6 (closed JNI list), G-R7 (golden pickles, one vodozemac version), G-R8 (clock/log/network sites of the vendored graph equal a justified baseline: 43 sites over 112 crates) | | Text and symbol gates have declared evasions (design `faza9-dm.md` §22.33 item 16). |

---

## 6. Assumptions and trust boundaries

From `docs/THREAT_MODEL_v2.1.md` (Phase 2 deliverable; its independent review, the Phase 2 exit gate, is **still open**).

| ID | Assumption | If false |
|---|---|---|
| A1 | vodozemac (Olm) and OpenMLS implement their protocols correctly at the pinned versions and GHOST does not modify them, except the declared pickle-layout deviation; GHOST's composition (PQ layer, session rules) is covered by the model and the external review (PQ-R6) | Content confidentiality falls (R-03). **Today the composition is an assumption, not a verified property.** |
| A2 | Android Keystore (hardware-backed) does not export keys | Impersonation after extraction (L1) |
| A3 | Tor resists local observers, not a global passive adversary | IP-relay correlation (L2) |
| A4 | RSA blind signatures / Privacy Pass (RFC 9474/9578) are correct | Payment-token linkability |
| A5 | Monero hides sender, amount, recipient on chain | Payment-person linkability |
| A6 | At least one of at least three relays is honest and available | Availability (not confidentiality) |
| A7 | The release signing key stays offline and uncompromised | Malicious update (R-11) |
| A8 | The user keeps the mnemonic and does not type it elsewhere | Identity loss or takeover (R-01) |

| Trust boundary | What crosses | What never crosses |
|---|---|---|
| TB-1 Android process and Keystore | sign/derive/open operations through the API | raw key material |
| TB-2 Client and relay (over Tor) | padded packets, capabilities, one-use tokens, hashes | IP, identity, plaintext, file key |
| TB-3 Relay and relay | authenticated inventory, blobs (gossip is **off** until peers are authenticated) | endpoint identities, client capabilities |
| TB-4 Client and issuer (over Tor) | invoice requests in quiet runs, `BlindSign` with fixed structure, blinded messages, invite/credit tokens, payment addresses; one Tor scope per flow | GHOST identity, pseudonyms, IP, deblinded access tokens, keys, prices or configuration |
| TB-5 Issuer and Monero network | view-key observation of payments | spend key |
| TB-6 Build and release | reproducible artefact, manifest signed offline; planned: auditor-reproduced build, transparency log | signing key (never in CI) |
| TB-7 Member and MLS group | application messages, commits, policies | base identity without an explicit reveal |

Adversaries AD-1 (operator, in practice the vendor, AD-V), AD-2 (malicious relay), AD-3 (compromised issuer), AD-4 (local network observer), AD-5 (global passive), AD-6 (malicious group member), AD-7 (malicious DM correspondent, including card holders), AD-8 (unlocked or rooted device), AD-9 (supply-chain attacker), AD-10 (active network attacker), AD-11 (Sybil/brigading), AD-12 (legal authority) are defined with capabilities and limits in `THREAT_MODEL_v2.1.md` §3. The 13 scenarios S1-S13 in §7 of that document and the residual-risk register in §8 are the natural starting set for abuse cases.

---

## 7. Claims register

"Where tested" names the test, gate or world that is meant to establish the claim. **A claim is listed as it is made, not as it is established**: the status column says what exists today. No row supports a user-facing statement (CP-10).

### 7.1 Core principles (spec v2.0 §2, text extracted from `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf`)

| ID | Claim (normative text, abbreviated) | Where addressed or tested | Status at base |
|---|---|---|---|
| CP-01 | Only user endpoints possess content-decryption keys; operator infrastructure MUST NOT receive them. | T1, T26, T35; code review of relay/issuer (no content-key path); builds only as far as AD-V allows | Designed and partially tested; unverifiable for users (closed source, L-SRC). |
| CP-02 | Plaintext does not cross the endpoint trust boundary. | T3, T24 (UI, Phase 13), T25 | Partial: T24 not built. |
| CP-03 | No email, phone, legal name or KYC. | By design (identity from mnemonic; no registration). Payment rail may impose its own. | No test needed; E7 (exchange KYC) declared. |
| CP-04 | Blockchain holds commitments only. | Superseded: v2.1 has no on-chain component (ADR-02/03). | n/a |
| CP-05 | Unlinkable entitlement: proof of entitlement does not expose the GHOST identity or recovery seed. | T2, T16, T22, T23 | Partial: PC-4. |
| CP-06 | Blind relays: opaque blobs, no source-IP logs by default. | T1, T6, T9 | Executable; staging capture never run. |
| CP-07 | Metadata resistance: multi-hop routing and size buckets; resistance, not elimination. | T9, T19, T21; T17/T18 Phase 12 | Partial. |
| CP-08 | Authenticated distribution: signed, hash-verified, rollback-protected updates. | T12; Phase 14 | **Not met** (no updater, no signing pipeline). |
| CP-09 | No custom crypto; exceptions need an ADR and external review. | ADR-31', -33', -35 (rules), -36; this audit | Open: the audit is the review. |
| CP-10 | Security and performance claims must be traceable to tests, measurements or audit evidence. | This register; `docs/STATUS.md` "Afirmații permise: niciuna" | In force. |

### 7.2 Invariants T1-T35 (`ghost/test-harness/privacy/INVARIANTS.md`, 66 lines; rows abbreviated)

| ID | Claimed property | Where tested | Status at base (from INVARIANTS and design notes) |
|---|---|---|---|
| T1 | A relay observes only the fields of `allowed-observables.json` (v2): no IP, identity, plaintext, unpadded size, time below the minute. | Relay capture NDJSON validated by `capture-check`; positive/negative fixtures (`privacy-capture.sh`); two-node suite capture (`relay/crates/node/tests/two_nodes.rs`) | Executable since Phase 2/5/9; **staging capture never run**. |
| T2 | No join key and no correlation between the issuer's complete view and the relays' views beyond the declared leak L1-L7; amounts uniform per epoch (A1). | Rust T2 world with real issuer and three real relays (`issuer/crates/service/tests/t2_unlinkability.rs`, `tests/t2/`), joins J1-J10, twins NI-1/1d/2/3/K, statistics S1-S4, 26 mutants (`t2_mutants.rs`), `t2-report-check.sh`; Kotlin engine twin `NiKTest` | PR scale green; gate scale: pair 0 green (Phase 8 closure), **nightly sweep never green** (pairs 2, 3, 9 red). |
| T3 | Secret canaries never appear in logs, telemetry, crash output. | `no-logging.sh`, G-R4/G-R8 (built), redacted `Debug` types, JNI without error text; `DeviceGateSuite` logcat scan (emulator, local) | **Partial**: the all-canaries all-outputs test is not built. |
| T4 | Backups and device transfer contain no seed, DB key, protocol state, decrypted cache. | `bmgr`/`adb backup` inspection (Phase 4) | **Not executed.** Manifest and extraction rules checked by gates. |
| T5 | Media metadata stripped. | Phase 11 | Not built. |
| T6 | Without Tor: zero clearnet connections and DNS queries. | Rust: `OnionAddress` only public destination, `compile_fail` doctest, `rust-feature-policy.sh`, clippy bans (23 APIs, fixture proves each), Kotlin `kotlin-clearnet.sh`; dynamic emulator capture (Phase 13) | Static parts executable; **dynamic test not run**; unlisted APIs not covered. |
| T7 | A dependency outside the allowlist stops the build. | `dependency-allowlist.sh`, `rust-client-allowlist.sh` + self-test | Executable. |
| T8 | No placeholder on the production path. | `anti-placeholder.sh` | Executable. |
| T9 | Only sizes 1/4/16/64 KiB on the wire and in storage; bytes indistinguishable from random. | Relay refuses other sizes; client refuses unpadded; padding in the AEAD plaintext; DM: T29 | Executable; DM statistical uniformity test not built. |
| T10 | Every window FLAG_SECURE, nothing in recents. | Phase 13 | Not built. |
| T11 | Notifications with locked device carry no text/sender. | Phase 13 | Not built. |
| T12 | Two release builds have identical hashes; native libs recorded and present in the APK. | `reproducible-build.sh`, `apk-native-libs.sh` (CI jobs `android-native`, `reproducible`) | Same-path only. `reproducible` passed on runner 2026-09-28 (run 36434212692). T12b (auditor build) planned, absent. |
| T13 | Authored timestamps have seconds = 0 (DM: minutes only). | Unit tests, vectors `dm_content.txt` | Executable. |
| T14 | Pseudonyms of one user in two channels are unequal and not derivable without the seed. | `android/identity` vectors | Executable. |
| T15 | Manifests hardened (no backup, no cleartext, only allowlisted permissions, no exported components except launcher). | `manifest-lint.sh`, `merged-manifest-lint.sh` (T15m; also now checks `androidx.startup` initialisers) | Executable on source and merged release manifests. |
| T16 | Invites contain no web host, plaintext identity key or payment address; not replayable; v2 verified offline against the ES. | `InviteTest`, `KeyDerivationTest`, issuer `negative.rs`, `issuer_semantics.txt`, `TrialStepsTest`, scenario E-E | Executable. |
| T17 | Idle traffic statistically indistinguishable from active traffic. | Phase 12 (high-privacy mode with cover traffic, P2) | Not built; volume follows activity (L2.1). |
| T18 | With bridges, no known Tor fingerprint. | Phase 12 | Not built (simple bridges only). |
| T19 | Read schedule independent of activity (start time, pair, limit of each first list request). | `engine/T19BasicTest`, `PrivacyHarnessTest`, `ReadLaneTest`; mutants M13/M15/M16/M17 | JVM executable; retest with full DM activity not built. |
| T20 | Sync layer writes nothing outside SQLCipher; persisted times only at minute/hour/day via CHECK; no request/schedule history. | `SchemaIntrospectionTest`, `PeriodicJobSpecTest`, `ExpiryAlarmSpecTest` | JVM executable; device inventory not executed. |
| T21 | Isolation scope equals capability scope; mismatches fail before any I/O. | `NamespaceClient` matrix test; 0 relay requests for each refused token | Executable (Rust). |
| T22 | Exactly one key per (kind, epoch), from the signed ES with a valid permutation proof; schedule only grows. | `schedule_vectors.rs`, `committed_schedule.rs`, `ScheduleAcceptanceTest`, `entitlement-schedule.sh` (git history), J7/J10 | Executable. |
| T23 | Each issuer flow has its own isolation scope; automatic issuer calls only in quiet runs (at most 1 per run, at most 6 linked per purchase). | `isolation.rs` tests, `SessionParticipantTest`, `QuietRunSchedulerTest`, NI-K, J6/J9/S3a; manual `live-tor` job | Executable; live part manual. |
| T24 | Message text does not leave the app through the UI; sensitive fields; clipboard rules. | Phase 13 | Not built. |
| T25 | An ephemeral message disappears at its timer on every honest device; relay TTL tiers per ADR-27 point 11. | `EphemeralTest`, `SweepTest`, `DmExpiredRowLint`, SCN-F, JD5, EP-* suite cases and mutants ME-* (22.37/22.38) | JVM executable; defect R-T3 open; device run local only (emulator). |
| T26 | DM addressing is blind: no relay-visible value computable from public identity material without a card or seed. | Derivation vectors, Rust and Kotlin G-DM3, JD1/JD2/JD9, S-DM3, mutants PM-3/13/24 | PR scale local; **gate scale red**. |
| T27 | All deposits into one inbox at one relay have the same scope; clients redeem and register only for their own namespaces; independent of DM activity. | JD3, JD8, NI-DM3, `EntDmWorldTest`, relay vectors | Partial: JD8 narrowed; "minute" of redemption not testable; hold question open. |
| T28 | No received blob produces traffic (no reflex). | `NoReflexTest`, G-DM2, NI-DM1, JD6, PM-2/6 | Partial (PM-25 and session-close times not built). **JD6, the join for this claim, is red at gate scale on 7 of 10 seed pairs** (PC-5, KI-PRV-2). |
| T29 | DM envelopes and bundles are exactly 4/16/64 KiB, tier a function of body length only, uniform bytes. | crate tests, `DmBucketsTest`, JD4, NI-DM2, PM-4 | Partial; open defect R-T3 visible to relays. |
| T30 | TTL tiers and per-operation deadlines; a copy at an honest relay disappears by deadline + tier + 1 h. | relay and client vectors, JD5, SCN-E, PM-5 half | Partial. |
| T31 | A client reads only its own namespaces and channels plus a bounded bundle fetch; own writes at activity-independent times. | JD7, SCN-C, G-DM2, NI-DM3, JD8 | Partial; MD-4 and a restore edge open. **JD7 is red at gate scale on 1 of 10 seed pairs** (pair 4; PC-5, KI-PRV-2). |
| T32 | The DM privacy world: joins JD1-JD10 find nothing; twins NI-DM1-7 equal; S-DM1/S-DM3 at alpha = 0.001; S-DM2/S-DM4 reported. | `android/messaging/src/test/.../dmworld`, `dm-report-check.sh`, mutants (15 of 40) | **PR scale green (local and CI `android` job). Gate scale: green on 10 of 10 pairs once (2026-09-27, earlier cadence), red on all 10 pairs every night since the production-trigger change (JD5 on 10 pairs, JD6 on 7, JD7 on 1; the suite job with the twins, T34 and the mutants is green); JD10 and NI-DM4-7 unbuilt.** |
| T33 | Local forensic minimality: only coarse-time columns, no activity counters, content under the content key, constant notification text. | `DmSchemaIntrospectionTest`, `pickle_structure.rs`, `NotificationPortContractTest`, `dm-no-fts.sh`, G-R8 | JVM/Rust executable; device not run. |
| T34 | After key erasure, old pair/intro/provisional envelopes cannot be attributed (seizure scenario). | Seizure world (10 clients, 70 days), `SweepTest`, `TrustFlowTest`, mutants PM-19/36/39; ProVerif M-7 (structure) | Partial: the Olm half of the seizure and PM-29 unbuilt. |
| T35 | Post-quantum confinement: relay-stored DM bytes sealed under card-, X-Wing- or PQ-transported keys only. | provenance tags (`ghost-dm-host --features provenance`), PQ1/PQ5 tests, `pq-mutants.sh` (10 source mutants; workflow `pq-bump`: 18 green runs, 4 of them on `main`), ProVerif M-1/M-3 | Partial: **no claim of quantum resistance (CP-10)**. |

### 7.3 Phase guarantees (design documents; IDs are scoped by phase)

| ID | Claim | Where tested | Status |
|---|---|---|---|
| F7 OUT-1..4, IN-1..3 | Sync exactly-once contract: no loss, no local or network duplicate, outcome truth; inbox no loss/duplicate, cursor safety. | `:sync` harness: exhaustive crash enumeration (S-A..S-H, S-L; 45,156 single crashes plus doubles), 20,000 seeded worlds, 17 mutants, `sync-exit-gate` | JVM; green on runner at `197b2b4`. |
| F8 MS-1..MS-8 | Money safety: no double issuance, none without value, no double spend, referral <= 10 %, spend key never online, no silent loss after payment, reconciliation, idempotent redemption. | `issuer/crates/service/tests/{crash,negative,custody,custody_window,journal_*,payout,refresh,races,server,monero_rail}.rs`, `entitlement-exit-gate` (E-A..E-J crash enumeration, 20,000 worlds, 12 shards), `monero-regtest` | Green on the runner (`entitlement-exit-gate` nightly 2026-10-02; `monero-regtest` nightly 2026-10-03; the `entitlement-exit-gate` nightly of 2026-10-03 was cancelled, shards 2, 4, 5 and 11 unfinished). MS-4 (referral at most 10 % of revenue) is enforced by construction in the code (design `faza8-issuer.md` §9.6, the cap proof); only MS-5 (spend key never online) depends on operations (workstation, air gap) and not on code. |
| F8 P-1..P-7 | Blindness for every accepted key; key consistency; non-interference; no join key; no statistical link beyond L; no referral graph at issuer; flow isolation and contact discipline. | T2 (above), `permutation_proof.rs`, `rfc9474_vectors.rs`, `differential.rs` | See T2. |
| F9 P-1..P-8 | DM: no identity at relays; no sender field; no reflex; no type/state in sizes or bytes; bounded relay lifetime; read confinement; attribution forward secrecy of envelopes; HNDL confidentiality (Level 2) of relay-stored bytes. | T26-T35 (above) | Partial, see above. |
| F10 P-C1..P-C6, CS-C1..CS-C9 | Channels: no channel identity at relays, no writer/reader field, commits look like posts, removal, joiner history "none", no reflex; atomic state, exactly-once display, convergence (T41), fork detection, no loss within the envelope, deterministic order, T25 bounds, bounded state, migration safety. | Planned T36-T41, EM-3, SCN-M20 (20 clients) | **Design claims; not implemented on `main`.** |

### 7.4 Declared limits (what the project says it cannot do)

Source `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` (323 lines): L1 compromised device (+ L1.1 local residues of sync, entitlement and DM), L2 global passive adversary (+ L2.1 sync residues), L3 malicious group member, L4 ISP sees Tor (+ periodic Tor bootstraps as a fingerprint), L5 implementation residues (31 rows, many open), L6 entitlement residues **E1-E34**, L-SRC closed source, L7 DM residues **L7-D1 to L7-D29**. Open rows are listed in `KNOWN_ISSUES.md`.

---

## 8. What the project explicitly does NOT claim

Read with `LIMITE` §5 ("Sinteză") and spec CP-10. An auditor should treat any contradiction between these statements and the code or docs as a finding.

1. **No quantum-resistance wording before the external review** (CP-10, design `faza9-dm.md` §9.8): forbidden "quantum-proof", "post-quantum end-to-end encryption", "PQ ratchet", "Signal protocol", "formally verified", "100% private". Even the permitted sentence after review says the Olm ratchet and authentication stay classical and network metadata is not PQ-protected.
2. **Post-quantum is partial by design**: authentication classical (PQ-R1); no PQ inside the ratchet (PQ-R2); first-flight forward secrecy bounded by generation erasure of up to 91 days (PQ-R3); network metadata and relay RPC credentials not protected (PQ-R4); primitives young, libcrux pre-1.0, X-Wing an Internet-Draft (PQ-R5); the composition is GHOST-built until model and review exist (PQ-R6); Olm is classical under the seal (PQ-R7); a contact-card link sent over a classical channel can be recorded, and a later quantum adversary then holds the card (it can recognise the owner's intro envelopes and deposit or fetch bundles, not read content; PQ-R8). **Channels have no PQ protection at all** (OpenMLS suite 0x0003).
3. **No unlinkability against relays under AD-1** for co-occurrence at session start (L2.1 #1, L7-D2); no UI claim of channel unlinkability against relays (Q22); all of one client's requests on a circuit are linkable (L7-D5); a card holder learns inbox timing and volume (L7-D3, L7-D16); a relay learns send and receive minutes, TTL tier, presence (LD in design §1.2).
4. **No anonymity against a global passive adversary** (AD-5), none against a compromised or unlocked device (AD-8), none against a malicious group member's copy or camera (L3), no hiding that the user uses Tor from the ISP (L4).
5. **No guarantee against the operator beyond a published, reproduced build**: statements such as "the operator cannot read content" are valid only for a build in the transparency log and reproduced by auditors; none of that exists (L-SRC/L7-D23, AD-V).
6. **No deniability**: binding v3 lets the recipient prove contact initiation (L7-D20); a channel reveal is provable (L8-C8).
7. **No payment anonymity beyond the issuer's view**: Monero's chain privacy is Monero's; an exchange with KYC knows the user paid GHOST (E7); the issuer sees invoice moments and amounts (uniform) and the declared leak L1-L7.
8. **No latency or battery claims**: NFR-1 (DM latency, p95 under 2 s and p99 under 5 s) is not met by design (ADR-20 point 5: about 40 s p95 in the foreground, estimated, and hours in the background); NFR-5 unmeasured; no throughput/load claims (NFR-3, which ADR-18 assigns to Phase 15).
9. **No availability or DoS-resistance claim**: onion-service proof-of-work is not solved by Arti clients (LIMITE L5 row 1); Tor blocking is possible (R-15).
10. **No claim about hardware-backed key protection on real devices**: only the emulator's software Keystore was exercised; StrongBox refused there.
11. **No claim for HIGH (high-privacy) mode beyond what is measured**: the privacy worlds do not model HIGH mode, key changes, restores, clock offsets (design `faza9-dm.md` §22.16 points 10-15).
12. **No claim that "closed" equals "unauditable"**: ADR-38's package (full audit reports published, auditor-reproduced build, transparency log, specification and vectors repository, escrow) is a **plan**; none of it exists.

---

## 9. The audit package and where things are

| File | Content | Goes to auditors |
|---|---|---|
| `README.md` | Index, reading order for the first day, conventions. | after the NDA |
| `AUDIT_SCOPE.md` | This document. | after the NDA |
| `EVIDENCE_INDEX.md` | What has been verified, with commands, counts and what has **not** run; the CI evidence (`ci-runs.tsv`, `ci-log-facts.tsv`) it cites. | after the NDA |
| `KNOWN_ISSUES.md` | Open findings, owner decisions and declared residues to read before starting. | after the NDA |
| `BUILD_AND_REVIEW_GUIDE.md` | Getting the source under NDA, building, running tests and gates, reading order, component-to-specification index. | after the NDA |
| `AUDITOR_RFQ.md` | The request for quotation (self-contained; contains no source and no unfixed weakness). | with the invitation to bid |
| `ci-runs.tsv`, `ci-log-facts.tsv` | Static copies of the CI results the package cites (run, job and log facts), because the repository is not shared and GitHub keeps logs for 90 days. | after the NDA |
| `tools/measure.sh`, `tools/check-package.sh` | The measurement script of Appendix A and the check that the package's numbers still equal its output. | after the NDA |

Two files stay with the owner and are never attached: `README-RO.md` (Romanian cover note) and `OWNER_ONLY_MARKET_AND_BUDGET.md` (market notes, budgeting method, negotiating notes).

---

## Appendix A: the measurement script

`docs/audit/tools/measure.sh`, reproduced verbatim (`tools/check-package.sh` fails if the two differ). Run it from anywhere inside a clean checkout (about a minute on Windows, seconds on Linux); it prints the sections `components`, `rust crates`, `totals` and `static test counts`. It produced the numbers of section 2; the rule for test-only Rust code is described in section 2.1.

```bash
#!/usr/bin/env bash
# GHOST audit package: size and test-count measurement (AUDIT_SCOPE.md section 2 and Appendix A).
# Run from anywhere inside a clean checkout. Usage: measure.sh [scratch dir, default /tmp]
# Needs git, bash, GNU awk and GNU xargs (-d). Nothing is built; only tracked files are read.
set -u
cd "$(git rev-parse --show-toplevel)"; T="${1:-/tmp}"
EXT='\.(rs|kt|kts|java|proto|sh|pl|pv|yml|yaml|toml|xml|sql|json|patch|ps1|bat|pro|properties)$'
git ls-files ghost .github | grep -E "$EXT" > "$T/files.txt"
xargs -d '\n' wc -l < "$T/files.txt" | grep -v ' total$' | awk '{n=$1; $1=""; sub(/^ /,""); print n "\t" $0}' > "$T/phys.tsv"
xargs -d '\n' grep -c -v '^[[:space:]]*$' < "$T/files.txt" | awk -F: '{print $NF "\t" substr($0,1,length($0)-length($NF)-1)}' > "$T/nb.tsv"

echo "## components: component, language, kind, files, physical lines, non-blank lines"
awk -F'\t' 'FNR==NR{nb[$2]=$1;next}{p=$2;n=$1;b=nb[p];
  comp="other"; if(p~/^ghost\/relay\//)comp="relay"; else if(p~/^ghost\/issuer\/crates\/[a-z-]+\//){split(p,a,"/");comp="issuer/" a[4]}
  else if(p~/^ghost\/client-core\/[a-z-]+\//){split(p,a,"/");comp="client-core/" a[3]}
  else if(p~/^ghost\/android\/[a-z-]+\//){split(p,a,"/");comp="android/" a[3]}
  else if(p~/^ghost\/(protocol|scripts|infra|licenses|test-harness)\//){split(p,a,"/");comp=a[2]} else if(p~/^\.github\//)comp="ci";
  lang=(p~/\.rs$/)?"Rust":(p~/\.kt$/)?"Kotlin":(p~/\.kts$/)?"Gradle":(p~/\.sh$/)?"Shell":(p~/\.pl$/)?"Perl":"misc";
  kind="all"; if(lang=="Rust"){kind=(p~/\/tests\//)?"tests":(p~/\/(examples|fuzz|benches)\//)?"aux":"src"}
  else if(lang=="Kotlin"){kind=(p~/\/src\/main\//)?"main":(p~/\/src\/release\//)?"release":(p~/\/src\/test\//)?"test":"otherset"}
  k=comp"\t"lang"\t"kind; f[k]++; ph[k]+=n; nbl[k]+=b}
  END{for(k in f)print k"\t"f[k]"\t"ph[k]"\t"nbl[k]}' "$T/nb.tsv" "$T/phys.tsv" | sort > "$T/components.tsv"
cat "$T/components.tsv"

# Rust `src/` files: lines inside test-only items. Test-only = #[cfg(test)], feature "test-vectors",
# any(test, feature "pq-spy") and feature "clippy-fixture" (test and fixture features that no shipped
# build enables). An item runs from its attribute line to its closing brace at the same indentation
# (rustfmt layout, enforced by `cargo fmt --check`) or to its terminating ';'. A `mod x;` declared
# that way makes the whole file x.rs test-only. Small gated statements and functions count as well.
cat > "$T/testonly.awk" <<'AWK'
function ind_of(s) { match(s, /^ */); return RLENGTH }
function is_test_attr(s) {
  return (s ~ /^[ \t]*#\[cfg\((test|feature = "test-vectors"|any\(test, feature = "pq-spy"\)|feature = "clippy-fixture")\)\][ \t]*$/)
}
function flush(   i, j, k, m, ind, cnt, kids, name, dir, base, pre, b) {
  if (cur == "") return
  dir = cur; sub(/[^\/]*$/, "", dir); base = cur; sub(/^.*\//, "", base)
  if (base == "lib.rs" || base == "main.rs" || base == "mod.rs") pre = dir
  else { b = base; sub(/\.rs$/, "", b); pre = dir b "/" }
  cnt = 0; kids = ""; i = 1
  while (i <= n) {
    if (!is_test_attr(L[i])) { i++; continue }
    ind = ind_of(L[i]); j = i + 1
    while (j <= n && (L[j] ~ /^[ \t]*#\[/ || L[j] ~ /^[ \t]*\/\/\//)) j++
    if (L[j] ~ /^[ \t]*(pub(\([a-z]+\))?[ \t]+)?mod[ \t]+[A-Za-z0-9_]+[ \t]*;/) {
      name = L[j]; sub(/^[ \t]*(pub(\([a-z]+\))?[ \t]+)?mod[ \t]+/, "", name); sub(/[ \t]*;.*$/, "", name)
      kids = kids " " pre name ".rs " pre name "/mod.rs"; cnt += j - i + 1; i = j + 1; continue
    }
    k = j
    while (k <= n && L[k] !~ /[{;][ \t]*(\/\/.*)?$/) k++
    if (k > n) { i = j; continue }
    if (L[k] ~ /;[ \t]*(\/\/.*)?$/) { cnt += k - i + 1; i = k + 1; continue }
    m = k + 1
    while (m <= n && !(substr(L[m], 1, ind) == substr(SP, 1, ind) && substr(L[m], ind + 1, 1) == "}")) m++
    if (m > n) m = n
    cnt += m - i + 1; i = m + 1
  }
  print cur "\t" n "\t" cnt "\t" kids
}
BEGIN { SP = sprintf("%80s", "") }
FNR == 1 { flush(); cur = FILENAME; n = 0; delete L }
{ n++; L[n] = $0 }
END { flush() }
AWK
git ls-files ghost | grep '\.rs$' | grep -vE '/(tests|examples|fuzz|benches)/|test-harness/gates/' > "$T/rs.txt"
xargs -d '\n' awk -f "$T/testonly.awk" < "$T/rs.txt" > "$T/rs-split.tsv"
awk -F'\t' '
{ f[NR]=$1; n[$1]=$2; c[$1]=$3; if ($4 != "") { m = split($4, a, " "); for (x = 1; x <= m; x++) kid[a[x]] = 1 } }
END {
  for (i = 1; i <= NR; i++) { p = f[i]; split(p, a, "/");
    k = a[2]; if (a[2]=="client-core"||a[2]=="test-harness") k = a[2] "/" a[3]; else if (a[2]=="issuer") k = "issuer/" a[4];
    t = (p in kid) ? n[p] : c[p];
    SRC[k] += n[p]; TST[k] += t; if (!(p in kid)) FP[k]++; FA[k]++ }
  for (k in SRC) printf "%s\t%d\t%d\t%d\t%d\t%d\n", k, FA[k], FP[k], SRC[k], TST[k], SRC[k]-TST[k]
}' "$T/rs-split.tsv" | sort > "$T/rs-crates.tsv"
echo "## rust crates: crate, src files, files not wholly test-only, src lines, test-only lines, production lines"
cat "$T/rs-crates.tsv"

echo "## totals (key=value)"
echo "files_total=$(wc -l < "$T/files.txt" | tr -d ' ')"
awk '{s += $1} END {print "phys_lines_total=" s}' "$T/phys.tsv"
# Shipped or deployed Rust = relay, issuer/*, client-core/net, client-core/dm. dm-host (a test-only
# cdylib), test-harness and the separate mls-spike workspace are not shipped and are left out.
awk -F'\t' '$1 ~ /^(relay|issuer\/.*|client-core\/net|client-core\/dm)$/ {fa+=$2; fp+=$3; s+=$4; t+=$5; p+=$6}
  END {printf "rust_src_files=%d\nrust_prod_files=%d\nrust_src_lines=%d\nrust_testonly_lines=%d\nrust_prod_lines=%d\n", fa, fp, s, t, p}' "$T/rs-crates.tsv"
awk -F'\t' '$1 ~ /^android\// && $2 == "Kotlin" {s[$3] += $5; fl[$3] += $4}
  END {printf "kotlin_main_lines=%d\nkotlin_main_files=%d\nkotlin_release_lines=%d\nkotlin_release_files=%d\nkotlin_unit_test_lines=%d\nkotlin_unit_test_files=%d\nkotlin_otherset_lines=%d\n",
       s["main"], fl["main"], s["release"], fl["release"], s["test"], fl["test"], s["otherset"]}' "$T/components.tsv"
awk -F'\t' '$2 == "Rust" && $3 == "tests" && $1 ~ /^(relay|issuer\/.*|client-core\/net|client-core\/dm)$/ {s+=$5; fl+=$4}
  END {printf "rust_integration_test_lines=%d\nrust_integration_test_files=%d\n", s, fl}' "$T/components.tsv"

echo "## static test counts (key=value)"
git ls-files '*.rs' | grep -v test-harness/gates | xargs -d '\n' grep -c -E '^\s*#\[(test|tokio::test)' | awk -F: '
  { w = ($1 ~ /mls-spike/) ? "mls_spike" : ($1 ~ /client-core\/dm\/fuzz\//) ? "dm_fuzz" : "main"; s[w] += $2; t += $2 }
  END { printf "rust_test_attrs_main=%d\nrust_test_attrs_dm_fuzz=%d\nrust_test_attrs_mls_spike=%d\nrust_test_attrs_total=%d\n", s["main"], s["dm_fuzz"], s["mls_spike"], t }'
git ls-files 'ghost/android/*.kt' | xargs -d '\n' grep -c '@Test' | awk -F: '
  { w = ($1 ~ /\/src\/test\//) ? "unit" : ($1 ~ /\/src\/androidTest\//) ? "android_test" : "other"; s[w] += $2; t += $2 }
  END { printf "kotlin_test_attrs_unit=%d\nkotlin_test_attrs_android_test=%d\nkotlin_test_attrs_total=%d\n", s["unit"], s["android_test"], t }'
echo "## end"
```

Results at the base commit (aggregated from the script's output): Rust `src/` of the shipped or deployed crates 47,453 lines in 109 files, of which 13,950 lines are test-only code (production **33,503** lines in 104 files; `ghost-dm-host`, 35 lines, is in no total); Android Kotlin `src/main` 39,712 lines in 203 files (non-blank 35,907) plus `src/release` 24 lines in 1 file; Android Kotlin `src/test` 74,430 lines in 231 files; other Kotlin source sets 1,798 lines in 12 files; Rust `tests/` of the shipped crates 45,997 lines in 101 files. The measured file set is 1,145 files and 247,042 physical lines. Counts of test functions (static): 892 `#[test]`/`#[tokio::test]` attributes in tracked Rust files (843 in the main workspace, 1 in `client-core/dm/fuzz`, 48 in `mls-spike`), 1,260 Kotlin `@Test` (1,252 in unit-test source sets, 8 in `androidTest`). The attribute count is not the runner's count: one `#[test]` inside `macro_rules!` in `issuer/crates/service/tests/t2_mutants.rs` yields 40 cases, 7 doc-tests have no attribute, 13 of the 204 attributes in `ghost-client-dm`'s `src/` need non-default features, and 49 attributes live in workspaces that `cargo test --workspace` does not run. `cargo test --workspace --locked -- --list` at `a0f3f58` on Windows lists 902 cases, and the CI run on Linux ran 840 passed plus 63 ignored = 903 (the one-case difference was not traced).
