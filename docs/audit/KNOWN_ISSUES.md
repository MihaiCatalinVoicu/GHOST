# GHOST external audit: known issues, owner decisions and declared residues

| Field | Value |
|---|---|
| Purpose | Everything an auditor should know *before* starting, so that effort goes to unknowns. Open findings, open owner decisions, declared residual risks, unverified assumptions, and inconsistencies in the project's own documents. Each row has a pointer. |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (2026-10-03). |
| Not exhaustive by design | The sources are long (LIMITE has 31 rows in L5, 34 entitlement residues E1-E34, 29 DM residues L7-D1..D29); this file lists them or, where they are many, indexes them with the ones that matter most. If a row here and the cited source disagree, the source wins (the design documents' later `§22.x` notes win over their `§0`-`§21`, except where a note says otherwise). |
| Severity convention | The repository's reviews recalibrate severities after adversarial verification. **"review: medium"** means that severity as recorded by the review; "(raw: high)" is the finder's original claim. "declared" = a residue the project states and accepts (no severity). "unrated" = found while preparing this package (2026-10-03), not analysed. **No severity here is the preparer's own rating.** |

---

## 1. New since the repository's own records (found while preparing this package)

These are visible in the CI history (`gh run view`), not in any document of the repository. They were **not** analysed beyond reading logs.

| ID | Item | Severity | Evidence and pointer |
|---|---|---|---|
| KI-PRV-2 | **Gate-scale T32 (DM privacy world) fails on all ten seed pairs in every nightly since 2026-09-28.** It passed on all ten pairs once, in the nightly of 2026-09-27 (run 36310990671, commit `7d84f55`), before the privacy worlds were moved to production's trigger mix (design `faza9-dm.md` §22.36, merge `3b2a389`). The failing test is `DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld` (`DmPrivacyWorldTest.kt:78`, AssertionError) and the report check names `JD5` (TTL after the timer a user set; T30/T25). It may be the open TIMER_SET defect (KI-DM-3), which the PR-scale world declares without gating; that is a guess, not established. | unrated | Run 36995511199 (2026-10-02); job log of seed pair 0, `DM-REPORT-FAIL: JD5 failed`. |
| KI-DM-F | **Nightly `dm-fuzz`: target `bundle` ends in `FAIL crash` in all 7 runs since the first (2026-09-27)**, after 2,118 to 114,901 executions; the other five targets pass. Reading the target shows a probable stale property: mode 1 asserts a refused built bundle is refused only for its X-Wing key, but `bundle::parse` now also refuses a non-canonical Olm identity or fallback key (CRY-P9-01 fix `e5beb4e`, merged before the fuzz branch). If so this is a harness defect and also evidence the fix works. **Not confirmed**: the crashing input (artifact 11271989988 of run 37110091953, 149 KB, expires 2026-10-06 because artifacts are kept 3 days; every nightly uploads a fresh one) was not downloaded. | unrated | `ghost/client-core/dm/fuzz/fuzz_targets/bundle.rs` mode 1; `ghost/client-core/dm/src/bundle.rs:133-151`; `EVIDENCE_INDEX.md` section 6. |
| KI-SUP-1 | **The `static gates` job of `ci` is red** at the last completed push run (36434212692, `197b2b4`) on one self-test case (G-R7 "fails closed on an unreadable base": a shallow checkout lacks the base). Every other job of that run is green. Fixed in `a0f3f58`, which was not on `origin/main` when checked. | unrated | `EVIDENCE_INDEX.md` section 3. |
| KI-DOC-1 | **`docs/STATUS.md` lags the design notes in its Phase 9 and CI rows**: it says the integration branch `p9-integ2` is "nemerguită în `main`" (it is merged: `21cc9af`, `3b2a389`, `aee4adb`), quotes mutants "15/57" (26/57 since §22.38), says the T32 gate-scale had not run on production's triggers (it has: red), and describes the `android` job as skipped since 2026-09-20 (it ran and passed on 2026-09-28). Its licence row still lists the deletion of the public-era artifacts as pending and its CI row says the artifact quota is reached, while the API shows no artifact older than 2026-10-01 and recent uploads succeed (KI-SUP-7, KI-SUP-8). `LIMITE` L5 row "DM: nimic nu a rulat pe un runner Android" is partly outdated for the same reason. An auditor should trust the dated `§22.x` notes of `faza9-dm.md` over STATUS rows. | unrated | `docs/STATUS.md` rows "Faza 9" and "CI"; design §22.36-§22.38. |

---

## 2. Open owner decisions of the Phase 9 whole-phase review

`docs/reviews/2026-09-25-faza9-review.md` ("Open"), design `faza9-dm.md` §22.34. Eight items were left to the owner with options and **nothing was changed**; exit-gate item 16 ("no open confirmed finding") stays open while they are open.

| ID | Item | Severity | Options recorded | Pointer |
|---|---|---|---|---|
| MD-1 | The own-copy `check` of a write-only DM pair becomes eligible 60 s after the ack, so a hash stored in background session *k* is checked in session *k+1* under the one static deposit scope: **every relay of an inbox can chain one sender's deposits across sessions**, including a relay hosting none of the sender's namespaces. LD lists check events, not store hashes; T32's view has no CHECK event. | review: medium (raw: high) | Accept the validated receipt as verification for LOCAL DM pairs; or confine verification to the store's own session; or declare it; add CHECK to `ViewRelay` and a mutant | §22.34 item 5 |
| MD-4 | `MAX_CONTROLS_PER_PASS` bounds a pass, not a relay session: a backlog of *k* reconnect/revocation notices to contacts without a session drains inside one foreground session (the degree-*k* leak the spread exists to prevent). | review: medium | Release due controls on session starts only (delays revocation notices) or a per-session marker, or declare | item 8 |
| MD-5 | A refused or ambiguous deposit is re-sent with the op's frozen bytes, so a refusing relay links all of one sender's sessions by blob hash until the op deadline (up to 7 days; one op re-stored across 591 sessions was measured). | review: low (raw: medium) | Park a delivery after a definite `unauthorized`, or declare and narrow design §21.2 | item 9, §22.25 item 5 |
| MD-6 | Background sessions consume inbound DMs on the Inbox listener while the lanes run, holding the one `SyncDatabase` lock across native calls, so a session's close time can depend on inbound volume and validity, contradicting P-3/SC-7. | review: low (raw: medium) | Gate the listener during background sessions, or correct the claims | item 10 |
| MD-7 | `relay_capability.generation` of a contact's deposit credential is bumped about daily by KEEPER and on every refusal; on a seized database it gives each contact's age in active days. | review: low | Change Phase 7's race guard (no bump for an identical token, or a random value) or accept | item 11 |
| CRY-P9-03 | Classical pair roots cross into the JVM heap in clear inside the L0 (`l0Encode` returns the L0 with the `seal_root` TLV; `SendStep` keeps it under the content key in `dm_outbound_item.l0_env` until the outcome, at most 7 days; `decrypt` returns it on receipt). Contradicts design §2.5 and L7-D19; the design itself mandates the crossing in §2.6, §21.8 point 1. | review: low (raw: medium) | Keep the root out of every L0 that crosses JNI (a change of the closed JNI surface, G-R6) or declare | item 3 |
| A-2 | The expiry-alarm receiver drops its wake lock (`goAsync()`, post, finish) before the sweep runs, and the one-shot alarm is re-armed only by a pass that finishes: a frozen and killed process leaves no alarm pending. | review: low (raw: medium) | Keep the `PendingResult` until the pass or a deadline (needs a device check no run could give) | item 21 |
| GATES-5 | Gradle dependency verification does not check the Linux `aapt2` binary every CI Gradle job runs (a trust regex covers it; the lone Windows checksum has no effect under it) and trusts every `.pom`/`.module`; the cargo-deny GitHub Action downloads cargo-deny without a checksum; THREAT_MODEL S9 lists checksum verification as a mitigation. | review: low (raw: medium) | A trusted Linux `aapt2` checksum from a source the owner trusts; run the pinned cargo-deny instead of the Docker action; or narrow S9 | item 31 |

**Recorded halves of items otherwise fixed** (the fix is partial; the remainder is the owner's): CRY-P9-01 (`SendStep` still treats `NON_CANONICAL` from `sealIntro` as a bug); ENG-1 and ENG-3 (a per-row fail-closed replay and a HELD offer counter; a per-blob catch in `consumeInbox`, a catch-all policy question); ENG-2 (the persistent-`SQLITE_FULL` case of SCN-J is not in the crash harness); ENG-6 (the receive side still starts the unread cap from the wall clock); A-1 (`SecretKeySpec` and `Mac` provider copies cannot be erased from Kotlin); A-5 (a neutral alarm action string); A-6 (the `ghost.dm.native` loader branch ships in the release); GATES-1 (sharding the gate); GATES-2 (a dm fixture for `clippy-clearnet-fixture.sh`); GATES-4 (the reduced emulator PR job never fires because no PR is opened). The review's own note for this audit: re-check the canonical-encoding rule across every peer-supplied X25519 value (CRY-P9-01 was its third instance), native and JVM secret residue (CRY-P9-02/04, A-1), and MD-1 against T32 once `ViewRelay` sees CHECK events.

---

## 3. Known open items by component

### 3.1 `ghost-client-dm` and the DM cryptographic composition (Tier A1, B1)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-DM-1 | The composition (sealed-sender modes, binding v3, provisional mode, PQ-B/PQ-C, session selection) is **an assumption, not a verified property** (A1, PQ-R6). ProVerif covers M-1, M-2, M-3, M-6 step (3), M-7 structure; **M-4 is an unwritten argument, M-5 (session selection) has no model.** The external cryptographic review (Q57, ADR-38 point 3) has not happened. | declared (L7-D24) | `protocol/models/dm/README.md`; design §9.5, §22.18; `THREAT_MODEL` A1 |
| KI-DM-2 | The crate reads **and writes** vodozemac's undocumented, unversioned serde pickle (`chainPosition`, `sessionPrune` rewrites stored state; the first-seen sidecar is a projection of the pickle). Guarded only by golden pickles per pin, `UpgradeTest` and G-R7. | declared deviation of ADR-35 | `client-core/dm/src/olm/pickle.rs`; design §2.1, §22.33 item 6 |
| KI-DM-3 | **R-T3 defect:** a TIMER_SET queued before a session exists (and a resent FAILED item) is stored with the *new* timer's TTL tier, not the larger of the two; a recipient offline over a day does not learn the change, the relay can tell a first flight's type from its TTL (P-4), and with a new 1 h timer the item can fail after an hour of establishment. NI-DM2 reproduces it and declares it without gating. Fix needs a new column in `dm_outbound_item` and a migration (owner). | open defect, reproduced | design §22.21 item 2; `LIMITE` L5 row "TIMER_SET"; T25, T29, T30 rows of INVARIANTS |
| KI-DM-4 | `send` with empty text throws out of the facade (the CHECK of `body_env` refuses the 29-byte envelope); §21.4 rule 5 calls this a defect. | open, robustness | §22.21 item 3 |
| KI-DM-5 | Memory residue: vodozemac keeps keys in memory (Least Authority 2022 issue I; declared); the JVM sees classical pair roots in clear (CRY-P9-03); Kotlin cannot erase `SecretKeySpec` clones (A-1); lock and wipe have no caller until Phase 13, so context closing is unexercised in the app. | declared / owner | L7-D19; §22.34 items 3, 20 |
| KI-DM-6 | Post-quantum residues PQ-R1..PQ-R8: classical authentication, nothing PQ inside the ratchet, first-flight FS bounded by generation erasure of up to 91 days, network metadata and relay credentials not HNDL-protected, young primitives (libcrux pre-1.0, X-Wing an Internet-Draft), Olm classical under the seal, card links over classical channels. | declared | design §9.8; L7-D24 |
| KI-DM-7 | libcrux: marked "pre-verification" by its own README; verified code covers the portable ML-KEM only, wrappers are unverified; public vulnerability reports in 2026 (ePrint 2026/192 and RustSec entries) concern libcrux and hpke-rs. The shipped build is portable-only, enforced by G-R3. | declared risk | design §9.2, `EVIDENCE_INDEX.md` section 9, `AUDITOR_RFQ.md` A1 |
| KI-DM-8 | Window limits: Olm keeps at most 40 skipped keys per chain and 5 chains per session, a message more than 40 behind is lost after the 12-minute gap hold; first message decryptable by whoever obtains the identity and generation secrets before deletion (<= 13 weeks); skipped-key prune at 51 days; a device absent for years silently loses the pair generation until its own next send. | declared | L7-D11, L7-D29 |
| KI-DM-9 | Binding v3 proves to a third party, if the recipient discloses the envelope and keys, that the sender's identity initiated a session at a minute (no deniability); the receipt upper bound tolerates sigma = 3 days of relay clock error. | declared | L7-D20, L7-D27 |

### 3.2 DM engine `:messaging` (Tier B3)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-ENG-1 | A bundle publication that ends FAILED or INDETERMINATE is not re-sealed: the owner has no bundle that week and every establishment towards them fails until the next publication time. | open, declared | `LIMITE` L5; design §22.12 item 19 |
| KI-ENG-2 | The rank of an out-of-schedule publication (restore) is always 1, so a restored device's bundle can lose a tie to the lost device's for up to a week. | open, declared | §22.11 item 6, §22.13 item 18 |
| KI-ENG-3 | A control (reconnect, revocation) that ends FAILED is not rescheduled; design §21.8 point 4 asks for up to 3 retries and schema v5 has no attempts column. | open, declared | §22.13 item 9 |
| KI-ENG-4 | Refusal cadence: a refused deposit is retried by KEEPER on every time-triggered pass and by SEND on every user send, up to two refused deposits per relay per foreground session until the message deadline (1,794 refusals for one message measured in SCN-E). | measured, **owner decision** (three variants) | §22.25 items 4, 5, 14(j) |
| KI-ENG-5 | An operation with a possible copy (timeout after apply) lives past its deadline until a check resolves it: towards a recipient who never returns the message stays "sending" until about `copy_hour` + 30 days; relays see the checks. | open, **owner decision** | §22.25 item 14(a) |
| KI-ENG-6 | The redeem hold (Q29) is armed by LOCAL DM write needs too (a refused or exhausted deposit credential), so a background session's length, which relays see as circuit-open time, can depend on DM state. Read from code, never run: JD8's twins have no such need. | open, **owner decision** | §22.26 item 14; `LIMITE` L5 |
| KI-ENG-7 | JD8 compares redemptions at session granularity, registrations at the minute; the minute of a redemption cannot be tested in this harness (twins share random draws in call order). T27's wording says "minute". | narrowed, **owner decision** | §22.26 items 3, 10 |
| KI-ENG-8 | A revocation that arrives while a contact is re-establishing does not stop the remaining fetch windows (up to two more of the three); effects of a session renewal are written before the R9/R10 checks. | open | §22.19 item 14(h) |
| KI-ENG-9 | Release R8 removes the DM facade from today's release APK (nothing in `:app` calls it), so G-DM5 and the release smoke test speak for a cut-down graph; no device run executes `MessagingWiring.onDatabaseOpen`, `ensureStack`, `GhostApp.dmStack` or the runtime-scheduled alarm. | declared | §22.34 item 23 (A-4) |
| KI-ENG-10 | Measurements not made: the hint benchmark for 1,000 contacts (V-13, Q37) and timings on the reference low-end device (design §15.10 step 9). | open | `LIMITE` L5 |

### 3.3 Android platform, identity and storage (Tier B2, B4)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-AND-1 | The SQLCipher database is under `databases/`, **not** `no_backup/`: `sqlcipher-android` 4.19.0's `SupportOpenHelperFactory` ignores `noBackupDirectory(true)`. Backup exclusion relies on `allowBackup="false"`, `data_extraction_rules.xml` (cloud backup and device transfer) and `backup_rules.xml` excluding the `database` domain. Phase 4/7 text (T4) said otherwise; the KDoc was corrected. T4 (inspection of a real backup) has not been run. | observed, declared | design §22.32 item 5(c) |
| KI-AND-2 | One SQLite error line appears at every database open (`database table is locked; [PRAGMA wal_checkpoint(TRUNCATE)]`); the truncation still succeeds in about 5 ms. Why the first step is `LOCKED` was not established. The line carries SQL text only. | observed, owner call | §22.32 item 10 |
| KI-AND-3 | Keystore: only the emulator's **software** Keystore was exercised (StrongBox refuses); wrappers are not user-authentication-bound; the identity root is unwrappable by an attacker with the unlocked app (AD-8). Phase 3 device test for the Keystore wrapper is still pending. | declared | `docs/STATUS.md` Phase 3 row; L1; §22.32 item 12 |
| KI-AND-4 | Residues outside SQLCipher: one periodic job entry (`dumpsys jobscheduler`), one inexact alarm whose label and **cancel time stay in `dumpsys alarm`'s removal history from Android 13 until reboot** (no root needed), and OS per-UID network and battery statistics (volume per 2-hour interval, job durations). A wipe cannot erase them. | declared | `LIMITE` L1.1 last rows; §22.34 item 24 |
| KI-AND-5 | Wipe and lock have no caller before Phase 13; `awaitIdle` semantics for the wipe flow were fixed in Phase 8 but nothing in production closes the database. | declared | Phase 8 review AND-P8-2; STATUS |
| KI-AND-6 | Fixed in the Phase 9 review but worth re-testing: `androidx.emoji2`'s `EmojiCompatInitializer` shipped from Phase 7 to Phase 9 and told the system font provider (Google Play Services on GMS phones) that the app started with UI (A-3). `merged-manifest-lint.sh` now allowlists `androidx.startup` initialisers. | fixed `707958a` | review A-3 |
| KI-AND-7 | Phase 3 and 4 device tests (Keystore, real SQLCipher open, T4 backup inspection), and Phase 7's device checklist (design §8.9: `SyncJobService` binding on API 29 and 37, persistent job after reboot and force-stop, inventory after wipe, real Tor foreground and background, `am kill` loops) have not been executed on devices. | open | `docs/STATUS.md` rows 12, 13, 16 |

### 3.4 `:sync` and `:entitlement` engines (Tier B3)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-SYN-1 | NFR-1 (DM p95 under 5 s) is **not met by design** with the 30 s listing interval (estimated about 40 s in the foreground, hours in the background); NFR-5 (battery) unmeasured. | declared | ADR-20 point 5; L2.1 #5 |
| KI-SYN-2 | A single `malformed_response` or two `not_found` from a relay make that source `bad` for a blob; without another candidate the blob is `unavailable` on that relay (transient honest errors lose that copy). | accepted | `LIMITE` L5 |
| KI-SYN-3 | All pairs of a client start together at session start (30 s foreground, 90 s per background job): relays see co-occurrence; reads of one namespace are linkable through capability scope and cursors. | declared | L2.1 #1-#2; L7-D2 |
| KI-ENT-1 | Tokens and credits are device-local bearer value, **not recoverable from the seed** (E11); a restore scans only invites 0..7 for five weeks (E32). | declared | L6 |
| KI-ENT-2 | Invite-only is a client rule: a modified client can buy without an invitation (E27). | declared | L6 |
| KI-ENT-3 | The optional check of the device clock against the Tor consensus (`CLOCK_UNTRUSTED`) is not implemented (Arti 0.46 exposes the consensus lifetime only under an experimental API); a device skewed by over 4 h reveals its skew to the issuer at the first call carrying `base_week` (E14). | accepted | L5, L6 E14 |
| KI-ENT-4 | Behaviour under Doze of quiet runs, scanning the 876-character invite QR, and the added pairs fitting Phase 7 budgets are assumptions checked on the JVM only. | assumed | design `faza8-issuer.md` Appendix D |

### 3.5 Client network core, JNI, Tor (Tier B1, A4)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-NET-1 | Onion-service proof-of-work (Prop 327) is not solved by the Arti client build (`hs-pow-full` experimental): under an introduction flood GHOST clients get no priority. | accepted | `LIMITE` L5 row 1; ADR-01 |
| KI-NET-2 | Bridges are simple lines only until Phase 12 (obfs4, webtunnel, snowflake refused explicitly); a simple bridge hides the guard, not the fact that the traffic is Tor. | known | L4, L5 row 2, AD-4 |
| KI-NET-3 | Each background job creates a fresh transport and a Tor bootstrap, a temporal fingerprint for the ISP. | declared conflict | L4 "Conflict (Faza 7)" |
| KI-NET-4 | Relay RPCs are plain HTTP/2 inside the onion stream (`relay_client.rs`): credentials and namespaces are not HNDL-protected. | declared | PQ-R4 |
| KI-NET-5 | The live Tor test (circuit isolation on real circuits, empty keystore) is a manual job (`live-tor`), last recorded on the Phase 6 commit `cd145fc`; the Phase 8 issuer-flow scopes are covered by it only in design; a local Windows run stalls at bootstrap (green on Linux). | partial | `docs/STATUS.md` Phase 6 row |
| KI-NET-6 | The premise "READY implies the device clock is within +-3 days" comes from Arti; a skew below 1 h is inside tolerance (sigma = 3 days). | assumed | L5 sync row |

### 3.6 Relay (Tier C1)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-RLY-1 | The quota ledger and the deposit ledger are in memory: an over-quota write can happen once per restart per capability lifetime (E29). | declared | L6 E29 |
| KI-RLY-2 | Losing the whole data directory while keeping the onion keys lets the relay accept a second redemption of already redeemed tokens for up to two open weeks; operators must start with `--nullifiers-reset`, and tokens of refused weeks are lost (E20). `nullifiers.redb` must never be restored from an old backup (runbook O1). | declared, operational | L6 E20 |
| KI-RLY-3 | `keys.redb` is rebuilt by owners; losing it refuses deposits until owners re-register in their next session. | by design | `relay/README.md` |
| KI-RLY-4 | Gossip is off by default: relays do not authenticate each other (Noise between relays is unscheduled; the old "Phase 10" reference is a spec-v2.0 numbering error, X-10 of the Phase 10 design). | known | `relay/README.md`; `faza10-forum.md` X-10 |
| KI-RLY-5 | No deployment on three independent operators (staging run by one party, operator ids are labels), no staging T1 capture, no NFR-3 load test. | open | `docs/STATUS.md` Phase 5 row; `protocol/entitlement/README.md` |
| KI-RLY-6 | The ES in `main` is stagenet **seq 1**, access weeks 2957..2989 (ISO 2026-W37 to 2027-W16); a release embedding it must ship by week 2964 (Monday 2026-10-26); seq 2 must reach releases and operators by week 2982 (Monday 2027-03-01). Audit staging after those dates needs a build carrying a later ES. | operational, dated | `ghost/protocol/entitlement/README.md` |

### 3.7 Issuer and entitlement cryptography (Tier A3, C2)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-ISS-1 | **ADR-22 to ADR-26 are "propus, aplicat"**: applied in code, awaiting the owner's decision; Q1 and the defaults of Q2-Q36 were applied "unless the owner objects". | owner decision | `docs/adr/README.md`; STATUS Phase 8 row |
| KI-ISS-2 | The signer runs on the pre-release `rsa 0.10.0-rc.18` / `crypto-bigint 0.7.5` through `blind-rsa-signatures =0.17.2`. The cargo-deny exception for RUSTSEC-2023-0071 (Marvin attack, no patched version) rests on: payment-gated signing, `CheckedSigner` fault check, a 2 s reply quantum, and a nightly Welch t-test showing the private-key operation's time independent of the blinded value (Welch t-statistic about 1.5 in absolute value on CI, issue #1). The unblinded CRT exponentiation is **not** constant-time in its base. Re-review when rsa 0.10.0 is final. | accepted risk with mitigations | `deny.toml`; design `faza8-issuer.md` §2.8, §19.30; Phase 8 review "re-verify the timing evidence" |
| KI-ISS-3 | The K1 key ceremony with the real offline key has not happened (stagenet keys only, generated outside the repository); the first mainnet ES needs it (Phase 16/17). | owner action | `protocol/entitlement/README.md` |
| KI-ISS-4 | Never run on mainnet or with real money: Monero regtest with pinned binaries only; `monerod` hard-fork and FCMP++ contingency in runbook M2; digest authentication to the Monero RPC is MD5 (the daemon's only offer); payout stations and air-gapped signing are operator procedure, not code. | known | `RUNBOOK.md` §7, §9; ADR-26 |
| KI-ISS-5 | Entitlement residues **E1-E34** (L6) are accepted, among them E8 (an active issuer can refuse service to isolate a client), E12 (token loss after compromise or reorg), E15/E16/E17 (payment timing, trigger timing, credit refresh linkage), E19 (a seized device shows the finalisation day of unused lots), E22/E23/E25/E26/E27, E28 (loss of both database and journal), E33 (newest snapshot outlives a long maintenance window), E34 (a credit holder can exhaust the refresh budget of an epoch). The Phase 8 review asks Phase 15 to re-verify E34 and the signing timing evidence. | declared | `LIMITE` L6; Phase 8 review "Note" |
| KI-ISS-6 | **T2 sweep not green on pairs 2, 3 and 9**: pair 3 `NI-1d` (drop writes differ at write 3), pair 9 `NI-1 across cells` (relay calls differ before the activation cell); the investigation concluded pairs 2 and 3 are not harness artefacts (write position in session, coverage rule for the invitee) and pair 9 is a design question (E15 against S3d). Pairs 1, 4, 5 and the rest pass after harness fixes (§22.28). | open, **owner decision** | design `faza9-dm.md` §22.24 item 9, §22.28; `LIMITE` L5 "T2 după §4.9" |
| KI-ISS-7 | Harness limits: mining only at payments (chain never advances with time in JVM scenarios); T2c does not see the renewal deferral; the T2 world runs release profile only (debug ignores it). | declared | Phase 8 review "Deschise" |

### 3.8 MLS channels (Tier A2; Phase 10, not on `main`)

Design-level residues only, until code lands. Source: `faza10-forum.md` §0.2, §0.4, §3.7, §19.27-§19.29, `LIMITE` L8 (to be written).

* **Classical suite only (0x0003), no post-quantum claim** for channels (D3); X-Wing suite deferred (64 KiB blobs, cap about 38-46 members).
* **Forks**: concurrent commits resolve by a deterministic rule without a server; a removed committer's capture of an invitee is a live fork detectable only by comparing the epoch-authenticator fingerprint out of band (Q49, L8-C25); a relay partition that keeps branches apart is not detectable in-band (RFC 9750 §5.2).
* **Password-sealed invites** (Q43-Q50): Argon2id RFC 9106, no PAKE; a leaked link allows offline guessing at the KDF cost (154-160 guesses per second on the measuring host's 24 threads, probe E-73); the password does not bind members who can invite (Q46); the sponsor's phone retains the link (Q50).
* **Storage adapter** edits OpenMLS's serde layout (two recorded deviations: `added_at` day rewrite, one row per past epoch); a missing field is `STATE_CORRUPT`; golden `MessageSecrets` guards each pin (G-M7). OpenMLS advisories are not in RustSec (checked by a GHSA watch, G-M1).
* **Library facts**: OpenMLS audited by SRLabs (2025-26) excluding providers; `hpke-rs` (MPL-2.0) and libcrux providers outside that audit; 53-method `StorageProvider` adapter, S1-3 "state and storage diverge on a failed write" answered by value semantics.
* Unmeasured: adapter cost on low-end devices (E-22 assumed); the harness pieces Phase 9 designed but never built (seeded native randomness, redeem lane inside the world, HIGH mode, circuit timing) are work items of the Phase 10 slices S1-S2 (§19.10).

### 3.9 Privacy evidence and harnesses (Tier A5)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-PRV-1 | The Phase 2 exit gate, **independent review of the threat model and the privacy harness, is open**; Phase 12's gate ("review independent al capturii de metadate") is open. Every review so far is by AI agents. | open | `THREAT_MODEL` §10; plan rows 2, 12 |
| KI-PRV-3 | T32 limits: the worlds do not model HIGH mode, key changes, restores, clock offsets or the slot-table change; one seed in the PR report; the JD8 twins have 0 and 4 contacts, not 30; PM-27/28, NI-DM6 and others unbuilt; the checked-in gate report fixture is assembled. | declared | design §22.16 points 10-15, §22.26, §22.38 item 22 |
| KI-PRV-4 | T1 on **staging** relays (runbook O1 "Staging în modul capture") never ran; the two-node suite's capture is the only real T1 evidence. | open | INVARIANTS T1 row |
| KI-PRV-5 | S-DM2 (attacker AUC 0.5621) and S-DM4 (0.8769 and 0.0029 bits) are **measured and reported, not claimed away**; their baselines are re-recorded from one PR-scale world (seed 5eed0001) with a +0.02 rule; relays' view of DM timing is the declared LD. | declared | design §22.30, §22.36 |
| KI-PRV-6 | T3 canary scanning of all process outputs is not built; the logcat scan exists in the device suite and ran on the emulator. | partial | INVARIANTS T3 |

### 3.10 Supply chain, CI and process (Tier D)

| ID | Item | Status | Pointer |
|---|---|---|---|
| KI-SUP-2 | **Commits are not signed** (FR-8.1 gap, STATUS); GitHub Free gives no branch protection for the private repository, so a red job blocks nothing and pushes go straight to `main`. | known | `docs/STATUS.md`; review GATES-4 |
| KI-SUP-3 | **CI runs on the owner's laptop** (four self-hosted runners in WSL2, active while the laptop is awake): anyone who can push a branch can run code there (`ci.yml` runs on `pull_request`; a workflow can be modified on the branch); `runner` has passwordless sudo and Docker access in the distro. Never grant an auditor write access to the GitHub repository (GitHub personal-account repositories cannot grant read-only collaborator access: https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-user-account-settings/permission-levels-for-a-personal-account-repository , accessed 2026-10-03). See `BUILD_AND_REVIEW_GUIDE.md` section 1. | known | `docs/ci-self-hosted.md` section 10 |
| KI-SUP-4 | Gradle verification: `verify-signatures = false`; every `.pom`/`.module` and the `aapt2` jar are trusted by rule (GATES-5, open). Rust: name-based allowlist (417 names), exact lock versions per graph, no per-crate source review of the 633 third-party packages in `Cargo.lock` (651 including GHOST's 18). | known | `verification-metadata.xml`; review GATES-5 |
| KI-SUP-5 | Text gates have **declared evasions** (names built at run time, reflection, aliases in modules a gate does not read, code that exists only after compilation, JVM errors swallowed without a catch); 26 of 27 reviewed evasion classes are closed, the rest declared. Older gates (`kotlin-clearnet`, Kotlin half of `no-logging`, `anti-placeholder`) still read Kotlin a line at a time. | declared | design `faza9-dm.md` §22.33 item 16 |
| KI-SUP-6 | Reproducible only at the same build path; no fixed-path builder, no auditor rebuild (T12b), no transparency log, no updater, no release signing or SBOM per release; ADR-38's package does not exist. Binaries are therefore trusted on the vendor's word (AD-V, L-SRC). | known | `LIMITE` L-SRC; ADR-37/38 |
| KI-SUP-7 | Public-era history: the repository was public from 2026-09-10 to 2026-09-16 (118 commits up to `3edf9dd`, published under `MIT OR Apache-2.0`). ADR-39 (2026-09-16) inventoried 348 Actions artifacts, 331 of them from runs of public commits (37 unsigned release APKs, 33 native-library bundles), and made their deletion an owner action. On 2026-10-04 the GitHub API (`gh api repos/MihaiCatalinVoicu/GHOST/actions/artifacts`) lists 98 artifacts, all created 2026-10-01 to 2026-10-03, so the public-era artifacts are no longer there (deleted by the owner or otherwise; the repository does not record it); copies taken while the repository was public cannot be recalled. Counsel review of the public history is open (ADR-37 point 10, ADR-39 point 2); onion keys of the staging relays should be rotated if used beyond staging. | owner actions (artifact deletion: done, inferred) | `docs/adr/ADR-39-private-repository.md`; `docs/design/faza9-s0-hygiene.md` §2, §9 |
| KI-SUP-8 | The Actions artifact storage quota was exhausted from 2026-09-20; uploads were made non-fatal (`continue-on-error`) on 2026-09-26 and the native-library hand-off between jobs moved to the Actions cache. Gate reports are kept for 3 days (`retention-days: 3`). On 2026-10-04 the API lists 98 artifacts (258 MB) created 2026-10-01 to 2026-10-03, so uploads work again (the cause is not recorded). Consequence: **gate evidence disappears after 3 days**; the owner should archive the reports at the freeze tag. | known | design §22.33 item 2; `docs/ci-self-hosted.md` §6 |

---

## 4. Owner decisions still pending (non-exhaustive index)

| Phase | Decision | Where |
|---|---|---|
| 9 | The eight review items (section 2); G-DM3: confirm the motivated allowlist (three HMAC sites and the content key's `SecretKeySpec`, applied as default) or introduce dedicated key types; the TIMER_SET column (KI-DM-3); empty-text facade (KI-DM-4); refusal-cadence variant (KI-ENG-4); possible-copy-past-deadline rule (KI-ENG-5); redeem-hold scope (KI-ENG-6); "minute" versus "session" in T27 (KI-ENG-7); T2 pairs 2, 3 and 9 (KI-ISS-6); Q36 (owner-bound read rule, default: Phase 12), Q69 (bundle-fetch visibility floor, default: Phase 12), Q70 (reduced reply card, default: Phase 13); retention of gate evidence (KI-SUP-8); a runner with KVM; two phones; staging relays in capture mode; **reviewers for the external cryptographic review (Q57)** | `faza9-dm.md` §19, §22.21-§22.26, §22.34; STATUS |
| 8 | ADR-22..26; K1 ceremony; staging deployment; device checks of design §11.9; live-tor with issuer flows; re-measured CI budgets on the runners; acceptance of E1-E34 | STATUS Phase 8 row |
| 10 | Approved with defaults (Q1-Q50). Pending only in the sense that implementation is unfinished. | `faza10-forum.md` Status |
| 11, 13, 14 | Designs "proposed, not approved" (Q38 timing of channel media; 54 questions and 11 owner actions in Phase 13; 47 questions and 10 owner actions in Phase 14, including the application id `org.ghost.app` naming a domain the project does not own and Google developer verification affecting the onion mirror) | `faza11-media.md`, `faza13-ux.md`, `faza14-distribution.md` |
| Process | Sign commits; (public-era artifacts: apparently deleted, KI-SUP-7); counsel review of the public history (ADR-37 point 10); rotate staging onion keys if reused; per-release SBOM; licence screen before any distribution (Phase 13) | ADR-37, ADR-39 |

---

## 5. Declared residual risks: index

`docs/LIMITE_REZIDUALE_SI_MITIGARI.md` is the authority; counts at the base commit:

| Family | Rows | What it covers | Most relevant to an auditor |
|---|---|---|---|
| L1, L1.1 | about 11 mitigation rows + 20 local-residue rows | Compromised device; what a seized/unlocked database, job entries, alarms and OS statistics reveal | Dedup tombstones, un-consumed ciphertext, token `eligible_minute` (E19), open purchase rows, DM tables, alarm removal history |
| L2, L2.1 | about 8 + 6 | Global passive adversary; sync co-occurrence, cursor-as-cookie, volume follows activity, NFR-1, capacity limits | Capacity caps (BACKLOG_CAP 4,096, FETCHED_CAP 256, 8/32 fetches per event) |
| L3 | prose + tables | Malicious group member; flags/strikes design (ADR-13, P1, Phase 10/13) | Mostly future |
| L4 | 7 | ISP sees Tor; bridges; periodic bootstraps | |
| L5 | 31 rows | Implementation residues (Phases 6-9) | Rows listed in section 3 |
| L6 | E1-E34 | Entitlement residues with the declared leak L1-L7 (activation slot day, coverage end week, immediate calls, purchase type, quiet-run gaps, first payment sighting, post-exhaustion purchase) | KI-ISS-5 |
| L-SRC | 1 | Closed source: no user-verifiable binary | AD-V |
| L7 | L7-D1..L7-D29 | DM residues: reply-timing edge reconstruction after about 6 exchanges (standard) or 8 (HIGH), TTL classes, card-holder powers (D3, D16, D25), restore losses, forensic residue (D7), PQ residues (D24), generation lifetime (D11), absent devices (D29) | Estimated figures are *model estimates, not measurements* (S-DM2/S-DM4 are the measured part) |

---

## 6. Assumptions registered as unverified (Appendix C / D style)

| Design | Assumption | Status |
|---|---|---|
| F9 A16 | Hint computation for 1,000 contacts (at most 22 recognition keys each) meets the 1 s foreground budget per 16-blob batch on a mid-range phone | Not measured (V-13) |
| F9 A17 | The emulator action works with API 29 and 35 images and KVM on the CI runner class | **False today**: no KVM, job red |
| F9 low-end timing | X-Wing/ML-KEM timings on the reference low-end phone (15-25x slower than the host) | Estimated from host figures; not measured |
| F8 App. D | Quiet runs under Doze behave as modelled; QR version 21-L holds the 876-character link and phones scan it; the signer takes at most 5 ms per signature on the runner; Arti exposes the consensus lifetime (**no**, accepted as E14); watch-only wallet `freeze` behaviour and `store-tx-info` handling (regtest steps 16b/17) | Device items open; regtest items covered by `monero-regtest` per the design |
| F10 E-22 | Adapter cost acceptable on low-end devices | Assumed (host and x86_64 emulator measured) |
| THREAT_MODEL A1-A8 | See `AUDIT_SCOPE.md` section 6 | Assumptions by definition |
| F7 | Relays cannot forge blobs (hash and bucket check); for liveness at least two honest reachable operators; SQLite atomic commit on SQLCipher | Honest-relay assumption by design; SQLCipher atomicity untested on devices |

---

## 7. Inconsistencies in the project's own documents that an auditor will meet

* **Numbering**: guarantee identifiers repeat across phases (`P-1..P-7` in the Phase 8 design, `P-1..P-8` in Phase 9, `P-C1..P-C6` in Phase 10). `AUDIT_SCOPE.md` section 7 prefixes them (`F8 P-n`, `F9 P-n`).
* **Mutant counts** differ by document and date: T2 privacy mutants 23, 24, 25, 26 in different sections (the report check requires 26); DM correctness mutants 13, 15, 16, 26 over time (the design's target is 57 correctness + 40 privacy = 97).
* **Precedence**: in `faza9-dm.md`, §22.x overrides §0-§21 and a later §22 note overrides an earlier one; `faza8-issuer.md` §19 overrides §0-§18; `faza10-forum.md` §19.29 overrides §19.27-§19.28 which override earlier sections.
* **STATUS.md** is stale in places (KI-DOC-1).
* **Date style**: documents use ISO dates; some CI timestamps are UTC while the owner's machine is UTC+3.
