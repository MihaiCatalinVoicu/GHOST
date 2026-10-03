# GHOST external audit: evidence index

| Field | Value |
|---|---|
| Purpose | What has already been verified, how a reader reproduces it, and (equally important) what has **not** run. The auditor should spend time on unknowns, not re-prove what is shown here, and should not trust anything here that they can cheaply re-check. |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (2026-10-03). Product code is identical to `197b2b4` (2026-09-28), the commit most CI results below refer to (`git diff --stat 197b2b4 HEAD -- ghost .github` touches only `self-test.sh` and three workflow trigger blocks). |
| Prepared | 2026-10-03 (UTC evening) by an AI agent for the owner. |
| Companion files | `AUDIT_SCOPE.md` (what and how big), `KNOWN_ISSUES.md` (open items), `BUILD_AND_REVIEW_GUIDE.md` (commands in context). |

**Evidence labels used below**

* **[R]** re-run for this package on 2026-10-03 on the base commit, command and result given.
* **[D]** documented in the repository (document, section, date, commit); not re-run here.
* **[C]** a CI run on the owner's self-hosted runners, identified by GitHub run id (`gh run view <id> --repo MihaiCatalinVoicu/GHOST`; CI is advisory only, see section 3).
* **[X]** external source, with URL and access date.

Every reviewer named in this repository is an AI agent (the review documents say so); **no human external review has taken place**, and the Phase 2 exit gate (independent review of the threat model) is still open.

---

## 1. Re-run for this package [R]

Constraint of this task: documentation only, no builds. Therefore nothing below compiles Rust or runs Gradle.

### 1.1 Static gates: `run-all.sh` (18 gates), base commit

Linux, in the `ghost-runner` WSL2 distribution (the CI runner image: Ubuntu 24.04), on a `git archive` of `a0f3f58` copied to `/tmp` (no `.git`), each gate run as `bash ghost/scripts/gates/<gate>.sh`:

| Gate | Result | Time | Gate | Result | Time |
|---|---|---|---|---|---|
| anti-placeholder | OK | 3 s | kotlin-clearnet | OK | 2 s |
| no-logging | OK | 4 s | no-public-binaries | OK | 0 s |
| issuer-output | OK | 4 s | dm-jni-surface (source halves) | OK | 2 s |
| monero-pin | OK | 1 s | dm-no-fts | OK | 21 s |
| manifest-lint | OK | 0 s | dm-enqueue-callers | OK | 13 s |
| dependency-allowlist | OK | 0 s | apk-no-debug-hooks (source half) | OK | 15 s |
| sync-no-catch-all | OK | 1 s | workflow-yaml | OK | 3 s |
| messaging-no-network | OK | 1 s | dm-no-replace | OK | 2 s |
| dm-derivation-inputs | OK | 2 s | **proto-check** | not run on Linux (no `protoc` in the distro); **OK on Windows** with protoc 36.0 in 14 s | |

Result: **18 of 18 OK** (17 on Linux, 75 s wall; `proto-check` on the Windows checkout). The first attempt to run the whole script in Git Bash on the loaded Windows workstation had not finished its second gate after 17 minutes and was stopped (process start-up on Windows is the bottleneck; the design documents record 30 to 45 minutes there).

### 1.2 Gate self-test: `self-test.sh` (proves each gate rejects its negative fixtures)

Linux (same distro and tree), `bash ghost/scripts/gates/self-test.sh`, 15 min 39 s (20:26:19Z to 20:41:58Z):

* **649 cases `self-test ok`, 0 `SELF-TEST FAIL`, exit 0.**
* Two blocks were **skipped by the script itself** because the tools were not on the ad-hoc shell's `PATH`: the `proto-check` cases (`protoc` absent) and the whole Rust block (`cargo` absent), which also holds the `cargo-deny` bans cases. So this run is *not* comparable with the last complete run, **654 cases at `f2792a7`** (2026-09-26, 145 minutes on Windows with `GHOST_YAML_VIA_WSL`, design `faza9-dm.md` §22.33 item 18). Later sections record 664 to 672 cases in partial sessions (§22.37 item 11, §22.38 item 21) and say the full self-test was not run in their sessions.
* In CI, the full self-test is the last step of the `static gates` job; at `197b2b4` exactly one case failed there (G-R7 "fails closed on an unreadable base", a shallow-checkout artefact), fixed in `a0f3f58`.

### 1.3 Static counts (no execution)

| Count | Command | Result |
|---|---|---|
| Rust test attributes | `git ls-files '*.rs' \| grep -v test-harness/gates \| xargs grep -c -E '^\s*#\[(test\|tokio::test)'` summed | **892** (844 in the main workspace, 48 in the separate `mls-spike` workspace) |
| Kotlin `@Test` | `git ls-files 'ghost/android/*.kt'` in `src/test`, `androidTest`, `testShared`, `gate`, `deviceRunner`, `equivalence`, `grep -c '@Test'` summed | **1,260**: unit tests `app` 52, `crypto-bridge` 64, `entitlement` 202, `identity` 65, `messaging` 329, `network` 24, `storage` 187, `sync` 329 (= **1,252**), plus 8 in `androidTest` (`app` 1, `crypto-bridge` 1, `messaging` 6) |
| `unsafe` in GHOST production Rust | `grep -n -E '\bunsafe\b'` over tracked non-test `src/*.rs` of `client-core/{dm,net,dm-host}`, `relay`, `issuer`, `test-harness/privacy` (comment lines and `forbid/deny(unsafe_code)` excluded) | **0** (`forbid(unsafe_code)` present in `ghost-client-dm`, `ghost-dm-host` and six issuer files) |
| Lock size | `grep -c '^\[\[package\]\]' ghost/Cargo.lock` | **651** packages; shipped graphs 455 (client library), 113 (relay), 136 (issuer) components (`ghost/licenses/THIRD_PARTY_NOTICES-*.txt`); 66 JVM libraries in the APK; 332 components in `verification-metadata.xml`; 417 names in the client Rust allowlist |

The static Kotlin counts equal the last recorded executed JUnit counts module by module (section 2.1), which is mild evidence that no test was added or removed without a run, not evidence that they pass.

### 1.4 CI history read from GitHub [R]

`gh run list --repo MihaiCatalinVoicu/GHOST --branch main --limit 100 --json ...` and `gh run view <id> --json jobs` / `--log-failed`, read-only, 2026-10-03. Section 3 tabulates the result. On 2026-10-04 the artifact listing was read as well (`gh api repos/MihaiCatalinVoicu/GHOST/actions/artifacts`, metadata only, nothing downloaded): 98 artifacts, 258 MB, all created 2026-10-01 to 2026-10-03 with a 3-day expiry (`KNOWN_ISSUES.md` KI-SUP-7, KI-SUP-8). Runs started after the first read (pushes of 2026-10-03 evening) were still in progress and are not used here.

### 1.5 What I did not run, and why

`cargo test/clippy/deny/audit`, `build-native.sh`, any Gradle task, ProVerif, the fuzzers, the T2 and T32 worlds, the emulator, the device checklist: the task forbids builds, and several take hours (T32 PR scale about 35 to 60 minutes of Gradle; T2 gate pair 94 to 123 minutes on the runners; the `android` CI job 56 minutes). For these the numbers below are the **most recent recorded** ones, with source and date.

---

## 2. Test suites and counts at (or just before) the base commit

### 2.1 Unit, integration and harness suites

| Suite | Command (from the repo root) | Last recorded result | Source |
|---|---|---|---|
| Rust workspace | `cd ghost && cargo test --locked --workspace` | **836 passed, 0 failed, 63 ignored**, 116 test binaries (with doc-tests); `fmt --check` and `clippy --workspace --all-targets -D warnings` clean | [D] design `faza9-dm.md` §22.33 item 18 and the Phase 9 review "Verification", Windows 11, 2026-09-26, tree `p9-integ2` at `42cf4b9`. [C] CI `rust` job success at `197b2b4`, run 36434212692 (34 min). Not re-run here. |
| `ghost-client-dm` | `cargo test -p ghost-client-dm` | 191 library tests (192 with `test-vectors`) plus integration tests, all green | [D] §22.37 item 7 |
| JVM unit tests, all modules | `cd ghost/android && ./gradlew build -Dghost.dm.native=<ghost_dm_host lib>` (see guide §3) | `app` 52, `crypto-bridge` 64, `entitlement` 202, `identity` 65, `messaging` **329**, `network` 24, `storage` 187, `sync` 329: **1,252 tests, 0 failures, 0 skipped** | [D] `messaging` 329 on the real AGP build 2026-09-28 (§22.38 item 23(g)); `sync` 329 (§22.36 item 12); the rest 2026-09-26 (§22.33 item 18). [C] CI `android` job success 2026-09-28, run 36434212692 (56 min). **Trap:** without `-Dghost.dm.native` the DM tests silently skip; always check `skipped=0` in the JUnit XML (`<module>/build/test-results/**/TEST-*.xml`). |
| Sync exit gate | `./gradlew --no-daemon :sync:testDebugUnitTest --rerun -Dghost.sync.seeds=20000 -Dghost.sync.exhaustive=full` | Green on the runner (12 min of job time) | [C] CI `sync exit gate`, run 36434212692 |
| Entitlement exit gate | `./gradlew :entitlement:testDebugUnitTest --rerun -Dghost.entitlement.seeds=… -Dghost.entitlement.exhaustive=full -Dghost.entitlement.shard=i/12` | Green nightly (12 shards) | [C] run 36993289276, 2026-10-02 (nightly, `197b2b4`) |
| DM messaging exit gate | `./gradlew :messaging:testDebugUnitTest --rerun -Dghost.dm.native=… -Dghost.dm.crash=full -Dghost.dm.seeds=64 -Dghost.dm.privacy=off`, then `dm-report-check.sh <report> gate` | Green nightly, job 5 h 7 min, `[dm-report-check] OK (gate)` | [C] run 36993321790, 2026-10-02 |
| T2 PR variant | `cargo test -p ghost-issuer --release --locked --test t2_unlinkability t2_pr_variant -- --exact`, then `t2-report-check.sh <report> pr` | PASS (N = 300, 21 days) | [C] inside `ci` `rust` job, 2026-09-28 |
| T2 gate scale | `GHOST_T2_SCALE=gate GHOST_T2_SEEDS=<pair> cargo test -p ghost-issuer --release --locked --test t2_unlinkability t2_exit_gate -- --ignored --exact`, then `t2-report-check.sh … gate` | Pair 0: PASS (push run 36434212670, 2026-09-28). **Nightly sweep over ten pairs: 7 pass, pairs 2, 3 and 9 fail** | [C] run 37108461415 (2026-10-03): pair 9 `NI-1 across cells` ("relay calls differ before the activation cell"), pair 3 `NI-1d` ("drop writes differ at write 3") |
| T2 mutants | `cargo test -p ghost-issuer --release --locked --test t2_mutants -- --ignored`, then `t2-report-check.sh … mutants` (requires all 26 privacy mutants detected) | Green with the nightly | [C] job `mutants` of the same runs |
| Monero regtest | `monero-regtest.yml` (pinned `monerod`/`monero-wallet-rpc` v0.18.5.1 by SHA-256) | Green nightly | [C] run 37109290947, 2026-10-03 |
| Signer timing | `signer-timing.yml` (Welch t-test on `CheckedSigner`, nightly) | Green nightly (Welch t-statistic at most 1.5 in absolute value on CI per design `faza8-issuer.md` §19.30) | [C] run 37112903139, 2026-10-03 |
| Live Tor | `cargo test -p ghost-client-net --locked --test live_tor -- --ignored --nocapture` (manual job `live-tor`) | Last recorded run: 34585120238 on commit `cd145fc` (Phase 6: circuit isolation on real circuits, empty keystore after bootstrap); skipped in every `ci` run since | [D] Phase 6 review; **not re-run**; Phase 8 issuer-flow scopes and Phase 9 not covered by a live run |

### 2.2 Gate scripts

`run-all.sh` 18 gates OK ([R] above); `self-test.sh` 654 cases OK at `f2792a7` ([D]) and 649 OK with two blocks skipped at the base commit ([R]).

### 2.3 Emulator and device

| Item | Result | Source |
|---|---|---|
| Device suites on an x86_64 AOSP emulator, **API 29 and API 35**, local Windows workstation, commit `84fd5f5`, 2026-09-24 | `crypto-bridge`: 1 test, host/Android equivalence **108 of 108 cases byte-identical** with the control detected; `messaging`: 6 tests (migration v3 to v5 on real SQLCipher, SCN-A, SCN-B, SCN-F with WAL at 0 bytes, alarm schedule/cancel, SCN-D with 5 canaries); `app` smoke: release variant, one in-process Olm session, no transport; all 0 skipped; `dm-emulator-check.sh <dir> 29 35` answers OK | [D] design §22.32 |
| `dm-emulator.yml` on a runner | **Never ran past its KVM step** (runner without KVM; "not run" is red by design); red every night | [C] e.g. run 37108821939 |
| Physical devices, two-device checklist (design `faza9-dm.md` §15.10), arm64 execution, hardware Keystore, StrongBox, Doze behaviour, alarm firing, notifications, OEM variants, live Tor on a device | **Not done** | [D] §22.32 item 12, §22.34 |

---

## 3. CI picture at the code of the base commit [C]

Runners: four self-hosted runners in a WSL2 distribution on the owner's laptop, active only while the laptop is awake and logged in (`docs/ci-self-hosted.md`). GitHub Free offers no branch protection for this private repository: **a red job blocks nothing**; commits go straight to `main`. Read 2026-10-03 with `gh`. "197" means the product code of `197b2b4`.

| Workflow | Trigger | Latest result on this code | Run id and date | Reading |
|---|---|---|---|---|
| `ci` (push) | push, PR, manual | **Failure of one job, five jobs success** | 36434212692, 2026-09-28 | `static gates` red at step "gates must reject the negative fixtures": one case (`dm-golden-lock fails closed on an unreadable base`) failed because the shallow checkout lacks the base; `rust` pass (34 min), `android native libs` pass, `android` pass (56 min), `reproducible release build` pass (6 min), `sync exit gate` pass, `live-tor` skipped (manual). Fixed by `a0f3f58`, which was not on `origin/main` when checked (its latest runs, for `d1a19cd`, were still in progress with `static gates` already red). |
| `messaging-exit-gate` | push (code paths), nightly | pass nightly | 36993321790, 2026-10-02 | Gate scale (crash at every event, 64 seeds), 5 h 7 min; earlier red only at artifact upload (quota) |
| `entitlement-exit-gate` | push, nightly | pass nightly | 36993289276, 2026-10-02 | 12 shards |
| `t2-exit-gate` | push, PR, nightly | pair 0 pass (push); **nightly FAIL** | 36434212670 pass (09-28); 37108461415 FAIL (10-03) | Pairs 2, 3 (`NI-1d`) and 9 (`NI-1 across cells`) red; the ten-pair sweep has never been green (open decisions, design §22.24 item 9, §22.28) |
| `dm-privacy-gate` | nightly | **FAIL** (all ten pair jobs) since 09-28; **pass once** (all ten, 36310990671, 2026-09-27) | 36995511199 FAIL (10-02); 37114290834 cancelled (10-03) | Fails in `DmPrivacyWorldTest.t32JoinsAndSdm3HoldOverThePrivacyWorld`; report check says "JD5 failed" (JD5 = TTL after the timer a user set). Not analysed here. The 09-27 pass predates the merge of §22.36 (privacy worlds on production's trigger mix). |
| `dm-fuzz` | nightly, manual | **FAIL** every run since the first (7 of 7) | 37110091953 FAIL (10-03) | Target `bundle` ends in `FAIL crash` after 2,118 to 114,901 executions; the other five targets pass. See section 6. |
| `dm-emulator` | nightly | FAIL (KVM) | 37108821939 | "not run is red" |
| `dm-state-models` | push, nightly | pass | 37110195190, 2026-10-03 | EM-1, EM-2 exhaustive state models |
| `monero-regtest` | push, nightly | pass | 37109290947 | |
| `signer-timing` | nightly | pass | 37112903139 | |
| `vendor-tests` | nightly, push | pass | 37105038448 | vodozemac's and libcrux's own suites |
| `pq-model` | push, PR | pass (4 successful runs 2026-09-25 to 09-28; two red runs on 2026-09-23, before the ProVerif SHA-256 was pinned: inferred from design §22.31) | 36434212771 | ProVerif 2.05 from the pinned release |
| `pq-bump` | push, PR | pass | 36434212687 | 10 source mutants of the PQ composition |

**Statements one may not make from this table:** that the Android build, the reproducible build and the Rust workspace are green *at the base commit itself* (they ran at `197b2b4`; the difference is documents and CI triggers), that any gate was green in a merge-blocking sense, or that nightly results are stable (they are produced by whatever hardware state the laptop is in; `dm-privacy-gate` jobs took 52 to 110 minutes each).

---

## 4. Crash-injection exit gates and mutant registries

"Detected" means a test or world that passes on the real code fails on the mutated code (mutants are implemented only in test source sets, or as patches applied by CI; each is checked against a control world of the same scale).

| Gate and harness | Method (from the design) | Latest recorded numbers | What it covers | What it does not cover |
|---|---|---|---|---|
| **Sync** (Phase 7), `:sync` JVM harness [D] STATUS row 7; [C] `sync exit gate` | Exhaustive crash-point enumeration of scenarios S-A..S-H, S-L in both journal modes, double crashes in WAL for S-A, S-D, S-F; seeded random worlds with hostile relays; model relay conformance-checked against `relay_semantics.txt` that the real Rust relay also replays | **45,156 single crashes enumerated** and re-checked after restart (2026-09-12); 1,000 seeded worlds (1,782 crashes, 6.0 M events) and, at the gate, **20,000 worlds** (35,647 crashes, 122.9 M events locally); mutants M1-M17 detected **17/17**; code-mutation checks stores 8/8, engine 20/20, Android 17/17; found and fixed one production defect (a background session that might never end) | OUT-1..4, IN-1..3, T19-T21 on the JVM | Plain SQLite (sqlite-jdbc), not SQLCipher; model relay; no Doze/process-kill on a device; device-only items of design §8.9 |
| **Entitlement** (Phase 8), `:entitlement` + issuer crash harness [D] STATUS row 8; [C] `entitlement-exit-gate` | Complete crash enumeration E-A..E-J on the client, I-A..I-M on the issuer with `FaultyStore`/`FaultyRail`/`FaultyJournal`, 20,000 worlds in 12 shards; 52 mutants (23 privacy, 20 issuer/relay, 9 client; 53 and 24 with M22) | Green nightly | MS-1..MS-8, flow state machines, restore scan | Real Monero only in `monero-regtest`; harness mines only at payments (design `faza8-issuer.md` §19.27) |
| **T2 privacy world** [D] INVARIANTS T2; [C] `t2-exit-gate` | Real issuer + 3 real relays + reference clients on production crypto; N = 2,000 packs, 700 trials, 84 virtual days at gate scale (N = 300, 21 days at PR scale); joins J1-J10, twins NI-1/1d/2/3, statistics S1-S4 at alpha = 0.001; **26 privacy mutants** (`t2_mutants.rs`, report check requires all 26) | PR: green. Gate: pair 0 green; sweep red on pairs 2, 3, 9 | Claim T2 and F8 P-3..P-5 against the declared leak L1-L7 | Ten-pair sweep never green; the Kotlin engine is covered by the twin `NiKTest` and 3 mutants only |
| **DM crash and correctness** [D] design §22.37-§22.38; [C] `messaging-exit-gate` | Crash scenarios SCN-A..SCN-L (+SCN-E offline recipient on the entitlement world) enumerated at every event with doubles; seeded worlds; suite cases KC/RO/RS/RP/EP/…; correctness mutants MC-*/ME-* | PR scale on the real build (2026-09-28, 329 tests): **`dm mutants: 26 run, 26 detected`** and **`dm suite cases: 18 run, 0 failures`**; gate scale nightly green (report check OK). The design registers **57** correctness mutants and a gate item requiring all of them with the 40 privacy mutants (`dm mutants: 97 run, 97 detected`); **31 correctness mutants are not run** (reasons per mutant in §22.38 item 22, e.g. MC-29 is an equivalent mutant with the pinned vodozemac, MC-22/ME-1/ME-5/ME-18 have no seam) | Engine invariants of F9 §7-§10, T25, T28-T31, T33, T34 | The checked-in `pass-gate.txt` report fixture is **assembled** (its lines copied from PR reports and enumerations), not one real gate run (§22.37 item 11, §22.38 item 21); suite cases RP1, RP2, RP10 and most of RO, KC, CB, RE, OS, RK not built (§22.38 item 22) |
| **DM privacy world (T32)** [D] §22.16, §22.30, §22.36; [C] `dm-privacy-gate` | 600 clients, 42 days, ten seed pairs at gate scale (120 clients, 14 days, one seed at PR scale); joins JD1-JD10, twins NI-DM1-7, statistics S-DM1-S-DM4, T34 seizure world, 40 privacy mutants | PR scale (production trigger mix): **82 tests, 0 skipped, 15/15 privacy mutants** (of 40); S-DM2 strongest attacker AUC 0.5621 (7-day class 0.5624), S-DM4 0.8769 and 0.0029 bits, baselines re-recorded from these only. Gate scale: green once (2026-09-27), red since | T26-T35 in part | JD10, NI-DM4..7, S-DM baselines at gate scale; HIGH mode, key changes, restores, clock offsets not modelled; **25 privacy mutants not run** |
| **PQ composition** [D] §22.20; [C] `pq-bump` | 10 source mutants (6 forms of PM-32, 3 of PQ1, 1 of PQ5) applied as patches to `client-core/dm`; PQ1 (one decapsulation per intro open) and PQ5 (the bump assertion with the RustCrypto `x-wing` oracle) | All detected; green on runner | T35 | Mutant PM-33 as a registered mutant |
| **Session state models** [C] `dm-state-models` | EM-1, EM-2 exhaustive interleavings of session convergence and seal-mode transitions (Rust `state_models.rs`) | Green nightly | Convergence, not PCS healing | M-5 has no ProVerif model |

---

## 5. Formal models (ProVerif)

Files: `ghost/protocol/models/dm/` (README, `expected.txt`, `proverif.sha256`), run by `scripts/gates/pq-model.sh` (workflow `pq-model`, ProVerif 2.05 from a pinned release, SHA-256 `4871f53c…ceabc4`).

| Model | Obligation | Proves (symbolic, Dolev-Yao) | Controls inside the model |
|---|---|---|---|
| `m1_m3_pqb.pv` | M-1, M-3 | With X25519 broken and ML-KEM-768 intact, a card holder never obtains the intro inner layer (card, binding v3, `reply_seed`, first L1) nor, by induction, B's root, A's root or pair content | `outerOnly` must be attacker-known (control); 3 reachability events; generated mutant "k_in without the KEM" makes every secrecy query fail |
| `m2_binding.pv` | M-2 | Non-injective agreement of binding v3 on (OI_A, base key, ciphertext, namespace, minute, OI_B) with two recipients and all recipient state public (KCI); no transfer between inboxes | Leaked-key identity control; reachability `AcceptedHonest`; mutant with unbound recipient fails |
| `m6_pqc_healing.pv` | M-6, step (3) only | After a leak of the complete state at t, envelopes under a PQ root made to a generation created after t stay secret a week later | Four controls (live week key, classical root, root to the leaked generation); reachability |
| `m7_erasure.pv` | M-7 derivation structure | After erasure of week w, the later seized keys and the seed reach neither week w's key, its recognition key nor its envelope | Control `msgLive`; two mutants (invertible ratchet, root from the seed) fail |

**First real run** 2026-09-24 locally: 8 models (4 + 4 generated mutants), **48 queries, all as expected** (design §22.31); on the runner `pq-model` has passed four times (2026-09-25 to 2026-09-28) after two red runs on 2026-09-23.

**Not proved, in the repository's own words:** M-4 (nesting does not weaken Olm) is a *written argument that has not been written*; M-5 (session selection R-SS0..R-SS4) has no ProVerif model (EM-1 enumerates convergence only); M-8 is vectors, differential tests and fuzzing; M-7 uses key secrecy as a proxy for unlinkability; a green `pq-model` run is "M-1, M-2, M-3, M-6 step (3) and M-7's structure, nothing more". Abstractions: X-Wing as an ideal IND-CCA KEM, HKDF/HMAC/AEAD ideal, "a quantum adversary" = X25519 broken only. **PQ healing steps (1), (2), (4) and its latency are measured by a JVM world (`PqHealingWorldTest`), not proved.** There is no model for the relay protocol, capabilities, the entitlement protocol (beyond the cited analysis of RFC 9474), Tor usage or the MLS design (`faza10-forum.md` Q23: no ProVerif model in Phase 10).

---

## 6. Fuzzing and vendor suites

| Item | What exists | Results | Gaps |
|---|---|---|---|
| **`dm-fuzz`** (`client-core/dm/fuzz`, own workspace, cargo-fuzz 0.13.2 pinned by SHA-256, `nightly-2026-09-25`, AddressSanitizer + debug assertions) [D] design §22.35 | Six libFuzzer targets reaching real parsers with attacker bytes: `card`, `bundle`, `intro_inner`, `l0`, `tlvs`, `olm_message`; fixture that holds the keys an attacker would, so inputs pass the AEAD and reach the parsers; 30 seed files from the committed vectors | **Local, 2026-09-26:** 40 minutes per target, **802,641,530 executions, no crash/timeout/OOM** (card 47,981,059; bundle 5,186,455; intro_inner 3,167,008; l0 650,515,147; tlvs 67,564,587; olm_message 28,227,274). **On the runner (nightly, 600 s per target), 2026-09-28 to 2026-10-03:** `card`, `intro_inner`, `l0`, `tlvs`, `olm_message` pass every night (e.g. 28.8 M, 1.15 M, 256.7 M, 24.6 M, 8.6 M executions on 10-03); **`bundle` ends in `FAIL crash` in all 7 runs** (2,118 to 114,901 executions), so the job is red. | Not covered: Olm session decryption on a stored state, stored-state formats (`state_env`, `decode_pickle`, `wrap::unwrap`), `compare_scanned`, the JNI surface; x86_64 only; corpus not kept between nights |
| **The `bundle` crash, assessed from the source (inferred, not reproduced)** | Target mode 1 builds a bundle from random fields and asserts that a *refused* bundle is refused only because the X-Wing key is invalid. The Phase 9 review fixed CRY-P9-01 (commit `e5beb4e`): `bundle::parse` now also refuses a non-canonical Olm identity or fallback key (`InvalidKey`). With two random 32-byte arrays, most inputs have bit 255 set in one of them, so the target's assertion fires almost immediately. The fuzz branch (`d44128f`) was written before that fix and merged after it. | **Most likely a stale property in the harness, not a defect of `ghost-client-dm`** (and, if so, evidence that the CRY-P9-01 fix works). The crashing input is in the run's artifact (`dm-fuzz`, e.g. artifact 11271989988, 149 KB, expiring 2026-10-06 because artifacts are kept 3 days; each nightly run uploads a new one); this package did not download or analyse it. | Needs a human to confirm; until then the `bundle` target gives no signal |
| **`vendor-tests`** [D] §22.33 item 11, §22.35 items 8-9; [C] nightly | vodozemac 0.11.0's own suite from the verified crates.io package (with the upstream `olm-rs` patch re-applied from `Cargo.toml.orig`; the five `fuzz_corpus_*` tests cannot run on the package); libcrux's suites run in upstream's workspace at the commit the crates were cut from, with each pinned crate's published files copied over upstream's (finding: `libcrux-platform` 0.0.3 differs from upstream at that commit in `src/x86.rs`) | vodozemac **337 tests, 0 failed** (148+11 default, 164+14 all-features); libcrux **160 tests, 0 failed** (ml-kem 53, sha3 69, sha2 17, kem 7, ecdh 4, p256 4, platform 3, secrets 2, curve25519 1); four libcrux crates have no tests of their own and the job checks that they still have none | libcrux proofs (hax/F*) not re-checked; only default features; test graph advisories not checked |
| **Differential and known-answer tests** | X-Wing draft-06 vectors and draft-10 equivalence, ML-KEM-768 KATs, RustCrypto `x-wing 0.1.0` as oracle (dev only), Olm key-schedule oracle (`HKDF(salt = 0x00, M, "OLM_KEYS", 80)` with AES-256-CBC and the 8-byte MAC), golden pickles per vodozemac pin with an `UpgradeTest`, BIP-39 (Trezor) and RFC 5869 vectors, RFC 9474 (4096-bit Appendix A) and RFC 9578 (2048-bit) vectors, 15 shared vector files | Green in the suites above | |
| **Unit-level property tests** | `10^6` parser property runs (`dm` S4a), 10-step exhaustive checks | Green | |

---

## 7. Reproducible build (T12) [C][D]

* **What is checked:** `scripts/build-native.sh` builds `libghost_client_net.so` for `arm64-v8a` and `x86_64` twice from a clean target directory **at the same path** and compares SHA-256 (CI job `android native libs`); `reproducible-build.sh` builds the release APK twice, compares, and checks that exactly the recorded native libraries are inside (`apk-native-libs.sh`; the sums are written by `build-native.sh` into a generated, git-ignored file, and in CI come from the same run's `android native libs` job, not from a separately reviewed reference); the build fails if any builder path, `HOME`, `RUSTUP_HOME` or the NDK path remains in the output.
* **Result on a runner:** success at `197b2b4` (`android native libs` and `reproducible release build`, run 36434212692). Before that the job chain was skipped from 2026-09-20 to 2026-09-27 because of the artifact storage quota (hand-off through the Actions cache since `ci.yml` was reworked, §22.33 item 2).
* **Not claimed and not true today:** identity **across environments** (a different host, Windows, a different path): cargo hashes the path-remap flags into build-script directory names, and Windows keeps `\` separators. The fixed-path builder is Phase 14 work; **T12b** (an auditor rebuilds the tagged commit and signs the hashes) has no implementation. The APK is not signed by any reproducible release pipeline. Gradle dependency verification has two declared gaps (GATES-5).

---

## 8. Reviews already done

All by AI agents; each finding was handed to a separate verifier that tried to refute it from the code, from its own runs and from the CI logs. **None is an external review.**

| Review | Date | Scope and lenses | Raw to confirmed to resolved | Open afterwards |
|---|---|---|---|---|
| Phase 6 security review `docs/reviews/2026-09-11-faza6-security-review.md` | 2026-09-11 | `client-core/net`, `android/network`, CI, `deny.toml`; 6 dimensions + completeness critic, 3 skeptics per finding; round 2 verified the fixes; round 3 five areas | Round 1: 55 raw, 47 confirmed, **27 after dedup** (1 high, 9 medium, 17 low), 8 rejected. Round 2: **11 regressions** introduced by fixes (1 high, 2 medium, 8 low). Round 3: 18, 15 confirmed (7 medium, 8 low), 3 rejected. All resolved with tests | Items moved to later phases: bridges (Phase 12), T6 dynamic (Phase 13), `.so` load on JVM/emulator, builder with fixed paths (Phase 14) |
| Phase 7 final review (slice S9), `docs/STATUS.md` row 7, design `faza7-sync-engine.md` §11 | 2026-09-12 | `:sync` engine and harness | **6 confirmed, all corrected** (5 code each with a test failing before, 1 documentation) | Device checks (design §8.9) |
| Phase 8 per-slice rounds (waves A-F) and the S12 final review `docs/reviews/2026-09-14-faza8-review.md` | 2026-09-14 | Five lenses over 84 commits (546 files, +95,665 lines): crypto/protocol; money/state; privacy and T2; Android client; ops/CI | **17 raw, 15 confirmed, 14 after dedup** (**3 high**, 4 medium, 7 low), 2 rejected; **all 14 resolved**, each with a test or mutant that failed before. Findings included an unbounded `WRONG_PERIOD` re-prepare loop, a claim-id batch-poisoning bug, a missing nightly constant-time test | Residues E33, E34 declared; "re-verify E34 and the signer timing evidence in Phase 15" |
| Phase 9 design rounds (9, 9b, **9c = §22.8**) | 2026-09-16 | Design review by three lenses: cryptography CRY-1..10, privacy PH-1..13, implementability IMPL-1..17 | **40 findings, none rejected as wrong**, four overlaps merged, seven fixes replaced or narrowed | Q36 re-asked (owner-bound read rule) |
| Phase 9 whole-phase review `docs/reviews/2026-09-25-faza9-review.md` | 2026-09-25 | Five lenses over the integrated tree (`f244b80`): crypto composition; relay-visible metadata; engine correctness; Android platform; gates and CI | **33 raw (8 high, 19 medium, 6 low) to 32 confirmed (15 medium, 17 low; none high after recalibration), 1 refuted (A-7)**; **21 fixed** (9 with a recorded remainder), **3 fixed in part**, **8 left to the owner** (`KNOWN_ISSUES.md`). A regression test, `PhaseReviewRegressionTest`, fails 11 of 11 with the fixes reverted | Exit-gate item 16 stays open |
| Phase 10 design rounds 10a-10e `faza10-forum.md` §19 | 2026-09-25 to 09-28 | Three lenses (rounds a-c: **55 findings**), S0 evidence checks V10-1..V10-14 with two adversarial reviews (S0-1..S0-18 corrections), a targeted review of S0-12/S0-15 (7 findings, TR-1..TR-7), a review of round 10d (**27 findings**, each re-run with a probe E-69..E-76) | None found wrong; round 10d's lifetime rule was found to fork honest members and was replaced (Q42 constant lifetime) | Q49 residue: fork capture by a removed committer is detectable only out of band |
| Phase 11 (media), Phase 13 (UX), Phase 14 (distribution) designs | 2026-09-25, 2026-10-03 | Three lenses each: Phase 13 **61 findings** (22 + 21 + 18), Phase 14 **72 findings** (21 + 22 + 29), none found wrong; Phase 11 three lenses (counts in design §21) | Designs only; no code | Not approved |
| Evidence spikes `faza9-s0-evidence.md` (V-1..V-17), `faza10-s0-evidence.md` (V10-1..V10-14) | 2026-09-19, 2026-09-25/26 | Measurements and probes behind normative corrections S0-1..S0-15 (Phase 9) and S0-1..S0-18 (Phase 10) | | |

---

## 9. External assessments of upstream components that exist [X]

Re-audit by this project is out of scope; these bound what is reused. All accessed 2026-10-03.

| Component | Assessment | Notes |
|---|---|---|
| vodozemac | Least Authority, final report 2022-03-30; code review 2021-12-20 to 2022-01-25, report 2022-01-28, verification 2022-03-28/29; five named researchers; 10 issues (A-J) and 8 suggestions. https://leastauthority.com/static/publications/LeastAuthority-Matrix_vodozemac_Final_Audit_Report.pdf ; blog https://matrix.org/blog/2022/05/16/independent-public-audit-of-vodozemac-a-native-rust-reference-implementation-of-matrix-end-to-end-encryption/ | GHOST pins 0.11.0 (2026-09-11); issue I (key material in memory) and J (8-byte MAC) are inherited, declared in design §2.5 |
| OpenMLS | SRLabs for Phoenix R&D, funded by the Sovereign Tech Agency; kick-off 2025-10-16, 12 weeks of analysis, final report v1.1 2026-03-03, v1.2 2026-03-11 (41 pages); 8 findings (1 high: MAC verification accepted truncated or empty tags; 3 medium; 2 low; 2 informational); scope crates `openmls`, `traits`, `basic_credential` up to commit `a3402f2` (2025-10-22); crypto providers, storage and PQ suites out of scope (as read by design `faza10-forum.md` §3.1). https://blog.openmls.tech/SRL-OpenMLS_security_assurance_assessment.pdf | GHOST will use 0.9.0 with the libcrux provider (not covered) |
| libcrux / hpke-rs | No public third-party audit found in a web search. A research paper claims 13 vulnerabilities in libcrux and hpke-rs, nine in unverified code: ePrint 2026/192, received 2026-02-05, revised 2026-06-25, https://eprint.iacr.org/2026/192 ; several RustSec advisories exist (e.g. RUSTSEC-2025-0133, RUSTSEC-2026-0075). The vendor contested parts of this publicly (secondary reporting; read both sides). | GHOST pins libcrux 0.0.8-0.0.10 and tracks the advisories (design `faza10-forum.md` §3.7); X-Wing/ML-KEM wrapper code is within Tier A1 |
| Arti / Tor | Cure53 pentest and source audit of Tor VPN for Android and the Tunnel Interface for Arti, June 2025 (two weeks, 24 work days allocated, six specialists, 18 findings); report dated 2025-07-04. 7ASecurity audit of Tor Project network-health tools including Arti, July-August 2025 (six vulnerabilities, eleven hardening recommendations). https://blog.torproject.org/code-audit-tor-vpn/ ; https://blog.torproject.org/code-audit-network-health-tools/ | Not an audit of the Arti client as GHOST uses it |
| RSA blind signatures (RFC 9474) | RFC and a security analysis; no public audit of `blind-rsa-signatures` or of a Privacy Pass implementation found in searches | GHOST's split implementation is Tier A3 |
| Monero | Bulletproofs: Kudelski Security and Quarkslab (2018, with OSTIF), https://ostif.org/the-quarkslab-and-kudelski-security-audits-of-monero-bulletproofs-are-complete/ ; RandomX: four firms in 2019, https://blog.quarkslab.com/security-audit-of-monero-randomx.html ; FCMP++: membership-proof circuit by Veridise, April-May 2025 (dated by a secondary summary; report PDF https://veridise.com/wp-content/uploads/2025/06/VAR_Monero_250407_fcmp___V3.pdf, not opened by the preparer); Trail of Bits cryptography review completed July 2026, two engineer-weeks, six informational findings, https://magicgrants.org/2026/08/17/Monero-FCMP-Cryptography-Implementation-ToB (the same secondary summary dates a Trail of Bits review of the FCMP++ integration to May 2026; whether that is the same engagement was not established); CARROT address scheme by Cypher Stack, https://github.com/cypherstack/carrot-audit | Wallet integration of GHOST (view-only wallet, payment detection, payouts) is not covered by any of these |

---

## 10. What has NOT been run or established (the honest list)

1. **Anything on a physical device or a hardware Keystore**; arm64 execution; Doze/standby/reboot behaviour; notifications; StrongBox; two-device checklist; NFR-1, NFR-4, NFR-5 measurements.
2. **Staging**: three independent relay operators, the issuer on stagenet, relay capture (T1) from staging, a live Tor run with issuer flows, onion-key rotation.
3. **The exit gate of Phase 9**: 31 of 57 correctness mutants and 25 of 40 privacy mutants unrun, T32 gate scale red, JD10/NI-DM4-7/S-DM baselines unbuilt, emulator CI never ran, `dm-fuzz` red, ProVerif partial, external cryptographic review (Q57) not done, phase review items open.
4. **T2 sweep** over ten seed pairs (3 red), and any T2 statement about HIGH mode.
5. **Cross-environment reproducibility** (T12b); signed releases; transparency log; updater; any Phase 11-14 code.
6. **Any code of Phase 10 on `main`**; any test of MLS behaviour other than the evidence spike.
7. **A complete `self-test.sh` run at the base commit** (this package ran 649 cases with two blocks skipped; a full run takes about 2.5 to 3.8 hours on the owner's Windows machine and was not repeated).
8. **A fresh `cargo test --workspace` count at the base commit** (836 passed is from 2026-09-26; tests were added since, e.g. `ghost-client-dm` binding-hook tests).
9. **Third-party audit of the GHOST-specific Rust or Kotlin by any human outside the project.**
10. **Penetration testing** of the relay and issuer onion services, of the Android app, or of the CI/runner trust model.
