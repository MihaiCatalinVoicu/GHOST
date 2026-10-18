# GHOST Phase 12, slice S4: the adversarial review + the close — notes and evidence

| Field | Value |
|---|---|
| Design | `docs/design/faza12-transports.md` (**revision 4, the S4 close** — Appendix B applied, the review round's corrections, §15 marked item by item), §14 slice row S4, §15; evidence base `docs/design/faza12-s0-evidence.md`, `faza12-s1-notes.md`, `faza12-s2-notes.md`, `faza12-s3-notes.md` |
| Scope of this document | the S4 slice: Appendix B applied across the other documents (INVARIANTS, THREAT_MODEL, LIMITE, STATUS, the ADR index, the plan), ADR-61/62 filed and corrected, the phase's adversarial implementation review (three lenses, findings reproduced, dispositions), the §15 exit checklist marked with its evidence, the verification runs on the closing tree; each S4 claim names its evidence (the S0–S3 convention) |
| Branch | `p12-s4` (worktree of `D:\Forum`, from `p12-s3` at `80459839`); **no commit made — the lead reviews and commits** |
| Dates | 2026-10-17 (S0 → S1 → S2 → S3, same day) → S4 session(s) |
| Status | **S4 done: Appendix B applied (with the S3-T8 amendment to T58's disk clause and the review's correction to ADR-61's recipe cell); the adversarial review round ran over the whole phase with its findings dispositioned (two corrected, two recorded for the lead, the rest confirmed); §15 is marked item by item — the loopback gate re-ran GREEN on the closing tree in 91.7 s; the verification caught and fixed one latent gate failure (G-M1's writer allowlist, red since S2). The phase's remaining items are the owner's: OA-1 (the live run), OA-2 (the arm64 device step), the written prune confirmation (OA-3's tail), and plan row 12's other two clauses (F-T1).** |

**How to read.** One section per work item, numbered like the slice's task list. Normative
corrections and precision notes are numbered **S4-T1 …** in §0 and follow the earlier slices'
convention. §1 is Appendix B applied (location per document). §2 is the adversarial review
round: three lenses over the whole phase, each finding reproduced by reading or probing the
code before it was believed; dispositions in §2.5. §3 is the §15 checklist with each item's
state and evidence. §4 is the verification on the closing tree. §5 is the owner's remaining
items. S4-T5 (the G-M1 allowlist fix the verification forced) is the close's own finding —
the gate doing its job on the way out, exactly as §12.3's harness did three times in S3.

---

## 0. Summary

### 0.1 Verdicts

| Item | Verdict | In one line |
|---|---|---|
| Appendix B applied | DONE | INVARIANTS T58–T60 (T58 with the S3-T8 amendment), TM AD-4 (TM:52), the new LIMITE L12 (L12.0 the LT table, L12.1 the C-rows, L12.2 the evidence cross-references), STATUS's Phase 12 closing segment, the ADR index's Phase 12 section, plan row 12's status — §1 for the exact locations |
| ADR-61/62 filed | DONE, corrected | filed as "Propus"; ADR-61's recipe cell carried a rev-1 remnant (llvm-strip, `CGO_ENABLED=0` for both ABIs) — corrected in the filed ADR and the design's Appendix A copy (S4-T1); both ADRs' Status records "aplicat în Faza 12, în așteptarea deciziei proprietarului (Q11)" |
| The adversarial review round | DONE, dispositioned | three lenses (crypto, privacy, implementability) over the whole phase's code, gates and fixtures; every candidate finding reproduced by reading/probing before it was believed; two corrections applied, two findings recorded for the lead, §2.4 lists the confirmations that needed no change |
| §15 exit checklist | DONE | every item marked with its state and evidence (§3); items 2/OA-2/the prune confirmation/F-T1 are the owner's, restated in §5 |
| Verification on the closing tree | GREEN (after one fix) | the loopback gate re-ran green in 91.7 s; `cargo test --lib` 77/0; `privacy-capture.sh` OK; `run-all.sh` caught one latent failure (G-M1 × PtInstaller, red since S2) — fixed via the writer allowlist (S4-T5) and re-verified; the full `run-all.sh` and `self-test.sh` re-ran on the final tree (§4) |

### 0.2 Normative notes (for the record, per the slices' convention)

| # | Sections | Note (short) |
|---|---|---|
| S4-T1 | Appendix A / ADR-61 point 3 (and point 5, point 6) | **The review's first confirmed finding, corrected in S4.** ADR-61's filed text (and the design's Appendix A copy, declared identical) still carried the **rev-1 recipe**: "strip cu llvm-strip din NDK", "`CGO_ENABLED=0`" for both ABIs. Both are refuted by S0-T2/rev 2 (evidence §4: the recipe is `-ldflags '-s -w …'` strip at link time, and android/amd64 hard-requires `CGO_ENABLED=1` with the pinned NDK clang). Point 5 also predated the rev-3 exec model (no linker-invocation sentence), point 6 still said the budgets were "fixed in S0" without the pruned values. Corrected in both places (filed ADR + design copy, kept identical); the design moved to **revision 4** with the amended cells marked. Root cause: the ADR texts were filed from the rev-1 draft and the rev-2/rev-3 design amendments never propagated back into them — flagged so future revisions remember the ADR copies are normative text too. |
| S4-T2 | Appendix B.1 / INVARIANTS T58 | **T58's applied row carries the S3-T8 amendment**, not Appendix B.1's pre-amendment text: the landed canary (S3's green run) caught arti 0.46's designed persistence of the configured bridge's identity in its own guard/dir stores, so the disk clause reads "nothing outside arti's own stores; the full line text verbatim nowhere". Appendix B.1 in the design keeps the original text with the amendment recorded next to it (rev 4); the INVARIANTS row itself states the amended clause. |
| S4-T3 | §6.6 / `transport.rs` (the arti parse-error arm) | **Recorded finding (lead's disposition; not changed in the docs slice).** `build_config` formats arti's `BridgeParseError` verbatim into `TransportError::Config` (`transport.rs:188`, `format!("bridge line {index}: {e}")`), and arti's error `Display` **embeds the offending word** (e.g. `Cannot parse {word:?} as identity key…`, `tor-guardmgr-0.46.0/src/bridge/config/err.rs` — for a PT setting the word is the `cert=<b64>` token). **Probed for reachability:** every arti failure arm is pre-empted by GHOST's stricter structural validator — `check_setting` (`tor-linkspec-0.46.0/src/transport.rs:471-483`) rejects only whitespace or `=` in keys/values (impossible post-validation: the grammar's values are base64/hex/https-url, the token was split on whitespace), and the address/fingerprint/identity arms are equally covered — so the word-carrying strings are **unreachable today**. The residual risk is a future arti divergence at a bump, which would place cert material into an error string. Recommended one-line hardening for a code-touching slice: map that arm to a static label (`bridge line {index}: arti rejected the validated line`), preserving the index-never-text contract absolutely. Recorded, not applied: S4 is the docs slice, and the fix deserves its own test run in a code slice. |
| S4-T4 | §8.1 / `TorTransportHolder.kt:357` | **Recorded note (nit).** The auto-mode's `needsPt` detection (`it.startsWith("obfs4 ") || it.startsWith("webtunnel ")`) is a **third naming site for the PT grammar set** (after the Rust validator and G-T8's pins). A 12b grammar addition could forget it; the outcome stays fail-closed (the new PT line would meet `pt_dir = null` → `PtBinaryMissing` → `bridge_config`), so this is maintainability, not security. Recommendation: when 12b lands, expose `BridgeLineKind::needs_pt_binary` over JNI instead of prefix-matching in Kotlin. |
| S4-T5 | §13 / G-M1 × PtInstaller (file-writer-allowlist) | **The close's own fired gate — corrected in S4.** The S4 `run-all.sh` caught `media-no-plaintext-io` (G-M1's writer half) red: `PtInstaller.kt`'s `tmp.outputStream()` (the asset stream into the per-ABI temp) and `stamp.writeText()` (the versioned `.lyrebird.sha256` stamp) were not in `file-writer-allowlist.txt`. Latent since S2 (neither S2 nor S3 ran the full run-all — both named their gates individually). The fix is the allowlist's designed mechanism: two motivated entries (the extracted PT binary and its hash stamp — never media), which also pin the counts so a new writer in the file fails the gate. Re-verified green. The G-M1 gate header's own note applies: what a text gate cannot see is the reviewer's — the two sites were read in S4's review round (§2.3) before the allowlist entry was written. |

---

## 1. Appendix B applied (the S4 diff, location per document)

| Document | What landed | Where |
|---|---|---|
| `ghost/test-harness/privacy/INVARIANTS.md` | Title T1–T47 → **T1–T60**; rows **T58** (with the S3-T8 amendment, S4-T2), **T59**, **T60** after T47; the "**Nota Faza 12**" state paragraph after the Faza 11 note | the invariant table; the notes block before "Nota T17" |
| `docs/THREAT_MODEL_v2.1.md` | The **AD-4 row replaced** (Appendix B.2's text: plain bridges show the Tor fingerprint; with a PT bridge "nu vede nici Tor" on the client↔bridge hop, volume/timing/bridge-IP remain, pointer to L12); §9's harness paragraph now names T58–T60 and the AD-4 update | TM:52 (the AD matrix); §9 |
| `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` | New section **L12** (header per Appendix B.3): intro, **L12.0** the declared-leakage table (LT-1…LT-4), **L12.1** the residues (L12-C1…L12-C7, Appendix B.3's rows), **L12.2** the evidence cross-references (PT-L1/PT-L2, PT-P1, the G-T gates, the §9.2 measurement, OA-1); the §5 synthesis "ISP" row and the L4 bridges row updated to name the delivered client half (the remainder stays F-T1's) | after L9.2, before "5. Sinteză"; L4's table; the synthesis table |
| `docs/STATUS.md` | Header date 2026-10-17; the ADR row names ADR-61/62 (propuse, aplicate); the "**Faze 12, 15–18**" row split — new **Faza 12 closing segment** (the PT set, the snowflake deferral, the gate state, the owner's remaining items) and "Faze 15–18" for the rest | the status table |
| `docs/adr/README.md` | New "**Propuse (Faza 12)**" section: ADR-61/62 with the applied-in-Phase-12 note and the S4 review pointer | before "Retrase" |
| `docs/adr/ADR-61-…md`, `docs/adr/ADR-62-…md` | Status fields record "Propus, **aplicat** în Faza 12 (S0–S4)"; ADR-61's recipe corrected (S4-T1: link-time strip, the x86_64 CGO external link, the pruned-tree paragraph, the linker-invocation sentence, the pinned sizes); ADR-62's T58 clause carries the S3-T8 amendment | each ADR's header table and decision points 3/5/6 (ADR-61), 4 (ADR-62) |
| `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` | **Plan row 12's status** (the rows 10/11 "stare la" convention): the bridges clause implemented and locally tested, the owner's remaining items named, F-T1's remainder explicit | §6.2 row 12 |
| `docs/design/faza12-transports.md` | **Revision 4**: the header Status/Revision cells; Appendix A's ADR copies corrected identically (S4-T1); Appendix B.1's T58 marked with the S3-T8 amendment (S4-T2); the S4 slice row's exit state; **§15's checklist marked item by item** with evidence and the owner's remaining items restated | the header table; Appendix A/B; §14; §15 |

## 2. The adversarial review round (the phase's named exit, §15 item 7)

**Method.** Three lenses over the **whole phase** (S0's pins/build, S1's Rust, S2's Android,
S3's harness/gates), reading the code and the gate scripts directly — nothing from the slice
notes was believed without checking the tree. Where a claim looked wrong, the finding was
**reproduced** (both parsers read for the reachability proof; the vendored crate diffed
against the crates.io baseline; the landed canary compared against the Appendix B text)
before it was recorded. Confirmations that survived skeptical reading are listed too — a
review that only writes findings is half a review.

### 2.1 The crypto lens (the grammars, wraps and env scrub against §4–§6)

- **The grammar validator (`bridge_line.rs`)** — read line by line against §3.2/§6.2: the
  three grammars, the distinct snowflake deferral, the 1 024/8 caps, exact dedup, the
  index-never-text error contract, and the 10⁶-input totality property are exactly as
  designed; the cert rule is S3-T3's corrected shape (standard alphabet, ≤2 trailing `=`,
  must decode — a hand-rolled decoder, no new dependency). The reviewer's own candidate
  attack — an internal newline smuggled into a stored line to break the JNI round trip — is
  refuted by construction: `nativeValidateBridgeLines` and `nativeCreate` split the input on
  lines, trim and drop empties before validating, so no accepted line can carry `\n`
  (`jni_bridge.rs:425-430`, `:380-384`). **Confirmed, no finding.**
- **The arti parse-error arm** — the one genuine crypto-lens finding; probed and recorded as
  **S4-T3** (unreachable today; recommended one-line hardening; the failure mode it guards
  is a bump-time divergence, which is exactly when §4.4 re-runs the whole suite).
- **The env scrub (`transport.rs:380-408`)** — `PT_ENV_STRIP` covers every proxy variable in
  both cases plus `HOME`; `TMPDIR` is redirected into the attempt's own state dir; the scrub
  runs at every PT config build (idempotent, cheap), i.e. strictly before any PT-spawning
  client can exist, because a PT-spawning client is by construction built from a config with
  PT lines. The S1 note's concurrency caveat (races on `TMPDIR` between concurrent config
  builds are harmless — every candidate dir is an app-private attempt dir) was re-examined
  and stands. **Confirmed.**
- **The launch shape (`pt_exec`/`pt_linker`, §5.4.5 + S3-T1)** — the platform split is
  exactly as specified: Android resolves the ELF-class linker (`linker64` for both shipped
  ABIs, existence-gated, `PtLinkerMissing` typed), every other host execs the verified
  binary directly; the unit test pins both halves per target. **Confirmed.**
- **The build pipeline (`BUILD.sh`, pins, prune patch) against §4** — the recipe matches the
  rev-2 normative text (toolchain fetch with hash verify, checkout at the pinned commit,
  patch hash-verified then applied to a reset tree, the pruned-module-graph assertion, the
  same-path double build, the leak check); the diffstat of `prune-snowflake.patch` is
  deletion-dominated as §10.1 of the S0 evidence records. The **vendored `saturating-time`
  patch** (flagged for this review by S3-T7) was diffed against the crates.io 0.4.0
  baseline: the only functional change is the marked stagnation arm in `find_limit` plus the
  `PartialEq` bounds; the termination argument (strictly monotone `res` over a finite range,
  or geometric step shrink to 1 ns) is sound, and the added branch is unreachable where the
  granularity divides every `Duration` (the shipped path). G-M2 pins the tree's file set and
  hashes. **Confirmed — the vendoring is minimal and provably terminating.**
- **The ADR-61 recipe text vs the recipe** — the finding: the filed ADR (and the design's
  Appendix A copy) contradicted §4's rev-2 recipe. **Confirmed and corrected (S4-T1).**

### 2.2 The privacy lens (LT/JM/PT-P/T58 against §3/§12 and the threat model)

- **T58's canary vs the landed code (`pt_loopback.rs:757-778`)** — the in-test canary
  implements exactly the S3-T8-amended scope: no needle (fingerprint, cert, line) outside
  arti's own two stores, the full line text verbatim nowhere, and the log clause absolute;
  both phases (post-bootstrap, post-process-death) run on the real artifacts. The review
  compared the landed scope against **Appendix B.1's text** — which predates S3-T8 — and
  caught the mismatch before it was applied verbatim. **Corrected as applied (S4-T2).**
- **G-T7's positive half** — the committed 4 380-line harness log is marked, non-empty and
  line/cert-clean (the D28 non-vacuity rule); the bare-40-hex scan is deliberately not the
  rule; the SMETHOD ARGS scrub is in place. **Confirmed.**
- **PT-P2's pair** — the committed `pt-relay-shape.txt` rows are byte-equal
  (`handshake=[(22,1),(20,3)]`, `alphabet=[(20,3),(22,1),(23,3)]` on both paths) with the
  drifted negative twin present; `privacy-capture.sh`'s PT clause reads the real pair. **Confirmed.**
- **The LT table against §2/§7** — LT-1…LT-4 as declared match what the capture shows (the
  observer sees the connection, volume, timing, the bridge IP — not Tor-ness) and land
  verbatim in L12.0. **Confirmed.**
- **The WebTunnel honesty boundary** — restated, not a new finding: the loopback server is
  obfs4-only because stock 0.9.0's webtunnel server answers `SMETHOD-ERROR … unimplemented`
  (measured unpruned too, C-1); P-T1's WebTunnel half is argued structurally (uTLS HTTPS
  cover) plus the grammar tests, and the live run (OA-1) carries the real line. The review
  verified no document overclaims a WebTunnel loopback. **Confirmed.**
- **The storage/JNI half of T58** — `BridgeLines.set` throws category+index only; the error
  regex cannot misfire on a validated line (the Rust contract test pins that a validated
  line never begins with `bridge_line_`); the DAO logs nothing. **Confirmed.**

### 2.3 The implementability lens (extraction/exec/auto-mode against the code)

- **`PtInstaller`** — idempotent versioned stamp (hash, not flag), 32 MiB hard cap refused
  like a hash mismatch, verify-before-chmod on the temp, atomic rename, temp deleted on
  refusal, fail-closed categories; `installed()` never throws; the device probe pins the
  exact mode and the exec verdicts. One nit recorded from reading: a non-`IOException`
  unchecked exception from chmod/move would leave an inert `lyrebird.tmp` (never exec'd,
  never stamped, overwritten next install) — not worth a change. **Confirmed.**
- **The reduced auto mode (`BootstrapPlan` + `TorTransportHolder`) against §6.5** — the
  sequence (direct when allowed, then lines in order, one fresh client per attempt), the
  spent-rule exhaustion (`PLAN_SPENT` fail-fast without creating a client), the abort/epoch
  reset, the pt_dir resolution (install at first PT need; a direct-attempt "no" is not
  final; a refused extraction remembered only when PT was needed), and the never-clearnet
  shape (the factory can only construct the direct shape or an exact configured line) are
  all in the code as specified. The `needsPt` prefix check is recorded as S4-T4 (fail-closed
  nit). **Confirmed, one nit.**
- **Host/JVM behaviour (§8.4)** — no assets → `pt_dir` absent → PT lines rejected at
  create; PT-U7/PT-U9 exercise the real paths through the host DLL. **Confirmed.**
- **The G-M1 writer allowlist** — the review read `PtInstaller`'s writers before the gate
  flagged them; the S4 full-run-all then caught the missing allowlist entries (the gate
  doing its job — neither S2 nor S3 had run the full run-all). **Fired in the close and
  fixed (S4-T5).**

### 2.4 Confirmations that needed no change (the review's "nothing found" rows)

The validator's totality and caps; the refusal relaxations pinned at both levels; the env
scrub's coverage and ordering; the launch-shape unit test's per-target pinning; the harness's
chance-density capture rule (S3-T9) against a fresh capture (0 c2s / 6 s2c three-byte hits
over ~22 MB, all isolated — chance-consistent, §4); the canary's amended scope; the relay-shape
equality; the vendored patch's minimality; the extraction's fail-closed shapes; the auto-mode
policy; the JNI trim contract. Each of these was read in the tree, not assumed from the notes.

### 2.5 Dispositions

| Finding | Lens | Disposition |
|---|---|---|
| S4-T1 — ADR-61's recipe cell (and points 5/6) contradict §4's rev-2/3 text | crypto | **Corrected in S4** (filed ADR + design Appendix A, kept identical; design rev 4) |
| S4-T2 — Appendix B.1's T58 predates the S3-T8 amendment | privacy | **Corrected as applied** (the INVARIANTS row carries the amended clause; B.1 records both) |
| S4-T3 — `transport.rs:188` formats arti's word-carrying parse error into `TransportError::Config` (unreachable today; fragility at bumps) | crypto/privacy | **Recorded for the lead** — recommended one-line hardening (`static label + index`) in a code-touching slice, with its own test run; not applied in the docs slice |
| S4-T4 — `needsPt` prefix check is a third grammar-naming site | implementability | **Recorded** (nit; fail-closed today; fold into 12b's JNI surface) |
| S4-T5 — G-M1's writer allowlist missing PtInstaller's two writers (latent since S2) | implementability/privacy | **Fired by the S4 run-all, corrected in S4** (two motivated allowlist entries, counts pinned) |

---

## 3. The §15 exit checklist, item by item

*(the same marking lives in the design's §15, rev 4)*

1. **Loopback obfs4 bootstrap green at the pinned lyrebird (PT-L1 + PT-L2).** **MET** — S3's
   run of record (`.claude/s3/p12s3-ptloop-green.log`, 187 s: bootstrap 0→100% in 32.7 s,
   the onion echo answered through the PT, two scopes on two circuits, keystore empty, the
   capture rule over ~22 MB) **and re-run green on the closing tree in S4** (§4: 91.7 s,
   bootstrap 43.1 s, every assertion passing).
2. **One recorded live public-bridge run.** **OWNER'S (OA-1) — not executed.** The mechanism
   is built and unblocked (`tests/live_pt.rs`); recorded as not executed; the distribution-day
   checklist carries it (exactly §12.4's "manual, recorded").
3. **G-T1 … G-T8 green with fixtures and self-tests; the extended gates unchanged green.**
   **MET** — S3's gate table (eight gates, fixtures, the extended G-M2) plus the S4 full
   `run-all.sh` re-run (§4), which caught and fixed the one latent failure (S4-T5).
4. **T58/T59/T60 evidenced.** **MET** — PT-P1's two-phase canary scans (S3-T8's amended
   scope), G-T5's release twin, G-T6's tree scan, the committed PT-P2 pair green under
   `privacy-capture.sh` (re-run in §4).
5. **No regression.** **MET** — Phase 6 suites unmodified and green (S1, re-counted in S3
   and S4: 77 lib tests); the `.so` re-measure (+0.55/+0.45 MiB vs +3/+3.5 MiB, S2 §9); the
   APK-asset budgets within the rev-2 pins (S2 §1; G-T3's pin + 0.5 % gzip rule, S3-T5).
6. **Appendix B applied; ADR-61/62 filed; STATUS updated.** **MET (rev 4)** — §1's table is
   the evidence.
7. **The adversarial review done; findings corrected or recorded.** **MET** — §2 (this
   document), with the dispositions in §2.5.

## 4. Verification on the closing tree (this branch, `p12-s4`)

All under `LC_ALL=C.UTF-8`; logs in `D:\Forum\.claude\s4\`.

- **The loopback gate re-run** — `cargo test --locked -p ghost-client-net --test pt_loopback -- --ignored pt_l1_l2_p1_obfs4_loopback`: **green in 91.66 s**. arti bootstrapped 0→100%
  through the pinned obfs4 hop in 43.1 s; the onion stream answered the echo through the PT
  (53 bytes); two isolation scopes rode two circuits; PT-L1's capture over 2 093 543 B c2s /
  19 779 256 B s2c: no TLS first byte, 6 three-byte signatures s2c (chance-consistent),
  all isolated, the naive two-byte hits at chance level; PT-P1 clean after bootstrap and
  after the mid-attempt kill of the lyrebird server; the plain-bridge control bootstrapped in
  14.9 s; the relay-shape pair equal on both paths (`[(22,1),(20,3)]` / `[(20,3),(22,1),(23,3)]`).
- **`cargo test --locked -p ghost-client-net --lib`** — **77 passed, 0 failed** (the Phase 6
  suites unmodified among them, CS-T2).
- **`privacy-capture.sh`** — **OK** (the capture fixtures and the committed PT-P2 pair).
- **`run-all.sh`** — first pass caught G-M1 red (S4-T5; latent since S2, missed because
  neither S2 nor S3 ran the full run-all — the close pays that debt); after the allowlist
  fix, `media-no-plaintext-io.sh` re-run green individually, and the full **`run-all.sh`
  re-ran on the final tree: 30/30 OK** (`.claude/s4/p12s4-runall-final.log`).
- **`self-test.sh` (the full window)** — green on the final tree: **1 017 drills, 0 fails**
  (`.claude/s4/p12s4-selftest-final.log` — the PT drills incl. the G-M2 22-case all ran and
  passed; the run's only skip was the cargo-gated tail, which needs `cargo` on the runner's
  PATH). A second full run with cargo on PATH (`.claude/s4/p12s4-selftest-final2.log`) covers
  that tail too (the pq-model/pq-mutants/entitlement-schedule drills — Phase 8/9-owned,
  untouched by Phase 12); it was still in progress at delivery, 0 fails so far.
- Not re-run in S4 (unchanged since their slices, per the notes): the JVM suites
  (`:network` 39/0, `:storage` 352+2 pre-existing Phase 11 debts, `:sync` 403/0,
  `:messaging` 34/0 — S2 §8), the emulator probe (S2 §7, API 29+35), the Gradle asset hook
  and the double builds (S2 §1/§9, S3 §6) — S4 touched no code those suites cover, and the
  one file S4 did touch (the G-M1 allowlist) is a gate table, re-verified by the gate itself.

## 5. The owner's remaining items (restated from §0.6 and §16)

- **OA-1 — the live public-bridge run** (`tests/live_pt.rs` is ready: `GHOST_PT_LIVE_LINE` +
  `GHOST_PT_LYREBIRD` → bootstrap + public-onion HEAD probe + recorded time). One obfs4 line
  and one WebTunnel line (or the owner's approval to fetch them at run time); the WebTunnel
  row exists only here.
- **OA-2 — the arm64 device step**: extraction, chmod, the through-linker exec and bootstrap
  timing on two arm64 reference phones; the assertion is pinned in `PtInstallDeviceTest`
  (the gate emulators carry no ARM translation — recorded in S2 §7).
- **The prune confirmation (OA-3's tail):** the pruned tree (past snowflake, to the approved
  P0 set) was applied as an owner-default; the owner's written confirmation closes it.
- **Plan row 12's remainder (F-T1):** the jitter/batch tuning clause and the independent
  metadata-capture review have no home in this design; the owner commissions the small
  follow-up design (or rewords the L9 pointers that named "Faza 12").

---

*Prepared on `p12-s4`; no commit made (the lead reviews and commits). Scratch:
`D:\Forum\.claude\s4\` (the run logs named above). Review base: the whole phase —
`bridge_line.rs`, `transport.rs`, `jni_bridge.rs`, `pt_loopback.rs`, `PtInstaller.kt`,
`BridgeLines.kt`, `BootstrapPlan.kt`, `TorTransportHolder.kt`, `BUILD.sh`, the pt-* gates,
the vendored trees — read in the tree; every finding reproduced before it was recorded.*
