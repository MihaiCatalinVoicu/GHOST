# GHOST Phase 12, slice S1: the Rust slice — notes and evidence

| Field | Value |
|---|---|
| Design | `docs/design/faza12-transports.md` (revision 2, OA-3 applied), §5.1–§5.3, §6.2, §8, §12.2 (PT-U1 … PT-U6), §13, slice row S1 (§14); evidence base `docs/design/faza12-s0-evidence.md` |
| Scope of this document | the S1 slice: the `pt-client` feature delta and its gate/licence updates, the bridge-line grammar validator, `TransportConfig.pt_dir`, the ptmgr wiring with the env scrub, and the Rust unit suites; each S1 claim names its evidence (the S0 document's convention) |
| Branch | `p12-s1` (worktree of `D:\Forum`, from `p12-s0` at `0fd3c7b3`); **no commit made — the lead reviews and commits** |
| Dates | 2026-10-17 (S0 evidence, same day) → S1 session |
| Status | S1 implemented; `cargo test -p ghost-client-net` green (results §7); the host-library size re-measure is **pending by design** — it belongs to the integration build (S2/S3), see §8 |

**How to read.** One section per work item, numbered like the slice's task list. Normative corrections to the design are numbered **S1-T1 …** in §0 and follow the S0 document's convention; nothing here contradicts revision 2 — S0-T4's correction (env inheritance) is *implemented* here, and one new precision about `run_on_startup` is recorded as S1-T1.

---

## 0. Summary

### 0.1 Verdicts

| Item | Verdict | In one line |
|---|---|---|
| Feature delta (`pt-client`) | DONE | arti-client gains exactly `pt-client` (default-features discipline kept); the only new package name in the shipped graph is `tor-ptmgr`; no new duplicate-version names (`itertools` stays at its baseline count of 2) |
| V-T7's full run (S1 finishes it) | GREEN | `cargo deny check licenses bans sources`: **licenses ok, bans ok, sources ok** on the new graph |
| Grammar validator | DONE | one total validator, the §3.2 table exactly (plain / obfs4 `cert=`+`iat-mode=0,1,2` / webtunnel `url=https://…`+`ver=hex`), snowflake and every other name refused distinctly; 10⁶-run seeded property test |
| `TransportConfig.pt_dir` + JNI | DONE | additive: `nativeCreate` gains one `ptDir` string (empty = PT unavailable); no new error category (`PtBinaryMissing` maps to the config class `bridge_config`, design §8.3) |
| ptmgr wiring | DONE | `[bridges.transports]` gets one managed entry (`protocols = [obfs4, webtunnel]`, `path = <pt_dir>/lyrebird`, `run_on_startup = false`); existence checked up front (`PtBinaryMissing`); per-attempt state isolation via the existing per-attempt `state_dir` → arti's `<state_dir>/pt_state` |
| Env scrub | DONE (mechanism recorded) | ptmgr inherits the process environment (S0-T4); GHOST scrubs its own process environment before the first PT-spawning client: proxy variables + `HOME` removed, `TMPDIR` redirected into the attempt's state dir (§4) |
| Unit suites | GREEN | PT-U1/PT-U2/PT-U5/PT-U6 in-crate; PT-U3 = the Phase 6 tests unmodified and green; PT-U4 (auto-mode sequence) and PT-U7…PT-U9 are S2's (Kotlin session owner / storage / extraction), see §6 |
| Gates | GREEN | `rust-feature-policy.sh`, `rust-client-allowlist.sh`, `dependency-allowlist.sh`, `ch-derivation-inputs.sh`, `proto-check`, `license-notices.sh rust` all green (§7) |

### 0.2 Normative notes (for the design's next revision, per its own convention)

| # | Sections | Note (short) |
|---|---|---|
| S1-T1 | §5.1/§5.2 (ptmgr contract) | `run_on_startup` is **stored but unread** in tor-ptmgr 0.46: managed PTs launch lazily on the first channel request, regardless of the flag (verified in the crate source: `PtMgr::get_cmethod_for_transport` → `spawn_transport`; no reader of `run_on_startup` outside `config.rs`). GHOST sets the flag to `false` anyway to pin the lazy policy against future arti behaviour. Consequence recorded, not a correction: **client creation never spawns a PT process** — the S1 unit suites build and create PT configs with a placeholder binary file; the real spawn is proven by S3's PT-L harness |

**Owner questions:** none new. Q-S-T3's order stands (arti-side loopback is S3's PT-L2).

---

## 1. The feature delta (V-T7 finished)

`ghost/Cargo.toml`: `arti-client` features gain exactly **`pt-client`** (ADR-61 point 5; the design's §5.1 "one line"). The `default-features = false` discipline is untouched; the feature chain is arti's own (`pt-client = bridge-client + tor-chanmgr/pt-client + tor-guardmgr/pt-client + tor-ptmgr`, `arti-client-0.46.0/Cargo.toml:189-194`), and `tor-ptmgr`'s default features (`managed-pts`, `tor-channel-factory` — the managed-spawning halves, S0 evidence §5) are what arti names. No `pt-server` exists on arti-client or tor-ptmgr; the feature gate now fails if either ever gains it (§5).

Measured graph delta (`cargo tree -p ghost-client-net -e normal` on both Android triples, `--locked`):

- **New package names: exactly one — `tor-ptmgr 0.46.0`** (MIT OR Apache-2.0, the S0-read licence). Its other direct deps (`derive-deftly`, `fs-mistrust`, `itertools 0.15`, `oneshot-fused-workaround`, `web-time-compat`, `visibility`, the arti family, `futures`, `serde`, `thiserror`, …) were already in the workspace graph — V-T7's draft list confirmed against the resolved lock.
- **Duplicate versions: no new name.** `itertools` gains a second copy (0.15 beside 0.14, tor-ptmgr's bound is `0.15`) but the committed baseline already allows `itertools 2` — the count stands; `rust-duplicate-versions.txt` needed no edit (the gate re-verified it, §7).

`cargo deny check licenses bans sources` (V-T7's exit criterion, "on the draft branch" — S1 **is** the draft branch): **licenses ok, bans ok, sources ok**. No new advisory-ignore entries were needed: every new locked crate is clean at its version; the pre-existing entries (rsa, paste, proc-macro-error2, the libcrux set) are untouched.

## 2. Licence/notice and allowlist updates (the standing checks of §5.1)

Per the gates' own patterns:

- `ghost/licenses/THIRD_PARTY_NOTICES-client-net.txt`: regenerated by `scripts/gates/license-notices.sh rust --write` — 479 → 480 components, the delta exactly the `tor-ptmgr 0.46.0` block. The crate ships no licence file (like the rest of the arti family), so it is carried under the SPDX MIT template and was **reviewed into `ghost/licenses/template-texts-reviewed.txt`** rather than left to fail G-L1.
- `ghost/client-core/rust-dependency-allowlist.txt`: gains the single line `tor-ptmgr` (alphabetical, matching the file's "name only" pattern).
- `ghost/client-core/rust-duplicate-versions.txt`: unchanged (see §1).
- `ghost/scripts/gates/rust-feature-policy.sh`: `pt-client` moves from the arti-client forbidden list to the **required** list (Phase 12 is the ADR that enables it); a new clause forbids `pt-server` on `arti-client` and `tor-ptmgr` (design §13: arti must never gain the server feature — neither crate defines it today, so the clause arms the moment either does).
- `ghost/scripts/gates/dependency-allowlist.sh`: **no change** — it reads only Gradle coordinates (`dependency-allowlist.txt`, Maven group prefixes); the design's §13 line naming it alongside the Rust lists is about the extension *family*, and a Rust-only delta adds no Maven coordinate. The gate runs green unchanged (§7).

## 3. The grammar validator (design §3.2, §6.2; ADR-62 point 3)

New module `ghost/client-core/net/src/bridge_line.rs` (crate-private; nothing new crosses the crate boundary). One total validator:

- **Accepted, the complete list:** plain `IP:PORT 40-hex-fingerprint` (unchanged from Phase 6); `obfs4 IP:PORT FP cert=<base64> iat-mode=<0|1|2>` (parameters in either order, each exactly once); `webtunnel IP:PORT FP url=<https://…> ver=<hex>` (either order, each exactly once). IPv6 bracketed literals parse as addresses.
- **Structural checks only** (§6.2 point 2): the fingerprint is 40 hex chars; `cert=` is standard-alphabet base64, length ≡ 0 (mod 4), at most two trailing `=`; `iat-mode` is exactly 0, 1 or 2; `url=` starts `https://`; `ver=` is non-empty hex. Contents are never interpreted — arti/ptmgr own the protocol.
- **Refused distinctly:** `snowflake …` → `BridgeLineError::SnowflakeDeferred` (the 12b deferral is the pinned contract, G-T8); any other transport-name shape → `UnsupportedTransport`; structural failures → `Malformed(<static label>)` (address / fingerprint / parameter / cert / iat-mode / url / ver). Labels are static strings — **no input text ever enters an error**.
- **Set rules:** 1 024-char cap per line; at most 8 lines (the first overflowing index is the error); exact-string duplicates deduped (§6.2 point 4 — dedup, not refusal).
- **Totality:** `validate_set` never panics and never over-reads; the PT-U5 property runs 10⁶ seeded random inputs (deterministic splitmix64, no new dev-dependency) per CI run as §6.2 point 5 pins.

`build_config` validates the set **before arti's parser sees a line** (§3.3: arti's `PluggableTransportsNotSupported` branch can never fire for snowflake — GHOST's pre-validation refuses it first), names the failing **index** in the config error, and pushes only the deduped lines.

## 4. `TransportConfig.pt_dir`, `PtBinaryMissing`, the ptmgr wiring, the env scrub

**`TransportConfig`** (design §5.2's exact shape) gains `pub pt_dir: Option<PathBuf>` — `None` = PT unavailable. **`TransportError`** gains `PtBinaryMissing` (config class): returned up front when a PT line is present and `pt_dir` is `None` **or** `<pt_dir>/lyrebird` is not a file — a missing binary is a create-time config error, never a bootstrap-time hang.

**Wiring** (`TorTransport::build_config`, the only wiring site):

- One `[bridges.transports.<name>]` entry (the V-T4 contract): `protocols = [obfs4, webtunnel]` (one lyrebird process serves both per the pt-spec env protocol), `path = <pt_dir>/lyrebird` as a literal `CfgPath`, `run_on_startup = false` (S1-T1: ptmgr 0.46 launches lazily; the explicit `false` pins that policy if a future arti implements the flag).
- The bridge lines then parse through arti's own `BridgeConfigBuilder::parse` (with `pt-client` compiled in it accepts obfs4/webtunnel) and `bridges.enabled = true` exactly as before; arti's config validation in turn requires every PT line's transport to have a transports entry, so the two halves cannot drift apart silently.
- **State isolation per attempt** (§5.3): arti creates `<state_dir>/pt_state` and hands it to ptmgr as `TOR_PT_STATE_LOCATION` (V-T4, `arti-client/src/client.rs:1176-1187`); ptmgr extends it per binary (`pt_state/lyrebird/`). Because every bootstrap attempt is already a fresh client with its own `state_dir`, the per-attempt PT state dir is the existing attempt dir — deleted with the attempt by the caller, no new bookkeeping (obfs4's client identity derives from the line's `cert=`, so there is nothing to keep, §7.1).
- **The CMETHOD contract** (V-T4): ptmgr requires the `CMETHOD` endpoint to be localhost (`ipc.rs:234`) and passes bridge ARGS in the SOCKS username field — GHOST adds nothing here; the loopback proof is S3's PT-L.

**Env scrub (the mechanism, per §5.3 and S0-T4).** ptmgr spawns with `Command::new(path).args(arguments).envs(TOR_PT_*)` and **no `env_clear`** — the child inherits arti's (i.e. the app's) full process environment. arti exposes no per-spawn environment hook, so the only lever GHOST has is its own process environment, sanitised before the first PT-spawning client is created. `scrub_pt_child_env` (in `transport.rs`, invoked from `build_config` exactly when a PT line is present):

1. removes every proxy variable (`HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, both cases) — a PT makes its own connections; an inherited proxy would reroute and de-anonymise them;
2. removes `HOME` (must not point at readable storage);
3. sets `TMPDIR` to the attempt's own app-private `state_dir`, so any reckless child temp file lands inside the per-attempt dir the caller deletes with the attempt.

Removal is idempotent and the function is cheap, so it runs on every PT config build rather than guarding on a `Once` — concurrent transports racing on `TMPDIR` is harmless (every candidate dir is an app-private attempt dir). No PT logging knob was needed: ptmgr logs via `tracing` only and GHOST's log plumbing is untouched (§7.4's canary is S3's G-T7 work).

**JNI surface** (design §8, additive): `nativeCreate` gains one trailing parameter `ptDir: String` (empty = `None`); Kotlin `TorRelayTransport.create/start` gain `ptDir: File? = null` (callers unchanged). Error categories: **no new constant** — `PtBinaryMissing` is config class and maps to `bridge_config` (§8.3), whose README row was reworded (PT lines are no longer "not yet activated"; snowflake stays refused, PT-without-binary is the new `bridge_config` case). The PT-1 … PT-5 functions and their `PT_HASH_MISMATCH` / `PT_UNSUPPORTED_ABI` / `BRIDGE_LINE_INVALID` / `BRIDGE_LINE_UNSUPPORTED_TRANSPORT` constants are **S2's** surface (extraction + storage land with the Android slice); nothing in S1 pretends to ship them.

## 5. Gates (each run on this branch; ADR-58 local)

| Gate | Result |
|---|---|
| `scripts/gates/rust-feature-policy.sh` | **OK** — `pt-client` required and present; `pt-server` clause armed; all pre-existing clauses green |
| `scripts/gates/rust-client-allowlist.sh` | **OK** — the shipped graph on both triples is on the allowlist (the one new name added); the duplicate union matches `rust-duplicate-versions.txt` exactly (stale-line check included) |
| `scripts/gates/dependency-allowlist.sh` | **OK** — unchanged, as designed (Gradle coordinates only) |
| `scripts/gates/license-notices.sh rust` | **OK** — committed notices equal the regenerated ones (after `--write`, diff reviewed: only the tor-ptmgr block) |
| `scripts/gates/ch-derivation-inputs.sh` | **OK** — `derive.rs` untouched; gate run anyway, green |
| `scripts/gates/proto-check.sh` | **OK** |
| `cargo deny check licenses bans sources` | **OK** — licences/bans/sources |

`cargo fmt --all -- --check`: clean. `cargo clippy --locked -p ghost-client-net --all-targets -- -D warnings`: see §7.

## 6. Unit suites (design §12.2, the S1-owned rows)

- **PT-U1** — `bridge_line.rs` tests: every acceptance (plain, obfs4 × all three iat-modes, webtunnel, either parameter order, IPv6) and every refusal (snowflake distinct — twice, including a shape that would parse as malformed for any other name; unknown transport; empty; bad address/fingerprint/cert/iat-mode/url/ver; missing/duplicate/unknown parameters; the length cap; the 8-line cap; dedup with surviving indices; error strings never containing line text).
- **PT-U2** — `transport.rs::pluggable_transport_lines_need_the_pt_binary`: `pt_dir = None` → `PtBinaryMissing`; `pt_dir` set but no binary → `PtBinaryMissing`; placeholder binary → config builds. Plus the direct/plain shapes unchanged.
- **PT-U3** — the Phase 6 transport tests run **unmodified and green** (CS-T2): bootstrap-deadline/spent semantics, no-implicit-bootstrap, keystore-empty, isolation tokens, setup-vs-config error classes.
- **PT-U5** — the 10⁶-input totality property (§3).
- **PT-U6 (in-process half)** — `a_pt_configured_client_leaves_no_line_or_key_on_disk`: create with an obfs4 line + placeholder binary, drop, then assert the keystore is empty and no file under state/cache contains the fingerprint or the cert (the T58 canary discipline in-process; PT-P1 completes it with a real bootstrap and a filesDir scan in S3).
- The **refusal relaxations** are pinned by tests at both levels: `bridge_line.rs` (grammar) and `transport.rs` (`snowflake_lines_stay_refused` asserts the distinct deferral error names the index, never the line; `pluggable_transport_lines_need_the_pt_binary` asserts obfs4/webtunnel now build with a binary present — G-T8's fixtures).
- **PT-U4** (the reduced auto-mode sequence) is **S2's**: §8.1 places the sequence in the sync runtime's session owner (Kotlin), and PT-U4's mocked-transport test belongs beside it. **PT-U7…PT-U9** are likewise S2 (JVM). S1 leaves the auto mode to S2 deliberately — no half-built policy was smuggled into Rust.

## 7. Test and lint results (this branch)

Measured on the S1 worktree (`p12-s1`, `CARGO_TARGET_DIR` = the p12s1 scratch dir, `CARGO_PROFILE_*_DEBUG=0`):

- `cargo fmt --all -- --check` — **clean** (run before and after the final edit).
- `cargo clippy --locked -p ghost-client-net --all-targets -- -D warnings` — **green, no warnings** (one `manual_is_multiple_of` finding in the new validator fixed with `is_multiple_of`; nothing suppressed).
- `cargo test --locked -p ghost-client-net` — **green**: lib 74 passed / 0 failed (includes the 13 new `bridge_line` tests and the new `pluggable_transport_lines_need_the_pt_binary`, `snowflake_lines_stay_refused`, `a_pt_configured_client_leaves_no_line_or_key_on_disk` transport tests; the 10⁶-input property runs in ~1 s), integration suites 5 + 5 + 9 + 2 + 0 (1 ignored, the live-tor test, unchanged) + 7 + 3 + 7, all ok. The Phase 6 transport tests are in the 74 and pass unmodified (CS-T2).

## 8. Pending by design (not S1 scope)

- **The host-library size re-measure** (`libghost_client_net.so` growth from `pt-client`, §9.1's re-measure): comes with the integration build in S2/S3 — the Android cross-builds and the Phase 10 budgets are measured there, not from a host `cargo check`.
- **PT-U4, PT-U7 … PT-U9**: S2 (Kotlin/JVM).
- **PT-L1/PT-L2, PT-P1 … PT-P3, G-T1 … G-T8**: S3.
- The `snowflake` grammar, the PT-1…PT-5 JNI functions and their error constants: S2/12b per the deferral boundary (§3.4).

*Prepared on `p12-s1`; no commit made (the lead reviews and commits). Scratch logs: `D:\Forum\.claude\s1\`.*
