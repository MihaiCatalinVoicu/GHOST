# p11-s1: fixing the review of Phase 11 slice S1 — progress (for a fresh agent)

Branch `p11-s1` (worktree `D:/Forum/.claude/worktrees/p11-s1`), never pushed, never merged. Cargo:
`CARGO_TARGET_DIR=C:\Users\mihai\AppData\Local\Temp\ghost-target-p11-s1`. The design's record of this
work is `docs/design/faza11-media.md` §22.2 rows 2–3, 5–10, 13, 15–16, 18–19, 21 (amended) and the new
rows 27 (the review's dispositions) and 28 (left to S2); row 29 (the runs after the review) is still
to be written (see "Next").

Trap found: the shared target directory reuses test binaries built from relocated copies of the
workspace (cargo's fingerprints are workspace-relative), whose `CARGO_MANIFEST_DIR` points at the
copy; after any reviewer ran in a copy, run `cargo clean -p ghost-client-media` first.

## Findings fixed (reviewer A = format/crypto/hostile input, B = fidelity/gates/honesty)

- A1 SPS coded frame exact 80 × 45 MBs, no cropping, level 3.1 DPB bounds (`src/sps.rs`; vectors; ms25, ms26).
- A2 wiped buffers never grown in place (`src/bytes.rs` `extend_wiped`/`reserve_wiped`, sealer, jpeg
  `canonicalize` → `Zeroizing`, `Descriptor::encode` → `Zeroizing`, walkers); `tests/zeroize.rs`; ms27–ms29.
- A3 vectors `image_content_with_app1` (new op `reseal_content`), `padding_chunk_not_zero`; sealer test; ms30–ms32.
- A4/B3 fMP4 cases moved to the last fragment, tile-consistent AAC, empty trun, AUD stop bit, VUI SAR,
  JPEG scan params, PPS/SPS headers and 513-byte bounds, SEI 1 025, 4-byte sample, 1 025 fragments,
  nine brands, `check_preview(240,160)`; own-reason test 31 → 54; ms34–ms50.
- A5 registry digests AD + plaintext, records repeats; vector reseals use the tests' own AEAD; ms33.
- A6 hand-written Debug (Descriptor, Manifest, SealedObject, walkers); ms51, ms52.
- A7 JDK replay walks image content (`MediaVectorReplayTest.kt`), `reseal_content`, JPEG table rules, 32 brands.
- A8 JPEG tables bounded (each table/DRI once, components once, tables before scan); video free bytes declared (row 9).
- A9 sniffer: 32 brands, claim reworded. A10 wording rows 2, 3.
- B1 `aead-stream =0.6.0` dev-dependency + `tests/oracle.rs` (decision: IN, per ADR-44 point 10).
- B2 `media-crate-purity.sh` tightened + 15 fixtures (`test-harness/gates/media-purity/*`) + self-test lines; `clippy.toml` 30 paths.
- B4 STATUS.md row, "S1 brief" citations replaced. B5 `media-mutants.sh` NOT RUN. B8 §17.1 S0a row, row 9.
- B7 hooks + self-test cases: `GHOST_POLICY_MEDIA_SHIPPED`, `GHOST_POLICY_MEDIA_METADATA`
  (`test-harness/gates/media-policy/`), `licenses.pl` required own crates (`GHOST_LICENSE_GRAPHS`,
  `GHOST_LICENSE_REQUIRED_OWN`), clock-log auto switch (`GHOST_G_R8_MEDIA_LINKER`).

## Decisions

- aead-stream oracle: IN (dev graph only; lock adds exactly aead-stream 0.6.0).
- B6/A10 read mode: NOT changed (§7.4 needs reads without a pass); recorded for S2 in row 28 with options.
- A8: JPEG tightened; PPS body, SEI 0/1/6 bodies, esds bitrates, SPS timing/HRD declared with options (row 9).
- A5: S2 worlds fail on any violation/repeat, vector keys allowlisted (row 28).

## Verified so far (2026-10-04, working tree before the first WIP commit)

- `cargo test --locked -p ghost-client-media`: 67 pass (27 unit, 40 integration), 1 ignored.
- Gate scale (release): properties 10 000 objects / 4 096 flips OK; sweep full OK; hostile 10⁶ OK;
  oracle 240 objects (1 264 chunks) OK; zeroize OK.
- Mutants: `bash scripts/ci/media-mutants.sh` → 52 run, 52 detected.
- JDK: `./gradlew --no-daemon --offline :media:testDebugUnitTest --rerun` → 4 tests, 0 skipped, 219 values, 50 negatives.
- fmt clean; clippy `-p ghost-client-media --all-targets -D warnings` clean; `cargo deny --offline check licenses bans sources` ok.
- Gates: media-crate-purity real tree + 27 purity self-test cases OK; the 7 new cargo self-test cases OK.

## Next (in order)

1. Workspace clippy: `cargo clippy --locked --workspace --all-targets -- -D warnings` (was running).
2. WSL self-test on the tree: tar the tracked+untracked files into `ghost-runner` (`/tmp/p11s1-st`),
   `cd ghost && bash scripts/gates/self-test.sh`; count `self-test ok` / `SELF-TEST FAIL`.
3. `GHOST_YAML_VIA_WSL=ghost-runner bash ghost/scripts/gates/run-all.sh`; plus `rust-client-allowlist.sh`,
   `rust-feature-policy.sh`, `media-rust-no-logging.sh`, `media-vendored-clock-log.sh`,
   `license-notices.sh rust`, `rust-license-headers.sh`, `mpl-sources.sh`, `rust-crypto-pins.sh`.
4. Release timing re-run on a quiet machine (`cargo test --release -p ghost-client-media --test timing -- --ignored --nocapture`);
   the loaded run gave 3.5 ms/chunk seal vs row 17's 0.74 — check it is load, not a regression.
5. Write §22.2 row 29 (the runs above), then the final commit (not WIP) and the report.
