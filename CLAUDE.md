# GHOST — project instructions for every session and subagent

## CI policy (owner decision 2026-10-04, official and permanent until the owner changes it)

**All CI runs LOCALLY on the owner's machine. Nothing is run through GitHub Actions.**

- Never add, enable, edit-to-extend, trigger or wait for a GitHub Actions workflow (`.github/workflows/**`, `gh workflow run`, `gh run ...`, hosted or self-hosted runners). Pushing to GitHub is only for backup and sharing; a push is never a verification step and nothing may depend on a remote run.
- A gate, check, nightly, exit gate or fuzz/model job is specified as a **local script** (`ghost/scripts/gates/*.sh` for static gates, `ghost/scripts/ci/*.sh` for long jobs) with negative fixtures and `self-test.sh` cases. Where a design or a brief says "workflow", "CI job", "`*.yml`" or "runner", read it as "local script with the same content, run on the owner's machine"; do not create the `.yml`.
- The merge signal is the **local verification recipe**, run on the exact commit and recorded with its commit hash and numbers (STATUS or the slice's forward notes):
  - Rust: `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked` (the touched crates at least; the workspace when practical), `cargo deny check` when dependencies changed. `CARGO_TARGET_DIR` on C: under `C:\Users\mihai\AppData\Local\Temp\ghost-target-<name>` (test executables cannot run from D:), `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`, delete `*.pdb` and the directory when done.
  - Kotlin: from `ghost/android`, `./gradlew --no-daemon clean` then `./gradlew --no-daemon --continue --no-build-cache build -Dghost.dm.native=<ghost_dm_host.dll>` (host library built with `cargo build -p ghost-dm-host --release --locked --features provenance`); JUnit sums per module with `skipped=0`; `dm-report-check.sh` on `report.txt` (`pr`) and `privacy.txt` (`privacy-pr`).
  - Gates: `GHOST_YAML_VIA_WSL=ghost-runner bash ghost/scripts/gates/run-all.sh`, and the WHOLE `self-test.sh` in WSL on a `git archive` of HEAD (`.claude/scratch/selftest-wsl.sh`), expecting 0 failures. (`proto-check` needs `protoc`, which only the Windows side has.)
  - Long jobs (privacy worlds, fuzzing, state models, emulator suites) run on request or on a schedule the owner approves, as local scripts; their reports are checked with the matching `*-report-check.sh`.
- The existing `.github/workflows/*.yml` and the self-hosted runners are **legacy**: do not extend them, do not rely on them, migrate their content to local scripts (see `docs/CI_LOCAL.md`, ADR-58). Actions is disabled on the repository and the runners are stopped (owner's decision, 2026-10-05); the workflow files are deleted when their content is migrated.

## Working rules (see the memory files for the reasons)

- The owner writes Romanian: reports to the owner are short and in Romanian; code, design documents and commit messages follow the repository's existing language.
- No code for a phase before the owner approved its design. Between slices of an approved phase, continue without asking.
- Delegated work: Opus 5.5 for cryptography, protocol and privacy-critical slices; Sonnet 5.5 for the usual work. Every slice: Implement, two adversarial reviews, Fix, then independent verification by the lead.
- Never delete anything of the owner's other projects (ospelio, m4); do not touch Docker data, WSL distributions other than `ghost-runner`, or system settings without the owner's explicit yes.
- Disk: C: is small. Big outputs on D:; cargo target directories on C: only as above and removed afterwards.
