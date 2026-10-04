# GHOST external audit: build and review guide

| Field | Value |
|---|---|
| Purpose | How an auditor under NDA gets the source, builds each component with the pinned toolchains, runs tests and gates, and finds the specification of each module. |
| Handling | **Confidential, for auditors under NDA.** |
| Base commit | `a0f3f58ef76bfd4e45f73fd0f1eaf9a89d5750e5` (2026-10-03; revised 2026-10-04 after two adversarial reviews). The audit itself should use a frozen tag (section 1.2). |
| Status of the commands | Commands marked **[CI]** are copied from the workflows that ran them on the project's runners; **[doc]** are from repository documents; **[R]** were run for this package (on 2026-10-03 the gate scripts, `EVIDENCE_INDEX.md` section 1; on 2026-10-04 the hand-over recipes of section 1.2, the host-library build of section 3.2 on a clean `git archive` copy, test listings, and one self-test case). The Gradle builds, the Android native build and the test suites were **not** re-run for this package, so those commands are as recorded by the project. |
| Companion files | `AUDIT_SCOPE.md`, `EVIDENCE_INDEX.md`, `KNOWN_ISSUES.md`, `AUDITOR_RFQ.md`; the static CI evidence `ci-runs.tsv` and `ci-log-facts.tsv`; the scripts `tools/measure.sh` and `tools/check-package.sh`. |

---

## 1. Getting the source (the repository is private and proprietary)

### 1.1 Legal and procedural prerequisites

* The root `LICENSE` is "Copyright (c) 2026 Mihai Voicu. All rights reserved." and grants **no** licence to use, copy or modify without written permission. An auditor therefore needs, before receiving anything, a signed NDA **and** a written limited-use licence for the audit (ADR-38 point 4: "access to source for auditors and vetted researchers under a limited-use licence"). Both are the owner's to draft; `AUDITOR_RFQ.md` section B6 lists the clauses to ask for.
* The repository was **public from 2026-09-10 to 2026-09-16** (history up to `3edf9dd`, 118 commits, under a `MIT OR Apache-2.0` declaration). Treat that part of the history as public (ADR-39 point 1). Nothing in the audit depends on secrecy of the code (CP-09: security must not rest on the source being secret).
* Language: the design documents (`docs/design/*.md`) and all code comments are in **English**. These are in **Romanian**: `docs/THREAT_MODEL_v2.1.md` (36 KB), `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` (106 KB), `ghost/test-harness/privacy/INVARIANTS.md` (50 KB), `docs/STATUS.md` (30 KB), the master plan (61 KB), `docs/ci-self-hosted.md` (27 KB), `ghost/infra/issuer/RUNBOOK.md` (57 KB), all ADRs (237 KB, 36 files), and the Appendices A and B of the phase designs (ADR drafts and text changes). About 600 KB of Romanian text in all (sizes are decimal kilobytes of the files at the base commit). `AUDIT_SCOPE.md` section 7 gives an English digest of the claims in the first three; **the owner should decide whether to commission English versions of THREAT_MODEL, INVARIANTS and LIMITE before the audit** (preparation step owed, see `README-RO.md`), otherwise the auditor will need translation time.

### 1.2 What to hand over and how

**Do not add auditors as GitHub collaborators.** On a repository owned by a personal account GitHub grants collaborators write access only ("Collaborators can't have read-only access", https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-user-account-settings/permission-levels-for-a-personal-account-repository , accessed 2026-10-03), and the CI of this repository runs on **self-hosted runners on the owner's laptop** that execute any workflow a pushed branch contains, with passwordless `sudo` and Docker inside the runner distribution (`docs/ci-self-hosted.md` §10). A collaborator could therefore run code on the owner's machine. Use one of:

1. **A signed source bundle (recommended).** Owner side, from a clean checkout of the frozen commit (an annotated tag needs `user.name` and `user.email` to be configured):

   ```bash
   git tag -a audit-rc1 -m "GHOST audit snapshot" <commit>        # sign the tag (-s) if the owner has a signing key; commits themselves are unsigned (FR-8.1 gap)
   git bundle create ghost-audit-rc1.bundle audit-rc1               # full history reachable from the tag
   sha256sum ghost-audit-rc1.bundle > ghost-audit-rc1.bundle.sha256
   git rev-parse audit-rc1^{commit}                                  # communicate this id and the SHA-256 over a separate channel
   ```

   Auditor side, in an empty directory **outside any repository**, with the bundle and its `.sha256` file side by side:

   ```bash
   sha256sum -c ghost-audit-rc1.bundle.sha256 && git clone ghost-audit-rc1.bundle ghost && cd ghost && git bundle verify ../ghost-audit-rc1.bundle && git checkout audit-rc1 && git rev-parse HEAD
   ```

   Then compare the printed commit id, and the first field of the `.sha256` file, with the values received through the separate channel. `git clone` prints `warning: remote HEAD refers to nonexistent ref, unable to checkout`: that is expected, the bundle carries only the tag, and the next steps check it out. `git bundle verify` needs a repository, so it comes after the clone (run outside a repository it stops with `error: need a repository to verify a bundle`, and a chain that starts with it never clones). The bundle is not authenticated by git: commits are unsigned, so the out-of-band hash and commit id are the integrity check. [R, 2026-10-04: the owner-side and auditor-side sequences were run end to end on a throwaway clone of this repository; `tools/check-package.sh` repeats them on a small repository.]
2. **A snapshot without history**, for an auditor who does not need `git blame`: `git archive --format=tar.gz --prefix=ghost-audit-rc1/ audit-rc1 ghost docs output .github .gitattributes .gitignore LICENSE README.md > ghost-audit-rc1.tar.gz` (excludes `legacy/`, 80 files of quarantined prototypes that are not built or shipped; keeps `.gitattributes`, whose `eol=lf` and `binary` rules matter if the tree is committed again on Windows). [R, 2026-10-04: runs as written; without the two dot files in the list they are missing from the archive.]
3. **A separate private repository in a GitHub organisation** (where read-only roles exist) with **Actions disabled** and no runners registered. This is the only variant that gives an auditor `git` access without a file hand-over; the owner must create the organisation and mirror the tag.

**What option 1 also hands over.** The full history carries the author and committer e-mail addresses of all 391 commits at `a0f3f58`: 371 of them the owner's personal address, 1 a second personal address (`KNOWN_ISSUES.md` KI-SUP-9), although ADR-39 point 4 says future commits use a no-reply identity. Choose option 2 if that is not acceptable.

Deliver by an encrypted channel named in the NDA. Do not give the auditor any CI token, runner credential, signing key, Monero wallet or onion key: **none of these is in the repository** (the entitlement-schedule gate refuses sealed key files, key-load files and onion secret keys outside the test fixtures), and the stagenet schedule key, custody secret and onion keys live outside the repository by design (`ghost/protocol/entitlement/README.md`).

### 1.3 What to include beside the source

* This `docs/audit/` directory (it is inside the repository), and the output of the gates at the frozen commit (`run-all.sh`, `self-test.sh`, the JUnit XML sums) so the auditor can compare.
* The **CI evidence**: `ci-runs.tsv` and `ci-log-facts.tsv` are static copies of what this package cites, because the auditor has no account on the private repository and GitHub keeps job logs for only 90 days (artifacts 3 days). If the owner wants to give more, export the logs of the cited runs while they exist (`gh run view <id> --repo MihaiCatalinVoicu/GHOST --log`) and the gate reports of the frozen tag; the retention can be raised up to 400 days (`gh api repos/MihaiCatalinVoicu/GHOST/actions/permissions/artifact-and-log-retention`, an owner setting).
* A **dependency snapshot** if the auditor works offline or wants byte-identical inputs: `cd ghost && cargo vendor --locked` (the checksums are already in `Cargo.lock`), and a Gradle offline cache; Gradle dependency verification (`ghost/android/gradle/verification-metadata.xml`) pins every Android artefact by SHA-256. (Inferred suggestion; the project has not produced such a snapshot.)
* Confirmation that the frozen tag embeds an Entitlement Schedule covering the audit period: the committed schedule is stagenet seq 1, access weeks 2957..2989 (ISO 2026-W37 to 2027-W16); a build embedding it must ship by week 2964 (Monday 2026-10-26) and seq 2 is due to releases by week 2982 (`ghost/protocol/entitlement/README.md`). An audit after those dates needs a later schedule signed with the (stagenet) schedule key held by the owner.

---

## 2. Toolchains and pins

| Tool | Version | Pinned in | Notes |
|---|---|---|---|
| Rust | **1.98.1**, components `rustfmt`, `clippy`; targets `aarch64-linux-android`, `x86_64-linux-android` for the native library | `ghost/rust-toolchain.toml`; targets added by the build scripts/CI | MSRV of OpenMLS 0.9.0 is 1.91 (Phase 10) |
| Cargo | `--locked` always | CI and gates | `ghost/Cargo.lock`, 651 packages |
| cargo-ndk | **4.1.2** (`cargo install cargo-ndk --version 4.1.2 --locked`) | `ghost/scripts/build-native.sh` | The script refuses another version |
| Android NDK | **30.0.16248370** | CI runner image (`docs/ci-self-hosted.md` §2.2); `ANDROID_NDK_HOME` | |
| Android SDK | platforms `android-37.0` (and `37.2` on the runners), build-tools `37.0.0` (and `36.0.0`); compile/target SDK **37**, min SDK **29** | `ghost/android/gradle/libs.versions.toml`; runner image | `ANDROID_HOME` or `local.properties` (`sdk.dir=`) |
| JDK | **17** (Temurin 17.0.20 in CI; 17.0.20.1 on the author's machine) | `compileOptions` source and target compatibility `VERSION_17` in each of the nine modules' `build.gradle.kts`; there is **no** `jvmToolchain`, so the JDK that runs Gradle also compiles | `ghost/docs/DEVELOPMENT.md` still says `jvmToolchain(17)` (`KNOWN_ISSUES.md` section 7) |
| Gradle | **9.7.1** via the wrapper; distribution SHA-256 `acd53f1e…804d20a` | `ghost/android/gradle/wrapper/gradle-wrapper.properties` | `org.gradle.jvmargs=-Xmx3g`, build cache and configuration cache on |
| AGP / Kotlin | **9.4.0** / **2.4.20** | `libs.versions.toml` | The modules apply only `com.android.application` or `com.android.library` (AGP 9's built-in Kotlin; no Kotlin plugin), `:app` adds the Compose compiler plugin; `android.builtInKotlin=false` appears only in `ghost/docs/DEVELOPMENT.md`, in no build file |
| protoc | **36.x** (CI installs 36.1 by hash; winget gave 36.0) | `ghost/scripts/install-protoc.sh <dir>`; PATH | Needed by `tonic-prost-build` (relay, client library) and `proto-check.sh` |
| cargo-deny | 0.20.2 (the version the design measured) | `EmbarkStudios/cargo-deny-action` in `ci.yml` | `cargo deny check` |
| cargo-audit | CI installs; `cargo audit --ignore RUSTSEC-2023-0071` | `ci.yml` | |
| ProVerif | **2.05**, release pinned by SHA-256 `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4` | `.github/workflows/pq-model.yml`, `ghost/protocol/models/dm/proverif.sha256` | CI tool only |
| cargo-fuzz / nightly | **0.13.2** (package SHA-256 `5acfd019…9400e2`) / **nightly-2026-09-25** | `ghost/client-core/dm/fuzz/rust-toolchain.toml`, `dm-fuzz.yml` | AddressSanitizer + debug assertions |
| Monero | `monerod` and `monero-wallet-rpc` **v0.18.5.1**, per-platform archives pinned by SHA-256 | `ghost/infra/issuer/monero-release.pin` | Only for `monero-regtest` and the issuer stack |
| Docker | Engine for relay/issuer images; base images `rust:1.98.1-bookworm`, `debian:bookworm-slim` | `ghost/infra/*/Dockerfile` | |
| Shell tools | bash, perl (gates), python3 + PyYAML (`workflow-yaml.sh`), node (optional) | | On Windows set `GHOST_YAML_VIA_WSL=<distro with python3-yaml>` |

**Reference environment:** Linux x86_64, Ubuntu 24.04 (the runner image). The author's workstation is Windows 11 with Git Bash; macOS was never used (inferred: untested). Resource guidance from the project's documents (inferred as a lower bound for you): 8 or more cores, 32 GB RAM for the gate-scale harnesses (each T32 gate job holds about 9 GB at its end: 6 GB heap + native + Gradle), `/dev/shm` of 24 GB for the T2 worlds (`GHOST_T2_TMP=/dev/shm`), 60+ GB disk with Gradle and Cargo caches.

---

## 3. Building each component

All paths from the repository root. `CARGO_TARGET_DIR` may point anywhere (on Windows pick a `C:` directory: Application Control can block test executables built on another volume, "os error 4551", `ghost/docs/DEVELOPMENT.md`).

### 3.1 Rust workspace (relay, issuer, client core, DM crate, test tooling) [CI]

```bash
cd ghost
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked                  # CI at 197b2b4 and d1a19cd: 840 passed, 0 failed, 63 ignored
cargo deny check                                  # advisories, bans, licenses, sources
cargo audit --ignore RUSTSEC-2023-0071
```

Members: `relay/crates/*`, `issuer/crates/*`, `client-core/{net,dm,dm-host}`, `test-harness/privacy/{capture-check,t2-join}`, `test-harness/vendored-scan`. `client-core/mls-spike` and `client-core/dm/fuzz` are separate workspaces.

### 3.2 The host library for JVM tests (`ghost-dm-host`) [CI]

DM tests on the JVM call the *real* Rust crate through a host `cdylib`:

```bash
cd ghost && cargo build -p ghost-dm-host --release --locked --features provenance
# Linux: target/release/libghost_dm_host.so   Windows: ghost_dm_host.dll
```

[R, 2026-10-04: this command ran to completion, exit 0, on a `git archive` copy of `a0f3f58` on Windows 11 and produced `ghost_dm_host.dll` (1.5 MB); it reported 5 s because the target directory was warm, and a review of this package reported 2 min 17 s on a cold one.]

Hand it to Gradle with `-Dghost.dm.native=<absolute path to the library>`. **Trap:** without it the DM tests *skip silently*. Always check `skipped=0` in `ghost/android/<module>/build/test-results/**/TEST-*.xml` (`messaging` has 329 tests; if it reports fewer, the native library did not load). Before the Android builds, CI cleans the three libcrux build-script packages so a stale SIMD cfg cannot survive (`cargo clean -p libcrux-ml-kem -p libcrux-sha3 -p libcrux-intrinsics …`, gate G-R3 `libcrux-portable.sh` reads cargo's build messages).

### 3.3 The native Android library [CI][doc]

```bash
export ANDROID_NDK_HOME=<sdk>/ndk/30.0.16248370
bash ghost/scripts/build-native.sh <out-dir> <sums-file>     # writes <out-dir>/{arm64-v8a,x86_64}/libghost_client_net.so and "sha256  abi/lib" lines
```

The script pins cargo-ndk 4.1.2, builds with `--locked` into a fixed target directory inside the workspace, remaps build paths, **fails if any builder path remains in the output**, and records SHA-256 sums. CI builds it twice at the same path and compares (`android native libs`). Without a `<sums-file>` argument it writes `ghost/native-libs.sha256`, a generated, git-ignored file (it is not in a clean checkout; in CI the sums come from the same run's `android native libs` job): pass an explicit path to keep two builds' sums apart. Cross-environment byte identity is *not* claimed (section 4.7).

### 3.4 Android app and unit tests [CI]

```bash
cd ghost/android
./gradlew build --no-daemon -Dghost.dm.native="$GHOST_DM_NATIVE"      # app, libraries, unit tests, lint, dependency verification
./gradlew --no-daemon :app:releaseRuntimeComponents                     # lists the release runtime components, read by the licence gates G-L1/G-L2 (ci.yml)
```

Useful switches (all read by the build files / tests): `-Dghost.dm.privacy=off` skips the privacy worlds, `=gate` runs the gate scale (unset: PR scale), `-Dghost.dm.privacy.seed=<0..9>`, `-Dghost.dm.crash=full` and `-Dghost.dm.seeds=64` (exit-gate scale), `-Dghost.dm.heap=<n>g` (test JVM heap; default 2 GB, the gate-scale T32 job uses 6 GB), `-Dghost.sync.seeds=20000 -Dghost.sync.exhaustive=full`, `-Dghost.entitlement.seeds=… -Dghost.entitlement.exhaustive=full -Dghost.entitlement.shard=i/12`. A Gradle `Unresolved reference` after a merge is a stale cache: `./gradlew clean`. `:messaging`'s test tasks are never taken from the build cache (they write reports as a side effect, review GATES-7). Expect about 40 to 75 minutes for a full build with the privacy worlds on a fast workstation (recorded: 1 h 11 min, 833 tasks).

### 3.5 Relay and issuer binaries and containers [doc]

```bash
cd ghost && cargo build --release --locked -p ghost-relay-node            # binary ghost-relay
cd ghost && cargo build --release --locked -p ghost-issuer -p ghost-issuer-ops
docker build -f ghost/infra/relay/Dockerfile -t ghost-relay ghost          # relay + Tor (v3 onion service), loopback only
GHOST_STAGING_KEYS=/srv/ghost-staging-keys docker compose -f ghost/infra/relay/docker-compose.staging.yml up --build   # three relays, slots 0..2 of the committed ES
```

The issuer stack (Tor, `monerod` stagenet, `monero-wallet-rpc` view-only, the issuer) is `ghost/infra/issuer/` (`Dockerfile`, `docker-compose.stagenet.yml`, `config.stagenet.toml`, `entrypoint.sh`, `snapshot.sh`, `journal-prune.sh`, `torrc`); the installation, key ceremonies (K1-K4), backups (B1), hard-fork procedure (M2), relay-operator procedure (O1), payouts (P1), reconciliation (R2), wallet loss (R5) and compromise response (I1) are in `ghost/infra/issuer/RUNBOOK.md` (Romanian, 883 lines). The Monero binaries come only from the pinned archive (`monero-release.pin`, gate `monero-pin.sh`). Operator key material is generated with `ghost-issuer-ops` **outside** the repository.

### 3.6 Offline model: ProVerif [CI]

```bash
bash ghost/scripts/gates/pq-model.sh        # needs the pinned ProVerif on PATH (see pq-model.yml for the fetch and SHA-256 check); compares each query with protocol/models/dm/expected.txt
```

---

## 4. Running the tests, gates and harnesses

### 4.1 Static gates (minutes)

```bash
bash ghost/scripts/gates/run-all.sh                 # the 18 source-only gates; expect "[<gate>] OK" x 18 and exit 0   [R: 17 on Linux in 75 s + proto-check]. The other 23 gate scripts need a build output or the git history and run in CI jobs only: table in EVIDENCE_INDEX.md section 1.1
bash ghost/scripts/gates/self-test.sh               # each gate must REJECT its negative fixtures; expect 0 "SELF-TEST FAIL"   [R: 649 ok on Linux, 15 min, cargo/protoc blocks skipped. A complete run has 736 cases: CI `rust` job, about 5 min on the runner, with the opt-ins below; 2.5-3.8 h on Windows]
```

Gates read `GHOST_ROOT` (default `ghost/`); fixtures are in `ghost/test-harness/gates/` (59 roots). CI additionally sets `GHOST_SELFTEST_CLIPPY=1 GHOST_SELFTEST_OPS=1 GHOST_SELFTEST_DENY=1` for the Rust block. Trap: `printf | grep -q` under `pipefail` can SIGPIPE (the gates use here-strings).

### 4.2 Test suites and exit-gate harnesses [CI]

| What | Command | Time (recorded) |
|---|---|---|
| Rust tests | `cd ghost && cargo test --workspace --locked` | about 10 to 30 min |
| T2 PR variant | `cd ghost && GHOST_T2_TMP=/dev/shm GHOST_T2_REPORT=/tmp/t2-pr.txt cargo test -p ghost-issuer --release --locked --test t2_unlinkability t2_pr_variant -- --exact --nocapture; bash scripts/gates/t2-report-check.sh /tmp/t2-pr.txt pr` | about 13 min |
| T2 gate pair `i` | `GHOST_T2_SCALE=gate GHOST_T2_SEEDS=i GHOST_T2_TMP=/dev/shm GHOST_T2_REPORT=… cargo test -p ghost-issuer --release --locked --test t2_unlinkability t2_exit_gate -- --ignored --exact --nocapture`, then `t2-report-check.sh … gate` | 94 to 123 min per pair |
| T2 mutants | `cargo test -p ghost-issuer --release --locked --test t2_mutants -- --ignored --nocapture`, then `t2-report-check.sh … mutants` | about 52 min |
| Issuer crash enumeration | `cargo test -p ghost-issuer --release --locked --test crash` | minutes |
| Sync exit gate | `cd ghost/android && ./gradlew --no-daemon :sync:testDebugUnitTest --rerun -Dghost.sync.seeds=20000 -Dghost.sync.exhaustive=full` | 12 to 31 min |
| Entitlement exit gate | `./gradlew --no-daemon :entitlement:testDebugUnitTest --rerun -Dghost.entitlement.seeds=<n> -Dghost.entitlement.exhaustive=full -Dghost.entitlement.shard=<i>/12` | 12 shards, 10 to 23 min each |
| DM messaging exit gate | `./gradlew --no-daemon :messaging:testDebugUnitTest --rerun -Dghost.dm.native=… -Dghost.dm.crash=full -Dghost.dm.seeds=64 -Dghost.dm.privacy=off`, then `bash ghost/scripts/gates/dm-report-check.sh messaging/build/reports/dm/report.txt gate` | about 5 h |
| DM PR-scale suite | `./gradlew --no-daemon :messaging:testDebugUnitTest --rerun -Dghost.dm.native=…`, then `dm-report-check.sh … pr` and `… privacy.txt privacy-pr` | 35 to 60 min |
| DM privacy gate, pair `i` | `… -Dghost.dm.privacy=gate -Dghost.dm.privacy.seed=i -Dghost.dm.heap=6g`, then `dm-report-check.sh … privacy-gate` | 52 to 110 min per pair |
| Monero regtest | workflow `monero-regtest.yml` (downloads the pinned binaries, checks `sha256sum -c`) | about 26 min |
| Signer timing | `cargo test -p ghost-issuer --release --locked --test signer_timing -- --ignored` (nightly workflow `signer-timing.yml`) | about 9 min |
| State models (EM-1, EM-2) | part of `cargo test -p ghost-client-dm` (`tests/state_models.rs`); the nightly `dm-state-models` runs `GHOST_DM_EM_SENDS=3 GHOST_DM_EM_WIRE=3 GHOST_DM_EM_BUDGET=4000000 cargo test --locked --release -p ghost-client-dm --test state_models -- --nocapture` (2,296,274 EM-1 states and 2,851,029 EM-2 states) | minutes; the nightly test 143 s |
| PQ mutants | `bash ghost/scripts/gates/pq-mutants.sh` | 45 min limit |
| Fuzzing | `bash ghost/scripts/ci/dm-fuzz.sh <seconds per target> <work dir> [target...]` (targets `card bundle intro_inner l0 tlvs olm_message`) | CI: 600 s each |
| Vendor suites | `bash ghost/scripts/ci/vendor-tests.sh 0.11.0 <work dir>` and `… libcrux <work dir>` | job limits 60 and 90 min; the libcrux suites ran in under 2 min after the first fetch |
| Reproducible release build | `bash ghost/scripts/gates/reproducible-build.sh <work dir> <sums file written by build-native.sh>` | 6 min on the runner |
| Live Tor (manual) | `cd ghost && cargo test -p ghost-client-net --locked --test live_tor -- --ignored --nocapture` (needs outbound Tor) | few minutes |
| Emulator device suites | `bash ghost/scripts/device/dm-emulator-run.sh <api: 29 or 35> <out-dir>` on a booted x86_64 emulator, then `bash ghost/scripts/gates/dm-emulator-check.sh <dir> 29 35` | 2 to 3 min per API level; the steps to reproduce on Windows are in design `faza9-dm.md` §22.32 item 13 |

### 4.3 What a green result means

Always read the report check (`*-report-check.sh`), not only the test exit: the checks pin mutant counts, crash-class lines and scale headers so a report cannot claim more than was measured. A JUnit XML with `skipped > 0` in `:messaging` means the DM world did not run. The checked-in report fixtures under `ghost/test-harness/gates/dm-report/` (including `pass-gate.txt`, which is **assembled**, not one real run) exist to test the checker, not as evidence.

### 4.4 Observing relays and the issuer dynamically

* The relay can write the T1 capture (`ghost-relay serve --data-dir <dir> --listen 127.0.0.1:7443 --capture <file.ndjson>`; `--data-dir` and `--listen` are required), validated by `cargo run -p ghost-capture-check -- --schema ghost/test-harness/privacy/allowed-observables.json --capture <file>`.
* A relay with an in-process peer for tests: `relay/crates/node/tests/{two_nodes,redeem,register,list_cursor}.rs`; issuer end-to-end scenarios use fake chain ports (`issuer/crates/service/tests/common/`) and the regtest chain in `monero_regtest.rs`.

### 4.5 Android runtime checks that exist

`ghost/scripts/device/dm-gate.sh` (physical-device gate, run through `dm-gate-self-test.sh` fixtures) and the instrumentation sources under `android/*/src/{androidTest,deviceRunner,equivalence,gate}`; `merged-manifest-lint.sh` on the merged release manifest; `apk-no-debug-hooks.sh <mapping.txt>` on R8's mapping. The "gate" build type is installed on gate devices only and never released.

### 4.6 Mutation testing recipes

The PQ mutants are patches in `ghost/client-core/dm/mutants/` (apply with `patch -p1`, run the named tests, they must fail); the ProVerif mutants are patches next to the models; the DM and T2 mutants are registered in the test source sets (`android/messaging/src/test/.../DmMutants.kt`, `issuer/crates/service/tests/t2_mutants.rs`) and enumerated by the report checks.

### 4.7 Reproducible build check

`bash ghost/scripts/gates/reproducible-build.sh <dir> <sums>` builds the release APK twice and compares; `apk-native-libs.sh <apk> <sums>` checks the contents. **Same path only.** To test cross-environment identity, build the tagged commit in a clean container at the *same* path as the reference and report differences: T12b (auditor-reproduced build) is exactly what ADR-38 plans and what does not exist yet.

---

## 5. Reading list (documents and their roles)

Sizes in lines; "RO" = Romanian. The design documents are long: read the parts named, not cover to cover. Rough effort for a cryptographer new to the project: 3 to 5 days for levels 0-2 and the parts of level 3 marked [key] **(inferred)**.

| Level | Document | Role |
|---|---|---|
| 0 | `README.md`, `ghost/README.md` (RO), `docs/STATUS.md` (RO, 30 lines of very long rows; **stale in places**, see `KNOWN_ISSUES.md` KI-DOC-1) | What exists. |
| 0 | `output/pdf/GHOST_Technical_Specification_v2_FINAL.pdf` §2 (principles CP-01..CP-10, guarantee matrix), FR/NFR tables, roadmap and gates | The baseline requirements; v2.1 changes it by delta. |
| 0 | `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md` (RO, 480 lines) §0, §3 (ADR-01..12 summaries), §4 (guarantee matrix), §6 (phases, row 15) | The plan and the audit gate. |
| 1 | `docs/THREAT_MODEL_v2.1.md` (RO, 194 lines): assets, adversaries AD-1..12, boundaries TB-1..7, exposure matrix per event, scenarios S1-S13 | **The model the audit tests against.** Independent review still owed. §2 (assets), §3 (adversaries), §4 (boundaries) and §5 (key lifecycle) are digested in English in `AUDIT_SCOPE.md` sections 1.1 and 6; entry points and data flows in sections 1.2 and 1.3. |
| 1 | `ghost/test-harness/privacy/INVARIANTS.md` (RO, 66 lines): T1-T35 | The claims and their tests. |
| 1 | `docs/LIMITE_REZIDUALE_SI_MITIGARI.md` (RO, 323 lines): L1-L7, E1-E34, L7-D1..D29 | What is declared not guaranteed. |
| 1 | `docs/audit/*` (this package, EN) | Digest and index. |
| 2 | `docs/adr/` (RO, 36 files): ADR-01 transport, 02 entitlement, 04 pseudonyms, 06 no SDKs, 07/37/38/39 distribution and closed source, 11 independent operators, 12/36 post-quantum, 17 Ed25519, 18 redb, 19 Rust core, 20 sync, **22-26 issuer**, 27 screen/text/ephemeral, **30'-36 DM**; ADR-40..43 (channels) are drafts in `faza10-forum.md` Appendix A | Decisions and their deviations from the spec. |
| 3 | `docs/design/faza7-sync-engine.md` (EN, 1,663 lines) [key] §0, §3-§4 (outbox/inbox contracts), §7, §9 (API), §11 (corrections win) | Sync engine contract (OUT/IN). |
| 3 | `docs/design/faza8-issuer.md` (EN, 2,949 lines) [key] §0 (decisions, guarantees), §1 (T2 statement), §2-§3 (crypto core, keys, ES), §5-§7 (service, storage/journal, Monero), §9-§10 (referral, relay redemption), §12 (residues), **§19 (normative corrections, wins)** | Entitlement issuer. |
| 3 | `docs/design/faza9-dm.md` (EN, 5,298 lines) [key] §0 (summary and guarantees P-1..P-8), §1 (views, LD), §2 (library), §3-§6 (identity/card, relay authorisation, addressing, envelope), §7-§10 (content and pipelines, sessions, **PQ plan §9.5 = the audit scope for DMs**, ephemeral), §21 (corrections), **§22 (forward notes; later notes win)**, Appendix C (verified vs assumed) | DM design and its history of corrections. §22.38 is the latest. |
| 3 | `docs/design/faza10-forum.md` (EN, 2,362 lines) [key] §0, §3 (**OpenMLS, §3.7 = the audit scope for channels**), §5-§6, **§19.27-§19.29 (win)**, Appendix C | Channels (not implemented on `main`). |
| 3 | `docs/design/faza11-media.md`, `faza13-ux.md`, `faza14-distribution.md` (EN) | Proposed designs of media, UI and distribution; read §0 and the scope tables only. |
| 4 | `docs/reviews/*.md` (Phase 6 RO, Phase 8 RO, Phase 9 EN) | Adversarial review results (AI reviewers). |
| 5 | `docs/design/faza9-s0-evidence.md`, `faza10-s0-evidence.md`, `faza9-s0-hygiene.md` | Measurements behind normative corrections; licence and public-history record. |
| 6 | `ghost/infra/issuer/RUNBOOK.md` (RO), `docs/ci-self-hosted.md` (RO), `ghost/relay/README.md`, `ghost/client-core/README.md`, `ghost/android/sync/README.md`, `ghost/client-core/dm/README.md` | Operations and component notes. |

---

## 6. Component to specification index

"F7/F8/F9/F10" are the phase designs. "Tests" lists the main evidence files (Rust under `ghost/<crate>/tests`, Kotlin under `ghost/android/<module>/src/test`).

| Component (path) | Specification | ADR | Main tests, vectors, models |
|---|---|---|---|
| Relay `relay/crates/*` | F8 §10 (redemption, capability v2, nullifiers); F9 §4 (RegisterKey, credential v3), §5 (addressing), §11; F7 §9 (relay semantics) | 18, 25, 30', 11 | `node/tests/{two_nodes,redeem,redeem_vectors,register,register_vectors,semantics_vectors,list_cursor,cli}.rs`; `protocol/test-vectors/{relay_semantics,redeem,register}.txt`; `allowed-observables.json`; `capture-check` |
| Blind-RSA and entitlement `issuer/crates/{blind-rsa,entitlement,api}` | F8 §2 (token format, RFC 9474 split implementation, permutation proof, deterministic blinding), §3 (ES, keys), §4 (grid) | 22 | `blind-rsa/tests/{rfc9474_vectors,permutation_proof,differential}.rs`, `entitlement/tests/{rfc9578_vectors,schedule_vectors,committed_schedule,ghost_vectors,monero_vectors}.rs`; vectors `blind_rsa_pp2`, `entitlement_*`, `monero_addresses` |
| Issuer service `issuer/crates/service` | F8 §5 (API, validation order, idempotency MS-1), §6 (redb, journal, retention, no logs), §7 (Monero rail), §8 (invites/trials), §9 (referral/payout), §12 (linkability rules), §13 (tests) | 22-26 | `tests/{crash,negative,custody,custody_window,journal_*,payout,refresh,races,server,end_to_end,monero_rail,monero_regtest,quantum,signer*}.rs`; T2 world `tests/t2/*`, `t2_unlinkability.rs`, `t2_mutants.rs`, `t2_policy_vectors.rs` |
| Issuer ops `issuer/crates/ops` + `infra/issuer` | F8 §3.3, §6.8, §9.5; RUNBOOK K1-K4, B1, P1, R2 | 26 | `ops/tests/{keys,onion_keygen,payout_tools,journal_prune,schedule_tools,schedule_onions,fixtures_check}.rs`; sealed fixtures `*.ghks` |
| Client net `client-core/net` + `android/network` | ADR-01/19/20; F7 §9; F8 §11, §14; Phase 6 review | 01, 09, 16, 19, 20 | `net/tests/{issuer_flow,redeem,register,entitlement_crypto,jni_error_canaries,dm_restore,live_tor}.rs`, unit tests in `src/`; `protocol/test-vectors/onion_addresses.txt`; `OnionAddress` doctests |
| DM crate `client-core/dm` | F9 §2 (integration), §3 (identity, card), §5 (bundles), §6 (envelope), §7 (content, pipelines, ordering), §8 (sessions, key change, revocation), §9 (PQ), §10 (ephemeral); §21-§22 corrections | 30'-36 | `dm/tests/{golden,key_schedule,pickle_structure,pq_root,state_models,vectors,xwing_kat,equivalence}.rs`; `protocol/test-vectors/dm_*.txt`; `protocol/models/dm/*.pv`; `dm/fuzz`; `dm/mutants/*.patch` |
| JNI wrapper `android/crypto-bridge` | F9 §2.6 (closed surface), §13.2; gate G-R6 `dm-jni-surface.sh` | 35 | `crypto-bridge/src/test` (12 files), `src/equivalence` (108-case host/Android equivalence) |
| Identity `android/identity` | Spec FR-1.x, §7; ADR-04, 14, 17; F8 §8 (invite v2) | 04, 14, 17, 24 | `identity/src/test` (BIP-39 Trezor vectors, RFC 5869 vectors, derivation, invite, revocation) |
| Storage `android/storage` | F7 §2 (v2), F8 §11 (v3), F9 §13.6 (v4, v5), `Schema.kt` | 20, 34' | `storage/src/test` (schema introspection, migrations, triggers); DM: `DmSchemaIntrospectionTest` |
| Sync `android/sync` | F7 whole (contracts OUT/IN, scheduling, API) | 20, 15, 09 | `sync/src/test/.../{engine,store,harness}` (T19, crash enumeration, mutants), `sync/README.md` |
| Entitlement client `android/entitlement` | F8 §11-§12 | 23, 24 | `entitlement/src/test` (crash enumeration E-A..E-J, `NiKTest`, `PolicyVectorsTest`) |
| DM engine `android/messaging` | F9 §7, §8, §10-§13, §21, §22 | 27, 32, 33', 34' | `messaging/src/test` (`DmWorld`, `dmworld/`, `entworld/`, `DmSuiteCases`, `DmMutants`, `PhaseReviewRegressionTest`) |
| App `android/app` | F7 §5; F9 §13.7; manifests; `proguard-rules.pro` | 06, 08, 20 | `app/src/test`, gates `manifest-lint`, `merged-manifest-lint`, `apk-*` |
| Gates and CI `ghost/scripts`, `.github/workflows`, `ghost/test-harness/gates` | ADR-10; F9 §16; `docs/ci-self-hosted.md` | 06, 10, 37, 39 | `self-test.sh`, 59 fixture roots |
| Protocol schemas `ghost/protocol` | F8 §5.2 (issuer), F7/F9 (relay) | 25, 30' | `proto-check.sh`; vectors |
| MLS (planned) `client-core/mls` + channel engine | F10 §3-§10, §19 | 40-43 (drafts) | branches `p10-*` only; `mls-spike` probes on `main` |

(The Phase 3 and 4 modules, identity and storage, have no phase design document of their own in the repository; their rules are in `docs/STATUS.md`, the spec, the ADRs above and the code.)

---

## 7. Known traps (collected)

* DM JVM tests skip silently without `-Dghost.dm.native`; check `skipped=0`.
* `build-native.sh` without a sums argument writes the generated, git-ignored `ghost/native-libs.sha256`; `reproducible-build.sh` needs the sums of a build you made.
* The libcrux build scripts read `LIBCRUX_DISABLE_SIMD128/256` without a `rerun-if` line: clean the packages before each Android/host build or G-R3 fails (design `faza9-dm.md` §22.33 item 4).
* On Windows: Application Control may block test executables on non-`C:` volumes; Git Bash starts processes slowly (a full `run-all.sh` took 30 to 45 minutes there, 75 seconds on Linux); `workflow-yaml.sh` needs PyYAML or `GHOST_YAML_VIA_WSL`.
* Gradle: `Unresolved reference` after a merge means a stale cache (`./gradlew clean`); do not export `MSYS_NO_PATHCONV=1` globally in Git Bash.
* `printf | grep -q` under `pipefail` can SIGPIPE: write checks with here-strings.
* A harness world that "passes" with 0 events is vacuous; the report checks reject empty enumerations ("not run is red").
* CI is advisory: a red job blocks nothing; read run history with `gh run list/view` rather than assuming `main` is green.
* Some docs are stale (`KNOWN_ISSUES.md` KI-DOC-1); later dated notes win.

---

## 8. What the auditor will want that the project must prepare (4 weeks ahead)

See `AUDITOR_RFQ.md` section B3. In short: a frozen tag and bundle with hashes; closed or explicitly waived exit gates for Phases 9-14; the open owner decisions of `KNOWN_ISSUES.md` decided; fresh green evidence at the tag (`run-all.sh`, `self-test.sh`, JUnit sums with `skipped=0`, the report checks), archived by the owner because CI artifacts are kept for only 3 days and job logs for 90 (`KNOWN_ISSUES.md` KI-SUP-8); a staging environment (three relays and the issuer on stagenet with an ES covering the audit window, a Monero stagenet node, two physical devices of API 29 or higher plus emulators API 29 and 35) or an agreement that the audit uses the in-repo worlds only; a named technical contact with one-business-day answers; English versions of the three Romanian claim documents or a glossary.
